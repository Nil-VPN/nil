//! HSM/KMS-backed Privacy Pass issuer key via PKCS#11 (the `hsm` feature).
//!
//! The RSA private key is generated in — and never leaves — the device. The Portal blind-signs by
//! asking the HSM for a **raw** RSA private-key operation (`CKM_RSA_X_509`, i.e. `blinded^d mod n`),
//! which is exactly the RSABSSA blind-sign step (`nil_crypto::token::Issuer::blind_sign` does the
//! same modexp in-process). This closes the "plaintext issuer key on disk → unlimited free minting"
//! risk: a key that never leaves the HSM cannot be exfiltrated by reading a file.
//!
//! Runs against SoftHSM2 in test/CI and a real HSM/KMS PKCS#11 module in production — the code is
//! identical; only the module path + PIN differ.
//!
//! Thread-safety: [`crate::tokens::TokenSigner`] is `Send + Sync` and is called from many request
//! threads. The PKCS#11 context (`Pkcs11`) is `Send + Sync`; a `Session` is not shared — each
//! `blind_sign` opens its own short-lived logged-in session, finds the key by label, signs, and
//! drops the session. The public-key DER is read once at construction and cached.

use anyhow::{anyhow, Context, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::tokens::TokenSigner;

/// A `TokenSigner` whose RSA private key lives in a PKCS#11 device.
pub struct Pkcs11Signer {
    ctx: Pkcs11,
    slot: Slot,
    pin: AuthPin,
    label: Vec<u8>,
    /// SubjectPublicKeyInfo DER, read once from the device and cached (handed to clients/verifier).
    public_der: Vec<u8>,
}

impl Pkcs11Signer {
    /// Open `module_path`, use the first token-bearing slot (or `slot_id` if given), and cache the
    /// public key DER for the keypair labelled `key_label`. The keypair must already exist (provision
    /// it once with [`Pkcs11Signer::provision`] or the HSM's own tooling).
    pub fn open(module_path: &str, slot_id: Option<u64>, pin: &str, key_label: &str) -> Result<Self> {
        let ctx = init_module(module_path)?;
        let slot = pick_slot(&ctx, slot_id)?;
        let pin = AuthPin::new(pin.into());
        let label = key_label.as_bytes().to_vec();
        let session = login(&ctx, slot, &pin)?;
        let pubh = find_one(&session, ObjectClass::PUBLIC_KEY, &label)
            .context("locating the issuer PUBLIC key in the HSM")?;
        let public_der = spki_from_handle(&session, pubh)?;
        Ok(Self { ctx, slot, pin, label, public_der })
    }

    /// One-time provisioning: generate a token-resident RSA-2048 keypair labelled `key_label`
    /// (private key non-extractable + sign-capable). Used by the SoftHSM test harness and by an
    /// operator bootstrapping a real HSM. Idempotency is the caller's concern (generating twice
    /// yields two same-labelled keys — `open` then fails closed on the ambiguity).
    pub fn provision(module_path: &str, slot_id: Option<u64>, pin: &str, key_label: &str) -> Result<()> {
        let ctx = init_module(module_path)?;
        let slot = pick_slot(&ctx, slot_id)?;
        let pin = AuthPin::new(pin.into());
        let session = login(&ctx, slot, &pin)?;
        let label = key_label.as_bytes();
        let pub_tmpl = [
            Attribute::Token(true),
            Attribute::Label(label.to_vec()),
            Attribute::KeyType(KeyType::RSA),
            Attribute::ModulusBits((nil_crypto::token::TOKEN_MODULUS_BITS as u64).into()),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]), // 65537
            Attribute::Verify(true),
        ];
        let priv_tmpl = [
            Attribute::Token(true),
            Attribute::Label(label.to_vec()),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
        ];
        session
            .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_tmpl, &priv_tmpl)
            .context("generating the issuer RSA keypair in the HSM")?;
        Ok(())
    }
}

impl TokenSigner for Pkcs11Signer {
    fn blind_sign(&self, blind_msg: &[u8]) -> Result<Vec<u8>> {
        // Fresh logged-in session per call (Session is not Sync); short-lived. A session pool is a
        // perf follow-up — a rate-limited mint endpoint does not need one.
        let session = login(&self.ctx, self.slot, &self.pin)?;
        let privh = find_one(&session, ObjectClass::PRIVATE_KEY, &self.label)
            .context("locating the issuer PRIVATE key in the HSM")?;
        // CKM_RSA_X_509 = raw RSA (blinded^d mod n) with no padding — the RSABSSA blind-sign op.
        let sig = session
            .sign(&Mechanism::RsaX509, privh, blind_msg)
            .context("HSM raw-RSA blind-sign")?;
        Ok(sig)
    }

    fn public_der(&self) -> Result<Vec<u8>> {
        Ok(self.public_der.clone())
    }
}

/// One-shot provisioning entrypoint (invoked by `main` when `NW_TOKEN_HSM_PROVISION` is set):
/// generate the issuer keypair in the HSM from the same env the server reads, then exit. Run once
/// per HSM; the server then serves normally and logs the pubkey to pin.
pub fn provision_from_env() -> Result<()> {
    let module = std::env::var("NW_TOKEN_HSM_MODULE")
        .map_err(|_| anyhow!("NW_TOKEN_HSM_MODULE is not set"))?;
    let pin = std::env::var("NW_TOKEN_HSM_PIN").map_err(|_| anyhow!("NW_TOKEN_HSM_PIN is not set"))?;
    let label =
        std::env::var("NW_TOKEN_HSM_KEY_LABEL").unwrap_or_else(|_| "nil-issuer".to_string());
    let slot = std::env::var("NW_TOKEN_HSM_SLOT").ok().and_then(|s| s.parse::<u64>().ok());
    Pkcs11Signer::provision(&module, slot, &pin, &label)?;
    tracing::info!(
        "provisioned HSM issuer keypair (label={label}); restart WITHOUT NW_TOKEN_HSM_PROVISION to \
         serve — the NW_TOKEN_PUBKEY to pin is logged on a normal start"
    );
    Ok(())
}

fn init_module(module_path: &str) -> Result<Pkcs11> {
    let ctx = Pkcs11::new(module_path)
        .with_context(|| format!("loading PKCS#11 module {module_path}"))?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("PKCS#11 C_Initialize")?;
    Ok(ctx)
}

/// The token-bearing slot: `slot_id` if given, else the first slot that has a token.
fn pick_slot(ctx: &Pkcs11, slot_id: Option<u64>) -> Result<Slot> {
    let slots = ctx.get_slots_with_token().context("enumerating PKCS#11 slots")?;
    match slot_id {
        Some(id) => slots
            .into_iter()
            .find(|s| s.id() == id)
            .ok_or_else(|| anyhow!("no PKCS#11 token in slot {id}")),
        None => slots.into_iter().next().ok_or_else(|| anyhow!("no PKCS#11 token in any slot")),
    }
}

fn login(ctx: &Pkcs11, slot: Slot, pin: &AuthPin) -> Result<Session> {
    let session = ctx.open_rw_session(slot).context("opening a PKCS#11 session")?;
    session.login(UserType::User, Some(pin)).context("PKCS#11 login (USER)")?;
    Ok(session)
}

/// Find exactly one object of `class` with the given label. Fail closed on 0 or >1 (an ambiguous
/// issuer key must never be silently resolved).
fn find_one(session: &Session, class: ObjectClass, label: &[u8]) -> Result<ObjectHandle> {
    let tmpl = [Attribute::Class(class), Attribute::Label(label.to_vec())];
    let mut found = session.find_objects(&tmpl).context("PKCS#11 find_objects")?;
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(anyhow!("no PKCS#11 object with the requested class + label")),
        n => Err(anyhow!("{n} PKCS#11 objects share the issuer key label — ambiguous, refusing")),
    }
}

/// Build a SubjectPublicKeyInfo DER from the device public key's (modulus, exponent) — the same DER
/// `nil_crypto::token`'s verifier expects (`PublicKey::from_der`).
fn spki_from_handle(session: &Session, pubh: ObjectHandle) -> Result<Vec<u8>> {
    use rsa::pkcs8::EncodePublicKey;
    use rsa::BigUint;

    let attrs = session
        .get_attributes(pubh, &[AttributeType::Modulus, AttributeType::PublicExponent])
        .context("reading HSM public-key modulus/exponent")?;
    let mut modulus = None;
    let mut exponent = None;
    for a in attrs {
        match a {
            Attribute::Modulus(m) => modulus = Some(m),
            Attribute::PublicExponent(e) => exponent = Some(e),
            _ => {}
        }
    }
    let n = modulus.ok_or_else(|| anyhow!("HSM public key exposed no modulus"))?;
    let e = exponent.ok_or_else(|| anyhow!("HSM public key exposed no public exponent"))?;
    let key = rsa::RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        .context("reconstructing the RSA public key from HSM attributes")?;
    Ok(key.to_public_key_der().context("encoding SubjectPublicKeyInfo")?.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full RSABSSA blind-token round-trip with the HSM doing the blind-sign (raw RSA via
    /// CKM_RSA_X_509): provision a keypair in the token → client blinds → HSM blind-signs → client
    /// finalizes → verifier accepts. Proves the PKCS#11 signer is a correct drop-in for the
    /// in-memory `Issuer`. Runs ONLY when a PKCS#11 module is configured (the SoftHSM harness,
    /// `deploy/verify-hsm.sh`, sets NW_TOKEN_HSM_*); skips cleanly on a box with no HSM so the normal
    /// `cargo test` stays green everywhere.
    #[test]
    fn hsm_blind_sign_round_trips_a_token() {
        let Ok(module) = std::env::var("NW_TOKEN_HSM_MODULE") else {
            eprintln!("no NW_TOKEN_HSM_MODULE set — skipping HSM round-trip (see deploy/verify-hsm.sh)");
            return;
        };
        let pin = std::env::var("NW_TOKEN_HSM_PIN").expect("NW_TOKEN_HSM_PIN");
        let label =
            std::env::var("NW_TOKEN_HSM_KEY_LABEL").unwrap_or_else(|_| "nil-issuer-test".to_string());
        let slot = std::env::var("NW_TOKEN_HSM_SLOT").ok().and_then(|s| s.parse::<u64>().ok());

        Pkcs11Signer::provision(&module, slot, &pin, &label).expect("provision issuer keypair");
        let signer = Pkcs11Signer::open(&module, slot, &pin, &label).expect("open HSM signer");

        let pub_der = signer.public_der().expect("public der from HSM");
        let msg = vec![0x42u8; 32];
        let req = nil_crypto::token::blind(&pub_der, &msg).expect("client blind");
        let blind_sig = signer.blind_sign(&req.blind_msg).expect("HSM blind_sign (raw RSA)");
        let token = nil_crypto::token::finalize(&pub_der, &req, &blind_sig).expect("client finalize");

        let verifier = nil_crypto::token::Verifier::from_public_der(&pub_der).expect("verifier");
        assert!(verifier.verify(&token, &msg), "HSM-signed token must verify");
        assert!(!verifier.verify(&token, b"a different message"), "must not verify for another msg");
    }
}
