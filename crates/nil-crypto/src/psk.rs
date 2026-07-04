//! PQ hybrid pre-shared key for the inner WireGuard tunnel (architecture spec §4.2).
//!
//! Two KEMs, combined the way Mullvad's `cme-mlkem` does: **ML-KEM-1024** (FIPS 203, the
//! forward-secrecy half) and **Classic McEliece 460896** (code-based, the authentication
//! half). Their two 32-byte shared secrets are concatenated and run through HKDF-SHA256 to
//! produce the 32-byte WireGuard PSK. The tunnel is safe if *either* KEM holds.
//!
//! Roles: the **client is the KEM initiator**. It generates both keypairs and ships the two
//! public keys (the McEliece key is ~512 KiB — sent once, client→node). The **node**
//! encapsulates against both and returns the two small ciphertexts; both sides then derive
//! the identical PSK locally. **The PSK never crosses the wire.**
//!
//! RNG note: `ml-kem` (rand_core 0.9) and `classic-mceliece-rust` (rand_core 0.6) want
//! incompatible RNG traits, so we don't take a generic RNG — ML-KEM uses its `getrandom`
//! system-RNG entry points and McEliece is handed `rand_core::OsRng`. Both are the OS CSPRNG.

use classic_mceliece_rust::{
    decapsulate_boxed, encapsulate_boxed, keypair_boxed, Ciphertext as McCiphertext, PublicKey,
    SecretKey, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES,
};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, Kem, MlKem1024};
use rand_core::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

/// ML-KEM-1024 encapsulation-key and ciphertext sizes (FIPS 203), for wire validation.
pub const MLKEM_EK_LEN: usize = 1568;
pub const MLKEM_CT_LEN: usize = 1568;
/// Classic McEliece 460896 public-key (~512 KiB) and ciphertext sizes.
pub const MCELIECE_PK_LEN: usize = CRYPTO_PUBLICKEYBYTES;
pub const MCELIECE_CT_LEN: usize = CRYPTO_CIPHERTEXTBYTES;

const PSK_SALT: &[u8] = b"nil.psk.v1.hkdf-salt";
const PSK_INFO: &[u8] = b"nil.psk.v1.wireguard-preshared-key";

#[derive(Debug, thiserror::Error)]
pub enum PskError {
    #[error("malformed KEM public key: {0}")]
    BadPublicKey(&'static str),
    #[error("malformed KEM ciphertext: {0}")]
    BadCiphertext(&'static str),
}

/// The 32-byte hybrid PSK fed to boringtun's `Tunn::new`. Zeroized on drop; never logged.
pub struct Psk(Zeroizing<[u8; 32]>);

impl Psk {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for Psk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Psk(redacted)")
    }
}

/// Public material the client sends to the node (one-time, client→node).
pub struct PqOffer {
    pub mlkem_ek: Vec<u8>,
    pub mceliece_pk: Vec<u8>,
}

/// The two small ciphertexts the node returns (node→client).
pub struct PqCiphertexts {
    pub mlkem_ct: Vec<u8>,
    pub mceliece_ct: Vec<u8>,
}

/// Client-held secret state (both decapsulation keys), retained until [`PqInitiator::finish`].
pub struct PqInitiator {
    mlkem_dk: DecapsulationKey1024,
    mceliece_sk: SecretKey<'static>,
}

impl PqInitiator {
    /// Client side: generate both KEM keypairs and the offer to send to the node.
    pub fn generate() -> (Self, PqOffer) {
        let (mlkem_dk, mlkem_ek) = MlKem1024::generate_keypair();
        let (mc_pk, mc_sk) = keypair_boxed(&mut OsRng);
        let offer = PqOffer {
            mlkem_ek: mlkem_ek.to_bytes().as_slice().to_vec(),
            mceliece_pk: mc_pk.as_array().to_vec(),
        };
        (Self { mlkem_dk, mceliece_sk: mc_sk }, offer)
    }

    /// Client side: decapsulate the node's two ciphertexts and derive the PSK.
    pub fn finish(&self, cts: &PqCiphertexts) -> Result<Psk, PskError> {
        let ss_mlkem = self
            .mlkem_dk
            .decapsulate_slice(&cts.mlkem_ct)
            .map_err(|_| PskError::BadCiphertext("ml-kem ciphertext length"))?;
        let mc_ct = mceliece_ct_from_bytes(&cts.mceliece_ct)?;
        let ss_mc = decapsulate_boxed(&mc_ct, &self.mceliece_sk);
        Ok(combine(ss_mlkem.as_slice(), ss_mc.as_array()))
    }
}

/// Node side (stateless): encapsulate against the client's offer; return ciphertexts + PSK.
pub fn responder_encapsulate(offer: &PqOffer) -> Result<(PqCiphertexts, Psk), PskError> {
    let ek = EncapsulationKey1024::new_from_slice(&offer.mlkem_ek)
        .map_err(|_| PskError::BadPublicKey("ml-kem encapsulation key"))?;
    let (mlkem_ct, ss_mlkem) = ek.encapsulate();

    let mc_pk = mceliece_pk_from_bytes(&offer.mceliece_pk)?;
    let (mc_ct, ss_mc) = encapsulate_boxed(&mc_pk, &mut OsRng);

    let cts = PqCiphertexts {
        mlkem_ct: mlkem_ct.as_slice().to_vec(),
        mceliece_ct: mc_ct.as_array().to_vec(),
    };
    Ok((cts, combine(ss_mlkem.as_slice(), ss_mc.as_array())))
}

/// `PSK = HKDF-SHA256(salt, ss_mlkem || ss_mceliece, 32)`. The concatenation order is part of
/// the construction and both sides agree on it.
///
/// The ML-KEM shared secret is passed by slice and copied STRAIGHT into the `Zeroizing` `ikm`
/// buffer — never into an intermediate plain `[u8; 32]`. That closes a defense-in-depth gap where a
/// stale, un-zeroized copy of the shared secret could linger on the stack after the source
/// `SharedKey` (which self-zeroizes on drop) was gone. `ikm` and `out` are both `Zeroizing`.
fn combine(ss_mlkem: &[u8], ss_mceliece: &[u8; 32]) -> Psk {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_mlkem);
    ikm[32..].copy_from_slice(ss_mceliece);
    let hk = Hkdf::<Sha256>::new(Some(PSK_SALT), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(PSK_INFO, out.as_mut_slice()).expect("32 bytes is within HKDF's output limit");
    Psk(out)
}

fn mceliece_pk_from_bytes(b: &[u8]) -> Result<PublicKey<'static>, PskError> {
    let arr: Box<[u8; CRYPTO_PUBLICKEYBYTES]> = b
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| PskError::BadPublicKey("mceliece public-key length"))?;
    Ok(PublicKey::from(arr))
}

fn mceliece_ct_from_bytes(b: &[u8]) -> Result<McCiphertext, PskError> {
    let arr: [u8; CRYPTO_CIPHERTEXTBYTES] =
        b.try_into().map_err(|_| PskError::BadCiphertext("mceliece ciphertext length"))?;
    Ok(McCiphertext::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    // One generate() (McEliece keygen is the slow part) covers both the agreeing round-trip
    // and the corrupt-ciphertext divergence.
    #[test]
    fn hybrid_psk_round_trip_and_tamper() {
        let (initiator, offer) = PqInitiator::generate();
        assert_eq!(offer.mlkem_ek.len(), MLKEM_EK_LEN, "ML-KEM-1024 ek size");
        assert_eq!(offer.mceliece_pk.len(), MCELIECE_PK_LEN, "McEliece 460896 pubkey size (~512 KiB)");

        let (cts, node_psk) = responder_encapsulate(&offer).expect("node encapsulates");
        assert_eq!(cts.mlkem_ct.len(), MLKEM_CT_LEN);
        assert_eq!(cts.mceliece_ct.len(), MCELIECE_CT_LEN);

        // Matching ciphertexts → both sides derive the identical PSK.
        let client_psk = initiator.finish(&cts).expect("client derives PSK");
        assert_eq!(client_psk.as_bytes(), node_psk.as_bytes(), "client and node derive the same PSK");

        // ML-KEM decapsulation is implicit-reject: a corrupt ciphertext doesn't error, it
        // yields a *different* shared secret — so the two sides simply disagree on the PSK.
        let mut tampered = cts;
        tampered.mlkem_ct[0] ^= 0xFF;
        let other = initiator.finish(&tampered).expect("decapsulation still returns a key");
        assert_ne!(other.as_bytes(), node_psk.as_bytes(), "corrupted ciphertext → PSKs differ");
    }

    #[test]
    fn combine_is_a_pinned_function_of_its_inputs() {
        // Anti-drift KAT: fixed shared secrets must always map to this exact PSK, so the HKDF
        // labels / concatenation order can never change silently.
        let psk = combine(&[0x01u8; 32], &[0x02u8; 32]);
        assert_eq!(
            hex::encode(psk.as_bytes()),
            "9b8a9798517615ec75d3b77a79b9c33b1257c23dc39df8a65f9270ed226caf45"
        );
    }

    #[test]
    fn wrong_length_inputs_are_rejected() {
        // Hand-built bad offer (no keygen): a too-short ML-KEM ek must be rejected.
        let bad = PqOffer { mlkem_ek: vec![0u8; 10], mceliece_pk: vec![0u8; MCELIECE_PK_LEN] };
        assert!(responder_encapsulate(&bad).is_err());
    }
}
