//! PQ hybrid pre-shared key for the inner WireGuard tunnel (architecture spec §4.2).
//!
//! Two KEMs, combined the way Mullvad's `cme-mlkem` does: **ML-KEM-1024** (FIPS 203, the
//! forward-secrecy half) and **Classic McEliece 460896** (code-based, the authentication
//! half). Their two 32-byte shared secrets are concatenated (ML-KEM first) as the HKDF-SHA256
//! input keying material, and the **KEM handshake transcript** (both public keys + both
//! ciphertexts) is bound into the HKDF `info`, producing the 32-byte WireGuard PSK. The tunnel is
//! safe if *either* KEM holds. Both KEM keypairs are **ephemeral** (freshly generated per
//! handshake by [`PqInitiator::generate`] and dropped after [`PqInitiator::finish`]); no long-term
//! PQ private key is ever stored, so the PQ layer is forward-secret — a future key seizure cannot
//! decrypt past sessions.
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
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// ML-KEM-1024 encapsulation-key and ciphertext sizes (FIPS 203), for wire validation.
pub const MLKEM_EK_LEN: usize = 1568;
pub const MLKEM_CT_LEN: usize = 1568;
/// Classic McEliece 460896 public-key (~512 KiB) and ciphertext sizes.
pub const MCELIECE_PK_LEN: usize = CRYPTO_PUBLICKEYBYTES;
pub const MCELIECE_CT_LEN: usize = CRYPTO_CIPHERTEXTBYTES;

// v2: the PSK now binds the KEM transcript (both public keys + both ciphertexts) into the HKDF
// `info`. The version bump makes the derivation change explicit — a v1 peer and a v2 peer derive
// different PSKs and simply fail the WireGuard handshake rather than agreeing on a weaker key.
const PSK_SALT: &[u8] = b"nil.psk.v2.hkdf-salt";
const PSK_INFO: &[u8] = b"nil.psk.v2.wireguard-preshared-key";
/// Domain-separation label prefixed to the bound KEM-transcript hash (v2).
const PSK_TRANSCRIPT_LABEL: &[u8] = b"nil.psk.v2.kem-transcript";

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
    /// The offer's public keys, retained so `finish` can bind them into the PSK transcript. The
    /// node binds the identical bytes it received in the offer, so both ends agree. Dropped with
    /// the initiator after one handshake (these are ephemeral, not long-term identity keys).
    mlkem_ek: Vec<u8>,
    mceliece_pk: Vec<u8>,
}

impl PqInitiator {
    /// Client side: generate both KEM keypairs and the offer to send to the node.
    pub fn generate() -> (Self, PqOffer) {
        let (mlkem_dk, mlkem_ek) = MlKem1024::generate_keypair();
        let (mc_pk, mc_sk) = keypair_boxed(&mut OsRng);
        let mlkem_ek_bytes = mlkem_ek.to_bytes().as_slice().to_vec();
        let mceliece_pk_bytes = mc_pk.as_array().to_vec();
        let offer =
            PqOffer { mlkem_ek: mlkem_ek_bytes.clone(), mceliece_pk: mceliece_pk_bytes.clone() };
        (
            Self {
                mlkem_dk,
                mceliece_sk: mc_sk,
                mlkem_ek: mlkem_ek_bytes,
                mceliece_pk: mceliece_pk_bytes,
            },
            offer,
        )
    }

    /// Client side: decapsulate the node's two ciphertexts and derive the PSK, binding the KEM
    /// transcript (our offer's public keys + the node's ciphertexts).
    pub fn finish(&self, cts: &PqCiphertexts) -> Result<Psk, PskError> {
        let ss_mlkem = self
            .mlkem_dk
            .decapsulate_slice(&cts.mlkem_ct)
            .map_err(|_| PskError::BadCiphertext("ml-kem ciphertext length"))?;
        let mc_ct = mceliece_ct_from_bytes(&cts.mceliece_ct)?;
        let ss_mc = decapsulate_boxed(&mc_ct, &self.mceliece_sk);
        let transcript = PqTranscript {
            mlkem_ek: &self.mlkem_ek,
            mlkem_ct: &cts.mlkem_ct,
            mceliece_pk: &self.mceliece_pk,
            mceliece_ct: &cts.mceliece_ct,
        };
        Ok(combine(ss_mlkem.as_slice(), ss_mc.as_array(), &transcript))
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
    let psk = {
        let transcript = PqTranscript {
            mlkem_ek: &offer.mlkem_ek,
            mlkem_ct: &cts.mlkem_ct,
            mceliece_pk: &offer.mceliece_pk,
            mceliece_ct: &cts.mceliece_ct,
        };
        combine(ss_mlkem.as_slice(), ss_mc.as_array(), &transcript)
    };
    Ok((cts, psk))
}

/// The KEM handshake transcript bound into the PSK derivation: both public keys and both
/// ciphertexts. The initiator and responder hold identical bytes for all four, so they compute
/// the same transcript hash and therefore the same PSK.
struct PqTranscript<'a> {
    mlkem_ek: &'a [u8],
    mlkem_ct: &'a [u8],
    mceliece_pk: &'a [u8],
    mceliece_ct: &'a [u8],
}

/// `PSK = HKDF-SHA256(salt, ss_mlkem || ss_mceliece, info = PSK_INFO || H(transcript))`.
///
/// The two shared secrets (ML-KEM first — a fixed order both sides agree on, per SP 800-56Cr2) are
/// the HKDF input keying material. The **transcript** (both KEM public keys + both ciphertexts) is
/// hashed and bound into the HKDF `info`, so the derived PSK commits to the exact ciphertexts and
/// keys of *this* handshake. ML-KEM is not a binding KEM (eprint 2024/523): without this binding, a
/// re-encapsulation / substituted-ciphertext adversary could steer both ends toward a shared secret
/// it can relate; binding ct+pk (MAL-BIND-K-CT / MAL-BIND-K-PK) closes that. The `ss_mlkem` slice is
/// copied straight into the `Zeroizing` `ikm` (no intermediate plain copy); `ikm`/`out` are both
/// `Zeroizing`. `info` is public KDF context (not secret).
fn combine(ss_mlkem: &[u8], ss_mceliece: &[u8; 32], transcript: &PqTranscript) -> Psk {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_mlkem);
    ikm[32..].copy_from_slice(ss_mceliece);

    // Length-prefixed, fixed-order hash of both public keys and both ciphertexts.
    let mut th = Sha256::new();
    th.update(PSK_TRANSCRIPT_LABEL);
    for part in [transcript.mlkem_ek, transcript.mlkem_ct, transcript.mceliece_pk, transcript.mceliece_ct] {
        th.update((part.len() as u32).to_be_bytes());
        th.update(part);
    }
    let transcript_hash = th.finalize();

    let mut info = Vec::with_capacity(PSK_INFO.len() + transcript_hash.len());
    info.extend_from_slice(PSK_INFO);
    info.extend_from_slice(&transcript_hash);

    let hk = Hkdf::<Sha256>::new(Some(PSK_SALT), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, out.as_mut_slice()).expect("32 bytes is within HKDF's output limit");
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

    /// A fixed transcript for the KAT / binding tests (tiny stand-in byte strings).
    fn kat_transcript() -> PqTranscript<'static> {
        PqTranscript {
            mlkem_ek: &[0x10u8; 4],
            mlkem_ct: &[0x11u8; 4],
            mceliece_pk: &[0x12u8; 4],
            mceliece_ct: &[0x13u8; 4],
        }
    }

    #[test]
    fn combine_is_a_pinned_function_of_its_inputs() {
        // Anti-drift KAT: fixed shared secrets + a fixed transcript must always map to this exact
        // PSK, so the HKDF labels / ordering / transcript binding can never change silently.
        let psk = combine(&[0x01u8; 32], &[0x02u8; 32], &kat_transcript());
        assert_eq!(
            hex::encode(psk.as_bytes()),
            "c3a34f7a9ef600bdea96ee43a6303c48bb5fdf6f278ef60ede212c4d291c1d2e"
        );
    }

    #[test]
    fn combine_binds_the_kem_transcript() {
        // Identical shared secrets but a different ciphertext in the transcript → a different PSK.
        // This is the ML-KEM-non-binding mitigation: the PSK commits to the exact ct/pk.
        let base = combine(&[0x01u8; 32], &[0x02u8; 32], &kat_transcript()).as_bytes().to_vec();
        let altered_ct = PqTranscript { mlkem_ct: &[0x99u8; 4], ..kat_transcript() };
        let altered = combine(&[0x01u8; 32], &[0x02u8; 32], &altered_ct).as_bytes().to_vec();
        assert_ne!(base, altered, "PSK must commit to the KEM transcript (ciphertext)");
        let altered_pk = PqTranscript { mceliece_pk: &[0x88u8; 4], ..kat_transcript() };
        let altered2 = combine(&[0x01u8; 32], &[0x02u8; 32], &altered_pk).as_bytes().to_vec();
        assert_ne!(base, altered2, "PSK must commit to the KEM transcript (public key)");
    }

    #[test]
    fn keypairs_are_ephemeral_per_handshake() {
        // Forward secrecy: each handshake generates fresh KEM keypairs, so two independent
        // handshakes produce different offers. No long-term PQ key exists to seize.
        let (_i1, o1) = PqInitiator::generate();
        let (_i2, o2) = PqInitiator::generate();
        assert_ne!(o1.mlkem_ek, o2.mlkem_ek, "fresh ML-KEM keypair per handshake");
        assert_ne!(o1.mceliece_pk, o2.mceliece_pk, "fresh McEliece keypair per handshake");
    }

    #[test]
    fn wrong_length_inputs_are_rejected() {
        // Hand-built bad offer (no keygen): a too-short ML-KEM ek must be rejected.
        let bad = PqOffer { mlkem_ek: vec![0u8; 10], mceliece_pk: vec![0u8; MCELIECE_PK_LEN] };
        assert!(responder_encapsulate(&bad).is_err());
    }
}
