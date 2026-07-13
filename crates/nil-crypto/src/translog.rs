//! Transparency-log inclusion verification (architecture review: "prove, don't promise").
//!
//! The client should be able to check *itself* that a node's reproducible-build measurement is
//! present in an independently operated append-only transparency log, rather than trusting a
//! Coordinator-pinned value — so a compromised/coerced Coordinator (or a malicious future owner)
//! cannot substitute a measurement pointing at a backdoored node without leaving a publicly visible,
//! log-detectable trace (PD-5/PD-7).
//!
//! This module is the offline verifier: given a leaf (the measurement), an RFC 6962 Merkle
//! **inclusion proof** to a tree root, and a **checkpoint** (root + tree size) **signed by the log's
//! Ed25519 key** (pinned in the client), it confirms the leaf is committed to that log. It is
//! **offline by design**: the proof + checkpoint are *stapled* (delivered alongside the attestation),
//! so the client never phones home to the log — which would leak *which* node it is verifying (PD-3).
//!
//! Merkle hashing follows RFC 6962 §2.1 (leaf prefix 0x00, node prefix 0x01) and the inclusion-proof
//! reconstruction is the standard Trillian decomposition. This verifier currently defines a
//! NIL-specific Ed25519 checkpoint body (`origin\n<size>\n<base64 root>\n`) whose leaf is the raw
//! measurement bytes. It is **not** a Sigstore bundle/Rekor adapter: Rekor proves inclusion of a
//! canonicalized transparency entry and uses a signed-note envelope/trusted-root policy. Production
//! use requires a reviewed converter/verifier that binds that entry's signed attestation predicate
//! to the exact measurement; treating a cosign bundle as [`LogProof`] would be unsafe.

use data_encoding::BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// RFC 6962 leaf hash: `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// RFC 6962 interior node hash: `SHA-256(0x01 || left || right)`.
fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// A stapled transparency-log proof for one leaf: an RFC 6962 inclusion proof plus the log-signed
/// checkpoint it proves inclusion against. All fields are attacker-supplied until verified.
#[derive(Debug, Clone)]
pub struct LogProof {
    /// Log origin string (part of the signed checkpoint body).
    pub origin: String,
    /// Number of entries in the tree the checkpoint commits to.
    pub tree_size: u64,
    /// 0-based index of the leaf in the log.
    pub leaf_index: u64,
    /// The Merkle tree root the checkpoint commits to.
    pub root: [u8; 32],
    /// The inclusion proof audit path (sibling hashes, leaf→root order).
    pub audit_path: Vec<[u8; 32]>,
    /// The log's Ed25519 signature over the checkpoint body.
    pub checkpoint_sig: Vec<u8>,
}

impl LogProof {
    /// Serialize for stapling alongside attestation evidence. Self-describing, big-endian:
    /// `[u16 origin_len][origin][u64 tree_size][u64 leaf_index][32 root][u16 path_len][path*32]
    /// [u16 sig_len][sig]`. A compatible NIL log operator may emit this directly. A Sigstore/Rekor
    /// bundle cannot be copied into this shape without separately verifying and binding its signed
    /// entry/attestation semantics; see the module-level limitation. The client decodes the bytes
    /// with [`LogProof::decode`] and never trusts them until [`verify_logged`] passes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let origin = self.origin.as_bytes();
        out.extend_from_slice(&(origin.len() as u16).to_be_bytes());
        out.extend_from_slice(origin);
        out.extend_from_slice(&self.tree_size.to_be_bytes());
        out.extend_from_slice(&self.leaf_index.to_be_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&(self.audit_path.len() as u16).to_be_bytes());
        for h in &self.audit_path {
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&(self.checkpoint_sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.checkpoint_sig);
        out
    }

    /// Parse bytes produced by [`LogProof::encode`]. `None` on any truncation, bad UTF-8 origin, or
    /// trailing garbage — an unparseable proof is treated as no proof (the caller fails closed).
    pub fn decode(mut b: &[u8]) -> Option<Self> {
        let olen = take_u16(&mut b)? as usize;
        let origin = String::from_utf8(take(&mut b, olen)?.to_vec()).ok()?;
        let tree_size = u64::from_be_bytes(take(&mut b, 8)?.try_into().ok()?);
        let leaf_index = u64::from_be_bytes(take(&mut b, 8)?.try_into().ok()?);
        let root: [u8; 32] = take(&mut b, 32)?.try_into().ok()?;
        let plen = take_u16(&mut b)? as usize;
        let mut audit_path = Vec::with_capacity(plen);
        for _ in 0..plen {
            audit_path.push(take(&mut b, 32)?.try_into().ok()?);
        }
        let slen = take_u16(&mut b)? as usize;
        let checkpoint_sig = take(&mut b, slen)?.to_vec();
        if !b.is_empty() {
            return None; // trailing garbage ⇒ reject rather than silently ignore
        }
        Some(LogProof {
            origin,
            tree_size,
            leaf_index,
            root,
            audit_path,
            checkpoint_sig,
        })
    }
}

/// Split the first `n` bytes off `b`, advancing it; `None` if fewer than `n` remain.
fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if b.len() < n {
        return None;
    }
    let (head, tail) = b.split_at(n);
    *b = tail;
    Some(head)
}

/// Read a big-endian `u16`, advancing `b`.
fn take_u16(b: &mut &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(take(b, 2)?.try_into().ok()?))
}

/// Reconstruct the Merkle root a leaf-at-index proves to, via the standard RFC 6962 inclusion-proof
/// decomposition. `None` if the index/size/path lengths are inconsistent.
fn root_from_inclusion(
    index: u64,
    size: u64,
    leaf: [u8; 32],
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    // inner = number of proof steps that combine within the "left" subtree structure; border = the
    // remaining right-edge steps. (Trillian decomposition of the RFC 6962 proof.)
    let inner = bit_length(index ^ (size - 1)) as usize;
    let border = (index >> inner).count_ones() as usize;
    if path.len() != inner + border {
        return None;
    }
    let mut seed = leaf;
    for (i, sibling) in path[..inner].iter().enumerate() {
        seed = if (index >> i) & 1 == 0 {
            hash_children(&seed, sibling)
        } else {
            hash_children(sibling, &seed)
        };
    }
    for sibling in &path[inner..] {
        seed = hash_children(sibling, &seed);
    }
    Some(seed)
}

/// Bit length of `x` (0 for `x == 0`), i.e. `Len64` — the position of the highest set bit.
fn bit_length(x: u64) -> u32 {
    64 - x.leading_zeros()
}

/// The Go/Sigstore signed-note checkpoint body: `origin\n<tree_size>\n<base64(root)>\n`.
fn checkpoint_body(origin: &str, tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    format!("{origin}\n{tree_size}\n{}\n", BASE64.encode(root)).into_bytes()
}

/// Verify the log's Ed25519 signature over the checkpoint (root + size).
fn verify_checkpoint(proof: &LogProof, log_key: &VerifyingKey) -> bool {
    let Ok(sig) = Signature::from_slice(&proof.checkpoint_sig) else {
        return false;
    };
    let body = checkpoint_body(&proof.origin, proof.tree_size, &proof.root);
    log_key.verify(&body, &sig).is_ok()
}

/// Fail-closed check that `leaf_data` (e.g. a node measurement) is committed to the transparency log
/// identified by the pinned `log_pubkey` (32-byte Ed25519). Verifies BOTH that the checkpoint is
/// signed by the pinned log key AND that the leaf is included under that checkpoint's root. Any
/// malformed field, bad signature, or non-matching root ⇒ `false`.
pub fn verify_logged(leaf_data: &[u8], proof: &LogProof, log_pubkey: &[u8; 32]) -> bool {
    let Ok(log_key) = VerifyingKey::from_bytes(log_pubkey) else {
        return false;
    };
    if !verify_checkpoint(proof, &log_key) {
        return false;
    }
    root_from_inclusion(
        proof.leaf_index,
        proof.tree_size,
        leaf_hash(leaf_data),
        &proof.audit_path,
    ) == Some(proof.root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // --- A reference RFC 6962 Merkle tree (build root + inclusion proofs), to validate the
    // verifier against the spec definition directly (no external vectors needed). ---

    /// RFC 6962 Merkle Tree Hash of `leaves` (each already a leaf byte-string).
    fn mth(leaves: &[Vec<u8>]) -> [u8; 32] {
        match leaves.len() {
            0 => Sha256::digest(b"").into(),
            1 => leaf_hash(&leaves[0]),
            n => {
                let k = largest_pow2_below(n);
                hash_children(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }

    /// RFC 6962 inclusion-proof audit path for leaf `m` in `leaves`.
    fn path(m: usize, leaves: &[Vec<u8>]) -> Vec<[u8; 32]> {
        let n = leaves.len();
        if n == 1 {
            return Vec::new();
        }
        let k = largest_pow2_below(n);
        if m < k {
            let mut p = path(m, &leaves[..k]);
            p.push(mth(&leaves[k..]));
            p
        } else {
            let mut p = path(m - k, &leaves[k..]);
            p.push(mth(&leaves[..k]));
            p
        }
    }

    /// Largest power of two strictly less than `n` (n >= 2).
    fn largest_pow2_below(n: usize) -> usize {
        let mut k = 1;
        while k << 1 < n {
            k <<= 1;
        }
        k
    }

    fn proof_for(idx: usize, leaves: &[Vec<u8>], sk: &SigningKey, origin: &str) -> LogProof {
        let root = mth(leaves);
        let body = checkpoint_body(origin, leaves.len() as u64, &root);
        LogProof {
            origin: origin.to_string(),
            tree_size: leaves.len() as u64,
            leaf_index: idx as u64,
            root,
            audit_path: path(idx, leaves),
            checkpoint_sig: sk.sign(&body).to_bytes().to_vec(),
        }
    }

    #[test]
    fn verifies_a_genuine_inclusion_proof_at_every_index_and_size() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        // Exercise a range of tree sizes (incl. non-powers-of-two, the interesting RFC 6962 shapes).
        for n in 1..=17usize {
            let leaves: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; 48]).collect();
            for idx in 0..n {
                let proof = proof_for(idx, &leaves, &sk, "nil.transparency.v1");
                assert!(
                    verify_logged(&leaves[idx], &proof, &pk),
                    "genuine proof must verify (n={n}, idx={idx})"
                );
            }
        }
    }

    #[test]
    fn rejects_tampering() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let leaves: Vec<Vec<u8>> = (0..11).map(|i| vec![i as u8; 48]).collect();
        let good = proof_for(5, &leaves, &sk, "nil.transparency.v1");

        // Wrong leaf data (a substituted measurement) → not included.
        assert!(
            !verify_logged(&[0xFFu8; 48], &good, &pk),
            "substituted leaf rejected"
        );

        // Tampered root → checkpoint signature no longer matches.
        let mut bad_root = good.clone();
        bad_root.root[0] ^= 1;
        assert!(
            !verify_logged(&leaves[5], &bad_root, &pk),
            "tampered root rejected"
        );

        // Corrupted audit path → wrong reconstructed root.
        let mut bad_path = good.clone();
        bad_path.audit_path[0][0] ^= 1;
        assert!(
            !verify_logged(&leaves[5], &bad_path, &pk),
            "corrupted path rejected"
        );

        // Wrong log key (a forged checkpoint signed by someone else) → rejected.
        let other = SigningKey::from_bytes(&[1u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(
            !verify_logged(&leaves[5], &good, &other),
            "wrong log key rejected"
        );

        // Garbage signature → rejected.
        let mut bad_sig = good.clone();
        bad_sig.checkpoint_sig = vec![0u8; 64];
        assert!(
            !verify_logged(&leaves[5], &bad_sig, &pk),
            "bad signature rejected"
        );

        // Mismatched index (claiming a different position) → wrong root.
        let mut bad_idx = good.clone();
        bad_idx.leaf_index = 6;
        assert!(
            !verify_logged(&leaves[5], &bad_idx, &pk),
            "wrong index rejected"
        );
    }

    #[test]
    fn encode_decode_round_trips_and_still_verifies() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let leaves: Vec<Vec<u8>> = (0..13).map(|i| vec![i as u8; 48]).collect();
        let proof = proof_for(9, &leaves, &sk, "nil.transparency.v1");

        let bytes = proof.encode();
        let back = LogProof::decode(&bytes).expect("round-trips");
        assert_eq!(back.origin, proof.origin);
        assert_eq!(back.tree_size, proof.tree_size);
        assert_eq!(back.leaf_index, proof.leaf_index);
        assert_eq!(back.root, proof.root);
        assert_eq!(back.audit_path, proof.audit_path);
        assert_eq!(back.checkpoint_sig, proof.checkpoint_sig);
        // The decoded proof still verifies against the same pinned key + leaf.
        assert!(
            verify_logged(&leaves[9], &back, &pk),
            "decoded proof must still verify"
        );
    }

    #[test]
    fn decode_rejects_truncation_and_trailing_garbage() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let leaves: Vec<Vec<u8>> = (0..7).map(|i| vec![i as u8; 48]).collect();
        let bytes = proof_for(2, &leaves, &sk, "nil.transparency.v1").encode();

        for cut in 0..bytes.len() {
            assert!(
                LogProof::decode(&bytes[..cut]).is_none(),
                "truncated at {cut} must be None"
            );
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(
            LogProof::decode(&extra).is_none(),
            "trailing garbage must be None"
        );
    }
}
