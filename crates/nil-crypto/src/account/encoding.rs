//! Crockford base32 encoding for account numbers and recovery codes.
//!
//! Crockford's alphabet omits the ambiguous letters I, L, O, U, so codes are easy to
//! read aloud and transcribe. We only ever *encode* (raw bytes → display string); the
//! canonical account key is always the raw hash bytes, never the string, so no decode
//! path is needed.

use std::sync::OnceLock;

use data_encoding::{Encoding, Specification};

const CROCKFORD_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford() -> &'static Encoding {
    static ENC: OnceLock<Encoding> = OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = Specification::new();
        spec.symbols.push_str(CROCKFORD_ALPHABET);
        // Infallible: a 32-symbol, no-padding alphabet is always a valid base32 spec.
        spec.encoding()
            .expect("static Crockford base32 alphabet (32 symbols) is valid")
    })
}

/// Encode bytes as unpadded, uppercase Crockford base32.
pub(crate) fn base32(bytes: &[u8]) -> String {
    crockford().encode(bytes)
}

/// Insert a `-` every `n` characters, for human transcription.
pub(crate) fn group(s: &str, n: usize) -> String {
    debug_assert!(n > 0);
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(n)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}
