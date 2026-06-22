//! The 7-word recovery phrase and its underlying entropy.
//!
//! 7 words × 11 bits = 77 bits of entropy, packed big-endian (most-significant word
//! first) into a `u128`. The phrase is canonical: the account secret is derived from
//! this entropy, so reconstructing the phrase reconstructs the account (ADR-0001).

use zeroize::Zeroize;

use super::words as wordlist;
use super::PHRASE_WORDS;
use crate::error::CryptoError;

/// The phrase's underlying entropy: a 77-bit value (7 × 11-bit indices), stored
/// low-aligned in a `u128`. Zeroized on drop.
#[derive(Clone)]
pub(crate) struct PhraseEntropy {
    value: u128,
}

impl PhraseEntropy {
    const BITS: u32 = (PHRASE_WORDS * 11) as u32; // 77

    /// Draw fresh entropy from an RNG. Masking to the low 77 bits is unbiased because
    /// every bit of a CSPRNG output is independent and uniform.
    pub(crate) fn random(rng: &mut impl rand_core::RngCore) -> Self {
        let mut raw = [0u8; 16];
        rng.fill_bytes(&mut raw);
        let mut value = u128::from_be_bytes(raw);
        raw.zeroize();
        value &= (1u128 << Self::BITS) - 1;
        Self { value }
    }

    /// The 7 word indices, most-significant first.
    pub(crate) fn indices(&self) -> [u16; PHRASE_WORDS] {
        let mut out = [0u16; PHRASE_WORDS];
        for (i, slot) in out.iter_mut().enumerate() {
            let shift = 11 * (PHRASE_WORDS - 1 - i) as u32;
            *slot = ((self.value >> shift) & 0x7FF) as u16;
        }
        out
    }

    fn from_indices(indices: &[u16; PHRASE_WORDS]) -> Self {
        let mut value: u128 = 0;
        for &idx in indices {
            value = (value << 11) | (idx as u128 & 0x7FF);
        }
        Self { value }
    }

    /// Canonical 16-byte big-endian encoding — the HKDF input keying material.
    pub(crate) fn ikm(&self) -> [u8; 16] {
        self.value.to_be_bytes()
    }
}

impl Drop for PhraseEntropy {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// A 7-word recovery phrase. Shown to the user exactly once; it is the sole root of
/// the account.
#[derive(Clone)]
pub struct Phrase {
    words: [String; PHRASE_WORDS],
}

impl Phrase {
    /// Render entropy as words.
    pub(crate) fn from_entropy(e: &PhraseEntropy) -> Self {
        let words = e.indices().map(|idx| wordlist::word_at(idx).to_string());
        Self { words }
    }

    /// Parse and validate user-supplied words (case-insensitive, trimmed).
    pub fn parse(input: &[String]) -> Result<Self, CryptoError> {
        if input.len() != PHRASE_WORDS {
            return Err(CryptoError::WrongLength {
                expected: PHRASE_WORDS,
                got: input.len(),
            });
        }
        let mut words: [String; PHRASE_WORDS] = std::array::from_fn(|_| String::new());
        for (slot, w) in words.iter_mut().zip(input.iter()) {
            let norm = w.trim().to_lowercase();
            if wordlist::index_of(&norm).is_none() {
                return Err(CryptoError::UnknownWord(w.clone()));
            }
            *slot = norm;
        }
        Ok(Self { words })
    }

    /// Recover the entropy from the (already validated) words.
    pub(crate) fn to_entropy(&self) -> Result<PhraseEntropy, CryptoError> {
        let mut indices = [0u16; PHRASE_WORDS];
        for (slot, w) in indices.iter_mut().zip(self.words.iter()) {
            *slot = wordlist::index_of(w).ok_or_else(|| CryptoError::UnknownWord(w.clone()))?;
        }
        Ok(PhraseEntropy::from_indices(&indices))
    }

    pub fn words(&self) -> &[String; PHRASE_WORDS] {
        &self.words
    }

    pub fn to_vec(&self) -> Vec<String> {
        self.words.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_index_roundtrip() {
        let idx = [1u16, 2, 4, 8, 16, 1023, 2047];
        let e = PhraseEntropy::from_indices(&idx);
        assert_eq!(e.indices(), idx);
    }

    #[test]
    fn phrase_roundtrips_through_words() {
        let e = PhraseEntropy::from_indices(&[7, 700, 2047, 0, 1, 1234, 99]);
        let phrase = Phrase::from_entropy(&e);
        assert_eq!(phrase.words().len(), 7);
        let back = phrase.to_entropy().expect("valid words");
        assert_eq!(back.indices(), e.indices());
    }

    #[test]
    fn parse_normalizes_case_and_whitespace() {
        let e = PhraseEntropy::from_indices(&[7, 700, 2047, 0, 1, 1234, 99]);
        let phrase = Phrase::from_entropy(&e);
        let shouty: Vec<String> = phrase.words().iter().map(|w| format!("  {} ", w.to_uppercase())).collect();
        let reparsed = Phrase::parse(&shouty).expect("normalized parse");
        assert_eq!(reparsed.to_entropy().unwrap().indices(), e.indices());
    }

    #[test]
    fn parse_rejects_wrong_count() {
        let six: Vec<String> = (0..6).map(|_| "abandon".to_string()).collect();
        assert!(matches!(
            Phrase::parse(&six),
            Err(CryptoError::WrongLength { expected: 7, got: 6 })
        ));
    }

    #[test]
    fn parse_rejects_unknown_word() {
        let mut words: Vec<String> = (0..7).map(|_| "abandon".to_string()).collect();
        words[3] = "notabip39word".to_string();
        assert!(matches!(Phrase::parse(&words), Err(CryptoError::UnknownWord(_))));
    }
}
