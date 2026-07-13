//! The v2 account recovery phrase and its underlying entropy.
//!
//! A phrase is a standard 12-word BIP39 English mnemonic: 128 bits of entropy plus
//! its BIP39 checksum. The phrase is the sole account root, so parsing delegates
//! checksum validation to the audited `bip39` crate before deriving account material.

use bip39::{Language, Mnemonic};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::PHRASE_WORDS;
use crate::error::CryptoError;

const ENTROPY_BYTES: usize = 16;

/// The phrase's underlying 128-bit entropy. Zeroized on drop.
#[derive(Clone)]
pub(crate) struct PhraseEntropy {
    bytes: [u8; ENTROPY_BYTES],
}

impl PhraseEntropy {
    /// Draw fresh 128-bit entropy from the injected CSPRNG.
    pub(crate) fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; ENTROPY_BYTES];
        rng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    #[cfg(test)]
    fn from_bytes(bytes: [u8; ENTROPY_BYTES]) -> Self {
        Self { bytes }
    }

    /// Canonical 16-byte entropy — the HKDF input keying material.
    pub(crate) fn ikm(&self) -> [u8; ENTROPY_BYTES] {
        self.bytes
    }
}

impl Drop for PhraseEntropy {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A checksum-protected 12-word BIP39 English mnemonic. It is the sole account root.
#[derive(Clone)]
pub struct Phrase {
    words: [String; PHRASE_WORDS],
}

impl Phrase {
    /// Render 128-bit entropy as a canonical BIP39 English mnemonic.
    pub(crate) fn from_entropy(entropy: &PhraseEntropy) -> Self {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy.bytes)
            .expect("128-bit entropy is always a valid BIP39 size");
        Self::from_mnemonic(&mnemonic)
    }

    fn from_mnemonic(mnemonic: &Mnemonic) -> Self {
        debug_assert_eq!(mnemonic.word_count(), PHRASE_WORDS);
        let mut source = mnemonic.words();
        let words = std::array::from_fn(|_| {
            source
                .next()
                .expect("a 12-word mnemonic contains exactly 12 words")
                .to_owned()
        });
        Self { words }
    }

    /// Parse and validate a BIP39 English mnemonic (case-insensitive, trimmed).
    ///
    /// Besides validating the word count and English wordlist, this delegates checksum
    /// validation to [`Mnemonic::parse_in_normalized`].
    pub fn parse(input: &[String]) -> Result<Self, CryptoError> {
        if input.len() != PHRASE_WORDS {
            return Err(CryptoError::WrongLength {
                expected: PHRASE_WORDS,
                got: input.len(),
            });
        }

        let english = Language::English.word_list();
        let mut normalized = Vec::with_capacity(PHRASE_WORDS);
        for word in input {
            let word = word.trim().to_lowercase();
            if english.binary_search(&word.as_str()).is_err() {
                return Err(CryptoError::UnknownWord(word));
            }
            normalized.push(word);
        }

        let sentence = normalized.join(" ");
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &sentence)
            .map_err(|_| CryptoError::InvalidMnemonicChecksum)?;
        Ok(Self::from_mnemonic(&mnemonic))
    }

    /// Recover the entropy from the already validated mnemonic.
    pub(crate) fn to_entropy(&self) -> Result<PhraseEntropy, CryptoError> {
        let sentence = self.words.join(" ");
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &sentence)
            .map_err(|_| CryptoError::InvalidMnemonicChecksum)?;
        let (mut entropy, len) = mnemonic.to_entropy_array();
        if len != ENTROPY_BYTES {
            entropy.zeroize();
            return Err(CryptoError::WrongLength {
                expected: ENTROPY_BYTES,
                got: len,
            });
        }
        let mut bytes = [0u8; ENTROPY_BYTES];
        bytes.copy_from_slice(&entropy[..ENTROPY_BYTES]);
        entropy.zeroize();
        Ok(PhraseEntropy { bytes })
    }

    pub fn words(&self) -> &[String; PHRASE_WORDS] {
        &self.words
    }

    pub fn to_vec(&self) -> Vec<String> {
        self.words.to_vec()
    }
}

impl Drop for Phrase {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip39_zero_entropy_vector_matches() {
        let entropy = PhraseEntropy::from_bytes([0u8; ENTROPY_BYTES]);
        let phrase = Phrase::from_entropy(&entropy);
        let expected: Vec<String> = ["abandon"; 11]
            .into_iter()
            .chain(["about"])
            .map(str::to_string)
            .collect();
        assert_eq!(phrase.to_vec(), expected);
    }

    #[test]
    fn phrase_roundtrips_through_bip39() {
        let entropy = PhraseEntropy::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let phrase = Phrase::from_entropy(&entropy);
        assert_eq!(phrase.words().len(), PHRASE_WORDS);
        assert_eq!(phrase.to_entropy().unwrap().ikm(), entropy.ikm());
    }

    #[test]
    fn parse_normalizes_case_and_whitespace() {
        let entropy = PhraseEntropy::from_bytes([0x42; ENTROPY_BYTES]);
        let phrase = Phrase::from_entropy(&entropy);
        let shouty: Vec<String> = phrase
            .words()
            .iter()
            .map(|word| format!("  {} ", word.to_uppercase()))
            .collect();
        let reparsed = Phrase::parse(&shouty).expect("normalized parse");
        assert_eq!(reparsed.to_entropy().unwrap().ikm(), entropy.ikm());
    }

    #[test]
    fn parse_rejects_wrong_count() {
        let eleven = vec!["abandon".to_owned(); 11];
        assert!(matches!(
            Phrase::parse(&eleven),
            Err(CryptoError::WrongLength {
                expected: PHRASE_WORDS,
                got: 11
            })
        ));
    }

    #[test]
    fn parse_rejects_unknown_word() {
        let mut words = vec!["abandon".to_owned(); PHRASE_WORDS];
        words[3] = "notabip39word".to_owned();
        assert!(matches!(
            Phrase::parse(&words),
            Err(CryptoError::UnknownWord(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        let words = vec!["abandon".to_owned(); PHRASE_WORDS];
        assert!(matches!(
            Phrase::parse(&words),
            Err(CryptoError::InvalidMnemonicChecksum)
        ));
    }
}
