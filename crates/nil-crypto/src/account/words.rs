//! The vendored BIP39 English wordlist (2048 words, sorted ascending).
//!
//! The file is the exact list from the BIP39 spec. We use it as a stable, vetted,
//! memorable word table — NIL's 7-word phrase is not a checksummed BIP39 mnemonic
//! (see ADR-0001), so we never parse it as one.

use std::sync::OnceLock;

const RAW: &str = include_str!("../wordlist/english.txt");

/// The wordlist as a slice of `'static` words. Built once, lazily.
pub(crate) fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| RAW.lines().collect())
}

/// The word at a given 11-bit index (`0..2048`).
pub(crate) fn word_at(index: u16) -> &'static str {
    words()[index as usize]
}

/// Reverse lookup. The list is sorted, so binary search is correct and O(log n).
pub(crate) fn index_of(word: &str) -> Option<u16> {
    words().binary_search(&word).ok().map(|i| i as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_2048_sorted_words() {
        let w = words();
        assert_eq!(w.len(), 2048, "BIP39 English wordlist must be exactly 2048 words");
        assert_eq!(w[0], "abandon");
        assert_eq!(w[2047], "zoo");
        assert!(w.windows(2).all(|p| p[0] < p[1]), "wordlist must be strictly sorted");
    }

    #[test]
    fn index_roundtrips() {
        for &probe in &[0u16, 1, 1000, 2047] {
            let w = word_at(probe);
            assert_eq!(index_of(w), Some(probe));
        }
        assert_eq!(index_of("notarealbip39word"), None);
    }
}
