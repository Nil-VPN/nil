//! Crypto-layer errors. Pure, no I/O.

/// Errors from account-credential handling.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("recovery phrase must be {expected} words, got {got}")]
    WrongLength { expected: usize, got: usize },
    #[error("unknown word in recovery phrase: {0:?}")]
    UnknownWord(String),
}
