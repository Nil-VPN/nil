//! NIL VPN crypto core.
//!
//! Phase 0 implements anonymous-account derivation (architecture spec §7.5). Later
//! phases add the PQ hybrid PSK (ML-KEM-1024 + Classic McEliece) and RA-TLS helpers.
//!
//! ## Anonymous account derivation (see ADR-0001)
//! The v2 recovery phrase is the **sole root** of an account: a standard 12-word
//! BIP39 English mnemonic containing 128 bits of entropy and a checksum. A 256-bit
//! account secret is derived from that entropy with versioned, domain-separated
//! HKDF-SHA256 labels, and the account number is `SHA-256(domain || secret)`.
//! The phrase-derived Ed25519 key authenticates the account without revealing the
//! phrase; registration uses a domain-separated proof of possession.

pub mod account;
mod error;
pub mod psk;
pub mod token;
pub mod translog;

pub use error::CryptoError;
pub use psk::{responder_encapsulate, PqCiphertexts, PqInitiator, PqOffer, Psk, PskError};
pub use token::{key_epoch, Issuer, TokenError, TokenRequest, Verifier, LEGACY_EPOCH};
