//! NIL VPN crypto core.
//!
//! Phase 0 implements anonymous-account derivation (architecture spec §7.5). Later
//! phases add the PQ hybrid PSK (ML-KEM-1024 + Classic McEliece) and RA-TLS helpers.
//!
//! ## Anonymous account derivation (see ADR-0001)
//! The 7-word recovery phrase is the **root** of the account: 7 words drawn from the
//! BIP39 English wordlist (≈77 bits of entropy — stronger than Mullvad's ~53-bit
//! account numbers, but honestly below a 128-bit bar; recorded in ADR-0001). The
//! 256-bit account secret is *derived from* the phrase via HKDF-SHA256, and the
//! account number is `SHA-256(secret)`. Recovery reconstructs everything from the
//! phrase alone, gated by an independent one-time recovery code.
//!
//! This is deliberately NOT a checksummed BIP39 mnemonic — 7 words is not a valid
//! BIP39 length — so we use the wordlist only, never claim BIP39 compatibility.

pub mod account;
pub mod psk;
pub mod token;
mod error;

pub use error::CryptoError;
pub use psk::{PqCiphertexts, PqInitiator, PqOffer, Psk, PskError, responder_encapsulate};
pub use token::{Issuer, TokenError, TokenRequest, Verifier};
