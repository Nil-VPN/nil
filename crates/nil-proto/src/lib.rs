//! Wire formats and API DTOs for NIL VPN.
//!
//! Everything that crosses a process boundary (client ↔ Portal REST, capsule types,
//! Coordinator RPC shapes) is defined here as serde types, so the client and the
//! services serialize from one source of truth. Pure data — no logic, no crypto, no
//! I/O — which keeps this crate safe for the Tauri client to depend on directly.

pub mod account;
pub mod path;
pub mod token;
