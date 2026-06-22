//! The transport layer — the most important boundary in NIL VPN.
//!
//! Everything hinges on one trait: [`Transport`]. Transports are interchangeable; the
//! rest of the system never knows or cares which one is active. That is what makes the
//! obfuscation cascade (MASQUE → AmneziaWG → wstunnel → REALITY) possible, and it is a
//! hard architectural invariant — the `Transport` trait is the ONLY seam between the
//! engine and any tunnel implementation.
//!
//! Phase 0 ships exactly one implementation: an in-memory [`loopback`] echo transport
//! used by tests and the client's mocked connect/disconnect state machine. The real
//! MASQUE/`quiche` implementation lands in Phase 1.

mod transport;
pub mod cascade;
pub mod connectip;
pub mod loopback;
pub mod udpip;
#[cfg(feature = "masque")]
pub mod masque;
#[cfg(feature = "masque")]
pub mod path;
#[cfg(feature = "pqwg")]
pub mod pqwg;

pub use transport::Transport;
#[cfg(feature = "masque")]
pub use masque::{MasqueConfig, MasqueTransport};
#[cfg(feature = "masque")]
pub use path::PathTransport;
#[cfg(feature = "pqwg")]
pub use pqwg::{PqWgCore, PqWgTransport, WgKeypair, WgStep};
