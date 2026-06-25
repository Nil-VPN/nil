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
// The trust-split onion now PQ-keys the exit hop (`PqWgTransport::wrap_session`), so it depends on
// the pqwg core, not just masque.
#[cfg(feature = "pqwg")]
pub mod path;
#[cfg(feature = "pqwg")]
pub mod amneziawg;
#[cfg(feature = "pqwg")]
pub mod pqwg;
#[cfg(feature = "wstunnel")]
pub mod wstunnel;
#[cfg(feature = "reality")]
pub mod reality;
// Network-aware selector: probe the path, then order the cascade fast-first or resistant-first.
// Pulls the resistant rungs (reality + wstunnel) so a consumer enabling `selector` gets the whole
// resistant set compiled, not just the trait.
#[cfg(feature = "selector")]
pub mod selector;

pub use transport::Transport;
#[cfg(feature = "masque")]
pub use masque::{MasqueConfig, MasqueTransport};
#[cfg(feature = "pqwg")]
pub use path::PathTransport;
#[cfg(feature = "pqwg")]
pub use amneziawg::{AmneziaWgConfig, AmneziaWgTransport, ObfsParams};
#[cfg(feature = "pqwg")]
pub use pqwg::{PqWgCore, PqWgTransport, WgKeypair, WgStep};
#[cfg(feature = "wstunnel")]
pub use wstunnel::{derive_request_path, WstunnelConfig, WstunnelTransport};
#[cfg(feature = "reality")]
pub use reality::{
    derive_auth_id, read_record_from, write_record_to, RealityConfig, RealityTransport,
    REALITY_AUTH_ID_LEN,
};
#[cfg(feature = "selector")]
pub use selector::{NetworkProbe, PathClass, Selector, SelectorTransport, UdpReachabilityProbe};
