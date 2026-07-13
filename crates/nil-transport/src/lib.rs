//! The transport layer — the most important boundary in NIL VPN.
//!
//! Everything hinges on one trait: [`Transport`]. Transports are interchangeable; the
//! rest of the system never knows or cares which one is active. That is what makes the
//! obfuscation cascade (MASQUE → AmneziaWG → wstunnel → REALITY) possible, and it is a
//! hard architectural invariant — the `Transport` trait is the ONLY seam between the
//! engine and any tunnel implementation.
//!
//! Debug builds also expose an in-memory `loopback` echo transport for tests and mocked client
//! flows. It is compiled out when debug assertions are disabled.

// Development transports and trust-bypass instrumentation must not be present in an optimized
// production artifact. The E2E harness uses the custom optimized `e2e` profile, which deliberately
// keeps debug assertions enabled, so these guards stay strong without sacrificing realistic
// optimization in CI.
#[cfg(all(not(debug_assertions), feature = "dev-fallbacks"))]
compile_error!(
    "nil-transport: `dev-fallbacks` is development-only and cannot be compiled without debug assertions"
);
#[cfg(all(not(debug_assertions), feature = "synthetic-attest"))]
compile_error!(
    "nil-transport: `synthetic-attest` is development-only and cannot be compiled without debug assertions"
);
#[cfg(all(not(debug_assertions), feature = "dev-trace"))]
compile_error!(
    "nil-transport: `dev-trace` is development-only and cannot be compiled without debug assertions"
);
#[cfg(all(
    any(feature = "wstunnel", feature = "reality"),
    not(feature = "dev-fallbacks")
))]
compile_error!(
    "nil-transport: internal fallback features must be selected through the explicit `dev-fallbacks` feature"
);

#[cfg(feature = "dev-fallbacks")]
pub mod cascade;
pub mod connectip;
#[cfg(debug_assertions)]
pub mod loopback;
#[cfg(feature = "masque")]
pub mod masque;
mod transport;
pub mod udpip;
// The trust-split onion now PQ-keys the exit hop (`PqWgTransport::wrap_session`), so it depends on
// the pqwg core, not just masque.
#[cfg(feature = "dev-fallbacks")]
pub mod amneziawg;
#[cfg(feature = "pqwg")]
pub mod path;
#[cfg(feature = "pqwg")]
pub mod pqwg;
#[cfg(feature = "dev-fallbacks")]
pub mod reality;
#[cfg(feature = "dev-fallbacks")]
pub mod wstunnel;
// Network-aware selector: probe the path, then order the cascade fast-first or resistant-first.
// Pulls the resistant rungs (reality + wstunnel) so a consumer enabling `selector` gets the whole
// resistant set compiled, not just the trait.
#[cfg(feature = "selector")]
pub mod selector;
// Maybenot/DAITA traffic-analysis defense driver (experimental): drives padding state machines over
// the CONNECT-IP padding channel. Off by default; the defense-machine profile + efficacy are a
// separate research step (see the module docs).
#[cfg(feature = "daita")]
pub mod daita;

#[cfg(feature = "dev-fallbacks")]
pub use amneziawg::{AmneziaWgConfig, AmneziaWgTransport, ObfsParams};
#[cfg(feature = "masque")]
pub use masque::{MasqueConfig, MasqueTransport};
#[cfg(feature = "pqwg")]
pub use path::PathTransport;
#[cfg(feature = "pqwg")]
pub use pqwg::{PqWgCore, PqWgTransport, WgKeypair, WgStep};
#[cfg(feature = "dev-fallbacks")]
pub use reality::{
    derive_auth_id, read_record_from, write_record_to, RealityConfig, RealityTransport,
    REALITY_AUTH_ID_LEN,
};
#[cfg(feature = "selector")]
pub use selector::{NetworkProbe, PathClass, Selector, SelectorTransport, UdpReachabilityProbe};
pub use transport::Transport;
#[cfg(feature = "dev-fallbacks")]
pub use wstunnel::{derive_request_path, WstunnelConfig, WstunnelTransport};
