//! Shared application state injected into every handler.

use std::sync::Arc;

use crate::store::Store;

/// Cloneable handle to the Portal's dependencies. `Arc<dyn Store>` lets us swap the
/// in-memory store for a Postgres one (Phase 1) without touching handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
}
