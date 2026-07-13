//! The Coordinator's HTTP API (architecture spec §6, §7, §8): redeem a Privacy Pass token for
//! a trust-split path, and publish pinned measurements. This is the **verifier / policy** side
//! of Pillar 4 — it verifies tokens with the issuer's *public* key (never mints them), keeps
//! only an identity-free permanent nullifier plus a short-lived encrypted redemption result, and
//! selects operator/jurisdiction-diverse paths. It never imports the Portal (issuer) and never
//! sees traffic.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use nil_proto::path::{MeasurementsResponse, PathResponse, PinnedMeasurement, Tee};
use nil_proto::token::RedeemRequest;
use zeroize::Zeroizing;

use crate::client_ip::ClientIp;
use crate::config::{from_hex, CoordConfig};
use crate::nullifier::{CommitOutcome, MemoryNullifierStore, NullifierStore};
use crate::pathsel::{Role, SelectedHop};
use crate::ratelimit::RateLimiter;

/// Hard cap on a `/v1/redeem` request body. A redeem body is two short hex strings (a token
/// message + an RSA blind-signature token); a few KiB is generous. The cap bounds the work an
/// unauthenticated caller can force before the (relatively expensive) RSA-verify + fsync runs.
const REDEEM_BODY_LIMIT: usize = 16 * 1024;

/// Per-IP redeem attempts allowed per [`REDEEM_RATE_WINDOW`]. RSA-verify plus an fsync under one
/// mutex is a cheap DoS, so cap how fast a single source can drive it. A legitimate client redeems
/// once per session, so this is comfortably above normal use.
const REDEEM_RATE_MAX: u32 = 30;
/// Fixed window for the per-IP redeem rate limit.
const REDEEM_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Shared state: immutable config plus the authoritative redemption ledger.
#[derive(Clone)]
pub struct CoordState {
    pub cfg: Arc<CoordConfig>,
    /// Permanent spent token messages plus a grant-lifetime encrypted first response. Identity-free
    /// and durable across restarts (file-backed, or clustered Postgres in production); a volatile
    /// ledger would re-permit a double-spend of every already-redeemed token. Behind the
    /// [`NullifierStore`] trait so the backend is swappable.
    pub nullifiers: Arc<dyn NullifierStore>,
    /// Per-IP abuse limiter for `/v1/redeem`. PII-free: a transient per-IP counter that resets each
    /// window and is never logged or persisted (mirrors the issuer's limiter in `nil-portal`).
    pub limiter: Arc<RateLimiter>,
}

impl CoordState {
    /// Development/test state with a volatile in-memory redemption ledger.
    pub fn new(cfg: Arc<CoordConfig>) -> Self {
        let result_key = *cfg.redemption_result_key;
        Self {
            cfg,
            nullifiers: Arc::new(MemoryNullifierStore::new(result_key)),
            limiter: Arc::new(RateLimiter::new(REDEEM_RATE_MAX, REDEEM_RATE_WINDOW)),
        }
    }

    /// Production state with a caller-provided durable redemption ledger.
    pub fn with_nullifiers(cfg: Arc<CoordConfig>, nullifiers: Arc<dyn NullifierStore>) -> Self {
        Self {
            cfg,
            nullifiers,
            limiter: Arc::new(RateLimiter::new(REDEEM_RATE_MAX, REDEEM_RATE_WINDOW)),
        }
    }
}

pub fn router(state: CoordState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/v1/redeem",
            // Bound the redeem body so an unauthenticated caller can't force buffering of a large
            // payload before the (relatively expensive) RSA-verify + fsync runs.
            post(redeem).layer(DefaultBodyLimit::max(REDEEM_BODY_LIMIT)),
        )
        .route("/v1/measurements", get(measurements))
        .with_state(state)
}

#[derive(Debug, PartialEq)]
pub enum RedeemError {
    /// No issuer public key configured — redemption is disabled.
    NotConfigured,
    /// The token message or signature wasn't valid hex.
    Malformed,
    /// The token signature didn't verify under the issuer's public key.
    BadToken,
    /// The token is permanently spent and no replayable result remains.
    AlreadyRedeemed,
    /// The nullifier could not be durably recorded — fail closed (grant nothing) rather than
    /// risk a double-spend on the next restart.
    Unavailable,
    /// No operator/jurisdiction-diverse path of the requested length exists right now.
    NoPath,
}

/// Core redemption logic (HTTP-free, unit-tested): verify the token, atomically commit or replay
/// its first response, and select a trust-split path. Returns the path only on success.
pub async fn redeem_logic(
    state: &CoordState,
    req: &RedeemRequest,
) -> Result<PathResponse, RedeemError> {
    let verifier = state
        .cfg
        .verifier
        .as_ref()
        .ok_or(RedeemError::NotConfigured)?;
    let msg = from_hex(&req.msg).ok_or(RedeemError::Malformed)?;
    let token = from_hex(&req.token).ok_or(RedeemError::Malformed)?;
    let now = nil_core::grant::now_unix_secs_for_expiry();
    if nil_crypto::token::is_v2_message(&msg)
        && !nil_crypto::token::v2_message_is_current(&msg, now)
    {
        return Err(RedeemError::BadToken);
    }
    if !nil_crypto::token::is_v2_message(&msg) {
        // The migration exception is for the historical 32-byte random-message format only. A
        // retained issuer key can mathematically sign arbitrary bytes; without this shape check a
        // newly issued non-NTV2 message of another length could inherit the legacy no-expiry path.
        if msg.len() != 32 || !legacy_token_allowed(now) {
            return Err(RedeemError::BadToken);
        }
    }

    // Verify AND learn the epoch (issuer key generation) that signed this token. A token whose
    // epoch key is no longer held returns None → BadToken: this rejection of retired-epoch tokens
    // is exactly what makes dropping that epoch's nullifier partition safe (a token that can't
    // verify can never re-enter the set). The epoch is DERIVED here, never sent on the wire — the
    // RedeemRequest stays {msg, token}, so unlinkability is unchanged (Pillar 4).
    let epoch = verifier
        .verify_with_epoch(&token, &msg)
        .ok_or(RedeemError::BadToken)?;

    // Complete every fallible path/grant step before spending the token. A transient no-path,
    // malformed registry endpoint, entropy failure, or signer failure must leave a paid anonymous
    // pass retryable. The material stays private in this request until the durable single-use
    // commit below succeeds; concurrent requests can both precompute, but only one can win the
    // atomic nullifier insert and receive its response.
    let mut selected = state
        .cfg
        .registry
        .select_path(state.cfg.path_hops)
        .ok_or(RedeemError::NoPath)?;
    let grant_now = nil_core::grant::now_unix_secs();
    if grant_now == 0 {
        return Err(RedeemError::Unavailable);
    }
    let replay_until = grant_now
        .checked_add(state.cfg.grant_ttl.as_secs())
        .ok_or(RedeemError::Unavailable)?;
    if let Some(signer) = state.cfg.grant_signer.as_ref() {
        attach_grants(
            &mut selected,
            signer,
            &state.cfg.grant_realm,
            state.cfg.grant_ttl,
            grant_now,
        )
        .map_err(|e| {
            tracing::error!("grant mint failed: {e}");
            RedeemError::Unavailable
        })?;
    }

    let proposed_path = PathResponse {
        hops: selected.into_iter().map(|selected| selected.hop).collect(),
    };
    let proposed_json = Zeroizing::new(serde_json::to_vec(&proposed_path).map_err(|error| {
        tracing::error!("serialize redemption result: {error}");
        RedeemError::Unavailable
    })?);

    // One authoritative operation permanently records the anonymous nullifier and preserves the
    // exact first response as short-lived AEAD ciphertext. A concurrent/lost-response retry gets
    // that ciphertext's plaintext, never its independently precomputed losing grants.
    //
    // Key on the LOWERCASE HEX OF THE DECODED BYTES, never the raw request string: the same token
    // submitted as "ab.." and "AB.." decodes to identical bytes, so it must hit the same nullifier.
    // Keying on the raw string would let an attacker re-spend one token by flipping hex case.
    let nullifier_key = to_hex(&msg);
    let outcome = state
        .nullifiers
        .commit_or_replay(
            epoch,
            &nullifier_key,
            replay_until,
            &proposed_json,
            grant_now,
        )
        .await
        .map_err(|error| {
            tracing::error!("redemption commit failed: {error}");
            RedeemError::Unavailable
        })?;
    match outcome {
        CommitOutcome::Granted {
            response,
            newly_committed,
        } => {
            // Operational visibility only: warn once when the set crosses the soft size threshold.
            // PII-free operational visibility: only the set size is logged — never token bytes,
            // key, epoch, or any user/account count. Automatic epoch GC is intentionally disabled
            // until fleet-coordinated retirement exists, so this is alerting, not a cap.
            if newly_committed {
                if let Some(n) = state.nullifiers.approx_len().await {
                    if crate::nullifier::should_warn(n, state.cfg.nullifier_warn_at) {
                        tracing::warn!(
                            nullifier_set_size = n,
                            "permanent redemption ledger crossed its soft size threshold; automatic epoch \
                             GC is disabled until fleet-coordinated retirement exists"
                        );
                    }
                }
            }
            serde_json::from_slice(&response).map_err(|error| {
                tracing::error!("stored redemption result is invalid: {error}");
                RedeemError::AlreadyRedeemed
            })
        }
        CommitOutcome::AlreadySpent => Err(RedeemError::AlreadyRedeemed),
    }
}

/// Legacy 32-byte random token messages have no embedded expiry. Production must set the absolute
/// NW_LEGACY_TOKEN_CUTOFF migration cutoff; tests retain legacy compatibility so protocol fixtures
/// remain useful. Missing cutoff is intentionally fail-closed outside tests.
fn legacy_token_allowed(now: u64) -> bool {
    if cfg!(test) {
        return true;
    }
    std::env::var("NW_LEGACY_TOKEN_CUTOFF")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|cutoff| now <= cutoff)
}

fn attach_grants(
    selected: &mut [SelectedHop],
    signer: &nil_core::grant::GrantSigningKey,
    realm: &str,
    ttl: std::time::Duration,
    now: u64,
) -> anyhow::Result<()> {
    let path_neighbors = selected
        .iter()
        .enumerate()
        .map(|(index, selected_hop)| {
            let previous_hop = index
                .checked_sub(1)
                .and_then(|previous_index| selected.get(previous_index))
                .map(|previous| {
                    previous.hop.host.parse::<std::net::Ipv4Addr>().map_err(|_| {
                        anyhow::anyhow!(
                            "selected previous-hop endpoint {} is not canonical IPv4 and cannot be bound into NWG2",
                            previous.hop.host
                        )
                    })
                })
                .transpose()?;
            let next_hop = if index + 1 < selected.len() {
                let next = selected
                    .get(index + 1)
                    .ok_or_else(|| anyhow::anyhow!("intermediate grant has no selected next hop"))?;
                let ip = next.hop.host.parse::<std::net::Ipv4Addr>().map_err(|_| {
                    anyhow::anyhow!(
                        "selected next-hop endpoint {}:{} is not canonical IPv4 and cannot be bound into NWG2",
                        next.hop.host,
                        next.hop.port
                    )
                })?;
                Some(std::net::SocketAddrV4::new(ip, next.hop.port))
            } else {
                None
            };
            match (selected_hop.intended_role, previous_hop, next_hop) {
                (Role::Entry, None, Some(next)) => Ok((None, Some(next))),
                (Role::Middle, Some(previous), Some(next)) => {
                    Ok((Some(previous), Some(next)))
                }
                (Role::Exit, previous, None) => Ok((previous, None)),
                _ => anyhow::bail!("selected path role ordering is invalid"),
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    for (selected_hop, (previous_hop, next_hop)) in selected.iter_mut().zip(path_neighbors) {
        let hop = &mut selected_hop.hop;
        let measurement = nil_core::grant::from_hex(hop.measurement.trim())
            .ok_or_else(|| anyhow::anyhow!("node measurement is not hex"))?;
        let measurement: [u8; 48] = measurement
            .try_into()
            .map_err(|_| anyhow::anyhow!("node measurement must be exactly 48 bytes"))?;
        let tls_spki_sha256 = hop
            .tls_spki_sha256
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("node TLS SPKI digest is not pinned"))?;
        let tls_spki_sha256: [u8; 32] = nil_core::grant::from_hex(tls_spki_sha256)
            .ok_or_else(|| anyhow::anyhow!("node TLS SPKI digest is not hex"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("node TLS SPKI digest must be exactly 32 bytes"))?;
        let audience = nil_core::grant::GrantAudience::new(
            realm,
            selected_hop.node_id.clone(),
            grant_role(selected_hop.intended_role),
            nil_core::grant::GrantTransport::Masque,
            core_tee(hop.tee),
            measurement,
            tls_spki_sha256,
            previous_hop,
            next_hop,
        )?;
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| anyhow::anyhow!("grant nonce entropy"))?;
        let grant = nil_core::grant::mint(signer, &audience, nonce, ttl, now)?;
        hop.grant = Some(nil_core::grant::to_hex(&grant.token));
        hop.grant_nonce = Some(nil_core::grant::to_hex(&grant.nonce));
    }
    Ok(())
}

fn grant_role(role: Role) -> nil_core::grant::GrantRole {
    match role {
        Role::Entry => nil_core::grant::GrantRole::Entry,
        Role::Middle => nil_core::grant::GrantRole::Middle,
        Role::Exit => nil_core::grant::GrantRole::Exit,
    }
}

fn core_tee(tee: Tee) -> nil_core::Tee {
    match tee {
        Tee::SevSnp => nil_core::Tee::SevSnp,
        Tee::Tdx => nil_core::Tee::Tdx,
    }
}

/// Lowercase-hex encode (matches [`from_hex`]'s accepted lowercase form, so a decode→encode
/// round-trip is the canonical key form). Used for the nullifier key only — no identity.
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn redeem(
    ClientIp(client_ip): ClientIp,
    State(state): State<CoordState>,
    Json(req): Json<RedeemRequest>,
) -> Result<Json<PathResponse>, StatusCode> {
    // Abuse control: cap redeem attempts per client IP before any RSA-verify/fsync work. The IP is
    // used transiently for the counter only — never stored, logged, or tied to an account.
    if !state.limiter.check(&client_ip.to_string()) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    match redeem_logic(&state, &req).await {
        Ok(path) => Ok(Json(path)),
        Err(RedeemError::NotConfigured) => Err(StatusCode::NOT_IMPLEMENTED),
        Err(RedeemError::Malformed) => Err(StatusCode::BAD_REQUEST),
        Err(RedeemError::BadToken) => Err(StatusCode::UNAUTHORIZED),
        Err(RedeemError::AlreadyRedeemed) => Err(StatusCode::CONFLICT),
        Err(RedeemError::Unavailable) => Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(RedeemError::NoPath) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn measurements(State(state): State<CoordState>) -> Json<MeasurementsResponse> {
    let mut seen: HashSet<String> = HashSet::new();
    let measurements = state
        .cfg
        .registry
        .nodes
        .iter()
        .filter(|n| seen.insert(n.measurement.clone()))
        .map(|n| PinnedMeasurement {
            tee: n.tee,
            measurement: n.measurement.clone(),
            source: None,
        })
        .collect();
    Json(MeasurementsResponse { measurements })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pathsel::NodeRegistry;
    use nil_crypto::{token, Issuer, Verifier};

    /// A coordinator state whose verifier matches a freshly-generated issuer, plus a valid
    /// `(msg, token)` minted by that issuer.
    fn state_and_token() -> (CoordState, RedeemRequest) {
        let issuer = Issuer::generate().unwrap();
        let pub_der = issuer.public_der().unwrap();
        let verifier = Verifier::from_public_der(&pub_der).unwrap();

        // Historical v1 tokens were exactly 32 random bytes. Keep the common success fixture in
        // that migration shape so successful-redemption tests do not accidentally exercise a
        // message format production now rejects.
        let msg = [0xab; 32].to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        let blind_sig = issuer.blind_sign(&req.blind_msg).unwrap();
        let tok = token::finalize(&pub_der, &req, &blind_sig).unwrap();

        let cfg = CoordConfig {
            addr: "127.0.0.1:9090".parse().unwrap(),
            registry: NodeRegistry::dev_default(),
            path_hops: 3,
            verifier: Some(verifier),
            nullifier_path: None,
            nullifier_dir: None,
            grant_signer: None,
            grant_realm: String::new(),
            grant_ttl: std::time::Duration::from_secs(300),
            redemption_result_key: Zeroizing::new([0x71; 32]),
            nullifier_warn_at: crate::config::DEFAULT_NULLIFIER_WARN_AT,
        };
        let redeem = RedeemRequest {
            msg: hex(&msg),
            token: hex(&tok),
        };
        (CoordState::new(Arc::new(cfg)), redeem)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A CoordConfig with a given (epoch-tagged) verifier and no persistence — for epoch/GC tests.
    fn cfg_with_verifier(verifier: Verifier) -> CoordConfig {
        CoordConfig {
            addr: "127.0.0.1:9090".parse().unwrap(),
            registry: NodeRegistry::dev_default(),
            path_hops: 3,
            verifier: Some(verifier),
            nullifier_path: None,
            nullifier_dir: None,
            grant_signer: None,
            grant_realm: String::new(),
            grant_ttl: std::time::Duration::from_secs(300),
            redemption_result_key: Zeroizing::new([0x72; 32]),
            nullifier_warn_at: crate::config::DEFAULT_NULLIFIER_WARN_AT,
        }
    }

    #[tokio::test]
    async fn valid_token_retry_returns_the_exact_first_path() {
        let (state, req) = state_and_token();
        // First redemption: a 3-hop trust-split path.
        let path = redeem_logic(&state, &req)
            .await
            .expect("valid token redeems");
        assert_eq!(path.hops.len(), 3);
        let replay = redeem_logic(&state, &req)
            .await
            .expect("live result is replayable");
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&path).unwrap()
        );
    }

    #[tokio::test]
    async fn retry_after_result_expiry_stays_spent_and_returns_no_replacement_path() {
        let (state, req) = state_and_token();
        redeem_logic(&state, &req)
            .await
            .expect("first redemption succeeds");
        assert_eq!(
            state
                .nullifiers
                .prune_expired_replays(u64::MAX)
                .await
                .unwrap(),
            1
        );
        assert!(matches!(
            redeem_logic(&state, &req).await,
            Err(RedeemError::AlreadyRedeemed)
        ));
        assert_eq!(state.nullifiers.approx_len().await, Some(1));
    }

    #[tokio::test]
    async fn configured_grant_signer_mints_audience_bound_per_hop_grants() {
        let (mut state, req) = state_and_token();
        let signer = nil_core::grant::GrantSigningKey::from_seed([0x37; 32]);
        let verifier =
            nil_core::grant::GrantVerifier::from_public_key(signer.public_key_bytes()).unwrap();
        let cfg = Arc::get_mut(&mut state.cfg).expect("state is uniquely owned");
        cfg.grant_signer = Some(signer);
        cfg.grant_realm = "nil-test".to_string();
        cfg.grant_ttl = std::time::Duration::from_secs(60);

        let path = redeem_logic(&state, &req)
            .await
            .expect("valid token redeems");
        let replay = redeem_logic(&state, &req)
            .await
            .expect("lost response retry succeeds");
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&path).unwrap(),
            "grants and nonces must be byte-for-byte stable on retry"
        );
        for (index, hop) in path.hops.iter().enumerate() {
            let token = nil_core::grant::from_hex(hop.grant.as_deref().expect("hop grant"))
                .expect("grant hex");
            let nonce = nil_core::grant::from_hex(hop.grant_nonce.as_deref().expect("hop nonce"))
                .expect("nonce hex");
            let measurement: [u8; 48] = nil_core::grant::from_hex(&hop.measurement)
                .expect("measurement hex")
                .try_into()
                .expect("48-byte measurement");
            let node = state
                .cfg
                .registry
                .nodes
                .iter()
                .find(|node| node.host == hop.host && node.port == hop.port)
                .expect("selected node remains in registry");
            let audience = nil_core::grant::GrantAudience::new(
                "nil-test",
                node.id.clone(),
                if index == 0 {
                    nil_core::grant::GrantRole::Entry
                } else if index + 1 == state.cfg.path_hops {
                    nil_core::grant::GrantRole::Exit
                } else {
                    nil_core::grant::GrantRole::Middle
                },
                nil_core::grant::GrantTransport::Masque,
                core_tee(hop.tee),
                measurement,
                nil_core::grant::from_hex(
                    hop.tls_spki_sha256
                        .as_deref()
                        .expect("registry TLS SPKI pin"),
                )
                .expect("TLS SPKI hash hex")
                .try_into()
                .expect("32-byte TLS SPKI hash"),
                index.checked_sub(1).map(|previous_index| {
                    path.hops[previous_index]
                        .host
                        .parse()
                        .expect("dev registry uses exact IPv4")
                }),
                path.hops.get(index + 1).map(|next| {
                    std::net::SocketAddrV4::new(
                        next.host.parse().expect("dev registry uses exact IPv4"),
                        next.port,
                    )
                }),
            )
            .unwrap();
            let verified = nil_core::grant::verify(
                &token,
                &verifier,
                &audience,
                nil_core::grant::now_unix_secs(),
            )
            .expect("grant verifies");
            assert_eq!(verified.nonce.as_slice(), nonce.as_slice());
        }
    }

    #[tokio::test]
    async fn concurrent_redemptions_return_one_authoritative_grant_set() {
        let (mut state, req) = state_and_token();
        let cfg = Arc::get_mut(&mut state.cfg).expect("state is uniquely owned");
        cfg.grant_signer = Some(nil_core::grant::GrantSigningKey::from_seed([0x38; 32]));
        cfg.grant_realm = "nil-test".to_string();
        cfg.grant_ttl = std::time::Duration::from_secs(60);

        let (left, right) = tokio::join!(redeem_logic(&state, &req), redeem_logic(&state, &req));
        let left = left.expect("one concurrent redemption result");
        let right = right.expect("the loser replays the winner");
        assert_eq!(
            serde_json::to_vec(&left).unwrap(),
            serde_json::to_vec(&right).unwrap(),
            "concurrent precomputation must expose only the committed grants/nonces"
        );
        assert_eq!(state.nullifiers.approx_len().await, Some(1));
    }

    #[tokio::test]
    async fn no_path_does_not_spend_the_token_and_a_retry_can_succeed() {
        let (state, req) = state_and_token();
        let hosts = state
            .cfg
            .registry
            .nodes
            .iter()
            .map(|node| node.host.clone())
            .collect::<Vec<_>>();
        for host in &hosts {
            state.cfg.registry.mark_down(host);
        }
        assert!(matches!(
            redeem_logic(&state, &req).await,
            Err(RedeemError::NoPath)
        ));
        assert_eq!(
            state.nullifiers.approx_len().await,
            Some(0),
            "path construction failure must not burn the pass"
        );

        for host in &hosts {
            state.cfg.registry.mark_up(host);
        }
        assert!(redeem_logic(&state, &req).await.is_ok());
    }

    #[tokio::test]
    async fn grant_construction_failure_does_not_spend_the_token() {
        let (mut state, req) = state_and_token();
        let cfg = Arc::get_mut(&mut state.cfg).expect("state is uniquely owned");
        cfg.grant_signer = Some(nil_core::grant::GrantSigningKey::from_seed([0x39; 32]));
        cfg.grant_realm = "nil-test".to_string();
        let entry = cfg
            .registry
            .nodes
            .iter_mut()
            .find(|node| node.role == crate::pathsel::Role::Entry)
            .expect("dev registry entry");
        let valid_entry_host = std::mem::replace(&mut entry.host, "entry.example.test".into());

        assert!(matches!(
            redeem_logic(&state, &req).await,
            Err(RedeemError::Unavailable)
        ));
        assert_eq!(
            state.nullifiers.approx_len().await,
            Some(0),
            "grant construction failure must not burn the pass"
        );

        Arc::get_mut(&mut state.cfg)
            .expect("state is uniquely owned")
            .registry
            .nodes
            .iter_mut()
            .find(|node| node.role == crate::pathsel::Role::Entry)
            .expect("dev registry entry")
            .host = valid_entry_host;
        assert!(redeem_logic(&state, &req).await.is_ok());
    }

    #[tokio::test]
    async fn legacy_migration_accepts_only_the_historical_32_byte_message_shape() {
        let issuer = Issuer::generate().unwrap();
        let public_der = issuer.public_der().unwrap();
        let verifier = Verifier::from_public_der(&public_der).unwrap();
        let state = CoordState::new(Arc::new(cfg_with_verifier(verifier)));

        for message in [vec![0x31; 31], vec![0x33; 33]] {
            let blind = token::blind(&public_der, &message).unwrap();
            let signature = issuer.blind_sign(&blind.blind_msg).unwrap();
            let finalized = token::finalize(&public_der, &blind, &signature).unwrap();
            let request = RedeemRequest {
                msg: hex(&message),
                token: hex(&finalized),
            };
            assert!(matches!(
                redeem_logic(&state, &request).await,
                Err(RedeemError::BadToken)
            ));
        }
        assert_eq!(state.nullifiers.approx_len().await, Some(0));
    }

    #[tokio::test]
    async fn encrypted_grant_result_replays_exactly_across_a_coordinator_restart() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nil-coord-nullifier-{}-{}.log",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);

        // The same config (and thus the same token verifier) persists across the restart; only
        // the authoritative redemption ledger is reloaded from disk.
        let (mut state0, req) = state_and_token();
        let mutable_cfg = Arc::get_mut(&mut state0.cfg).expect("state owns its config");
        mutable_cfg.grant_signer = Some(nil_core::grant::GrantSigningKey::from_seed([0x41; 32]));
        mutable_cfg.grant_realm = "nil-restart-test".to_string();
        mutable_cfg.grant_ttl = std::time::Duration::from_secs(60);
        let cfg = state0.cfg.clone();
        drop(state0);

        // Boot 1: file-backed ledger. First redemption returns per-hop bearer grants.
        let key = *cfg.redemption_result_key;
        let now = nil_core::grant::now_unix_secs_for_expiry();
        let boot1 = CoordState::with_nullifiers(
            cfg.clone(),
            Arc::new(crate::nullifier::FileNullifierStore::open_flat(&path, key, now).unwrap()),
        );
        let first = redeem_logic(&boot1, &req)
            .await
            .expect("first redemption succeeds");
        assert!(first.hops.iter().all(|hop| hop.grant.is_some()));
        drop(boot1); // simulate a Coordinator crash/restart

        // Boot 2: the same key decrypts the exact first response after an ambiguous crash/loss.
        let boot2 = CoordState::with_nullifiers(
            cfg,
            Arc::new(crate::nullifier::FileNullifierStore::open_flat(&path, key, now).unwrap()),
        );
        let replay = redeem_logic(&boot2, &req)
            .await
            .expect("live result survives restart");
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&first).unwrap(),
            "restart retry returns the originally committed path"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Primitive safety after FLEET-WIDE retirement: once every verifier has stopped accepting key
    /// A, deleting A's partition cannot reintroduce a spend. This does not authorize replica-local
    /// startup GC; rolling deployment needs shared retirement state and grace first.
    #[tokio::test]
    async fn fleetwide_retired_key_partition_cannot_re_spend_after_explicit_gc() {
        use std::collections::BTreeSet;

        // A token minted under issuer key A.
        let issuer_a = Issuer::generate().unwrap();
        let pk_a = issuer_a.public_der().unwrap();
        let ea = nil_crypto::key_epoch(&pk_a);
        let msg = b"gc-safety-token-nonce-0123456789".to_vec();
        let req = token::blind(&pk_a, &msg).unwrap();
        let tok =
            token::finalize(&pk_a, &req, &issuer_a.blind_sign(&req.blind_msg).unwrap()).unwrap();
        let redeem = RedeemRequest {
            msg: hex(&msg),
            token: hex(&tok),
        };

        // One epoch-partitioned nullifier store shared across the rotation.
        let nullifiers: Arc<dyn NullifierStore> = Arc::new(
            crate::nullifier::MemoryNullifierStore::epoch_partitioned([0x72; 32]),
        );

        // Boot 1: verifier holds key A. Redeem → recorded under key A's derived epoch; a replay is
        // rejected as a double-spend while key A is still held (the nullifier is present).
        let boot1 = CoordState::with_nullifiers(
            Arc::new(cfg_with_verifier(
                Verifier::from_public_ders(std::slice::from_ref(&pk_a)).unwrap(),
            )),
            nullifiers.clone(),
        );
        assert!(
            redeem_logic(&boot1, &redeem).await.is_ok(),
            "first redemption succeeds under key A"
        );
        assert_eq!(
            nullifiers.approx_len().await,
            Some(1),
            "nullifier recorded in key A's partition"
        );
        assert!(redeem_logic(&boot1, &redeem).await.is_ok());
        nullifiers.prune_expired_replays(u64::MAX).await.unwrap();
        assert!(matches!(
            redeem_logic(&boot1, &redeem).await,
            Err(RedeemError::AlreadyRedeemed)
        ));

        // Model the point after fleet-wide retirement has been independently established: every
        // verifier now holds only key B. The maintenance primitive may then drop A.
        let issuer_b = Issuer::generate().unwrap();
        let pk_b = issuer_b.public_der().unwrap();
        let retained = BTreeSet::from([nil_crypto::key_epoch(&pk_b), nil_crypto::LEGACY_EPOCH]);
        assert!(
            !retained.contains(&ea),
            "key A's derived epoch is no longer retained"
        );
        let dropped = nullifiers.drop_epochs(&retained).await.unwrap();
        assert_eq!(dropped, 1, "key A's partition is dropped wholesale");
        assert_eq!(
            nullifiers.approx_len().await,
            Some(0),
            "its nullifier is gone"
        );

        // Boot 2: verifier holds only key B (key A is retired). Re-redeeming the key-A token now
        // returns BadToken — it no longer verifies — NOT a fresh path. This proves the primitive's
        // post-retirement property, not the distributed retirement decision.
        let boot2 = CoordState::with_nullifiers(
            Arc::new(cfg_with_verifier(
                Verifier::from_public_ders(&[pk_b]).unwrap(),
            )),
            nullifiers.clone(),
        );
        assert!(
            matches!(
                redeem_logic(&boot2, &redeem).await,
                Err(RedeemError::BadToken)
            ),
            "a retired-key token is rejected at verify — a dropped nullifier cannot be re-spent"
        );
        assert_eq!(
            nullifiers.approx_len().await,
            Some(0),
            "the rejected token never re-entered the set"
        );
    }

    #[tokio::test]
    async fn same_token_in_different_hex_case_replays_the_same_result() {
        // Regression guard: the nullifier must key on the DECODED token bytes, not the raw request
        // string. The same token submitted as lowercase then UPPERCASE hex decodes to identical
        // bytes, so the second request must replay the same first result — keying on the raw string
        // would let case-flipping mint a second authorization.
        let (state, req) = state_and_token();

        // First redemption (lowercase, as minted) succeeds.
        let first = redeem_logic(&state, &req)
            .await
            .expect("first redemption succeeds");

        // Same token, uppercased hex. It still verifies and must hit the same authoritative row.
        let upper = RedeemRequest {
            msg: req.msg.to_uppercase(),
            token: req.token.to_uppercase(),
        };
        assert_ne!(upper.msg, req.msg, "the test actually flips hex case");
        let replay = redeem_logic(&state, &upper)
            .await
            .expect("canonicalized retry replays live result");
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&first).unwrap(),
            "hex spelling cannot select a second result"
        );
    }

    #[tokio::test]
    async fn forged_token_is_rejected() {
        let (state, mut req) = state_and_token();
        req.token = hex(&vec![0u8; 256]); // not the issuer's signature
        assert!(matches!(
            redeem_logic(&state, &req).await,
            Err(RedeemError::BadToken)
        ));
    }

    #[tokio::test]
    async fn v1_path_payment_bypass_is_removed() {
        // Regression guard: the old `/v1/path` stub granted a path to ANY non-empty entitlement
        // string — a token-free payment bypass. It must no longer be routed; the ONLY way to a
        // path is a redeemed token at `/v1/redeem`.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt; // oneshot

        let (state, _req) = state_and_token();
        let app = router(state).layer(axum::Extension(crate::client_ip::ClientIpPolicy::direct()));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/path")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"entitlement":"i-did-not-pay"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "/v1/path must be gone — no token-free path bypass"
        );

        // ...while the real, token-gated endpoint is still routed (a bad token → 401, never 404).
        let resp2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"msg":"ab","token":"cd"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp2.status(),
            StatusCode::NOT_FOUND,
            "/v1/redeem must still be routed"
        );
    }

    #[tokio::test]
    async fn http_retry_returns_byte_identical_first_response() {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::Request;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let (mut state, req) = state_and_token();
        let cfg = Arc::get_mut(&mut state.cfg).expect("state owns its config");
        cfg.grant_signer = Some(nil_core::grant::GrantSigningKey::from_seed([0x42; 32]));
        cfg.grant_realm = "nil-http-retry".to_string();
        cfg.grant_ttl = std::time::Duration::from_secs(60);
        let app = router(state).layer(axum::Extension(crate::client_ip::ClientIpPolicy::direct()));
        let request_body = serde_json::to_vec(&req).unwrap();
        let send = |body: Vec<u8>| {
            Request::builder()
                .method("POST")
                .uri("/v1/redeem")
                .header("content-type", "application/json")
                .extension(ConnectInfo(
                    "127.0.0.1:41234".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::from(body))
                .unwrap()
        };

        let first = app
            .clone()
            .oneshot(send(request_body.clone()))
            .await
            .unwrap();
        let retry = app.oneshot(send(request_body)).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(retry.status(), StatusCode::OK);
        let first = first.into_body().collect().await.unwrap().to_bytes();
        let retry = retry.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            retry, first,
            "HTTP retry must return the exact first JSON bytes"
        );
    }

    #[tokio::test]
    async fn redemption_disabled_without_an_issuer_key() {
        let cfg = CoordConfig {
            addr: "127.0.0.1:9090".parse().unwrap(),
            registry: NodeRegistry::dev_default(),
            path_hops: 3,
            verifier: None,
            nullifier_path: None,
            nullifier_dir: None,
            grant_signer: None,
            grant_realm: String::new(),
            grant_ttl: std::time::Duration::from_secs(300),
            redemption_result_key: Zeroizing::new([0x73; 32]),
            nullifier_warn_at: crate::config::DEFAULT_NULLIFIER_WARN_AT,
        };
        let state = CoordState::new(Arc::new(cfg));
        let req = RedeemRequest {
            msg: "00".into(),
            token: "00".into(),
        };
        assert!(matches!(
            redeem_logic(&state, &req).await,
            Err(RedeemError::NotConfigured)
        ));
    }
}
