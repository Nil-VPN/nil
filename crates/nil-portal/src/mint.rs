//! Subscription-gated batch issuance for randomized client prefetch.
//!
//! `POST /v1/tokens/mint` retains the original single-item wire contract. The versioned
//! `POST /v2/tokens/mint` accepts a bounded batch for randomized prefetch. Both are gated on an
//! active subscription and use the same atomic result/quota store.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Json, Router};

use nil_core::grant::now_unix_secs_for_expiry;
use nil_proto::account::{MintBatchRequest, MintBatchResponse, MintRequest};
use nil_proto::token::{
    BlindSignatureBatch, IssueResponse, BLIND_TOKEN_HEX_LEN, MAX_MINT_BATCH_SIZE,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::account::auth::authenticate;
use crate::account::error::ApiError;
use crate::account::handlers::map_auth_err;
use crate::client_ip::ClientIp;
use crate::ratelimit::RateLimiter;
use crate::state::AppState;
use crate::store::{MintCommit, MintLookup, MintQuota, MintResult};
use crate::tokens::TokenSigner;

/// Hard cap on the mint request body. Sixteen RSA-2048 blinded messages occupy a little over 8 KiB
/// as hex plus JSON/auth overhead, so 16 KiB covers the protocol maximum without permitting Axum's
/// much larger default allocation.
const MINT_BODY_LIMIT: usize = 16 * 1024;

/// Per-IP cap on mint attempts (a cheap DoS guard, independent of the per-account cap below). The IP
/// is used transiently for the counter only — never stored, logged, or tied to an account.
const MINT_IP_RATE_MAX: u32 = 120;
const MINT_IP_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Default per-ACCOUNT mint cap and window: the abuse/resale bound. Generous for real use (a token
/// per connection, reconnects on network changes, a few per multi-hop path) but far below resale
/// scale. Tunable via `NW_MINT_RATE_MAX` (see `main`).
pub const DEFAULT_MINT_ACCOUNT_RATE_MAX: u32 = 120;
pub const MINT_ACCOUNT_RATE_WINDOW: Duration = Duration::from_secs(3600);
/// Keep an ambiguous completed response for the maximum v2 token lifetime (24h plus one coarse
/// epoch). The row is keyed only by a hash of a random request id and is pruned after this bound.
pub const MINT_RESULT_TTL_SECS: u64 =
    nil_crypto::token::V2_VALIDITY_SECS + nil_crypto::token::V2_EPOCH_SECS;

/// Mint-plane state: the account [`AppState`] (auth — store + challenges, SHARED with the account
/// router so a `/v1/account/challenge` nonce is consumable here) and the issuer's signing
/// capability. The per-account cap keeps an active account from minting at resale scale.
#[derive(Clone)]
pub struct MintState {
    pub app: AppState,
    pub issuer: Arc<dyn TokenSigner>,
    ip_limiter: Arc<RateLimiter>,
    /// Process-local early admission guard. The authoritative cross-replica account/window charge
    /// is committed with the result by [`crate::store::Store::commit_mint`].
    account_limiter: Arc<RateLimiter>,
    account_rate_max: u32,
}

impl MintState {
    pub fn new(app: AppState, issuer: Arc<dyn TokenSigner>, account_rate_max: u32) -> Self {
        Self {
            app,
            issuer,
            ip_limiter: Arc::new(RateLimiter::new(MINT_IP_RATE_MAX, MINT_IP_RATE_WINDOW)),
            account_limiter: Arc::new(RateLimiter::new(account_rate_max, MINT_ACCOUNT_RATE_WINDOW)),
            account_rate_max,
        }
    }
}

pub fn mint_router(state: MintState) -> Router {
    Router::new()
        .route("/v1/tokens/mint", post(mint_v1))
        .route("/v2/tokens/mint", post(mint))
        .layer(DefaultBodyLimit::max(MINT_BODY_LIMIT))
        .with_state(state)
}

/// `POST /v2/tokens/mint` — authenticate once, replay an identical completed request when present,
/// otherwise require an active subscription, charge token-count limits, and sign in request order.
async fn mint(
    ClientIp(client_ip): ClientIp,
    State(state): State<MintState>,
    Json(req): Json<MintBatchRequest>,
) -> Result<Json<MintBatchResponse>, ApiError> {
    let batch_cost = u32::try_from(req.blind_msgs.len())
        .map_err(|_| ApiError::BadRequest("invalid mint batch size"))?;
    if !state.ip_limiter.check_n(&client_ip.to_string(), batch_cost) {
        return Err(ApiError::TooManyRequests);
    }
    // Auth + subscription are GATES → fail-closed clock (unknown clock ⇒ challenge/expiry treated as
    // expired ⇒ refuse). The challenge is consumed here (single-use), so each mint needs a fresh one.
    let now = now_unix_secs_for_expiry();
    let record = authenticate(&state.app, &req.auth, now)
        .await
        .map_err(map_auth_err)?;

    // Decode and validate the WHOLE batch before either the account quota or signer is touched. A
    // bad item can never yield a prefix of signatures or burn the subscriber's mint allowance.
    let blind_messages = validate_blind_batch(req.blind_msgs.as_slice())?;
    let request_id = parse_request_id(&req.request_id)?;
    let request_key = mint_request_key(&request_id);
    let request_hash = mint_request_hash(
        b"nil/subscription-mint/request/v2\0",
        &record.account_number,
        &blind_messages,
    );

    let signatures = mint_validated(
        &state,
        &record,
        request_key,
        request_hash,
        blind_messages,
        batch_cost,
        now,
    )
    .await?;
    response_from_signatures(signatures)
}

/// Backward-compatible single-item endpoint. Its retry identity is derived from the canonical
/// authenticated account plus decoded blinded request; the fresh auth challenge is not part of it.
async fn mint_v1(
    ClientIp(client_ip): ClientIp,
    State(state): State<MintState>,
    Json(req): Json<MintRequest>,
) -> Result<Json<IssueResponse>, ApiError> {
    if !state.ip_limiter.check(&client_ip.to_string()) {
        return Err(ApiError::TooManyRequests);
    }
    let now = now_unix_secs_for_expiry();
    let record = authenticate(&state.app, &req.auth, now)
        .await
        .map_err(map_auth_err)?;
    let blind_message = from_hex_blind_message(&req.blind_msg)
        .ok_or(ApiError::BadRequest("malformed blind message"))?;
    let blind_messages = vec![blind_message];
    let request_key = mint_v1_request_key(&record.account_number, &blind_messages[0]);
    let request_hash = mint_request_hash(
        b"nil/subscription-mint/request/v1\0",
        &record.account_number,
        &blind_messages,
    );
    let mut signatures = mint_validated(
        &state,
        &record,
        request_key,
        request_hash,
        blind_messages,
        1,
        now,
    )
    .await?;
    let mut signature = signatures.pop().ok_or(ApiError::Internal)?;
    let blind_sig = to_hex(&signature);
    signature.zeroize();
    Ok(Json(IssueResponse { blind_sig }))
}

async fn mint_validated(
    state: &MintState,
    record: &crate::account::model::AccountRecord,
    request_key: [u8; 32],
    request_hash: [u8; 32],
    blind_messages: Vec<Vec<u8>>,
    batch_cost: u32,
    now: u64,
) -> Result<Vec<Vec<u8>>, ApiError> {
    match state
        .app
        .store
        .lookup_mint(&request_key, &request_hash, now)
        .await
        .map_err(|error| {
            tracing::error!("mint-result lookup failed: {error}");
            ApiError::Internal
        })? {
        MintLookup::Replay { blind_sigs } => return Ok(blind_sigs),
        MintLookup::Conflict => return Err(ApiError::Conflict),
        MintLookup::Missing => {}
    }
    if record.entitlement.active_until(now).is_none() {
        return Err(ApiError::PaymentRequired);
    }

    // This process-local reservation avoids needless signer work. The authoritative charge below
    // is persisted atomically with the winning result and is the cross-replica security boundary.
    let admission = state
        .account_limiter
        .reserve_n(&to_hex(&record.account_number), batch_cost)
        .ok_or(ApiError::TooManyRequests)?;
    let mut signatures = Vec::with_capacity(blind_messages.len());
    for blind_message in &blind_messages {
        let mut signature = match state.issuer.blind_sign(blind_message) {
            Ok(signature) => signature,
            Err(error) => {
                signatures.zeroize();
                tracing::error!("mint batch blind-sign failed: {error}");
                return Err(ApiError::Internal);
            }
        };
        if signature.len() * 2 != BLIND_TOKEN_HEX_LEN {
            signature.zeroize();
            signatures.zeroize();
            tracing::error!("mint signer returned an invalid signature length");
            return Err(ApiError::Internal);
        }
        signatures.push(signature);
    }
    let result = MintResult {
        request_hash,
        blind_sigs: signatures.clone(),
        expires_at: now.saturating_add(MINT_RESULT_TTL_SECS),
    };
    let quota = mint_quota(
        &record.account_number,
        batch_cost,
        state.account_rate_max,
        now,
    )?;
    let commit = match state
        .app
        .store
        .commit_mint(&request_key, result, quota, now)
        .await
    {
        Ok(commit) => commit,
        Err(error) => {
            signatures.zeroize();
            tracing::error!("mint-result commit failed: {error}");
            return Err(ApiError::Internal);
        }
    };
    match commit {
        MintCommit::Stored => {
            admission.commit();
            Ok(signatures)
        }
        MintCommit::Replay { blind_sigs } => {
            signatures.zeroize();
            Ok(blind_sigs)
        }
        MintCommit::Conflict => {
            signatures.zeroize();
            Err(ApiError::Conflict)
        }
        MintCommit::QuotaExceeded => {
            // Another replica may already have exhausted the authoritative window while this
            // process-local advisory bucket was empty. Consume this reservation so repeats on the
            // same replica are rejected before doing another RSA operation.
            admission.commit();
            signatures.zeroize();
            Err(ApiError::TooManyRequests)
        }
    }
}

fn response_from_signatures(signatures: Vec<Vec<u8>>) -> Result<Json<MintBatchResponse>, ApiError> {
    let signatures = signatures
        .into_iter()
        .map(|mut signature| {
            if signature.len() * 2 != BLIND_TOKEN_HEX_LEN {
                signature.zeroize();
                return Err(ApiError::Internal);
            }
            let encoded = to_hex(&signature);
            signature.zeroize();
            Ok(encoded)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let blind_sigs = BlindSignatureBatch::try_from(signatures).map_err(|_| {
        tracing::error!("mint produced an invalid response batch size");
        ApiError::Internal
    })?;
    Ok(Json(MintBatchResponse { blind_sigs }))
}

fn parse_request_id(value: &str) -> Result<[u8; 32], ApiError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::BadRequest("malformed mint request id"));
    }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        };
        out[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(out)
}

fn mint_request_key(request_id: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"nil/subscription-mint/request-key/v2\0");
    hash.update(request_id);
    hash.finalize().into()
}

fn mint_v1_request_key(account: &[u8; 32], blind_message: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"nil/subscription-mint/request-key/v1\0");
    hash.update(account);
    hash.update(blind_message);
    hash.finalize().into()
}

fn mint_request_hash(domain: &[u8], account: &[u8; 32], blind_messages: &[Vec<u8>]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(account);
    hash.update((blind_messages.len() as u64).to_be_bytes());
    for message in blind_messages {
        hash.update((message.len() as u64).to_be_bytes());
        hash.update(message);
    }
    hash.finalize().into()
}

fn mint_quota(account: &[u8; 32], cost: u32, max: u32, now: u64) -> Result<MintQuota, ApiError> {
    let window_secs = MINT_ACCOUNT_RATE_WINDOW.as_secs();
    let window_start = now - (now % window_secs);
    let window_end = window_start
        .checked_add(window_secs)
        .ok_or(ApiError::Internal)?;
    let mut hash = Sha256::new();
    hash.update(b"nil/subscription-mint/quota/v1\0");
    hash.update(account);
    Ok(MintQuota {
        quota_key: hash.finalize().into(),
        window_start,
        window_end,
        cost,
        max,
    })
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn validate_blind_batch(messages: &[String]) -> Result<Vec<Vec<u8>>, ApiError> {
    if messages.is_empty() || messages.len() > MAX_MINT_BATCH_SIZE {
        return Err(ApiError::BadRequest("invalid mint batch size"));
    }
    messages
        .iter()
        .map(|message| {
            from_lower_hex_blind_message(message)
                .ok_or(ApiError::BadRequest("malformed blind message"))
        })
        .collect()
}

fn from_lower_hex_blind_message(s: &str) -> Option<Vec<u8>> {
    let h = s.as_bytes();
    if h.len() != BLIND_TOKEN_HEX_LEN {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    h.chunks_exact(2)
        .map(|p| Some((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

fn from_hex_blind_message(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() != BLIND_TOKEN_HEX_LEN {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    bytes
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use nil_crypto::account::{create_account_os, AuthKeypair};
    use nil_crypto::{token, Issuer};
    use nil_proto::account::AccountAuth;
    use nil_proto::token::BlindMessageBatch;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::account::model::{AccountRecord, Entitlement};
    use crate::store::memory::InMemoryStore;
    use crate::store::Store;

    fn peer() -> ClientIp {
        ClientIp("1.2.3.4".parse().unwrap())
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A mint state over a real issuer + in-memory store, with a configurable per-account cap.
    fn state_with(issuer: Arc<dyn TokenSigner>, account_max: u32) -> MintState {
        let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
        MintState::new(AppState::new(store), issuer, account_max)
    }

    /// Insert a fresh account with the given entitlement; return its keypair + account-number hex.
    async fn add_account(state: &MintState, entitlement: Entitlement) -> (AuthKeypair, String) {
        let d = create_account_os();
        state
            .app
            .store
            .insert(AccountRecord {
                account_number: *d.account_number.as_bytes(),
                entitlement,
                auth_pubkey: d.auth_public_key,
            })
            .await
            .expect("insert");
        let kp = AuthKeypair::from_phrase(&d.recovery_phrase).expect("kp");
        (kp, hex(d.account_number.as_bytes()))
    }

    fn mint_req(
        state: &MintState,
        acct: &str,
        kp: &AuthKeypair,
        blind_msg_hex: &str,
    ) -> MintBatchRequest {
        mint_batch_req(state, acct, kp, vec![blind_msg_hex.to_string()])
    }

    fn mint_v1_req(
        state: &MintState,
        acct: &str,
        kp: &AuthKeypair,
        blind_msg: String,
    ) -> MintRequest {
        let challenge = state
            .app
            .challenges
            .issue(nil_core::grant::now_unix_secs())
            .expect("issue");
        MintRequest {
            auth: AccountAuth {
                account_number: acct.to_string(),
                challenge: challenge.clone(),
                signature: hex(&kp.sign(challenge.as_bytes())),
            },
            blind_msg,
        }
    }

    fn mint_batch_req(
        state: &MintState,
        acct: &str,
        kp: &AuthKeypair,
        blind_msgs: Vec<String>,
    ) -> MintBatchRequest {
        let challenge = state
            .app
            .challenges
            .issue(nil_core::grant::now_unix_secs())
            .expect("issue");
        let request_id = hex(&Sha256::digest(challenge.as_bytes()));
        MintBatchRequest {
            auth: AccountAuth {
                account_number: acct.to_string(),
                challenge: challenge.clone(),
                signature: hex(&kp.sign(challenge.as_bytes())),
            },
            request_id,
            blind_msgs: BlindMessageBatch::try_from(blind_msgs).expect("bounded test batch"),
        }
    }

    struct CountingSigner {
        issuer: Issuer,
        calls: AtomicUsize,
    }

    impl CountingSigner {
        fn new() -> Self {
            Self {
                issuer: Issuer::generate().unwrap(),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl TokenSigner for CountingSigner {
        fn blind_sign(&self, blind_msg: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            TokenSigner::blind_sign(&self.issuer, blind_msg)
        }

        fn public_der(&self) -> anyhow::Result<Vec<u8>> {
            TokenSigner::public_der(&self.issuer)
        }
    }

    struct FailOnceSigner {
        issuer: Issuer,
        fail: AtomicBool,
        calls: AtomicUsize,
    }

    impl FailOnceSigner {
        fn new() -> Self {
            Self {
                issuer: Issuer::generate().unwrap(),
                fail: AtomicBool::new(true),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl TokenSigner for FailOnceSigner {
        fn blind_sign(&self, blind_msg: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.swap(false, Ordering::SeqCst) {
                anyhow::bail!("injected signer failure");
            }
            TokenSigner::blind_sign(&self.issuer, blind_msg)
        }

        fn public_der(&self) -> anyhow::Result<Vec<u8>> {
            TokenSigner::public_der(&self.issuer)
        }
    }

    /// A valid blinded message for the given issuer (so blind_sign succeeds).
    fn blinded(issuer: &Issuer) -> String {
        let pub_der = issuer.public_der().unwrap();
        let msg = b"mint-nonce-0123456789abcdef0123".to_vec();
        let req = token::blind(&pub_der, &msg).unwrap();
        req.blind_msg.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn active_until_now_plus_30d() -> Entitlement {
        // Far-future expiry so it's unambiguously active under the real clock.
        Entitlement::Active {
            until: 4_000_000_000,
        }
    }

    #[tokio::test]
    async fn active_account_mints_a_blind_signature_batch() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 1000);
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        let resp = mint(
            peer(),
            State(state.clone()),
            Json(mint_req(&state, &acct, &kp, &blind)),
        )
        .await
        .expect("mint ok");
        assert_eq!(resp.0.blind_sigs.len(), 1);
        assert!(resp.0.blind_sigs.as_slice()[0]
            .bytes()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn v1_single_item_wire_contract_has_deterministic_retry_identity() {
        let signer = Arc::new(CountingSigner::new());
        let blind = blinded(&signer.issuer);
        let state = state_with(signer.clone(), 1);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        let first = mint_v1(
            peer(),
            State(state.clone()),
            Json(mint_v1_req(&state, &acct, &kp, blind.clone())),
        )
        .await
        .expect("v1 mint")
        .0;
        let retry = mint_v1(
            peer(),
            State(state.clone()),
            Json(mint_v1_req(&state, &acct, &kp, blind.to_ascii_uppercase())),
        )
        .await
        .expect("v1 retry")
        .0;
        assert_eq!(retry.blind_sig, first.blind_sig);
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            1,
            "fresh auth and hex case do not change the canonical v1 operation"
        );

        let public = signer.public_der().unwrap();
        let other = token::blind(&public, b"second-v1-message-0123456789abcdef").unwrap();
        assert!(matches!(
            mint_v1(
                peer(),
                State(state.clone()),
                Json(mint_v1_req(&state, &acct, &kp, hex(&other.blind_msg))),
            )
            .await,
            Err(ApiError::TooManyRequests)
        ));
    }

    #[tokio::test]
    async fn identical_request_id_replays_same_batch_without_signing_or_charging_twice() {
        let signer = Arc::new(CountingSigner::new());
        let blind = blinded(&signer.issuer);
        let state = state_with(signer.clone(), 2);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        let first = mint_batch_req(&state, &acct, &kp, vec![blind.clone(), blind.clone()]);
        let request_id = first.request_id.clone();
        let expected = mint(peer(), State(state.clone()), Json(first))
            .await
            .expect("first mint")
            .0;
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);

        // A retry authenticates with a fresh challenge but preserves request id + ordered batch.
        let mut retry = mint_batch_req(&state, &acct, &kp, vec![blind.clone(), blind.clone()]);
        retry.request_id = request_id.clone();
        let replay = mint(peer(), State(state.clone()), Json(retry))
            .await
            .expect("retry replays")
            .0;
        assert_eq!(replay, expected);
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            2,
            "a completed retry never reaches the signer"
        );

        let other_blind = {
            let public = signer.public_der().unwrap();
            let request = token::blind(&public, b"different-mint-message-0123456789").unwrap();
            hex(&request.blind_msg)
        };
        let mut rebound = mint_batch_req(&state, &acct, &kp, vec![other_blind]);
        rebound.request_id = request_id;
        assert!(matches!(
            mint(peer(), State(state), Json(rebound)).await,
            Err(ApiError::Conflict)
        ));
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn signer_failure_refunds_account_quota_and_leaves_request_retryable() {
        let signer = Arc::new(FailOnceSigner::new());
        let blind = blinded(&signer.issuer);
        let state = state_with(signer.clone(), 1);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        assert!(matches!(
            mint(
                peer(),
                State(state.clone()),
                Json(mint_req(&state, &acct, &kp, &blind)),
            )
            .await,
            Err(ApiError::Internal)
        ));
        assert!(
            mint(
                peer(),
                State(state.clone()),
                Json(mint_req(&state, &acct, &kp, &blind)),
            )
            .await
            .is_ok(),
            "the one-token account budget must be available after signer failure"
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn mint_request_id_is_exact_canonical_256_bit_hex() {
        assert_eq!(parse_request_id(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        for invalid in [
            "ab".repeat(31),
            "ab".repeat(33),
            "AB".repeat(32),
            "zz".repeat(32),
        ] {
            assert!(matches!(
                parse_request_id(&invalid),
                Err(ApiError::BadRequest("malformed mint request id"))
            ));
        }
    }

    #[test]
    fn empty_oversized_and_malformed_batches_are_rejected_before_signing() {
        assert!(matches!(
            validate_blind_batch(&[]),
            Err(ApiError::BadRequest("invalid mint batch size"))
        ));
        let valid_shape = "11".repeat(BLIND_TOKEN_HEX_LEN / 2);
        let oversized = vec![valid_shape; MAX_MINT_BATCH_SIZE + 1];
        assert!(matches!(
            validate_blind_batch(&oversized),
            Err(ApiError::BadRequest("invalid mint batch size"))
        ));
        let malformed = vec![
            "22".repeat(BLIND_TOKEN_HEX_LEN / 2),
            "zz".repeat(BLIND_TOKEN_HEX_LEN / 2),
        ];
        assert!(matches!(
            validate_blind_batch(&malformed),
            Err(ApiError::BadRequest("malformed blind message"))
        ));
    }

    #[tokio::test]
    async fn malformed_item_signs_nothing_and_does_not_charge_account_quota() {
        let signer = Arc::new(CountingSigner::new());
        let valid = blinded(&signer.issuer);
        let state = state_with(signer.clone(), 2);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        let malformed = "zz".repeat(BLIND_TOKEN_HEX_LEN / 2);
        match mint(
            peer(),
            State(state.clone()),
            Json(mint_batch_req(
                &state,
                &acct,
                &kp,
                vec![valid.clone(), malformed],
            )),
        )
        .await
        {
            Err(ApiError::BadRequest("malformed blind message")) => {}
            other => panic!("expected malformed batch rejection, got {other:?}"),
        }
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);

        // The invalid request did not touch the account's two-token allowance: a full valid batch
        // still succeeds under the same cap (with a fresh single-use auth challenge).
        assert!(mint(
            peer(),
            State(state.clone()),
            Json(mint_batch_req(
                &state,
                &acct,
                &kp,
                vec![valid.clone(), valid],
            )),
        )
        .await
        .is_ok());
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn account_rate_limit_is_charged_by_token_count() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 3);
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        assert!(mint(
            peer(),
            State(state.clone()),
            Json(mint_batch_req(
                &state,
                &acct,
                &kp,
                vec![blind.clone(), blind.clone()],
            )),
        )
        .await
        .is_ok());
        assert!(mint(
            peer(),
            State(state.clone()),
            Json(mint_req(&state, &acct, &kp, &blind)),
        )
        .await
        .is_ok());
        match mint(
            peer(),
            State(state.clone()),
            Json(mint_req(&state, &acct, &kp, &blind)),
        )
        .await
        {
            Err(ApiError::TooManyRequests) => {}
            other => panic!("fourth token in a three-token window was not capped: {other:?}"),
        }
    }

    #[tokio::test]
    async fn authoritative_quota_loser_consumes_local_admission_to_bound_wasted_signing() {
        let signer = Arc::new(CountingSigner::new());
        let blind = blinded(&signer.issuer);
        let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
        let replica_one = MintState::new(AppState::new(store.clone()), signer.clone(), 1);
        let replica_two = MintState::new(AppState::new(store), signer.clone(), 1);
        let (kp, acct) = add_account(&replica_one, active_until_now_plus_30d()).await;

        assert!(mint(
            peer(),
            State(replica_one.clone()),
            Json(mint_req(&replica_one, &acct, &kp, &blind)),
        )
        .await
        .is_ok());
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);

        // Replica two has an empty advisory bucket, so its first attempt reaches signing before
        // the shared Store reveals that replica one consumed the authoritative window.
        assert!(matches!(
            mint(
                peer(),
                State(replica_two.clone()),
                Json(mint_req(&replica_two, &acct, &kp, &blind)),
            )
            .await,
            Err(ApiError::TooManyRequests)
        ));
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);

        // That authoritative loser consumes the local reservation. Repeats on replica two stop
        // before RSA signing for the remainder of its process-local window.
        assert!(matches!(
            mint(
                peer(),
                State(replica_two.clone()),
                Json(mint_req(&replica_two, &acct, &kp, &blind)),
            )
            .await,
            Err(ApiError::TooManyRequests)
        ));
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ip_rate_limit_charges_the_whole_batch_before_auth_or_signing() {
        let signer = Arc::new(CountingSigner::new());
        let blind = blinded(&signer.issuer);
        let mut state = state_with(signer.clone(), 10);
        state.ip_limiter = Arc::new(RateLimiter::new(3, Duration::from_secs(60)));
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        assert!(mint(
            peer(),
            State(state.clone()),
            Json(mint_batch_req(
                &state,
                &acct,
                &kp,
                vec![blind.clone(), blind.clone()],
            )),
        )
        .await
        .is_ok());
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);

        match mint(
            peer(),
            State(state.clone()),
            Json(mint_batch_req(
                &state,
                &acct,
                &kp,
                vec![blind.clone(), blind],
            )),
        )
        .await
        {
            Err(ApiError::TooManyRequests) => {}
            other => panic!("second two-token batch exceeded a three-token IP cap: {other:?}"),
        }
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            2,
            "a rejected atomic charge never reaches signing"
        );
    }

    #[tokio::test]
    async fn successful_batch_response_preserves_request_order() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let public_der = issuer.public_der().unwrap();
        let verifier = nil_crypto::Verifier::from_public_der(&public_der).unwrap();
        let state = state_with(issuer.clone(), 10);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        let mut requests = Vec::new();
        for marker in 1u8..=3 {
            let message = vec![marker; 32];
            let request = token::blind(&public_der, &message).unwrap();
            let blind_hex = hex(&request.blind_msg);
            requests.push((message, request, blind_hex));
        }
        let body = mint_batch_req(
            &state,
            &acct,
            &kp,
            requests
                .iter()
                .map(|(_, _, blind_hex)| blind_hex.clone())
                .collect(),
        );
        let response = mint(peer(), State(state), Json(body))
            .await
            .expect("batch mint succeeds")
            .0
            .blind_sigs
            .into_vec();
        assert_eq!(response.len(), requests.len());

        for ((message, request, _), blind_sig_hex) in requests.into_iter().zip(response) {
            let blind_sig = from_lower_hex_blind_message(&blind_sig_hex)
                .expect("server returned canonical signature hex");
            let token = token::finalize(&public_der, &request, &blind_sig).unwrap();
            assert!(
                verifier.verify(&token, &message),
                "signature must correspond to the request at the same index"
            );
        }
    }

    #[tokio::test]
    async fn account_without_active_subscription_is_refused() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 1000);
        let blind = blinded(&issuer);
        // None, Expired, and a LAPSED Active (until in the past) all fail.
        for ent in [
            Entitlement::None,
            Entitlement::Expired,
            Entitlement::Active { until: 1 },
        ] {
            let (kp, acct) = add_account(&state, ent).await;
            match mint(
                peer(),
                State(state.clone()),
                Json(mint_req(&state, &acct, &kp, &blind)),
            )
            .await
            {
                Err(ApiError::PaymentRequired) => {}
                other => panic!("expected PaymentRequired for {ent:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn per_account_rate_cap_is_enforced() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 2); // cap of 2 mints/window
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        assert!(mint(
            peer(),
            State(state.clone()),
            Json(mint_req(&state, &acct, &kp, &blind))
        )
        .await
        .is_ok());
        assert!(mint(
            peer(),
            State(state.clone()),
            Json(mint_req(&state, &acct, &kp, &blind))
        )
        .await
        .is_ok());
        // Third within the window is capped.
        match mint(
            peer(),
            State(state.clone()),
            Json(mint_req(&state, &acct, &kp, &blind)),
        )
        .await
        {
            Err(ApiError::TooManyRequests) => {}
            other => panic!("expected TooManyRequests, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn per_account_cap_is_not_bypassable_by_hex_case() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 1); // cap of 1 mint/window
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        // First mint with the lowercase account number succeeds.
        assert!(mint(
            peer(),
            State(state.clone()),
            Json(mint_req(&state, &acct, &kp, &blind))
        )
        .await
        .is_ok());

        // Same account, account number in UPPERCASE hex: hex decode is case-insensitive and the auth
        // signature covers only the challenge, so this authenticates as the SAME account. It must
        // therefore hit the SAME per-account bucket and be capped — not handed a fresh mint budget.
        let acct_upper = acct.to_uppercase();
        assert_ne!(
            acct_upper, acct,
            "test precondition: the account hex contains at least one a-f"
        );
        match mint(
            peer(),
            State(state.clone()),
            Json(mint_req(&state, &acct_upper, &kp, &blind)),
        )
        .await
        {
            Err(ApiError::TooManyRequests) => {}
            other => panic!("hex-case variant must share the per-account cap, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_replayed_challenge_does_not_mint() {
        let issuer = Arc::new(Issuer::generate().unwrap());
        let state = state_with(issuer.clone(), 1000);
        let blind = blinded(&issuer);
        let (kp, acct) = add_account(&state, active_until_now_plus_30d()).await;

        let req = mint_req(&state, &acct, &kp, &blind);
        assert!(mint(peer(), State(state.clone()), Json(req.clone()))
            .await
            .is_ok());
        // Same proof again → the challenge was consumed → Unauthorized.
        match mint(peer(), State(state.clone()), Json(req)).await {
            Err(ApiError::Unauthorized) => {}
            other => panic!("expected Unauthorized on replay, got {other:?}"),
        }
    }
}
