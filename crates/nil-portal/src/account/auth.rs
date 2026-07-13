//! Account authentication (ADR-0007): single-use challenge nonces + signature verification.
//!
//! A subscriber proves account ownership by signing a Portal-issued challenge with the account's
//! auth key (the secret half lives only on the client; the Portal stored the public half at
//! creation). This module mints the challenges and verifies the proof, resolving the
//! [`AccountRecord`] so callers (mint, account-tied checkout) can then check entitlement.
//!
//! ## Privacy
//! The challenge store is IN-MEMORY (PD-2): nonces are throwaway and non-identifying, so losing
//! them on restart is harmless (a client just asks for a new one). No challenge is tied to an
//! account, an IP, or any identity. The auth public key it verifies against is itself anonymous.

use std::collections::HashMap;
use std::sync::Mutex;

use nil_crypto::account::{verify_auth_signature, AUTH_SIG_LEN};
use nil_proto::account::AccountAuth;

use crate::account::model::AccountRecord;
use crate::state::AppState;
use crate::store::unhex32;

/// How long an issued challenge stays valid. Short: a challenge is requested immediately before the
/// authed call, so a tight window minimises the replay surface while tolerating normal latency.
const CHALLENGE_TTL_SECS: u64 = 120;
/// Challenge nonce length in bytes (256-bit, unguessable).
const CHALLENGE_BYTES: usize = 32;

/// Single-use, short-TTL challenge nonces, keyed by the nonce (lowercase hex). The value is the
/// issue time (unix secs). In-memory only — ephemeral and non-identifying (PD-2).
#[derive(Default)]
pub struct ChallengeStore {
    issued: Mutex<HashMap<String, u64>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh challenge nonce (hex), record it as live, and opportunistically prune expired
    /// entries so the map stays bounded. Returns the nonce to hand to the client.
    pub fn issue(&self, now: u64) -> Result<String, getrandom::Error> {
        let mut raw = [0u8; CHALLENGE_BYTES];
        getrandom::getrandom(&mut raw)?;
        let nonce: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let mut g = self.issued.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = now.saturating_sub(CHALLENGE_TTL_SECS);
        g.retain(|_, t| *t >= cutoff);
        g.insert(nonce.clone(), now);
        Ok(nonce)
    }

    /// Atomically consume a challenge: returns `true` iff it was live (issued and not expired),
    /// removing it so it can never be used twice. A wrong, expired, or replayed nonce returns
    /// `false`. The remove-then-check ordering means even an expired-but-present nonce is dropped.
    pub fn consume(&self, nonce: &str, now: u64) -> bool {
        let mut g = self.issued.lock().unwrap_or_else(|e| e.into_inner());
        match g.remove(nonce) {
            Some(issued_at) => now.saturating_sub(issued_at) <= CHALLENGE_TTL_SECS,
            None => false,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.issued.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Why an authenticated request was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The request was structurally invalid (account number / signature not the right hex shape).
    Malformed,
    /// The proof did not check out: unknown/expired/replayed challenge, no such account, or a bad
    /// signature. Deliberately ONE variant so the endpoint is not an account-existence oracle (PD-3).
    Unauthorized,
    /// The store backend failed — fail closed (deny), don't leak details.
    Backend,
}

/// Verify an [`AccountAuth`] proof and resolve the account. On success the challenge has been
/// consumed (single-use) and the returned [`AccountRecord`] is the authenticated account — the
/// caller still decides what the account is entitled to do.
pub async fn authenticate(
    state: &AppState,
    auth: &AccountAuth,
    now: u64,
) -> Result<AccountRecord, AuthError> {
    let account_number = unhex32(&auth.account_number).ok_or(AuthError::Malformed)?;
    let signature = parse_sig(&auth.signature).ok_or(AuthError::Malformed)?;

    // Consume the challenge FIRST (single-use), before any store work or signature check, so a
    // replayed nonce is rejected regardless of whether the rest would have passed.
    if !state.challenges.consume(&auth.challenge, now) {
        return Err(AuthError::Unauthorized);
    }

    // No existence oracle: an unknown account is the SAME Unauthorized as a bad signature.
    let record = state
        .store
        .get(&account_number)
        .await
        .map_err(|_| AuthError::Backend)?
        .ok_or(AuthError::Unauthorized)?;

    // The signature is over the challenge's ASCII (hex) bytes — what the client received verbatim.
    if !verify_auth_signature(&record.auth_pubkey, auth.challenge.as_bytes(), &signature) {
        return Err(AuthError::Unauthorized);
    }
    Ok(record)
}

/// Parse a 64-byte Ed25519 signature from lowercase/uppercase hex.
fn parse_sig(s: &str) -> Option<[u8; AUTH_SIG_LEN]> {
    if s.len() != AUTH_SIG_LEN * 2 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let h = s.as_bytes();
    let mut out = [0u8; AUTH_SIG_LEN];
    for (i, p) in h.chunks_exact(2).enumerate() {
        out[i] = (nib(p[0])? << 4) | nib(p[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use nil_crypto::account::{create_account_os, AuthKeypair};

    use crate::account::model::{AccountRecord, Entitlement};
    use crate::store::memory::InMemoryStore;
    use crate::store::Store;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Create a real (random) account, store its record, and return (state, account_number_hex,
    /// keypair). The seed arg is unused now (kept so each call reads as a distinct fixture).
    async fn seeded_account(_seed: u64) -> (AppState, String, AuthKeypair) {
        let derived = create_account_os();
        let store = Arc::new(InMemoryStore::new());
        store
            .insert(AccountRecord {
                account_number: *derived.account_number.as_bytes(),
                entitlement: Entitlement::None,
                auth_pubkey: derived.auth_public_key,
            })
            .await
            .expect("insert");
        let kp = AuthKeypair::from_phrase(&derived.recovery_phrase).expect("derive");
        (
            AppState::new(store),
            hex(derived.account_number.as_bytes()),
            kp,
        )
    }

    fn signed(challenge: &str, account_number: &str, kp: &AuthKeypair) -> AccountAuth {
        AccountAuth {
            account_number: account_number.to_string(),
            challenge: challenge.to_string(),
            signature: hex(&kp.sign(challenge.as_bytes())),
        }
    }

    #[tokio::test]
    async fn issued_challenge_signed_correctly_authenticates() {
        let (state, acct, kp) = seeded_account(1).await;
        let challenge = state.challenges.issue(1000).expect("issue");
        let auth = signed(&challenge, &acct, &kp);
        let rec = authenticate(&state, &auth, 1001)
            .await
            .expect("authenticates");
        assert_eq!(hex(&rec.account_number), acct);
    }

    #[tokio::test]
    async fn a_challenge_is_single_use() {
        let (state, acct, kp) = seeded_account(2).await;
        let challenge = state.challenges.issue(1000).expect("issue");
        let auth = signed(&challenge, &acct, &kp);
        assert!(authenticate(&state, &auth, 1000).await.is_ok());
        // The same proof replayed is rejected — the nonce was consumed.
        assert_eq!(
            authenticate(&state, &auth, 1000).await,
            Err(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn an_expired_challenge_is_rejected() {
        let (state, acct, kp) = seeded_account(3).await;
        let challenge = state.challenges.issue(1000).expect("issue");
        let auth = signed(&challenge, &acct, &kp);
        let later = 1000 + CHALLENGE_TTL_SECS + 1;
        assert_eq!(
            authenticate(&state, &auth, later).await,
            Err(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn an_unissued_challenge_is_rejected() {
        let (state, acct, kp) = seeded_account(4).await;
        // A nonce we never issued (client-fabricated) must fail.
        let auth = signed(&"ab".repeat(32), &acct, &kp);
        assert_eq!(
            authenticate(&state, &auth, 1000).await,
            Err(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn a_wrong_key_signature_is_rejected() {
        let (state, acct, _kp) = seeded_account(5).await;
        // A different account's key signs the challenge → must not authenticate as `acct`.
        let attacker = AuthKeypair::from_phrase(&create_account_os().recovery_phrase).unwrap();
        let challenge = state.challenges.issue(1000).expect("issue");
        let auth = signed(&challenge, &acct, &attacker);
        assert_eq!(
            authenticate(&state, &auth, 1000).await,
            Err(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn unknown_account_is_indistinguishable_from_a_bad_signature() {
        let (state, _acct, kp) = seeded_account(6).await;
        let challenge = state.challenges.issue(1000).expect("issue");
        // A well-formed proof for an account number that isn't stored → Unauthorized (no oracle).
        let auth = signed(&challenge, &"cd".repeat(32), &kp);
        assert_eq!(
            authenticate(&state, &auth, 1000).await,
            Err(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn malformed_inputs_are_rejected_as_malformed() {
        let (state, acct, kp) = seeded_account(7).await;
        let challenge = state.challenges.issue(1000).expect("issue");
        let mut auth = signed(&challenge, &acct, &kp);
        auth.signature = "not-hex".to_string();
        assert_eq!(
            authenticate(&state, &auth, 1000).await,
            Err(AuthError::Malformed)
        );

        let mut auth2 = signed(&challenge, "zz", &kp);
        auth2.account_number = "zz".to_string();
        assert_eq!(
            authenticate(&state, &auth2, 1000).await,
            Err(AuthError::Malformed)
        );
    }

    #[test]
    fn consume_prunes_expired_entries_on_issue() {
        let cs = ChallengeStore::new();
        let _a = cs.issue(1000).unwrap();
        assert_eq!(cs.len(), 1);
        // Issuing far later prunes the now-expired first nonce.
        let _b = cs.issue(1000 + CHALLENGE_TTL_SECS + 5).unwrap();
        assert_eq!(cs.len(), 1, "the stale nonce was pruned on the next issue");
    }
}
