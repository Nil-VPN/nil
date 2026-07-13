//! NIL VPN Control plane (`nil-coordinator`).
//!
//! Hands the client a trust-split path and the measurement each hop must attest to, and
//! publishes the pinned measurement set from the reproducible-build transparency log. It is
//! the verifier/policy tier: it learns *that* a valid subscriber connected, never *which*
//! one, and never sees traffic. Token *issuance* lives in the Portal, a separate trust domain
//! (Pillar 4) — this binary never imports it.
//!
//! Phase 2 publishes a single pinned node. Phase 3 adds the Privacy Pass token verifier and
//! operator/jurisdiction-diverse multi-hop path selection.

mod api;
mod client_ip;
mod config;
mod nullifier;
mod pathsel;
mod ratelimit;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

const GRANT_KEY_USAGE: &str =
    "usage:\n  nil-coordinator grant-keygen PATH\n  nil-coordinator grant-public-key PATH\n  nil-coordinator redemption-keygen PATH";

/// Handle the two offline grant-key provisioning commands before service configuration or logging
/// starts. Secret seed bytes are written directly to an owner-only file and are never printed.
fn run_grant_key_command() -> Result<bool> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() == 1 {
        return Ok(false);
    }
    let command = args
        .get(1)
        .and_then(|arg| arg.to_str())
        .ok_or_else(|| anyhow::anyhow!(GRANT_KEY_USAGE))?;
    if command == "--help" || command == "-h" {
        println!("{GRANT_KEY_USAGE}");
        return Ok(true);
    }
    if args.len() != 3 {
        anyhow::bail!(GRANT_KEY_USAGE);
    }
    let path = Path::new(&args[2]);
    match command {
        "grant-keygen" => {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(seed.as_mut())
                .map_err(|_| anyhow::anyhow!("operating-system entropy unavailable"))?;
            write_new_signing_seed(path, &seed)?;
            let signer = nil_core::grant::GrantSigningKey::from_seed(*seed);
            print_grant_public_metadata(&signer);
            Ok(true)
        }
        "grant-public-key" => {
            let path = path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("grant signing key path must be valid UTF-8"))?;
            let signer = config::load_grant_signing_key_file(path, true)?;
            print_grant_public_metadata(&signer);
            Ok(true)
        }
        "redemption-keygen" => {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(key.as_mut())
                .map_err(|_| anyhow::anyhow!("operating-system entropy unavailable"))?;
            write_new_raw_secret(path, key.as_ref(), "redemption-result key")?;
            println!("redemption_result_key_created=true");
            Ok(true)
        }
        _ => anyhow::bail!(GRANT_KEY_USAGE),
    }
}

fn print_grant_public_metadata(signer: &nil_core::grant::GrantSigningKey) {
    println!(
        "grant_verify_key={}",
        nil_core::grant::to_hex(&signer.public_key_bytes())
    );
    println!("grant_key_id={}", nil_core::grant::to_hex(&signer.key_id()));
}

fn write_new_signing_seed(path: &Path, seed: &[u8; 32]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|e| anyhow::anyhow!("create grant signing seed {}: {e}", path.display()))?;
    let mut encoded = Zeroizing::new(nil_core::grant::to_hex(seed));
    encoded.push('\n');
    if let Err(error) = file
        .write_all(encoded.as_bytes())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(anyhow::anyhow!(
            "write grant signing seed {}: {error}",
            path.display()
        ));
    }
    Ok(())
}

fn write_new_raw_secret(path: &Path, secret: &[u8], label: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("create {label} {}: {error}", path.display()))?;
    if let Err(error) = file.write_all(secret).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(anyhow::anyhow!("write {label} {}: {error}", path.display()));
    }
    Ok(())
}

/// Select the one authoritative anonymous nullifier + encrypted-result ledger.
fn file_or_volatile_nullifiers(cfg: &Arc<config::CoordConfig>) -> Result<api::CoordState> {
    let key = *cfg.redemption_result_key;
    let now = nil_core::grant::now_unix_secs_for_expiry();
    // Epoch-partitioned store (automatic deletion currently disabled). The legacy single file, if
    // also set, is migrated in as the epoch-0 partition so already-spent tokens stay spent.
    if let Some(dir) = &cfg.nullifier_dir {
        let file = dir.join("nullifiers.epoch.log");
        let set = nullifier::FileNullifierStore::open_epoch(
            &file,
            cfg.nullifier_path.as_deref(),
            key,
            now,
        )
        .map_err(|e| anyhow::anyhow!("open epoch nullifier store {}: {e}", file.display()))?;
        tracing::info!(path = %file.display(), "epoch-partitioned redemption ledger loaded");
        return Ok(api::CoordState::with_nullifiers(cfg.clone(), Arc::new(set)));
    }
    match &cfg.nullifier_path {
        Some(path) => {
            let set = nullifier::FileNullifierStore::open_flat(path, key, now)
                .map_err(|e| anyhow::anyhow!("open nullifier store {}: {e}", path.display()))?;
            tracing::info!(path = %path.display(), "durable redemption ledger loaded");
            Ok(api::CoordState::with_nullifiers(cfg.clone(), Arc::new(set)))
        }
        None => {
            // A volatile redemption ledger re-permits a double-spend of every redeemed token after
            // a restart — never acceptable in production. Refuse to boot unless an operator has
            // explicitly opted into dev fallbacks; the friction is intentional (fail closed).
            if !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
                anyhow::bail!(
                    "NW_NULLIFIER_PATH unset (no durable redemption ledger): volatile state would \
                     re-permit double-spend of every redeemed token after a restart. Set \
                     NW_NULLIFIER_PATH (or NW_NULLIFIER_PG_URL with the `postgres` feature). A \
                     debug-assertion build may explicitly enable its volatile integration fallback."
                );
            }
            tracing::warn!(
                "NW_ALLOW_DEV_FALLBACKS=1: the redemption ledger is VOLATILE (dev only); \
                 a restart will re-permit double-spend of every redeemed token"
            );
            Ok(api::CoordState::new(cfg.clone()))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if run_grant_key_command()? {
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Arc::new(config::CoordConfig::from_env()?);
    let addr = cfg.addr;
    let postgres_configured = std::env::var_os("NW_NULLIFIER_PG_URL").is_some();
    tracing::info!(
        %addr,
        nodes = cfg.registry.nodes.len(),
        path_hops = cfg.path_hops,
        redeem = cfg.verifier.is_some(),
        durable_nullifiers = cfg.nullifier_path.is_some() || cfg.nullifier_dir.is_some() || postgres_configured,
        epoch_partitioned = cfg.nullifier_dir.is_some(),
        "nil-coordinator configuration loaded (redeem + measurements)"
    );

    // The redemption ledger MUST be durable: a restart with volatile state would re-admit every
    // spent token and could not replay a lost first response. Backends (all identity-free):
    //  - clustered Postgres (cross-instance single-use) when NW_NULLIFIER_PG_URL is set and the
    //    `postgres` feature is built;
    //  - else file-backed when NW_NULLIFIER_PATH is set;
    //  - else volatile in-memory + a loud warning (dev only).
    #[cfg(feature = "postgres")]
    let state = match std::env::var("NW_NULLIFIER_PG_URL") {
        Ok(url) => {
            if cfg.nullifier_path.is_some() || cfg.nullifier_dir.is_some() {
                anyhow::bail!(
                    "configure exactly one authoritative redemption ledger: unset \
                     NW_NULLIFIER_PATH/NW_NULLIFIER_DIR when NW_NULLIFIER_PG_URL is set"
                );
            }
            let pg = nullifier::PgNullifierStore::connect(&url, *cfg.redemption_result_key)
                .await
                .map_err(|e| anyhow::anyhow!("connect Postgres nullifier store: {e}"))?;
            tracing::info!(
                "clustered Postgres redemption ledger connected (cross-instance atomic replay)"
            );
            api::CoordState::with_nullifiers(cfg.clone(), Arc::new(pg))
        }
        Err(_) => file_or_volatile_nullifiers(&cfg)?,
    };
    #[cfg(not(feature = "postgres"))]
    let state = {
        if postgres_configured {
            anyhow::bail!(
                "NW_NULLIFIER_PG_URL is set, but nil-coordinator was built without the `postgres` \
                 feature; refusing to fall back to a different redemption ledger"
            );
        }
        file_or_volatile_nullifiers(&cfg)?
    };

    // Ciphertext is useful only while its grants remain valid. Sweep frequently and atomically
    // preserve the permanent spent marker. A stopped process cannot mutate storage; startup also
    // performs the same cleanup before serving.
    let cleanup_store = state.nullifiers.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let now = nil_core::grant::now_unix_secs_for_expiry();
            match cleanup_store.prune_expired_replays(now).await {
                Ok(removed) if removed > 0 => {
                    tracing::info!(removed, "expired redemption replay ciphertext removed")
                }
                Ok(_) => {}
                Err(error) => tracing::error!("redemption replay cleanup failed: {error}"),
            }
        }
    });

    // Never garbage-collect nullifier epochs from this process's local verifier list. During a
    // rolling deployment a new replica may have removed an old issuer key while another live
    // replica still accepts it. Deleting the shared old partition would let that replica re-accept
    // spent tokens. Epoch deletion stays disabled until a shared fleet-wide retirement record, a
    // grace period longer than token lifetime + rollout overlap, and an elected/leased GC worker
    // exist. Over-retention is safe; premature deletion is a double-spend vulnerability (NIL-009).
    if cfg.verifier.is_some() && state.nullifiers.supports_epoch_gc() {
        tracing::warn!(
            "automatic nullifier epoch GC is disabled: a replica-local NW_TOKEN_PUBKEY list \
             is not fleet-wide retirement authority; partitions remain until shared retirement, \
             rollout grace, and a GC lease are implemented"
        );
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // ConnectInfo so `/v1/redeem` can rate-limit by client IP (the IP is used transiently for the
    // limiter only — never stored, logged, or tied to an account).
    axum::serve(
        listener,
        api::router(state)
            .layer(axum::Extension(client_ip::ClientIpPolicy::from_env(
                !cfg!(debug_assertions),
            )?))
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
