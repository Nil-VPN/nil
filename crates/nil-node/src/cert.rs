//! Stable self-signed TLS identity for the node's QUIC/MASQUE listener.
//!
//! RA-TLS deliberately does not trust a public CA: the client verifies hardware evidence and binds
//! it to the live certificate SPKI. The Coordinator additionally pins `SHA-256(SPKI)` in its node
//! registry and signs that digest into NWG2. Consequently a production node must keep one stable,
//! owner-only private key across restarts. Debug builds may still generate an ephemeral key.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{CertificateParams, KeyPair};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_TLS_PRIVATE_KEY_FILE_BYTES: usize = 64 * 1024;

pub struct NodeCert {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// The exact DER SubjectPublicKeyInfo bound into each attestation report.
    pub spki: Vec<u8>,
    /// Stable registry identity: `SHA-256(spki)`.
    pub tls_spki_sha256: [u8; 32],
    dir: PathBuf,
}

impl NodeCert {
    /// Generate an ephemeral debug identity. Production callers use [`Self::from_key_file`].
    #[cfg(any(debug_assertions, test))]
    pub fn generate(subject_alt_names: Vec<String>) -> anyhow::Result<Self> {
        let key_pair = KeyPair::generate()?;
        Self::from_key_pair(key_pair, subject_alt_names)
    }

    /// Load a stable private key from an owner-only, non-symlink regular file and issue the
    /// process-local self-signed leaf certificate around that same key.
    pub fn from_key_file(path: &Path, subject_alt_names: Vec<String>) -> anyhow::Result<Self> {
        let pem_bytes = read_private_key(path)?;
        let pem = std::str::from_utf8(&pem_bytes)
            .map_err(|e| anyhow::anyhow!("parse NW_NODE_TLS_KEY_FILE {}: {e}", path.display()))?;
        let key_pair = KeyPair::from_pem(pem)
            .map_err(|e| anyhow::anyhow!("parse NW_NODE_TLS_KEY_FILE {}: {e}", path.display()))?;
        drop(pem_bytes);
        Self::from_key_pair(key_pair, subject_alt_names)
    }

    fn from_key_pair(key_pair: KeyPair, subject_alt_names: Vec<String>) -> anyhow::Result<Self> {
        let cert = CertificateParams::new(subject_alt_names)?.self_signed(&key_pair)?;
        let spki = nil_attest::ratls::spki_of(cert.der())
            .map_err(|e| anyhow::anyhow!("extract node SPKI: {e}"))?;
        let tls_spki_sha256: [u8; 32] = Sha256::digest(&spki).into();

        let dir = temp_cert_dir();
        let mut dir_builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            dir_builder.mode(0o700);
        }
        dir_builder
            .create(&dir)
            .map_err(|e| anyhow::anyhow!("create node certificate directory: {e}"))?;
        let cert_path = dir.join("cert.pem");
        std::fs::write(&cert_path, cert.pem())
            .map_err(|e| anyhow::anyhow!("write node certificate: {e}"))?;
        // quiche's server API accepts a key pathname rather than in-memory key bytes. Stage the
        // already-validated key into this process-owned temporary directory instead of handing
        // quiche the configured production pathname: the configured secret is resolved exactly
        // once above, with O_NOFOLLOW, and cannot be swapped between validation and TLS loading.
        let key_path = dir.join("key.pem");
        let pem = Zeroizing::new(key_pair.serialize_pem());
        write_new_private_key(&key_path, pem.as_bytes())?;

        let node_cert = Self {
            cert_path,
            key_path,
            spki,
            tls_spki_sha256,
            dir,
        };
        #[cfg(any(feature = "hw-attest", feature = "synthetic-attest"))]
        tracing::info!(
            tls_spki_sha256 = %nil_core::grant::to_hex(&node_cert.tls_spki_sha256),
            "RA-TLS identity loaded; attestation and NWG2 bind the stable TLS SPKI"
        );
        #[cfg(not(any(feature = "hw-attest", feature = "synthetic-attest")))]
        tracing::warn!(
            tls_spki_sha256 = %nil_core::grant::to_hex(&node_cert.tls_spki_sha256),
            "DEV TLS identity loaded with no attestation report provider"
        );
        Ok(node_cert)
    }
}

/// Offline provisioning command: create a new PKCS#8 private key at `path` with mode 0600 and
/// return only its public SPKI digest. `create_new` refuses overwrite and symlink targets.
pub fn generate_tls_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    let key_pair = KeyPair::generate()?;
    let cert = CertificateParams::new(vec!["nil-node".to_string()])?.self_signed(&key_pair)?;
    let spki = nil_attest::ratls::spki_of(cert.der())
        .map_err(|e| anyhow::anyhow!("extract generated TLS SPKI: {e}"))?;
    let digest: [u8; 32] = Sha256::digest(&spki).into();
    let pem = Zeroizing::new(key_pair.serialize_pem());
    write_new_private_key(path, pem.as_bytes())?;
    Ok(digest)
}

fn write_new_private_key(path: &Path, pem: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|e| anyhow::anyhow!("create TLS private key {}: {e}", path.display()))?;
    if let Err(error) = file.write_all(pem).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(anyhow::anyhow!(
            "write TLS private key {}: {error}",
            path.display()
        ));
    }
    Ok(())
}

fn read_private_key(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|e| anyhow::anyhow!("open NW_NODE_TLS_KEY_FILE {}: {e}", path.display()))?;
    let opened_meta = file
        .metadata()
        .map_err(|e| anyhow::anyhow!("stat opened NW_NODE_TLS_KEY_FILE {}: {e}", path.display()))?;
    if !opened_meta.is_file() {
        anyhow::bail!(
            "NW_NODE_TLS_KEY_FILE {} is not a regular file",
            path.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = opened_meta.mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "NW_NODE_TLS_KEY_FILE {} must not be accessible by group/other (mode {:04o}; require 0600 or stricter)",
                path.display(),
                mode & 0o7777
            );
        }
    }
    #[cfg(not(unix))]
    anyhow::bail!("production TLS private-key permission validation requires a Unix platform");

    if opened_meta.len() > MAX_TLS_PRIVATE_KEY_FILE_BYTES as u64 {
        anyhow::bail!(
            "NW_NODE_TLS_KEY_FILE {} exceeds the {}-byte limit",
            path.display(),
            MAX_TLS_PRIVATE_KEY_FILE_BYTES
        );
    }
    let mut pem = Zeroizing::new(Vec::with_capacity(
        usize::try_from(opened_meta.len())
            .unwrap_or(MAX_TLS_PRIVATE_KEY_FILE_BYTES)
            .min(MAX_TLS_PRIVATE_KEY_FILE_BYTES),
    ));
    (&mut file)
        .take((MAX_TLS_PRIVATE_KEY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut pem)
        .map_err(|e| anyhow::anyhow!("read NW_NODE_TLS_KEY_FILE {}: {e}", path.display()))?;
    if pem.len() > MAX_TLS_PRIVATE_KEY_FILE_BYTES {
        anyhow::bail!(
            "NW_NODE_TLS_KEY_FILE {} exceeds the {}-byte limit",
            path.display(),
            MAX_TLS_PRIVATE_KEY_FILE_BYTES
        );
    }
    Ok(pem)
}

fn temp_cert_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "nil-node-cert-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

impl Drop for NodeCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn generated_key_is_stable_owner_only_bounded_and_symlinks_are_refused() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let base = std::env::temp_dir().join(format!(
            "nil-node-tls-key-test-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let link = base.with_extension("link");
        let oversized = base.with_extension("oversized");
        let malformed = base.with_extension("malformed");
        let digest = generate_tls_key(&base).expect("generate TLS key");
        assert_eq!(std::fs::metadata(&base).unwrap().mode() & 0o777, 0o600);

        let first = NodeCert::from_key_file(&base, vec!["localhost".into()]).unwrap();
        let second = NodeCert::from_key_file(&base, vec!["localhost".into()]).unwrap();
        assert_eq!(first.tls_spki_sha256, digest);
        assert_eq!(second.tls_spki_sha256, digest);
        assert_ne!(
            first.key_path, base,
            "quiche must not reopen the configured path"
        );
        assert_eq!(
            std::fs::metadata(&first.key_path).unwrap().mode() & 0o777,
            0o600
        );

        symlink(&base, &link).unwrap();
        assert!(NodeCert::from_key_file(&link, vec!["localhost".into()]).is_err());
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(NodeCert::from_key_file(&base, vec!["localhost".into()]).is_err());

        std::fs::write(&oversized, vec![b'x'; MAX_TLS_PRIVATE_KEY_FILE_BYTES + 1]).unwrap();
        std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(NodeCert::from_key_file(&oversized, vec!["localhost".into()]).is_err());

        std::fs::write(&malformed, b"not a PKCS#8 PEM private key\n").unwrap();
        std::fs::set_permissions(&malformed, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(NodeCert::from_key_file(&malformed, vec!["localhost".into()]).is_err());

        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(oversized);
        let _ = std::fs::remove_file(malformed);
        let _ = std::fs::remove_file(base);
    }
}
