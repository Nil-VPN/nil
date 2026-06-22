//! Self-signed dev TLS cert (Phase 1). quiche loads cert/key from PEM file paths, so we
//! generate in memory and write to a per-process temp dir (removed on drop).
//!
//! This is a DEV placeholder — it proves no node identity. RA-TLS (an embedded SEV-SNP/TDX
//! report appraised by `nil-attest`) replaces it in Phase 2 (spec §5).

use std::path::PathBuf;

pub struct DevCert {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// The cert's TLS SubjectPublicKeyInfo (DER) — the key the attestation report binds to.
    pub spki: Vec<u8>,
    dir: PathBuf,
}

impl DevCert {
    pub fn generate(subject_alt_names: Vec<String>) -> anyhow::Result<DevCert> {
        let ck = rcgen::generate_simple_self_signed(subject_alt_names)?;
        let spki = nil_attest::ratls::spki_of(ck.cert.der())
            .map_err(|e| anyhow::anyhow!("extract node SPKI: {e}"))?;
        let cert_pem = ck.cert.pem();
        let key_pem = ck.key_pair.serialize_pem();

        let dir = std::env::temp_dir().join(format!("nil-node-cert-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert_pem)?;
        std::fs::write(&key_path, key_pem)?;
        tracing::warn!(
            "DEV TLS: self-signed cert generated — NOT attested (Phase 1 dev only; RA-TLS is Phase 2)"
        );
        Ok(DevCert { cert_path, key_path, spki, dir })
    }
}

impl Drop for DevCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
