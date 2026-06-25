//! Self-signed TLS cert for the node's QUIC/MASQUE listener. quiche loads cert/key from PEM file
//! paths, so we generate in memory and write to a per-process temp dir (removed on drop).
//!
//! The cert is **intentionally self-signed and unverified by PKI**: RA-TLS does not trust a CA, it
//! trusts the attestation report. The node's per-connection report (delivered over H3 — see
//! [`crate::attest`]) binds *this cert's* SubjectPublicKeyInfo (SPKI) plus the client's fresh nonce,
//! and that report — not any certificate chain — is the node's identity proof. So an ephemeral
//! per-process key is fine: the report always binds the current SPKI. A build with a report provider
//! (`hw-attest` in production, `synthetic-attest` for the test harness) is fully attested; a build
//! with neither serves unattested and a pinning client refuses it.

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
        // The cert is self-signed by design (RA-TLS trusts the report, not a CA). It is "attested"
        // exactly when a report provider is compiled in; say which, honestly (PD-8).
        #[cfg(any(feature = "hw-attest", feature = "synthetic-attest"))]
        tracing::info!(
            "RA-TLS: self-signed TLS cert generated; its SPKI is bound into the per-connection \
             attestation report (intentionally self-signed — RA-TLS trusts the report, not a CA)"
        );
        #[cfg(not(any(feature = "hw-attest", feature = "synthetic-attest")))]
        tracing::warn!(
            "DEV TLS: self-signed cert with NO attestation report provider — a pinning client will \
             refuse this node; build with `hw-attest` for production"
        );
        Ok(DevCert { cert_path, key_path, spki, dir })
    }
}

impl Drop for DevCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
