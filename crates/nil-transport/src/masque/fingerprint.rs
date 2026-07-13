//! Outer QUIC/TLS ClientHello fingerprint-parity harness (architecture review, Theme A).
//!
//! The default MASQUE transport's camouflage depends on the *outer* QUIC/TLS ClientHello looking
//! like an ordinary browser's — a censor fingerprints it (JA4/JA4+) regardless of how good the SNI
//! is. This harness measures that ClientHello as ground truth so drift is CI-visible and the gap to
//! a real Chrome HTTP/3 handshake is explicit.
//!
//! It captures the ClientHello the way a censor would: it drives NIL's *real* [`super::build_client_config`]
//! to emit the client's first Initial packet, then decrypts that QUIC v1 Initial (RFC 9001 §5.2 —
//! the keys derive from the public initial salt + the packet's own DCID, so no secret is needed),
//! and parses the TLS ClientHello out of the CRYPTO frames. It then pins a stable digest of the
//! fingerprint (any handshake-shape drift fails the test) and prints a breakdown plus the Chrome
//! reference gap — most importantly whether an X25519MLKEM768 post-quantum key share is present,
//! which as of 2025 is the browser baseline and its absence is itself a fingerprint.
//!
//! Test-only: the QUIC-Initial crypto uses dev-dependency RustCrypto primitives; nothing here ships
//! in a release build. The end-to-end sanity checks (the recovered bytes parse as a ClientHello with
//! the `h3` ALPN and TLS 1.3 cipher suites) validate the whole decrypt→parse pipeline without an
//! external vector.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// RFC 9001 §5.2 initial salt for QUIC v1.
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// IANA TLS supported-group codepoints of interest for the PQ-baseline check.
const X25519MLKEM768: u16 = 0x11ec;
const X25519KYBER768_DRAFT: u16 = 0x6399;

/// Real Chrome HTTP/3 ClientHello extension SET (sorted), captured 2026-07 (Chrome on macOS, QUIC
/// v1) via a local UDP listener + `--origin-to-force-quic-on` + a `--host-resolver-rules` hostname
/// map (so SNI is present). Chrome's substantive JA4 components — cipher suites `1301/1302/1303`,
/// supported groups `11ec,001d,0017,0018`, key_share `11ec,001d`, ALPN `h3`, SNI — are all matched
/// by NIL after the outer-ClientHello shaping. This is the ground-truth reference for the remaining
/// extension-SET gap (JA4 sorts extensions, so only the set matters, not order).
const CHROME_EXT_SET: &[u16] = &[
    0x0000, 0x000a, 0x000d, 0x0010, 0x001b, 0x002b, 0x002d, 0x0033, 0x0039, 0x44cd, 0xfe0d,
];

fn u16be(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}

/// RFC 8701 TLS GREASE value (both bytes equal, low nibble `a`).
fn is_grease(v: u16) -> bool {
    (v & 0xff) as u8 == (v >> 8) as u8 && (v & 0x0f) == 0x0a
}

/// Decode a QUIC variable-length integer; returns (value, bytes-consumed).
fn read_varint(b: &[u8]) -> (u64, usize) {
    let len = 1usize << (b[0] >> 6);
    let mut v = (b[0] & 0x3f) as u64;
    for &byte in b.iter().take(len).skip(1) {
        v = (v << 8) | byte as u64;
    }
    (v, len)
}

/// HKDF-Expand-Label (RFC 8446 §7.1) over an already-extracted PRK.
fn expand_label(prk: &Hkdf<Sha256>, label: &str, out_len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0u8); // zero-length context
    let mut out = vec![0u8; out_len];
    prk.expand(&info, &mut out)
        .expect("hkdf expand within output limit");
    out
}

/// Derive the client Initial (key, iv, hp) from the connection's DCID (RFC 9001 §5.2).
fn client_initial_keys(dcid: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let extract = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), dcid);
    let client_secret = expand_label(&extract, "client in", 32);
    let prk = Hkdf::<Sha256>::from_prk(&client_secret).expect("32-byte prk");
    (
        expand_label(&prk, "quic key", 16),
        expand_label(&prk, "quic iv", 12),
        expand_label(&prk, "quic hp", 16),
    )
}

/// Drive NIL's real client config to produce the client's first flight of Initial packets. A
/// ClientHello carrying a post-quantum key share (~1.2 KiB) does not fit one 1200-byte Initial, so
/// it spans several — all with the same DCID/Initial keys — hence we drain every datagram.
fn capture_initials() -> Vec<Vec<u8>> {
    let mut config = super::build_client_config(super::MAX_UDP_PAYLOAD).expect("client config");
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    getrandom::getrandom(&mut scid).expect("scid entropy");
    let scid = quiche::ConnectionId::from_ref(&scid);
    let local = "127.0.0.1:0".parse().unwrap();
    let peer = "127.0.0.1:443".parse().unwrap();
    let mut conn = quiche::connect(Some("fingerprint.invalid"), &scid, local, peer, &mut config)
        .expect("connect");
    let mut datagrams = Vec::new();
    loop {
        let mut buf = vec![0u8; 2048];
        match conn.send(&mut buf) {
            Ok((n, _)) => {
                buf.truncate(n);
                datagrams.push(buf);
            }
            Err(quiche::Error::Done) => break,
            Err(e) => panic!("conn.send: {e}"),
        }
    }
    assert!(!datagrams.is_empty(), "client produced no Initial packets");
    datagrams
}

/// Decrypt a QUIC v1 client Initial packet → the plaintext QUIC frames.
fn decrypt_initial(pkt: &[u8]) -> Vec<u8> {
    assert!(
        pkt[0] & 0x80 != 0,
        "expected a long-header (Initial) packet"
    );
    let dcid_len = pkt[5] as usize;
    let dcid = &pkt[6..6 + dcid_len];
    let mut off = 6 + dcid_len;
    let scid_len = pkt[off] as usize;
    off += 1 + scid_len;
    let (token_len, adv) = read_varint(&pkt[off..]);
    off += adv + token_len as usize;
    let (length, adv) = read_varint(&pkt[off..]);
    off += adv;
    let pn_offset = off;

    let (key, iv, hp) = client_initial_keys(dcid);

    // Remove header protection (RFC 9001 §5.4): AES-128-ECB mask over a 16-byte sample.
    let sample = &pkt[pn_offset + 4..pn_offset + 4 + 16];
    let cipher = Aes128::new(GenericArray::from_slice(&hp));
    let mut mask = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut mask);

    let mut hdr = pkt.to_vec();
    hdr[0] ^= mask[0] & 0x0f; // long header: low 4 bits
    let pn_len = ((hdr[0] & 0x03) + 1) as usize;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        hdr[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | hdr[pn_offset + i] as u64;
    }

    // AEAD (AES-128-GCM): nonce = iv XOR right-aligned packet number; AAD = the unprotected header.
    let mut nonce = iv.clone();
    let pn_be = pn.to_be_bytes();
    let nl = nonce.len();
    for i in 0..8 {
        nonce[nl - 8 + i] ^= pn_be[i];
    }
    let aad = &hdr[0..pn_offset + pn_len];
    let ct = &pkt[pn_offset + pn_len..pn_offset + length as usize];

    let gcm = Aes128Gcm::new_from_slice(&key).expect("aes-128 key");
    gcm.decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad })
        .expect("Initial AEAD decrypt (a wrong key derivation would fail here)")
}

/// Collect CRYPTO frames (offset, data) from one packet's decrypted frames (PADDING/PING skipped).
fn collect_crypto(frames: &[u8], chunks: &mut Vec<(u64, Vec<u8>)>) {
    let mut i = 0;
    while i < frames.len() {
        let (ftype, adv) = read_varint(&frames[i..]);
        i += adv;
        match ftype {
            0x00 | 0x01 => {} // PADDING / PING
            0x06 => {
                let (offset, a) = read_varint(&frames[i..]);
                i += a;
                let (len, a) = read_varint(&frames[i..]);
                i += a;
                chunks.push((offset, frames[i..i + len as usize].to_vec()));
                i += len as usize;
            }
            _ => break, // no other frame type precedes the ClientHello in a client Initial
        }
    }
}

/// Reassemble the contiguous CRYPTO stream (the TLS handshake) from collected offset chunks.
fn reassemble(mut chunks: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    chunks.sort_by_key(|(o, _)| *o);
    let mut out = Vec::new();
    for (o, d) in chunks {
        if o as usize == out.len() {
            out.extend_from_slice(&d);
        } else if (o as usize) < out.len() {
            // Overlapping retransmit chunk — extend only the non-overlapping tail.
            let skip = out.len() - o as usize;
            if skip < d.len() {
                out.extend_from_slice(&d[skip..]);
            }
        }
    }
    out
}

/// The fingerprint-relevant fields parsed out of a TLS ClientHello.
#[derive(Debug, Default)]
struct ClientHelloShape {
    tls13: bool,
    has_sni: bool,
    ciphers: Vec<u16>,    // GREASE removed
    extensions: Vec<u16>, // in order, GREASE removed
    alpn: Vec<String>,
    groups: Vec<u16>,           // supported_groups (ext 10)
    sig_algs: Vec<u16>,         // ext 13, original order
    key_share_groups: Vec<u16>, // ext 51 offered shares
    grease_present: bool,
}

impl ClientHelloShape {
    fn has_pq_key_share(&self) -> bool {
        self.key_share_groups
            .iter()
            .any(|&g| g == X25519MLKEM768 || g == X25519KYBER768_DRAFT)
    }

    /// A stable, unambiguous digest over the normalized shape (anti-drift pin). Not JA4 — this is
    /// NIL's own canonical fingerprint, independent of any external algorithm's edge cases.
    fn digest(&self) -> String {
        let mut sorted_ciphers = self.ciphers.clone();
        sorted_ciphers.sort_unstable();
        let mut sorted_exts = self.extensions.clone();
        sorted_exts.sort_unstable();
        let mut sorted_groups = self.groups.clone();
        sorted_groups.sort_unstable();
        let canon = format!(
            "v{}|sni{}|grease{}|ciphers[{}]|exts[{}]|groups[{}]|sigalgs[{}]|ks[{}]|alpn[{}]",
            if self.tls13 { "13" } else { "??" },
            self.has_sni as u8,
            self.grease_present as u8,
            hexlist(&sorted_ciphers),
            hexlist(&sorted_exts),
            hexlist(&sorted_groups),
            hexlist(&self.sig_algs),
            hexlist(&self.key_share_groups),
            self.alpn.join(","),
        );
        let d = Sha256::digest(canon.as_bytes());
        d[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Best-effort JA4 QUIC fingerprint (FoxIO). Labeled best-effort: the anti-drift guarantee rides
    /// on [`Self::digest`]; JA4 is printed for direct comparison against public Chrome fingerprints.
    fn ja4(&self) -> String {
        let mut sc = self.ciphers.clone();
        sc.sort_unstable();
        let cipher_hash = trunc12(
            &sc.iter()
                .map(|c| format!("{c:04x}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        // JA4_c: extensions sorted, excluding SNI(0x0000) and ALPN(0x0010), then "_" + sig algs in order.
        let mut se: Vec<u16> = self
            .extensions
            .iter()
            .copied()
            .filter(|&e| e != 0x0000 && e != 0x0010)
            .collect();
        se.sort_unstable();
        let ext_part = se
            .iter()
            .map(|e| format!("{e:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let sig_part = self
            .sig_algs
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let ext_hash = trunc12(&format!("{ext_part}_{sig_part}"));
        let alpn2 = match self.alpn.first() {
            Some(a) if a.len() >= 2 => format!("{}{}", &a[..1], &a[a.len() - 1..]),
            Some(a) if a.len() == 1 => format!("{a}{a}"),
            _ => "00".to_string(),
        };
        format!(
            "q{}{}{:02}{:02}{}_{}_{}",
            if self.tls13 { "13" } else { "00" },
            if self.has_sni { "d" } else { "i" },
            self.ciphers.len().min(99),
            self.extensions.len().min(99),
            alpn2,
            cipher_hash,
            ext_hash,
        )
    }
}

fn hexlist(v: &[u16]) -> String {
    v.iter()
        .map(|x| format!("{x:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn trunc12(s: &str) -> String {
    Sha256::digest(s.as_bytes())[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn parse_client_hello(hs: &[u8]) -> ClientHelloShape {
    assert_eq!(hs[0], 0x01, "first handshake message must be a ClientHello");
    let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let body = &hs[4..4 + body_len];
    let mut sh = ClientHelloShape::default();
    let mut p = 2 + 32; // legacy_version + random
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    let cs_len = u16be(&body[p..p + 2]) as usize;
    p += 2;
    for c in body[p..p + cs_len].chunks(2) {
        let v = u16be(c);
        if is_grease(v) {
            sh.grease_present = true;
        } else {
            sh.ciphers.push(v);
        }
    }
    p += cs_len;
    let comp_len = body[p] as usize;
    p += 1 + comp_len;
    let ext_total = u16be(&body[p..p + 2]) as usize;
    p += 2;
    let ext_end = p + ext_total;
    while p + 4 <= ext_end {
        let etype = u16be(&body[p..p + 2]);
        let elen = u16be(&body[p + 2..p + 4]) as usize;
        p += 4;
        let edata = &body[p..p + elen];
        p += elen;
        if is_grease(etype) {
            sh.grease_present = true;
            continue;
        }
        sh.extensions.push(etype);
        match etype {
            0x0000 => sh.has_sni = true,
            0x0010 => {
                // ALPN: 2-byte list length, then [1-byte len + name]*
                let mut q = 2;
                while q < edata.len() {
                    let l = edata[q] as usize;
                    q += 1;
                    sh.alpn
                        .push(String::from_utf8_lossy(&edata[q..q + l]).into_owned());
                    q += l;
                }
            }
            0x000a => {
                let mut q = 2;
                while q + 2 <= edata.len() {
                    let g = u16be(&edata[q..q + 2]);
                    if !is_grease(g) {
                        sh.groups.push(g);
                    }
                    q += 2;
                }
            }
            0x000d => {
                let mut q = 2;
                while q + 2 <= edata.len() {
                    sh.sig_algs.push(u16be(&edata[q..q + 2]));
                    q += 2;
                }
            }
            0x0033 => {
                // key_share: 2-byte client-shares length, then [group(2) + keylen(2) + key]*
                let mut q = 2;
                while q + 4 <= edata.len() {
                    let g = u16be(&edata[q..q + 2]);
                    let kl = u16be(&edata[q + 2..q + 4]) as usize;
                    if !is_grease(g) {
                        sh.key_share_groups.push(g);
                    }
                    q += 4 + kl;
                }
            }
            0x002b => {
                // supported_versions: pick TLS 1.3 if offered
                let mut q = 1;
                while q + 2 <= edata.len() {
                    if u16be(&edata[q..q + 2]) == 0x0304 {
                        sh.tls13 = true;
                    }
                    q += 2;
                }
            }
            _ => {}
        }
    }
    sh
}

fn nil_client_hello_shape() -> ClientHelloShape {
    let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    for datagram in capture_initials() {
        let frames = decrypt_initial(&datagram);
        collect_crypto(&frames, &mut chunks);
    }
    parse_client_hello(&reassemble(chunks))
}

/// Parse a ClientHello out of a length-prefixed (u32 BE + bytes) capture of one or more Initial
/// datagrams — e.g. a real Chrome QUIC flight captured by a local UDP listener. Retransmits/overlaps
/// are handled by the offset reassembly.
fn shape_from_capture(path: &str) -> ClientHelloShape {
    let raw = std::fs::read(path).expect("read capture file");
    let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut i = 0;
    while i + 4 <= raw.len() {
        let len = u32::from_be_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]) as usize;
        i += 4;
        let dg = &raw[i..i + len];
        i += len;
        // Only decrypt long-header Initial packets (type bits 00); skip anything else defensively.
        if dg.first().is_some_and(|b| b & 0x80 != 0) {
            let frames = decrypt_initial(dg);
            collect_crypto(&frames, &mut chunks);
        }
    }
    parse_client_hello(&reassemble(chunks))
}

#[test]
fn nil_outer_client_hello_fingerprint() {
    let sh = nil_client_hello_shape();

    // Pipeline sanity (also validates the RFC 9001 decrypt end-to-end): a real ClientHello with the
    // MASQUE ALPN and TLS 1.3 cipher suites. Garbage from a wrong key derivation would not parse.
    assert!(sh.tls13, "TLS 1.3 must be offered");
    assert!(
        sh.alpn.iter().any(|a| a == "h3"),
        "ALPN must advertise h3, got {:?}",
        sh.alpn
    );
    assert!(
        sh.ciphers.contains(&0x1301),
        "TLS_AES_128_GCM_SHA256 must be offered"
    );
    // NOTE: TLS-level GREASE (RFC 8701) is measured, not asserted — quiche's `grease` flag greases
    // the QUIC layer; whether BoringSSL adds a TLS GREASE cipher/extension is a separate fingerprint
    // characteristic this harness reports (its absence is a Chrome-parity gap).

    let digest = sh.digest();
    let ja4 = sh.ja4();
    let pq = sh.has_pq_key_share();

    // Human-readable report (visible with `--nocapture`). This is the artifact for comparing against
    // a real Chrome HTTP/3 ClientHello and for tracking the gap the architecture review flagged.
    println!("\n=== NIL outer QUIC/TLS ClientHello fingerprint ===");
    println!("digest (pinned): {digest}");
    println!("JA4 (best-effort; verify vs FoxIO tooling): {ja4}");
    println!(
        "TLS1.3={} SNI={} GREASE={}",
        sh.tls13, sh.has_sni, sh.grease_present
    );
    println!("cipher suites: {}", hexlist(&sh.ciphers));
    println!("extensions:    {}", hexlist(&sh.extensions));
    println!("supported groups: {}", hexlist(&sh.groups));
    println!("key_share groups: {}", hexlist(&sh.key_share_groups));
    println!("ALPN: {:?}", sh.alpn);
    println!("PQ key share (X25519MLKEM768/Kyber): {pq}");
    println!(
        "--- Chrome HTTP/3 reference gap ---\n\
         Chrome ships an X25519MLKEM768 key share by default (2025); its ALPN is h3; it offers the\n\
         three TLS 1.3 AEAD suites and adds TLS-level GREASE. Actionable parity deltas for NIL:\n\
         (1) PQ key share present? -> {}\n\
         (2) TLS GREASE present? -> {}\n\
         (3) whether the extension SET/ORDER and supported_groups match a current-Chrome capture\n\
             (compare the lists above against a real JA4). A mismatch means the MASQUE rung is\n\
             JA4-distinguishable regardless of SNI — see THREAT_MODEL.md.",
        if pq { "YES (good)" } else { "NO — the top parity gap: NIL's outer handshake lacks the PQ key share Chrome sends" },
        if sh.grease_present { "YES (good)" } else { "NO — a parity gap: Chrome greases the ClientHello" },
    );

    // Anti-drift pin: if NIL's outer handshake shape changes (quiche/BoringSSL bump, config change),
    // this fails and forces a review of whether the change moved NIL closer to or further from
    // browser parity. Update deliberately, never blindly.
    // The two headline Chrome-parity gaps are now CLOSED via `build_client_config`'s BoringSSL
    // shaping: NIL offers the X25519MLKEM768 PQ key share (groups 11ec,001d,0017,0018; key_share
    // 11ec,001d — both, like Chrome) and adds TLS-level GREASE. Assert those substantive properties
    // directly (robust to future re-pins), then pin the full digest for anti-drift. Any drift
    // (quiche/BoringSSL bump, config change) fails here — re-pin only after confirming the change
    // keeps NIL at or closer to browser parity.
    assert!(
        pq,
        "regression: NIL's outer ClientHello must offer the X25519MLKEM768 PQ key share"
    );
    assert!(
        sh.grease_present,
        "regression: NIL's outer ClientHello must carry TLS GREASE"
    );
    // Pinned 2026-07 (quiche 0.22 boring-crate + boring 4.22 pq-experimental): TLS1.3; ciphers
    // 1301/1302/1303; groups 11ec,001d,0017,0018; key_share 11ec,001d; GREASE on; 8 extensions.
    // Remaining finer gap (not the headline ones): Chrome carries a larger extension SET/ORDER —
    // full JA4_c parity is a deeper follow-up (see THREAT_MODEL.md / the architecture plan).
    assert_eq!(
        digest, "9ea0d65febe48970",
        "NIL's outer ClientHello fingerprint changed (see the printed breakdown). If intentional, \
         re-pin; if not, the handshake shape drifted."
    );

    // Track the exact remaining gap to the pinned real-Chrome reference. Not an assert — it's a
    // known, documented residual: NIL matches Chrome on every substantive JA4 component; only three
    // finer extensions remain, and closing them needs quiche per-SSL hooks (see below).
    let nset: std::collections::BTreeSet<u16> = sh.extensions.iter().copied().collect();
    let missing: Vec<String> = CHROME_EXT_SET
        .iter()
        .filter(|e| !nset.contains(e))
        .map(|e| format!("{e:04x}"))
        .collect();
    let extra: Vec<String> = sh
        .extensions
        .iter()
        .filter(|e| !CHROME_EXT_SET.contains(e))
        .map(|e| format!("{e:04x}"))
        .collect();
    println!(
        "--- extension-set gap vs pinned real Chrome ---\n\
         Chrome set: {}\n\
         NIL lacks:  [{}]   NIL extra: [{}]\n\
         fe0d=ECH-GREASE (per-SSL SSL_set_enable_ech_grease — NOT exposed via quiche's ctx builder);\n\
         001b=compress_certificate (needs a brotli CertificateCompressor impl);\n\
         44cd=Chrome-specific. Substantive JA4 (ciphers/groups/key_share/ALPN/SNI) matches; the\n\
         remaining set-parity needs quiche to expose per-SSL config — tracked, not yet closable here.",
        CHROME_EXT_SET.iter().map(|e| format!("{e:04x}")).collect::<Vec<_>>().join(","),
        missing.join(","),
        extra.join(","),
    );
}

/// Diagnostic (skips unless `NW_CAPTURED_INITIAL` points at a captured Initial flight): parse a real
/// browser ClientHello and print the exact parity delta vs NIL. Used to drive full extension-set
/// parity against a Chrome ground-truth capture.
#[test]
fn compare_against_captured_chrome() {
    let Ok(path) = std::env::var("NW_CAPTURED_INITIAL") else {
        println!("NW_CAPTURED_INITIAL unset — skipping Chrome-parity comparison (diagnostic only)");
        return;
    };
    use std::collections::BTreeSet;
    let chrome = shape_from_capture(&path);
    let nil = nil_client_hello_shape();
    let dump = |tag: &str, s: &ClientHelloShape| {
        println!(
            "{tag}: TLS1.3={} GREASE={} PQ={} JA4={}\n  ciphers: {}\n  exts:    {}\n  groups:  {}  key_share: {}  alpn: {:?}",
            s.tls13, s.grease_present, s.has_pq_key_share(), s.ja4(),
            hexlist(&s.ciphers), hexlist(&s.extensions), hexlist(&s.groups),
            hexlist(&s.key_share_groups), s.alpn,
        );
    };
    println!("\n=== Chrome (captured) vs NIL outer ClientHello ===");
    dump("Chrome", &chrome);
    dump("NIL   ", &nil);
    let cset: BTreeSet<u16> = chrome.extensions.iter().copied().collect();
    let nset: BTreeSet<u16> = nil.extensions.iter().copied().collect();
    let hx = |it: std::collections::btree_set::Difference<u16>| {
        it.map(|e| format!("{e:04x}")).collect::<Vec<_>>().join(",")
    };
    let cg: BTreeSet<u16> = chrome.groups.iter().copied().collect();
    let ng: BTreeSet<u16> = nil.groups.iter().copied().collect();
    println!("--- parity delta (what NIL must add to match Chrome) ---");
    println!(
        "extensions Chrome has, NIL LACKS: [{}]",
        hx(cset.difference(&nset))
    );
    println!(
        "extensions NIL has, Chrome lacks: [{}]",
        hx(nset.difference(&cset))
    );
    println!(
        "groups Chrome has, NIL lacks:     [{}]",
        hx(cg.difference(&ng))
    );
    println!("cipher suites match: {}", chrome.ciphers == nil.ciphers);
    println!("ALPN match: {}", chrome.alpn == nil.alpn);
}
