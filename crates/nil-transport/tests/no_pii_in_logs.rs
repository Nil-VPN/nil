//! SOUL §3 / PD-2 guardrail (enforced at `cargo test`): a log line in the data plane or on
//! the client device must never be able to reconstruct a session timeline tied to a user.
//!
//! This test scans the privacy-critical crates' source for `tracing` log macros and fails the
//! build if any invocation interpolates a user-linkable network value (a source/peer/node
//! address, the in-tunnel client IP, a `SocketAddr`, or a `host`/`port` field). It is the
//! "prove, don't promise" (PD-5) backstop for the manual cleanup — a future log line that
//! re-introduces an address can't ship silently.
//!
//! Escape hatch: append `// soul-allow: <reason>` on the same line as the macro's opener for a
//! value that is genuinely not user-linkable (e.g. a server's own bind address).

use std::fs;
use std::path::{Path, PathBuf};

/// Source trees that must stay address-free in logs. Relative to the workspace root.
const SCANNED_DIRS: &[&str] = &[
    "crates/nil-node/src",
    "crates/nil-transport/src",
    "crates/nil-datapath/src",
    "crates/nil-cli/src",
    "client/src-tauri/src",
    // The business plane mints billing identity (accounts, payment refs, the card webhook) — the
    // highest-PII-risk crate, so it gets the same automated log scan (its own bind address is the
    // one legitimate exception, annotated `// soul-allow:`).
    "crates/nil-portal/src",
];

/// Substrings that, inside a log-macro invocation, indicate a user-linkable network value or a
/// payment identifier that could link who-pays to what-flows (PD-4).
const FORBIDDEN: &[&str] = &[
    "%peer", "%from", "%addr", "%node_ip", "%src", "%dst", // formatted address fields
    "node_ip", "client_ip", "peer_addr", "remote_addr", "src_addr", "dst_addr",
    "socketaddr", ".host", ".port",
    // Payment identifiers (the card/Monero rails) — must never reach a log (PD-4).
    "transaction_id", "txn_id", "payment_reference", "payment_id", "customer_id", "card_",
    "refund_id", "checkout_id",
];

const LOG_MACROS: &[&str] = &["info!", "warn!", "error!", "debug!", "trace!"];

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/crates/nil-transport
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above the crate manifest")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Lower-cased forbidden-token match (so `SocketAddr` matches `socketaddr`).
fn has_forbidden(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    FORBIDDEN.iter().copied().find(|tok| lower.contains(*tok))
}

#[test]
fn no_user_linkable_addresses_in_logs() {
    let root = workspace_root();
    let mut files = Vec::new();
    for dir in SCANNED_DIRS {
        rust_files(&root.join(dir), &mut files);
    }
    assert!(!files.is_empty(), "guardrail scanned no files — check SCANNED_DIRS / workspace root");

    let mut violations = Vec::new();

    for file in &files {
        let Ok(src) = fs::read_to_string(file) else { continue };
        let lines: Vec<&str> = src.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            // Find a log-macro opener on this line.
            let opener = LOG_MACROS.iter().find_map(|m| line.find(m).map(|pos| (pos, *m)));
            let Some((pos, _macro)) = opener else {
                i += 1;
                continue;
            };
            // Per-line opt-out for genuinely non-identifying values (e.g. our own bind address).
            if line.contains("// soul-allow:") {
                i += 1;
                continue;
            }
            // Accumulate the full invocation across lines until parentheses balance.
            let start_line = i;
            let mut depth: i32 = 0;
            let mut started = false;
            let mut invocation = String::new();
            let mut j = i;
            let mut from = pos;
            'accumulate: while j < lines.len() {
                let chunk = &lines[j][from..];
                for ch in chunk.chars() {
                    invocation.push(ch);
                    match ch {
                        '(' => {
                            depth += 1;
                            started = true;
                        }
                        ')' => {
                            depth -= 1;
                            if started && depth == 0 {
                                break 'accumulate;
                            }
                        }
                        _ => {}
                    }
                }
                invocation.push('\n');
                j += 1;
                from = 0;
            }

            if let Some(tok) = has_forbidden(&invocation) {
                let rel = file.strip_prefix(&root).unwrap_or(file);
                violations.push(format!(
                    "{}:{} — log macro interpolates forbidden token `{}`",
                    rel.display(),
                    start_line + 1,
                    tok
                ));
            }
            i = j + 1;
        }
    }

    assert!(
        violations.is_empty(),
        "SOUL §3 / PD-2 violation: user-linkable network values must never reach logs.\n\
         Drop the field, or annotate the macro line with `// soul-allow: <reason>` if the value \
         is genuinely not user-linkable.\n\n{}",
        violations.join("\n")
    );
}
