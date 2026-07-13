# Client trust bundle

> **Schema documentation, not production roots.** No independently published production bundle or
> closed artifact-to-measurement chain exists yet, and this remains a pre-release, NO-GO artifact.
> The example below is deliberately unusable for a real release.

Release clients embed one independently reviewed trust-bundle v1. The bundle is the client-side
root for token issuer consistency, confidential-guest measurements, and the measurement
transparency log. It is public configuration, not a secret.

`bundle.example.json` is schema documentation only. Its RSA private key was discarded and its
repeated measurement/log-key bytes are obvious placeholders. It must never be used for a release.

## Schema

- `version`: exactly `1`.
- `issuer_public_keys_der`: one or more globally consistent token issuer RSA public DER keys,
  lowercase hex. Include old and new keys together only for a reviewed rotation window.
- `node_measurements`: one or more 48-byte guest measurements, lowercase hex.
- `transparency_log_ed25519_key`: exactly one 32-byte Ed25519 public key, lowercase hex.

Unknown fields, empty lists, duplicates, uppercase/malformed hex, wrong lengths, and unusable token
issuer DER keys fail the build. `build.rs` canonicalizes and embeds the JSON; the runtime reads it
through an immutable `OnceLock`.

## Release setup

Set the GitHub repository variable `NIL_TRUST_BUNDLE_JSON` to the reviewed one-line or multiline
JSON. `.github/workflows/release-sign.yml` passes it to every platform build. A missing or invalid
variable makes a release-profile Rust build fail before Tauri packaging or signing.

For a local validation build:

```sh
NIL_TRUST_BUNDLE_JSON="$(tr -d '\n' < client/trust/bundle.example.json)" \
  cargo check -p nil-client --release
```

Do not ship that example. Production roots should come from the independently published release
manifest/transparency process, be reviewed as one global value, and change only through an explicit
key/measurement rotation.

In debug builds only, absence of the bundle retains the existing env-driven development behavior.
When a bundle is embedded, `NW_TOKEN_ISSUER_PUBKEYS`, `NW_EXPECTED_MEASUREMENT`,
`NW_PINNED_MEASUREMENTS`, and `NW_TRANSPARENCY_LOG_KEY` may select matching embedded values, but can
never add trust outside the bundle.
