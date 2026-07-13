# NIL VPN client

The client is a Tauri application with a React/Vite interface and a Rust control plane in
`src-tauri`. It manages the recoverable account secret, encrypted local vault, batched Privacy Pass
inventory, Coordinator redemption, trust-bundle validation, and the platform tunnel lifecycle.

> **Status (2026-07-12): engineering alpha.** Desktop release builds require a Coordinator-issued
> path with at least two hops. The current Android and Apple native engines implement one hop only,
> so packaged non-debug mobile clients fail with `NativeMultiHopUnavailable` before removing a pass
> from the vault or contacting the Coordinator.

## Development

```sh
pnpm install
pnpm test
pnpm build
pnpm tauri dev
```

The debug build retains explicit local integration paths. Those paths are compiled out of normal
release builds and are not release evidence. See the repository [README](../README.md) before
changing connection or trust behavior.

## Security boundaries

- Account authentication material, bearer passes, exact pending batch-blinding state, and an
  ID-bound pending redemption are held in one encrypted, versioned vault backed by the operating
  system's protected key facility; there is no plaintext release fallback.
- A pass is atomically reserved before Coordinator redemption because it is single-use. Preflight
  failures leave the vault unchanged; completion clears only the matching random reservation ID.
  Android/iOS consent, grant handoff, status reconciliation, and commit run through a private
  Rust-held plugin handle, so bearer start arguments never cross JavaScript.
- The client accepts release trust inputs only through the embedded trust-bundle path. Closing the
  signed release-artifact and measured-image chain remains a separate release blocker.
- A selected node can observe network metadata appropriate to its position. Blind issuance prevents
  a direct cryptographic account-to-redemption join, but it does not eliminate timing, volume, or
  infrastructure correlation.

Platform integration details and evidence requirements live in
[`crates/nil-android`](../crates/nil-android/README.md) and
[`crates/nil-apple`](../crates/nil-apple/README.md).
