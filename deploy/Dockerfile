# Builds nil-node + nil-cli for the Docker verification harness (Linux).
# BuildKit cache mounts keep the BoringSSL/quiche build cached across iterations.
# Pinned base + toolchain (rust-toolchain.toml pins 1.96.0) for build reproducibility.
FROM --platform=linux/amd64 rust:1.96.0-bookworm@sha256:19817ead3289c8c631c73df281e18b59b172f6a31f4f563290f69cddd06c30e9 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang pkg-config && rm -rf /var/lib/apt/lists/*
# Determinism knobs (see deploy/reproducible-build.sh): fixed source date, no incremental
# build, stable locale/timezone, and path remapping so absolute paths don't leak into the
# binary. SOURCE_DATE_EPOCH defaults to 0; the reproducible-build script passes the commit time.
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_INCREMENTAL=0 \
    LC_ALL=C \
    TZ=UTC \
    RUSTFLAGS="--remap-path-prefix=/build=/src --remap-path-prefix=/usr/local/cargo=/cargo"
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ ./crates/
COPY client/src-tauri/ ./client/src-tauri/
COPY client/trust/ ./client/trust/
# Phase 2: RA-TLS attestation replaces the dev TLS bypass; nil-node is built with the
# `synthetic-attest` feature so the Docker harness can attest without real TEE hardware. The
# optimized `e2e` profile retains debug assertions, which is required by the compile-time guards
# on synthetic attestation, diagnostics, and incomplete fallback responders.
# `--locked` pins the committed Cargo.lock (required for reproducibility).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --profile e2e --locked -p nil-node --no-default-features --features synthetic-attest,dev-trace,dev-fallbacks && \
    cargo build --profile e2e --locked -p nil-cli --features synthetic-attest,dev-trace,dev-fallbacks && \
    mkdir -p /out && \
    cp target/e2e/nil-node target/e2e/nil-cli /out/

FROM --platform=linux/amd64 debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables procps ethtool curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/nil-node /usr/local/bin/nil-node
COPY --from=builder /out/nil-cli /usr/local/bin/nil-cli
