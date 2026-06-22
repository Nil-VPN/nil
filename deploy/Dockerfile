# Builds nil-node + nil-cli for the Docker verification harness (Linux).
# BuildKit cache mounts keep the BoringSSL/quiche build cached across iterations.
# Pinned base + toolchain (rust-toolchain.toml pins 1.96.0) for build reproducibility.
FROM rust:1.96.0-bookworm AS builder
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
COPY . .
# Phase 2: RA-TLS attestation replaces the dev TLS bypass; nil-node is built with the
# `synthetic-attest` feature so the Docker harness can attest without real TEE hardware.
# `--locked` pins the committed Cargo.lock (required for reproducibility).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p nil-node --features synthetic-attest && \
    cargo build --release --locked -p nil-cli --features synthetic-attest && \
    mkdir -p /out && \
    cp target/release/nil-node target/release/nil-cli /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables procps ethtool curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/nil-node /usr/local/bin/nil-node
COPY --from=builder /out/nil-cli /usr/local/bin/nil-cli
