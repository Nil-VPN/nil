# Builds nil-node + nil-cli for the Docker verification harness (Linux).
# BuildKit cache mounts keep the BoringSSL/quiche build cached across iterations.
FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# Phase 2: RA-TLS attestation replaces the dev TLS bypass; nil-node is built with the
# `synthetic-attest` feature so the Docker harness can attest without real TEE hardware.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p nil-node --features synthetic-attest && \
    cargo build --release -p nil-cli && \
    mkdir -p /out && \
    cp target/release/nil-node target/release/nil-cli /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables procps ethtool curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/nil-node /usr/local/bin/nil-node
COPY --from=builder /out/nil-cli /usr/local/bin/nil-cli
