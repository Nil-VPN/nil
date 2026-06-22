# Builds nil-node + nil-cli for the Docker verification harness (Linux).
# BuildKit cache mounts keep the BoringSSL/quiche build cached across iterations.
FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# nil-cli is built with `dev-insecure` (self-signed Phase-1 node); nil-node has no such flag.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p nil-node && \
    cargo build --release -p nil-cli --features dev-insecure && \
    mkdir -p /out && \
    cp target/release/nil-node target/release/nil-cli /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables procps ethtool curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/nil-node /usr/local/bin/nil-node
COPY --from=builder /out/nil-cli /usr/local/bin/nil-cli
