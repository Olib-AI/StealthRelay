# =============================================================================
# StealthOS Relay Server — Multi-stage Docker Build
# =============================================================================
# Produces a minimal image with the release binary, CA certificates, and
# timezone data. Runs as non-root (stealthos).
#
# Uses Debian for multi-arch support (amd64 + arm64). For x86_64-only Arch
# Linux builds, see Dockerfile.archlinux.
#
# Build:  docker build -t stealth-relay .
# Run:    docker run -p 9090:9090 -p 9091:9091 stealth-relay

# ---------------------------------------------------------------------------
# Stage 1: Build the release binary
# ---------------------------------------------------------------------------
FROM rust:1.87-bookworm AS builder

# Install build dependencies for aws-lc-rs (used by rustls).
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake perl pkg-config libclang-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy everything and build.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY config/ config/
RUN cargo build --release --locked -p stealthos-server

# ---------------------------------------------------------------------------
# Stage 2: Minimal Debian runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -s /usr/sbin/nologin stealthos && \
    mkdir -p /var/stealth-relay/keys && \
    chown stealthos:stealthos /var/stealth-relay/keys

# Copy the release binary.
COPY --from=builder /build/target/release/stealth-relay /usr/local/bin/stealth-relay

# Copy default configuration.
COPY config/default.toml /etc/stealth-relay/config.toml

# Run as non-root.
USER stealthos

# WebSocket port + metrics port.
EXPOSE 9090 9091

# Health check against the internal metrics endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/stealth-relay", "healthcheck", "--url", "http://127.0.0.1:9091/health"]

ENTRYPOINT ["/usr/local/bin/stealth-relay"]
CMD ["serve", "--config", "/etc/stealth-relay/config.toml"]
