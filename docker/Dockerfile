# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Stage 1: Build the mosaic binary
# ------------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder

# Install build dependencies and Rust nightly toolchain.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         adduser build-essential ca-certificates clang curl libclang-dev pkg-config \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
         | sh -s -- -y --default-toolchain nightly --profile minimal \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/root/.cargo/bin:${PATH}"

# Install FoundationDB client library (required by the fdb crate at link time).
# Map Docker TARGETARCH (amd64/arm64) to FDB's naming (amd64/aarch64).
ARG TARGETARCH
ARG FDB_VERSION=7.3.75
RUN FDB_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "amd64") \
    && curl -fsSLO --proto "=https" --tlsv1.2 \
    "https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_${FDB_ARCH}.deb" \
    && dpkg -i "foundationdb-clients_${FDB_VERSION}-1_${FDB_ARCH}.deb" \
    && rm -f "foundationdb-clients_${FDB_VERSION}-1_${FDB_ARCH}.deb"

WORKDIR /build

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml* ./
COPY .cargo .cargo
COPY bin bin
COPY crates crates

# Build the release binary
RUN cargo build --release --bin mosaic \
    && strip --strip-debug target/release/mosaic

# ------------------------------------------------------------------------------
# Stage 2: Minimal runtime image
# ------------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

# Install FoundationDB client library (required at runtime).
ARG TARGETARCH
ARG FDB_VERSION=7.3.75
RUN FDB_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "amd64") \
    && apt-get update \
    && apt-get install -y --no-install-recommends adduser ca-certificates curl \
    && curl -fsSLO --proto "=https" --tlsv1.2 \
    "https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_${FDB_ARCH}.deb" \
    && dpkg -i "foundationdb-clients_${FDB_VERSION}-1_${FDB_ARCH}.deb" \
    && rm -f "foundationdb-clients_${FDB_VERSION}-1_${FDB_ARCH}.deb" \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Volume mounts expected at runtime:
#   /etc/mosaic/config.toml            – mosaic configuration (required)
#   circuit artifact (.v5c)            – path configured via circuit.path in config.toml
#   table store directory              – path configured via table_store.root in config.toml (local_filesystem backend only)
#   FDB cluster file                   – path configured via storage.cluster_file in config.toml
RUN mkdir -p /etc/mosaic && chown ubuntu:ubuntu /etc/mosaic

COPY --from=builder /build/target/release/mosaic /usr/local/bin/mosaic
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER ubuntu

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
