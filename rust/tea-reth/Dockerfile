# tea-reth Docker build
# Single-pass build (no cargo-chef) to minimize disk usage.
#
# Build context: rust/ (workspace root)
#   docker build -t tea-reth -f tea-reth/Dockerfile .

FROM rust:1 AS builder
WORKDIR /app

RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config curl

ARG OP_REVM_VERSION=15.0.0
ARG BUILD_PROFILE=release

# Copy full source
COPY . .

# vendor/op-revm may or may not exist in context (.gitignored but not .dockerignored).
# If absent, download from crates.io and apply Tea's L1 cost multiplier patch.
RUN if [ ! -f vendor/op-revm/Cargo.toml ]; then \
      echo "Vendoring op-revm v${OP_REVM_VERSION} from crates.io..." && \
      mkdir -p vendor && \
      curl -sL https://crates.io/api/v1/crates/op-revm/${OP_REVM_VERSION}/download | tar xz -C vendor && \
      mv vendor/op-revm-${OP_REVM_VERSION} vendor/op-revm && \
      cd vendor/op-revm && patch -p1 < ../../patches/op-revm-l1-cost-multiplier.patch; \
    else \
      echo "vendor/op-revm already present in context, skipping download."; \
    fi

RUN cargo build --profile ${BUILD_PROFILE} --bin tea-reth \
    --manifest-path /app/tea-reth/Cargo.toml

RUN cp /app/target/${BUILD_PROFILE}/tea-reth /app/tea-reth-bin

# ---------------------------------------------------------------------------
# Runtime: minimal image with just the binary
# ---------------------------------------------------------------------------
FROM ubuntu AS runtime

RUN apt-get update && \
    apt-get install -y ca-certificates libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/tea-reth-bin /usr/local/bin/tea-reth
RUN chmod +x /usr/local/bin/tea-reth

EXPOSE 30303 30303/udp 8545 8546 8551 6060
ENTRYPOINT ["/usr/local/bin/tea-reth"]
