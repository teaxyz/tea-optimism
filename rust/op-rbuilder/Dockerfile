# tea-op-rbuilder Docker build
# Builds op-rbuilder with Tea's custom EVM (GPG precompile + TEA L1 costs).
#
# Build context: rust/ (workspace root)
#   docker build -t tea-op-rbuilder -f op-rbuilder/Dockerfile .

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

RUN cargo build --profile ${BUILD_PROFILE} --bin op-rbuilder \
    --manifest-path /app/op-rbuilder/crates/op-rbuilder/Cargo.toml

RUN cp /app/target/${BUILD_PROFILE}/op-rbuilder /app/op-rbuilder-bin

# ---------------------------------------------------------------------------
# Runtime: minimal image with just the binary
# ---------------------------------------------------------------------------
FROM ubuntu AS runtime

RUN apt-get update && \
    apt-get install -y ca-certificates libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/op-rbuilder-bin /app/rbuilder
RUN chmod +x /app/rbuilder

EXPOSE 9550 9551 1111 6061 30304
ENTRYPOINT ["/app/rbuilder"]
