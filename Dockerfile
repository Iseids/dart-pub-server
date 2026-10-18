FROM rust:1-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY migrations ./migrations

RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 registry \
    && useradd --system --uid 10001 --gid registry --home-dir /data registry \
    && mkdir -p /data \
    && chown registry:registry /data

COPY --from=builder /app/target/release/pub-registry /usr/local/bin/pub-registry

ENV BIND_ADDRESS=0.0.0.0:6844 \
    DATA_DIR=/data \
    DATABASE_URL=sqlite:///data/registry.db \
    MAX_UPLOAD_MB=32 \
    PUBLIC_READS=true \
    RUST_LOG=info

WORKDIR /data
VOLUME ["/data"]
EXPOSE 6844
USER registry:registry

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:6844/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/pub-registry"]
CMD ["serve"]
