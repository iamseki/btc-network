# syntax=docker/dockerfile:1.7

FROM rust:1.95.0-bookworm AS builder

WORKDIR /workspace

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/target \
    cargo build --locked --profile dist \
    -p btc-network-crawler \
    -p btc-network-postgres-migrate \
    && mkdir -p /out \
    && cp /workspace/target/dist/btc-network-crawler /out/btc-network-crawler \
    && cp /workspace/target/dist/btc-network-postgres-migrate /out/btc-network-postgres-migrate

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd \
    --system \
    --uid 10001 \
    --create-home \
    --home-dir /home/btc-network \
    --shell /usr/sbin/nologin \
    btc-network \
    && mkdir -p /data/mmdb \
    && chown -R btc-network:btc-network /data/mmdb

COPY --from=builder /out/btc-network-crawler /usr/local/bin/btc-network-crawler
COPY --from=builder /out/btc-network-postgres-migrate /usr/local/bin/btc-network-postgres-migrate

USER btc-network:btc-network
WORKDIR /home/btc-network

ENTRYPOINT ["/usr/local/bin/btc-network-crawler"]
