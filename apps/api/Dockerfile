# syntax=docker/dockerfile:1.7

FROM rust:1.93.1-bookworm AS builder

WORKDIR /workspace

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/target \
    cargo build --locked --profile dist -p btc-network-api \
    && mkdir -p /out \
    && cp /workspace/target/dist/btc-network-api /out/btc-network-api

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
    btc-network

COPY --from=builder /out/btc-network-api /usr/local/bin/btc-network-api

USER btc-network:btc-network
WORKDIR /home/btc-network

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/btc-network-api"]
