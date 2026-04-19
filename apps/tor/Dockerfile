# syntax=docker/dockerfile:1.7

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd tor \
    && rm -rf /var/lib/apt/lists/*

COPY apps/tor/torrc /etc/tor/torrc

RUN mkdir -p /var/lib/tor \
    && chown -R debian-tor:debian-tor /var/lib/tor /etc/tor

USER debian-tor:debian-tor
WORKDIR /var/lib/tor

CMD ["tor", "-f", "/etc/tor/torrc"]
