# apps/api

Browser-safe Rust HTTP API for public crawler analytics reads.

Responsibilities:

- expose read-only crawler analytics endpoints
- hide ClickHouse adapter details from web and desktop clients
- keep request validation, pagination limits, and error shaping at the HTTP boundary

Non-responsibilities:

- direct crawler control
- authentication or authorization for future control-plane actions
- desktop-only behavior
- raw SQL exposure

## Endpoints

- `GET /api/v1/crawler/runs?limit=<n>`
- `GET /api/v1/crawler/runs/:run_id`
- `GET /api/v1/crawler/asn?limit=<n>`

## Environment

- `BTC_NETWORK_API_BIND_ADDR` — bind address for the Axum server; defaults to `127.0.0.1:8080`
- `BTC_NETWORK_CLICKHOUSE_URL` — ClickHouse HTTP URL; defaults to `http://localhost:8123`
- `BTC_NETWORK_CLICKHOUSE_DATABASE` — ClickHouse database name; defaults to `btc_network`
- `BTC_NETWORK_CLICKHOUSE_USER` — optional ClickHouse user
- `BTC_NETWORK_CLICKHOUSE_PASSWORD` — optional ClickHouse password
- `BTC_NETWORK_API_ALLOWED_ORIGINS` — optional comma-separated CORS allowlist; defaults to local Vite, common Tauri local origins, `https://btcnetwork.info`, and `https://www.btcnetwork.info`
- `BTC_NETWORK_API_REQUEST_TIMEOUT_SECS` — optional per-request timeout; defaults to `10`
- `BTC_NETWORK_API_CONCURRENCY_LIMIT` — optional in-flight request cap; defaults to `64`

## Local Commands

- `make api`
- `make api-test`
- `cargo run -p btc-network-api`
- `cargo test -p btc-network-api`

## Notes

- this app is intentionally read-only in the current slice
- API errors should stay generic on the wire and keep adapter-specific detail in logs only
- the web and desktop analytics UI should use this app through `VITE_API_BASE_URL`, not through Tauri commands or direct ClickHouse access
- CORS is now allowlist-based rather than wildcard-based; set `BTC_NETWORK_API_ALLOWED_ORIGINS` explicitly when deploying to a different frontend origin
