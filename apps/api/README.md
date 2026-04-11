# apps/api

Browser-safe Rust HTTP API for public crawler analytics reads.

Responsibilities:

- expose read-only crawler analytics endpoints
- hide storage-adapter details from web and desktop clients
- keep request validation, pagination limits, and error shaping at the HTTP boundary

Default backend:

- PostgreSQL via `btc-network-postgres`

## Endpoints

- `GET /api/v1/crawler/runs?limit=<n>`
- `GET /api/v1/crawler/runs/:run_id`
- `GET /api/v1/crawler/asn?limit=<n>`

## Environment

- `BTC_NETWORK_API_BIND_ADDR` — bind address for the Axum server; defaults to `127.0.0.1:8080`
- `BTC_NETWORK_POSTGRES_URL` — PostgreSQL connection URL; defaults to `postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network`
- `BTC_NETWORK_POSTGRES_MAX_CONNECTIONS` — optional pool size; defaults to `16`
- `BTC_NETWORK_API_ALLOWED_ORIGINS` — optional comma-separated CORS allowlist
- `BTC_NETWORK_API_REQUEST_TIMEOUT_SECS` — optional per-request timeout; defaults to `10`
- `BTC_NETWORK_API_CONCURRENCY_LIMIT` — optional in-flight request cap; defaults to `64`

## Local Commands

- `make infra-postgres-up`
- `make infra-api-up`
- `make infra-crawler-api-up`
- `make infra-compose-down`
- `make postgres-migrate`
- `make api`
- `make api-test`
- `cargo test -p btc-network-api`
- `docker compose --profile api up`
- `docker compose --profile crawler --profile api up`

## Notes

- this app is intentionally read-only in the current slice
- local development uses the shared PostgreSQL service defined in the repository root `docker-compose.yml`
- the shared local PostgreSQL container uses PostgreSQL 18 with `PGDATA=/var/lib/postgresql/18/btc-network`
- enabling the `api` profile also runs the one-shot `postgres-migrate` service before the API process starts
- the profiled API service defaults to `BTC_NETWORK_API_CPUS=2.0` and `BTC_NETWORK_API_MEM_LIMIT=2g`; override them in your shell or a repository-root `.env` file before running `docker compose`
- API errors stay generic on the wire and keep adapter-specific detail in logs only
- the web and desktop analytics UI should use this app through `VITE_API_BASE_URL`, not through Tauri commands or direct database access
