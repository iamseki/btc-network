# apps/api

Browser-safe Rust HTTP API for public network analytics reads.

Responsibilities:

- expose read-only network analytics endpoints
- hide storage-adapter details from web and desktop clients
- keep request validation, pagination limits, and error shaping at the HTTP boundary

Default backend:

- PostgreSQL via `btc-network-postgres`

## Endpoints

- `GET /api/openapi.json`
- `GET /api/docs/config.json`
- `GET /docs`
- `GET /api/v1/network/historical/runs?limit=<n>`
- `GET /api/v1/network/historical/runs/:run_id`
- `GET /api/v1/network/historical/asns?limit=<n>`
- `GET /api/v1/network/last-run/services?limit=<n>`
- `GET /api/v1/network/last-run/protocol-versions?limit=<n>`
- `GET /api/v1/network/last-run/user-agents?limit=<n>`
- `GET /api/v1/network/last-run/network-types?limit=<n>`
- `GET /api/v1/network/last-run/countries?limit=<n>`
- `GET /api/v1/network/last-run/asns?limit=<n>`
- `GET /api/v1/network/last-run/start-heights?limit=<n>`
- `GET /api/v1/network/last-run/asn-organizations?limit=<n>`
- `GET /api/v1/network/last-run/nodes?limit=<n>`

## Environment

- `BTC_NETWORK_API_BIND_ADDR` — bind address for the Axum server; defaults to `127.0.0.1:8080`
- `BTC_NETWORK_POSTGRES_URL` — PostgreSQL connection URL; defaults to `postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network`
- `BTC_NETWORK_POSTGRES_MAX_CONNECTIONS` — optional pool size; defaults to `16`
- `BTC_NETWORK_API_ALLOWED_ORIGINS` — optional comma-separated CORS allowlist
- `BTC_NETWORK_API_REQUEST_TIMEOUT_SECS` — optional per-request timeout; defaults to `10`
- `BTC_NETWORK_API_CONCURRENCY_LIMIT` — optional in-flight request cap; defaults to `64`
- `BTC_NETWORK_API_DOCS_TITLE` — optional OpenAPI and docs UI title; defaults to `btc-network API`
- `BTC_NETWORK_API_DOCS_VERSION` — optional OpenAPI and docs UI version; defaults to the crate version
- `BTC_NETWORK_API_DOCS_DESCRIPTION` — optional shared OpenAPI and docs UI description used by hosted docs and embedded web API reference
- `BTC_NETWORK_API_DOCS_INTRODUCTION` — optional shared introduction copy exposed by `/api/docs/config.json` for embedded docs surfaces
- `BTC_NETWORK_API_PUBLIC_BASE_URL` — optional absolute public API base URL used in the OpenAPI `servers` list and docs UI config

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
- OpenAPI is generated from Rust handlers and shared response models via `utoipa`; Scalar UI is served from the same app via `utoipa-scalar`
- `/api/docs/config.json` exposes shared docs metadata, intro copy, and the canonical OpenAPI URL so the web app can render the same API reference without duplicating config
- docs title, version, description, introduction, and public base URL can all be configured at runtime so hosted docs and embedded docs surfaces stay in sync without frontend copy drift
- the intended web integration path is to fetch `/api/docs/config.json`, then pass `openapiUrl` into a Scalar React reference component or another OpenAPI viewer using the generated spec as the single source of truth
- last-run endpoints read from the latest finished crawl run only
- local development uses the shared PostgreSQL service defined in the repository root `docker-compose.yml`
- the `api` Compose profile now builds `apps/api/Dockerfile` into a slim runtime image instead of compiling on every container start
- the shared local PostgreSQL container uses PostgreSQL 18 with `PGDATA=/var/lib/postgresql/18/btc-network`
- enabling the `api` profile also runs the one-shot `postgres-migrate` service before the API process starts
- the profiled API service defaults to `BTC_NETWORK_API_CPUS=2.0` and `BTC_NETWORK_API_MEM_LIMIT=2g`; override them in your shell or a repository-root `.env` file before running `docker compose`
- API errors stay generic on the wire and keep adapter-specific detail in logs only
- the web and desktop analytics UI should use this app through `VITE_API_BASE_URL`, not through Tauri commands or direct database access
