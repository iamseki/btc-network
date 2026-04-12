# Crawler Local Development

The preferred local crawler path now uses:

- Docker Compose for the shared local PostgreSQL service used by the crawler and API
- host-managed MMDB files under `.dev-data/mmdb/`
- explicit migrations before host-run crawler startup, or the profiled `postgres-migrate` container path

There are now two supported local paths:

- host-run binaries with explicit `make postgres-migrate`
- Docker Compose profiles where `postgres-migrate` runs as a one-shot dependency

## Typical Local Flow

1. Run `make crawler-mmdb-update`.
2. Run `make infra-postgres-up`.
3. Run `make postgres-migrate`.
4. Run `make crawler ARGS="--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb"`.

## Local Paths

- PostgreSQL data: `.dev-data/postgres/`
- ASN MMDB: `.dev-data/mmdb/GeoLite2-ASN.mmdb`
- country MMDB: `.dev-data/mmdb/GeoLite2-Country.mmdb`

## Download Or Refresh MMDB Files

From the repository root:

```bash
make crawler-mmdb-update
```

That command downloads the current ASN and country MMDB tarballs without running package install scripts and writes the extracted `.mmdb` files under `.dev-data/mmdb/`.

## Start PostgreSQL

From the repository root:

```bash
make infra-postgres-up
```

The local development container uses:

- database URL: `postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network`
- user: `btc_network_dev`
- password: `btc_network_dev`
- data root mount: `.dev-data/postgres/` -> `/var/lib/postgresql`
- active PGDATA: `/var/lib/postgresql/18/btc-network`

Stop it with:

```bash
make infra-postgres-down
```

Reset local data with:

```bash
make infra-postgres-reset
```

If your local `.dev-data/postgres/` was created by an older PostgreSQL image or
the old `/var/lib/postgresql/data` mount layout, run `make infra-postgres-reset`
once before bringing the service back up. That clears incompatible dev data and
lets PostgreSQL 18 initialize the new versioned data directory layout.

## Compose Profiles

The repository root `docker-compose.yml` keeps `postgres` unprofiled so it can
act as the shared base service, then layers app services behind Docker
profiles:

- `crawler` profile: `postgres` + `postgres-migrate` + `crawler`
- `api` profile: `postgres` + `postgres-migrate` + `api`
- both profiles together: `postgres` + `postgres-migrate` + `crawler` + `api`

Useful commands from the repository root:

```bash
docker compose up postgres
docker compose --profile crawler up
docker compose --profile crawler --profile api up
docker compose down
```

Equivalent `make` wrappers:

```bash
make infra-postgres-up
make infra-crawler-up
make infra-crawler-api-up
make infra-compose-down
```

The profiled services run the checked-in Rust binaries inside a shared
`rust:1.93.1-bookworm` container image and reuse named Cargo caches for
dependency downloads and build artifacts.

The profiled crawler service also sets default runtime tuning through
environment variables in `compose/crawler.yml`, including:

- `BTC_NETWORK_CRAWLER_MAX_CONCURRENCY=10000`
- `BTC_NETWORK_CRAWLER_MAX_TRACKED_NODES=500000`
- `BTC_NETWORK_POSTGRES_MAX_CONNECTIONS=16`
- `BTC_NETWORK_CRAWLER_CONNECT_MAX_ATTEMPTS=10`
- `BTC_NETWORK_CRAWLER_CONNECT_RETRY_BACKOFF_MS=250`
- `BTC_NETWORK_CRAWLER_CONNECT_TIMEOUT_SECS=30`
- `BTC_NETWORK_CRAWLER_IO_TIMEOUT_SECS=20`
- `BTC_NETWORK_MMDB_ASN_PATH=/workspace/.dev-data/mmdb/GeoLite2-ASN.mmdb`
- `BTC_NETWORK_MMDB_COUNTRY_PATH=/workspace/.dev-data/mmdb/GeoLite2-Country.mmdb`

Compose resource defaults are also set there:

- `BTC_NETWORK_CRAWLER_CPUS=6.0`
- `BTC_NETWORK_CRAWLER_MEM_LIMIT=12g`
- `BTC_NETWORK_CRAWLER_NOFILE_SOFT=65536`
- `BTC_NETWORK_CRAWLER_NOFILE_HARD=65536`

Override any of these by exporting them in your shell or by adding them to a
repository-root `.env` file before running `docker compose`.

High crawler concurrency needs a high container open-file limit. Each in-flight
peer visit consumes at least one socket file descriptor, and the process also
needs descriptors for PostgreSQL, epoll/event-loop state, MMDB files, and
stdio. The Compose crawler service sets `ulimits.nofile` to `65536` by default
so high concurrency does not fail later with `Too many open files (os error
24)` during checkpoint or observation writes.

The crawler only has a small number of concurrent PostgreSQL writers, so the
Compose default also keeps `BTC_NETWORK_POSTGRES_MAX_CONNECTIONS` modest at
`16`. That preserves file descriptors for peer sockets instead of reserving an
oversized database pool that the crawler does not use.

## Apply Migrations

Migrations stay explicit. They are not tied to crawler startup.

```bash
make postgres-migrate
```

That uses the preferred local PostgreSQL defaults automatically.

This explicit migration step applies to the host-run workflow above. When you
use the Compose profiles, `postgres-migrate` runs automatically before the
`crawler` or `api` service starts.

## Run The Crawler

```bash
make crawler ARGS="--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb"
```

Optional PostgreSQL overrides:

- `--postgres-url`
- `--postgres-max-connections`

Optional crawler tuning overrides:

- `--max-concurrency`
- `--max-tracked-nodes`
- `--max-runtime-minutes`
- `--idle-timeout-minutes`
- `--checkpoint-interval-secs`
- `--connect-timeout-secs`
- `--connect-max-attempts`
- `--connect-retry-backoff-ms`
- `--io-timeout-secs`
- `--shutdown-grace-period-secs`

The crawler still runs without MMDB files, but enrichment will be unavailable and ASN/country data will not be persisted.

The profiled `crawler` container now defaults to the checked-out
`.dev-data/mmdb/*.mmdb` paths. Run `make crawler-mmdb-update` before starting
the Compose crawler stack so those files exist on the bind-mounted workspace.

Do not bake MMDB files into a crawler image for this local workflow. They are
host-managed datasets refreshed on a weekly cadence, so bind-mounting the
checked-out repository data is simpler and avoids rebuilding an image just to
pick up fresh GeoLite files.

## Inspect Data

If you have `psql` installed locally:

```bash
psql postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network
```

Useful first queries:

```sql
SELECT
    run_id,
    phase,
    checkpointed_at,
    frontier_size,
    scheduled_tasks,
    successful_handshakes,
    failed_tasks,
    persisted_observation_rows
FROM crawler_run_checkpoints
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 10;
```

```sql
SELECT
    run_id,
    phase,
    checkpointed_at,
    recovery_frontier_size,
    octet_length(frontier_payload) AS compressed_payload_bytes,
    payload_encoding
FROM crawler_run_recovery_points
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 10;
```

```sql
SELECT
    endpoint,
    network_type,
    handshake_status,
    failure_classification,
    enrichment_status,
    asn,
    country
FROM node_observations
ORDER BY observed_at DESC, observation_id DESC
LIMIT 20;
```

`crawler_run_checkpoints` is progress history only. Crash-restart state lives in `crawler_run_recovery_points` as a compressed frontier payload.
