# Crawler Local Development

The preferred local crawler path now uses:

- Docker Compose for the shared local PostgreSQL service used by the crawler and API
- host-managed MMDB files under `.dev-data/mmdb/`
- explicit migrations before the crawler starts

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

## Apply Migrations

Migrations stay explicit. They are not tied to crawler startup.

```bash
make postgres-migrate
```

That uses the preferred local PostgreSQL defaults automatically.

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
