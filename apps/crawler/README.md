# Crawler Local Development

The preferred local development path for the crawler uses:

- Docker Compose for the shared local ClickHouse used by the crawler and API
- host-managed MMDB files under `.dev-data/mmdb/`
- explicit migrations before the crawler starts

## Typical Local Flow

1. Run `make crawler-mmdb-update`.
2. Run `make infra-clickhouse-up`.
3. Run `make clickhouse-migrate`.
4. Run `make crawler ARGS="--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb --max-tracked-nodes 500000 --connect-max-attempts 10 --connect-retry-backoff-ms 250 --connect-timeout-secs 30 --io-timeout-secs 20"`.

## Local Paths

Use these local development paths from the repository root:

- ClickHouse data: `.dev-data/clickhouse/`
- ASN MMDB: `.dev-data/mmdb/GeoLite2-ASN.mmdb`
- country MMDB: `.dev-data/mmdb/GeoLite2-Country.mmdb`

The MMDB files are not committed to this repository. Download or provision them locally and place them under `.dev-data/mmdb/`.

## Download Or Refresh MMDB Files

The preferred local source is the public [`sapics/ip-location-db`](https://github.com/sapics/ip-location-db) project, which BNDD-0001 already references for ASN and country MMDB data.

This repository uses these npm packages from that source for local development:

- `@ip-location-db/geolite2-asn-mmdb`
- `@ip-location-db/geolite2-country-mmdb`

From the repository root:

```bash
make crawler-mmdb-update
```

That command:

- downloads the current package tarballs with `npm pack`
- extracts `geolite2-asn.mmdb` and `geolite2-country.mmdb`
- writes them to:
  - `.dev-data/mmdb/GeoLite2-ASN.mmdb`
  - `.dev-data/mmdb/GeoLite2-Country.mmdb`
- stores the upstream README and GeoLite2 license files next to them

The script uses `npm pack` instead of `npm install`, so it fetches the published tarballs without running package install scripts.

### Keeping Them Up To Date

The upstream `sapics/ip-location-db` project currently documents GeoLite2 country and ASN updates as twice weekly.

For local development, the practical rule is:

1. run `make crawler-mmdb-update` when setting up a new machine
2. run it again before long crawler runs or when you want fresher enrichment data
3. re-run it any time you want to refresh the local `.dev-data/mmdb/` copies in place

The local development copies are disposable. The source of truth stays upstream, not in this repository.

## Start ClickHouse

From the repository root:

```bash
make infra-clickhouse-up
```

This starts the shared local ClickHouse service defined in [`docker-compose.yml`](../../docker-compose.yml) and exposes it on `http://localhost:8123`.
The command waits for the container healthcheck before it returns.

The local development container is configured with these credentials:

- database: `btc_network`
- user: `btc_network_dev`
- password: `btc_network_dev`

To stop it:

```bash
make infra-clickhouse-down
```

To inspect logs:

```bash
docker compose -f docker-compose.yml logs -f clickhouse
```

## Apply Migrations

Migrations stay explicit. They are not tied to crawler startup.

From the repository root:

```bash
make clickhouse-migrate
```

That uses the preferred local ClickHouse development settings automatically:

- URL: `http://localhost:8123`
- database: `btc_network`
- user: `btc_network_dev`
- password: `btc_network_dev`

These are local development defaults provided by the repository Make targets.
The dedicated migration binary still only defaults the URL and database; it does not hardcode a global username or password.

If you need different settings, pass them through `ARGS`:

```bash
make clickhouse-migrate ARGS="--clickhouse-user another_user --clickhouse-password another_password"
```

If you already initialized `.dev-data/clickhouse/` with older local settings and keep seeing authentication failures, reset the local dev data once and start again:

```bash
make infra-clickhouse-reset
make infra-clickhouse-up
make clickhouse-migrate
```

## Run The Crawler

With local MMDB files in place:

```bash
make crawler ARGS="--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb"
```

`make crawler` also injects the same local ClickHouse development defaults automatically, so it matches `make infra-clickhouse-up` and `make clickhouse-migrate` out of the box.

You can also provide the same paths through environment variables:

```bash
export BTC_NETWORK_MMDB_ASN_PATH=.dev-data/mmdb/GeoLite2-ASN.mmdb
export BTC_NETWORK_MMDB_COUNTRY_PATH=.dev-data/mmdb/GeoLite2-Country.mmdb
make crawler
```

Optional ClickHouse overrides:

- `--clickhouse-url`
- `--clickhouse-database`
- `--clickhouse-user`
- `--clickhouse-password`

Optional crawler tuning overrides:

- `--max-concurrency`
- `--max-tracked-nodes`
- `--max-runtime-minutes`
- `--idle-timeout-minutes`
- `--connect-timeout-secs`
- `--connect-max-attempts`
- `--connect-retry-backoff-ms`
- `--io-timeout-secs`
- `--shutdown-grace-period-secs`

The crawler will still run without MMDB files, but enrichment will be unavailable and ASN/country data will not be persisted.

## Inspect Data

The quickest built-in option is the native `clickhouse-client` shell.

If you have it installed locally, connect to the local dev instance with:

```bash
clickhouse-client --host localhost --port 9000 --database btc_network --user btc_network_dev --password btc_network_dev
```

Useful first queries:

Quick glossary for the checkpoint metrics used below:

- `unique_nodes`: every endpoint discovered and accepted into tracking during the run
- `frontier_size`: the current pending frontier, meaning discovered endpoints still waiting to be attempted by a worker
- `scheduled_tasks`: node attempts already dequeued by workers
- `successful_handshakes`: currently counts successful node visits, which means the handshake plus peer-discovery path completed for that node
- `handshake_status` in `node_observations` is a historical field name; `failed` means the node visit failed somewhere, so use `failure_classification` for the exact stage

During an active run, start with the latest checkpoint stream for the most recent `run_id`:

```sql
WITH latest_run AS (
    SELECT run_id
    FROM crawler_run_checkpoints
    ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
    LIMIT 1
)
SELECT
    run_id,
    phase,
    checkpointed_at,
    frontier_size,
    in_flight_work,
    scheduled_tasks,
    successful_handshakes,
    failed_tasks,
    persisted_observation_rows,
    writer_backlog
FROM crawler_run_checkpoints
WHERE run_id = (SELECT run_id FROM latest_run)
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 10;
```

To inspect what is currently failing in that run, include `failure_classification` rather than relying on `handshake_status` alone:

```sql
WITH latest_run AS (
    SELECT run_id
    FROM crawler_run_checkpoints
    ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
    LIMIT 1
)
SELECT
    observed_at,
    endpoint,
    network_type,
    handshake_status,
    failure_classification,
    latency_ms,
    enrichment_status,
    asn,
    country
FROM node_observations
WHERE crawl_run_id = (SELECT run_id FROM latest_run)
  AND handshake_status = 'failed'
ORDER BY observed_at DESC
LIMIT 20;
```

After a run finishes, the latest checkpoint for that `run_id` is the quickest summary:

```sql
WITH latest_run AS (
    SELECT run_id
    FROM crawler_run_checkpoints
    ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
    LIMIT 1
)
SELECT
    run_id,
    phase,
    started_at,
    checkpointed_at,
    stop_reason,
    failure_reason,
    scheduled_tasks,
    successful_handshakes,
    failed_tasks,
    unique_nodes,
    discovered_node_states,
    persisted_observation_rows
FROM crawler_run_checkpoints
WHERE run_id = (SELECT run_id FROM latest_run)
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 1;
```

Failure mix by stage for the latest run:

```sql
WITH latest_run AS (
    SELECT run_id
    FROM crawler_run_checkpoints
    ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
    LIMIT 1
)
SELECT
    failure_classification,
    count() AS failures
FROM node_observations
WHERE crawl_run_id = (SELECT run_id FROM latest_run)
  AND handshake_status = 'failed'
GROUP BY failure_classification
ORDER BY failures DESC, failure_classification ASC;
```

Compare the latest checkpoint summary across runs:

```sql
SELECT
    run_id,
    phase,
    scheduled_tasks,
    unique_nodes,
    frontier_size,
    in_flight_work,
    persisted_rows,
    unique_nodes - scheduled_tasks AS unscheduled_gap,
    round(100.0 * scheduled_tasks / nullIf(unique_nodes, 0), 2) AS scheduled_pct
FROM (
    SELECT
        run_id,
        argMax(phase, tuple(checkpointed_at, checkpoint_sequence)) AS phase,
        argMax(scheduled_tasks, tuple(checkpointed_at, checkpoint_sequence)) AS scheduled_tasks,
        argMax(unique_nodes, tuple(checkpointed_at, checkpoint_sequence)) AS unique_nodes,
        argMax(frontier_size, tuple(checkpointed_at, checkpoint_sequence)) AS frontier_size,
        argMax(in_flight_work, tuple(checkpointed_at, checkpoint_sequence)) AS in_flight_work,
        argMax(persisted_observation_rows, tuple(checkpointed_at, checkpoint_sequence)) AS persisted_rows,
        max(checkpointed_at) AS latest_checkpointed_at
    FROM crawler_run_checkpoints
    GROUP BY run_id
)
ORDER BY latest_checkpointed_at DESC;
```

`unscheduled_gap` is the difference between nodes that were discovered and tracked (`unique_nodes`) and nodes that workers actually attempted (`scheduled_tasks`).
This gap is normal when a run stops before draining the full frontier, for example because it hit `max_runtime`, hit `idle_timeout`, or ended with queued work still remaining.
It can also grow when `--max-tracked-nodes` is large enough to admit more discoveries than the current runtime and concurrency settings can process in one run.

Verified versus failed observations by network type for the latest run:

```sql
WITH latest_run AS (
    SELECT run_id
    FROM crawler_run_checkpoints
    ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
    LIMIT 1
)
SELECT
    network_type,
    count() AS observations,
    countIf(confidence_level = 'verified') AS verified_nodes,
    countIf(confidence_level = 'failed') AS failed_nodes,
    round(100.0 * countIf(confidence_level = 'verified') / nullIf(count(), 0), 2) AS verified_pct
FROM node_observations
WHERE crawl_run_id = (SELECT run_id FROM latest_run)
GROUP BY network_type
ORDER BY verified_nodes DESC, failed_nodes DESC, network_type ASC;
```

Top ASNs among verified nodes in the latest run:

```sql
WITH latest_run AS (
    SELECT run_id
    FROM crawler_run_checkpoints
    ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
    LIMIT 1
)
SELECT asn, asn_organization, count() AS verified_nodes
FROM node_observations
WHERE crawl_run_id = (SELECT run_id FROM latest_run)
  AND confidence_level = 'verified'
  AND asn IS NOT NULL
GROUP BY asn, asn_organization
ORDER BY verified_nodes DESC, asn ASC
LIMIT 20;
```

If you prefer HTTP instead of the native shell:

```bash
curl 'http://localhost:8123/?database=btc_network&user=btc_network_dev&password=btc_network_dev' \
  --data-binary 'SELECT count() FROM node_observations'
```

## ClickHouse Clients

Good local options for this project:

- `clickhouse-client`
  Best default if you want the most direct and lowest-friction local experience.

- `DBeaver`
  Good general-purpose GUI and officially listed by ClickHouse as a SQL client integration.

- `DataGrip`
  Good if you already live in JetBrains tools and want a polished SQL IDE.

For this repository, I recommend:

1. use `clickhouse-client` for quick local verification
2. use `DBeaver` or `DataGrip` if you want a GUI for browsing tables and saving queries

## Typical Local Flow

1. Run `make crawler-mmdb-update`.
2. Run `make infra-clickhouse-up`.
3. Run `make clickhouse-migrate`.
4. Run `make crawler` with MMDB paths.

## Verification

From the repository root:

```bash
cargo test -p btc-network-crawler
git diff --check
```
