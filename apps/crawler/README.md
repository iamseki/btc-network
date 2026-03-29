# Crawler Local Development

The preferred local development path for the crawler uses:

- Docker Compose for ClickHouse
- host-managed MMDB files under `.dev-data/mmdb/`
- explicit migrations before the crawler starts

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
make crawler-dev-up
```

This starts the local ClickHouse service defined in [`docker-compose.yml`](./docker-compose.yml) and exposes it on `http://localhost:8123`.
The command waits for the container healthcheck before it returns.

The local development container is configured with these credentials:

- database: `btc_network`
- user: `btc_network_dev`
- password: `btc_network_dev`

To stop it:

```bash
make crawler-dev-down
```

To inspect logs:

```bash
make crawler-dev-logs
```

## Apply Migrations

Migrations stay explicit. They are not tied to crawler startup.

From the repository root:

```bash
make crawler-migrate
```

That uses the preferred local ClickHouse development settings automatically:

- URL: `http://localhost:8123`
- database: `btc_network`
- user: `btc_network_dev`
- password: `btc_network_dev`

These are local development defaults provided by the repository Make targets.
The crawler binary itself still only defaults the URL and database; it does not hardcode a global username or password.

If you need different settings, pass them through `ARGS`:

```bash
make crawler-migrate ARGS="--clickhouse-user another_user --clickhouse-password another_password"
```

If you already initialized `.dev-data/clickhouse/` with older local settings and keep seeing authentication failures, reset the local dev data once and start again:

```bash
make crawler-dev-reset
make crawler-dev-up
make crawler-migrate
```

## Run The Crawler

With local MMDB files in place:

```bash
make crawler ARGS="--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb"
```

`make crawler` also injects the same local ClickHouse development defaults automatically, so it matches `make crawler-dev-up` and `make crawler-migrate` out of the box.

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

The crawler will still run without MMDB files, but enrichment will be unavailable and ASN/country data will not be persisted.

## Inspect Data

The quickest built-in option is the native `clickhouse-client` shell.

If you have it installed locally, connect to the local dev instance with:

```bash
clickhouse-client --host localhost --port 9000 --database btc_network --user btc_network_dev --password btc_network_dev
```

Useful first queries:

```sql
SELECT phase, checkpointed_at, scheduled_tasks, successful_handshakes, failed_tasks
FROM crawler_run_checkpoints
ORDER BY checkpointed_at DESC
LIMIT 10;
```

```sql
SELECT observed_at, endpoint, network_type, handshake_status, enrichment_status, asn, country
FROM node_observations
ORDER BY observed_at DESC
LIMIT 20;
```

```sql
SELECT asn, asn_organization, count() AS observations
FROM node_observations
WHERE asn IS NOT NULL
GROUP BY asn, asn_organization
ORDER BY observations DESC
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
2. Run `make crawler-dev-up`.
3. Run `make crawler-migrate`.
4. Run `make crawler` with MMDB paths.

## Verification

From the repository root:

```bash
cargo test -p btc-network-crawler
git diff --check
```
