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

## Start ClickHouse

From the repository root:

```bash
make crawler-dev-up
```

This starts the local ClickHouse service defined in [`docker-compose.yml`](./docker-compose.yml) and exposes it on `http://localhost:8123`.

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

That uses the crawler app's default local ClickHouse settings:

- URL: `http://localhost:8123`
- database: `btc_network`

If you need different settings, pass them through `ARGS`:

```bash
make crawler-migrate ARGS="--clickhouse-url http://localhost:8123 --clickhouse-database btc_network"
```

## Run The Crawler

With local MMDB files in place:

```bash
make crawler ARGS="--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb"
```

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

## Typical Local Flow

1. Put the MMDB files under `.dev-data/mmdb/`.
2. Run `make crawler-dev-up`.
3. Run `make crawler-migrate`.
4. Run `make crawler` with MMDB paths.

## Verification

From the repository root:

```bash
cargo test -p btc-network-crawler
git diff --check
```
