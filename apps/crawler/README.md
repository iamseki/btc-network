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
