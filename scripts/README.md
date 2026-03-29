# Scripts

Small repository helper scripts for local development and maintenance.

## Current Scripts

- [`crawler_timing.sh`](./crawler_timing.sh)
  Runs the crawler with timing capture and writes artifacts for later inspection.

- [`crawler_timing_summary.jq`](./crawler_timing_summary.jq)
  Summarizes crawler timing artifacts produced by `crawler_timing.sh`.

- [`new-clickhouse-migration.sh`](./new-clickhouse-migration.sh)
  Creates a new timestamped ClickHouse migration file for `btc-network-clickhouse`.

- [`test_summary.sh`](./test_summary.sh)
  Runs the repository test summary flow used by `make test`.

- [`update-crawler-mmdb.sh`](./update-crawler-mmdb.sh)
  Downloads or refreshes the local crawler MMDB files under `.dev-data/mmdb/` from the documented upstream source.

## Notes

- These scripts are developer and operator helpers, not shared runtime logic.
- Prefer running them from the repository root unless the script says otherwise.
- If a script changes repository conventions or local setup, update this README with it.
