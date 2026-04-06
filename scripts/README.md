# Scripts

Small repository helper scripts for local development and maintenance.

## Current Scripts

- [`crawler_timing.sh`](./crawler_timing.sh)
  Runs the crawler with timing capture and writes artifacts for later inspection.

- [`crawler_timing_summary.jq`](./crawler_timing_summary.jq)
  Summarizes crawler timing artifacts produced by `crawler_timing.sh`.

- [`new-postgres-migration.sh`](./new-postgres-migration.sh)
  Creates a new timestamped PostgreSQL migration file for `btc-network-postgres`.

- [`test_summary.sh`](./test_summary.sh)
  Runs the repository test summary flow used by `make test`.

- [`update-crawler-mmdb.sh`](./update-crawler-mmdb.sh)
  Downloads or refreshes the local crawler MMDB files under `.dev-data/mmdb/` from the documented upstream source.

- [`validate-semantic-subject.sh`](./validate-semantic-subject.sh)
  Validates semantic commit subjects and PR titles for repository workflow checks and the optional local git hook.

## Notes

- These scripts are developer and operator helpers, not shared runtime logic.
- Prefer running them from the repository root unless the script says otherwise.
- If a script changes repository conventions or local setup, update this README with it.
