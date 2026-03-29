#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/new-clickhouse-migration.sh <snake_case_slug>" >&2
  exit 1
fi

slug="$1"

if [[ ! "$slug" =~ ^[a-z0-9]+(_[a-z0-9]+)*$ ]]; then
  echo "migration slug must be snake_case using lowercase letters, digits, and underscores" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
migrations_dir="$repo_root/crates/btc-network-clickhouse/migrations"
timestamp="$(date -u +%Y%m%d%H%M%S)"
filename="${timestamp}_${slug}.sql"
path="$migrations_dir/$filename"

if [[ -e "$path" ]]; then
  echo "migration already exists: $path" >&2
  exit 1
fi

cat >"$path" <<SQL
-- Forward-only ClickHouse migration.
-- Document any required backfill or manual coordination steps next to this file.

SQL

echo "$path"
