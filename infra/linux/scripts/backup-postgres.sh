#!/usr/bin/env bash
set -euo pipefail

backup_root="${BTC_NETWORK_BACKUP_ROOT:-/var/backups/btc-network/postgres}"
database_url="${BTC_NETWORK_BACKUP_POSTGRES_URL:-postgresql:///btc_network?host=/var/run/postgresql}"
retention_days="${BTC_NETWORK_BACKUP_RETENTION_DAYS:-14}"
s3_uri="${BTC_NETWORK_BACKUP_S3_URI:-}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
daily_dir="${backup_root}/daily"
globals_dir="${backup_root}/globals"

mkdir -p "${daily_dir}" "${globals_dir}"

archive_path="${daily_dir}/btc_network_${timestamp}.dump"
globals_path="${globals_dir}/btc_network_globals_${timestamp}.sql"

pg_dump --format=custom --file "${archive_path}" "${database_url}"
pg_dumpall --globals-only > "${globals_path}"

find "${daily_dir}" -type f -name '*.dump' -mtime +"${retention_days}" -delete
find "${globals_dir}" -type f -name '*.sql' -mtime +"${retention_days}" -delete

if [[ -n "${s3_uri}" ]]; then
    aws s3 cp "${archive_path}" "${s3_uri}/daily/$(basename "${archive_path}")"
    aws s3 cp "${globals_path}" "${s3_uri}/globals/$(basename "${globals_path}")"
fi

