#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_ROOT="${SCRIPT_DIR}/results"

PRESET="${1:-small}"
PARTITION_GRANULARITY="${PARTITION_GRANULARITY:-monthly}"

case "${PRESET}" in
  small)
    OBSERVATIONS="${OBSERVATIONS:-250000}"
    ENDPOINTS="${ENDPOINTS:-25000}"
    DAYS="${DAYS:-14}"
    ;;
  medium)
    OBSERVATIONS="${OBSERVATIONS:-1000000}"
    ENDPOINTS="${ENDPOINTS:-100000}"
    DAYS="${DAYS:-30}"
    ;;
  large)
    OBSERVATIONS="${OBSERVATIONS:-5000000}"
    ENDPOINTS="${ENDPOINTS:-500000}"
    DAYS="${DAYS:-60}"
    ;;
  custom)
    OBSERVATIONS="${OBSERVATIONS:-250000}"
    ENDPOINTS="${ENDPOINTS:-25000}"
    DAYS="${DAYS:-14}"
    ;;
  *)
    echo "unknown preset: ${PRESET}" >&2
    echo "use one of: small, medium, large, custom" >&2
    exit 1
    ;;
esac

case "${PARTITION_GRANULARITY}" in
  daily|monthly)
    ;;
  *)
    echo "unknown PARTITION_GRANULARITY: ${PARTITION_GRANULARITY}" >&2
    echo "use one of: daily, monthly" >&2
    exit 1
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "docker compose is required" >&2
  exit 1
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="${RESULTS_ROOT}/${TIMESTAMP}_preset-${PRESET}_part-${PARTITION_GRANULARITY}_obs-${OBSERVATIONS}_endpoints-${ENDPOINTS}_days-${DAYS}"
mkdir -p "${RESULTS_DIR}"

echo "benchmark preset=${PRESET} observations=${OBSERVATIONS} endpoints=${ENDPOINTS} days=${DAYS}"
echo "partition_granularity=${PARTITION_GRANULARITY}"
echo "results=${RESULTS_DIR}"

"${COMPOSE[@]}" -f "${SCRIPT_DIR}/docker-compose.yml" up -d

wait_for_timescaledb() {
  for _ in $(seq 1 60); do
    if docker exec btc-network-timescaledb-bench pg_isready -U btc -d btc_bench >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "timescaledb did not become ready" >&2
  exit 1
}

wait_for_clickhouse() {
  for _ in $(seq 1 60); do
    if docker exec btc-network-clickhouse-bench clickhouse-client --user btc --password btc --query "SELECT 1" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "clickhouse did not become ready" >&2
  exit 1
}

run_timed() {
  local label="$1"
  shift
  local started ended elapsed_ms
  started="$(date +%s%3N)"
  "$@"
  ended="$(date +%s%3N)"
  elapsed_ms="$((ended - started))"
  printf "%s=%sms\n" "${label}" "${elapsed_ms}" | tee -a "${RESULTS_DIR}/timings.txt" >/dev/null
}

psql_exec() {
  local sql="$1"
  docker exec -i btc-network-timescaledb-bench psql -v ON_ERROR_STOP=1 -U btc -d btc_bench -c "${sql}"
}

clickhouse_exec() {
  local sql="$1"
  docker exec -i btc-network-clickhouse-bench clickhouse-client --user btc --password btc --query "${sql}"
}

wait_for_timescaledb
wait_for_clickhouse

run_timed "timescaledb_schema" \
  docker exec -i btc-network-timescaledb-bench psql -v ON_ERROR_STOP=1 -U btc -d btc_bench \
  -f /dev/stdin < "${SCRIPT_DIR}/sql/timescaledb/schema.${PARTITION_GRANULARITY}.sql"

run_timed "clickhouse_schema" \
  docker exec -i btc-network-clickhouse-bench clickhouse-client --user btc --password btc \
  --multiquery < "${SCRIPT_DIR}/sql/clickhouse/schema.${PARTITION_GRANULARITY}.sql"

TIMESCALE_LOAD_SQL="$(cat <<SQL
TRUNCATE TABLE node_observations;
INSERT INTO node_observations (
    observed_at,
    crawl_run_id,
    endpoint,
    network_type,
    handshake_status,
    confidence_level,
    protocol_version,
    services,
    user_agent,
    start_height,
    relay,
    asn,
    country_code,
    prefix,
    latency_ms,
    discovered_count
)
SELECT
    NOW() - (((gs - 1) % (${DAYS} * 24 * 240)) * INTERVAL '15 seconds') AS observed_at,
    ((gs - 1) / 5000) + 1 AS crawl_run_id,
    CASE
        WHEN endpoint_id % 100 < 72 THEN format('ipv4:%s.%s.%s.%s:8333',
            (endpoint_id / 65536) % 223 + 1,
            (endpoint_id / 256) % 256,
            endpoint_id % 256,
            (endpoint_id * 13) % 256
        )
        WHEN endpoint_id % 100 < 92 THEN format('ipv6:2001:db8:%s:%s::%s:8333',
            lpad(to_hex((endpoint_id / 256) % 65535), 4, '0'),
            lpad(to_hex(endpoint_id % 65535), 4, '0'),
            lpad(to_hex((endpoint_id * 17) % 65535), 4, '0')
        )
        WHEN endpoint_id % 100 < 98 THEN format('tor:%s.onion:8333', md5(endpoint_id::text))
        ELSE format('i2p:%s.b32.i2p:8333', md5((endpoint_id * 7)::text))
    END AS endpoint,
    CASE
        WHEN endpoint_id % 100 < 72 THEN 'ipv4'
        WHEN endpoint_id % 100 < 92 THEN 'ipv6'
        WHEN endpoint_id % 100 < 98 THEN 'torv3'
        ELSE 'i2p'
    END AS network_type,
    CASE
        WHEN gs % 100 < 72 THEN 'verified_handshake'
        WHEN gs % 100 < 87 THEN 'gossiped_only'
        WHEN gs % 100 < 95 THEN 'recent_connection_failed'
        ELSE 'timeout'
    END AS handshake_status,
    CASE
        WHEN gs % 100 < 72 THEN 'verified_handshake'
        WHEN gs % 100 < 87 THEN 'seen_by_n_peers'
        WHEN gs % 100 < 95 THEN 'recent_connection_failed'
        ELSE 'gossiped_only'
    END AS confidence_level,
    CASE
        WHEN endpoint_id % 100 < 70 THEN 70016
        WHEN endpoint_id % 100 < 92 THEN 70015
        ELSE 70014
    END AS protocol_version,
    CASE
        WHEN endpoint_id % 4 = 0 THEN 1033
        WHEN endpoint_id % 4 = 1 THEN 9
        WHEN endpoint_id % 4 = 2 THEN 1
        ELSE 0
    END AS services,
    CASE
        WHEN endpoint_id % 100 < 45 THEN '/Satoshi:28.0.0/'
        WHEN endpoint_id % 100 < 65 THEN '/Satoshi:27.1.0/'
        WHEN endpoint_id % 100 < 78 THEN '/Satoshi:26.0.0/'
        WHEN endpoint_id % 100 < 88 THEN '/btcd:0.24.2/'
        WHEN endpoint_id % 100 < 96 THEN '/bcoin:2.2.0/'
        ELSE '/libbitcoin:4.0.0/'
    END AS user_agent,
    820000 + (endpoint_id % 120000) AS start_height,
    (endpoint_id % 2 = 0) AS relay,
    CASE
        WHEN endpoint_id % 100 < 94 THEN 64512 + (endpoint_id % 4096)
        ELSE 0
    END AS asn,
    CASE
        WHEN endpoint_id % 10 = 0 THEN 'US'
        WHEN endpoint_id % 10 = 1 THEN 'DE'
        WHEN endpoint_id % 10 = 2 THEN 'NL'
        WHEN endpoint_id % 10 = 3 THEN 'FR'
        WHEN endpoint_id % 10 = 4 THEN 'CA'
        WHEN endpoint_id % 10 = 5 THEN 'BR'
        WHEN endpoint_id % 10 = 6 THEN 'SG'
        WHEN endpoint_id % 10 = 7 THEN 'JP'
        WHEN endpoint_id % 10 = 8 THEN 'GB'
        ELSE 'FI'
    END AS country_code,
    CASE
        WHEN endpoint_id % 100 < 92 THEN format('%s.%s.0.0/16', endpoint_id % 223 + 1, (endpoint_id / 256) % 256)
        ELSE 'overlay'
    END AS prefix,
    15 + ((endpoint_id * 17) % 350) AS latency_ms,
    CASE
        WHEN gs % 100 < 72 THEN (endpoint_id * 7) % 2500
        ELSE (endpoint_id * 3) % 250
    END AS discovered_count
FROM (
    SELECT gs, ((gs - 1) % ${ENDPOINTS}) + 1 AS endpoint_id
    FROM generate_series(1, ${OBSERVATIONS}) AS gs
) AS dataset;
SQL
)"

CLICKHOUSE_LOAD_SQL="$(cat <<SQL
TRUNCATE TABLE btc_bench.node_observations;
INSERT INTO btc_bench.node_observations
SELECT
    now() - toIntervalSecond(((number) % (${DAYS} * 24 * 240)) * 15) AS observed_at,
    intDiv(number, 5000) + 1 AS crawl_run_id,
    multiIf(
        endpoint_id % 100 < 72, concat(
            'ipv4:',
            toString((intDiv(endpoint_id, 65536) % 223) + 1), '.',
            toString(intDiv(endpoint_id, 256) % 256), '.',
            toString(endpoint_id % 256), '.',
            toString((endpoint_id * 13) % 256),
            ':8333'
        ),
        endpoint_id % 100 < 92, concat(
            'ipv6:2001:db8:',
            lower(hex(intDiv(endpoint_id, 256) % 65535)), ':',
            lower(hex(endpoint_id % 65535)), '::',
            lower(hex((endpoint_id * 17) % 65535)),
            ':8333'
        ),
        endpoint_id % 100 < 98, concat('tor:', lower(hex(cityHash64(toString(endpoint_id)))), '.onion:8333'),
        concat('i2p:', lower(hex(cityHash64(toString(endpoint_id * 7)))), '.b32.i2p:8333')
    ) AS endpoint,
    multiIf(
        endpoint_id % 100 < 72, 'ipv4',
        endpoint_id % 100 < 92, 'ipv6',
        endpoint_id % 100 < 98, 'torv3',
        'i2p'
    ) AS network_type,
    multiIf(
        number % 100 < 72, 'verified_handshake',
        number % 100 < 87, 'gossiped_only',
        number % 100 < 95, 'recent_connection_failed',
        'timeout'
    ) AS handshake_status,
    multiIf(
        number % 100 < 72, 'verified_handshake',
        number % 100 < 87, 'seen_by_n_peers',
        number % 100 < 95, 'recent_connection_failed',
        'gossiped_only'
    ) AS confidence_level,
    multiIf(
        endpoint_id % 100 < 70, 70016,
        endpoint_id % 100 < 92, 70015,
        70014
    ) AS protocol_version,
    multiIf(
        endpoint_id % 4 = 0, 1033,
        endpoint_id % 4 = 1, 9,
        endpoint_id % 4 = 2, 1,
        0
    ) AS services,
    multiIf(
        endpoint_id % 100 < 45, '/Satoshi:28.0.0/',
        endpoint_id % 100 < 65, '/Satoshi:27.1.0/',
        endpoint_id % 100 < 78, '/Satoshi:26.0.0/',
        endpoint_id % 100 < 88, '/btcd:0.24.2/',
        endpoint_id % 100 < 96, '/bcoin:2.2.0/',
        '/libbitcoin:4.0.0/'
    ) AS user_agent,
    820000 + (endpoint_id % 120000) AS start_height,
    endpoint_id % 2 = 0 AS relay,
    if(endpoint_id % 100 < 94, 64512 + (endpoint_id % 4096), 0) AS asn,
    multiIf(
        endpoint_id % 10 = 0, 'US',
        endpoint_id % 10 = 1, 'DE',
        endpoint_id % 10 = 2, 'NL',
        endpoint_id % 10 = 3, 'FR',
        endpoint_id % 10 = 4, 'CA',
        endpoint_id % 10 = 5, 'BR',
        endpoint_id % 10 = 6, 'SG',
        endpoint_id % 10 = 7, 'JP',
        endpoint_id % 10 = 8, 'GB',
        'FI'
    ) AS country_code,
    if(endpoint_id % 100 < 92,
        concat(toString((endpoint_id % 223) + 1), '.', toString(intDiv(endpoint_id, 256) % 256), '.0.0/16'),
        'overlay'
    ) AS prefix,
    15 + ((endpoint_id * 17) % 350) AS latency_ms,
    if(number % 100 < 72, (endpoint_id * 7) % 2500, (endpoint_id * 3) % 250) AS discovered_count
FROM (
    SELECT
        number,
        (number % ${ENDPOINTS}) + 1 AS endpoint_id
    FROM numbers(${OBSERVATIONS})
);
SQL
)"

run_timed "timescaledb_load" psql_exec "${TIMESCALE_LOAD_SQL}"
run_timed "clickhouse_load" clickhouse_exec "${CLICKHOUSE_LOAD_SQL}"

run_timed "timescaledb_columnstore_convert" \
  docker exec -i btc-network-timescaledb-bench psql -v ON_ERROR_STOP=1 -U btc -d btc_bench \
  -c "DO \$\$
DECLARE
    c REGCLASS;
BEGIN
    FOR c IN SELECT show_chunks('node_observations')
    LOOP
        CALL convert_to_columnstore(c);
    END LOOP;
END
\$\$;"

run_timed "timescaledb_vacuum_full" \
  docker exec -i btc-network-timescaledb-bench psql -v ON_ERROR_STOP=1 -U btc -d btc_bench \
  -c "VACUUM FULL node_observations;"

run_timed "timescaledb_analyze" \
  docker exec -i btc-network-timescaledb-bench psql -v ON_ERROR_STOP=1 -U btc -d btc_bench \
  -c "ANALYZE node_observations;"

run_timed "timescaledb_queries" \
  docker exec -i btc-network-timescaledb-bench psql -v ON_ERROR_STOP=1 -U btc -d btc_bench \
  -f /dev/stdin < "${SCRIPT_DIR}/sql/timescaledb/queries.sql" \
  | tee "${RESULTS_DIR}/timescaledb-queries.txt"

run_timed "clickhouse_queries" \
  docker exec -i btc-network-clickhouse-bench clickhouse-client --user btc --password btc --multiquery --time \
  < "${SCRIPT_DIR}/sql/clickhouse/queries.sql" 2>&1 \
  | tee "${RESULTS_DIR}/clickhouse-queries.txt"

docker exec btc-network-timescaledb-bench psql -U btc -d btc_bench -c \
  "SELECT pg_size_pretty(pg_database_size('btc_bench')) AS timescaledb_size;" \
  | tee "${RESULTS_DIR}/timescaledb-size.txt"

docker exec btc-network-timescaledb-bench psql -U btc -d btc_bench -c \
  "SELECT * FROM hypertable_columnstore_stats('node_observations');" \
  | tee "${RESULTS_DIR}/timescaledb-columnstore-stats.txt"

docker exec btc-network-clickhouse-bench clickhouse-client --user btc --password btc --query \
  "SELECT formatReadableSize(sum(bytes_on_disk)) AS clickhouse_size FROM system.parts WHERE database = 'btc_bench' AND active;" \
  | tee "${RESULTS_DIR}/clickhouse-size.txt"

echo "finished"
echo "review:"
echo "  ${RESULTS_DIR}/timings.txt"
echo "  ${RESULTS_DIR}/timescaledb-queries.txt"
echo "  ${RESULTS_DIR}/clickhouse-queries.txt"
