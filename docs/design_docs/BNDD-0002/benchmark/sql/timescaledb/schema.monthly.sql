CREATE EXTENSION IF NOT EXISTS timescaledb;

DROP TABLE IF EXISTS node_observations;

-- Synthetic crawler observations for the BNDD-0002 benchmark.
--
-- Field notes for the less obvious columns:
-- - relay: whether the peer advertised transaction relay support during handshake.
-- - asn: the Autonomous System Number from IP enrichment, used for concentration and
--   decentralization analysis.
-- - prefix: a simplified IP network grouping used to test subnet/prefix concentration.
-- - latency_ms: synthetic crawler latency in milliseconds for future telemetry-style queries.
-- - discovered_count: how many addresses the node returned during peer discovery.
--
-- TimescaleDB rationale:
-- - observed_at is the hypertable time column because the workload is append-heavy and most
--   benchmark queries are time-windowed.
-- - The benchmark uses a monthly chunk interval as the production-oriented default for a
--   long-running system. This keeps chunk counts reasonable as history grows. A daily variant
--   can still be benchmarked separately if short recent-window queries dominate.
-- - Hypercore columnstore is enabled so the benchmark can measure TimescaleDB with
--   compression/columnar storage rather than only rowstore behavior.
-- - segmentby uses low-cardinality dimensions that appear in grouping/filtering and compress
--   well; orderby keeps time-first analytical scans efficient.
-- - The endpoint index supports "latest row per endpoint" patterns, which are important in
--   this project because current state is a first-class view, not only historical facts.
-- - The ASN and handshake-status indexes support the main analytical filters in the query set.
CREATE TABLE node_observations (
    observed_at TIMESTAMPTZ NOT NULL,
    crawl_run_id BIGINT NOT NULL,
    endpoint TEXT NOT NULL,
    network_type TEXT NOT NULL,
    handshake_status TEXT NOT NULL,
    confidence_level TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    services BIGINT NOT NULL,
    user_agent TEXT NOT NULL,
    start_height INTEGER NOT NULL,
    relay BOOLEAN NOT NULL,
    asn INTEGER NOT NULL,
    country_code CHAR(2) NOT NULL,
    prefix TEXT NOT NULL,
    latency_ms INTEGER NOT NULL,
    discovered_count INTEGER NOT NULL
);

SELECT create_hypertable(
    'node_observations',
    by_range('observed_at', INTERVAL '1 month'),
    if_not_exists => TRUE,
    migrate_data => TRUE
);

ALTER TABLE node_observations SET (
    timescaledb.enable_columnstore,
    timescaledb.segmentby = 'network_type, handshake_status, country_code',
    timescaledb.orderby = 'observed_at DESC, endpoint'
);

CREATE INDEX IF NOT EXISTS node_observations_observed_at_endpoint_idx
    ON node_observations (observed_at DESC, endpoint);

CREATE INDEX IF NOT EXISTS node_observations_asn_observed_at_idx
    ON node_observations (asn, observed_at DESC);

CREATE INDEX IF NOT EXISTS node_observations_status_observed_at_idx
    ON node_observations (handshake_status, observed_at DESC);
