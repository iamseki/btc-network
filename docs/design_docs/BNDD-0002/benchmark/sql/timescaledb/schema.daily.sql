CREATE EXTENSION IF NOT EXISTS timescaledb;

DROP TABLE IF EXISTS node_observations;

-- Daily chunk variant for short recent-window analytics.
-- This is the comparison case against the monthly production-oriented default.
-- Hypercore columnstore is enabled so this variant also measures compressed TimescaleDB.
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
    by_range('observed_at', INTERVAL '1 day'),
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
