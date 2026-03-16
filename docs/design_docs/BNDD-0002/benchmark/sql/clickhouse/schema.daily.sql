CREATE DATABASE IF NOT EXISTS btc_bench;
USE btc_bench;

DROP TABLE IF EXISTS node_observations;

-- Daily partition variant for short recent-window analytics.
-- This is the comparison case against the monthly production-oriented default.
CREATE TABLE node_observations (
    observed_at DateTime,
    crawl_run_id UInt64,
    endpoint String,
    network_type LowCardinality(String),
    handshake_status LowCardinality(String),
    confidence_level LowCardinality(String),
    protocol_version UInt32,
    services UInt64,
    user_agent LowCardinality(String),
    start_height UInt32,
    relay Bool,
    asn UInt32,
    country_code FixedString(2),
    prefix String,
    latency_ms UInt32,
    discovered_count UInt32
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (observed_at, endpoint, asn);
