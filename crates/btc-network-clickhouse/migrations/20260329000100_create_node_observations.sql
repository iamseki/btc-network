CREATE TABLE IF NOT EXISTS __BTC_NETWORK_DATABASE__.node_observations (
    observed_at DateTime,
    crawl_run_id String,
    observation_id String,
    batch_id String,
    endpoint String,
    network_type LowCardinality(String),
    handshake_status LowCardinality(String),
    confidence_level LowCardinality(String),
    protocol_version Nullable(Int32),
    services Nullable(UInt64),
    user_agent Nullable(String),
    start_height Nullable(Int32),
    relay Nullable(Bool),
    discovered_count UInt64,
    latency_ms Nullable(UInt64),
    failure_classification Nullable(String),
    enrichment_status LowCardinality(String),
    asn Nullable(UInt32),
    asn_organization Nullable(String),
    country Nullable(String),
    prefix Nullable(String)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(observed_at)
ORDER BY (observed_at, endpoint, observation_id)
