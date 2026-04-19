CREATE TABLE IF NOT EXISTS node_observations (
    observed_at TIMESTAMPTZ NOT NULL,
    crawl_run_id UUID NOT NULL,
    observation_id UUID NOT NULL,
    endpoint TEXT NOT NULL,
    network_type TEXT NOT NULL,
    protocol_version INTEGER,
    services TEXT,
    user_agent TEXT,
    start_height INTEGER,
    relay BOOLEAN,
    discovered_peer_addresses_count BIGINT NOT NULL,
    latency_ms BIGINT,
    failure_classification TEXT,
    enrichment_status TEXT NOT NULL,
    asn INTEGER,
    asn_organization TEXT,
    country TEXT,
    prefix TEXT
);

CREATE INDEX IF NOT EXISTS node_observations_endpoint_latest_idx
    ON node_observations (endpoint, observed_at DESC, observation_id DESC);

CREATE INDEX IF NOT EXISTS node_observations_run_observed_idx
    ON node_observations (crawl_run_id, observed_at DESC, observation_id DESC);

CREATE INDEX IF NOT EXISTS node_observations_run_failure_idx
    ON node_observations (crawl_run_id, failure_classification)
    WHERE failure_classification IS NOT NULL;

CREATE INDEX IF NOT EXISTS node_observations_run_network_idx
    ON node_observations (crawl_run_id, network_type);
