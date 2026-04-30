CREATE TABLE IF NOT EXISTS unreachable_nodes (
    endpoint TEXT PRIMARY KEY,
    network_type TEXT NOT NULL,
    first_unreachable_at TIMESTAMPTZ NOT NULL,
    last_unreachable_at TIMESTAMPTZ NOT NULL,
    last_crawl_run_id UUID NOT NULL,
    last_failure_classification TEXT NOT NULL,
    failure_count BIGINT NOT NULL DEFAULT 1,
    recovered_at TIMESTAMPTZ,
    recovered_crawl_run_id UUID
);

CREATE INDEX IF NOT EXISTS unreachable_nodes_active_latest_idx
    ON unreachable_nodes (last_unreachable_at DESC, endpoint)
    WHERE recovered_at IS NULL;

CREATE INDEX IF NOT EXISTS unreachable_nodes_recovered_idx
    ON unreachable_nodes (recovered_at DESC)
    WHERE recovered_at IS NOT NULL;