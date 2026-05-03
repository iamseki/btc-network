CREATE TYPE "NODE_STATUS" AS ENUM ('healthy', 'failed', 'unknown');

CREATE TABLE IF NOT EXISTS node_status (
    node_status_id BIGSERIAL PRIMARY KEY,
    endpoint TEXT NOT NULL,
    label TEXT NOT NULL,
    description TEXT NOT NULL,
    status "NODE_STATUS" NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL,
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS node_status_endpoint_checked_at_idx
    ON node_status (endpoint, checked_at DESC);
