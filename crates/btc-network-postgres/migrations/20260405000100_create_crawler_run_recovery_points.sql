CREATE TABLE IF NOT EXISTS crawler_run_recovery_points (
    run_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    checkpointed_at TIMESTAMPTZ NOT NULL,
    checkpoint_sequence BIGINT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    stop_reason TEXT,
    failure_reason TEXT,
    frontier_size BIGINT NOT NULL,
    in_flight_work BIGINT NOT NULL,
    scheduled_tasks BIGINT NOT NULL,
    successful_handshakes BIGINT NOT NULL,
    failed_tasks BIGINT NOT NULL,
    queued_nodes_total BIGINT NOT NULL,
    unique_nodes BIGINT NOT NULL,
    discovered_node_states BIGINT NOT NULL,
    persisted_observation_rows BIGINT NOT NULL,
    writer_backlog BIGINT NOT NULL,
    payload_encoding TEXT NOT NULL,
    frontier_payload BYTEA NOT NULL,
    recovery_frontier_size BIGINT NOT NULL,
    caller TEXT
);

CREATE INDEX IF NOT EXISTS crawler_run_recovery_points_latest_idx
    ON crawler_run_recovery_points (checkpointed_at DESC, checkpoint_sequence DESC);
