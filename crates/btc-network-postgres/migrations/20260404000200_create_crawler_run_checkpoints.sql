CREATE TABLE IF NOT EXISTS crawler_run_checkpoints (
    run_id UUID NOT NULL,
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
    unique_nodes BIGINT NOT NULL,
    persisted_observation_rows BIGINT NOT NULL,
    writer_backlog BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS crawler_run_checkpoints_run_latest_idx
    ON crawler_run_checkpoints (run_id, checkpointed_at DESC, checkpoint_sequence DESC);

CREATE INDEX IF NOT EXISTS crawler_run_checkpoints_latest_idx
    ON crawler_run_checkpoints (checkpointed_at DESC, checkpoint_sequence DESC);
