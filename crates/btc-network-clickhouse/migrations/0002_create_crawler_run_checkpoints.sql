CREATE TABLE IF NOT EXISTS __BTC_NETWORK_DATABASE__.crawler_run_checkpoints (
    run_id String,
    phase LowCardinality(String),
    checkpointed_at DateTime,
    started_at DateTime,
    stop_reason Nullable(String),
    failure_reason Nullable(String),
    frontier_size UInt64,
    in_flight_work UInt64,
    scheduled_tasks UInt64,
    successful_handshakes UInt64,
    failed_tasks UInt64,
    queued_nodes_total UInt64,
    unique_nodes UInt64,
    discovered_node_states UInt64,
    persisted_observation_rows UInt64,
    writer_backlog UInt64,
    resume_state Nullable(String),
    caller Nullable(String)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(checkpointed_at)
ORDER BY (run_id, checkpointed_at)
