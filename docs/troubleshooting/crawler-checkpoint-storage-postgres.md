# Troubleshooting: `crawler_run_checkpoints` PostgreSQL Storage Growth

Use this guide when the PostgreSQL `public.crawler_run_checkpoints` relation looks too large for its row count.

The main question is simple: is the space coming from indexes or table mechanics, or from one payload repeated many times? In the observed case, the answer is the repeated `resume_state` snapshot, with PostgreSQL storing most of it in TOAST.

This is the PostgreSQL-specific version of the same storage problem described in [Crawler Checkpoint Storage Growth](./crawler-checkpoint-storage.md). Leave the ClickHouse diagnosis there. Use this guide when you need PostgreSQL-specific evidence and interpretation.

## Use When

- `pg_total_relation_size` shows hundreds of MiB for only tens or hundreds of rows
- `pg_indexes_size` stays tiny relative to the full relation
- the TOAST relation is almost as large as the base table
- you need to separate index bloat from oversized row payloads

## Quick Checks

1. Check the total relation, table, and index sizes.
2. Check the table's TOAST relation size.
3. Check which columns account for the stored row bytes.
4. If `resume_state` dominates, inspect the checkpoint serializer and schema design.

Relation-size query:

```sql
SELECT
    pg_size_pretty(pg_total_relation_size('public.crawler_run_checkpoints')) AS total,
    pg_size_pretty(pg_table_size('public.crawler_run_checkpoints')) AS table,
    pg_size_pretty(pg_indexes_size('public.crawler_run_checkpoints')) AS indexes;
```

TOAST query:

```sql
SELECT
    c.relname AS table_name,
    t.relname AS toast_table,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS table_total,
    pg_size_pretty(pg_total_relation_size(t.oid)) AS toast_total
FROM pg_class c
LEFT JOIN pg_class t ON t.oid = c.reltoastrelid
WHERE c.oid = 'public.crawler_run_checkpoints'::regclass;
```

Column-attribution query:

```sql
SELECT
    pg_size_pretty(sum(pg_column_size(resume_state))) AS resume_state_total,
    pg_size_pretty(sum(pg_column_size(run_id))) AS run_id_total,
    pg_size_pretty(sum(pg_column_size(phase))) AS phase_total,
    pg_size_pretty(sum(pg_column_size(checkpointed_at))) AS checkpointed_at_total,
    pg_size_pretty(sum(pg_column_size(checkpoint_sequence))) AS checkpoint_sequence_total,
    pg_size_pretty(sum(pg_column_size(started_at))) AS started_at_total,
    pg_size_pretty(sum(pg_column_size(stop_reason))) AS stop_reason_total,
    pg_size_pretty(sum(pg_column_size(failure_reason))) AS failure_reason_total,
    pg_size_pretty(sum(pg_column_size(frontier_size))) AS frontier_size_total,
    pg_size_pretty(sum(pg_column_size(in_flight_work))) AS in_flight_work_total,
    pg_size_pretty(sum(pg_column_size(scheduled_tasks))) AS scheduled_tasks_total,
    pg_size_pretty(sum(pg_column_size(successful_handshakes))) AS successful_handshakes_total,
    pg_size_pretty(sum(pg_column_size(failed_tasks))) AS failed_tasks_total,
    pg_size_pretty(sum(pg_column_size(queued_nodes_total))) AS queued_nodes_total_total,
    pg_size_pretty(sum(pg_column_size(unique_nodes))) AS unique_nodes_total,
    pg_size_pretty(sum(pg_column_size(persisted_observation_rows))) AS persisted_observation_rows_total,
    pg_size_pretty(sum(pg_column_size(writer_backlog))) AS writer_backlog_total
FROM crawler_run_checkpoints;
```

Expected result in this failure mode:

- `indexes` stay tiny
- the TOAST relation is almost the entire table footprint
- `resume_state` is almost all row bytes
- small scalar columns stay tiny

Observed example:

```text
rows: 110
total: 426 MB
table: 426 MB
indexes: 32 kB
toast_total: 426 MB
resume_state_total: 410 MB
```

That means the relation is large because each checkpoint row stores a large resumable snapshot, not because PostgreSQL indexes are bloated.

## Why It Happens In This Repository

Each checkpoint stores the full crawler resume state in `resume_state`, and PostgreSQL moves oversized values out of line into TOAST.

This highlights a bad design decision that we need to change and fix. We currently mix progress history with the full resumable crawler state in one checkpoint record, then rewrite that full state on every checkpoint. PostgreSQL shows the cost through TOAST, but the real problem is the repeated full-state snapshot itself.

The stored snapshot includes:

- `seen_nodes`
- `pending_nodes`
- `in_flight_nodes`
- `node_states`

So total storage scales roughly with:

- number of checkpoints
- average size of `resume_state` per checkpoint

## Interpretation

- `indexes` are tiny but `toast_total` is large: this is not index bloat
- `resume_state_total` is close to total relation size: `resume_state` is the storage driver
- only tens or hundreds of rows consume hundreds of MiB: row count is not the issue
- TOAST is large because PostgreSQL is storing oversized variable-width values out of line

## Deeper Checks

### Is the storage in indexes or TOAST?

```sql
SELECT
    pg_size_pretty(pg_total_relation_size('public.crawler_run_checkpoints')) AS total,
    pg_size_pretty(pg_table_size('public.crawler_run_checkpoints')) AS table,
    pg_size_pretty(pg_indexes_size('public.crawler_run_checkpoints')) AS indexes;

SELECT
    c.relname AS table_name,
    t.relname AS toast_table,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS table_total,
    pg_size_pretty(pg_total_relation_size(t.oid)) AS toast_total
FROM pg_class c
LEFT JOIN pg_class t ON t.oid = c.reltoastrelid
WHERE c.oid = 'public.crawler_run_checkpoints'::regclass;
```

Use this when the row count is small but the relation is still large. If `indexes` are tiny and `toast_total` is close to `table_total`, the storage driver is a large variable-width column.

### Which columns account for the row bytes?

```sql
SELECT
    pg_size_pretty(sum(pg_column_size(resume_state))) AS resume_state_total,
    pg_size_pretty(sum(pg_column_size(run_id))) AS run_id_total,
    pg_size_pretty(sum(pg_column_size(phase))) AS phase_total,
    pg_size_pretty(sum(pg_column_size(checkpointed_at))) AS checkpointed_at_total,
    pg_size_pretty(sum(pg_column_size(checkpoint_sequence))) AS checkpoint_sequence_total,
    pg_size_pretty(sum(pg_column_size(started_at))) AS started_at_total,
    pg_size_pretty(sum(pg_column_size(stop_reason))) AS stop_reason_total,
    pg_size_pretty(sum(pg_column_size(failure_reason))) AS failure_reason_total,
    pg_size_pretty(sum(pg_column_size(frontier_size))) AS frontier_size_total,
    pg_size_pretty(sum(pg_column_size(in_flight_work))) AS in_flight_work_total,
    pg_size_pretty(sum(pg_column_size(scheduled_tasks))) AS scheduled_tasks_total,
    pg_size_pretty(sum(pg_column_size(successful_handshakes))) AS successful_handshakes_total,
    pg_size_pretty(sum(pg_column_size(failed_tasks))) AS failed_tasks_total,
    pg_size_pretty(sum(pg_column_size(queued_nodes_total))) AS queued_nodes_total_total,
    pg_size_pretty(sum(pg_column_size(unique_nodes))) AS unique_nodes_total,
    pg_size_pretty(sum(pg_column_size(persisted_observation_rows))) AS persisted_observation_rows_total,
    pg_size_pretty(sum(pg_column_size(writer_backlog))) AS writer_backlog_total
FROM crawler_run_checkpoints;
```

Use this when you want a direct confirmation that `resume_state` accounts for nearly all stored bytes.

### Which checkpoints are the largest?

```sql
SELECT
    run_id,
    checkpoint_sequence,
    checkpointed_at,
    frontier_size,
    unique_nodes,
    pg_size_pretty(pg_column_size(resume_state)::bigint) AS resume_state_bytes
FROM crawler_run_checkpoints
ORDER BY pg_column_size(resume_state) DESC
LIMIT 20;
```

Use this when you need to know whether a few outlier checkpoints dominate history.

### Which runs consume the most raw snapshot space?

```sql
SELECT
    run_id,
    count(*) AS checkpoints,
    min(started_at) AS started_at,
    max(checkpointed_at) AS last_checkpointed_at,
    max(unique_nodes) AS max_unique_nodes,
    max(frontier_size) AS max_frontier_size,
    pg_size_pretty(sum(pg_column_size(resume_state))::bigint) AS total_resume_state,
    pg_size_pretty(avg(pg_column_size(resume_state))::bigint) AS avg_resume_state,
    pg_size_pretty(max(pg_column_size(resume_state))::bigint) AS max_resume_state
FROM crawler_run_checkpoints
GROUP BY run_id
ORDER BY sum(pg_column_size(resume_state)) DESC
LIMIT 20;
```

Use this when you need to separate "many runs" from "one expensive run."

## PostgreSQL Notes

- large `TEXT` or similar variable-width values are moved into TOAST when they do not fit inline
- `pg_total_relation_size` includes the base table, TOAST table, and indexes
- `pg_table_size` includes the table and its TOAST data, so compare it with `pg_indexes_size` to separate data from index overhead
- when `toast_total` is close to the full relation size, large out-of-line values are the main storage driver
- TOAST explains where the bytes live, but it does not change the root cause
- moving the same oversized blob to another database engine would not fix the design; it would only change how the penalty appears

## Next Steps

- If the issue is checkpoint frequency, review checkpoint cadence before touching PostgreSQL settings
- If the issue is payload size, treat the current checkpoint shape as a design bug and separate progress history from resumable state instead of repeatedly storing the full snapshot
- If old rows are no longer needed, review retention only after the schema and write-path decision are understood
- Before deleting checkpoint history, confirm recovery requirements

## Official PostgreSQL Docs

- TOAST: https://www.postgresql.org/docs/current/storage-toast.html
- size functions: https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-DBSIZE
- `pg_class`: https://www.postgresql.org/docs/current/catalog-pg-class.html

## References

- `docs/agents/agent-safety.md`
- `docs/troubleshooting/crawler-checkpoint-storage.md`
- `crates/btc-network/src/crawler/lifecycle.rs`
- `crates/btc-network/src/crawler/types.rs`
- `crates/btc-network-clickhouse/migrations/20260329000200_create_crawler_run_checkpoints.sql`
