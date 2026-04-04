# Troubleshooting: `crawler_run_checkpoints` Storage Growth

Use this guide when `btc_network.crawler_run_checkpoints` looks too large for its row count.

The main question is simple: is the space coming from table mechanics, or from one payload repeated many times? In the observed case, the answer is the repeated `resume_state` snapshot.

The same workflow also helps with other ClickHouse tables where storage growth looks strange. Replace the table and column names, then use the same progression: measure table size, find the dominant columns, and inspect the largest raw values before changing schema or retention.

## Use When

- `system.parts` shows GiB of storage for only thousands of rows
- `system.parts_columns` shows one column dominating disk usage
- you need to separate checkpoint-count problems from payload-size problems
- another ClickHouse table has storage growth that does not match its row count or expected payload size

## Quick Checks

1. Check table size and part-level storage.
2. Check which column consumes the bytes.
3. If `resume_state` dominates, inspect the checkpoint schema and serializer.

Reusable pattern for other tables:

1. Start with `system.parts` for the table-level footprint.
2. Use `system.parts_columns` to find the dominant column or columns.
3. Query the base table for the largest raw values in those columns.
4. Decide whether the main driver is retention, write cadence, or payload shape.

Table-level query:

```sql
SELECT
    database,
    table,
    sum(rows) AS rows,
    formatReadableSize(sum(bytes_on_disk)) AS bytes_on_disk,
    formatReadableSize(sum(data_compressed_bytes)) AS data_compressed,
    formatReadableSize(sum(data_uncompressed_bytes)) AS data_uncompressed,
    formatReadableSize(sum(marks_bytes)) AS marks,
    sum(files) AS files,
    count() AS active_parts
FROM system.parts
WHERE active
  AND database = 'btc_network'
  AND table = 'crawler_run_checkpoints'
GROUP BY database, table;
```

Column-level query:

```sql
SELECT
    column,
    any(type) AS type,
    sum(rows) AS rows,
    formatReadableSize(sum(column_bytes_on_disk)) AS on_disk,
    formatReadableSize(sum(column_data_compressed_bytes)) AS compressed,
    formatReadableSize(sum(column_data_uncompressed_bytes)) AS uncompressed,
    formatReadableSize(sum(column_marks_bytes)) AS marks
FROM system.parts_columns
WHERE active
  AND database = 'btc_network'
  AND table = 'crawler_run_checkpoints'
GROUP BY column
ORDER BY sum(column_bytes_on_disk) DESC;
```

Expected result in this failure mode:

- `resume_state` is almost all on-disk bytes
- `marks` stay tiny
- numeric and small text columns stay tiny

Observed example:

```text
rows: 3251
bytes_on_disk: 10.74 GiB
data_uncompressed: 54.42 GiB
resume_state on_disk: 10.74 GiB
```

That means the table is large because each checkpoint row stores a large resumable snapshot, not because there are many rows or expensive indexes.

## Why It Happens In This Repository

The checkpoint table schema includes `resume_state Nullable(String)`, and each checkpoint serializes the full crawler state into that field.

Relevant code:

- schema: `crates/btc-network-clickhouse/migrations/20260329000200_create_crawler_run_checkpoints.sql`
- checkpoint write path: `crates/btc-network/src/crawler/lifecycle.rs`
- snapshot shape: `crates/btc-network/src/crawler/types.rs`

The stored snapshot includes:

- `seen_nodes`
- `pending_nodes`
- `in_flight_nodes`
- `node_states`

So total storage scales roughly with:

- number of checkpoints
- average size of `resume_state` per checkpoint

## Interpretation

- `resume_state` dominates bytes: repeated full-state snapshots are the storage driver
- one run dominates raw `resume_state` bytes: one long or noisy run dominates history
- a few checkpoints are much larger than the rest: payload size spikes near the largest frontier or node-state set
- `files` are high but `marks` are small: part/file overhead exists, but it is not the main GiB driver
- compressed bytes are still large: compression helps, but the payload itself is too large or retained for too long

## Deeper Checks

### Which checkpoints are the largest?

```sql
SELECT
    run_id,
    checkpoint_sequence,
    checkpointed_at,
    frontier_size,
    unique_nodes,
    discovered_node_states,
    formatReadableSize(length(ifNull(resume_state, ''))) AS resume_state_raw
FROM btc_network.crawler_run_checkpoints
ORDER BY length(ifNull(resume_state, '')) DESC
LIMIT 20;
```

Use this when you need to know whether a few outlier checkpoints dominate the table.

### Which runs consume the most raw snapshot space?

```sql
SELECT
    run_id,
    count() AS checkpoints,
    min(started_at) AS started_at,
    max(checkpointed_at) AS last_checkpointed_at,
    max(unique_nodes) AS max_unique_nodes,
    max(frontier_size) AS max_frontier_size,
    max(discovered_node_states) AS max_discovered_node_states,
    formatReadableSize(sum(length(ifNull(resume_state, '')))) AS total_resume_state_raw,
    formatReadableSize(avg(length(ifNull(resume_state, '')))) AS avg_resume_state_raw,
    formatReadableSize(max(length(ifNull(resume_state, '')))) AS max_resume_state_raw
FROM btc_network.crawler_run_checkpoints
GROUP BY run_id
ORDER BY sum(length(ifNull(resume_state, ''))) DESC
LIMIT 20;
```

Use this when you need to separate "many runs" from "one expensive run."

### Are checkpoints being written too often?

```sql
SELECT
    run_id,
    count() AS checkpoints,
    min(checkpointed_at) AS first_checkpoint_at,
    max(checkpointed_at) AS last_checkpoint_at,
    dateDiff('second', min(checkpointed_at), max(checkpointed_at)) AS span_seconds,
    round(
        dateDiff('second', min(checkpointed_at), max(checkpointed_at))
        / nullIf(count() - 1, 0),
        2
    ) AS avg_checkpoint_spacing_seconds
FROM btc_network.crawler_run_checkpoints
GROUP BY run_id
ORDER BY checkpoints DESC
LIMIT 20;
```

Use this when history size looks driven by checkpoint cadence instead of only payload size.

### Does payload size grow with crawler state?

```sql
SELECT
    run_id,
    checkpoint_sequence,
    checkpointed_at,
    frontier_size,
    unique_nodes,
    discovered_node_states,
    length(ifNull(resume_state, '')) AS resume_state_bytes,
    formatReadableSize(length(ifNull(resume_state, ''))) AS resume_state_raw
FROM btc_network.crawler_run_checkpoints
WHERE run_id = '<target-run-id>'
ORDER BY checkpoint_sequence ASC;
```

Use this when you need to relate snapshot growth to crawler progress.

## ClickHouse Notes

- `system.parts` and `system.parts_columns` are the right first tools for MergeTree storage diagnosis
- `marks_bytes` being small means sparse-index overhead is not the main issue
- `LowCardinality(String)` is appropriate for `phase`, not for large unique blobs like `resume_state`
- `Nullable` adds overhead, but it does not explain multi-GiB storage here
- `JSON` is not automatically better than `String` when the value is stored and retrieved as one opaque blob
- codecs can improve compression, but they do not fix repeated full-state duplication
- TTL is the main ClickHouse-native option when the real problem is retention

## Next Steps

- If the issue is history growth, review retention before changing types or codecs
- If the issue is checkpoint frequency, review checkpoint cadence before redesigning the payload
- If the issue is payload size, review whether progress history and resumable state should be stored separately
- Before deleting old checkpoints, confirm recovery requirements

## Official ClickHouse Docs

- `system.parts`: https://clickhouse.com/docs/operations/system-tables/parts
- `system.parts_columns`: https://clickhouse.com/docs/operations/system-tables/parts_columns
- `MergeTree`: https://clickhouse.com/docs/engines/table-engines/mergetree-family/mergetree
- `LowCardinality(T)`: https://clickhouse.com/docs/sql-reference/data-types/lowcardinality
- `Nullable(T)`: https://clickhouse.com/docs/sql-reference/data-types/nullable
- `JSON` and when `String` is a better fit: https://clickhouse.com/docs/sql-reference/data-types/newjson
- compression guidance: https://clickhouse.com/docs/data-compression/compression-in-clickhouse
- `CREATE TABLE` codecs: https://clickhouse.com/docs/sql-reference/statements/create/table
- TTL: https://clickhouse.com/docs/guides/developer/ttl

## References

- `docs/agents/agent-safety.md`
- `crates/btc-network-clickhouse/migrations/20260329000200_create_crawler_run_checkpoints.sql`
- `crates/btc-network/src/crawler/lifecycle.rs`
- `crates/btc-network/src/crawler/types.rs`
- `docs/design_docs/BNDD-0005/BNDD-0005.md`
