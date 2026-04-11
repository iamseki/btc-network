# BNDD-0002 benchmark kit

This directory contains a side-by-side benchmark for TimescaleDB and ClickHouse using synthetic Bitcoin crawler observations.

Important:

- this benchmark kit is historical workload tooling, not the current runtime schema contract
- the synthetic benchmark schema still uses older dimensions such as integer `crawl_run_id` and `confidence_level`
- current crawler persistence uses UUIDv7-backed `crawl_run_id` and `observation_id`, no `confidence_level`, and no `batch_id`
- if you change the live crawler schema, do not assume the benchmark kit already tracks it unless these benchmark assets are updated explicitly

The default schema uses `monthly` partitioning/chunking because that is the more realistic production starting point for a system intended to run for years. `daily` remains available as an explicit comparison variant.

The benchmark defaults to TimescaleDB on PostgreSQL 18 via `timescale/timescaledb:2.25.2-pg18`. Override it with `TIMESCALE_IMAGE=...` if you want to compare a different supported image tag.

The TimescaleDB path enables hypercore columnstore and manually converts chunks after loading data so the benchmark reflects compressed TimescaleDB storage instead of pure rowstore only.
It also runs `VACUUM FULL` and `ANALYZE` before measuring query and size outputs so the TimescaleDB result reflects a compacted and refreshed post-load state.

Run:

```bash
cd docs/design_docs/BNDD-0002/benchmark
./run-benchmark.sh small
```

Choose the partitioning/chunking variant:

```bash
PARTITION_GRANULARITY=monthly ./run-benchmark.sh small
PARTITION_GRANULARITY=daily ./run-benchmark.sh small
```

Presets:

- `small`
- `medium`
- `large`

Override defaults with environment variables:

```bash
OBSERVATIONS=2000000 ENDPOINTS=150000 DAYS=30 ./run-benchmark.sh custom
```

Outputs land in `results/<timestamp>/`.
The result directory name also includes the preset, partition granularity, and dataset shape.
