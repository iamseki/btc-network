# btc-network-clickhouse

ClickHouse storage adapter for the crawler persistence work in BNDD-0005.

This crate owns:

- ClickHouse connection configuration
- checked-in forward-only SQL migrations
- the migration runner and migration ledger
- the concrete `CrawlerRepository` implementation for observations and run checkpoints

It does not own crawler orchestration, protocol parsing, or MMDB enrichment logic. Those stay in `crates/btc-network`.

## Quick Start

### Create a new migration

Use the helper script from the repository root:

```bash
scripts/new-clickhouse-migration.sh <snake_case_slug>
```

Example:

```bash
scripts/new-clickhouse-migration.sh add_run_owner_column
```

This creates a new file under `crates/btc-network-clickhouse/migrations/` with the required filename shape:

```text
YYYYMMDDHHMMSS_slug.sql
```

Rules:

- keep migrations forward-only
- keep the slug descriptive and in `snake_case`
- document any required backfill or manual coordination directly in the migration file
- update `src/migrations.rs` so `bundled_migrations()` includes the new file

### Apply migrations

Migrations are applied explicitly through `ClickHouseMigrationRunner`. They are not tied to app startup.

Minimal example:

```rust,no_run
use btc_network_clickhouse::{ClickHouseConnectionConfig, ClickHouseMigrationRunner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClickHouseConnectionConfig::new("http://localhost:8123", "btc_network")
        .with_user("default")
        .with_password("secret");

    let report = ClickHouseMigrationRunner::new(&config).apply_all().await?;

    println!("applied: {:?}", report.applied_versions);
    println!("skipped: {:?}", report.skipped_versions);
    Ok(())
}
```

What `apply_all()` does:

- creates the target database if needed
- creates the `schema_migrations` ledger table if needed
- validates checksums for already-recorded migrations
- applies any pending checked-in migrations in order
- records each applied migration in the ledger

### Inspect applied migrations

```rust,no_run
use btc_network_clickhouse::{ClickHouseConnectionConfig, ClickHouseMigrationRunner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClickHouseConnectionConfig::default();
    let applied = ClickHouseMigrationRunner::new(&config)
        .applied_migrations()
        .await?;

    for migration in applied {
        println!("{} {} {}", migration.version, migration.name, migration.applied_at);
    }

    Ok(())
}
```

## Workflow

For a normal schema change:

1. Generate the migration file with `scripts/new-clickhouse-migration.sh`.
2. Write the forward-only ClickHouse DDL.
3. Add the new file to `bundled_migrations()` in [`src/migrations.rs`](./src/migrations.rs).
4. Update repository code or row mappings if the schema changed.
5. Run crate verification.
6. Apply migrations through an explicit admin or deploy step.

## Verification

Useful commands from the repository root:

```bash
cargo test -p btc-network-clickhouse
git diff --check
```

The crate test suite includes live ClickHouse integration tests through Testcontainers, so Docker must be available for the full package test run.

## Key Types

- `ClickHouseConnectionConfig`: builds normal and admin ClickHouse clients
- `ClickHouseMigrationRunner`: applies and inspects checked-in migrations
- `ClickHouseCrawlerRepository`: concrete `CrawlerRepository` implementation

## Notes

- migration filenames are timestamped so creation order is obvious in Git history
- the migration ledger protects against silent checksum drift for already-applied versions
- repository queries that select the "latest" checkpoint rely on deterministic checkpoint ordering from the shared crawler domain
