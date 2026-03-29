# btc-network-clickhouse

ClickHouse storage adapter for BNDD-0005.

This crate owns:

- ClickHouse connection configuration
- forward-only SQL migrations
- the migration runner and migration ledger
- the concrete `CrawlerRepository` implementation

## Create A Migration

From the repository root:

```bash
scripts/new-clickhouse-migration.sh <snake_case_slug>
```

Example:

```bash
scripts/new-clickhouse-migration.sh add_run_owner_column
```

This creates a file in `crates/btc-network-clickhouse/migrations/` with this format:

```text
YYYYMMDDHHMMSS_slug.sql
```

Important:

- timestamps are generated in `UTC`, not local time
- the existing initial migration files were backfilled with synthetic UTC timestamps to preserve stable ordering
- keep migrations forward-only
- document any required backfill or manual coordination in the migration file
- add the new file to `bundled_migrations()` in [`src/migrations/bundled.rs`](./src/migrations/bundled.rs)

## Apply Migrations

Migrations are applied explicitly with `ClickHouseMigrationRunner`. They are not tied to app startup.

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

`apply_all()` will:

- create the database if needed
- create the `schema_migrations` table if needed
- verify checksums for already-recorded migrations
- apply pending checked-in migrations in order
- record applied migrations in the ledger

## Inspect Applied Migrations

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

## Typical Workflow

1. Generate the migration file.
2. Write the ClickHouse DDL.
3. Add the file to `bundled_migrations()`.
4. Update repository code if the schema changed.
5. Run verification.
6. Apply migrations as an explicit admin or deploy step.

## Verification

From the repository root:

```bash
cargo test -p btc-network-clickhouse
```

The full crate test suite uses Testcontainers, so Docker must be available.
