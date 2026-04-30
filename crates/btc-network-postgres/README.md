# btc-network-postgres

PostgreSQL storage adapter for `BNDD-0007`.

This crate owns:

- PostgreSQL connection configuration
- forward-only SQL migrations
- the migration runner and migration ledger
- the concrete `CrawlerRepository` and `CrawlerAnalyticsReader` implementation
- the `sqlx` PostgreSQL pool used by those adapters

The current crawler storage split is:

- `node_observations` for append-only observation history
- `crawler_run_checkpoints` for append-only progress history
- `unreachable_nodes` for active unreachable-node state used by normal crawler exclusion and recovery
- `schema_migrations` for the migration ledger

## Create A Migration

From the repository root:

```bash
scripts/new-postgres-migration.sh <snake_case_slug>
```

This creates a file in `crates/btc-network-postgres/migrations/` using:

```text
YYYYMMDDHHMMSS_slug.sql
```

Keep migrations forward-only and document any required manual coordination in
the migration file.

## Apply Migrations

Migrations are applied explicitly with `PostgresMigrationRunner`. They are not
tied to app startup.

```rust,no_run
use btc_network_postgres::{PostgresConnectionConfig, PostgresMigrationRunner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = PostgresConnectionConfig::new(
        "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network",
    );
    let report = PostgresMigrationRunner::new(&config)?.apply_all().await?;

    println!("applied: {:?}", report.applied_versions);
    println!("skipped: {:?}", report.skipped_versions);
    Ok(())
}
```

## Verification

From the repository root:

```bash
cargo test -p btc-network-postgres
```

The full integration suite uses Testcontainers, so Docker must be available.
