use super::*;
use chrono::Utc;
use clickhouse::{
    Client,
    test::{self, handlers},
};
use std::collections::HashSet;

#[test]
fn bundled_migrations_have_unique_versions_and_checksums() {
    let migrations = bundled_migrations();
    let versions = migrations
        .iter()
        .map(|migration| migration.version().to_string())
        .collect::<HashSet<_>>();

    assert_eq!(versions.len(), migrations.len());
    assert!(
        migrations
            .iter()
            .all(|migration| migration.checksum().len() == 64)
    );
    assert!(
        migrations
            .iter()
            .all(|migration| migration.version().len() == 14)
    );
    assert!(
        migrations
            .iter()
            .all(|migration| migration.version().chars().all(|ch| ch.is_ascii_digit()))
    );
}

#[test]
fn migration_from_filename_parses_timestamp_prefix_and_slug() {
    let migration = Migration::from_filename(
        "20260329001000_add_example_table.sql",
        "CREATE TABLE test (id UInt64) ENGINE = Memory",
    );

    assert_eq!(migration.version(), "20260329001000");
    assert_eq!(migration.name(), "add_example_table");
}

#[tokio::test]
async fn migration_runner_applies_pending_migrations_and_records_them() {
    let mock = test::Mock::new();
    let client = Client::default().with_mock(&mock);
    let runner = ClickHouseMigrationRunner::with_client(client, "btc_network");

    let create_db = mock.add(handlers::record_ddl());
    let create_ledger = mock.add(handlers::record_ddl());
    mock.add(handlers::provide(Vec::<AppliedMigration>::new()));
    let create_observations = mock.add(handlers::record_ddl());
    let record_migration_1 = mock.add(handlers::record());
    let create_checkpoints = mock.add(handlers::record_ddl());
    let record_migration_2 = mock.add(handlers::record());

    let report = runner.apply_all().await.expect("apply migrations");

    assert_eq!(
        report.applied_versions,
        vec!["20260329000100", "20260329000200"]
    );
    assert!(
        create_db
            .query()
            .await
            .contains("CREATE DATABASE IF NOT EXISTS")
    );
    assert!(create_ledger.query().await.contains("schema_migrations"));
    assert!(
        create_observations
            .query()
            .await
            .contains("node_observations")
    );
    assert!(
        create_checkpoints
            .query()
            .await
            .contains("crawler_run_checkpoints")
    );

    let rows_1: Vec<AppliedMigration> = record_migration_1.collect().await;
    let rows_2: Vec<AppliedMigration> = record_migration_2.collect().await;
    assert_eq!(rows_1[0].version, "20260329000100");
    assert_eq!(rows_2[0].version, "20260329000200");
}

#[tokio::test]
async fn migration_runner_rejects_checksum_drift_for_recorded_version() {
    let mock = test::Mock::new();
    let client = Client::default().with_mock(&mock);
    let runner = ClickHouseMigrationRunner::with_client(client, "btc_network");

    let create_db = mock.add(handlers::record_ddl());
    let create_ledger = mock.add(handlers::record_ddl());
    mock.add(handlers::provide(vec![AppliedMigration {
        version: "20260329000100".to_string(),
        name: "create_node_observations".to_string(),
        checksum: "deadbeef".repeat(8),
        applied_at: Utc::now(),
    }]));

    let err = runner.apply_all().await.expect_err("checksum mismatch");

    assert!(matches!(
        err,
        ClickHouseMigrationError::ChecksumMismatch { .. }
    ));
    assert!(create_db.query().await.contains("CREATE DATABASE"));
    assert!(create_ledger.query().await.contains("schema_migrations"));
}
