use super::model::Migration;

/// Returns the checked-in PostgreSQL migrations in apply order.
pub fn bundled_migrations() -> Vec<Migration> {
    vec![
        Migration::from_filename(
            "20260404000100_create_node_observations.sql",
            include_str!("../../migrations/20260404000100_create_node_observations.sql"),
        ),
        Migration::from_filename(
            "20260404000200_create_crawler_run_checkpoints.sql",
            include_str!("../../migrations/20260404000200_create_crawler_run_checkpoints.sql"),
        ),
    ]
}
