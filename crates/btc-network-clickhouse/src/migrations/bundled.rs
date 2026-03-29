use super::model::Migration;

/// Returns the checked-in ClickHouse migrations in apply order.
///
/// Filenames must follow `YYYYMMDDHHMMSS_slug.sql` so the lexicographic version
/// order matches migration application order and the creation time is obvious in
/// the repository history.
pub fn bundled_migrations() -> Vec<Migration> {
    vec![
        Migration::from_filename(
            "20260329000100_create_node_observations.sql",
            include_str!("../../migrations/20260329000100_create_node_observations.sql"),
        ),
        Migration::from_filename(
            "20260329000200_create_crawler_run_checkpoints.sql",
            include_str!("../../migrations/20260329000200_create_crawler_run_checkpoints.sql"),
        ),
    ]
}
