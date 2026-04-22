mod handlers;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use btc_network_api::build_router;
use btc_network_postgres::PostgresCrawlerRepository;
use btc_network_testkit::{FixtureRouterApp, ScenarioDatabase, TestkitResult};

pub(crate) type TestResult<T = ()> = TestkitResult<T>;

pub(crate) fn build_api_router(database: &ScenarioDatabase) -> TestResult<Router> {
    Ok(build_router(Arc::new(PostgresCrawlerRepository::new(
        database.config(),
    )?)))
}

pub(crate) async fn fixture_app(scenario_name: &str) -> TestResult<FixtureRouterApp> {
    FixtureRouterApp::from_fixture_root(fixtures_root(), scenario_name, build_api_router).await
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}
