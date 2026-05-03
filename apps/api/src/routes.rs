use std::sync::Arc;

use axum::Router;
use axum::http::{Method, StatusCode, header};
use axum::routing::get;
use btc_network::crawler::CrawlerAnalyticsReader;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;

use crate::config::ApiRuntimeConfig;
use crate::docs::{self, DocsConfig};
use crate::handlers;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) analytics_reader: Arc<dyn CrawlerAnalyticsReader>,
    pub(crate) docs_config: DocsConfig,
}

impl AppState {
    fn new(analytics_reader: Arc<dyn CrawlerAnalyticsReader>, docs_config: DocsConfig) -> Self {
        Self {
            analytics_reader,
            docs_config,
        }
    }
}

pub fn build_router(analytics_reader: Arc<dyn CrawlerAnalyticsReader>) -> Router {
    build_router_with_config(
        analytics_reader,
        ApiRuntimeConfig::default(),
        DocsConfig::default(),
    )
}

pub fn build_router_with_config(
    analytics_reader: Arc<dyn CrawlerAnalyticsReader>,
    config: ApiRuntimeConfig,
    docs_config: DocsConfig,
) -> Router {
    Router::new()
        .merge(docs::router(docs_config.clone()))
        .route(
            handlers::HISTORICAL_RUNS_PATH,
            get(handlers::list_crawl_runs),
        )
        .route(
            handlers::HISTORICAL_RUN_DETAIL_PATH,
            get(handlers::get_crawl_run),
        )
        .route(
            handlers::HISTORICAL_ASNS_PATH,
            get(handlers::count_nodes_by_asn),
        )
        .route(
            handlers::LIST_LAST_RUN_SERVICES_PATH,
            get(handlers::list_last_run_services),
        )
        .route(
            handlers::LIST_LAST_RUN_PROTOCOL_VERSIONS_PATH,
            get(handlers::list_last_run_protocol_versions),
        )
        .route(
            handlers::LIST_LAST_RUN_USER_AGENTS_PATH,
            get(handlers::list_last_run_user_agents),
        )
        .route(
            handlers::LIST_LAST_RUN_NETWORK_TYPES_PATH,
            get(handlers::list_last_run_network_types),
        )
        .route(
            handlers::LIST_LAST_RUN_COUNTRIES_PATH,
            get(handlers::list_last_run_countries),
        )
        .route(
            handlers::LIST_LAST_RUN_ASNS_PATH,
            get(handlers::list_last_run_asns),
        )
        .route(
            handlers::LIST_LAST_RUN_START_HEIGHTS_PATH,
            get(handlers::list_last_run_start_heights),
        )
        .route(
            handlers::LIST_LAST_RUN_ASN_ORGANIZATIONS_PATH,
            get(handlers::list_last_run_asn_organizations),
        )
        .route(
            handlers::LIST_LAST_RUN_NODES_PATH,
            get(handlers::list_last_run_nodes),
        )
        .route(handlers::NODE_STATUS_PATH, get(handlers::list_node_status))
        .layer(
            ServiceBuilder::new()
                .layer(ConcurrencyLimitLayer::new(config.concurrency_limit))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    config.request_timeout,
                ))
                .layer(
                    CorsLayer::new()
                        .allow_origin(config.allowed_origins)
                        .allow_methods([Method::GET])
                        .allow_headers([header::ACCEPT]),
                ),
        )
        .with_state(AppState::new(analytics_reader, docs_config))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::{HeaderValue, StatusCode, header};
    use btc_network_postgres::PostgresCrawlerRepository;
    use btc_network_testkit::{FixtureRouterApp, TestkitResult};
    use tower::util::ServiceExt;

    use super::*;

    fn build_configured_router(
        database: &btc_network_testkit::ScenarioDatabase,
    ) -> TestkitResult<Router> {
        Ok(build_router_with_config(
            Arc::new(PostgresCrawlerRepository::new(database.config())?),
            ApiRuntimeConfig::default()
                .with_allowed_origins(vec![HeaderValue::from_static("https://btcnetwork.info")]),
            DocsConfig::default(),
        ))
    }

    #[tokio::test]
    async fn cors_allows_configured_origin_and_omits_disallowed_origin() -> TestkitResult {
        let app = FixtureRouterApp::empty("cors", build_configured_router).await?;

        let allowed = app
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(handlers::HISTORICAL_RUNS_PATH)
                    .header(header::ORIGIN, "https://btcnetwork.info")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await?;
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            allowed.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://btcnetwork.info"))
        );

        let disallowed = app
            .router
            .oneshot(
                axum::http::Request::builder()
                    .uri(handlers::HISTORICAL_RUNS_PATH)
                    .header(header::ORIGIN, "https://evil.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await?;
        assert!(
            disallowed
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );

        Ok(())
    }
}
