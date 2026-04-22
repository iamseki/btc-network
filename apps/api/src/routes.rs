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

    use axum::body::Body;
    use axum::http::{HeaderValue, Request, StatusCode, header};
    use btc_network::crawler::{
        AsnNodeCountItem, CrawlRunDetail, CrawlRunId, CrawlRunListItem, CrawlerAnalyticsReader,
        CrawlerRepositoryError, LastRunAsnCountItem, LastRunAsnOrganizationCountItem,
        LastRunCountryCountItem, LastRunNetworkTypeCountItem, LastRunNodeSummaryItem,
        LastRunProtocolVersionCountItem, LastRunServicesCountItem, LastRunStartHeightCountItem,
        LastRunUserAgentCountItem, RepositoryFuture,
    };
    use tower::util::ServiceExt;

    use super::build_router_with_config;
    use crate::{ApiRuntimeConfig, DocsConfig};

    #[derive(Default)]
    struct CorsReader {
        runs: Vec<CrawlRunListItem>,
    }

    impl CrawlerAnalyticsReader for CorsReader {
        fn list_crawl_runs<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<CrawlRunListItem>, CrawlerRepositoryError>> {
            let runs = self.runs.clone();
            Box::pin(async move { Ok(runs) })
        }

        fn get_crawl_run<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
            _checkpoint_limit: usize,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunDetail>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(None) })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_services<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunServicesCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_protocol_versions<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<
            'a,
            Result<Vec<LastRunProtocolVersionCountItem>, CrawlerRepositoryError>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_user_agents<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunUserAgentCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_network_types<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunNetworkTypeCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_countries<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunCountryCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_asns<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_start_heights<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunStartHeightCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_asn_organizations<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<
            'a,
            Result<Vec<LastRunAsnOrganizationCountItem>, CrawlerRepositoryError>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_nodes<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunNodeSummaryItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn sample_run() -> CrawlRunListItem {
        CrawlRunListItem {
            run_id: "00000000-0000-0000-0000-000000000001".to_string(),
            phase: "finished".to_string(),
            started_at: "2026-03-30T12:00:00+00:00".to_string(),
            last_checkpointed_at: "2026-03-30T12:10:00+00:00".to_string(),
            stop_reason: Some("idle timeout".to_string()),
            failure_reason: None,
            scheduled_tasks: 10,
            successful_handshakes: 4,
            failed_tasks: 6,
            unique_nodes: 12,
            persisted_observation_rows: 10,
            success_pct: 40.0,
            scheduled_pct: 83.33,
            unscheduled_gap: 2,
        }
    }

    #[tokio::test]
    async fn cors_allows_configured_origin_and_omits_disallowed_origin() {
        let origin = HeaderValue::from_static("https://btcnetwork.info");
        let app = build_router_with_config(
            Arc::new(CorsReader {
                runs: vec![sample_run()],
            }),
            ApiRuntimeConfig::default().with_allowed_origins(vec![origin.clone()]),
            DocsConfig::default(),
        );

        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/network/historical/runs")
                    .header(header::ORIGIN, "https://btcnetwork.info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("allowed response");
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            allowed.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&origin)
        );

        let disallowed = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/network/historical/runs")
                    .header(header::ORIGIN, "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("disallowed response");
        assert!(
            disallowed
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }
}
