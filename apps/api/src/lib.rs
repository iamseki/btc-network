use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use btc_network::crawler::{
    AsnNodeCountItem, CrawlRunDetail, CrawlRunId, CrawlRunListItem, CrawlerAnalyticsReader,
    CrawlerRepositoryError,
};
use btc_network_postgres::{PostgresConnectionConfig, PostgresCrawlerRepository};
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::error;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_RUN_LIMIT: usize = 10;
const DEFAULT_ASN_LIMIT: usize = 10;
const DEFAULT_CHECKPOINT_LIMIT: usize = 10;
const MAX_PAGE_LIMIT: usize = 100;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;
const DEFAULT_CONCURRENCY_LIMIT: usize = 64;
const DEFAULT_ALLOWED_ORIGINS: [&str; 7] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://btcnetwork.info",
    "https://www.btcnetwork.info",
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
];

#[derive(Clone)]
struct ApiRuntimeConfig {
    allowed_origins: Vec<HeaderValue>,
    request_timeout: Duration,
    concurrency_limit: usize,
}

impl Default for ApiRuntimeConfig {
    fn default() -> Self {
        Self {
            allowed_origins: DEFAULT_ALLOWED_ORIGINS
                .into_iter()
                .map(HeaderValue::from_static)
                .collect(),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    analytics_reader: Arc<dyn CrawlerAnalyticsReader>,
}

impl AppState {
    pub fn new(analytics_reader: Arc<dyn CrawlerAnalyticsReader>) -> Self {
        Self { analytics_reader }
    }
}

pub fn build_router(analytics_reader: Arc<dyn CrawlerAnalyticsReader>) -> Router {
    build_router_with_config(analytics_reader, ApiRuntimeConfig::default())
}

fn build_router_with_config(
    analytics_reader: Arc<dyn CrawlerAnalyticsReader>,
    config: ApiRuntimeConfig,
) -> Router {
    Router::new()
        .route("/api/v1/crawler/runs", get(list_crawl_runs))
        .route("/api/v1/crawler/runs/{run_id}", get(get_crawl_run))
        .route("/api/v1/crawler/asn", get(count_nodes_by_asn))
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
        .with_state(AppState::new(analytics_reader))
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = parse_bind_addr()?;
    let postgres_config = parse_postgres_config()?;
    let runtime_config = parse_runtime_config()?;
    let analytics_reader: Arc<dyn CrawlerAnalyticsReader> =
        Arc::new(PostgresCrawlerRepository::new(&postgres_config)?);
    let app = build_router_with_config(analytics_reader, runtime_config);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!(%bind_addr, "[api] listening for crawler analytics requests");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct PaginationQuery {
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CrawlRunsResponse {
    runs: Vec<CrawlRunListItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AsnCountsResponse {
    rows: Vec<AsnNodeCountItem>,
}

async fn list_crawl_runs(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<CrawlRunsResponse>, ApiError> {
    let limit = parse_limit(query.limit, DEFAULT_RUN_LIMIT)?;
    let runs = state
        .analytics_reader
        .list_crawl_runs(limit)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(CrawlRunsResponse { runs }))
}

async fn get_crawl_run(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
) -> Result<Json<CrawlRunDetail>, ApiError> {
    let run_id = CrawlRunId::parse_str(&run_id)
        .map_err(|_| ApiError::bad_request("invalid crawl run id"))?;
    let detail = state
        .analytics_reader
        .get_crawl_run(&run_id, DEFAULT_CHECKPOINT_LIMIT)
        .await
        .map_err(ApiError::internal)?;

    match detail {
        Some(detail) => Ok(Json(detail)),
        None => Err(ApiError::not_found("crawl run not found")),
    }
}

async fn count_nodes_by_asn(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<AsnCountsResponse>, ApiError> {
    let limit = parse_limit(query.limit, DEFAULT_ASN_LIMIT)?;
    let rows = state
        .analytics_reader
        .count_nodes_by_asn(limit)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(AsnCountsResponse { rows }))
}

fn parse_bind_addr() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let value =
        env::var("BTC_NETWORK_API_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    Ok(value.parse()?)
}

fn parse_postgres_config() -> Result<PostgresConnectionConfig, Box<dyn std::error::Error>> {
    let url = env::var("BTC_NETWORK_POSTGRES_URL").unwrap_or_else(|_| {
        "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network".to_string()
    });
    let max_connections = parse_positive_usize_env("BTC_NETWORK_POSTGRES_MAX_CONNECTIONS", 16)?;

    Ok(PostgresConnectionConfig::new(url).with_max_connections(max_connections))
}

fn parse_runtime_config() -> Result<ApiRuntimeConfig, Box<dyn std::error::Error>> {
    Ok(ApiRuntimeConfig {
        allowed_origins: parse_allowed_origins()?,
        request_timeout: Duration::from_secs(parse_positive_u64_env(
            "BTC_NETWORK_API_REQUEST_TIMEOUT_SECS",
            DEFAULT_REQUEST_TIMEOUT_SECS,
        )?),
        concurrency_limit: parse_positive_usize_env(
            "BTC_NETWORK_API_CONCURRENCY_LIMIT",
            DEFAULT_CONCURRENCY_LIMIT,
        )?,
    })
}

fn parse_allowed_origins() -> Result<Vec<HeaderValue>, Box<dyn std::error::Error>> {
    let Some(value) = env::var("BTC_NETWORK_API_ALLOWED_ORIGINS").ok() else {
        return Ok(ApiRuntimeConfig::default().allowed_origins);
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(ApiRuntimeConfig::default().allowed_origins);
    }

    let mut origins = Vec::new();
    for origin in trimmed
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
    {
        origins.push(HeaderValue::from_str(origin)?);
    }

    if origins.is_empty() {
        return Ok(ApiRuntimeConfig::default().allowed_origins);
    }

    Ok(origins)
}

fn parse_positive_usize_env(
    name: &str,
    default_value: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let Some(raw_value) = env::var(name).ok() else {
        return Ok(default_value);
    };

    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return Ok(default_value);
    }

    let value: usize = trimmed.parse()?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }

    Ok(value)
}

fn parse_positive_u64_env(
    name: &str,
    default_value: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let Some(raw_value) = env::var(name).ok() else {
        return Ok(default_value);
    };

    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return Ok(default_value);
    }

    let value: u64 = trimmed.parse()?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }

    Ok(value)
}

fn parse_limit(value: Option<usize>, default_value: usize) -> Result<usize, ApiError> {
    let limit = value.unwrap_or(default_value);

    if limit == 0 {
        return Err(ApiError::bad_request("limit must be greater than zero"));
    }

    if limit > MAX_PAGE_LIMIT {
        return Err(ApiError::bad_request(
            "limit must be less than or equal to 100",
        ));
    }

    Ok(limit)
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    log_detail: Option<String>,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
            log_detail: None,
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
            log_detail: None,
        }
    }

    fn internal(error: CrawlerRepositoryError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "crawler analytics backend failed".to_string(),
            log_detail: Some(error.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Some(detail) = self.log_detail {
            error!(code = self.code, detail = %detail, "[api] request failed");
        }

        (
            self.status,
            Json(ErrorResponse {
                error: ErrorBody {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use btc_network::crawler::{FailureClassificationCount, NetworkOutcomeCount, RepositoryFuture};
    use serde_json::Value;
    use tower::util::ServiceExt;

    #[derive(Default)]
    struct StubAnalyticsReader {
        runs: Vec<CrawlRunListItem>,
        detail: Option<CrawlRunDetail>,
        asn_rows: Vec<AsnNodeCountItem>,
        fail_with: Option<CrawlerRepositoryError>,
    }

    impl CrawlerAnalyticsReader for StubAnalyticsReader {
        fn list_crawl_runs<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<CrawlRunListItem>, CrawlerRepositoryError>> {
            Box::pin(async move {
                if let Some(error) = &self.fail_with {
                    return Err(error.clone());
                }

                Ok(self.runs.clone())
            })
        }

        fn get_crawl_run<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
            _checkpoint_limit: usize,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunDetail>, CrawlerRepositoryError>> {
            Box::pin(async move {
                if let Some(error) = &self.fail_with {
                    return Err(error.clone());
                }

                Ok(self.detail.clone())
            })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError>> {
            Box::pin(async move {
                if let Some(error) = &self.fail_with {
                    return Err(error.clone());
                }

                Ok(self.asn_rows.clone())
            })
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

    fn sample_detail() -> CrawlRunDetail {
        CrawlRunDetail {
            run: sample_run(),
            checkpoints: Vec::new(),
            failure_counts: vec![FailureClassificationCount {
                classification: "connect".to_string(),
                observations: 6,
            }],
            network_outcomes: vec![NetworkOutcomeCount {
                network_type: "ipv4".to_string(),
                observations: 10,
                verified_nodes: 4,
                failed_nodes: 6,
                verified_pct: 40.0,
            }],
        }
    }

    #[tokio::test]
    async fn list_runs_returns_json_payload() {
        let app = build_router(Arc::new(StubAnalyticsReader {
            runs: vec![sample_run()],
            ..StubAnalyticsReader::default()
        }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/runs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_runs_rejects_zero_limit() {
        let app = build_router(Arc::new(StubAnalyticsReader::default()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/runs?limit=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_runs_rejects_limit_above_max() {
        let app = build_router(Arc::new(StubAnalyticsReader::default()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/runs?limit=101")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_run_returns_not_found_when_missing() {
        let app = build_router(Arc::new(StubAnalyticsReader::default()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/runs/00000000-0000-0000-0000-000000000099")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_run_returns_detail_payload() {
        let app = build_router(Arc::new(StubAnalyticsReader {
            detail: Some(sample_detail()),
            ..StubAnalyticsReader::default()
        }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/runs/00000000-0000-0000-0000-000000000001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_run_rejects_invalid_uuid() {
        let app = build_router(Arc::new(StubAnalyticsReader::default()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/runs/not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn asn_counts_returns_internal_error_without_leaking_adapter_message() {
        let app = build_router(Arc::new(StubAnalyticsReader {
            fail_with: Some(CrawlerRepositoryError::new("raw postgres detail")),
            ..StubAnalyticsReader::default()
        }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/asn")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: Value = serde_json::from_slice(&body).expect("json body");

        assert_eq!(json["error"]["code"], "internal_error");
        assert_eq!(json["error"]["message"], "crawler analytics backend failed");
        assert!(
            !body
                .windows("raw postgres detail".len())
                .any(|window| window == b"raw postgres detail")
        );
    }

    #[test]
    fn parse_postgres_config_uses_defaults_and_max_connections_override() {
        unsafe {
            env::remove_var("BTC_NETWORK_POSTGRES_URL");
            env::set_var("BTC_NETWORK_POSTGRES_MAX_CONNECTIONS", "24");
        }

        let config = parse_postgres_config().expect("postgres config");

        assert_eq!(
            config.url(),
            "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network"
        );
        assert_eq!(config.max_connections(), 24);

        unsafe {
            env::remove_var("BTC_NETWORK_POSTGRES_MAX_CONNECTIONS");
        }
    }

    #[tokio::test]
    async fn cors_allows_configured_origin_and_omits_disallowed_origin() {
        let app = build_router_with_config(
            Arc::new(StubAnalyticsReader {
                runs: vec![sample_run()],
                ..StubAnalyticsReader::default()
            }),
            ApiRuntimeConfig {
                allowed_origins: vec![HeaderValue::from_static("https://btcnetwork.info")],
                ..ApiRuntimeConfig::default()
            },
        );

        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/runs")
                    .header(header::ORIGIN, "https://btcnetwork.info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("allowed response");
        assert_eq!(
            allowed.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://btcnetwork.info"))
        );

        let disallowed = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/crawler/runs")
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
