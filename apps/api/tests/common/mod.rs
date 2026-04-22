use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::Request;
use btc_network::crawler::{
    AsnNodeCountItem, CrawlRunDetail, CrawlRunId, CrawlRunListItem, CrawlerAnalyticsReader,
    CrawlerRepositoryError, FailureClassificationCount, LastRunAsnCountItem,
    LastRunAsnOrganizationCountItem, LastRunCountryCountItem, LastRunNetworkTypeCountItem,
    LastRunNodeSummaryItem, LastRunProtocolVersionCountItem, LastRunServicesCountItem,
    LastRunStartHeightCountItem, LastRunUserAgentCountItem, NetworkOutcomeCount, RepositoryFuture,
};
use btc_network_api::build_router;
use serde_json::Value;

#[derive(Default)]
pub struct StubAnalyticsReader {
    pub runs: Vec<CrawlRunListItem>,
    pub detail: Option<CrawlRunDetail>,
    pub asn_rows: Vec<AsnNodeCountItem>,
    pub last_run_services: Vec<LastRunServicesCountItem>,
    pub last_run_protocol_versions: Vec<LastRunProtocolVersionCountItem>,
    pub last_run_user_agents: Vec<LastRunUserAgentCountItem>,
    pub last_run_network_types: Vec<LastRunNetworkTypeCountItem>,
    pub last_run_countries: Vec<LastRunCountryCountItem>,
    pub last_run_asns: Vec<LastRunAsnCountItem>,
    pub last_run_start_heights: Vec<LastRunStartHeightCountItem>,
    pub last_run_asn_organizations: Vec<LastRunAsnOrganizationCountItem>,
    pub last_run_nodes: Vec<LastRunNodeSummaryItem>,
    pub fail_with: Option<CrawlerRepositoryError>,
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

    fn list_last_run_services<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunServicesCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_services.clone())
        })
    }

    fn list_last_run_protocol_versions<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunProtocolVersionCountItem>, CrawlerRepositoryError>>
    {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_protocol_versions.clone())
        })
    }

    fn list_last_run_user_agents<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunUserAgentCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_user_agents.clone())
        })
    }

    fn list_last_run_network_types<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunNetworkTypeCountItem>, CrawlerRepositoryError>>
    {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_network_types.clone())
        })
    }

    fn list_last_run_countries<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunCountryCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_countries.clone())
        })
    }

    fn list_last_run_asns<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_asns.clone())
        })
    }

    fn list_last_run_start_heights<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunStartHeightCountItem>, CrawlerRepositoryError>>
    {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_start_heights.clone())
        })
    }

    fn list_last_run_asn_organizations<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnOrganizationCountItem>, CrawlerRepositoryError>>
    {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_asn_organizations.clone())
        })
    }

    fn list_last_run_nodes<'a>(
        &'a self,
        _limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunNodeSummaryItem>, CrawlerRepositoryError>> {
        Box::pin(async move {
            if let Some(error) = &self.fail_with {
                return Err(error.clone());
            }

            Ok(self.last_run_nodes.clone())
        })
    }
}

pub fn app(reader: StubAnalyticsReader) -> axum::Router {
    build_router(Arc::new(reader))
}

pub fn request(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

pub async fn json_body(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&body).expect("json body")
}

pub fn sample_run() -> CrawlRunListItem {
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

pub fn sample_detail() -> CrawlRunDetail {
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

pub fn sample_last_run_asn() -> LastRunAsnCountItem {
    LastRunAsnCountItem {
        asn: 64512,
        asn_organization: Some("Example ASN".to_string()),
        node_count: 4,
    }
}

pub fn sample_last_run_node() -> LastRunNodeSummaryItem {
    LastRunNodeSummaryItem {
        endpoint: "1.1.1.7:8333".to_string(),
        network_type: "ipv4".to_string(),
        protocol_version: 70016,
        user_agent: "/Satoshi:27.0.0/".to_string(),
        services: "1".to_string(),
        start_height: 900_000,
        country: Some("US".to_string()),
        asn: Some(64512),
        asn_organization: Some("Example ASN".to_string()),
    }
}
