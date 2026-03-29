use super::*;
use btc_network::crawler::{
    BatchId, CountNodesByAsnRow, CrawlEndpoint, CrawlNetwork, CrawlPhase, CrawlRunCheckpoint,
    CrawlRunId, CrawlRunMetrics, HandshakeStatus, IpEnrichment, ObservationConfidence,
    ObservationId, PersistedNodeObservation, RawNodeObservation,
};
use chrono::Utc;
use clickhouse::test::{self, handlers};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::rows::{CountNodesByAsnDbRow, NodeObservationRow, from_checkpoint};

fn sample_observation() -> PersistedNodeObservation {
    RawNodeObservation {
        observed_at: Utc::now(),
        crawl_run_id: CrawlRunId::new("run-1"),
        endpoint: CrawlEndpoint::new(
            "1.1.1.7",
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 7))),
        ),
        handshake_status: HandshakeStatus::Succeeded,
        confidence: ObservationConfidence::Verified,
        protocol_version: Some(70016),
        services: Some(1),
        user_agent: Some("/Satoshi:27.0.0/".to_string()),
        start_height: Some(900_000),
        relay: Some(true),
        discovered_count: 8,
        latency: Some(Duration::from_millis(125)),
        failure_classification: None,
    }
    .into_persisted(
        ObservationId::new("observation-1"),
        BatchId::new("batch-1"),
        IpEnrichment::matched(
            Some(64512),
            Some("Example ASN".to_string()),
            Some("US".to_string()),
            Some("1.1.1.0/24".to_string()),
        ),
    )
}

fn sample_checkpoint() -> CrawlRunCheckpoint {
    CrawlRunCheckpoint {
        run_id: CrawlRunId::new("run-1"),
        phase: CrawlPhase::Crawling,
        checkpointed_at: Utc::now(),
        checkpoint_sequence: 1,
        started_at: Utc::now(),
        stop_reason: None,
        failure_reason: None,
        metrics: CrawlRunMetrics {
            frontier_size: 1,
            in_flight_work: 2,
            scheduled_tasks: 3,
            successful_handshakes: 4,
            failed_tasks: 1,
            queued_nodes_total: 5,
            unique_nodes: 6,
            discovered_node_states: 7,
            persisted_observation_rows: 8,
            writer_backlog: 0,
        },
        resume_state: Some("{\"frontier\":[]}".to_string()),
        caller: Some("test".to_string()),
    }
}

#[tokio::test]
async fn repository_streams_observation_rows_with_expected_shape() {
    let mock = test::Mock::new();
    let client = Client::default().with_mock(&mock);
    let repository = ClickHouseCrawlerRepository::with_client(client);
    let recording = mock.add(handlers::record());

    repository
        .insert_observations_stream(vec![sample_observation()])
        .await
        .expect("insert observations");

    let rows: Vec<NodeObservationRow> = recording.collect().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].observation_id, "observation-1");
    assert_eq!(rows[0].endpoint, "1.1.1.7:8333");
    assert_eq!(rows[0].network_type, "ipv4");
    assert_eq!(rows[0].confidence_level, "verified");
    assert_eq!(rows[0].asn, Some(64512));
}

#[tokio::test]
async fn repository_fetches_latest_checkpoint_for_run() {
    let mock = test::Mock::new();
    let client = Client::default().with_mock(&mock);
    let repository = ClickHouseCrawlerRepository::with_client(client);
    let checkpoint = from_checkpoint(sample_checkpoint());
    mock.add(handlers::provide(vec![checkpoint.clone()]));

    let result = repository
        .get_run_checkpoint(&CrawlRunId::new("run-1"))
        .await
        .expect("get checkpoint")
        .expect("checkpoint exists");

    assert_eq!(result.run_id.as_str(), "run-1");
    assert_eq!(result.phase, CrawlPhase::Crawling);
    assert_eq!(
        result.metrics.unique_nodes,
        checkpoint.unique_nodes as usize
    );
}

#[tokio::test]
async fn repository_counts_latest_verified_nodes_by_asn() {
    let mock = test::Mock::new();
    let client = Client::default().with_mock(&mock);
    let repository = ClickHouseCrawlerRepository::with_client(client);
    mock.add(handlers::provide(vec![
        CountNodesByAsnDbRow {
            asn: Some(64512),
            asn_organization: Some("Example ASN".to_string()),
            verified_nodes: 4,
        },
        CountNodesByAsnDbRow {
            asn: None,
            asn_organization: None,
            verified_nodes: 1,
        },
    ]));

    let rows = repository
        .count_nodes_by_asn()
        .await
        .expect("count nodes by asn");

    assert_eq!(
        rows,
        vec![
            CountNodesByAsnRow {
                asn: Some(64512),
                asn_organization: Some("Example ASN".to_string()),
                verified_nodes: 4,
            },
            CountNodesByAsnRow {
                asn: None,
                asn_organization: None,
                verified_nodes: 1,
            },
        ]
    );
}

#[tokio::test]
async fn repository_list_runs_query_includes_argmax_latest_checkpoint_shape() {
    let mock = test::Mock::new();
    let client = Client::default().with_mock(&mock);
    let repository = ClickHouseCrawlerRepository::with_client(client.clone());
    let recording = mock.add(handlers::record_ddl());

    repository.list_runs().await.expect("list runs");

    let query = recording.query().await;
    assert!(query.contains("argMax(phase, tuple(checkpointed_at, checkpoint_sequence))"));
    assert!(query.contains("latest_checkpoint_sequence AS checkpoint_sequence"));
    assert!(query.contains("GROUP BY run_id"));
    assert!(query.contains("crawler_run_checkpoints"));
}
