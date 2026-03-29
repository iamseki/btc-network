use btc_network::crawler::{
    CountNodesByAsnRow, CrawlPhase, CrawlRunCheckpoint, CrawlRunId, FailureClassification,
    HandshakeStatus, IpEnrichmentStatus, ObservationConfidence, PersistedNodeObservation,
};
use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub(crate) struct NodeObservationRow {
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub observed_at: DateTime<Utc>,
    pub crawl_run_id: String,
    pub observation_id: String,
    pub batch_id: String,
    pub endpoint: String,
    pub network_type: String,
    pub handshake_status: String,
    pub confidence_level: String,
    pub protocol_version: Option<i32>,
    pub services: Option<u64>,
    pub user_agent: Option<String>,
    pub start_height: Option<i32>,
    pub relay: Option<bool>,
    pub discovered_count: u64,
    pub latency_ms: Option<u64>,
    pub failure_classification: Option<String>,
    pub enrichment_status: String,
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
    pub country: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub(crate) struct RunCheckpointRow {
    pub run_id: String,
    pub phase: String,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub checkpointed_at: DateTime<Utc>,
    pub checkpoint_sequence: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub started_at: DateTime<Utc>,
    pub stop_reason: Option<String>,
    pub failure_reason: Option<String>,
    pub frontier_size: u64,
    pub in_flight_work: u64,
    pub scheduled_tasks: u64,
    pub successful_handshakes: u64,
    pub failed_tasks: u64,
    pub queued_nodes_total: u64,
    pub unique_nodes: u64,
    pub discovered_node_states: u64,
    pub persisted_observation_rows: u64,
    pub writer_backlog: u64,
    pub resume_state: Option<String>,
    pub caller: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub(crate) struct CountNodesByAsnDbRow {
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
    pub verified_nodes: u64,
}

pub(crate) fn from_persisted_observation(
    observation: PersistedNodeObservation,
) -> NodeObservationRow {
    let latency_ms = observation
        .raw
        .latency
        .map(|latency| latency.as_millis().min(u128::from(u64::MAX)) as u64);

    NodeObservationRow {
        observed_at: observation.raw.observed_at,
        crawl_run_id: observation.raw.crawl_run_id.as_str().to_string(),
        observation_id: observation.observation_id.as_str().to_string(),
        batch_id: observation.batch_id.as_str().to_string(),
        endpoint: observation.raw.endpoint.canonical,
        network_type: crawl_network_to_str(observation.raw.endpoint.network).to_string(),
        handshake_status: handshake_status_to_str(observation.raw.handshake_status).to_string(),
        confidence_level: confidence_to_str(observation.raw.confidence).to_string(),
        protocol_version: observation.raw.protocol_version,
        services: observation.raw.services,
        user_agent: observation.raw.user_agent,
        start_height: observation.raw.start_height,
        relay: observation.raw.relay,
        discovered_count: observation.raw.discovered_count as u64,
        latency_ms,
        failure_classification: observation
            .raw
            .failure_classification
            .as_ref()
            .map(failure_classification_to_str),
        enrichment_status: enrichment_status_to_str(observation.enrichment.status).to_string(),
        asn: observation.enrichment.asn,
        asn_organization: observation.enrichment.asn_organization,
        country: observation.enrichment.country,
        prefix: observation.enrichment.prefix,
    }
}

pub(crate) fn from_checkpoint(checkpoint: CrawlRunCheckpoint) -> RunCheckpointRow {
    RunCheckpointRow {
        run_id: checkpoint.run_id.as_str().to_string(),
        phase: phase_to_str(checkpoint.phase).to_string(),
        checkpointed_at: checkpoint.checkpointed_at,
        checkpoint_sequence: checkpoint.checkpoint_sequence,
        started_at: checkpoint.started_at,
        stop_reason: checkpoint.stop_reason,
        failure_reason: checkpoint.failure_reason,
        frontier_size: checkpoint.metrics.frontier_size as u64,
        in_flight_work: checkpoint.metrics.in_flight_work as u64,
        scheduled_tasks: checkpoint.metrics.scheduled_tasks as u64,
        successful_handshakes: checkpoint.metrics.successful_handshakes as u64,
        failed_tasks: checkpoint.metrics.failed_tasks as u64,
        queued_nodes_total: checkpoint.metrics.queued_nodes_total as u64,
        unique_nodes: checkpoint.metrics.unique_nodes as u64,
        discovered_node_states: checkpoint.metrics.discovered_node_states as u64,
        persisted_observation_rows: checkpoint.metrics.persisted_observation_rows as u64,
        writer_backlog: checkpoint.metrics.writer_backlog as u64,
        resume_state: checkpoint.resume_state,
        caller: checkpoint.caller,
    }
}

pub(crate) fn to_checkpoint(row: RunCheckpointRow) -> CrawlRunCheckpoint {
    CrawlRunCheckpoint {
        run_id: CrawlRunId::new(row.run_id),
        phase: phase_from_str(&row.phase),
        checkpointed_at: row.checkpointed_at,
        checkpoint_sequence: row.checkpoint_sequence,
        started_at: row.started_at,
        stop_reason: row.stop_reason,
        failure_reason: row.failure_reason,
        metrics: btc_network::crawler::CrawlRunMetrics {
            frontier_size: row.frontier_size as usize,
            in_flight_work: row.in_flight_work as usize,
            scheduled_tasks: row.scheduled_tasks as usize,
            successful_handshakes: row.successful_handshakes as usize,
            failed_tasks: row.failed_tasks as usize,
            queued_nodes_total: row.queued_nodes_total as usize,
            unique_nodes: row.unique_nodes as usize,
            discovered_node_states: row.discovered_node_states as usize,
            persisted_observation_rows: row.persisted_observation_rows as usize,
            writer_backlog: row.writer_backlog as usize,
        },
        resume_state: row.resume_state,
        caller: row.caller,
    }
}

pub(crate) fn to_count_nodes_by_asn(row: CountNodesByAsnDbRow) -> CountNodesByAsnRow {
    CountNodesByAsnRow {
        asn: row.asn,
        asn_organization: row.asn_organization,
        verified_nodes: row.verified_nodes,
    }
}

fn crawl_network_to_str(value: btc_network::crawler::CrawlNetwork) -> &'static str {
    match value {
        btc_network::crawler::CrawlNetwork::Ipv4 => "ipv4",
        btc_network::crawler::CrawlNetwork::Ipv6 => "ipv6",
        btc_network::crawler::CrawlNetwork::TorV2 => "tor_v2",
        btc_network::crawler::CrawlNetwork::TorV3 => "tor_v3",
        btc_network::crawler::CrawlNetwork::I2p => "i2p",
        btc_network::crawler::CrawlNetwork::Cjdns => "cjdns",
        btc_network::crawler::CrawlNetwork::Yggdrasil => "yggdrasil",
        btc_network::crawler::CrawlNetwork::Unknown => "unknown",
    }
}

fn handshake_status_to_str(value: HandshakeStatus) -> &'static str {
    match value {
        HandshakeStatus::Succeeded => "succeeded",
        HandshakeStatus::Failed => "failed",
        HandshakeStatus::NotAttempted => "not_attempted",
    }
}

fn confidence_to_str(value: ObservationConfidence) -> &'static str {
    match value {
        ObservationConfidence::Verified => "verified",
        ObservationConfidence::Failed => "failed",
        ObservationConfidence::Rumored => "rumored",
    }
}

fn failure_classification_to_str(value: &FailureClassification) -> String {
    match value {
        FailureClassification::Connect => "connect".to_string(),
        FailureClassification::Handshake => "handshake".to_string(),
        FailureClassification::PeerDiscovery => "peer_discovery".to_string(),
        FailureClassification::Io => "io".to_string(),
        FailureClassification::Other(message) => format!("other:{message}"),
    }
}

fn enrichment_status_to_str(value: IpEnrichmentStatus) -> &'static str {
    match value {
        IpEnrichmentStatus::Matched => "matched",
        IpEnrichmentStatus::NotApplicable => "not_applicable",
        IpEnrichmentStatus::Unavailable => "unavailable",
        IpEnrichmentStatus::LookupFailed => "lookup_failed",
    }
}

fn phase_to_str(value: CrawlPhase) -> &'static str {
    match value {
        CrawlPhase::Bootstrap => "bootstrap",
        CrawlPhase::Crawling => "crawling",
        CrawlPhase::Draining => "draining",
        CrawlPhase::Completed => "completed",
        CrawlPhase::Failed => "failed",
    }
}

fn phase_from_str(value: &str) -> CrawlPhase {
    match value {
        "bootstrap" => CrawlPhase::Bootstrap,
        "crawling" => CrawlPhase::Crawling,
        "draining" => CrawlPhase::Draining,
        "completed" => CrawlPhase::Completed,
        "failed" => CrawlPhase::Failed,
        _ => CrawlPhase::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_network::crawler::{
        BatchId, CrawlEndpoint, CrawlNetwork, CrawlRunId, HandshakeStatus, IpEnrichment,
        ObservationConfidence, ObservationId, RawNodeObservation,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn persisted_observation_rows_preserve_bnnd_boundary_fields() {
        let row = from_persisted_observation(
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
                discovered_count: 3,
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
            ),
        );

        assert_eq!(row.endpoint, "1.1.1.7:8333");
        assert_eq!(row.network_type, "ipv4");
        assert_eq!(row.enrichment_status, "matched");
        assert_eq!(row.asn, Some(64512));
        assert_eq!(row.country.as_deref(), Some("US"));
        assert_eq!(row.latency_ms, Some(125));
    }
}
