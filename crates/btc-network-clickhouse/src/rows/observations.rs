use btc_network::crawler::{
    FailureClassification, HandshakeStatus, IpEnrichmentStatus, ObservationConfidence,
    PersistedNodeObservation,
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
