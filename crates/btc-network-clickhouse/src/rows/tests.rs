use super::*;
use btc_network::crawler::{
    BatchId, CrawlEndpoint, CrawlNetwork, CrawlRunId, HandshakeStatus, IpEnrichment,
    ObservationConfidence, ObservationId, RawNodeObservation,
};
use chrono::Utc;
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
    assert_eq!(row.confidence_level, "verified");
    assert_eq!(row.enrichment_status, "matched");
    assert_eq!(row.asn, Some(64512));
    assert_eq!(row.country.as_deref(), Some("US"));
}
