use std::time::Duration;

use btc_network::crawler::{CrawlNetwork, CrawlPhase, FailureClassification, IpEnrichmentStatus};

pub(crate) fn crawl_phase_to_str(value: CrawlPhase) -> &'static str {
    match value {
        CrawlPhase::Bootstrap => "bootstrap",
        CrawlPhase::Crawling => "crawling",
        CrawlPhase::Draining => "draining",
        CrawlPhase::Finished => "finished",
    }
}

pub(crate) fn crawl_phase_from_str(value: &str) -> CrawlPhase {
    match value {
        "bootstrap" => CrawlPhase::Bootstrap,
        "crawling" => CrawlPhase::Crawling,
        "draining" => CrawlPhase::Draining,
        "finished" => CrawlPhase::Finished,
        _ => CrawlPhase::Finished,
    }
}

pub(crate) fn crawl_network_to_str(value: CrawlNetwork) -> &'static str {
    match value {
        CrawlNetwork::Ipv4 => "ipv4",
        CrawlNetwork::Ipv6 => "ipv6",
        CrawlNetwork::TorV2 => "tor_v2",
        CrawlNetwork::TorV3 => "tor_v3",
        CrawlNetwork::I2p => "i2p",
        CrawlNetwork::Cjdns => "cjdns",
        CrawlNetwork::Yggdrasil => "yggdrasil",
        CrawlNetwork::Unknown => "unknown",
    }
}

pub(crate) fn enrichment_status_to_str(value: IpEnrichmentStatus) -> &'static str {
    match value {
        IpEnrichmentStatus::Matched => "matched",
        IpEnrichmentStatus::NotApplicable => "not_applicable",
        IpEnrichmentStatus::Unavailable => "unavailable",
        IpEnrichmentStatus::LookupFailed => "lookup_failed",
    }
}

pub(crate) fn failure_classification_to_str(value: &FailureClassification) -> String {
    match value {
        FailureClassification::Connect => "connect".to_string(),
        FailureClassification::Handshake => "handshake".to_string(),
        FailureClassification::PeerDiscovery => "peer_discovery".to_string(),
        FailureClassification::Io => "io".to_string(),
        FailureClassification::Other(message) => format!("other:{message}"),
    }
}

pub(crate) fn duration_to_millis(value: Duration) -> i64 {
    value.as_millis().min(i64::MAX as u128) as i64
}

pub(crate) fn usize_to_i64(value: usize) -> i64 {
    value.min(i64::MAX as usize) as i64
}
