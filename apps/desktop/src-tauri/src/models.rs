use btc_network::client::peer;
use serde::{Deserialize, Serialize};

/// Minimal desktop request for single-peer actions.
#[derive(Debug, Deserialize)]
pub struct ConnectionRequest {
    pub node: String,
}

/// Desktop request for workflows that also emit incremental progress.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressConnectionRequest {
    pub node: String,
    pub operation_id: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockRequest {
    pub node: String,
    pub hash: String,
}

/// Desktop-facing handshake payload exposed to the web UI through Tauri.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeResponse {
    pub node: String,
    pub protocol_version: i32,
    pub services: String,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: Option<bool>,
}

/// Desktop-facing ping result with hex-encoded nonces for direct display.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PingResponse {
    pub node: String,
    pub nonce: String,
    pub echoed_nonce: String,
}

/// Desktop-facing result of the peer's current best-known block height.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LastBlockHeightResponse {
    pub node: String,
    pub height: usize,
    pub rounds: usize,
    pub elapsed_ms: u64,
    pub best_block_hash: Option<String>,
}

/// Desktop-facing progress snapshot for the chain-height workflow.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LastBlockHeightProgressResponse {
    pub operation_id: String,
    pub node: String,
    pub phase: LastBlockHeightProgressPhaseResponse,
    pub rounds_completed: usize,
    pub headers_seen: usize,
    pub last_batch_count: usize,
    pub best_block_hash: Option<String>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LastBlockHeightProgressPhaseResponse {
    Connecting,
    Handshaking,
    RequestingHeaders,
    Completed,
}

/// Desktop-facing peer address entry.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerAddressResponse {
    pub address: String,
    pub port: u16,
    pub network: String,
}

/// Desktop-facing peer address result.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerAddressesResponse {
    pub node: String,
    pub addresses: Vec<PeerAddressResponse>,
}

/// Desktop-facing block summary.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockSummaryResponse {
    pub hash: String,
    pub tx_count: u64,
    pub serialized_size: usize,
    pub coinbase_tx_detected: bool,
}

/// Desktop-facing block download result.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockDownloadResponse {
    pub hash: String,
    pub output_path: String,
    pub raw_bytes: usize,
}

impl From<peer::HandshakeSummary> for HandshakeResponse {
    fn from(summary: peer::HandshakeSummary) -> Self {
        Self {
            node: summary.node,
            protocol_version: summary.protocol_version,
            services: summary.services,
            user_agent: summary.user_agent,
            start_height: summary.start_height,
            relay: summary.relay,
        }
    }
}

impl From<peer::PingSummary> for PingResponse {
    fn from(summary: peer::PingSummary) -> Self {
        Self {
            node: summary.node,
            nonce: format!("{:#018x}", summary.nonce),
            echoed_nonce: format!("{:#018x}", summary.echoed_nonce),
        }
    }
}

impl From<peer::LastBlockHeightSummary> for LastBlockHeightResponse {
    fn from(summary: peer::LastBlockHeightSummary) -> Self {
        Self {
            node: summary.node,
            height: summary.height,
            rounds: summary.rounds,
            elapsed_ms: summary.elapsed_ms,
            best_block_hash: summary.best_block_hash,
        }
    }
}

impl LastBlockHeightProgressResponse {
    pub(crate) fn from_progress(
        operation_id: &str,
        progress: peer::LastBlockHeightProgress,
    ) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            node: progress.node,
            phase: match progress.phase {
                peer::LastBlockHeightPhase::Connecting => {
                    LastBlockHeightProgressPhaseResponse::Connecting
                }
                peer::LastBlockHeightPhase::Handshaking => {
                    LastBlockHeightProgressPhaseResponse::Handshaking
                }
                peer::LastBlockHeightPhase::RequestingHeaders => {
                    LastBlockHeightProgressPhaseResponse::RequestingHeaders
                }
                peer::LastBlockHeightPhase::Completed => {
                    LastBlockHeightProgressPhaseResponse::Completed
                }
            },
            rounds_completed: progress.rounds_completed,
            headers_seen: progress.headers_seen,
            last_batch_count: progress.last_batch_count,
            best_block_hash: progress.best_block_hash,
            elapsed_ms: progress.elapsed_ms,
        }
    }
}

impl From<peer::PeerAddressesSummary> for PeerAddressesResponse {
    fn from(summary: peer::PeerAddressesSummary) -> Self {
        Self {
            node: summary.node,
            addresses: summary
                .addresses
                .into_iter()
                .map(|entry| PeerAddressResponse {
                    address: entry.address,
                    port: entry.port,
                    network: entry.network,
                })
                .collect(),
        }
    }
}

impl From<peer::BlockSummary> for BlockSummaryResponse {
    fn from(summary: peer::BlockSummary) -> Self {
        Self {
            hash: summary.hash,
            tx_count: summary.tx_count,
            serialized_size: summary.serialized_size,
            coinbase_tx_detected: summary.coinbase_tx_detected,
        }
    }
}

impl From<peer::BlockDownloadSummary> for BlockDownloadResponse {
    fn from(summary: peer::BlockDownloadSummary) -> Self {
        Self {
            hash: summary.hash,
            output_path: summary.output_path,
            raw_bytes: summary.raw_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_block_height_progress_response_maps_shared_progress() {
        let response = LastBlockHeightProgressResponse::from_progress(
            "op-1",
            peer::LastBlockHeightProgress {
                node: "seed.bitcoin.sipa.be:8333".to_owned(),
                phase: peer::LastBlockHeightPhase::RequestingHeaders,
                rounds_completed: 3,
                headers_seen: 4000,
                last_batch_count: 2000,
                best_block_hash: Some("abc123".to_owned()),
                elapsed_ms: 1500,
            },
        );

        assert_eq!(response.operation_id, "op-1");
        assert_eq!(
            response.phase,
            LastBlockHeightProgressPhaseResponse::RequestingHeaders
        );
        assert_eq!(response.rounds_completed, 3);
        assert_eq!(response.headers_seen, 4000);
        assert_eq!(response.last_batch_count, 2000);
        assert_eq!(response.best_block_hash.as_deref(), Some("abc123"));
        assert_eq!(response.elapsed_ms, 1500);
    }
}
