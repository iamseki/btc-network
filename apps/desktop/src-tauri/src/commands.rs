use btc_network::client::peer;
use serde::{Deserialize, Serialize};
use tauri::Emitter;

const CHAIN_HEIGHT_PROGRESS_EVENT: &str = "chain-height-progress";

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
    pub phase: String,
    pub rounds_completed: usize,
    pub headers_seen: usize,
    pub last_batch_count: usize,
    pub best_block_hash: Option<String>,
    pub elapsed_ms: u64,
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

#[derive(Debug, Deserialize)]
pub struct BlockRequest {
    pub node: String,
    pub hash: String,
}

async fn run_blocking<T, F>(task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|err| err.to_string())?
}

async fn run_get_last_block_height<E>(
    request: ProgressConnectionRequest,
    emit_progress: E,
) -> Result<LastBlockHeightResponse, String>
where
    E: Fn(LastBlockHeightProgressResponse) + Send + 'static,
{
    let summary = run_blocking(move || {
        let operation_id = request.operation_id.clone();
        peer::get_last_block_height_node_with_progress(&request.node, |progress| {
            emit_progress(LastBlockHeightProgressResponse::from_progress(
                &operation_id,
                progress,
            ));
        })
        .map_err(|err| err.to_string())
    })
    .await?;

    Ok(summary.into())
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
    fn from_progress(operation_id: &str, progress: peer::LastBlockHeightProgress) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            node: progress.node,
            phase: match progress.phase {
                peer::LastBlockHeightPhase::Connecting => "connecting",
                peer::LastBlockHeightPhase::Handshaking => "handshaking",
                peer::LastBlockHeightPhase::RequestingHeaders => "requesting_headers",
                peer::LastBlockHeightPhase::Completed => "completed",
            }
            .to_owned(),
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

#[tauri::command]
pub async fn handshake(request: ConnectionRequest) -> Result<HandshakeResponse, String> {
    let summary = run_blocking(move || {
        peer::handshake_node(&request.node).map_err(|err| err.to_string())
    })
    .await?;

    Ok(summary.into())
}

/// Runs the shared Rust ping workflow through the desktop command boundary.
#[tauri::command]
pub async fn ping(request: ConnectionRequest) -> Result<PingResponse, String> {
    let summary = run_blocking(move || {
        peer::ping_node(&request.node).map_err(|err| err.to_string())
    })
    .await?;

    Ok(summary.into())
}

#[tauri::command]
pub async fn get_last_block_height(
    app: tauri::AppHandle,
    request: ProgressConnectionRequest,
) -> Result<LastBlockHeightResponse, String> {
    run_get_last_block_height(request, move |payload| {
        let _ = app.emit(CHAIN_HEIGHT_PROGRESS_EVENT, payload);
    })
    .await
}

#[tauri::command]
pub async fn get_peer_addresses(
    request: ConnectionRequest,
) -> Result<PeerAddressesResponse, String> {
    let summary = run_blocking(move || {
        peer::get_peer_addresses_node(&request.node).map_err(|err| err.to_string())
    })
    .await?;

    Ok(summary.into())
}

#[tauri::command]
pub async fn get_block_summary(request: BlockRequest) -> Result<BlockSummaryResponse, String> {
    let summary = run_blocking(move || {
        peer::get_block_summary_node(&request.node, &request.hash).map_err(|err| err.to_string())
    })
    .await?;

    Ok(summary.into())
}

#[tauri::command]
pub async fn download_block(request: BlockRequest) -> Result<BlockDownloadResponse, String> {
    let summary = run_blocking(move || {
        peer::download_block_node(&request.node, &request.hash, None).map_err(|err| err.to_string())
    })
    .await?;

    Ok(summary.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_network::wire::message::{Block, BlockHeader, Decode};
    use btc_network::wire::{Command, build_version_payload, read_message, send_message};
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::thread;

    fn bind_listener_or_skip() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping desktop command socket test: {err}");
                None
            }
            Err(err) => panic!("bind listener failed: {err}"),
        }
    }

    fn encode_single_headers_message(header: &BlockHeader) -> Vec<u8> {
        let mut payload = Vec::with_capacity(82);
        payload.push(1);
        payload.extend_from_slice(&header.version.to_le_bytes());
        payload.extend_from_slice(&header.prev_blockhash);
        payload.extend_from_slice(&header.merkle_root);
        payload.extend_from_slice(&header.time.to_le_bytes());
        payload.extend_from_slice(&header.bits.to_le_bytes());
        payload.extend_from_slice(&header.nonce.to_le_bytes());
        payload.push(0);
        payload
    }

    fn encode_addrv2_ipv4(address: [u8; 4], port: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(1); // one entry
        payload.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        payload.push(1); // services varint
        payload.push(0x01); // IPv4
        payload.push(4); // addr len
        payload.extend_from_slice(&address);
        payload.extend_from_slice(&port.to_be_bytes());
        payload
    }

    fn sample_header_bytes() -> [u8; 80] {
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&1i32.to_le_bytes());
        header[4..36].copy_from_slice(&[0x11; 32]);
        header[36..68].copy_from_slice(&[0x22; 32]);
        header[68..72].copy_from_slice(&1234567890u32.to_le_bytes());
        header[72..76].copy_from_slice(&0x1d00ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&42u32.to_le_bytes());
        header
    }

    fn minimal_legacy_tx() -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend(&1i32.to_le_bytes());
        tx.push(1);
        tx.extend([0u8; 32]);
        tx.extend(&0xffff_ffffu32.to_le_bytes());
        tx.push(0);
        tx.extend(&0xffff_ffffu32.to_le_bytes());
        tx.push(1);
        tx.extend(&50_0000_0000u64.to_le_bytes());
        tx.push(0);
        tx.extend(&0u32.to_le_bytes());
        tx
    }

    fn minimal_block_payload() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend(sample_header_bytes());
        payload.push(1);
        payload.extend(minimal_legacy_tx());
        payload
    }

    fn sample_block_hash_hex() -> String {
        let block = Block::decode(&minimal_block_payload()).expect("decode sample block");
        let mut hash = block.header.hash();
        hash.reverse();
        hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn handshake_command_maps_shared_result() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let version =
                build_version_payload(btc_network::wire::constants::PROTOCOL_VERSION, 0x08)
                    .expect("version");
            send_message(&mut peer, Command::Version, &version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");
        });

        let result = tauri::async_runtime::block_on(handshake(ConnectionRequest {
            node: addr.to_string(),
        }))
        .expect("handshake command");

        assert_eq!(result.node, addr.to_string());
        assert_eq!(
            result.protocol_version,
            btc_network::wire::constants::PROTOCOL_VERSION
        );
        assert_eq!(result.services, "0x0000000000000008");

        server.join().expect("join");
    }

    #[test]
    fn ping_command_returns_hex_nonce_fields() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let version = build_version_payload(btc_network::wire::constants::PROTOCOL_VERSION, 0)
                .expect("version");
            send_message(&mut peer, Command::Version, &version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");

            let ping = read_message(&mut peer).expect("read ping");
            assert_eq!(ping.command, Command::Ping);
            send_message(&mut peer, Command::Pong, &ping.payload).expect("send pong");
        });

        let result = tauri::async_runtime::block_on(ping(ConnectionRequest {
            node: addr.to_string(),
        }))
        .expect("ping command");

        assert_eq!(result.node, addr.to_string());
        assert!(result.nonce.starts_with("0x"));
        assert_eq!(result.nonce, result.echoed_nonce);

        server.join().expect("join");
    }

    #[test]
    fn get_last_block_height_command_maps_last_block_height() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let version = build_version_payload(btc_network::wire::constants::PROTOCOL_VERSION, 0)
                .expect("version");
            send_message(&mut peer, Command::Version, &version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");

            let getheaders = read_message(&mut peer).expect("read getheaders");
            assert_eq!(getheaders.command, Command::GetHeaders);

            let header = BlockHeader {
                version: 1,
                prev_blockhash: [0u8; 32],
                merkle_root: [0x11; 32],
                time: 1_700_000_000,
                bits: 0x1d00ffff,
                nonce: 42,
            };
            let payload = encode_single_headers_message(&header);
            send_message(&mut peer, Command::Headers, &payload).expect("send headers");
        });

        let progress_events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_events = progress_events.clone();
        let result = tauri::async_runtime::block_on(run_get_last_block_height(
            ProgressConnectionRequest {
                node: addr.to_string(),
                operation_id: "test-op".to_owned(),
            },
            move |payload| captured_events.lock().expect("lock progress").push(payload),
        ))
        .expect("last block height command");

        assert_eq!(result.node, addr.to_string());
        assert_eq!(result.height, 1);
        assert_eq!(result.rounds, 1);
        assert!(result.elapsed_ms > 0);
        assert!(result.best_block_hash.is_some());
        assert_eq!(
            progress_events
                .lock()
                .expect("lock progress")
                .iter()
                .map(|event| event.phase.as_str())
                .collect::<Vec<_>>(),
            vec!["connecting", "handshaking", "requesting_headers", "completed"]
        );

        server.join().expect("join");
    }

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
        assert_eq!(response.phase, "requesting_headers");
        assert_eq!(response.rounds_completed, 3);
        assert_eq!(response.headers_seen, 4000);
        assert_eq!(response.last_batch_count, 2000);
        assert_eq!(response.best_block_hash.as_deref(), Some("abc123"));
        assert_eq!(response.elapsed_ms, 1500);
    }

    #[test]
    fn get_peer_addresses_command_maps_addrv2_entries() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let version = build_version_payload(btc_network::wire::constants::PROTOCOL_VERSION, 0)
                .expect("version");
            send_message(&mut peer, Command::Version, &version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");

            let getaddr = read_message(&mut peer).expect("read getaddr");
            assert_eq!(getaddr.command, Command::GetAddr);
            send_message(&mut peer, Command::AddrV2, &encode_addrv2_ipv4([127, 0, 0, 1], 8333))
                .expect("send addrv2");
        });

        let result = tauri::async_runtime::block_on(get_peer_addresses(ConnectionRequest {
            node: addr.to_string(),
        }))
        .expect("get peer addresses command");

        assert_eq!(result.node, addr.to_string());
        assert_eq!(result.addresses.len(), 1);
        assert_eq!(result.addresses[0].address, "127.0.0.1");
        assert_eq!(result.addresses[0].port, 8333);
        assert_eq!(result.addresses[0].network, "ipv4");

        server.join().expect("join");
    }

    #[test]
    fn get_block_summary_command_maps_decoded_block() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");
        let requested_hash = sample_block_hash_hex();

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let version = build_version_payload(btc_network::wire::constants::PROTOCOL_VERSION, 0)
                .expect("version");
            send_message(&mut peer, Command::Version, &version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");

            let getdata = read_message(&mut peer).expect("read getdata");
            assert_eq!(getdata.command, Command::GetData);
            send_message(&mut peer, Command::Block, &minimal_block_payload()).expect("send block");
        });

        let result = tauri::async_runtime::block_on(get_block_summary(BlockRequest {
            node: addr.to_string(),
            hash: requested_hash.clone(),
        }))
        .expect("get block summary command");

        assert_eq!(result.hash, requested_hash);
        assert_eq!(result.tx_count, 1);
        assert_eq!(result.serialized_size, minimal_block_payload().len());
        assert!(result.coinbase_tx_detected);

        server.join().expect("join");
    }

    #[test]
    fn download_block_command_writes_blk_record() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");
        let requested_hash = sample_block_hash_hex();
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let version = build_version_payload(btc_network::wire::constants::PROTOCOL_VERSION, 0)
                .expect("version");
            send_message(&mut peer, Command::Version, &version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");

            let getdata = read_message(&mut peer).expect("read getdata");
            assert_eq!(getdata.command, Command::GetData);
            send_message(&mut peer, Command::Block, &minimal_block_payload()).expect("send block");
        });

        let result = tauri::async_runtime::block_on(download_block(BlockRequest {
            node: addr.to_string(),
            hash: requested_hash.clone(),
        }))
        .expect("download block command");

        assert_eq!(result.hash, requested_hash);
        assert_eq!(result.raw_bytes, minimal_block_payload().len());
        assert!(result.output_path.ends_with(".dat"));
        assert!(std::path::Path::new(&result.output_path).exists());

        std::fs::remove_file(&result.output_path).expect("remove temp block file");
        server.join().expect("join");
    }
}
