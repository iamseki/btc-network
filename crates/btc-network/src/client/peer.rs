use rand::Rng;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::session::Session;
use crate::wire::message::{AddrV2Addr, Block, Decode, VersionMessage};
use crate::wire::{self, Command, Message};

/// App-facing summary of the peer metadata collected during the Bitcoin handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeSummary {
    pub node: String,
    pub protocol_version: i32,
    pub services: String,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: Option<bool>,
}

/// App-facing summary of the peer's current best-known block height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastBlockHeightSummary {
    pub node: String,
    pub height: usize,
    pub rounds: usize,
    pub elapsed_ms: u64,
    pub best_block_hash: Option<String>,
}

/// App-facing progress snapshot for the best-known block height workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastBlockHeightProgress {
    pub node: String,
    pub phase: LastBlockHeightPhase,
    pub rounds_completed: usize,
    pub headers_seen: usize,
    pub last_batch_count: usize,
    pub best_block_hash: Option<String>,
    pub elapsed_ms: u64,
}

/// High-level phase for block-height discovery progress updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastBlockHeightPhase {
    Connecting,
    Handshaking,
    RequestingHeaders,
    Completed,
}

/// App-facing summary of a ping roundtrip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingSummary {
    pub node: String,
    pub nonce: u64,
    pub echoed_nonce: u64,
}

/// App-facing peer address entry returned by `getaddr`/`addrv2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddressSummary {
    pub address: String,
    pub port: u16,
    pub network: String,
}

/// App-facing summary of peer address discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddressesSummary {
    pub node: String,
    pub addresses: Vec<PeerAddressSummary>,
}

/// App-facing summary of a fetched block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    pub hash: String,
    pub tx_count: u64,
    pub serialized_size: usize,
    pub coinbase_tx_detected: bool,
}

/// App-facing summary of a raw block download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDownloadSummary {
    pub hash: String,
    pub output_path: String,
    pub raw_bytes: usize,
}

/// Connects to a node, performs the handshake, and derives the current best block height.
pub fn get_last_block_height_node(node: &str) -> Result<LastBlockHeightSummary, Box<dyn Error>> {
    get_last_block_height_node_with_progress(node, |_| {})
}

/// Connects to a node, performs the handshake, and derives the current best block height while
/// reporting progress snapshots at major workflow boundaries.
pub fn get_last_block_height_node_with_progress<F>(
    node: &str,
    mut report: F,
) -> Result<LastBlockHeightSummary, Box<dyn Error>>
where
    F: FnMut(LastBlockHeightProgress),
{
    let start = Instant::now();
    report(LastBlockHeightProgress {
        node: node.to_owned(),
        phase: LastBlockHeightPhase::Connecting,
        rounds_completed: 0,
        headers_seen: 0,
        last_batch_count: 0,
        best_block_hash: None,
        elapsed_ms: 0,
    });

    let mut session = connect(node, Duration::from_secs(30))?;

    report(LastBlockHeightProgress {
        node: node.to_owned(),
        phase: LastBlockHeightPhase::Handshaking,
        rounds_completed: 0,
        headers_seen: 0,
        last_batch_count: 0,
        best_block_hash: None,
        elapsed_ms: start.elapsed().as_millis() as u64,
    });

    let _ = handshake_session(node, &mut session)?;
    get_last_block_height_session_with_progress(node, &mut session, start, report)
}

/// Reuses an existing session to derive the current best block height from the headers chain.
///
/// Sends `getheaders` repeatedly, advancing the locator to the last received
/// header hash each round. Stops when the peer returns fewer than 2000 headers.
pub fn get_last_block_height_session(
    node: &str,
    session: &mut Session,
) -> Result<LastBlockHeightSummary, Box<dyn Error>> {
    get_last_block_height_session_with_progress(node, session, Instant::now(), |_| {})
}

/// Reuses an existing session to derive the current best block height from the headers chain while
/// reporting progress snapshots after each `headers` batch.
pub fn get_last_block_height_session_with_progress<F>(
    node: &str,
    session: &mut Session,
    start: Instant,
    mut report: F,
) -> Result<LastBlockHeightSummary, Box<dyn Error>>
where
    F: FnMut(LastBlockHeightProgress),
{
    let mut round = 0usize;
    let mut total_headers = 0usize;
    let mut current_locator = wire::constants::GENESIS_BLOCK_HASH_MAINNET;
    let mut best_block_hash: Option<String> = None;

    loop {
        round += 1;

        let payload = wire::build_getheaders_payload(&[current_locator]);
        session.send(Command::GetHeaders, &payload)?;

        let headers = session.recv_until(|msg, session| match msg {
            Message::Headers(h) => Ok(Some(h)),
            Message::Ping(payload) => {
                session.send(Command::Pong, &payload)?;
                Ok(None)
            }
            _ => Ok(None),
        })?;

        let count = headers.len();
        if count == 0 {
            break;
        }

        total_headers += count;

        let last = headers.last().expect("headers not empty");
        let mut last_hash = last.hash();
        last_hash.reverse();
        best_block_hash = Some(hex::encode(last_hash));

        report(LastBlockHeightProgress {
            node: node.to_owned(),
            phase: LastBlockHeightPhase::RequestingHeaders,
            rounds_completed: round,
            headers_seen: total_headers,
            last_batch_count: count,
            best_block_hash: best_block_hash.clone(),
            elapsed_ms: start.elapsed().as_millis() as u64,
        });

        if count < 2000 {
            break;
        }

        current_locator = last.hash();
    }

    let summary = LastBlockHeightSummary {
        node: node.to_owned(),
        height: total_headers,
        rounds: round,
        elapsed_ms: start.elapsed().as_millis() as u64,
        best_block_hash,
    };

    report(LastBlockHeightProgress {
        node: node.to_owned(),
        phase: LastBlockHeightPhase::Completed,
        rounds_completed: summary.rounds,
        headers_seen: summary.height,
        last_batch_count: 0,
        best_block_hash: summary.best_block_hash.clone(),
        elapsed_ms: summary.elapsed_ms,
    });

    Ok(summary)
}

/// Connects to a node and completes the Bitcoin handshake.
pub fn handshake_node(node: &str) -> Result<HandshakeSummary, Box<dyn Error>> {
    let mut session = connect(node, Duration::from_secs(30))?;
    handshake_session(node, &mut session)
}

/// Connects to a node, performs the handshake, and validates a ping/pong exchange.
pub fn ping_node(node: &str) -> Result<PingSummary, Box<dyn Error>> {
    let mut session = connect(node, Duration::from_secs(30))?;
    let _ = handshake_session(node, &mut session)?;
    ping_session(node, &mut session)
}

/// Connects to a node, performs the handshake, and requests peer addresses.
pub fn get_peer_addresses_node(node: &str) -> Result<PeerAddressesSummary, Box<dyn Error>> {
    let mut session = connect(node, Duration::from_secs(30))?;
    let _ = handshake_session(node, &mut session)?;
    get_peer_addresses_session(node, &mut session)
}

/// Reuses an existing session to request peer addresses.
pub fn get_peer_addresses_session(
    node: &str,
    session: &mut Session,
) -> Result<PeerAddressesSummary, Box<dyn Error>> {
    session.send(Command::GetAddr, &[])?;

    let addresses = session.recv_until(|msg, session| match msg {
        Message::AddrV2(entries) => Ok(Some(
            entries
                .into_iter()
                .map(|entry| PeerAddressSummary {
                    address: format_addrv2(&entry.addr),
                    port: entry.port,
                    network: addrv2_network(&entry.addr).to_owned(),
                })
                .collect::<Vec<_>>(),
        )),
        Message::Addr(entries) => Ok(Some(
            entries
                .into_iter()
                .map(|entry| PeerAddressSummary {
                    address: display_ip(entry.addr.ip),
                    port: entry.addr.port,
                    network: ip_network(entry.addr.ip).to_owned(),
                })
                .collect::<Vec<_>>(),
        )),
        Message::Ping(payload) => {
            session.send(Command::Pong, &payload)?;
            Ok(None)
        }
        _ => Ok(None),
    })?;

    Ok(PeerAddressesSummary {
        node: node.to_owned(),
        addresses,
    })
}

/// Connects to a node, performs the handshake, and fetches a decoded block summary.
pub fn get_block_summary_node(node: &str, hash_hex: &str) -> Result<BlockSummary, Box<dyn Error>> {
    let mut session = connect(node, Duration::from_secs(30))?;
    let _ = handshake_session(node, &mut session)?;
    get_block_summary_session(&mut session, hash_hex)
}

/// Reuses an existing session to fetch a decoded block summary.
pub fn get_block_summary_session(
    session: &mut Session,
    hash_hex: &str,
) -> Result<BlockSummary, Box<dyn Error>> {
    let requested_hash = parse_requested_block_hash(hash_hex)?;
    let payload = wire::build_getdata_block_payload(requested_hash);
    session.send(Command::GetData, &payload)?;

    loop {
        let msg = session.recv()?;
        match msg {
            Message::Ping(payload) => {
                session.send(Command::Pong, &payload)?;
            }
            Message::Block(block) => {
                let got_hash = block.header.hash();
                if got_hash != requested_hash {
                    continue;
                }

                let mut display_hash = got_hash;
                display_hash.reverse();

                return Ok(BlockSummary {
                    hash: hex::encode(display_hash),
                    tx_count: block.tx_count,
                    serialized_size: block.serialized_size,
                    coinbase_tx_detected: block
                        .transactions
                        .first()
                        .map(|tx| tx.is_coinbase())
                        .unwrap_or(false),
                });
            }
            _ => {}
        }
    }
}

/// Connects to a node, performs the handshake, and downloads a raw block record.
pub fn download_block_node(
    node: &str,
    hash_hex: &str,
    out: Option<&str>,
) -> Result<BlockDownloadSummary, Box<dyn Error>> {
    let mut session = connect(node, Duration::from_secs(30))?;
    let _ = handshake_session(node, &mut session)?;
    download_block_session(&mut session, hash_hex, out)
}

/// Reuses an existing session to download a raw block record.
pub fn download_block_session(
    session: &mut Session,
    hash_hex: &str,
    out: Option<&str>,
) -> Result<BlockDownloadSummary, Box<dyn Error>> {
    let requested_hash = parse_requested_block_hash(hash_hex)?;
    let payload = wire::build_getdata_block_payload(requested_hash);
    session.send(Command::GetData, &payload)?;

    let output_path = out
        .map(str::to_owned)
        .unwrap_or_else(|| default_block_filename(hash_hex));

    loop {
        let raw = session.recv_raw()?;
        match raw.command {
            Command::Ping => {
                session.send(Command::Pong, &raw.payload)?;
            }
            Command::Block => {
                let block = Block::decode(&raw.payload)?;
                let got_hash = block.header.hash();
                if got_hash != requested_hash {
                    continue;
                }

                write_blk_record(&output_path, &raw.payload)?;
                let mut display_hash = got_hash;
                display_hash.reverse();

                return Ok(BlockDownloadSummary {
                    hash: hex::encode(display_hash),
                    output_path,
                    raw_bytes: raw.payload.len(),
                });
            }
            _ => {}
        }
    }
}

/// Reuses an existing session to complete the handshake and map the peer version into
/// a UI-friendly summary.
pub fn handshake_session(
    node: &str,
    session: &mut Session,
) -> Result<HandshakeSummary, Box<dyn Error>> {
    let version = session.handshake()?;
    Ok(map_handshake(node, version))
}

/// Reuses an existing session to perform a ping roundtrip.
pub fn ping_session(node: &str, session: &mut Session) -> Result<PingSummary, Box<dyn Error>> {
    let nonce: u64 = rand::thread_rng().r#gen();
    let echoed_nonce = session.ping(nonce)?;
    Ok(PingSummary {
        node: node.to_owned(),
        nonce,
        echoed_nonce,
    })
}

fn connect(node: &str, timeout: Duration) -> Result<Session, Box<dyn Error>> {
    let addr = node
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve address")?;

    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    Ok(Session::new(stream))
}

fn map_handshake(node: &str, version: VersionMessage) -> HandshakeSummary {
    HandshakeSummary {
        node: node.to_owned(),
        protocol_version: version.version,
        services: format!("{:#018x}", version.services.bits()),
        user_agent: version.user_agent,
        start_height: version.start_height,
        relay: version.relay,
    }
}

fn addrv2_network(addr: &AddrV2Addr) -> &'static str {
    match addr {
        AddrV2Addr::IPv4(_) => "ipv4",
        AddrV2Addr::IPv6(_) => "ipv6",
        AddrV2Addr::TorV2(_) => "torv2",
        AddrV2Addr::TorV3(_) => "torv3",
        AddrV2Addr::I2P(_) => "i2p",
        AddrV2Addr::Cjdns(_) => "cjdns",
        AddrV2Addr::Yggdrasil(_) => "unknown",
        AddrV2Addr::Unknown { .. } => "unknown",
    }
}

fn format_addrv2(addr: &AddrV2Addr) -> String {
    match addr {
        AddrV2Addr::IPv4(ip) => ip.to_string(),
        AddrV2Addr::IPv6(ip) => ip.to_string(),
        AddrV2Addr::TorV2(bytes) => hex::encode(bytes),
        AddrV2Addr::TorV3(bytes) => hex::encode(bytes),
        AddrV2Addr::I2P(bytes) => hex::encode(bytes),
        AddrV2Addr::Cjdns(ip) => ip.to_string(),
        AddrV2Addr::Yggdrasil(ip) => ip.to_string(),
        AddrV2Addr::Unknown { bytes, .. } => hex::encode(bytes),
    }
}

fn display_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(|| ip.to_string(), |ip| ip.to_string()),
    }
}

fn ip_network(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(ip) => {
            if ip.to_ipv4_mapped().is_some() {
                "ipv4"
            } else {
                "ipv6"
            }
        }
    }
}

fn parse_requested_block_hash(hash_hex: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let mut hash = hex::decode(hash_hex)?;
    if hash.len() != 32 {
        return Err("block hash must be 32 bytes (64 hex chars)".into());
    }
    hash.reverse();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);
    Ok(arr)
}

fn default_block_filename(hash_hex: &str) -> String {
    let first8 = &hash_hex[..8];
    let last6 = &hash_hex[hash_hex.len() - 6..];
    format!("blk-{}-{}.dat", first8, last6)
}

fn write_blk_record(path: &str, raw_block: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(path)?;
    file.write_all(&wire::constants::MAIN_NET_MAGIC.to_le_bytes())?;
    file.write_all(&(raw_block.len() as u32).to_le_bytes())?;
    file.write_all(raw_block)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Command, build_version_payload, read_message, send_message};
    use std::fs;
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::error;

    fn bind_listener_or_skip() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                error!("skipping peer client socket test: {err}");
                None
            }
            Err(err) => panic!("bind listener failed: {err}"),
        }
    }

    fn addr_payload_two_entries() -> Vec<u8> {
        fn net_addr_bytes(services: u64, ip: [u8; 4], port: u16) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&services.to_le_bytes());
            b.extend_from_slice(&[0u8; 10]);
            b.extend_from_slice(&[0xFF, 0xFF]);
            b.extend_from_slice(&ip);
            b.extend_from_slice(&port.to_be_bytes());
            b
        }

        let mut payload = vec![2];
        payload.extend_from_slice(&1700000100u32.to_le_bytes());
        payload.extend(net_addr_bytes(1, [1, 2, 3, 4], 8333));
        payload.extend_from_slice(&1700000200u32.to_le_bytes());
        payload.extend(net_addr_bytes(1, [5, 6, 7, 8], 8334));
        payload
    }

    fn sample_block_header(nonce: u32) -> crate::wire::message::BlockHeader {
        crate::wire::message::BlockHeader {
            version: 1,
            prev_blockhash: [0x11; 32],
            merkle_root: [0x22; 32],
            time: 1234567890,
            bits: 0x1d00ffff,
            nonce,
        }
    }

    fn header_bytes(header: &crate::wire::message::BlockHeader) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&header.version.to_le_bytes());
        bytes.extend_from_slice(&header.prev_blockhash);
        bytes.extend_from_slice(&header.merkle_root);
        bytes.extend_from_slice(&header.time.to_le_bytes());
        bytes.extend_from_slice(&header.bits.to_le_bytes());
        bytes.extend_from_slice(&header.nonce.to_le_bytes());
        bytes
    }

    fn headers_payload(headers: &[crate::wire::message::BlockHeader]) -> Vec<u8> {
        let mut payload = vec![headers.len() as u8];
        for header in headers {
            payload.extend(header_bytes(header));
            payload.push(0);
        }
        payload
    }

    fn minimal_legacy_tx() -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend(&1i32.to_le_bytes());
        tx.push(1);
        tx.extend([0u8; 32]);
        tx.extend(&0xffffffffu32.to_le_bytes());
        tx.push(0);
        tx.extend(&0xffffffffu32.to_le_bytes());
        tx.push(1);
        tx.extend(&50_0000_0000u64.to_le_bytes());
        tx.push(0);
        tx.extend(&0u32.to_le_bytes());
        tx
    }

    fn minimal_block_payload(header: &crate::wire::message::BlockHeader) -> Vec<u8> {
        let mut payload = header_bytes(header);
        payload.push(1);
        payload.extend(minimal_legacy_tx());
        payload
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "btc-network-{name}-{}-{nanos}.dat",
            std::process::id()
        ))
    }

    #[test]
    fn handshake_session_maps_peer_version_into_summary() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let peer_version =
                build_version_payload(crate::wire::constants::PROTOCOL_VERSION, 0x08)
                    .expect("build version");
            send_message(&mut peer, Command::Version, &peer_version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);

            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);

            send_message(&mut peer, Command::Verack, &[]).expect("send verack");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let summary =
            handshake_session(&addr.to_string(), &mut session).expect("handshake session");

        assert_eq!(summary.node, addr.to_string());
        assert_eq!(
            summary.protocol_version,
            crate::wire::constants::PROTOCOL_VERSION
        );
        assert_eq!(summary.services, "0x0000000000000008");

        server.join().expect("join");
    }

    #[test]
    fn ping_session_returns_echoed_nonce() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let peer_version = build_version_payload(crate::wire::constants::PROTOCOL_VERSION, 0)
                .expect("build version");
            send_message(&mut peer, Command::Version, &peer_version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);

            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);

            send_message(&mut peer, Command::Verack, &[]).expect("send verack");

            let ping = read_message(&mut peer).expect("read ping");
            assert_eq!(ping.command, Command::Ping);
            send_message(&mut peer, Command::Pong, &ping.payload).expect("send pong");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let _ = handshake_session(&addr.to_string(), &mut session).expect("handshake");
        let echoed_nonce = session.ping(0xAABBCCDDEEFF0011).expect("session ping");
        let summary = PingSummary {
            node: addr.to_string(),
            nonce: 0xAABBCCDDEEFF0011,
            echoed_nonce,
        };

        assert_eq!(summary.node, addr.to_string());
        assert_eq!(summary.nonce, 0xAABBCCDDEEFF0011);
        assert_eq!(summary.echoed_nonce, 0xAABBCCDDEEFF0011);

        server.join().expect("join");
    }

    #[test]
    fn get_peer_addresses_session_maps_legacy_addr_entries() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let request = read_message(&mut peer).expect("read getaddr");
            assert_eq!(request.command, Command::GetAddr);

            send_message(&mut peer, Command::Addr, &addr_payload_two_entries())
                .expect("send addr");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let summary =
            get_peer_addresses_session(&addr.to_string(), &mut session).expect("get peer addr");

        assert_eq!(summary.node, addr.to_string());
        assert_eq!(
            summary.addresses,
            vec![
                PeerAddressSummary {
                    address: "1.2.3.4".to_owned(),
                    port: 8333,
                    network: "ipv4".to_owned(),
                },
                PeerAddressSummary {
                    address: "5.6.7.8".to_owned(),
                    port: 8334,
                    network: "ipv4".to_owned(),
                },
            ]
        );

        server.join().expect("join");
    }

    #[test]
    fn get_last_block_height_session_maps_headers_summary() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");
        let headers = vec![sample_block_header(42), sample_block_header(84)];
        let mut expected_hash = headers.last().expect("last header").hash();
        expected_hash.reverse();
        let expected_hash = hex::encode(expected_hash);

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let request = read_message(&mut peer).expect("read getheaders");
            assert_eq!(request.command, Command::GetHeaders);

            send_message(&mut peer, Command::Headers, &headers_payload(&headers))
                .expect("send headers");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let summary =
            get_last_block_height_session(&addr.to_string(), &mut session).expect("height");

        assert_eq!(summary.node, addr.to_string());
        assert_eq!(summary.height, 2);
        assert_eq!(summary.rounds, 1);
        assert_eq!(summary.best_block_hash.as_deref(), Some(expected_hash.as_str()));

        server.join().expect("join");
    }

    #[test]
    fn get_last_block_height_session_reports_progress_per_headers_batch() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");
        let first_batch = vec![sample_block_header(42); 2000];
        let second_batch = vec![sample_block_header(84), sample_block_header(126)];
        let mut expected_hash = second_batch.last().expect("last header").hash();
        expected_hash.reverse();
        let expected_hash = hex::encode(expected_hash);

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let first_request = read_message(&mut peer).expect("read first getheaders");
            assert_eq!(first_request.command, Command::GetHeaders);
            send_message(&mut peer, Command::Headers, &headers_payload(&first_batch))
                .expect("send first headers");

            let second_request = read_message(&mut peer).expect("read second getheaders");
            assert_eq!(second_request.command, Command::GetHeaders);
            send_message(&mut peer, Command::Headers, &headers_payload(&second_batch))
                .expect("send second headers");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let mut progress = Vec::new();
        let summary = get_last_block_height_session_with_progress(
            &addr.to_string(),
            &mut session,
            Instant::now(),
            |update| progress.push(update),
        )
        .expect("height");

        assert_eq!(summary.height, 2002);
        assert_eq!(summary.rounds, 2);
        assert_eq!(summary.best_block_hash.as_deref(), Some(expected_hash.as_str()));
        assert_eq!(progress.len(), 3);
        assert_eq!(progress[0].phase, LastBlockHeightPhase::RequestingHeaders);
        assert_eq!(progress[0].rounds_completed, 1);
        assert_eq!(progress[0].headers_seen, 2000);
        assert_eq!(progress[0].last_batch_count, 2000);
        assert_eq!(progress[1].phase, LastBlockHeightPhase::RequestingHeaders);
        assert_eq!(progress[1].rounds_completed, 2);
        assert_eq!(progress[1].headers_seen, 2002);
        assert_eq!(progress[1].last_batch_count, 2);
        assert_eq!(progress[1].best_block_hash.as_deref(), Some(expected_hash.as_str()));
        assert_eq!(progress[2].phase, LastBlockHeightPhase::Completed);
        assert_eq!(progress[2].headers_seen, 2002);

        server.join().expect("join");
    }

    #[test]
    fn get_block_summary_session_returns_matching_block_summary() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");
        let header = sample_block_header(126);
        let payload = minimal_block_payload(&header);
        let server_payload = payload.clone();
        let mut requested_hash = header.hash();
        requested_hash.reverse();
        let requested_hash_hex = hex::encode(requested_hash);

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let request = read_message(&mut peer).expect("read getdata");
            assert_eq!(request.command, Command::GetData);

            send_message(&mut peer, Command::Block, &server_payload).expect("send block");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let summary =
            get_block_summary_session(&mut session, &requested_hash_hex).expect("block summary");

        assert_eq!(summary.hash, requested_hash_hex);
        assert_eq!(summary.tx_count, 1);
        assert_eq!(summary.serialized_size, payload.len());
        assert!(summary.coinbase_tx_detected);

        server.join().expect("join");
    }

    #[test]
    fn download_block_session_writes_blk_record_for_matching_block() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");
        let header = sample_block_header(168);
        let payload = minimal_block_payload(&header);
        let server_payload = payload.clone();
        let mut requested_hash = header.hash();
        requested_hash.reverse();
        let requested_hash_hex = hex::encode(requested_hash);
        let output_path = unique_temp_path("download-block");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let request = read_message(&mut peer).expect("read getdata");
            assert_eq!(request.command, Command::GetData);

            send_message(&mut peer, Command::Block, &server_payload).expect("send block");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let summary = download_block_session(
            &mut session,
            &requested_hash_hex,
            Some(output_path.to_str().expect("utf8 path")),
        )
        .expect("download block");

        assert_eq!(summary.hash, requested_hash_hex);
        assert_eq!(summary.output_path, output_path.to_string_lossy());
        assert_eq!(summary.raw_bytes, payload.len());

        let written = fs::read(&output_path).expect("read blk record");
        assert_eq!(&written[..4], &wire::constants::MAIN_NET_MAGIC.to_le_bytes());
        assert_eq!(
            &written[4..8],
            &(payload.len() as u32).to_le_bytes()
        );
        assert_eq!(&written[8..], payload.as_slice());

        fs::remove_file(&output_path).expect("cleanup blk record");
        server.join().expect("join");
    }

    #[test]
    fn parse_requested_block_hash_rejects_non_32_byte_hashes() {
        let err = parse_requested_block_hash("abcd").expect_err("short hash should fail");
        assert_eq!(err.to_string(), "block hash must be 32 bytes (64 hex chars)");
    }

    #[test]
    fn display_ip_normalizes_ipv4_mapped_ipv6_addresses() {
        let mapped = "::ffff:1.2.3.4".parse::<IpAddr>().expect("parse mapped ip");

        assert_eq!(display_ip(mapped), "1.2.3.4");
        assert_eq!(ip_network(mapped), "ipv4");
    }
}
