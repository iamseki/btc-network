use crate::session::Session;
use crate::wire;
use crate::wire::message::{AddrV2Addr, VersionMessage};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use super::domain::{CrawlEndpoint, CrawlNetwork, FailureClassification};
use super::types::{CrawlerConfig, NodeState, NodeVisit, NodeVisitFailure, NodeVisitResult};

pub(crate) trait NodeProcessor: Send + Sync {
    fn process(&self, endpoint: CrawlEndpoint, config: CrawlerConfig) -> NodeVisitResult;
}

pub(crate) struct DefaultNodeProcessor;

impl NodeProcessor for DefaultNodeProcessor {
    fn process(&self, endpoint: CrawlEndpoint, config: CrawlerConfig) -> NodeVisitResult {
        process_node(endpoint, config)
    }
}

pub(crate) fn process_node(endpoint: CrawlEndpoint, config: CrawlerConfig) -> NodeVisitResult {
    let total_started = Instant::now();
    let connect_addr = endpoint.socket_addr().ok_or_else(|| {
        Box::new(NodeVisitFailure {
            node: endpoint.clone(),
            latency: total_started.elapsed(),
            classification: FailureClassification::Connect,
            message: format!("endpoint {} is not connectable", endpoint.canonical),
        })
    })?;
    let connect_started = Instant::now();
    let stream = connect_with_retries(&endpoint, connect_addr, config, total_started)?;
    let connect_elapsed = connect_started.elapsed();
    stream
        .set_read_timeout(Some(config.io_timeout))
        .map_err(|e| {
            Box::new(NodeVisitFailure {
                node: endpoint.clone(),
                latency: total_started.elapsed(),
                classification: FailureClassification::Io,
                message: format!("set read timeout: {e}"),
            })
        })?;
    stream
        .set_write_timeout(Some(config.io_timeout))
        .map_err(|e| {
            Box::new(NodeVisitFailure {
                node: endpoint.clone(),
                latency: total_started.elapsed(),
                classification: FailureClassification::Io,
                message: format!("set write timeout: {e}"),
            })
        })?;

    let mut session = Session::new(stream);
    let mut client = SessionNodeClient {
        session: &mut session,
    };

    let handshake_started = Instant::now();
    let version = client.handshake().map_err(|message| {
        Box::new(NodeVisitFailure {
            node: endpoint.clone(),
            latency: total_started.elapsed(),
            classification: FailureClassification::Handshake,
            message,
        })
    })?;
    let handshake_elapsed = handshake_started.elapsed();

    let get_addr_started = Instant::now();
    let discovered = client.get_addresses().map_err(|message| {
        Box::new(NodeVisitFailure {
            node: endpoint.clone(),
            latency: total_started.elapsed(),
            classification: FailureClassification::PeerDiscovery,
            message,
        })
    })?;
    let get_addr_elapsed = get_addr_started.elapsed();

    let visit = NodeVisit {
        node: endpoint.clone(),
        state: NodeState {
            version: version.version,
            services: version.services.bits(),
            user_agent: version.user_agent,
            start_height: version.start_height,
            relay: version.relay,
            timestamp: version.timestamp,
        },
        discovered,
        latency: total_started.elapsed(),
    };

    if config.verbose {
        info!(
            node = %endpoint.canonical,
            connect_ms = connect_elapsed.as_millis(),
            handshake_ms = handshake_elapsed.as_millis(),
            get_addr_ms = get_addr_elapsed.as_millis(),
            discovered_nodes = visit.discovered.len(),
            process_node_total_ms = total_started.elapsed().as_millis(),
            "[crawler] node timing"
        );
    }

    Ok(visit)
}

fn connect_with_retries(
    endpoint: &CrawlEndpoint,
    connect_addr: SocketAddr,
    config: CrawlerConfig,
    total_started: Instant,
) -> Result<TcpStream, Box<NodeVisitFailure>> {
    connect_with_retries_using(
        endpoint,
        connect_addr,
        config,
        total_started,
        || TcpStream::connect_timeout(&connect_addr, config.connect_timeout),
        thread::sleep,
    )
}

fn connect_with_retries_using<T, Connect, Sleep>(
    endpoint: &CrawlEndpoint,
    connect_target: impl ToString,
    config: CrawlerConfig,
    total_started: Instant,
    mut connect: Connect,
    mut sleep: Sleep,
) -> Result<T, Box<NodeVisitFailure>>
where
    Connect: FnMut() -> io::Result<T>,
    Sleep: FnMut(Duration),
{
    let connect_target = connect_target.to_string();
    let max_attempts = config.connect_max_attempts.max(1);
    let mut last_error = None;

    for attempt in 1..=max_attempts {
        match connect() {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                last_error = Some(error);

                if attempt == max_attempts {
                    break;
                }

                let backoff = connect_retry_delay(config.connect_retry_backoff, attempt);
                if config.verbose {
                    info!(
                        node = %endpoint.canonical,
                        attempt,
                        max_attempts,
                        backoff_ms = backoff.as_millis(),
                        "[crawler] connect attempt failed; retrying"
                    );
                }
                if !backoff.is_zero() {
                    sleep(backoff);
                }
            }
        }
    }

    let error = last_error.expect("connect retry loop should capture the last error");
    let message = if max_attempts == 1 {
        format!("connect {connect_target}: {error}")
    } else {
        format!("connect {connect_target} failed after {max_attempts} attempts: {error}")
    };

    Err(Box::new(NodeVisitFailure {
        node: endpoint.clone(),
        latency: total_started.elapsed(),
        classification: FailureClassification::Connect,
        message,
    }))
}

fn connect_retry_delay(base: Duration, retry_number: usize) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }

    let shift = retry_number.saturating_sub(1).min(10);
    let factor = 1u32 << shift;
    base.checked_mul(factor).unwrap_or(Duration::MAX)
}

pub(crate) trait NodeClient {
    fn handshake(&mut self) -> Result<VersionMessage, String>;
    fn get_addresses(&mut self) -> Result<Vec<CrawlEndpoint>, String>;
}

struct SessionNodeClient<'a> {
    session: &'a mut Session,
}

impl NodeClient for SessionNodeClient<'_> {
    fn handshake(&mut self) -> Result<VersionMessage, String> {
        self.session.handshake().map_err(|e| e.to_string())
    }

    fn get_addresses(&mut self) -> Result<Vec<CrawlEndpoint>, String> {
        request_peer_addresses(self.session)
    }
}

#[cfg(test)]
pub(crate) fn process_node_with_client<C: NodeClient>(
    endpoint: CrawlEndpoint,
    client: &mut C,
) -> Result<NodeVisit, NodeVisitFailure> {
    let started = Instant::now();
    let version = client.handshake().map_err(|message| NodeVisitFailure {
        node: endpoint.clone(),
        latency: started.elapsed(),
        classification: FailureClassification::Handshake,
        message,
    })?;
    let discovered = client.get_addresses().map_err(|message| NodeVisitFailure {
        node: endpoint.clone(),
        latency: started.elapsed(),
        classification: FailureClassification::PeerDiscovery,
        message,
    })?;

    Ok(NodeVisit {
        node: endpoint,
        state: NodeState {
            version: version.version,
            services: version.services.bits(),
            user_agent: version.user_agent,
            start_height: version.start_height,
            relay: version.relay,
            timestamp: version.timestamp,
        },
        discovered,
        latency: started.elapsed(),
    })
}

fn request_peer_addresses(session: &mut Session) -> Result<Vec<CrawlEndpoint>, String> {
    session
        .send(wire::Command::GetAddr, &[])
        .map_err(|e| e.to_string())?;

    loop {
        let msg = session.recv().map_err(|e| e.to_string())?;

        match msg {
            wire::Message::AddrV2(entries) => {
                let mut out = Vec::new();
                for entry in entries {
                    out.push(endpoint_from_addrv2(&entry.addr, entry.port));
                }
                return Ok(out);
            }
            wire::Message::Addr(entries) => {
                let mut out = Vec::new();
                for entry in entries {
                    out.push(CrawlEndpoint::from_socket_addr(SocketAddr::new(
                        entry.addr.ip,
                        entry.addr.port,
                    )));
                }
                return Ok(out);
            }
            wire::Message::Ping(payload) => {
                session
                    .send(wire::Command::Pong, &payload)
                    .map_err(|e| e.to_string())?;
            }
            _ => {}
        }
    }
}

fn endpoint_from_addrv2(addr: &AddrV2Addr, port: u16) -> CrawlEndpoint {
    match addr {
        AddrV2Addr::IPv4(ip) => CrawlEndpoint::new(
            ip.to_string(),
            port,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(*ip)),
        ),
        AddrV2Addr::IPv6(ip) => CrawlEndpoint::new(
            ip.to_string(),
            port,
            CrawlNetwork::Ipv6,
            Some(IpAddr::V6(*ip)),
        ),
        AddrV2Addr::Cjdns(ip) => CrawlEndpoint::new(
            ip.to_string(),
            port,
            CrawlNetwork::Cjdns,
            Some(IpAddr::V6(*ip)),
        ),
        AddrV2Addr::Yggdrasil(ip) => CrawlEndpoint::new(
            ip.to_string(),
            port,
            CrawlNetwork::Yggdrasil,
            Some(IpAddr::V6(*ip)),
        ),
        AddrV2Addr::TorV2(bytes) => {
            CrawlEndpoint::new(hex::encode(bytes), port, CrawlNetwork::TorV2, None)
        }
        AddrV2Addr::TorV3(bytes) => {
            CrawlEndpoint::new(hex::encode(bytes), port, CrawlNetwork::TorV3, None)
        }
        AddrV2Addr::I2P(bytes) => {
            CrawlEndpoint::new(hex::encode(bytes), port, CrawlNetwork::I2p, None)
        }
        AddrV2Addr::Unknown { network_id, bytes } => CrawlEndpoint::new(
            format!("unknown-{network_id}-{}", hex::encode(bytes)),
            port,
            CrawlNetwork::Unknown,
            None,
        ),
    }
}

pub(crate) fn resolve_seed_nodes() -> Vec<SocketAddr> {
    let mut out = Vec::new();

    for seed in wire::constants::MAINNET_DNS_SEEDS {
        match seed.to_socket_addrs() {
            Ok(addrs) => out.extend(addrs),
            Err(err) => warn!("[crawler] failed to resolve seed {seed}: {err}"),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::message::{NetAddr, Services};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    struct MockClient {
        calls: Vec<&'static str>,
        version: Option<VersionMessage>,
        addrs: Vec<CrawlEndpoint>,
        fail_handshake: bool,
    }

    impl NodeClient for MockClient {
        fn handshake(&mut self) -> Result<VersionMessage, String> {
            self.calls.push("handshake");
            if self.fail_handshake {
                return Err("handshake failed".to_string());
            }
            self.version
                .take()
                .ok_or_else(|| "missing mock version".to_string())
        }

        fn get_addresses(&mut self) -> Result<Vec<CrawlEndpoint>, String> {
            self.calls.push("get_addresses");
            Ok(self.addrs.clone())
        }
    }

    #[test]
    fn process_node_calls_handshake_then_get_addresses() {
        let node = CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 2),
            8333,
        )));
        let discovered = vec![CrawlEndpoint::from_socket_addr(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 8333),
        ))];

        let mut client = MockClient {
            calls: vec![],
            version: Some(mock_version()),
            addrs: discovered.clone(),
            fail_handshake: false,
        };

        let visit = process_node_with_client(node, &mut client).unwrap();

        assert_eq!(client.calls, vec!["handshake", "get_addresses"]);
        assert_eq!(
            visit.node,
            CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                8333
            )))
        );
        assert_eq!(visit.discovered, discovered);
        assert_eq!(visit.state.version, 70016);
        assert_eq!(visit.state.start_height, 938408);
    }

    #[test]
    fn process_node_stops_when_handshake_fails() {
        let node = CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 2),
            8333,
        )));
        let mut client = MockClient {
            calls: vec![],
            version: Some(mock_version()),
            addrs: vec![],
            fail_handshake: true,
        };

        let err = process_node_with_client(node, &mut client).unwrap_err();
        assert_eq!(err.message, "handshake failed");
        assert_eq!(err.classification, FailureClassification::Handshake);
        assert_eq!(client.calls, vec!["handshake"]);
    }

    #[test]
    fn connect_with_retries_retries_before_succeeding() {
        let node = CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 7),
            8333,
        )));
        let config = CrawlerConfig {
            connect_max_attempts: 3,
            connect_retry_backoff: Duration::from_millis(10),
            ..CrawlerConfig::default()
        };
        let mut attempts = 0;
        let mut backoffs = Vec::new();

        let result = connect_with_retries_using(
            &node,
            "1.1.1.7:8333",
            config,
            Instant::now(),
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
                } else {
                    Ok("connected")
                }
            },
            |delay| backoffs.push(delay),
        )
        .expect("third attempt should succeed");

        assert_eq!(result, "connected");
        assert_eq!(attempts, 3);
        assert_eq!(
            backoffs,
            vec![Duration::from_millis(10), Duration::from_millis(20)]
        );
    }

    #[test]
    fn connect_with_retries_returns_connect_failure_after_max_attempts() {
        let node = CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 8),
            8333,
        )));
        let config = CrawlerConfig {
            connect_max_attempts: 2,
            connect_retry_backoff: Duration::from_millis(5),
            ..CrawlerConfig::default()
        };
        let mut attempts = 0;
        let mut backoffs = Vec::new();

        let err = connect_with_retries_using(
            &node,
            "1.1.1.8:8333",
            config,
            Instant::now(),
            || {
                attempts += 1;
                Err::<(), _>(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
            },
            |delay| backoffs.push(delay),
        )
        .expect_err("connect should fail after max attempts");

        assert_eq!(attempts, 2);
        assert_eq!(backoffs, vec![Duration::from_millis(5)]);
        assert_eq!(err.classification, FailureClassification::Connect);
        assert!(err.message.contains("failed after 2 attempts"));
    }

    #[test]
    fn endpoint_from_addrv2_preserves_overlay_and_special_network_types() {
        let cjdns = endpoint_from_addrv2(
            &AddrV2Addr::Cjdns("fc00::1".parse().expect("cjdns ip")),
            8333,
        );
        let tor = endpoint_from_addrv2(&AddrV2Addr::TorV3([0x42; 32]), 8333);

        assert_eq!(cjdns.network, CrawlNetwork::Cjdns);
        assert!(!cjdns.supports_ip_enrichment());
        assert_eq!(tor.network, CrawlNetwork::TorV3);
        assert!(tor.socket_addr().is_none());
    }

    fn mock_version() -> VersionMessage {
        VersionMessage {
            version: 70016,
            services: Services::new(Services::NODE_WITNESS.bits()),
            timestamp: 1700000000,
            addr_recv: NetAddr {
                services: 0,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8333,
            },
            addr_from: NetAddr {
                services: 0,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8333,
            },
            nonce: 42,
            user_agent: "/Satoshi:27.0.0/".to_string(),
            start_height: 938408,
            relay: Some(true),
        }
    }
}
