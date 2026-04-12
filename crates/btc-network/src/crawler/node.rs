use crate::session::AsyncSession;
use crate::wire;
use crate::wire::message::AddrV2Addr;
#[cfg(test)]
use crate::wire::message::VersionMessage;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::time::{Duration, Instant};
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

use super::domain::{CrawlEndpoint, CrawlNetwork, FailureClassification};
use super::types::{CrawlerConfig, NodeState, NodeVisit, NodeVisitFailure, NodeVisitResult};

pub(crate) trait NodeProcessor: Send + Sync {
    fn process<'a>(
        &'a self,
        endpoint: CrawlEndpoint,
        config: CrawlerConfig,
    ) -> Pin<Box<dyn Future<Output = NodeVisitResult> + Send + 'a>>;
}

pub(crate) struct DefaultNodeProcessor {
    connect_limiter: Arc<Semaphore>,
}

use std::sync::Arc;

impl DefaultNodeProcessor {
    pub(crate) fn new(connect_limiter: Arc<Semaphore>) -> Self {
        Self { connect_limiter }
    }
}

impl NodeProcessor for DefaultNodeProcessor {
    fn process<'a>(
        &'a self,
        endpoint: CrawlEndpoint,
        config: CrawlerConfig,
    ) -> Pin<Box<dyn Future<Output = NodeVisitResult> + Send + 'a>> {
        let connect_limiter = Arc::clone(&self.connect_limiter);
        Box::pin(async move { process_node(endpoint, config, connect_limiter).await })
    }
}

pub(crate) async fn process_node(
    endpoint: CrawlEndpoint,
    config: CrawlerConfig,
    connect_limiter: Arc<Semaphore>,
) -> NodeVisitResult {
    info!(
        node = %endpoint.canonical,
        "[crawler] start processing node"
    );

    let total_started = Instant::now();
    let connect_addr = endpoint.socket_addr().ok_or_else(|| {
        Box::new(NodeVisitFailure {
            node: endpoint.clone(),
            latency: total_started.elapsed(),
            classification: FailureClassification::Connect,
            message: format!("endpoint {} is not connectable", endpoint.canonical),
            connect_error_kind: None,
        })
    })?;
    let connect_started = Instant::now();
    let stream = connect_once(
        &endpoint,
        connect_addr,
        config,
        total_started,
        connect_limiter,
    )
    .await?;
    let connect_elapsed = connect_started.elapsed();
    let mut session = AsyncSession::new(stream, config.io_timeout);

    let handshake_started = Instant::now();
    let version = session.handshake().await.map_err(|message| {
        Box::new(NodeVisitFailure {
            node: endpoint.clone(),
            latency: total_started.elapsed(),
            classification: FailureClassification::Handshake,
            message: message.to_string(),
            connect_error_kind: None,
        })
    })?;
    let handshake_elapsed = handshake_started.elapsed();

    let get_addr_started = Instant::now();
    let discovered = request_peer_addresses(&mut session)
        .await
        .map_err(|message| {
            Box::new(NodeVisitFailure {
                node: endpoint.clone(),
                latency: total_started.elapsed(),
                classification: FailureClassification::PeerDiscovery,
                message,
                connect_error_kind: None,
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

async fn connect_once(
    endpoint: &CrawlEndpoint,
    connect_addr: SocketAddr,
    config: CrawlerConfig,
    total_started: Instant,
    connect_limiter: Arc<Semaphore>,
) -> Result<AsyncTcpStream, Box<NodeVisitFailure>> {
    connect_once_using(
        endpoint,
        connect_addr,
        config,
        total_started,
        acquire_connect_permit(connect_limiter, endpoint.clone(), total_started).await?,
        || async move {
            tokio::time::timeout(
                config.connect_timeout,
                AsyncTcpStream::connect(connect_addr),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect timed out after {:?}", config.connect_timeout),
                )
            })?
        },
    )
    .await
}

async fn connect_once_using<T, Connect, ConnectFuture>(
    endpoint: &CrawlEndpoint,
    connect_target: impl ToString,
    _config: CrawlerConfig,
    total_started: Instant,
    _permit: OwnedSemaphorePermit,
    connect: Connect,
) -> Result<T, Box<NodeVisitFailure>>
where
    Connect: FnOnce() -> ConnectFuture,
    ConnectFuture: Future<Output = io::Result<T>>,
{
    let connect_target = connect_target.to_string();
    match connect().await {
        Ok(stream) => Ok(stream),
        Err(error) => Err(Box::new(NodeVisitFailure {
            node: endpoint.clone(),
            latency: total_started.elapsed(),
            classification: FailureClassification::Connect,
            message: format!("connect {connect_target}: {error}"),
            connect_error_kind: Some(error.kind()),
        })),
    }
}

async fn acquire_connect_permit(
    connect_limiter: Arc<Semaphore>,
    endpoint: CrawlEndpoint,
    total_started: Instant,
) -> Result<OwnedSemaphorePermit, Box<NodeVisitFailure>> {
    connect_limiter.acquire_owned().await.map_err(|_| {
        Box::new(NodeVisitFailure {
            node: endpoint,
            latency: total_started.elapsed(),
            classification: FailureClassification::Connect,
            message: "connect limiter closed".to_string(),
            connect_error_kind: None,
        })
    })
}

pub(crate) fn connect_retry_delay(base: Duration, retry_number: usize) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }

    let shift = retry_number.saturating_sub(1).min(10);
    let factor = 1u32 << shift;
    base.checked_mul(factor).unwrap_or(Duration::MAX)
}

#[cfg(test)]
pub(crate) async fn process_node_with_client<C: NodeClient>(
    endpoint: CrawlEndpoint,
    client: &mut C,
) -> Result<NodeVisit, NodeVisitFailure> {
    let started = Instant::now();
    let version = client
        .handshake()
        .await
        .map_err(|message| NodeVisitFailure {
            node: endpoint.clone(),
            latency: started.elapsed(),
            classification: FailureClassification::Handshake,
            message,
            connect_error_kind: None,
        })?;
    let discovered = client
        .get_addresses()
        .await
        .map_err(|message| NodeVisitFailure {
            node: endpoint.clone(),
            latency: started.elapsed(),
            classification: FailureClassification::PeerDiscovery,
            message,
            connect_error_kind: None,
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

async fn request_peer_addresses(session: &mut AsyncSession) -> Result<Vec<CrawlEndpoint>, String> {
    session
        .send(wire::Command::GetAddr, &[])
        .await
        .map_err(|e| e.to_string())?;

    loop {
        let msg = session.recv().await.map_err(|e| e.to_string())?;

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
                    .await
                    .map_err(|e| e.to_string())?;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
type VersionFuture<'a> = Pin<Box<dyn Future<Output = Result<VersionMessage, String>> + Send + 'a>>;
#[cfg(test)]
type AddressFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<CrawlEndpoint>, String>> + Send + 'a>>;

#[cfg(test)]
pub(crate) trait NodeClient {
    fn handshake(&mut self) -> VersionFuture<'_>;
    fn get_addresses(&mut self) -> AddressFuture<'_>;
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockClient {
        calls: Vec<&'static str>,
        version: Option<VersionMessage>,
        addrs: Vec<CrawlEndpoint>,
        fail_handshake: bool,
    }

    impl NodeClient for MockClient {
        fn handshake(&mut self) -> VersionFuture<'_> {
            self.calls.push("handshake");
            let fail_handshake = self.fail_handshake;
            let version = self.version.take();

            Box::pin(async move {
                if fail_handshake {
                    return Err("handshake failed".to_string());
                }

                version.ok_or_else(|| "missing mock version".to_string())
            })
        }

        fn get_addresses(&mut self) -> AddressFuture<'_> {
            self.calls.push("get_addresses");
            let addrs = self.addrs.clone();
            Box::pin(async move { Ok(addrs) })
        }
    }

    #[tokio::test]
    async fn process_node_calls_handshake_then_get_addresses() {
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

        let visit = process_node_with_client(node, &mut client).await.unwrap();

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

    #[tokio::test]
    async fn process_node_stops_when_handshake_fails() {
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

        let err = process_node_with_client(node, &mut client)
            .await
            .unwrap_err();
        assert_eq!(err.message, "handshake failed");
        assert_eq!(err.classification, FailureClassification::Handshake);
        assert_eq!(client.calls, vec!["handshake"]);
    }

    #[tokio::test]
    async fn connect_once_returns_connected_stream() {
        let node = CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 7),
            8333,
        )));
        let limiter = Arc::new(Semaphore::new(1));
        let attempts = AtomicUsize::new(0);

        let result = connect_once_using(
            &node,
            "1.1.1.7:8333",
            CrawlerConfig::default(),
            Instant::now(),
            limiter.acquire_owned().await.expect("permit"),
            || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                async move {
                    if attempt == 1 {
                        Ok("connected")
                    } else {
                        Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
                    }
                }
            },
        )
        .await
        .expect("connect should succeed");

        assert_eq!(result, "connected");
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn connect_once_returns_connect_failure() {
        let node = CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 8),
            8333,
        )));
        let limiter = Arc::new(Semaphore::new(1));
        let attempts = AtomicUsize::new(0);

        let err = connect_once_using(
            &node,
            "1.1.1.8:8333",
            CrawlerConfig::default(),
            Instant::now(),
            limiter.acquire_owned().await.expect("permit"),
            || {
                attempts.fetch_add(1, Ordering::Relaxed);
                async { Err::<(), _>(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")) }
            },
        )
        .await
        .expect_err("connect should fail");

        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert_eq!(err.classification, FailureClassification::Connect);
        assert_eq!(
            err.connect_error_kind,
            Some(io::ErrorKind::ConnectionRefused)
        );
        assert!(err.message.contains("connect 1.1.1.8:8333"));
    }

    #[tokio::test]
    async fn acquire_connect_permit_waits_until_slot_is_released() {
        let limiter = Arc::new(Semaphore::new(1));
        let first = acquire_connect_permit(
            Arc::clone(&limiter),
            CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 9),
                8333,
            ))),
            Instant::now(),
        )
        .await
        .expect("first permit");

        let second_task = tokio::spawn(acquire_connect_permit(
            Arc::clone(&limiter),
            CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 10),
                8333,
            ))),
            Instant::now(),
        ));

        tokio::task::yield_now().await;
        assert!(
            !second_task.is_finished(),
            "second connect permit should wait while the first slot is held"
        );

        drop(first);

        let second = second_task.await.expect("second permit join");
        assert!(second.is_ok(), "second permit should acquire after release");
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
