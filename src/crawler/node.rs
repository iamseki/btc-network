use crate::session::Session;
use crate::wire;
use crate::wire::message::{AddrV2Addr, VersionMessage};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};

use super::types::{CrawlerConfig, NodeState, NodeVisit};

pub(crate) trait NodeProcessor: Send + Sync {
    fn process(&self, addr: SocketAddr, config: CrawlerConfig) -> Result<NodeVisit, String>;
}

pub(crate) struct DefaultNodeProcessor;

impl NodeProcessor for DefaultNodeProcessor {
    fn process(&self, addr: SocketAddr, config: CrawlerConfig) -> Result<NodeVisit, String> {
        process_node(addr, config)
    }
}

pub(crate) fn process_node(addr: SocketAddr, config: CrawlerConfig) -> Result<NodeVisit, String> {
    let stream = TcpStream::connect_timeout(&addr, config.connect_timeout)
        .map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(config.io_timeout))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(config.io_timeout))
        .map_err(|e| format!("set write timeout: {e}"))?;

    let mut session = Session::new(stream);
    let mut client = SessionNodeClient {
        session: &mut session,
    };

    process_node_with_client(addr, &mut client)
}

pub(crate) trait NodeClient {
    fn handshake(&mut self) -> Result<VersionMessage, String>;
    fn get_addresses(&mut self) -> Result<Vec<SocketAddr>, String>;
}

struct SessionNodeClient<'a> {
    session: &'a mut Session,
}

impl NodeClient for SessionNodeClient<'_> {
    fn handshake(&mut self) -> Result<VersionMessage, String> {
        self.session.handshake().map_err(|e| e.to_string())
    }

    fn get_addresses(&mut self) -> Result<Vec<SocketAddr>, String> {
        request_peer_addresses(self.session)
    }
}

pub(crate) fn process_node_with_client<C: NodeClient>(
    addr: SocketAddr,
    client: &mut C,
) -> Result<NodeVisit, String> {
    let version = client.handshake()?;
    let discovered = client.get_addresses()?;

    Ok(NodeVisit {
        node: addr,
        state: NodeState {
            version: version.version,
            services: version.services.bits(),
            user_agent: version.user_agent,
            start_height: version.start_height,
            relay: version.relay,
            timestamp: version.timestamp,
        },
        discovered,
    })
}

fn request_peer_addresses(session: &mut Session) -> Result<Vec<SocketAddr>, String> {
    session
        .send(wire::Command::GetAddr, &[])
        .map_err(|e| e.to_string())?;

    loop {
        let msg = session.recv().map_err(|e| e.to_string())?;

        match msg {
            wire::Message::AddrV2(entries) => {
                let mut out = Vec::new();
                for entry in entries {
                    if let Some(addr) = socket_from_addrv2(&entry.addr, entry.port) {
                        out.push(addr);
                    }
                }
                return Ok(out);
            }
            wire::Message::Addr(entries) => {
                let mut out = Vec::new();
                for entry in entries {
                    out.push(SocketAddr::new(entry.addr.ip, entry.addr.port));
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

fn socket_from_addrv2(addr: &AddrV2Addr, port: u16) -> Option<SocketAddr> {
    match addr {
        AddrV2Addr::IPv4(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), port)),
        AddrV2Addr::IPv6(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), port)),
        AddrV2Addr::Cjdns(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), port)),
        AddrV2Addr::Yggdrasil(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), port)),
        AddrV2Addr::TorV2(_)
        | AddrV2Addr::TorV3(_)
        | AddrV2Addr::I2P(_)
        | AddrV2Addr::Unknown { .. } => None,
    }
}

pub(crate) fn resolve_seed_nodes() -> Vec<SocketAddr> {
    let mut out = Vec::new();

    for seed in wire::constants::MAINNET_DNS_SEEDS {
        match seed.to_socket_addrs() {
            Ok(addrs) => out.extend(addrs),
            Err(err) => println!("[crawler] failed to resolve seed {seed}: {err}"),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::message::{NetAddr, Services};
    use std::net::{Ipv4Addr, SocketAddrV4};

    struct MockClient {
        calls: Vec<&'static str>,
        version: Option<VersionMessage>,
        addrs: Vec<SocketAddr>,
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

        fn get_addresses(&mut self) -> Result<Vec<SocketAddr>, String> {
            self.calls.push("get_addresses");
            Ok(self.addrs.clone())
        }
    }

    #[test]
    fn process_node_calls_handshake_then_get_addresses() {
        let node = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 8333));
        let discovered = vec![SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 3),
            8333,
        ))];

        let mut client = MockClient {
            calls: vec![],
            version: Some(mock_version()),
            addrs: discovered.clone(),
            fail_handshake: false,
        };

        let visit = process_node_with_client(node, &mut client).unwrap();

        assert_eq!(client.calls, vec!["handshake", "get_addresses"]);
        assert_eq!(visit.node, node);
        assert_eq!(visit.discovered, discovered);
        assert_eq!(visit.state.version, 70016);
        assert_eq!(visit.state.start_height, 938408);
    }

    #[test]
    fn process_node_stops_when_handshake_fails() {
        let node = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 8333));
        let mut client = MockClient {
            calls: vec![],
            version: Some(mock_version()),
            addrs: vec![],
            fail_handshake: true,
        };

        let err = process_node_with_client(node, &mut client).unwrap_err();
        assert_eq!(err, "handshake failed");
        assert_eq!(client.calls, vec!["handshake"]);
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
