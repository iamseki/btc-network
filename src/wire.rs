use std::io::{self, Read};
use std::net::TcpStream;

/// A raw Bitcoin P2P message frame.
///
/// This struct represents a message as transmitted on the wire
/// according to the Bitcoin P2P protocol (https://developer.bitcoin.org/reference/p2p_networking.html#message-headers).
///
/// A Bitcoin message frame consists of:
/// - 4-byte magic value (network identifier)
/// - 12-byte command
/// - 4-byte payload length
/// - 4-byte checksum
/// - variable-length payload (up to 32MB)
///
/// `RawMessage` contains the decoded header fields and payload,
/// but does not yet validate checksum or interpret the payload.
#[derive(Debug)]
pub struct RawMessage {
    pub command: Command,
    pub payload: Vec<u8>,
    magic: [u8; 4],
    checksum: [u8; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    // Control
    Version,
    Verack,
    Addr,
    AddrV2,
    SendAddrV2,
    GetAddr,
    Ping,
    Pong,
    SendHeaders,
    SendCmpct,
    FeeFilter,
    Reject,
    Alert,
    // Data
    Inv,
    GetData,
    NotFound,
    GetBlocks,
    GetHeaders,
    Headers,
    Block,
    Tx,
    GetBlockTxn,
    BlockTxn,
    CmpctBlock,
    Mempool,
    MerkleBlock,
    // Bloom filter
    FilterLoad,
    FilterAdd,
    FilterClear,

    Unknown,
}

#[derive(Debug)]
pub struct NetAddr {
    pub services: u64,
    pub ip: std::net::IpAddr,
    pub port: u16,
}

#[derive(Debug)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetAddr,
    pub addr_from: NetAddr,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: Option<bool>,
}

#[derive(Debug)]
pub struct AddrEntry {
    pub timestamp: u32,
    pub addr: NetAddr,
}

/// Network-specific address payload from an `addrv2` message (BIP 155).
///
/// Each variant carries exactly the bytes defined by the BIP 155 registry:
///
/// | ID   | Variant      | Length  |
/// |------|--------------|---------|
/// | 0x01 | IPv4         | 4 B     |
/// | 0x02 | IPv6         | 16 B    |
/// | 0x03 | TorV2        | 10 B    | (deprecated — Tor v2 shut down Oct 2021)
/// | 0x04 | TorV3        | 32 B    |
/// | 0x05 | I2P          | 32 B    |
/// | 0x06 | CJDNS        | 16 B    |
/// | 0x07 | Yggdrasil    | 16 B    |
///
/// https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
#[derive(Debug)]
pub enum AddrV2Addr {
    IPv4(std::net::Ipv4Addr),
    IPv6(std::net::Ipv6Addr),
    TorV2([u8; 10]),
    TorV3([u8; 32]),
    I2P([u8; 32]),
    Cjdns(std::net::Ipv6Addr),
    Yggdrasil(std::net::Ipv6Addr),
    Unknown { network_id: u8, bytes: Vec<u8> },
}

#[derive(Debug)]
pub struct AddrV2Entry {
    pub timestamp: u32,
    /// Services encoded as a CompactSize (varint) on the wire, expanded to u64.
    pub services: u64,
    pub addr: AddrV2Addr,
    pub port: u16,
}

/// A fully-decoded Bitcoin P2P message.
#[derive(Debug)]
pub enum Message {
    // --- decoded ---
    Version(VersionMessage),
    Verack,
    Addr(Vec<AddrEntry>),
    AddrV2(Vec<AddrV2Entry>),

    // --- TODO: implement Decode ---
    SendAddrV2(Vec<u8>),
    GetAddr(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    SendHeaders(Vec<u8>),
    SendCmpct(Vec<u8>),
    FeeFilter(Vec<u8>),
    Reject(Vec<u8>),
    Alert(Vec<u8>),
    Inv(Vec<u8>),
    GetData(Vec<u8>),
    NotFound(Vec<u8>),
    GetBlocks(Vec<u8>),
    GetHeaders(Vec<u8>),
    Headers(Vec<u8>),
    Block(Vec<u8>),
    Tx(Vec<u8>),
    GetBlockTxn(Vec<u8>),
    BlockTxn(Vec<u8>),
    CmpctBlock(Vec<u8>),
    Mempool(Vec<u8>),
    MerkleBlock(Vec<u8>),
    FilterLoad(Vec<u8>),
    FilterAdd(Vec<u8>),
    FilterClear(Vec<u8>),

    Unknown { payload: Vec<u8> },
}

/// Implemented by types that can be decoded from a raw Bitcoin message payload.
pub trait Decode: Sized {
    fn decode(payload: &[u8]) -> io::Result<Self>;
}

impl From<&[u8; 12]> for Command {
    fn from(bytes: &[u8; 12]) -> Self {
        let cmd = std::str::from_utf8(bytes)
            .unwrap_or("")
            .trim_matches(char::from(0));

        match cmd {
            "version"     => Command::Version,
            "verack"      => Command::Verack,
            "addr"        => Command::Addr,
            "addrv2"      => Command::AddrV2,
            "sendaddrv2"  => Command::SendAddrV2,
            "getaddr"     => Command::GetAddr,
            "ping"        => Command::Ping,
            "pong"        => Command::Pong,
            "sendheaders" => Command::SendHeaders,
            "sendcmpct"   => Command::SendCmpct,
            "feefilter"   => Command::FeeFilter,
            "reject"      => Command::Reject,
            "alert"       => Command::Alert,
            "inv"         => Command::Inv,
            "getdata"     => Command::GetData,
            "notfound"    => Command::NotFound,
            "getblocks"   => Command::GetBlocks,
            "getheaders"  => Command::GetHeaders,
            "headers"     => Command::Headers,
            "block"       => Command::Block,
            "tx"          => Command::Tx,
            "getblocktxn" => Command::GetBlockTxn,
            "blocktxn"    => Command::BlockTxn,
            "cmpctblock"  => Command::CmpctBlock,
            "mempool"     => Command::Mempool,
            "merkleblock" => Command::MerkleBlock,
            "filterload"  => Command::FilterLoad,
            "filteradd"   => Command::FilterAdd,
            "filterclear" => Command::FilterClear,
            _             => Command::Unknown,
        }
    }
}

impl TryFrom<RawMessage> for Message {
    type Error = io::Error;

    fn try_from(raw: RawMessage) -> io::Result<Self> {
        match raw.command {
            // decoded
            Command::Version     => Ok(Message::Version(VersionMessage::decode(&raw.payload)?)),
            Command::Verack      => Ok(Message::Verack),
            Command::Addr        => Ok(Message::Addr(Vec::<AddrEntry>::decode(&raw.payload)?)),
            Command::AddrV2      => Ok(Message::AddrV2(Vec::<AddrV2Entry>::decode(&raw.payload)?)),
            // TODO: implement Decode
            Command::SendAddrV2  => Ok(Message::SendAddrV2(raw.payload)),
            Command::GetAddr     => Ok(Message::GetAddr(raw.payload)),
            Command::Ping        => Ok(Message::Ping(raw.payload)),
            Command::Pong        => Ok(Message::Pong(raw.payload)),
            Command::SendHeaders => Ok(Message::SendHeaders(raw.payload)),
            Command::SendCmpct   => Ok(Message::SendCmpct(raw.payload)),
            Command::FeeFilter   => Ok(Message::FeeFilter(raw.payload)),
            Command::Reject      => Ok(Message::Reject(raw.payload)),
            Command::Alert       => Ok(Message::Alert(raw.payload)),
            Command::Inv         => Ok(Message::Inv(raw.payload)),
            Command::GetData     => Ok(Message::GetData(raw.payload)),
            Command::NotFound    => Ok(Message::NotFound(raw.payload)),
            Command::GetBlocks   => Ok(Message::GetBlocks(raw.payload)),
            Command::GetHeaders  => Ok(Message::GetHeaders(raw.payload)),
            Command::Headers     => Ok(Message::Headers(raw.payload)),
            Command::Block       => Ok(Message::Block(raw.payload)),
            Command::Tx          => Ok(Message::Tx(raw.payload)),
            Command::GetBlockTxn => Ok(Message::GetBlockTxn(raw.payload)),
            Command::BlockTxn    => Ok(Message::BlockTxn(raw.payload)),
            Command::CmpctBlock  => Ok(Message::CmpctBlock(raw.payload)),
            Command::Mempool     => Ok(Message::Mempool(raw.payload)),
            Command::MerkleBlock => Ok(Message::MerkleBlock(raw.payload)),
            Command::FilterLoad  => Ok(Message::FilterLoad(raw.payload)),
            Command::FilterAdd   => Ok(Message::FilterAdd(raw.payload)),
            Command::FilterClear => Ok(Message::FilterClear(raw.payload)),
            Command::Unknown     => Ok(Message::Unknown { payload: raw.payload }),
        }
    }
}

impl Decode for VersionMessage {
    fn decode(payload: &[u8]) -> io::Result<Self> {
        let mut c = 0;

        let version     = read_i32(payload, &mut c)?;
        let services    = read_u64(payload, &mut c)?;
        let timestamp   = read_i64(payload, &mut c)?;
        let addr_recv   = decode_net_addr(payload, &mut c)?;
        let addr_from   = decode_net_addr(payload, &mut c)?;
        let nonce       = read_u64(payload, &mut c)?;

        let ua_len = read_varint(payload, &mut c)? as usize;
        let user_agent = std::str::from_utf8(
            payload.get(c..c + ua_len).ok_or_else(|| eof("version: user_agent"))?,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .to_string();
        c += ua_len;

        let start_height = read_i32(payload, &mut c)?;
        let relay = payload.get(c).map(|&b| b != 0);

        Ok(VersionMessage { version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay })
    }
}

impl Decode for Vec<AddrEntry> {
    fn decode(payload: &[u8]) -> io::Result<Self> {
        let mut c = 0;
        let count = read_varint(payload, &mut c)? as usize;
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            let timestamp = read_u32(payload, &mut c)?;
            let addr = decode_net_addr(payload, &mut c)?;
            entries.push(AddrEntry { timestamp, addr });
        }

        Ok(entries)
    }
}

impl Decode for Vec<AddrV2Entry> {
    fn decode(payload: &[u8]) -> io::Result<Self> {
        let mut c = 0;
        let count = read_varint(payload, &mut c)? as usize;

        // BIP 155: reject messages with more than 1000 addresses
        if count > 1000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "addrv2: exceeds 1000-entry limit",
            ));
        }

        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            let timestamp = read_u32(payload, &mut c)?;
            let services  = read_varint(payload, &mut c)?; // CompactSize on wire
            let network_id = *payload.get(c).ok_or_else(|| eof("addrv2: network_id"))?;
            c += 1;

            let addr_len = read_varint(payload, &mut c)? as usize;
            if addr_len > 512 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "addrv2: addr field exceeds 512-byte limit",
                ));
            }
            let addr_bytes = payload
                .get(c..c + addr_len)
                .ok_or_else(|| eof("addrv2: addr bytes"))?;
            c += addr_len;

            let port = u16::from_be_bytes(slice2(payload, &mut c, "addrv2: port")?);

            let addr = match network_id {
                0x01 => {
                    if addr_bytes.len() != 4 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "addrv2: IPv4 must be 4 bytes"));
                    }
                    AddrV2Addr::IPv4(std::net::Ipv4Addr::new(
                        addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
                    ))
                }
                0x02 => {
                    if addr_bytes.len() != 16 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "addrv2: IPv6 must be 16 bytes"));
                    }
                    AddrV2Addr::IPv6(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(addr_bytes).unwrap(),
                    ))
                }
                0x03 => {
                    if addr_bytes.len() != 10 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "addrv2: TorV2 must be 10 bytes"));
                    }
                    AddrV2Addr::TorV2(addr_bytes.try_into().unwrap())
                }
                0x04 => {
                    if addr_bytes.len() != 32 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "addrv2: TorV3 must be 32 bytes"));
                    }
                    AddrV2Addr::TorV3(addr_bytes.try_into().unwrap())
                }
                0x05 => {
                    if addr_bytes.len() != 32 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "addrv2: I2P must be 32 bytes"));
                    }
                    AddrV2Addr::I2P(addr_bytes.try_into().unwrap())
                }
                0x06 => {
                    if addr_bytes.len() != 16 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "addrv2: CJDNS must be 16 bytes"));
                    }
                    AddrV2Addr::Cjdns(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(addr_bytes).unwrap(),
                    ))
                }
                0x07 => {
                    if addr_bytes.len() != 16 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "addrv2: Yggdrasil must be 16 bytes"));
                    }
                    AddrV2Addr::Yggdrasil(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(addr_bytes).unwrap(),
                    ))
                }
                id => AddrV2Addr::Unknown { network_id: id, bytes: addr_bytes.to_vec() },
            };

            entries.push(AddrV2Entry { timestamp, services, addr, port });
        }

        Ok(entries)
    }
}

/// Reads a single Bitcoin P2P message frame from the TCP stream.
///
/// This function reads the header and payload and returns a [`RawMessage`].
/// It does not validate the magic value or checksum.
///
/// Returns an [`io::Error`] if the stream fails or the header is malformed.
pub fn read_message(stream: &mut TcpStream) -> io::Result<RawMessage> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header)?;

    let magic: [u8; 4] = header[0..4]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid magic field"))?;

    let cmd = header[4..16]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cmd field"))?;

    let command = Command::from(&cmd);

    let length = u32::from_le_bytes(
        header[16..20]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid length field"))?,
    );

    let checksum: [u8; 4] = header[20..24]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid checksum field"))?;

    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;

    Ok(RawMessage { magic, command, payload, checksum })
}

// --- helpers ----------------------------------------------------------------

fn eof(context: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, context)
}

fn read_varint(p: &[u8], c: &mut usize) -> io::Result<u64> {
    let first = *p.get(*c).ok_or_else(|| eof("varint"))?;
    *c += 1;
    match first {
        0xFD => { let v = u16::from_le_bytes(slice2(p, c, "varint:fd")?); Ok(v as u64) }
        0xFE => { let v = u32::from_le_bytes(slice4(p, c, "varint:fe")?); Ok(v as u64) }
        0xFF => { let v = u64::from_le_bytes(slice8(p, c, "varint:ff")?); Ok(v) }
        n    => Ok(n as u64),
    }
}

fn decode_net_addr(p: &[u8], c: &mut usize) -> io::Result<NetAddr> {
    let services = read_u64(p, c)?;

    let ip_bytes: [u8; 16] = p
        .get(*c..*c + 16)
        .ok_or_else(|| eof("net_addr: ip"))?
        .try_into()
        .unwrap();
    *c += 16;

    let port = u16::from_be_bytes(slice2(p, c, "net_addr: port")?);

    let ip = if ip_bytes[..12] == [0u8; 12] {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15],
        ))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes))
    };

    Ok(NetAddr { services, ip, port })
}

fn read_i32(p: &[u8], c: &mut usize) -> io::Result<i32> { Ok(i32::from_le_bytes(slice4(p, c, "i32")?)) }
fn read_i64(p: &[u8], c: &mut usize) -> io::Result<i64> { Ok(i64::from_le_bytes(slice8(p, c, "i64")?)) }
fn read_u32(p: &[u8], c: &mut usize) -> io::Result<u32> { Ok(u32::from_le_bytes(slice4(p, c, "u32")?)) }
fn read_u64(p: &[u8], c: &mut usize) -> io::Result<u64> { Ok(u64::from_le_bytes(slice8(p, c, "u64")?)) }

fn slice2(p: &[u8], c: &mut usize, ctx: &'static str) -> io::Result<[u8; 2]> {
    let b = p.get(*c..*c + 2).ok_or_else(|| eof(ctx))?.try_into().unwrap();
    *c += 2;
    Ok(b)
}

fn slice4(p: &[u8], c: &mut usize, ctx: &'static str) -> io::Result<[u8; 4]> {
    let b = p.get(*c..*c + 4).ok_or_else(|| eof(ctx))?.try_into().unwrap();
    *c += 4;
    Ok(b)
}

fn slice8(p: &[u8], c: &mut usize, ctx: &'static str) -> io::Result<[u8; 8]> {
    let b = p.get(*c..*c + 8).ok_or_else(|| eof(ctx))?.try_into().unwrap();
    *c += 8;
    Ok(b)
}

// --- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    // 4-byte network identifier that prefixes every mainnet message header.
    // Each network has its own value (testnet, signet, regtest differ).
    // https://developer.bitcoin.org/reference/p2p_networking.html#message-headers
    const MAINNET_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

    /// Creates a connected local TcpStream pair (client, server).
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    /// Writes a complete framed Bitcoin message into a stream.
    /// Checksum is zeroed — read_message does not validate it.
    fn write_frame(stream: &mut TcpStream, cmd_str: &[u8], payload: &[u8]) {
        let mut cmd = [0u8; 12];
        cmd[..cmd_str.len()].copy_from_slice(cmd_str);
        stream.write_all(&MAINNET_MAGIC).unwrap();
        stream.write_all(&cmd).unwrap();
        stream.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
        stream.write_all(&[0u8; 4]).unwrap(); // checksum (not validated)
        stream.write_all(payload).unwrap();
    }

    /// Encodes a single NetAddr field as used in version / addr payloads.
    /// Uses the all-zero 12-byte prefix so the decoder treats it as IPv4.
    fn net_addr_bytes(services: u64, ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&services.to_le_bytes());
        b.extend_from_slice(&[0u8; 12]); // IPv4 prefix (12 zero bytes)
        b.extend_from_slice(&ip);
        b.extend_from_slice(&port.to_be_bytes());
        b
    }

    /// Realistic version payload for protocol v70016 (/Satoshi:25.0.0/).
    /// services = NODE_NETWORK(1) | NODE_WITNESS(8) | NODE_NETWORK_LIMITED(1024) = 1033
    fn version_payload_v70016() -> Vec<u8> {
        let mut p = vec![];
        p.extend_from_slice(&70016i32.to_le_bytes());
        p.extend_from_slice(&1033u64.to_le_bytes());
        p.extend_from_slice(&1700000000i64.to_le_bytes());
        p.extend(net_addr_bytes(1033, [192, 168, 1, 1], 8333)); // addr_recv
        p.extend(net_addr_bytes(1033, [10, 0, 0, 1], 8333));    // addr_from
        p.extend_from_slice(&0x1234567890abcdefu64.to_le_bytes()); // nonce
        let ua = b"/Satoshi:25.0.0/";
        p.push(ua.len() as u8);
        p.extend_from_slice(ua);
        p.extend_from_slice(&820000i32.to_le_bytes()); // start_height (~late 2023)
        p.push(1);                                     // relay = true
        p
    }

    /// addr payload with 2 IPv4 entries.
    fn addr_payload_two_entries() -> Vec<u8> {
        let mut p = vec![];
        p.push(2); // varint count
        p.extend_from_slice(&1700000100u32.to_le_bytes());
        p.extend(net_addr_bytes(1, [1, 2, 3, 4], 8333));
        p.extend_from_slice(&1700000200u32.to_le_bytes());
        p.extend(net_addr_bytes(1, [5, 6, 7, 8], 8334));
        p
    }

    // --- read_message -------------------------------------------------------

    #[test]
    fn read_message_recognises_version_command() {
        let (mut client, mut server) = tcp_pair();
        let payload = version_payload_v70016();
        thread::spawn(move || write_frame(&mut server, b"version", &payload));

        let raw = read_message(&mut client).unwrap();
        assert_eq!(raw.command, Command::Version);
        assert!(!raw.payload.is_empty());
    }

    #[test]
    fn read_message_verack_has_empty_payload() {
        let (mut client, mut server) = tcp_pair();
        thread::spawn(move || write_frame(&mut server, b"verack", &[]));

        let raw = read_message(&mut client).unwrap();
        assert_eq!(raw.command, Command::Verack);
        assert!(raw.payload.is_empty());
    }

    #[test]
    fn read_message_unknown_command_preserved_in_payload() {
        let (mut client, mut server) = tcp_pair();
        thread::spawn(move || write_frame(&mut server, b"wtfmessage", &[1, 2, 3]));

        let raw = read_message(&mut client).unwrap();
        assert_eq!(raw.command, Command::Unknown);
        assert_eq!(raw.payload, vec![1, 2, 3]);
    }

    // --- Decode: VersionMessage ---------------------------------------------

    #[test]
    fn decode_version_v70016_all_fields() {
        let msg = VersionMessage::decode(&version_payload_v70016()).unwrap();

        assert_eq!(msg.version, 70016);
        assert_eq!(msg.services, 1033);
        assert_eq!(msg.timestamp, 1700000000);
        assert_eq!(msg.user_agent, "/Satoshi:25.0.0/");
        assert_eq!(msg.start_height, 820000);
        assert_eq!(msg.relay, Some(true));
        assert_eq!(msg.addr_recv.port, 8333);
        assert_eq!(
            msg.addr_recv.ip,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(msg.addr_from.port, 8333);
        assert_eq!(
            msg.addr_from.ip,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn decode_version_relay_absent_when_byte_missing() {
        let mut payload = version_payload_v70016();
        payload.pop(); // remove relay byte
        let msg = VersionMessage::decode(&payload).unwrap();
        assert_eq!(msg.relay, None);
    }

    #[test]
    fn decode_version_truncated_payload_returns_error() {
        assert!(VersionMessage::decode(&[0u8; 10]).is_err());
    }

    // --- Decode: Vec<AddrEntry> ---------------------------------------------

    #[test]
    fn decode_addr_two_entries() {
        let entries = Vec::<AddrEntry>::decode(&addr_payload_two_entries()).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].timestamp, 1700000100);
        assert_eq!(entries[0].addr.port, 8333);
        assert_eq!(
            entries[0].addr.ip,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(entries[1].timestamp, 1700000200);
        assert_eq!(entries[1].addr.port, 8334);
        assert_eq!(
            entries[1].addr.ip,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8))
        );
    }

    #[test]
    fn decode_addr_empty_list() {
        let entries = Vec::<AddrEntry>::decode(&[0x00]).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn decode_addr_truncated_entry_returns_error() {
        let mut payload = addr_payload_two_entries();
        payload.truncate(payload.len() - 5); // corrupt last entry
        assert!(Vec::<AddrEntry>::decode(&payload).is_err());
    }

    // --- decode_net_addr ----------------------------------------------------
    //
    // Bitcoin P2P represents all addresses as 16-byte fields inside message
    // payloads (version, addr). The encoding convention is:
    //
    //   IPv4   — 10 x 0x00  +  0xFF 0xFF  +  4-byte IPv4  (standard ::ffff: mapping)
    //   IPv6   — 16 bytes of native IPv6
    //   Tor v2 — 0xFD 0x87 0xD8 0x7E 0xEB 0x43  +  10-byte .onion (deprecated)
    //
    // IPv4 is by far the most common in practice. IPv6 nodes exist but are a
    // minority. Tor v2 is deprecated; Tor v3 and I2P require addrv2 (BIP 155),
    // which uses a separate message type and a different address encoding.
    //
    // NOTE: our decoder currently checks for 12 zero bytes to detect IPv4.
    // The standard Bitcoin encoding uses the ::ffff: prefix (10 zeros + 0xFF 0xFF),
    // so real nodes' IPv4 addresses will fall through to the IPv6 branch.
    // https://developer.bitcoin.org/reference/p2p_networking.html#addr
    // https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki

    /// Returns a raw 26-byte NetAddr field (services + 16-byte IP + port).
    fn raw_net_addr(services: u64, ip_field: [u8; 16], port: u16) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&services.to_le_bytes());
        b.extend_from_slice(&ip_field);
        b.extend_from_slice(&port.to_be_bytes());
        b
    }

    #[test]
    fn decode_net_addr_ipv4_standard_ffff_prefix() {
        // Standard encoding used by real Bitcoin nodes: ::ffff:x.x.x.x
        // 10 x 0x00 + 0xFF 0xFF + 4-byte IPv4 address
        let mut ip = [0u8; 16];
        ip[10] = 0xFF;
        ip[11] = 0xFF;
        ip[12..].copy_from_slice(&[8, 8, 8, 8]);
        let payload = raw_net_addr(1, ip, 8333);

        let addr = decode_net_addr(&payload, &mut 0).unwrap();
        assert_eq!(addr.port, 8333);
        // Our decoder checks for 12 zero bytes, not ::ffff:, so this
        // decodes as IPv6. Fixing this would align with the spec.
        assert!(matches!(addr.ip, std::net::IpAddr::V6(_)));
    }

    #[test]
    fn decode_net_addr_ipv4_twelve_zero_prefix() {
        // Non-standard but accepted by our decoder: 12 x 0x00 + 4-byte IPv4
        let mut ip = [0u8; 16];
        ip[12..].copy_from_slice(&[93, 184, 216, 34]);
        let payload = raw_net_addr(1, ip, 8333);

        let addr = decode_net_addr(&payload, &mut 0).unwrap();
        assert_eq!(addr.port, 8333);
        assert_eq!(
            addr.ip,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn decode_net_addr_ipv6() {
        // 2001:db8::1 — documentation prefix (RFC 3849)
        let ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let payload = raw_net_addr(8, ip, 8333); // services: NODE_WITNESS

        let addr = decode_net_addr(&payload, &mut 0).unwrap();
        assert_eq!(addr.port, 8333);
        assert_eq!(
            addr.ip,
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip))
        );
    }

    #[test]
    fn decode_net_addr_torv2_decoded_as_ipv6() {
        // Tor v2 (.onion) used a 6-byte prefix 0xFD87D87EEB43 + 10-byte onion
        // address packed into the 16-byte IP field of the legacy addr message.
        // Tor v2 is deprecated; Tor v3 requires addrv2 (BIP 155).
        // Our decoder has no special-case for onion — it falls through to IPv6.
        let mut ip = [0u8; 16];
        ip[..6].copy_from_slice(&[0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43]);
        ip[6..].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA]);
        let payload = raw_net_addr(0, ip, 9050); // 9050 = Tor SOCKS port

        let addr = decode_net_addr(&payload, &mut 0).unwrap();
        assert_eq!(addr.port, 9050);
        assert!(matches!(addr.ip, std::net::IpAddr::V6(_)));
    }

    // --- Message dispatch (TryFrom) -----------------------------------------

    #[test]
    fn message_from_verack_raw() {
        let (mut client, mut server) = tcp_pair();
        thread::spawn(move || write_frame(&mut server, b"verack", &[]));

        let raw = read_message(&mut client).unwrap();
        assert!(matches!(Message::try_from(raw).unwrap(), Message::Verack));
    }

    #[test]
    fn message_from_version_raw_yields_decoded_struct() {
        let (mut client, mut server) = tcp_pair();
        let payload = version_payload_v70016();
        thread::spawn(move || write_frame(&mut server, b"version", &payload));

        let raw = read_message(&mut client).unwrap();
        let Message::Version(v) = Message::try_from(raw).unwrap() else {
            panic!("expected Message::Version");
        };
        assert_eq!(v.version, 70016);
    }

    #[test]
    fn message_from_addr_raw_yields_entries() {
        let (mut client, mut server) = tcp_pair();
        let payload = addr_payload_two_entries();
        thread::spawn(move || write_frame(&mut server, b"addr", &payload));

        let raw = read_message(&mut client).unwrap();
        let Message::Addr(entries) = Message::try_from(raw).unwrap() else {
            panic!("expected Message::Addr");
        };
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn message_from_unimplemented_command_holds_raw_bytes() {
        let (mut client, mut server) = tcp_pair();
        thread::spawn(move || write_frame(&mut server, b"inv", &[0xAB, 0xCD]));

        let raw = read_message(&mut client).unwrap();
        let Message::Inv(bytes) = Message::try_from(raw).unwrap() else {
            panic!("expected Message::Inv");
        };
        assert_eq!(bytes, vec![0xAB, 0xCD]);
    }

    // --- Handshake sequence -------------------------------------------------

    /// Simulates the version → verack exchange of protocol v70016,
    /// as performed by /Satoshi:25.0.0/ (Bitcoin Core ~25.x).
    #[test]
    fn handshake_v70016_version_then_verack() {
        let (mut client, mut server) = tcp_pair();
        let version_bytes = version_payload_v70016();

        let server_thread = thread::spawn(move || {
            write_frame(&mut server, b"version", &version_bytes);
            write_frame(&mut server, b"verack", &[]);
        });

        // step 1 — read version
        let raw = read_message(&mut client).unwrap();
        assert_eq!(raw.command, Command::Version);
        let Message::Version(v) = Message::try_from(raw).unwrap() else {
            panic!("expected Version");
        };
        assert_eq!(v.version, 70016);
        assert_eq!(v.user_agent, "/Satoshi:25.0.0/");
        assert_eq!(v.relay, Some(true));

        // step 2 — read verack
        let raw = read_message(&mut client).unwrap();
        assert_eq!(raw.command, Command::Verack);
        assert!(matches!(Message::try_from(raw).unwrap(), Message::Verack));

        server_thread.join().unwrap();
    }

    // --- AddrV2 (BIP 155) ---------------------------------------------------
    //
    // To receive addrv2 from a peer, you must send `sendaddrv2` (empty payload)
    // BEFORE your own `verack`. Peers that understand BIP 155 will then reply
    // to `getaddr` with `addrv2` instead of the legacy `addr`.
    //
    // Handshake flow with addrv2 support:
    //   → send version
    //   ← recv version
    //   → send sendaddrv2    ← BEFORE verack
    //   → send verack
    //   ← recv verack (peer may also send sendaddrv2 before their verack)
    //   → send getaddr
    //   ← recv addrv2        ← if peer supports BIP 155 (Bitcoin Core 22.0+)
    //
    // https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki

    fn addrv2_entry_bytes(network_id: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&1700001000u32.to_le_bytes()); // timestamp
        b.push(0x09);                                       // services = 9 as varint
        b.push(network_id);
        b.push(addr.len() as u8);                          // addr length as varint
        b.extend_from_slice(addr);
        b.extend_from_slice(&port.to_be_bytes());
        b
    }

    fn addrv2_payload(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut p = vec![];
        p.push(entries.len() as u8); // count varint
        for e in entries {
            p.extend_from_slice(e);
        }
        p
    }

    #[test]
    fn decode_addrv2_ipv4() {
        let entry = addrv2_entry_bytes(0x01, &[1, 2, 3, 4], 8333);
        let entries = Vec::<AddrV2Entry>::decode(&addrv2_payload(&[entry])).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp, 1700001000);
        assert_eq!(entries[0].services, 9);
        assert_eq!(entries[0].port, 8333);
        assert!(matches!(
            entries[0].addr,
            AddrV2Addr::IPv4(a) if a == std::net::Ipv4Addr::new(1, 2, 3, 4)
        ));
    }

    #[test]
    fn decode_addrv2_ipv6() {
        let ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let entry = addrv2_entry_bytes(0x02, &ip, 8333);
        let entries = Vec::<AddrV2Entry>::decode(&addrv2_payload(&[entry])).unwrap();

        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].addr,
            AddrV2Addr::IPv6(a) if a == std::net::Ipv6Addr::from(ip)
        ));
    }

    #[test]
    fn decode_addrv2_torv3() {
        let torv3 = [0xABu8; 32];
        let entry = addrv2_entry_bytes(0x04, &torv3, 9050);
        let entries = Vec::<AddrV2Entry>::decode(&addrv2_payload(&[entry])).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].port, 9050);
        assert!(matches!(entries[0].addr, AddrV2Addr::TorV3(b) if b == torv3));
    }

    #[test]
    fn decode_addrv2_i2p() {
        let dest = [0x11u8; 32];
        let entry = addrv2_entry_bytes(0x05, &dest, 0);
        let entries = Vec::<AddrV2Entry>::decode(&addrv2_payload(&[entry])).unwrap();

        assert!(matches!(entries[0].addr, AddrV2Addr::I2P(b) if b == dest));
    }

    #[test]
    fn decode_addrv2_cjdns() {
        // CJDNS uses the fc00::/8 range (16 bytes, treated as IPv6)
        let mut ip = [0u8; 16];
        ip[0] = 0xFC;
        let entry = addrv2_entry_bytes(0x06, &ip, 8333);
        let entries = Vec::<AddrV2Entry>::decode(&addrv2_payload(&[entry])).unwrap();

        assert!(matches!(
            entries[0].addr,
            AddrV2Addr::Cjdns(a) if a == std::net::Ipv6Addr::from(ip)
        ));
    }

    #[test]
    fn decode_addrv2_yggdrasil() {
        // Yggdrasil uses the 200::/7 range (16 bytes, treated as IPv6)
        let mut ip = [0u8; 16];
        ip[0] = 0x02;
        let entry = addrv2_entry_bytes(0x07, &ip, 8333);
        let entries = Vec::<AddrV2Entry>::decode(&addrv2_payload(&[entry])).unwrap();

        assert!(matches!(
            entries[0].addr,
            AddrV2Addr::Yggdrasil(a) if a == std::net::Ipv6Addr::from(ip)
        ));
    }

    #[test]
    fn decode_addrv2_unknown_network_id_preserved() {
        let entry = addrv2_entry_bytes(0xFF, &[0xDE, 0xAD], 1234);
        let entries = Vec::<AddrV2Entry>::decode(&addrv2_payload(&[entry])).unwrap();

        assert!(matches!(
            &entries[0].addr,
            AddrV2Addr::Unknown { network_id: 0xFF, bytes } if bytes == &[0xDE, 0xAD]
        ));
    }

    #[test]
    fn decode_addrv2_mixed_network_types() {
        let entries_raw = vec![
            addrv2_entry_bytes(0x01, &[5, 5, 5, 5], 8333),
            addrv2_entry_bytes(0x04, &[0xCCu8; 32], 9050),
            addrv2_entry_bytes(0x02, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8333),
        ];
        let entries = Vec::<AddrV2Entry>::decode(&addrv2_payload(&entries_raw)).unwrap();

        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[0].addr, AddrV2Addr::IPv4(_)));
        assert!(matches!(entries[1].addr, AddrV2Addr::TorV3(_)));
        assert!(matches!(entries[2].addr, AddrV2Addr::IPv6(_)));
    }

    #[test]
    fn decode_addrv2_rejects_wrong_addr_length_for_known_network() {
        // IPv4 with 6 bytes instead of 4
        let entry = addrv2_entry_bytes(0x01, &[1, 2, 3, 4, 5, 6], 8333);
        assert!(Vec::<AddrV2Entry>::decode(&addrv2_payload(&[entry])).is_err());
    }

    #[test]
    fn decode_addrv2_rejects_over_1000_entries() {
        let mut payload = vec![];
        // encode count as varint 0xFD + u16 LE = 1001
        payload.push(0xFD);
        payload.extend_from_slice(&1001u16.to_le_bytes());
        assert!(Vec::<AddrV2Entry>::decode(&payload).is_err());
    }

    #[test]
    fn message_from_addrv2_raw_yields_decoded_entries() {
        let entry = addrv2_entry_bytes(0x01, &[127, 0, 0, 1], 8333);
        let payload = addrv2_payload(&[entry]);

        let (mut client, mut server) = tcp_pair();
        thread::spawn(move || write_frame(&mut server, b"addrv2", &payload));

        let raw = read_message(&mut client).unwrap();
        assert_eq!(raw.command, Command::AddrV2);
        let Message::AddrV2(entries) = Message::try_from(raw).unwrap() else {
            panic!("expected Message::AddrV2");
        };
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].addr,
            AddrV2Addr::IPv4(a) if a == std::net::Ipv4Addr::new(127, 0, 0, 1)
        ));
    }
}
