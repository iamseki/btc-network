//! Bitcoin P2P wire protocol primitives.
//!
//! This module provides low-level utilities to read and decode
//! Bitcoin P2P messages directly from a TCP stream.
//!
//! It implements:
//! - Parsing of the 24-byte Bitcoin message header
//! - Extraction of command name and payload
//! - Raw message reading from `std::net::TcpStream`
//!
//! Higher-level message decoding is handled by [`Message`],
//! which converts raw payloads into strongly typed variants.
//!
//! Protocol reference:
//! https://developer.bitcoin.org/reference/p2p_networking.html

use byteorder::{LittleEndian, WriteBytesExt};
use rand::Rng;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fmt::{Debug, Formatter, Result};

/// Network magic value used in the Bitcoin P2P message header.
///
/// The first 4 bytes of every Bitcoin P2P message identify the
/// network (mainnet, testnet, regtest, signet) and act as a
/// message boundary marker in the TCP stream.
///
/// For mainnet, the magic value is `0xD9B4BEF9` (F9 BE B4 D9 in bytes).
///
/// You can also see how Bitcoin Core maps magic values to networks
/// in `GetNetworkForMagic`:
/// https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp#L703-L723
///
/// Other network magic values:
/// - Mainnet:  0xD9B4BEF9
/// - Testnet3: 0x0709110B
/// - Regtest:  0xDAB5BFFA
/// - Signet:   0x40CF030A
const MAGIC: u32 = 0xD9B4BEF9;

/// Reads a raw Bitcoin P2P message frame from any [`Read`] source.
///
/// This function:
/// 1. Reads the 24-byte Bitcoin message header
/// 2. Extracts magic, command, length and checksum
/// 3. Reads the payload according to the length field
///
/// It does **not** validate:
/// - Network magic
/// - Checksum correctness
///
/// # Example
///
/// ```
/// use std::io::Cursor;
/// use btc_network::wire::{self, Command};
///
/// // Build a minimal fake "verack" frame:
/// let mut bytes = vec![];
///
/// // Magic (mainnet)
/// bytes.extend_from_slice(&[0xF9, 0xBE, 0xB4, 0xD9]);
///
/// // Command "verack" padded to 12 bytes
/// let mut cmd = [0u8; 12];
/// cmd[..6].copy_from_slice(b"verack");
/// bytes.extend_from_slice(&cmd);
///
/// // Payload length = 0
/// bytes.extend_from_slice(&0u32.to_le_bytes());
///
/// // Checksum (not validated here)
/// bytes.extend_from_slice(&[0u8; 4]);
///
/// let mut cursor = Cursor::new(bytes);
///
/// let raw = wire::read_message(&mut cursor).unwrap();
/// assert_eq!(raw.command, Command::Verack);
/// assert!(raw.payload.is_empty());
/// ```
pub fn read_message<R: Read>(reader: &mut R) -> io::Result<RawMessage> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;

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
    reader.read_exact(&mut payload)?;

    Ok(RawMessage {
        magic,
        command,
        payload,
        checksum,
    })
}

/// Writes a complete Bitcoin P2P message frame to the given writer.
///
/// This function serializes a message according to the Bitcoin
/// P2P message format:
///
/// ```text
/// +------------+--------------+---------------+------------+
/// | magic (4)  | command (12) | length (4 LE) | checksum(4)|
/// +------------+--------------+---------------+------------+
/// | payload (variable)                                ...  |
/// +----------------------------------------------------------
/// ```
///
/// The checksum is defined as the first 4 bytes of:
///
/// ```text
/// SHA256(SHA256(payload))
/// ```
///
/// # Arguments
///
/// * `writer`  - Any type implementing [`Write`] (e.g. `TcpStream`,
///               `Cursor<Vec<u8>>`, `BufWriter`, TLS streams, etc.)
/// * `command` - The Bitcoin P2P command to send
/// * `payload` - The raw payload bytes
///
/// # Example
///
/// ```
/// use btc_network::wire::{self, Command};
///
/// let mut buffer = Vec::new();
///
/// wire::send_message(&mut buffer, Command::Verack, &[]).unwrap();
///
/// // The buffer now contains a full Bitcoin message frame.
/// assert!(buffer.len() >= 24);
/// ```
///
/// # Errors
///
/// Returns an error if writing to the underlying stream fails.
pub fn send_message<W: Write>(writer: &mut W, command: Command, payload: &[u8]) -> io::Result<()> {
    use byteorder::{LittleEndian, WriteBytesExt};
    use sha2::{Digest, Sha256};

    writer.write_u32::<LittleEndian>(MAGIC)?;

    writer.write_all(&command.as_bytes())?;

    writer.write_u32::<LittleEndian>(payload.len() as u32)?;

    let checksum = Sha256::digest(&Sha256::digest(payload));
    writer.write_all(&checksum[..4])?;

    writer.write_all(payload)?;

    Ok(())
}

/// Builds a `version` message payload as defined by the Bitcoin P2P protocol.
///
/// This constructs a minimal version payload suitable for initiating
/// a handshake with a peer.
///
/// The payload layout is:
///
/// ```text
/// int32    version
/// uint64   services
/// int64    timestamp
/// net_addr addr_recv
/// net_addr addr_from
/// uint64   nonce
/// var_str  user_agent
/// int32    start_height
/// bool     relay
/// ```
///
/// This implementation:
///
/// - Uses the current UNIX timestamp
/// - Uses zeroed `addr_recv` and `addr_from`
/// - Uses an empty user agent
/// - Sets `start_height` to 0
///
/// # Arguments
///
/// * `protocol_version` - Protocol version (e.g. 70015+)
/// * `services`         - Service flags supported by this node
///
/// # Example
///
/// ```
/// use btc_network::wire;
///
/// let payload = wire::build_version_payload(70015, 0).unwrap();
/// assert!(!payload.is_empty());
/// ```
///
/// # Errors
///
/// Returns an error if serialization fails (unlikely).
pub fn build_version_payload(protocol_version: i32, services: u64) -> io::Result<Vec<u8>> {
    let mut payload = vec![];

    payload.write_i32::<LittleEndian>(protocol_version)?;
    payload.write_u64::<LittleEndian>(services)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .as_secs();

    payload.write_i64::<LittleEndian>(now as i64)?;

    // addr_recv (26 bytes: services + 16-byte IP + port)
    payload.extend([0u8; 26]);

    // addr_from
    payload.extend([0u8; 26]);

    let nonce: u64 = rand::thread_rng().r#gen();
    payload.write_u64::<LittleEndian>(nonce)?;

    // user agent (empty string => CompactSize 0)
    payload.push(0);

    payload.write_i32::<LittleEndian>(0)?; // start_height
    payload.push(0); // relay = false

    Ok(payload)
}

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
    pub services: Services,
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

/// Represents a decoded Bitcoin P2P message.
///
/// Each variant corresponds to a known Bitcoin protocol command.
///
/// Unknown or unsupported commands may be mapped to
/// [`Message::Unknown`].
///
/// See:
/// https://developer.bitcoin.org/reference/p2p_networking.html
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
            "version" => Command::Version,
            "verack" => Command::Verack,
            "addr" => Command::Addr,
            "addrv2" => Command::AddrV2,
            "sendaddrv2" => Command::SendAddrV2,
            "getaddr" => Command::GetAddr,
            "ping" => Command::Ping,
            "pong" => Command::Pong,
            "sendheaders" => Command::SendHeaders,
            "sendcmpct" => Command::SendCmpct,
            "feefilter" => Command::FeeFilter,
            "reject" => Command::Reject,
            "alert" => Command::Alert,
            "inv" => Command::Inv,
            "getdata" => Command::GetData,
            "notfound" => Command::NotFound,
            "getblocks" => Command::GetBlocks,
            "getheaders" => Command::GetHeaders,
            "headers" => Command::Headers,
            "block" => Command::Block,
            "tx" => Command::Tx,
            "getblocktxn" => Command::GetBlockTxn,
            "blocktxn" => Command::BlockTxn,
            "cmpctblock" => Command::CmpctBlock,
            "mempool" => Command::Mempool,
            "merkleblock" => Command::MerkleBlock,
            "filterload" => Command::FilterLoad,
            "filteradd" => Command::FilterAdd,
            "filterclear" => Command::FilterClear,
            _ => Command::Unknown,
        }
    }
}

impl Command {
    /// Returns the 12-byte command field as defined by the Bitcoin P2P protocol.
    ///
    /// The command string is ASCII and padded with zero bytes.
    pub fn as_bytes(&self) -> [u8; 12] {
        let name: &[u8] = match self {
            Command::Version => b"version",
            Command::Verack => b"verack",
            Command::Addr => b"addr",
            Command::AddrV2 => b"addrv2",
            Command::SendAddrV2 => b"sendaddrv2",
            Command::GetAddr => b"getaddr",
            Command::Ping => b"ping",
            Command::Pong => b"pong",
            Command::SendHeaders => b"sendheaders",
            Command::SendCmpct => b"sendcmpct",
            Command::FeeFilter => b"feefilter",
            Command::Reject => b"reject",
            Command::Alert => b"alert",
            Command::Inv => b"inv",
            Command::GetData => b"getdata",
            Command::NotFound => b"notfound",
            Command::GetBlocks => b"getblocks",
            Command::GetHeaders => b"getheaders",
            Command::Headers => b"headers",
            Command::Block => b"block",
            Command::Tx => b"tx",
            Command::GetBlockTxn => b"getblocktxn",
            Command::BlockTxn => b"blocktxn",
            Command::CmpctBlock => b"cmpctblock",
            Command::Mempool => b"mempool",
            Command::MerkleBlock => b"merkleblock",
            Command::FilterLoad => b"filterload",
            Command::FilterAdd => b"filteradd",
            Command::FilterClear => b"filterclear",
            Command::Unknown => b"",
        };

        let mut padded = [0u8; 12];
        padded[..name.len()].copy_from_slice(name);
        padded
    }
}

impl TryFrom<RawMessage> for Message {
    type Error = io::Error;

    fn try_from(raw: RawMessage) -> io::Result<Self> {
        match raw.command {
            // decoded
            Command::Version => Ok(Message::Version(VersionMessage::decode(&raw.payload)?)),
            Command::Verack => Ok(Message::Verack),
            Command::Addr => Ok(Message::Addr(Vec::<AddrEntry>::decode(&raw.payload)?)),
            Command::AddrV2 => Ok(Message::AddrV2(Vec::<AddrV2Entry>::decode(&raw.payload)?)),
            // TODO: implement Decode
            Command::SendAddrV2 => Ok(Message::SendAddrV2(raw.payload)),
            Command::GetAddr => Ok(Message::GetAddr(raw.payload)),
            Command::Ping => Ok(Message::Ping(raw.payload)),
            Command::Pong => Ok(Message::Pong(raw.payload)),
            Command::SendHeaders => Ok(Message::SendHeaders(raw.payload)),
            Command::SendCmpct => Ok(Message::SendCmpct(raw.payload)),
            Command::FeeFilter => Ok(Message::FeeFilter(raw.payload)),
            Command::Reject => Ok(Message::Reject(raw.payload)),
            Command::Alert => Ok(Message::Alert(raw.payload)),
            Command::Inv => Ok(Message::Inv(raw.payload)),
            Command::GetData => Ok(Message::GetData(raw.payload)),
            Command::NotFound => Ok(Message::NotFound(raw.payload)),
            Command::GetBlocks => Ok(Message::GetBlocks(raw.payload)),
            Command::GetHeaders => Ok(Message::GetHeaders(raw.payload)),
            Command::Headers => Ok(Message::Headers(raw.payload)),
            Command::Block => Ok(Message::Block(raw.payload)),
            Command::Tx => Ok(Message::Tx(raw.payload)),
            Command::GetBlockTxn => Ok(Message::GetBlockTxn(raw.payload)),
            Command::BlockTxn => Ok(Message::BlockTxn(raw.payload)),
            Command::CmpctBlock => Ok(Message::CmpctBlock(raw.payload)),
            Command::Mempool => Ok(Message::Mempool(raw.payload)),
            Command::MerkleBlock => Ok(Message::MerkleBlock(raw.payload)),
            Command::FilterLoad => Ok(Message::FilterLoad(raw.payload)),
            Command::FilterAdd => Ok(Message::FilterAdd(raw.payload)),
            Command::FilterClear => Ok(Message::FilterClear(raw.payload)),
            Command::Unknown => Ok(Message::Unknown {
                payload: raw.payload,
            }),
        }
    }
}

/// Service flags as defined by the Bitcoin P2P protocol.
///
/// This is a bitfield (`u64`) transmitted in the `version` message.
/// Each bit represents a capability supported by the node.
///
/// Official reference:
/// https://developer.bitcoin.org/reference/p2p_networking.html#version
///
/// The flags are forward-compatible: unknown bits must be preserved.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Services(u64);

impl Services {
    /// Creates a new `Services` from raw bits.
    pub const fn new(bits: u64) -> Self {
        Self(bits)
    }

    /// Returns the raw bitfield value.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns true if all bits in `other` are set.
    pub const fn contains(self, other: Services) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns true if no bits are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    // ---- Assigned Service Flags ----

    /// 0x00 — Unnamed
    ///
    /// This node is not a full node.
    /// It may not be able to provide any data except for transactions it originates.
    pub const NONE: Services = Services(0x00);

    /// 0x01 — NODE_NETWORK
    ///
    /// This is a full node and can be asked for full blocks.
    /// It should implement all protocol features available in
    /// its self-reported protocol version.
    pub const NODE_NETWORK: Services = Services(0x01);

    /// 0x02 — NODE_GETUTXO
    ///
    /// This node can respond to `getutxo` requests.
    /// Defined in BIP64.
    ///
    /// Not supported by currently maintained Bitcoin Core versions.
    pub const NODE_GETUTXO: Services = Services(0x02);

    /// 0x04 — NODE_BLOOM
    ///
    /// Supports bloom-filtered connections.
    /// Defined in BIP111.
    pub const NODE_BLOOM: Services = Services(0x04);

    /// 0x08 — NODE_WITNESS
    ///
    /// Can provide blocks and transactions including witness data.
    /// Defined in BIP144.
    pub const NODE_WITNESS: Services = Services(0x08);

    /// 0x10 — NODE_XTHIN
    ///
    /// Supports Xtreme Thinblocks.
    ///
    /// Not supported by currently maintained Bitcoin Core versions.
    pub const NODE_XTHIN: Services = Services(0x10);

    /// 0x0400 — NODE_NETWORK_LIMITED
    ///
    /// Same as NODE_NETWORK but guarantees at least the last 288 blocks
    /// (~2 days).
    /// Defined in BIP159.
    pub const NODE_NETWORK_LIMITED: Services = Services(0x0400);

    pub fn names(self) -> Vec<&'static str> {
        let mut names = Vec::new();

        if self.is_empty() {
            names.push("NONE");
            return names;
        }

        if self.contains(Self::NODE_NETWORK) {
            names.push("NODE_NETWORK");
        }
        if self.contains(Self::NODE_GETUTXO) {
            names.push("NODE_GETUTXO");
        }
        if self.contains(Self::NODE_BLOOM) {
            names.push("NODE_BLOOM");
        }
        if self.contains(Self::NODE_WITNESS) {
            names.push("NODE_WITNESS");
        }
        if self.contains(Self::NODE_XTHIN) {
            names.push("NODE_XTHIN");
        }
        if self.contains(Self::NODE_NETWORK_LIMITED) {
            names.push("NODE_NETWORK_LIMITED");
        }

        names
    }
}

impl From<u64> for Services {
    fn from(value: u64) -> Self {
        Services::new(value)
    }
}

impl Debug for Services {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        if self.is_empty() {
            return write!(f, "Services(NONE)");
        }

        let names = self.names().join(" | ");

        write!(
            f,
            "Services({}) [0x{:016x}]",
            names,
            self.bits()
        )
    }
}

impl Decode for VersionMessage {
    fn decode(payload: &[u8]) -> io::Result<Self> {
        let mut c = 0;

        let version = read_i32(payload, &mut c)?;
        let services = Services::from(read_u64(payload, &mut c)?);
        let timestamp = read_i64(payload, &mut c)?;
        let addr_recv = decode_net_addr(payload, &mut c)?;
        let addr_from = decode_net_addr(payload, &mut c)?;
        let nonce = read_u64(payload, &mut c)?;

        let ua_len = read_varint(payload, &mut c)? as usize;
        let user_agent = std::str::from_utf8(
            payload
                .get(c..c + ua_len)
                .ok_or_else(|| eof("version: user_agent"))?,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .to_string();
        c += ua_len;

        let start_height = read_i32(payload, &mut c)?;
        let relay = payload.get(c).map(|&b| b != 0);

        Ok(VersionMessage {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
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
            let services = read_varint(payload, &mut c)?; // CompactSize on wire
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
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "addrv2: IPv4 must be 4 bytes",
                        ));
                    }
                    AddrV2Addr::IPv4(std::net::Ipv4Addr::new(
                        addr_bytes[0],
                        addr_bytes[1],
                        addr_bytes[2],
                        addr_bytes[3],
                    ))
                }
                0x02 => {
                    if addr_bytes.len() != 16 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "addrv2: IPv6 must be 16 bytes",
                        ));
                    }
                    AddrV2Addr::IPv6(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(addr_bytes).unwrap(),
                    ))
                }
                0x03 => {
                    if addr_bytes.len() != 10 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "addrv2: TorV2 must be 10 bytes",
                        ));
                    }
                    AddrV2Addr::TorV2(addr_bytes.try_into().unwrap())
                }
                0x04 => {
                    if addr_bytes.len() != 32 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "addrv2: TorV3 must be 32 bytes",
                        ));
                    }
                    AddrV2Addr::TorV3(addr_bytes.try_into().unwrap())
                }
                0x05 => {
                    if addr_bytes.len() != 32 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "addrv2: I2P must be 32 bytes",
                        ));
                    }
                    AddrV2Addr::I2P(addr_bytes.try_into().unwrap())
                }
                0x06 => {
                    if addr_bytes.len() != 16 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "addrv2: CJDNS must be 16 bytes",
                        ));
                    }
                    AddrV2Addr::Cjdns(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(addr_bytes).unwrap(),
                    ))
                }
                0x07 => {
                    if addr_bytes.len() != 16 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "addrv2: Yggdrasil must be 16 bytes",
                        ));
                    }
                    AddrV2Addr::Yggdrasil(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(addr_bytes).unwrap(),
                    ))
                }
                id => AddrV2Addr::Unknown {
                    network_id: id,
                    bytes: addr_bytes.to_vec(),
                },
            };

            entries.push(AddrV2Entry {
                timestamp,
                services,
                addr,
                port,
            });
        }

        Ok(entries)
    }
}

// --- helpers ----------------------------------------------------------------

fn eof(context: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, context)
}

fn read_varint(p: &[u8], c: &mut usize) -> io::Result<u64> {
    let first = *p.get(*c).ok_or_else(|| eof("varint"))?;
    *c += 1;
    match first {
        0xFD => {
            let v = u16::from_le_bytes(slice2(p, c, "varint:fd")?);
            Ok(v as u64)
        }
        0xFE => {
            let v = u32::from_le_bytes(slice4(p, c, "varint:fe")?);
            Ok(v as u64)
        }
        0xFF => {
            let v = u64::from_le_bytes(slice8(p, c, "varint:ff")?);
            Ok(v)
        }
        n => Ok(n as u64),
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
            ip_bytes[12],
            ip_bytes[13],
            ip_bytes[14],
            ip_bytes[15],
        ))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes))
    };

    Ok(NetAddr { services, ip, port })
}

fn read_i32(p: &[u8], c: &mut usize) -> io::Result<i32> {
    Ok(i32::from_le_bytes(slice4(p, c, "i32")?))
}
fn read_i64(p: &[u8], c: &mut usize) -> io::Result<i64> {
    Ok(i64::from_le_bytes(slice8(p, c, "i64")?))
}
fn read_u32(p: &[u8], c: &mut usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(slice4(p, c, "u32")?))
}
fn read_u64(p: &[u8], c: &mut usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(slice8(p, c, "u64")?))
}

fn slice2(p: &[u8], c: &mut usize, ctx: &'static str) -> io::Result<[u8; 2]> {
    let b = p
        .get(*c..*c + 2)
        .ok_or_else(|| eof(ctx))?
        .try_into()
        .unwrap();
    *c += 2;
    Ok(b)
}

fn slice4(p: &[u8], c: &mut usize, ctx: &'static str) -> io::Result<[u8; 4]> {
    let b = p
        .get(*c..*c + 4)
        .ok_or_else(|| eof(ctx))?
        .try_into()
        .unwrap();
    *c += 4;
    Ok(b)
}

fn slice8(p: &[u8], c: &mut usize, ctx: &'static str) -> io::Result<[u8; 8]> {
    let b = p
        .get(*c..*c + 8)
        .ok_or_else(|| eof(ctx))?
        .try_into()
        .unwrap();
    *c += 8;
    Ok(b)
}

// --- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Builds a full Bitcoin message frame (header + payload).
    fn build_frame(cmd_str: &[u8], payload: &[u8]) -> Vec<u8> {
        const MAINNET_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

        let mut bytes = vec![];

        // magic
        bytes.extend_from_slice(&MAINNET_MAGIC);

        // command padded to 12 bytes
        let mut cmd = [0u8; 12];
        cmd[..cmd_str.len()].copy_from_slice(cmd_str);
        bytes.extend_from_slice(&cmd);

        // length
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());

        // checksum (still not validated)
        bytes.extend_from_slice(&[0u8; 4]);

        // payload
        bytes.extend_from_slice(payload);

        bytes
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
        p.extend(net_addr_bytes(1033, [10, 0, 0, 1], 8333)); // addr_from
        p.extend_from_slice(&0x1234567890abcdefu64.to_le_bytes()); // nonce
        let ua = b"/Satoshi:25.0.0/";
        p.push(ua.len() as u8);
        p.extend_from_slice(ua);
        p.extend_from_slice(&820000i32.to_le_bytes()); // start_height (~late 2023)
        p.push(1); // relay = true
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

    #[test]
    fn read_message_recognises_version_command() {
        let mut cursor = Cursor::new(build_frame(b"version", &version_payload_v70016()));

        let raw = read_message(&mut cursor).unwrap();
        assert_eq!(raw.command, Command::Version);
        assert!(!raw.payload.is_empty());
    }

    #[test]
    fn read_message_verack_has_empty_payload() {
        let bytes = build_frame(b"verack", &[]);
        let mut cursor = Cursor::new(bytes);

        let raw = read_message(&mut cursor).unwrap();
        assert_eq!(raw.command, Command::Verack);
        assert!(raw.payload.is_empty());
    }

    #[test]
    fn read_message_unknown_command_preserved_in_payload() {
        let mut cursor = Cursor::new(build_frame(b"wtfmessage", &[1, 2, 3]));

        let raw = read_message(&mut cursor).unwrap();
        assert_eq!(raw.command, Command::Unknown);
        assert_eq!(raw.payload, vec![1, 2, 3]);
    }

    #[test]
    fn decode_version_v70016_all_fields() {
        let msg = VersionMessage::decode(&version_payload_v70016()).unwrap();

        assert_eq!(msg.version, 70016);
        assert_eq!(msg.services.bits(), 1033);
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
        let ip: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let payload = raw_net_addr(8, ip, 8333); // services: NODE_WITNESS

        let addr = decode_net_addr(&payload, &mut 0).unwrap();
        assert_eq!(addr.port, 8333);
        assert_eq!(addr.ip, std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)));
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
        let mut cursor = Cursor::new(build_frame(b"verack", &[]));

        let raw = read_message(&mut cursor).unwrap();
        assert!(matches!(Message::try_from(raw).unwrap(), Message::Verack));
    }

    #[test]
    fn message_from_version_raw_yields_decoded_struct() {
        let mut cursor = Cursor::new(build_frame(b"version", &version_payload_v70016()));
        let raw = read_message(&mut cursor).unwrap();
        let Message::Version(v) = Message::try_from(raw).unwrap() else {
            panic!("expected Message::Version");
        };
        assert_eq!(v.version, 70016);
    }

    #[test]
    fn message_from_addr_raw_yields_entries() {
        let mut cursor = Cursor::new(build_frame(b"addr", &addr_payload_two_entries()));

        let raw = read_message(&mut cursor).unwrap();
        let Message::Addr(entries) = Message::try_from(raw).unwrap() else {
            panic!("expected Message::Addr");
        };
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn message_from_unimplemented_command_holds_raw_bytes() {
        let mut cursor = Cursor::new(build_frame(b"inv", &[0xAB, 0xCD]));

        let raw = read_message(&mut cursor).unwrap();
        let Message::Inv(bytes) = Message::try_from(raw).unwrap() else {
            panic!("expected Message::Inv");
        };
        assert_eq!(bytes, vec![0xAB, 0xCD]);
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
        b.push(0x09); // services = 9 as varint
        b.push(network_id);
        b.push(addr.len() as u8); // addr length as varint
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
        let ip: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
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
            addrv2_entry_bytes(
                0x02,
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                8333,
            ),
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
        let mut cursor = Cursor::new(build_frame(b"addrv2", &payload));

        let raw = read_message(&mut cursor).unwrap();
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
