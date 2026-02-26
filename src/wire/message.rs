use sha2::{Digest, Sha256};
use std::fmt::{Debug, Formatter, Result};
use std::io::{self};

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
    pub magic: [u8; 4],
    pub checksum: [u8; 4],
}

/// Implemented by types that can be decoded from a raw Bitcoin message payload.
pub trait Decode: Sized {
    fn decode(payload: &[u8]) -> io::Result<Self>;
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
    Headers(Vec<BlockHeader>),
    Block(Block),

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

impl TryFrom<RawMessage> for Message {
    type Error = io::Error;

    fn try_from(raw: RawMessage) -> io::Result<Self> {
        match raw.command {
            // decoded
            Command::Version => Ok(Message::Version(VersionMessage::decode(&raw.payload)?)),
            Command::Verack => Ok(Message::Verack),
            Command::Addr => Ok(Message::Addr(Vec::<AddrEntry>::decode(&raw.payload)?)),
            Command::AddrV2 => Ok(Message::AddrV2(Vec::<AddrV2Entry>::decode(&raw.payload)?)),
            Command::Headers => Ok(Message::Headers(Vec::<BlockHeader>::decode(&raw.payload)?)),
            Command::Block => Ok(Message::Block(Block::decode(&raw.payload)?)),

            Command::GetHeaders => Ok(Message::GetHeaders(raw.payload)),
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

/// A Bitcoin block header (exactly 80 bytes on the wire).
///
/// The header is defined by the Bitcoin P2P protocol and is transmitted
/// inside `block` and `headers` messages.
///
/// Layout (little-endian fields unless otherwise noted):
///
/// ```text
/// 4  bytes  version
/// 32 bytes  previous block hash
/// 32 bytes  merkle root
/// 4  bytes  timestamp (Unix epoch)
/// 4  bytes  nBits (compact target encoding)
/// 4  bytes  nonce
/// ```
///
/// Total: 80 bytes
///
/// Reference:
/// https://developer.bitcoin.org/reference/block_chain.html#block-headers
///
/// In `headers` messages, each header is followed by a CompactSize
/// transaction count (always zero). The transaction data is NOT included.
/// See:
/// https://developer.bitcoin.org/reference/p2p_networking.html#headers
#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_blockhash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    /// Computes the block header hash (block ID).
    ///
    /// The block hash is defined as: SHA256(SHA256(header_bytes))
    ///
    /// This "double SHA256" construction is part of the original Bitcoin
    /// design and is used throughout the protocol for:
    ///
    /// - Block identifiers
    /// - Transaction identifiers (txid)
    /// - Merkle tree internal hashing
    ///
    /// Reference:
    /// https://developer.bitcoin.org/reference/block_chain.html#block-hashes
    ///
    /// The returned hash is in little-endian byte order, matching the
    /// internal representation used on the wire. For human-readable
    /// display (block explorers), the bytes must be reversed.
    pub fn hash(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(80);

        bytes.extend(&self.version.to_le_bytes());
        bytes.extend(&self.prev_blockhash);
        bytes.extend(&self.merkle_root);
        bytes.extend(&self.time.to_le_bytes());
        bytes.extend(&self.bits.to_le_bytes());
        bytes.extend(&self.nonce.to_le_bytes());

        // Bitcoin uses double SHA256 to reduce structural weaknesses in
        // single-round SHA256 and to harden against length-extension attacks.
        // This construction is consensus-critical and cannot be changed.
        let hash = Sha256::digest(&Sha256::digest(&bytes));

        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
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

        write!(f, "Services({}) [0x{:016x}]", names, self.bits())
    }
}

/// A minimally decoded Bitcoin block as received via the P2P `block` message.
///
/// This struct represents the serialized block payload defined by the
/// Bitcoin wire protocol:
///
/// ```text
/// block
///   block_header      (80 bytes)
///   txn_count         (CompactSize)
///   transactions[]    (raw serialized transactions)
/// ```
///
/// Reference (serialized block format):
/// https://developer.bitcoin.org/reference/block_chain.html#serialized-blocks
///
/// Transaction format reference:
/// https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
///
/// Fields:
///
/// - `header`:
///     The 80-byte block header (version, prev_blockhash, merkle_root,
///     time, bits, nonce). See [`BlockHeader`].
///
/// - `tx_count`:
///     The number of transactions in the block, decoded from the
///     CompactSize (varint) immediately following the header.
///
/// - `serialized_size`:
///     The total size in bytes of the serialized block payload as
///     received over the wire. This includes:
///     - 80-byte header
///     - CompactSize transaction count
///     - All serialized transactions
///     - Witness data (if present)
///
///     This value does NOT include the 24-byte P2P message header
///     (magic, command, length, checksum).
///
/// Notes:
///
/// - Transactions are not decoded at this stage; only the header and
///   transaction count are parsed.
/// - This struct reflects the wire-level representation, not a fully
///   validated consensus object.
/// - The block hash is derived from the double SHA256 of the 80-byte
///   header (not from the full serialized block).
///
/// See also:
/// - `block` message: https://developer.bitcoin.org/reference/p2p_networking.html#block
/// - BIP141 (SegWit serialization changes)
#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub tx_count: u64,
    pub serialized_size: usize,
}

/// Inventory object types used in `inv`, `getdata`, and `notfound` messages.
///
/// Defined by the Bitcoin P2P protocol:
/// https://developer.bitcoin.org/reference/p2p_networking.html#data-messages
///
/// These values are serialized as little-endian 32-bit unsigned integers.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryType {
    /// Error / undefined type.
    Error = 0,

    /// Transaction (legacy txid-based).
    Tx = 1,

    /// Full block.
    Block = 2,

    /// Filtered block (BIP37).
    FilteredBlock = 3,

    /// Compact block (BIP152).
    CompactBlock = 4,

    /// Witness transaction (BIP144).
    WitnessTx = 0x40000001,

    /// Witness block (BIP144).
    WitnessBlock = 0x40000002,

    /// Witness filtered block (BIP144).
    WitnessFilteredBlock = 0x40000003,
}

impl InventoryType {
    /// Serialize the inventory type to little-endian bytes for wire usage.
    pub fn to_le_bytes(self) -> [u8; 4] {
        (self as u32).to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::codec::*;
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
