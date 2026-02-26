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
pub const MAIN_NET_MAGIC: u32 = 0xD9B4BEF9;

/// Current Bitcoin P2P protocol version.
///
/// This value is sent in the `version` message during handshake
/// and is used for peer capability negotiation and feature gating.
///
/// The protocol version is defined in Bitcoin Core:
/// https://github.com/bitcoin/bitcoin/blob/707ad466968b947b364cfc25bcb4d6895e799418/src/node/protocol_version.h#L12
///
/// It is serialized on the wire as a signed 32-bit little-endian integer.
///
/// You can find a list of notable versions here: https://developer.bitcoin.org/reference/p2p_networking.html#protocol-versions
pub const PROTOCOL_VERSION: i32 = 70016;

/// The genesis block hash for Bitcoin mainnet. This is the hash of block height 0 (the first block in the chain).
///
/// Source (Bitcoin Core):
/// https://github.com/bitcoin/bitcoin/blob/707ad466968b947b364cfc25bcb4d6895e799418/src/kernel/chainparams.cpp#L136
///
/// Important:
/// - This value is encoded in little-endian byte order, matching the
///   internal representation used on the Bitcoin wire protocol.
/// - When displayed in human-readable form (e.g. block explorers),
///   the bytes must be reversed.
///
/// Human-readable (big-endian) form:
///
/// ```text
/// 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
/// ```
///
/// The genesis block has:
/// - No parent (`prev_blockhash` = 0)
/// - Height = 0
pub const GENESIS_BLOCK_HASH_MAINNET: [u8; 32] = [
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
];
