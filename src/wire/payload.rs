use crate::wire::constants::PROTOCOL_VERSION;
use crate::wire::message::InventoryType;
use byteorder::{LittleEndian, WriteBytesExt};
use rand::Rng;
use std::io::{self};
use std::time::{SystemTime, UNIX_EPOCH};

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
/// * `protocol_version` - Protocol version (e.g. 70016+)
/// * `services`         - Service flags supported by this node
///
/// # Example
///
/// ```
/// use btc_network::wire;
///
/// let payload = wire::payload::build_version_payload(70016, 0).unwrap();
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

/// Builds the payload for a `getheaders` message as defined by the
/// Bitcoin P2P wire protocol.
///
/// The payload structure is:
///
/// ```text
/// int32   protocol_version
/// varint  hash_count
/// hash[]  block_locator_hashes
/// hash    hash_stop
/// ```
///
/// Semantics:
/// The peer will:
/// 1. Find the first locator hash it recognizes in its active chain.
/// 2. Return headers *after* that block in forward chronological order.
/// 3. Stop after 2000 headers or when reaching `hash_stop`.
///
/// Reference:
/// https://developer.bitcoin.org/reference/p2p_networking.html#getheaders
pub fn build_getheaders_payload(locator: &[[u8; 32]]) -> Vec<u8> {
    let mut payload = Vec::new();

    payload.extend(&PROTOCOL_VERSION.to_le_bytes());

    write_varint(locator.len() as u64, &mut payload);

    for hash in locator {
        payload.extend(hash);
    }

    // stop hash = zero (no stop)
    payload.extend([0u8; 32]);

    payload
}

/// Builds a single-inventory `getdata` payload requesting one block.
///
/// Uses `MSG_WITNESS_BLOCK` so peers can return full SegWit-aware block
/// serialization when supported.
///
/// References:
/// - `getdata` / inventory vectors:
///   https://developer.bitcoin.org/reference/p2p_networking.html#getdata
/// - Witness inventory types (BIP144):
///   https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
pub fn build_getdata_block_payload(hash: [u8; 32]) -> Vec<u8> {
    let mut payload = Vec::new();

    write_varint(1, &mut payload);

    // Request full block including witness data (BIP144).
    //
    // We use MSG_WITNESS_BLOCK (0x40000002) instead of MSG_BLOCK (2).
    //
    // Reference:
    // - BIP144: Segregated Witness (Peer Services)
    //   https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
    //
    // Semantics:
    //
    // - MSG_BLOCK (2) allows peers to send the legacy "stripped" block
    //   serialization (without witness data).
    //
    // - MSG_WITNESS_BLOCK (0x40000002) requires peers that support
    //   NODE_WITNESS to return the block including witness data.
    payload.extend(&InventoryType::WitnessBlock.to_le_bytes());

    // block hash (little-endian wire format)
    payload.extend(hash);

    payload
}

/// Writes Bitcoin `CompactSize` (varint) to output.
///
/// This matches wire encoding used by inventory counts, vector lengths,
/// and many transaction/block fields.
///
/// Reference:
/// https://developer.bitcoin.org/reference/transactions.html#compactsize-unsigned-integers
fn write_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0xFC => out.push(value as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend(&value.to_le_bytes());
        }
    }
}
