use crate::wire::constants::MAIN_NET_MAGIC;
use crate::wire::message::{Command, RawMessage};
use std::io::{self, Read, Write};

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
/// use btc_network::wire::{self};
/// use btc_network::wire::message::{Command};
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
/// let raw = wire::codec::read_message(&mut cursor).unwrap();
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
/// use btc_network::wire::{self};
/// use btc_network::wire::message::{Command};
///
/// let mut buffer = Vec::new();
///
/// wire::codec::send_message(&mut buffer, Command::Verack, &[]).unwrap();
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

    writer.write_u32::<LittleEndian>(MAIN_NET_MAGIC)?;

    writer.write_all(&command.as_bytes())?;

    writer.write_u32::<LittleEndian>(payload.len() as u32)?;

    let checksum = Sha256::digest(Sha256::digest(payload));
    writer.write_all(&checksum[..4])?;

    writer.write_all(payload)?;

    Ok(())
}

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
}
