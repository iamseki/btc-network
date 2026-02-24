mod wire;

use byteorder::{LittleEndian, WriteBytesExt};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};
use wire::Message;

const MAGIC: u32 = 0xD9B4BEF9;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed = "seed.bitcoin.sipa.be:8333";
    let addr = seed.to_socket_addrs()?.next().expect("to get socket addrs");

    println!("connecting to {addr}");

    let mut stream = TcpStream::connect(addr)?;

    // https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
    // The handshake expects:
    // 1. version messages exchanges between peers
    // 2. verack messages
    // 3. now we can communicate, and send messages like getaddr to list btc available nodes

    // 2️⃣ Send version
    let version_payload = build_version_payload();
    send_message(&mut stream, b"version", &version_payload)?;

    // 3️⃣ Read + decode version
    let msg = Message::try_from(wire::read_message(&mut stream)?)?;
    println!("Received: {:?}", msg);

    // 4️⃣ Signal BIP 155 support — must be sent BEFORE verack
    // Peers that understand addrv2 will respond to getaddr with addrv2 instead of addr.
    // Peers that don't support BIP 155 (pre Bitcoin Core 22.0) will ignore this and
    // still send the legacy addr message.
    send_message(&mut stream, b"sendaddrv2", &[])?;

    // 5️⃣ Send verack
    send_message(&mut stream, b"verack", &[])?;

    // 6️⃣ Wait for verack -- HANDSHAKE COMPLETE
    let msg = Message::try_from(wire::read_message(&mut stream)?)?;
    println!("Received: {:?}", msg);

    // 7️⃣ Request peer addresses
    send_message(&mut stream, b"getaddr", &[])?;

    // 8️⃣ Read responses — prefer addrv2 (BIP 155), fall back to legacy addr
    loop {
        let msg = Message::try_from(wire::read_message(&mut stream)?)?;
        match msg {
            Message::AddrV2(entries) => {
                println!("Received {} peer addresses (addrv2):", entries.len());
                for entry in &entries {
                    println!("  {:?}:{}", entry.addr, entry.port);
                }
                break;
            }
            Message::Addr(entries) => {
                println!("Received {} peer addresses (addr):", entries.len());
                for entry in &entries {
                    println!("  {}:{}", entry.addr.ip, entry.addr.port);
                }
                break;
            }
            other => println!("Received: {:?}", other),
        }
    }

    Ok(())
}

// everything built here is documented in: https://developer.bitcoin.org/reference/p2p_networking.html#version
fn build_version_payload() -> Vec<u8> {
    let mut payload = vec![];

    payload.write_i32::<LittleEndian>(70015).unwrap(); // protocol version (latest of 2017)
    payload.write_u64::<LittleEndian>(0).unwrap(); // services (Unnamed, not a full node)

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    payload.write_i64::<LittleEndian>(now as i64).unwrap();

    payload.extend([0u8; 26]); // addr_recv
    payload.extend([0u8; 26]); // addr_from

    payload
        .write_u64::<LittleEndian>(rand::thread_rng().r#gen())
        .unwrap(); // nonce

    payload.push(0); // user agent (empty)
    payload.write_i32::<LittleEndian>(0).unwrap(); // start height
    payload.push(0); // relay flag

    payload
}

fn send_message(stream: &mut TcpStream, command: &[u8], payload: &[u8]) -> std::io::Result<()> {
    let mut header = vec![];

    header.write_u32::<LittleEndian>(MAGIC)?;

    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command);
    header.extend(cmd);

    header.write_u32::<LittleEndian>(payload.len() as u32)?;

    let checksum = Sha256::digest(&Sha256::digest(payload));
    header.extend(&checksum[..4]);

    stream.write_all(&header)?;
    stream.write_all(payload)?;

    Ok(())
}
