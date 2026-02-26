use btc_network::wire;
use std::io::ErrorKind;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// seeds from bitcoin core node codebase: https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp#L139-L151
const SEED_NODES: &[&str] = &[
    "seed.bitcoin.sipa.be:8333",
    // "dnsseed.bluematt.me:8333",
    "seed.bitcoin.jonasschnelli.ch:8333",
    "seed.btc.petertodd.net:8333",
    "seed.bitcoin.sprovoost.nl:8333",
    "dnsseed.emzy.de:8333",
    "seed.bitcoin.wiz.biz:8333",
    "seed.mainnet.achownodes.xyz:8333",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for node in SEED_NODES {
        let seed = node.to_string();
        println!("Connecting to: {seed}");

        let addr = seed.to_socket_addrs()?.next().expect("to get socket addrs");

        let timeout = Duration::from_secs(30);
        let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                println!("Timeout connecting to {addr}, skipping...");
                continue;
            }
            Err(e) => return Err(Box::new(e)),
        };

        // https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
        // The handshake expects:
        // 1. version messages exchanges between peers
        // 2. verack messages
        // 3. now we can communicate, and send messages like getaddr to list btc available nodes

        // 2️⃣ Send version
        // protocol version (latest of 2017)
        // services (Unnamed, not a full node)
        let version_payload = wire::build_version_payload(70015, 0)?;
        wire::send_message(&mut stream, wire::Command::Version, &version_payload)?;

        // 3️⃣ Read + decode version
        let msg = wire::Message::try_from(wire::read_message(&mut stream)?)?;
        println!("Received: {:?}", msg);

        // 4️⃣ Signal BIP 155 support — must be sent BEFORE verack
        // Peers that understand addrv2 will respond to getaddr with addrv2 instead of addr.
        // Peers that don't support BIP 155 (pre Bitcoin Core 22.0) will ignore this and
        // still send the legacy addr message.
        wire::send_message(&mut stream, wire::Command::SendAddrV2, &[])?;

        // 5️⃣ Send verack
        wire::send_message(&mut stream, wire::Command::Verack, &[])?;

        // 6️⃣ Wait for verack -- HANDSHAKE COMPLETE
        let msg = wire::Message::try_from(wire::read_message(&mut stream)?)?;
        println!("Received: {:?}", msg);

        // 7️⃣ Request peer addresses
        wire::send_message(&mut stream, wire::Command::GetAddr, &[])?;

        // 8️⃣ Read responses — prefer addrv2 (BIP 155), fall back to legacy addr
        loop {
            let msg = wire::Message::try_from(wire::read_message(&mut stream)?)?;
            match msg {
                wire::Message::AddrV2(entries) => {
                    println!(
                        "Received {} peer addresses (addrv2): from {}",
                        entries.len(),
                        seed
                    );
                    for entry in &entries {
                        // println!("  {:?}:{}", entry.addr, entry.port);
                    }
                    break;
                }
                wire::Message::Addr(entries) => {
                    println!(
                        "Received {} peer addresses (addr): from {}",
                        entries.len(),
                        seed
                    );
                    for entry in &entries {
                        // println!("  {}:{}", entry.addr.ip, entry.addr.port);
                    }
                    break;
                }
                other => println!("Received: {:?}", other),
            }
        }
    }

    Ok(())
}
