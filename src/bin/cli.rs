use clap::{Parser, Subcommand};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use btc_network::session::Session;
use btc_network::wire::{Command, Message};

use std::time::Instant;

use rand::Rng;

#[derive(Parser)]
#[command(name = "btc-cli")]
struct Cli {
    #[arg(long)]
    node: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Ping,
    GetAddr,
    GetHeaders,
    LastBlockHeader,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    println!("Connecting to {}", cli.node);

    let addr = cli
        .node
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve address")?;

    let timeout = Duration::from_secs(30);
    let stream = TcpStream::connect_timeout(&addr, timeout)?;

    let mut session = Session::new(stream);

    session.handshake()?;

    match cli.command {
        Commands::Ping => ping(&mut session)?,
        Commands::GetAddr => get_addresses(&mut session)?,
        Commands::GetHeaders => get_headers(&mut session)?,
        Commands::LastBlockHeader => last_block_header(&mut session)?,
    }

    Ok(())
}

fn ping(session: &mut Session) -> Result<(), Box<dyn Error>> {
    let nonce: u64 = rand::thread_rng().r#gen();

    println!("Sending ping");

    session.send(Command::Ping, &nonce.to_le_bytes())?;

    loop {
        let msg = session.recv()?;

        match msg {
            Message::Pong(payload) => {
                let returned = u64::from_le_bytes(payload[..8].try_into()?);

                if returned == nonce {
                    println!("Received matching pong");
                    break;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn get_addresses(session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting peer addresses...");

    // 1️⃣ Send getaddr
    session.send(Command::GetAddr, &[])?;

    // 2️⃣ Wait for addr or addrv2
    loop {
        let msg = session.recv()?;

        match msg {
            Message::AddrV2(entries) => {
                println!("Received {} peers (addrv2)", entries.len());

                for entry in entries {
                    println!("  {:?}:{:?}", entry.addr, entry.port);
                }

                break;
            }

            Message::Addr(entries) => {
                println!("Received {} peers (legacy addr)", entries.len());

                for entry in entries {
                    println!("  {}:{}", entry.addr.ip, entry.addr.port);
                }

                break;
            }

            Message::Ping(payload) => {
                session.send(Command::Pong, &payload)?;
            }

            other => {
                println!("Other command received from get addresses: {:?}", other);
            }
        }
    }

    Ok(())
}

// from bitcoin core: https://github.com/bitcoin/bitcoin/blob/707ad466968b947b364cfc25bcb4d6895e799418/src/kernel/chainparams.cpp#L136
const GENESIS: [u8; 32] = [
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn get_headers(session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting headers from genesis...");

    let payload = build_getheaders_payload(&[GENESIS]);

    session.send(Command::GetHeaders, &payload)?;

    loop {
        match session.recv()? {
            Message::Headers(headers) => {
                println!("Received {} headers", headers.len());

                if let Some(last) = headers.last() {
                    let mut hash = last.hash();
                    hash.reverse(); // display big-endian

                    println!("Last header hash: {}", hex::encode(hash));
                }

                break;
            }

            Message::Ping(payload) => {
                session.send(Command::Pong, &payload)?;
            }

            other => {
                println!("Received: {:?}", other);
            }
        }
    }

    Ok(())
}

/// The `headers` message returns block headers in strictly
/// chronological (forward) order along the peer's active chain.
///
/// Semantics:
/// - The peer finds the first locator hash it recognizes.
/// - It then returns headers *after* that block.
/// - Headers are ordered from oldest → newest.
/// - At most 2000 headers are returned per message.
///
/// This ordering allows the client to validate linkage linearly:
///
///     header[i].prev_blockhash == header[i-1].hash()
///
/// Even though block headers only contain a backward pointer
/// (`prev_blockhash`), peers maintain a forward index internally
/// and iterate forward when constructing the response.
///
/// Reference:
/// https://developer.bitcoin.org/reference/p2p_networking.html#getheaders
///
/// This forward ordering is relied upon by header-first sync
/// and is required for deterministic chain construction.
fn last_block_header(session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting header sync from genesis...");

    let start = Instant::now();
    let mut round = 0usize;
    let mut total_headers = 0usize;
    let mut current_locator = GENESIS;

    loop {
        round += 1;

        println!(
            "[round {}] requesting headers (total so far: {})",
            round, total_headers
        );

        let payload = build_getheaders_payload(&[current_locator]);
        session.send(Command::GetHeaders, &payload)?;

        let headers = loop {
            match session.recv()? {
                Message::Headers(h) => break h,
                Message::Ping(p) => {
                    session.send(Command::Pong, &p)?;
                }
                other => {
                    println!("Received: {:?}", other);
                }
            }
        };

        let count = headers.len();
        println!("[round {}] received {} headers", round, count);

        if count == 0 {
            println!("No new headers returned. Already at tip?");
            break;
        }

        total_headers += count;

        let last = headers.last().expect("headers not empty");

        let mut last_hash = last.hash();
        last_hash.reverse(); // big-endian for display

        println!(
            "[round {}] last header hash: {}",
            round,
            hex::encode(last_hash)
        );

        // If less than 2000, we reached peer tip
        if count < 2000 {
            println!();
            println!("Reached peer tip.");
            println!("Total headers fetched: {}", total_headers);
            println!("Rounds: {}", round);
            println!("Elapsed: {:.2?}", start.elapsed());
            println!("Most recent block: {}", hex::encode(last_hash));
            break;
        }

        current_locator = last.hash();
    }

    Ok(())
}

fn build_getheaders_payload(locator: &[[u8; 32]]) -> Vec<u8> {
    let mut payload = Vec::new();

    payload.extend(&70016i32.to_le_bytes());

    write_varint(locator.len() as u64, &mut payload);

    for hash in locator {
        payload.extend(hash);
    }

    // stop hash = zero (no stop)
    payload.extend([0u8; 32]);

    payload
}

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
