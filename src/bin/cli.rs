use clap::{Parser, Subcommand};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use btc_network::observability;
use btc_network::session::Session;
use btc_network::wire::message::{Block, Decode};
use btc_network::wire::{self, Command, Message};
use tracing::{debug, info, warn};

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
    GetBlock {
        #[arg(long)]
        hash: String,
    },
    DownloadBlock {
        #[arg(long)]
        hash: String,
        #[arg(long)]
        out: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    observability::init_tracing();
    let cli = Cli::parse();

    info!("Connecting to {}", cli.node);

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
        Commands::GetBlock { hash } => get_block(&mut session, hash)?,
        Commands::DownloadBlock { hash, out } => download_block(&mut session, hash, out)?,
    }

    Ok(())
}

/// Receives the next decoded Bitcoin P2P message from the peer.
///
/// It automatically handle Ping
///
/// The name `recv` "receive" follows conventional socket APIs (`recv()` in
/// POSIX/BSD sockets) and indicates a blocking receive operation.
fn recv_until<F>(session: &mut Session, mut handler: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(Message) -> Result<bool, Box<dyn std::error::Error>>,
{
    loop {
        let msg = session.recv()?;

        if let Message::Ping(payload) = &msg {
            session.send(Command::Pong, payload)?;
            continue;
        }

        if handler(msg)? {
            break;
        }
    }

    Ok(())
}

fn ping(session: &mut Session) -> Result<(), Box<dyn Error>> {
    let nonce: u64 = rand::thread_rng().r#gen();

    info!("Sending ping");
    session.send(Command::Ping, &nonce.to_le_bytes())?;

    recv_until(session, |msg| match msg {
        Message::Pong(payload) => {
            let returned = u64::from_le_bytes(payload[..8].try_into()?);
            info!(
                "Received matching pong. ping nounce: {}, pong nonce: {}",
                nonce, returned
            );
            Ok(true)
        }
        other => {
            debug!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
}

fn get_addresses(session: &mut Session) -> Result<(), Box<dyn Error>> {
    info!("Requesting peer addresses...");
    session.send(Command::GetAddr, &[])?;

    recv_until(session, |msg| match msg {
        Message::AddrV2(entries) => {
            info!("Received {} peers (addrv2)", entries.len());
            for e in entries {
                info!("  {:?}:{:?}", e.addr, e.port);
            }
            Ok(true)
        }
        Message::Addr(entries) => {
            info!("Received {} peers (legacy addr)", entries.len());
            for e in entries {
                info!("  {}:{}", e.addr.ip, e.addr.port);
            }
            Ok(true)
        }
        other => {
            debug!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
}

fn get_headers(session: &mut Session) -> Result<(), Box<dyn Error>> {
    info!("Requesting headers from genesis...");

    let payload = wire::build_getheaders_payload(&[wire::constants::GENESIS_BLOCK_HASH_MAINNET]);

    session.send(Command::GetHeaders, &payload)?;

    recv_until(session, |msg| match msg {
        Message::Headers(headers) => {
            info!("Received {} headers", headers.len());

            if let Some(last) = headers.last() {
                let mut hash = last.hash();
                hash.reverse();
                info!("Last header hash: {}", hex::encode(hash));
            }

            Ok(true)
        }
        other => {
            debug!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
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
    info!("Starting header sync from genesis...");

    let start = Instant::now();
    let mut round = 0usize;
    let mut total_headers = 0usize;
    let mut current_locator = wire::constants::GENESIS_BLOCK_HASH_MAINNET;

    loop {
        round += 1;

        info!(
            "[round {}] requesting headers (total so far: {})",
            round, total_headers
        );

        let payload = wire::build_getheaders_payload(&[current_locator]);
        session.send(Command::GetHeaders, &payload)?;

        let mut received_headers = None;

        recv_until(session, |msg| match msg {
            Message::Headers(h) => {
                received_headers = Some(h);
                Ok(true)
            }
            other => {
                debug!("Received: {:?}", other);
                Ok(false)
            }
        })?;

        let headers = received_headers.expect("headers expected");

        let count = headers.len();
        info!("[round {}] received {} headers", round, count);

        if count == 0 {
            info!("No new headers returned. Already at tip?");
            break;
        }

        total_headers += count;

        let last = headers.last().expect("headers not empty");

        let mut last_hash = last.hash();
        last_hash.reverse(); // big-endian for display

        info!(
            "[round {}] last header hash: {}",
            round,
            hex::encode(last_hash)
        );

        // If less than 2000, we reached peer tip
        if count < 2000 {
            info!("Reached peer tip.");
            info!("Total headers fetched: {}", total_headers);
            info!("Rounds: {}", round);
            info!("Elapsed: {:.2?}", start.elapsed());
            info!("Most recent block: {}", hex::encode(last_hash));
            break;
        }

        current_locator = last.hash();
    }

    Ok(())
}

fn get_block(session: &mut Session, hash_hex: String) -> Result<(), Box<dyn Error>> {
    let hash = parse_requested_block_hash(&hash_hex)?;
    let payload = wire::build_getdata_block_payload(hash);
    session.send(Command::GetData, &payload)?;

    recv_until(session, |msg| match msg {
        Message::Block(block) => {
            let mb = block.serialized_size as f64 / (1024.0 * 1024.0);

            info!("Block header: {:?}", block.header);
            info!("Tx count: {}", block.tx_count);
            info!("Size: {:.2} MB", mb);

            if block.tx_count > 0 {
                let tx = block
                    .transactions
                    .last()
                    .ok_or("block has no transactions")?;

                info!("tx.is_coinbase => {}, tx: {:?}", tx.is_coinbase(), tx);
            }

            Ok(true)
        }
        other => {
            debug!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
}

fn download_block(
    session: &mut Session,
    hash_hex: String,
    out: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let requested_hash = parse_requested_block_hash(&hash_hex)?;
    let payload = wire::build_getdata_block_payload(requested_hash);
    session.send(Command::GetData, &payload)?;

    let out_path = out.unwrap_or_else(|| {
        let first8 = &hash_hex[..8];
        let last6 = &hash_hex[hash_hex.len() - 6..];
        format!("blk-{}-{}.dat", first8, last6)
    });

    loop {
        let raw = session.recv_raw()?;

        match raw.command {
            Command::Ping => {
                session.send(Command::Pong, &raw.payload)?;
            }
            Command::Block => {
                let block = Block::decode(&raw.payload)?;
                let got_hash = block.header.hash();

                if got_hash != requested_hash {
                    let mut display_hash = got_hash;
                    display_hash.reverse();
                    let display_hash_hex = hex::encode(display_hash);
                    warn!("Received different block {}, ignoring...", display_hash_hex);
                    continue;
                }

                write_blk_record(&out_path, &raw.payload)?;
                info!(
                    "Saved block to {} (raw block: {} bytes, blk record: {} bytes)",
                    out_path,
                    raw.payload.len(),
                    raw.payload.len() + 8
                );
                return Ok(());
            }
            _ => {}
        }
    }
}

fn parse_requested_block_hash(hash_hex: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let mut hash = hex::decode(hash_hex)?;
    if hash.len() != 32 {
        return Err("block hash must be 32 bytes (64 hex chars)".into());
    }
    hash.reverse();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);
    Ok(arr)
}

fn write_blk_record(path: &str, raw_block: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(path)?;
    file.write_all(&wire::constants::MAIN_NET_MAGIC.to_le_bytes())?;
    file.write_all(&(raw_block.len() as u32).to_le_bytes())?;
    file.write_all(raw_block)?;
    Ok(())
}
