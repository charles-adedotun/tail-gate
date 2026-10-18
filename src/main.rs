#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use tail_gate::config::Config;
use tail_gate::proxy::handle_proxy_request;
use tail_gate::proxy::headers::SENSITIVE_HEADER_NAMES;
use tail_gate::router::RouteTable;
use tail_gate::tailscale::TailscaleClient;

#[derive(Parser, Debug)]
#[command(
    name = "tail-gate",
    version = "0.1.0",
    about = "RFC 9110 HTTP 421 fail-closed edge ingress proxy and Unix Domain Socket zero-trust gateway for Tailscale meshes in Safe Rust."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the tail-gate ingress proxy server.
    Run {
        /// Path to configuration file (TOML or JSON).
        #[arg(short, long, default_value = "tail-gate.toml")]
        config: PathBuf,

        /// Override listen address (e.g. 127.0.0.1:9443 or 100.64.0.1:9443).
        #[arg(short, long)]
        listen: Option<SocketAddr>,

        /// Path to Tailscale LocalAPI Unix Domain Socket.
        #[arg(long)]
        tailscale_socket: Option<PathBuf>,
    },

    /// Validate a configuration file for syntax, route validity, and fail-closed invariants.
    ValidateConfig {
        /// Path to configuration file to validate.
        #[arg(short, long, default_value = "tail-gate.toml")]
        config: PathBuf,
    },

    /// Inspect the 11 sensitive headers scrubbed by the ingress pipeline.
    InspectHeaders,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Commands::InspectHeaders => {
            println!("============================================================");
            println!("  tail-gate Ingress Security Header Sanitization Pipeline   ");
            println!("============================================================");
            println!("The following sensitive headers are unconditionally scrubbed");
            println!("from all incoming requests before route matching or upstream");
            println!("forwarding, preventing client spoofing and auth bypasses:\n");

            for (idx, name) in SENSITIVE_HEADER_NAMES.iter().enumerate() {
                println!("  {:2}. {}", idx + 1, name);
            }

            println!("\nInjected Canonical Headers:");
            println!("  • X-Forwarded-For: <remote_tailscale_ip>");
            println!("  • X-Forwarded-Host: <matched_host>");
            println!("  • X-Forwarded-Proto: https");
            println!("============================================================");
            Ok(())
        }

        Commands::ValidateConfig { config } => {
            info!("Validating configuration from '{}'...", config.display());
            let cfg = Config::from_file(&config)?;
            info!(
                "Configuration valid: {} exact host routes loaded, listen address: {}",
                cfg.routes.len(),
                cfg.listen_addr
            );

            for (idx, r) in cfg.routes.iter().enumerate() {
                info!("  [{}] host: '{}' -> {:?}", idx + 1, r.host, r.backend);
            }
            Ok(())
        }

        Commands::Run {
            config,
            listen,
            tailscale_socket,
        } => {
            info!("Loading configuration from '{}'...", config.display());
            let mut cfg = Config::from_file(&config).unwrap_or_else(|e| {
                error!(
                    "Failed to load configuration: {}. Falling back to default empty config.",
                    e
                );
                Config::default()
            });

            if let Some(addr) = listen {
                cfg.listen_addr = addr;
            }
            if let Some(ts_sock) = tailscale_socket {
                cfg.tailscale_socket_path = ts_sock;
            }

            let route_table = Arc::new(RouteTable::new(&cfg));
            let tailscale_client = Arc::new(TailscaleClient::new(&cfg.tailscale_socket_path));

            info!(
                "Starting tail-gate on {} with {} exact routes (RFC 9110 HTTP 421 fail-closed active)...",
                cfg.listen_addr,
                route_table.len()
            );

            let listener = TcpListener::bind(cfg.listen_addr).await?;
            info!("Listening on http://{}", cfg.listen_addr);

            let auto_builder = AutoConnBuilder::new(TokioExecutor::new());

            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(e) => {
                        error!("Accept error: {}", e);
                        continue;
                    }
                };

                let io = TokioIo::new(stream);
                let table = Arc::clone(&route_table);
                let ts_client = Some(Arc::clone(&tailscale_client));
                let auto = auto_builder.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let t = Arc::clone(&table);
                        let ts = ts_client.clone();
                        async move { handle_proxy_request(req, remote_addr, t, ts).await }
                    });

                    if let Err(err) = auto.serve_connection(io, service).await {
                        // Connection reset or closed prematurely by client is normal
                        tracing::debug!("Error serving connection from {}: {:?}", remote_addr, err);
                    }
                });
            }
        }
    }
}
