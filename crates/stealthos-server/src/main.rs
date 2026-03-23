//! `StealthOS` Relay Server
//!
//! A zero-knowledge WebSocket relay for the `StealthOS` Connection Pool.
//! The server routes encrypted messages between peers without ever
//! seeing plaintext content.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::unused_async,
    clippy::too_many_lines,
    clippy::significant_drop_tightening
)]

mod app;
mod claim;
mod config;
mod handler;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use stealthos_crypto::identity::HostIdentity;
use stealthos_observability::{LogConfig, LogFormat, health_router, init_logging};
use stealthos_transport::connection::ConnectionEvent;
use stealthos_transport::{TransportConfig, TransportServer};
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

use crate::app::AppState;
use crate::config::ServerConfig;

/// `StealthOS` Relay Server -- zero-knowledge WebSocket relay.
#[derive(Parser)]
#[command(name = "stealth-relay", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the relay server.
    Serve {
        /// Path to TOML configuration file.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Run a health check against a running server (exit 0 on healthy, 1 otherwise).
    Healthcheck {
        /// Health endpoint URL.
        #[arg(short, long, default_value = "http://127.0.0.1:9091/health")]
        url: String,
    },
    /// Generate a host identity keypair.
    GenerateIdentity {
        /// Output directory for key files.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print version information.
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            config: config_path,
        } => run_server(config_path).await,
        Commands::Healthcheck { url } => run_healthcheck(&url).await,
        Commands::GenerateIdentity { output } => run_generate_identity(output),
        Commands::Version => {
            println!(
                "stealth-relay {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_DESCRIPTION")
            );
            Ok(())
        }
    }
}

/// Main server entry point.
async fn run_server(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    // 1. Load configuration.
    let config = ServerConfig::load(config_path.as_deref())?;

    // 2. Load host identity and claim state BEFORE initializing logging.
    //    This ensures the QR code banner prints cleanly to stderr without
    //    any tracing log lines interleaving with it.
    let key_dir = PathBuf::from(&config.crypto.key_dir);
    let seed_path = key_dir.join("host.key");
    let host_identity = if seed_path.exists() {
        HostIdentity::load(&seed_path)
            .map_err(|e| anyhow::anyhow!("failed to load host identity: {e}"))?
    } else if config.crypto.auto_generate_keys {
        std::fs::create_dir_all(&key_dir)
            .map_err(|e| anyhow::anyhow!("failed to create key directory: {e}"))?;
        let identity = HostIdentity::generate();
        identity
            .save(&seed_path)
            .map_err(|e| anyhow::anyhow!("failed to save host identity: {e}"))?;
        identity
    } else {
        return Err(anyhow::anyhow!(
            "no host identity at {} and auto_generate_keys is disabled",
            seed_path.display()
        ));
    };

    let host_identity = Arc::new(host_identity);

    // 2b. Check claim state and print QR banner BEFORE any logging starts.
    let claim_state = claim::ClaimState::load_or_create(&key_dir);
    if !claim_state.is_claimed()
        && let Some(secret) = claim_state.claim_secret()
    {
        claim::print_claim_banner(secret);
    }

    // 3. NOW initialize structured logging (after QR banner is fully printed).
    let log_format = match config.logging.format.as_str() {
        "pretty" | "text" => LogFormat::Pretty,
        _ => LogFormat::Json,
    };
    init_logging(&LogConfig {
        level: config.logging.level.clone(),
        format: log_format,
    });

    info!(
        version = env!("CARGO_PKG_VERSION"),
        ws_bind = %config.server.ws_bind,
        metrics_bind = %config.server.metrics_bind,
        max_connections = config.server.max_connections,
        max_pools = config.pool.max_pools,
        "starting stealth-relay"
    );

    info!(
        fingerprint = %hex_short(&host_identity.fingerprint()),
        "host identity loaded"
    );

    if claim_state.is_claimed() {
        info!("server is claimed and ready");
    } else {
        info!("server is UNCLAIMED -- waiting for claim");
    }

    // 4. Build application state.
    let state = AppState::build(config.clone(), Arc::clone(&host_identity));

    // 5. Spawn health/metrics HTTP server.
    let health_state = state.health_state.clone();
    let metrics_bind: SocketAddr = config
        .server
        .metrics_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid metrics_bind address: {e}"))?;

    let health_handle = tokio::spawn(async move {
        let app = health_router(health_state);
        let listener = match TcpListener::bind(metrics_bind).await {
            Ok(l) => l,
            Err(e) => {
                error!(bind = %metrics_bind, "failed to bind health listener: {e}");
                return;
            }
        };
        info!(bind = %metrics_bind, "health/metrics endpoint listening");

        if let Err(e) = axum::serve(listener, app).await {
            error!("health server error: {e}");
        }
    });

    // 6. Housekeeping task is spawned after handler creation (step 7b).
    let pool_idle_timeout = Duration::from_secs(config.pool.pool_idle_timeout);

    // 7. Create and start transport server.
    let ws_bind: SocketAddr = config
        .server
        .ws_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid ws_bind address: {e}"))?;

    let (tls_cert_path, tls_key_path) = config.transport.tls_paths();
    let transport_config = TransportConfig {
        ws_bind_addr: ws_bind,
        max_connections: config.server.max_connections,
        max_message_size: config.server.max_message_size,
        handshake_timeout: Duration::from_secs(config.server.handshake_timeout),
        idle_timeout: Duration::from_secs(config.server.idle_timeout),
        tls_cert_path,
        tls_key_path,
        ..TransportConfig::default()
    };

    let mut transport = TransportServer::new(transport_config);
    let shutdown_handle = transport.shutdown_handle();

    // Use the transport's registry instead of building our own --
    // the transport server owns connection lifecycle.
    // Note: AppState already built its own ConnectionRegistry,
    // but the transport server has the one that's actually wired to WS actors.
    // We pass the transport's registry into the handler via AppState rebuild.
    // For simplicity, we'll just use the handler and connection_registry from state.
    // The transport server's registry is what connection actors use,
    // but since AppState.connection_registry is passed to the handler,
    // and the transport creates its own, we need them to be the same.
    // Solution: use the transport's registry in AppState.
    let transport_registry = transport.registry();
    let event_loop_registry = Arc::clone(&transport_registry);
    // Keep a clone for the graceful shutdown drain (HIGH-2).
    let drain_registry = Arc::clone(&transport_registry);

    // Rebuild the handler with the transport's connection registry.
    let handler = {
        let rate_limit_config = config.rate_limit.to_rate_limit_config();

        let rate_limiter = Arc::new(stealthos_core::ratelimit::IpRateLimiter::new(
            rate_limit_config.clone(),
        ));
        let throttler = Arc::new(stealthos_core::ratelimit::ConnectionThrottler::new(
            rate_limit_config,
        ));

        Arc::new(crate::handler::MessageHandler::new(
            state.pool_registry.clone(),
            transport_registry,
            state.metrics.clone(),
            rate_limiter,
            throttler,
            host_identity,
            config.server.ws_bind.clone(),
            config.pool.max_pool_size,
            claim_state,
            key_dir.clone(),
        ))
    };

    // 7b. Spawn housekeeping task now that handler exists.
    //     Cleans: idle pools, expired invitations, stale rate limiter entries,
    //     expired pending joins, and throttler records.
    let housekeeping_handler = Arc::clone(&handler);
    let housekeeping_pool_reg = state.pool_registry.clone();
    let housekeeping_shutdown = state.shutdown_rx.clone();

    let housekeeping_handle = tokio::spawn(async move {
        let mut shutdown = housekeeping_shutdown;
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    housekeeping_pool_reg.cleanup_idle_pools(pool_idle_timeout);
                    housekeeping_handler.periodic_cleanup();
                }
                _ = shutdown.changed() => {
                    info!("housekeeping task shutting down");
                    return;
                }
            }
        }
    });

    let mut event_rx = transport.take_event_receiver();
    let listener_handle = transport
        .start_listener()
        .expect("failed to start WebSocket listener (check TLS configuration)");

    info!(bind = %ws_bind, "WebSocket transport listening");

    // 8. Main event loop.
    let mut shutdown_rx = state.shutdown_rx.clone();

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("main loop received shutdown signal");
                    break;
                }
            }

            () = shutdown_signal() => {
                info!("shutdown signal received, draining connections...");
                let _ = state.shutdown_tx.send(true);
                shutdown_handle.shutdown();
                break;
            }

            event = event_rx.recv() => {
                match event {
                    Some(ConnectionEvent::Connected {
                        connection_id,
                        remote_addr,
                    }) => {
                        info!(
                            connection = %connection_id,
                            remote = %remote_addr,
                            "new connection, sending auth challenge"
                        );
                        handler.handle_new_connection(connection_id);
                    }
                    Some(ConnectionEvent::MessageReceived {
                        connection_id,
                        message,
                        remote_addr,
                    }) => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            if let Err(e) = handler
                                .handle_message(connection_id, remote_addr, &message)
                                .await
                            {
                                warn!(
                                    connection = %connection_id,
                                    "message handling error: {e}"
                                );
                            }
                        });
                    }
                    Some(ConnectionEvent::Disconnected {
                        connection_id,
                        reason,
                    }) => {
                        info!(
                            connection = %connection_id,
                            reason = %reason,
                            "connection disconnected"
                        );
                        event_loop_registry.unregister(connection_id);
                        handler.handle_disconnect(connection_id);
                    }
                    None => {
                        info!("event channel closed");
                        break;
                    }
                }
            }
        }
    }

    // 9. Graceful drain.
    //
    // SECURITY: HIGH-2 — Send WebSocket Close frames to all active
    // connections so clients receive a proper close (code 1001 "Going Away")
    // instead of a TCP RST. This prevents clients from interpreting a clean
    // shutdown as a network error and retrying aggressively.
    {
        let active_ids = drain_registry.connection_ids();
        let active_count = active_ids.len();
        if active_count > 0 {
            info!(
                connections = active_count,
                "sending close frames to active connections"
            );
            for conn_id in &active_ids {
                let _ = drain_registry.send_to(
                    *conn_id,
                    stealthos_transport::connection::OutboundMessage::Close(
                        1001,
                        "server shutting down".to_owned(),
                    ),
                );
            }
            // Brief grace period for connection actors to process the close
            // frames and complete the WebSocket closing handshake.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    let drain_timeout = Duration::from_secs(10);
    tokio::select! {
        () = tokio::time::sleep(drain_timeout) => {
            warn!("drain timeout exceeded, forcing shutdown");
        }
        _ = listener_handle => {
            info!("listener task completed");
        }
    }

    health_handle.abort();
    housekeeping_handle.abort();

    info!("stealth-relay stopped");
    Ok(())
}

/// Format the first 8 bytes of a fingerprint as hex.
///
/// Uses a stack-allocated buffer to avoid per-byte `format!` allocations.
fn hex_short(bytes: &[u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for (i, &b) in bytes[..8].iter().enumerate() {
        buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
        buf[i * 2 + 1] = HEX_CHARS[(b & 0x0f) as usize];
    }
    String::from_utf8(buf.to_vec()).expect("hex chars are valid UTF-8")
}

/// Wait for SIGINT or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

/// Health check subcommand -- pings the health endpoint.
async fn run_healthcheck(url: &str) -> anyhow::Result<()> {
    // Use a minimal TCP check since we don't want to pull in an HTTP client dependency.
    let addr: SocketAddr = url
        .strip_prefix("http://")
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:9091")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid health URL: {e}"))?;

    match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            println!("healthy");
            Ok(())
        }
        Ok(Err(e)) => {
            eprintln!("unhealthy: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("unhealthy: connection timed out");
            std::process::exit(1);
        }
    }
}

/// Generate host identity keypair.
fn run_generate_identity(output: Option<PathBuf>) -> anyhow::Result<()> {
    let output_dir = output.unwrap_or_else(|| PathBuf::from("."));

    std::fs::create_dir_all(&output_dir)
        .map_err(|e| anyhow::anyhow!("failed to create output directory: {e}"))?;

    let seed_path = output_dir.join("host.key");

    if seed_path.exists() {
        eprintln!(
            "Host identity already exists at {}. Remove it first to regenerate.",
            seed_path.display()
        );
        std::process::exit(1);
    }

    let identity = HostIdentity::generate();
    identity
        .save(&seed_path)
        .map_err(|e| anyhow::anyhow!("failed to save host identity: {e}"))?;

    let pk = identity.public_keys();
    let fingerprint = hex_short(&pk.fingerprint);

    println!("Host identity generated successfully.");
    println!("  Seed file: {}", seed_path.display());
    println!("  Fingerprint: {fingerprint}");

    Ok(())
}
