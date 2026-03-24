//! Application state -- the root container for all shared server state.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use stealthos_core::PoolRegistry;
use stealthos_core::ratelimit::{ConnectionThrottler, IpRateLimiter};
use stealthos_crypto::identity::HostIdentity;
use stealthos_observability::{HealthState, ServerMetrics};
use stealthos_transport::ConnectionRegistry;
use tokio::sync::watch;

use crate::claim::ClaimState;
use crate::config::ServerConfig;
use crate::handler::MessageHandler;

/// Top-level application state, shared across all server tasks.
///
/// Created once during startup and passed (via `Arc`) to the transport
/// layer, health endpoints, and housekeeping tasks.
#[allow(dead_code)] // Fields used once transport server is wired up.
pub struct AppState {
    /// Parsed and validated configuration.
    pub config: ServerConfig,
    /// Registry of active connection pools.
    pub pool_registry: Arc<PoolRegistry>,
    /// Registry of active WebSocket connections.
    pub connection_registry: Arc<ConnectionRegistry>,
    /// Atomic metric counters.
    pub metrics: Arc<ServerMetrics>,
    /// Central message dispatcher.
    pub handler: Arc<MessageHandler>,
    /// Shutdown signal sender -- set to `true` to initiate graceful drain.
    pub shutdown_tx: watch::Sender<bool>,
    /// Shutdown signal receiver -- cloned into each spawned task.
    pub shutdown_rx: watch::Receiver<bool>,
    /// Health endpoint state.
    pub health_state: Arc<HealthState>,
}

impl AppState {
    /// Build the complete application state from configuration.
    ///
    /// This wires up all shared registries, metrics, rate limiters,
    /// and the message handler.
    pub fn build(config: ServerConfig, host_identity: Arc<HostIdentity>) -> Self {
        let metrics = Arc::new(ServerMetrics::new());

        let pool_registry = Arc::new(PoolRegistry::new(config.pool.max_pools));

        let connection_registry = Arc::new(ConnectionRegistry::new(config.server.max_connections));

        let rate_limit_config = config.rate_limit.to_rate_limit_config();

        let rate_limiter = Arc::new(IpRateLimiter::new(rate_limit_config.clone()));
        let throttler = Arc::new(ConnectionThrottler::new(rate_limit_config));

        let server_addr = config.server.ws_bind.clone();
        let max_pool_size = config.pool.max_pool_size;

        // NOTE: This handler instance is a placeholder. The real handler
        // is built in main.rs with the transport server's connection registry
        // and the actual ClaimState. This handler exists only because AppState
        // was designed with it as a field; it is never used for dispatch.
        let placeholder_claim = Arc::new(Mutex::new(ClaimState::Claimed {
            binding: crate::claim::HostBinding {
                host_public_key: String::new(),
                claimed_at: String::new(),
                server_fingerprint: String::new(),
                recovery_key_hash: String::new(),
            },
        }));
        let handler = Arc::new(MessageHandler::new(
            Arc::clone(&pool_registry),
            Arc::clone(&connection_registry),
            Arc::clone(&metrics),
            rate_limiter,
            throttler,
            host_identity,
            server_addr,
            max_pool_size,
            placeholder_claim,
            PathBuf::from(&config.crypto.key_dir),
            None, // No setup state for the placeholder handler
        ));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let health_state = Arc::new(HealthState {
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION"),
            max_connections: config.server.max_connections,
            max_pools: config.pool.max_pools,
            metrics: Arc::clone(&metrics),
        });

        Self {
            config,
            pool_registry,
            connection_registry,
            metrics,
            handler,
            shutdown_tx,
            shutdown_rx,
            health_state,
        }
    }
}
