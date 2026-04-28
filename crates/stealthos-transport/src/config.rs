//! Transport configuration with sensible defaults.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for the WebSocket transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Address the WebSocket listener binds to.
    pub ws_bind_addr: SocketAddr,

    /// Maximum number of concurrent WebSocket connections.
    pub max_connections: usize,

    /// Maximum size of a single WebSocket message in bytes.
    pub max_message_size: usize,

    /// Time allowed for a client to complete the WebSocket handshake.
    pub handshake_timeout: Duration,

    /// Duration of inactivity before a connection is closed.
    pub idle_timeout: Duration,

    /// Interval between server-initiated WebSocket pings.
    pub heartbeat_interval: Duration,

    /// Time after the last pong before a connection is considered dead
    /// (approximately 3 missed heartbeats with the default config).
    pub heartbeat_timeout: Duration,

    /// Bounded capacity of the per-connection outbound channel. When full,
    /// the connection is considered a slow consumer.
    pub slow_consumer_threshold: usize,

    /// Number of consecutive back-pressure warnings before eviction.
    pub slow_consumer_max_warnings: u32,

    /// Optional path to a PEM-encoded TLS certificate chain.
    pub tls_cert_path: Option<PathBuf>,

    /// Optional path to a PEM-encoded TLS private key.
    pub tls_key_path: Option<PathBuf>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            ws_bind_addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8443),
            max_connections: 500,
            max_message_size: 65_536, // 64 KiB
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(10),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90), // 3 missed heartbeats
            slow_consumer_threshold: 256,
            slow_consumer_max_warnings: 3,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}
