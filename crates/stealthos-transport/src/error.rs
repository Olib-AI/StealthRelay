//! Transport-layer error types.

use crate::types::ConnectionId;

/// Errors produced by the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The server has reached its configured maximum number of connections.
    #[error("connection limit reached ({current}/{max})")]
    ConnectionLimitReached {
        /// Current number of active connections.
        current: usize,
        /// Configured maximum.
        max: usize,
    },

    /// No connection with the given ID exists in the registry.
    #[error("connection not found: {0}")]
    ConnectionNotFound(ConnectionId),

    /// The outbound channel to a connection actor has been closed.
    #[error("send failed: channel closed")]
    SendFailed,

    /// An error originating from the WebSocket layer.
    #[error("websocket error: {0}")]
    WebSocket(String),

    /// A TLS configuration or handshake error.
    #[error("tls error: {0}")]
    Tls(String),

    /// An I/O error from the underlying TCP layer.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The client did not complete the WebSocket handshake in time.
    #[error("handshake timeout")]
    HandshakeTimeout,

    /// A received message exceeds the configured maximum size.
    #[error("message too large: {size} > {max}")]
    MessageTooLarge {
        /// Actual message size in bytes.
        size: usize,
        /// Configured maximum size in bytes.
        max: usize,
    },

    /// The connection was closed due to inactivity.
    #[error("idle timeout")]
    IdleTimeout,

    /// The connection was closed because it could not consume outbound
    /// messages quickly enough.
    #[error("slow consumer evicted")]
    SlowConsumerEvicted,
}
