//! Active connection registry.
//!
//! Provides O(1) lookup, registration, removal, and targeted send for
//! all live connections. Built on [`DashMap`] for lock-free concurrent
//! reads.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::warn;

use crate::connection::OutboundMessage;
use crate::error::TransportError;
use crate::types::ConnectionId;

/// A handle to a live connection, held by the registry.
///
/// Cloning is cheap — the `mpsc::Sender` uses an `Arc` internally.
#[derive(Debug, Clone)]
pub struct ConnectionHandle {
    /// Unique identifier for this connection.
    pub connection_id: ConnectionId,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Sender half of the bounded outbound channel.
    pub outbound_tx: mpsc::Sender<OutboundMessage>,
    /// When this connection was accepted.
    pub connected_at: Instant,
}

/// Thread-safe registry of all active connections.
pub struct ConnectionRegistry {
    connections: DashMap<ConnectionId, ConnectionHandle>,
    active_count: AtomicUsize,
    max_connections: usize,
}

impl ConnectionRegistry {
    /// Create a new registry with the given capacity limit.
    #[must_use]
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: DashMap::with_capacity(max_connections),
            active_count: AtomicUsize::new(0),
            max_connections,
        }
    }

    /// Register a new connection.
    ///
    /// Uses a compare-and-swap loop to atomically reserve a slot before
    /// inserting into the `DashMap`. This eliminates the TOCTOU race where
    /// concurrent `register` calls could all pass the capacity check and
    /// exceed `max_connections`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionLimitReached`] if the registry
    /// is at capacity.
    pub fn register(&self, handle: ConnectionHandle) -> Result<(), TransportError> {
        // Atomically reserve a slot via CAS loop.
        loop {
            let current = self.active_count.load(Ordering::Acquire);
            if current >= self.max_connections {
                return Err(TransportError::ConnectionLimitReached {
                    current,
                    max: self.max_connections,
                });
            }
            if self
                .active_count
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
            // CAS failed due to contention, retry.
        }

        // Slot reserved. Insert the handle into the map.
        self.connections.insert(handle.connection_id, handle);
        Ok(())
    }

    /// Remove a connection from the registry, returning the handle if
    /// it existed.
    pub fn unregister(&self, connection_id: ConnectionId) -> Option<ConnectionHandle> {
        let removed = self.connections.remove(&connection_id).map(|(_, h)| h);
        if removed.is_some() {
            self.active_count.fetch_sub(1, Ordering::Release);
        }
        removed
    }

    /// Look up a connection by ID, returning a cloned handle.
    #[must_use]
    pub fn get(&self, connection_id: ConnectionId) -> Option<ConnectionHandle> {
        self.connections.get(&connection_id).map(|r| r.clone())
    }

    /// Send a message to a specific connection.
    ///
    /// Uses `try_send` to avoid blocking; if the outbound channel is full
    /// (slow consumer), returns [`TransportError::SendFailed`].
    ///
    /// # Errors
    ///
    /// - [`TransportError::ConnectionNotFound`] if no connection with the
    ///   given ID exists.
    /// - [`TransportError::SendFailed`] if the outbound channel is full
    ///   or closed.
    pub fn send_to(
        &self,
        connection_id: ConnectionId,
        message: OutboundMessage,
    ) -> Result<(), TransportError> {
        let handle = self
            .connections
            .get(&connection_id)
            .ok_or(TransportError::ConnectionNotFound(connection_id))?;

        handle.outbound_tx.try_send(message).map_err(|e| {
            warn!(
                connection_id = %connection_id,
                "outbound channel full or closed: {e}",
            );
            TransportError::SendFailed
        })
    }

    /// Broadcast a message to all connections except those in `exclude`.
    ///
    /// Connections whose outbound channels are full are skipped with a
    /// warning — they are not evicted here (eviction is handled by the
    /// connection actor's own backpressure logic).
    pub fn broadcast(&self, message: &str, exclude: &[ConnectionId]) {
        for entry in &self.connections {
            if exclude.contains(entry.key()) {
                continue;
            }
            let msg = OutboundMessage::Text(message.to_owned());
            if let Err(e) = entry.outbound_tx.try_send(msg) {
                warn!(
                    connection_id = %entry.connection_id,
                    "broadcast: outbound channel full or closed: {e}",
                );
            }
        }
    }

    /// Number of currently active connections.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::Acquire)
    }

    /// Snapshot of all active connection IDs.
    #[must_use]
    pub fn connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.iter().map(|r| *r.key()).collect()
    }
}
