//! Transport server — ties the listener, registry, and event processing
//! into a single entry point for the server binary.

use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tracing::{error, info};

use crate::config::TransportConfig;
use crate::connection::ConnectionEvent;
use crate::connection_registry::ConnectionRegistry;
use crate::listener::WebSocketListener;

/// Top-level transport server.
///
/// The server binary creates a `TransportServer`, obtains an
/// `Arc<ConnectionRegistry>` for sending frames, and calls
/// [`run`](Self::run) to start accepting connections.
pub struct TransportServer {
    config: TransportConfig,
    registry: Arc<ConnectionRegistry>,
    event_rx: mpsc::Receiver<ConnectionEvent>,
    event_tx: mpsc::Sender<ConnectionEvent>,
    /// Sending `true` triggers graceful shutdown.
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// A clonable handle for triggering graceful server shutdown.
///
/// Obtain one via [`TransportServer::shutdown_handle`] before calling
/// [`TransportServer::run`].
#[derive(Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signal the transport server to shut down gracefully.
    pub fn shutdown(&self) {
        let _ = self.tx.send(true);
    }
}

/// Capacity of the shared event channel (connection events -> server).
const EVENT_CHANNEL_CAPACITY: usize = 4096;

impl TransportServer {
    /// Create a new transport server with the given configuration.
    #[must_use]
    pub fn new(config: TransportConfig) -> Self {
        let registry = Arc::new(ConnectionRegistry::new(config.max_connections));
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Self {
            config,
            registry,
            event_rx,
            event_tx,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Obtain a handle to the connection registry.
    ///
    /// The server binary uses this to send frames to specific connections
    /// via [`ConnectionRegistry::send_to`].
    #[must_use]
    pub fn registry(&self) -> Arc<ConnectionRegistry> {
        Arc::clone(&self.registry)
    }

    /// Obtain a clone of the event sender.
    ///
    /// Useful if additional components need to inject synthetic events.
    #[must_use]
    pub fn event_sender(&self) -> mpsc::Sender<ConnectionEvent> {
        self.event_tx.clone()
    }

    /// Obtain a shutdown handle that can be used to trigger graceful
    /// shutdown from another task.
    ///
    /// Call this before [`run`](Self::run), since `run` consumes `self`.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            tx: self.shutdown_tx.clone(),
        }
    }

    /// Take the event receiver out of the transport server.
    ///
    /// The caller can then process events asynchronously (e.g., with an
    /// async message handler). This must be called before [`start_listener`].
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn take_event_receiver(&mut self) -> mpsc::Receiver<ConnectionEvent> {
        // Replace with a dummy channel; the real receiver is returned.
        let (_, dummy_rx) = mpsc::channel(1);
        std::mem::replace(&mut self.event_rx, dummy_rx)
    }

    /// Start the WebSocket listener without consuming `self`.
    ///
    /// Spawns the accept loop and returns its `JoinHandle`. The caller
    /// must separately process events from the receiver obtained via
    /// [`take_event_receiver`].
    ///
    /// Drops the internal event sender so that the event channel closes
    /// naturally when all connection actors finish.
    /// # Errors
    ///
    /// Returns [`crate::error::TransportError::Tls`] if TLS is configured but
    /// the certificate or key files cannot be loaded.
    pub fn start_listener(
        &mut self,
    ) -> Result<tokio::task::JoinHandle<()>, crate::error::TransportError> {
        let listener = WebSocketListener::new(
            self.config.clone(),
            Arc::clone(&self.registry),
            self.event_tx.clone(),
            self.shutdown_rx.clone(),
        )?;

        // Drop our copy of event_tx so the channel closes when all actors exit.
        let (dead_tx, _) = mpsc::channel(1);
        let _ = std::mem::replace(&mut self.event_tx, dead_tx);

        Ok(tokio::spawn(async move {
            if let Err(e) = listener.run().await {
                error!("listener exited with error: {e}");
            }
        }))
    }

    /// Start the listener and process connection events.
    ///
    /// The provided callback is invoked for every [`ConnectionEvent`].
    /// This method blocks until the server shuts down.
    /// # Errors
    ///
    /// Returns [`crate::error::TransportError::Tls`] if TLS is configured but
    /// the certificate or key files cannot be loaded.
    pub async fn run(
        self,
        mut on_event: impl FnMut(ConnectionEvent) + Send + 'static,
    ) -> Result<(), crate::error::TransportError> {
        let listener = WebSocketListener::new(
            self.config.clone(),
            Arc::clone(&self.registry),
            self.event_tx.clone(),
            self.shutdown_rx.clone(),
        )?;

        // Spawn the accept loop.
        let listener_handle = tokio::spawn(async move {
            if let Err(e) = listener.run().await {
                error!("listener exited with error: {e}");
            }
        });

        let registry = Arc::clone(&self.registry);

        // Destructure self so we can move individual fields into the
        // event loop without partial-move issues.
        let mut event_rx = self.event_rx;
        let mut shutdown_rx = self.shutdown_rx;
        // Drop our copy of event_tx so that when all connection actors
        // finish, the channel closes and the event loop exits.
        drop(self.event_tx);

        // Process events until shutdown or all senders are dropped.
        loop {
            tokio::select! {
                biased;

                event = event_rx.recv() => {
                    match event {
                        Some(ConnectionEvent::Disconnected { connection_id, reason }) => {
                            registry.unregister(connection_id);
                            info!(
                                %connection_id,
                                %reason,
                                active = registry.active_count(),
                                "connection unregistered",
                            );
                            on_event(ConnectionEvent::Disconnected {
                                connection_id,
                                reason,
                            });
                        }
                        Some(ev) => {
                            on_event(ev);
                        }
                        None => {
                            info!("event channel closed, shutting down");
                            break;
                        }
                    }
                }

                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("transport server shutting down");
                        break;
                    }
                }
            }
        }

        // Wait for the listener task to finish.
        let _ = listener_handle.await;

        info!(
            remaining = registry.active_count(),
            "transport server stopped",
        );

        Ok(())
    }
}
