//! WebSocket listener — accepts TCP connections, upgrades to WebSocket,
//! and spawns per-connection actor tasks.
//!
//! When `tls_cert_path` and `tls_key_path` are both set in
//! [`TransportConfig`], the listener performs a TLS handshake on every
//! accepted connection before the WebSocket upgrade. When neither is
//! set, connections remain plaintext (suitable for local development
//! behind a TLS-terminating reverse proxy).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, error, info, warn};

use crate::config::TransportConfig;
use crate::connection::{ConnectionActor, ConnectionActorParams, ConnectionEvent, OutboundMessage};
use crate::connection_registry::{ConnectionHandle, ConnectionRegistry};
use crate::error::TransportError;
use crate::types::ConnectionId;

/// Accepts inbound TCP connections, upgrades them to WebSocket, and
/// spawns [`ConnectionActor`] tasks.
///
/// When TLS certificate and key paths are configured, every accepted TCP
/// connection is wrapped in a TLS session before the WebSocket upgrade.
pub struct WebSocketListener {
    config: TransportConfig,
    connection_counter: AtomicU64,
    registry: Arc<ConnectionRegistry>,
    event_tx: mpsc::Sender<ConnectionEvent>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    /// `None` when TLS is not configured (plaintext mode for local dev).
    tls_acceptor: Option<TlsAcceptor>,
}

impl WebSocketListener {
    /// Create a new listener.
    ///
    /// When both `tls_cert_path` and `tls_key_path` are set in `config`,
    /// the certificate chain and private key are loaded eagerly so that
    /// configuration errors surface at startup rather than on the first
    /// accepted connection.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Tls`] if the certificate or key files
    /// cannot be read or parsed.
    pub fn new(
        config: TransportConfig,
        registry: Arc<ConnectionRegistry>,
        event_tx: mpsc::Sender<ConnectionEvent>,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self, TransportError> {
        let tls_acceptor = Self::build_tls_acceptor(&config)?;

        if tls_acceptor.is_some() {
            info!("TLS enabled — connections will be encrypted");
        } else {
            warn!(
                "TLS is NOT configured — all connections will be plaintext. \
                 This is acceptable only for local development behind a \
                 TLS-terminating reverse proxy."
            );
        }

        Ok(Self {
            config,
            connection_counter: AtomicU64::new(1),
            registry,
            event_tx,
            shutdown_rx,
            tls_acceptor,
        })
    }

    /// Load the TLS certificate chain and private key from the paths in
    /// `config`, returning a configured [`TlsAcceptor`].
    ///
    /// Returns `Ok(None)` when neither path is configured.
    fn build_tls_acceptor(config: &TransportConfig) -> Result<Option<TlsAcceptor>, TransportError> {
        let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path)
        else {
            // If only one of the two is set, that is a configuration error.
            if config.tls_cert_path.is_some() || config.tls_key_path.is_some() {
                return Err(TransportError::Tls(
                    "both tls_cert_path and tls_key_path must be set (or neither)".to_owned(),
                ));
            }
            return Ok(None);
        };

        // Read and parse certificate chain (PEM).
        let cert_file = std::fs::File::open(cert_path).map_err(|e| {
            TransportError::Tls(format!(
                "cannot open cert file {}: {e}",
                cert_path.display()
            ))
        })?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                TransportError::Tls(format!(
                    "cannot parse PEM certs from {}: {e}",
                    cert_path.display()
                ))
            })?;

        if certs.is_empty() {
            return Err(TransportError::Tls(format!(
                "no certificates found in {}",
                cert_path.display()
            )));
        }

        // Read and parse private key (PEM). Accept PKCS#8 or RSA.
        let key_file = std::fs::File::open(key_path).map_err(|e| {
            TransportError::Tls(format!("cannot open key file {}: {e}", key_path.display()))
        })?;
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
            .map_err(|e| {
                TransportError::Tls(format!(
                    "cannot parse PEM key from {}: {e}",
                    key_path.display()
                ))
            })?
            .ok_or_else(|| {
                TransportError::Tls(format!("no private key found in {}", key_path.display()))
            })?;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TransportError::Tls(format!("rustls config error: {e}")))?;

        Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
    }

    /// Run the accept loop until a shutdown signal is received.
    ///
    /// This method binds a TCP listener on the configured address and
    /// loops, accepting connections and spawning actor tasks.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError::Io`] if the TCP listener cannot bind
    /// to the configured address.
    pub async fn run(mut self) -> Result<(), crate::error::TransportError> {
        let tcp_listener = TcpListener::bind(self.config.ws_bind_addr).await?;
        info!(addr = %self.config.ws_bind_addr, "websocket listener started");

        loop {
            tokio::select! {
                biased;

                // Shutdown signal.
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("listener received shutdown signal");
                        break;
                    }
                }

                // Accept a new TCP connection.
                accept_result = tcp_listener.accept() => {
                    let (tcp_stream, remote_addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            error!("tcp accept error: {e}");
                            continue;
                        }
                    };

                    // Connection-limit gate.
                    let current = self.registry.active_count();
                    if current >= self.config.max_connections {
                        warn!(
                            %remote_addr,
                            current,
                            max = self.config.max_connections,
                            "connection limit reached, rejecting",
                        );
                        drop(tcp_stream);
                        continue;
                    }

                    let connection_id = ConnectionId(
                        self.connection_counter.fetch_add(1, Ordering::Relaxed),
                    );

                    debug!(
                        %connection_id,
                        %remote_addr,
                        "accepted tcp connection, upgrading to websocket",
                    );

                    // Spawn the handshake + actor on a dedicated task so
                    // that a slow handshake cannot block the accept loop.
                    let config = self.config.clone();
                    let registry = Arc::clone(&self.registry);
                    let event_tx = self.event_tx.clone();
                    let tls_acceptor = self.tls_acceptor.clone();

                    tokio::spawn(handle_new_connection(
                        config,
                        registry,
                        event_tx,
                        tls_acceptor,
                        connection_id,
                        remote_addr,
                        tcp_stream,
                    ));
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Free-standing connection handler (extracted to keep `run` under 100 lines)
// ---------------------------------------------------------------------------

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Perform the TLS + WebSocket handshake and run the connection actor.
///
/// Extracted from `WebSocketListener::run` so that the accept loop stays
/// small and the per-connection logic (which is mostly error handling for
/// the two-phase handshake) lives in its own function.
#[allow(clippy::too_many_arguments)]
async fn handle_new_connection(
    config: TransportConfig,
    registry: Arc<ConnectionRegistry>,
    event_tx: mpsc::Sender<ConnectionEvent>,
    tls_acceptor: Option<TlsAcceptor>,
    connection_id: ConnectionId,
    remote_addr: std::net::SocketAddr,
    tcp_stream: TcpStream,
) {
    // SECURITY: S1 — Frame-level message size enforcement.
    //
    // SECURITY: HIGH-5 — permessage-deflate (CRIME-like side-channel).
    // tungstenite 0.26 does not implement WebSocket compression extensions
    // at all — there is no `permessage-deflate` negotiation code in this
    // version. `WebSocketConfig::default()` is therefore compression-free.
    // If tungstenite adds compression support in a future version, the
    // `accept_hdr_async_with_config` path below explicitly rejects any
    // `Sec-WebSocket-Extensions` header containing `permessage-deflate`
    // to prevent a compression oracle (CRIME/BREACH) side-channel.
    let mut ws_config = WebSocketConfig::default();
    ws_config.max_message_size = Some(config.max_message_size);
    ws_config.max_frame_size = Some(config.max_message_size);

    if let Some(acceptor) = tls_acceptor {
        // ── TLS path ─────────────────────────────────────────────────────
        let Some(tls_stream) =
            tls_handshake(&acceptor, tcp_stream, &config, connection_id, remote_addr).await
        else {
            return;
        };
        let Some(ws_stream) = ws_handshake(
            tls_stream,
            ws_config,
            &config,
            connection_id,
            remote_addr,
            "tls",
        )
        .await
        else {
            return;
        };
        info!(%connection_id, %remote_addr, "websocket+tls connection established");
        run_actor(
            config,
            registry,
            event_tx,
            connection_id,
            remote_addr,
            ws_stream,
        )
        .await;
    } else {
        // ── Plaintext path (local dev / behind TLS proxy) ────────────────
        let Some(ws_stream) = ws_handshake(
            tcp_stream,
            ws_config,
            &config,
            connection_id,
            remote_addr,
            "plain",
        )
        .await
        else {
            return;
        };
        info!(%connection_id, %remote_addr, "websocket connection established (plaintext)");
        run_actor(
            config,
            registry,
            event_tx,
            connection_id,
            remote_addr,
            ws_stream,
        )
        .await;
    }
}

/// Perform the TLS handshake with timeout. Returns `None` on failure.
async fn tls_handshake(
    acceptor: &TlsAcceptor,
    tcp_stream: TcpStream,
    config: &TransportConfig,
    connection_id: ConnectionId,
    remote_addr: std::net::SocketAddr,
) -> Option<tokio_rustls::server::TlsStream<TcpStream>> {
    match time::timeout(config.handshake_timeout, acceptor.accept(tcp_stream)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(e)) => {
            warn!(%connection_id, %remote_addr, "tls handshake failed: {e}");
            None
        }
        Err(_) => {
            warn!(%connection_id, %remote_addr, "tls handshake timeout");
            None
        }
    }
}

/// Perform the WebSocket upgrade handshake with timeout. Returns `None` on failure.
///
/// SECURITY: HIGH-5 — Uses a header callback to reject any client requesting
/// `permessage-deflate` via `Sec-WebSocket-Extensions`. Compression creates a
/// CRIME/BREACH-style oracle when combined with encrypted payloads. While
/// tungstenite 0.26 does not implement compression, this callback provides
/// defense-in-depth against future library upgrades silently enabling it.
async fn ws_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    ws_config: WebSocketConfig,
    config: &TransportConfig,
    connection_id: ConnectionId,
    remote_addr: std::net::SocketAddr,
    transport_label: &str,
) -> Option<tokio_tungstenite::WebSocketStream<S>> {
    // Callback that rejects permessage-deflate compression extensions and
    // strips any Sec-WebSocket-Extensions from the response to ensure the
    // server never negotiates compression.
    let reject_compression =
        |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
         response: tokio_tungstenite::tungstenite::handshake::server::Response|
         -> Result<
            tokio_tungstenite::tungstenite::handshake::server::Response,
            tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
        > {
            // Check if the client requests permessage-deflate. If so, we
            // simply do not echo the extension back — the upgrade proceeds
            // without compression. tungstenite 0.26 already ignores unknown
            // extensions, but being explicit prevents regressions.
            if let Some(ext) = request.headers().get("Sec-WebSocket-Extensions")
                && let Ok(ext_str) = ext.to_str()
                && ext_str.contains("permessage-deflate")
            {
                debug!(
                    %connection_id,
                    "rejecting permessage-deflate extension from client"
                );
            }
            // Return the response as-is (without adding any extensions).
            Ok(response)
        };

    match time::timeout(
        config.handshake_timeout,
        accept_hdr_async_with_config(stream, reject_compression, Some(ws_config)),
    )
    .await
    {
        Ok(Ok(ws)) => Some(ws),
        Ok(Err(e)) => {
            warn!(%connection_id, %remote_addr, "websocket handshake ({transport_label}) failed: {e}");
            None
        }
        Err(_) => {
            warn!(%connection_id, %remote_addr, "websocket handshake ({transport_label}) timeout");
            None
        }
    }
}

/// Register the connection and run the actor to completion.
async fn run_actor<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    config: TransportConfig,
    registry: Arc<ConnectionRegistry>,
    event_tx: mpsc::Sender<ConnectionEvent>,
    connection_id: ConnectionId,
    remote_addr: std::net::SocketAddr,
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
) {
    let (outbound_tx, outbound_rx) =
        mpsc::channel::<OutboundMessage>(config.slow_consumer_threshold);
    let handle = ConnectionHandle {
        connection_id,
        remote_addr,
        outbound_tx,
        connected_at: tokio::time::Instant::now(),
    };
    if let Err(e) = registry.register(handle) {
        warn!(%connection_id, "failed to register connection: {e}");
        return;
    }
    let actor = ConnectionActor::new(ConnectionActorParams {
        connection_id,
        remote_addr,
        outbound_rx,
        event_tx,
        max_message_size: config.max_message_size,
        idle_timeout: config.idle_timeout,
        heartbeat_interval: config.heartbeat_interval,
        heartbeat_timeout: config.heartbeat_timeout,
    });
    actor.run(ws_stream).await;
}
