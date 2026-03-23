//! Per-connection actor.
//!
//! Each accepted WebSocket connection is driven by its own tokio task
//! running [`ConnectionActor::run`]. The actor manages:
//!
//! - Inbound message dispatch to the server via a shared event channel.
//! - Outbound message delivery from a bounded per-connection channel.
//! - Heartbeat (ping/pong) monitoring.
//! - Idle-timeout enforcement.
//! - Slow-consumer detection and eviction.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::{self, Instant};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::{debug, info, warn};

use crate::types::ConnectionId;

// ---------------------------------------------------------------------------
// Public message types
// ---------------------------------------------------------------------------

/// A message destined for a connected client, enqueued by the server layer.
#[derive(Debug)]
pub enum OutboundMessage {
    /// Send a UTF-8 text frame.
    Text(String),
    /// Send a UTF-8 text frame backed by a shared `Arc<str>`.
    /// Cloning this variant is O(1) (reference count bump), avoiding
    /// per-recipient heap allocation in broadcast scenarios.
    SharedText(Arc<str>),
    /// Send a binary frame.
    Binary(Vec<u8>),
    /// Initiate a graceful close with the given status code and reason.
    Close(u16, String),
}

/// Events emitted by a connection actor back to the server layer.
#[derive(Debug)]
pub enum ConnectionEvent {
    /// A new WebSocket connection has been established and registered.
    ///
    /// Emitted immediately after registration so the server layer can
    /// send initial frames (e.g., auth challenge nonces) before the
    /// client sends any messages.
    Connected {
        /// The newly assigned connection identifier.
        connection_id: ConnectionId,
        /// Remote socket address.
        remote_addr: SocketAddr,
    },
    /// A text message was received from the client.
    MessageReceived {
        /// The connection that produced this message.
        connection_id: ConnectionId,
        /// Raw text payload (unparsed).
        message: String,
        /// Remote socket address.
        remote_addr: SocketAddr,
    },
    /// The connection has been closed (cleanly or due to error).
    Disconnected {
        /// The connection that disconnected.
        connection_id: ConnectionId,
        /// Human-readable reason for the disconnection.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// Parameters for constructing a [`ConnectionActor`].
///
/// Grouped to avoid excessive constructor arguments.
pub struct ConnectionActorParams {
    /// Unique connection identifier.
    pub connection_id: ConnectionId,
    /// Remote peer address.
    pub remote_addr: SocketAddr,
    /// Receiver for outbound messages from the server layer.
    pub outbound_rx: mpsc::Receiver<OutboundMessage>,
    /// Sender for events back to the server layer.
    pub event_tx: mpsc::Sender<ConnectionEvent>,
    /// Maximum allowed message size in bytes.
    pub max_message_size: usize,
    /// Duration of inactivity before disconnect.
    pub idle_timeout: Duration,
    /// Interval between heartbeat pings.
    pub heartbeat_interval: Duration,
    /// Maximum time to wait for a pong response.
    pub heartbeat_timeout: Duration,
}

/// The per-connection actor.
///
/// Created by [`WebSocketListener`](crate::listener::WebSocketListener) for
/// every accepted connection and driven on its own tokio task.
pub struct ConnectionActor {
    connection_id: ConnectionId,
    remote_addr: SocketAddr,
    outbound_rx: mpsc::Receiver<OutboundMessage>,
    event_tx: mpsc::Sender<ConnectionEvent>,
    max_message_size: usize,
    idle_timeout: Duration,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
}

impl ConnectionActor {
    /// Create a new connection actor from the given parameters.
    ///
    /// The caller retains the sending half of `outbound_rx` (wrapped in
    /// a [`ConnectionHandle`](crate::connection_registry::ConnectionHandle))
    /// so that the server layer can push frames to this connection.
    #[must_use]
    pub fn new(params: ConnectionActorParams) -> Self {
        Self {
            connection_id: params.connection_id,
            remote_addr: params.remote_addr,
            outbound_rx: params.outbound_rx,
            event_tx: params.event_tx,
            max_message_size: params.max_message_size,
            idle_timeout: params.idle_timeout,
            heartbeat_interval: params.heartbeat_interval,
            heartbeat_timeout: params.heartbeat_timeout,
        }
    }

    /// Drive the connection to completion.
    ///
    /// This method takes ownership of `self` and the WebSocket stream,
    /// running until the connection is closed (cleanly, by error, or by
    /// timeout). On exit it always emits a [`ConnectionEvent::Disconnected`].
    pub async fn run<S>(mut self, ws_stream: WebSocketStream<S>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (ws_sink, ws_source) = ws_stream.split();
        let reason = self.event_loop(ws_sink, ws_source).await;

        info!(
            connection_id = %self.connection_id,
            remote_addr = %self.remote_addr,
            %reason,
            "connection closed",
        );

        // Best-effort notification — if the receiver is gone we just drop it.
        let _ = self
            .event_tx
            .send(ConnectionEvent::Disconnected {
                connection_id: self.connection_id,
                reason,
            })
            .await;
    }

    /// The core select loop. Returns the disconnection reason.
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)] // Inherent complexity of a 4-arm select loop
    async fn event_loop<S>(
        &mut self,
        mut ws_sink: SplitSink<WebSocketStream<S>, WsMessage>,
        mut ws_source: SplitStream<WebSocketStream<S>>,
    ) -> String
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut heartbeat_interval = time::interval(self.heartbeat_interval);
        // The first tick fires immediately — consume it so the first
        // real ping goes out after one full interval.
        heartbeat_interval.tick().await;

        let mut last_activity = Instant::now();
        let mut last_pong = Instant::now();

        loop {
            tokio::select! {
                biased;

                // ---- Inbound from client ----
                frame = ws_source.next() => {
                    match frame {
                        Some(Ok(msg)) => {
                            last_activity = Instant::now();

                            match msg {
                                WsMessage::Text(text) => {
                                    if text.len() > self.max_message_size {
                                        warn!(
                                            connection_id = %self.connection_id,
                                            size = text.len(),
                                            max = self.max_message_size,
                                            "message too large, closing",
                                        );
                                        let _ = send_close(
                                            &mut ws_sink,
                                            CloseCode::Size,
                                            "message too large",
                                        ).await;
                                        return format!(
                                            "message too large: {} > {}",
                                            text.len(),
                                            self.max_message_size,
                                        );
                                    }
                                    if self.emit_message_received(text.to_string()).await.is_err() {
                                        return "event channel closed".to_owned();
                                    }
                                }
                                WsMessage::Binary(data) => {
                                    if data.len() > self.max_message_size {
                                        let _ = send_close(
                                            &mut ws_sink,
                                            CloseCode::Size,
                                            "message too large",
                                        ).await;
                                        return format!(
                                            "binary message too large: {} > {}",
                                            data.len(),
                                            self.max_message_size,
                                        );
                                    }
                                    // Convert binary to text and route it.
                                    let Ok(text) = String::from_utf8(data.to_vec()) else {
                                        debug!(
                                            connection_id = %self.connection_id,
                                            "non-UTF8 binary frame dropped",
                                        );
                                        continue;
                                    };
                                    last_activity = Instant::now();
                                    if self.emit_message_received(text).await.is_err() {
                                        return "event channel closed".to_owned();
                                    }
                                }
                                WsMessage::Ping(payload) => {
                                    // RFC 6455: respond with matching Pong.
                                    if ws_sink.send(WsMessage::Pong(payload)).await.is_err() {
                                        return "failed to send pong".to_owned();
                                    }
                                }
                                WsMessage::Pong(_) => {
                                    last_pong = Instant::now();
                                }
                                WsMessage::Close(_) => {
                                    return "client initiated close".to_owned();
                                }
                                // Raw frame — not expected in normal
                                // operation; silently ignore.
                                WsMessage::Frame(_) => {}
                            }
                        }
                        Some(Err(e)) => {
                            return format!("websocket read error: {e}");
                        }
                        None => {
                            return "websocket stream ended".to_owned();
                        }
                    }
                }

                // ---- Outbound to client ----
                msg = self.outbound_rx.recv() => {
                    if let Some(outbound) = msg {
                        let ws_msg = match outbound {
                            OutboundMessage::Text(t) => WsMessage::text(t),
                            OutboundMessage::SharedText(t) => WsMessage::text(t.as_ref()),
                            OutboundMessage::Binary(b) => WsMessage::binary(b),
                            OutboundMessage::Close(code, reason) => {
                                let _ = send_close(
                                    &mut ws_sink,
                                    CloseCode::from(code),
                                    &reason,
                                ).await;
                                return format!("server close: {reason}");
                            }
                        };
                        if ws_sink.send(ws_msg).await.is_err() {
                            return "failed to send outbound frame".to_owned();
                        }
                    } else {
                        // The server dropped our outbound sender — shut down.
                        let _ = send_close(
                            &mut ws_sink,
                            CloseCode::Away,
                            "server shutting down",
                        ).await;
                        return "outbound channel closed".to_owned();
                    }
                }

                // ---- Heartbeat tick ----
                _ = heartbeat_interval.tick() => {
                    // Check if the peer has responded to previous pings.
                    let since_pong = Instant::now().duration_since(last_pong);
                    if since_pong > self.heartbeat_timeout {
                        warn!(
                            connection_id = %self.connection_id,
                            elapsed = ?since_pong,
                            timeout = ?self.heartbeat_timeout,
                            "heartbeat timeout",
                        );
                        let _ = send_close(
                            &mut ws_sink,
                            CloseCode::Away,
                            "heartbeat timeout",
                        ).await;
                        return "heartbeat timeout".to_owned();
                    }

                    // Send a ping.
                    if ws_sink.send(WsMessage::Ping(Vec::new().into())).await.is_err() {
                        return "failed to send ping".to_owned();
                    }
                }

                // ---- Idle timeout ----
                () = tokio::time::sleep_until(last_activity + self.idle_timeout) => {
                    info!(
                        connection_id = %self.connection_id,
                        timeout = ?self.idle_timeout,
                        "idle timeout",
                    );
                    let _ = send_close(
                        &mut ws_sink,
                        CloseCode::Away,
                        "idle timeout",
                    ).await;
                    return "idle timeout".to_owned();
                }
            }
        }
    }

    /// Forward a received text message to the server event channel.
    async fn emit_message_received(&self, message: String) -> Result<(), ()> {
        self.event_tx
            .send(ConnectionEvent::MessageReceived {
                connection_id: self.connection_id,
                message,
                remote_addr: self.remote_addr,
            })
            .await
            .map_err(|_| ())
    }
}

/// Send a WebSocket close frame. Best-effort — errors are ignored.
async fn send_close<S>(
    sink: &mut SplitSink<WebSocketStream<S>, WsMessage>,
    code: CloseCode,
    reason: &str,
) -> Result<(), ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = CloseFrame {
        code,
        reason: reason.to_owned().into(),
    };
    sink.send(WsMessage::Close(Some(frame)))
        .await
        .map_err(|_| ())
}
