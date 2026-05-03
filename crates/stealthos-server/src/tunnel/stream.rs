//! Per-stream bridge between the WebSocket and a real `tokio::net` socket.
//!
//! Each open stream owns one of these tasks. The task multiplexes:
//!  - outbound bytes from the WebSocket toward the destination (`outbound_rx`),
//!  - inbound bytes from the destination toward the WebSocket,
//!  - cancellation (`cancel`),
//!  - idle and connect timeouts.
//!
//! Backpressure / flow control:
//!
//! - **Server -> Member credit**: the member sends `tunnel_open.initial_window`
//!   as the initial credit. Every `TUNNEL_DATA` frame the server emits subtracts
//!   `payload.len()` from `member_credit`. If the credit drops to ≤ 0 the
//!   server stops draining the destination socket — TCP backpressure
//!   propagates upstream naturally. The member tops up via
//!   `tunnel_window_update`.
//! - **Member -> Server credit**: the server-side `initial_receive_window`
//!   bounds how much un-acked data the member can stuff into the destination
//!   queue. Every `window_update_threshold` bytes drained into the destination,
//!   the server emits `tunnel_window_update` upstream so the member knows it
//!   can keep sending.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use stealthos_core::server_frame::{
    CloseReason, ServerFrame, TunnelCloseData, TunnelNetwork, TunnelWindowUpdateData,
};
use stealthos_core::types::ConnectionId;
use stealthos_transport::ConnectionRegistry;
use stealthos_transport::connection::OutboundMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Instant, sleep_until, timeout};
use tracing::debug;

use super::{encode_tunnel_data, encode_tunnel_udp};

/// Owned per-stream state passed into the spawned bridge task.
pub struct StreamHandle {
    pub connection_id: ConnectionId,
    pub stream_id: u32,
    pub network: TunnelNetwork,
    /// Resolved-and-policy-checked destination addresses, in resolver order.
    pub destinations: Vec<SocketAddr>,
    /// Bytes the member pushed via `tunnel_data` / `tunnel_udp` heading
    /// toward the destination socket.
    pub outbound_rx: mpsc::Receiver<Vec<u8>>,
    /// Cancel signal — `notify_waiters()` aborts the bridge.
    pub cancel: Arc<Notify>,
    /// Wake signal — tripped on member-credit refill. Distinct from `cancel`
    /// so credit refills don't abort the stream.
    pub wake: Arc<Notify>,
    /// Credit (in bytes) the server may still send to the member.
    pub member_credit: Arc<AtomicI64>,
    /// Server-side per-stream sequence counter for outbound `TUNNEL_DATA`.
    pub sequence: Arc<AtomicU32>,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_payload_bytes: usize,
    pub initial_receive_window: u32,
    pub window_update_threshold: u32,
    pub connection_registry: Arc<ConnectionRegistry>,
}

impl StreamHandle {
    /// Drive the stream to completion. Always emits a `tunnel_close` to the
    /// member on exit, with an appropriate `CloseReason`.
    pub async fn run(mut self) {
        let close_reason = match self.network {
            TunnelNetwork::Tcp => self.run_tcp().await,
            TunnelNetwork::Udp => self.run_udp().await,
        };
        let frame = ServerFrame::TunnelClose(TunnelCloseData {
            stream_id: self.stream_id,
            reason: close_reason,
        });
        self.send_json(&frame);
    }

    async fn run_tcp(&mut self) -> CloseReason {
        // Try each resolved address in order until one succeeds.
        let mut last_kind: Option<std::io::ErrorKind> = None;
        let mut tcp: Option<TcpStream> = None;
        for addr in &self.destinations {
            match timeout(self.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    if let Err(e) = stream.set_nodelay(true) {
                        debug!(
                            connection = %self.connection_id,
                            stream = self.stream_id,
                            "set_nodelay failed: {e}"
                        );
                    }
                    tcp = Some(stream);
                    break;
                }
                Ok(Err(e)) => {
                    debug!(
                        connection = %self.connection_id,
                        stream = self.stream_id,
                        addr = %addr,
                        "tcp connect failed: {e}"
                    );
                    last_kind = Some(e.kind());
                }
                Err(_) => {
                    return CloseReason::Timeout;
                }
            }
        }
        let Some(tcp) = tcp else {
            return match last_kind {
                Some(std::io::ErrorKind::ConnectionRefused) => CloseReason::ConnectionRefused,
                _ => CloseReason::DestinationUnreachable,
            };
        };
        self.bridge_tcp(tcp).await
    }

    async fn bridge_tcp(&mut self, tcp: TcpStream) -> CloseReason {
        // Grant the member its initial send-credit (member -> server). Without
        // this the member would not know how much it may push before waiting
        // for a `tunnel_window_update`.
        if self.initial_receive_window > 0 {
            self.send_window_update(self.initial_receive_window);
        }

        let (mut read_half, mut write_half) = tcp.into_split();
        let mut read_buf = vec![0u8; self.max_payload_bytes];
        let mut bytes_consumed_since_update: u64 = 0;
        let mut last_activity = Instant::now();
        let mut peer_closed_write = false;

        loop {
            // Whether we may currently read from the destination. If the
            // server has no credit to forward bytes to the member, skip the
            // read arm so OS buffers fill up and TCP backpressures upstream.
            let may_read = self.member_credit.load(Ordering::Acquire) > 0 && !peer_closed_write;
            let idle_deadline = last_activity + self.idle_timeout;

            tokio::select! {
                biased;

                // Cancellation
                () = self.cancel.notified() => {
                    return CloseReason::Aborted;
                }

                // Wake-up (e.g. credit refill). Just loop and re-evaluate
                // `may_read`. Do NOT update `last_activity`: a wake is not
                // proof that the destination saw any bytes.
                () = self.wake.notified() => {
                    // Wake-up arm intentionally has an empty body — falling
                    // through the select! and looping re-evaluates `may_read`.
                }

                // Outbound chunk from member -> destination.
                chunk = self.outbound_rx.recv() => {
                    let Some(chunk) = chunk else {
                        // The gateway dropped the sender — treat as peer close.
                        return CloseReason::PeerClosed;
                    };
                    last_activity = Instant::now();
                    if let Err(e) = write_half.write_all(&chunk).await {
                        debug!(
                            connection = %self.connection_id,
                            stream = self.stream_id,
                            "write to destination failed: {e}"
                        );
                        return CloseReason::Aborted;
                    }
                    // Account toward the member->server window.
                    bytes_consumed_since_update +=
                        u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                    if bytes_consumed_since_update
                        >= u64::from(self.window_update_threshold)
                    {
                        let credit = u32::try_from(bytes_consumed_since_update)
                            .unwrap_or(u32::MAX);
                        self.send_window_update(credit);
                        bytes_consumed_since_update = 0;
                    }
                }

                // Destination -> member, gated on credit.
                read = async {
                    if may_read {
                        read_half.read(&mut read_buf).await
                    } else {
                        // Park forever; the cancel / outbound_rx / idle arms
                        // will move the loop forward.
                        std::future::pending::<std::io::Result<usize>>().await
                    }
                } => {
                    match read {
                        Ok(0) => {
                            // Destination closed its write half. Forward an
                            // empty TUNNEL_DATA so the member knows EOF, then
                            // continue draining outbound until member closes.
                            peer_closed_write = true;
                            // Emit an empty data frame as EOF marker.
                            let seq = self.sequence.fetch_add(1, Ordering::AcqRel);
                            let frame = encode_tunnel_data(self.stream_id, seq, &[]);
                            if !self.send_binary(&frame) {
                                return CloseReason::Aborted;
                            }
                        }
                        Ok(n) => {
                            last_activity = Instant::now();
                            // Decrement the member-credit counter BEFORE
                            // sending, so a slow WS sender cannot transiently
                            // overrun the member's stated window.
                            // `n` is bounded by `read_buf.len() == max_payload_bytes` (32 KiB
                            // by default) so the `try_from` is effectively infallible; on
                            // overflow we fall back to `i64::MAX` as a safe upper bound.
                            let cost = i64::try_from(n).unwrap_or(i64::MAX);
                            self.member_credit.fetch_sub(cost, Ordering::AcqRel);
                            let seq = self.sequence.fetch_add(1, Ordering::AcqRel);
                            let frame = encode_tunnel_data(self.stream_id, seq, &read_buf[..n]);
                            if !self.send_binary(&frame) {
                                return CloseReason::Aborted;
                            }
                        }
                        Err(e) => {
                            debug!(
                                connection = %self.connection_id,
                                stream = self.stream_id,
                                "read from destination failed: {e}"
                            );
                            return CloseReason::Aborted;
                        }
                    }
                }

                // Idle timeout
                () = sleep_until(idle_deadline) => {
                    return CloseReason::IdleTimeout;
                }
            }
        }
    }

    async fn run_udp(&mut self) -> CloseReason {
        // For UDP, "connect" is binding a local socket. Use the resolver's
        // first address as the peer; any datagrams received from a different
        // peer are silently dropped.
        let Some(peer) = self.destinations.first().copied() else {
            return CloseReason::DestinationUnreachable;
        };

        let bind_addr: SocketAddr = if peer.is_ipv4() {
            "0.0.0.0:0".parse().expect("static")
        } else {
            "[::]:0".parse().expect("static")
        };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    connection = %self.connection_id,
                    stream = self.stream_id,
                    "udp bind failed: {e}"
                );
                return CloseReason::DestinationUnreachable;
            }
        };
        if socket.connect(peer).await.is_err() {
            return CloseReason::DestinationUnreachable;
        }

        // Grant the member its initial send-credit on UDP as well.
        if self.initial_receive_window > 0 {
            self.send_window_update(self.initial_receive_window);
        }

        let mut recv_buf = vec![0u8; self.max_payload_bytes];
        let mut bytes_consumed_since_update: u64 = 0;
        let mut last_activity = Instant::now();

        loop {
            let may_read = self.member_credit.load(Ordering::Acquire) > 0;
            let idle_deadline = last_activity + self.idle_timeout;

            tokio::select! {
                biased;

                () = self.cancel.notified() => {
                    return CloseReason::Aborted;
                }

                () = self.wake.notified() => {
                    // Wake-up arm intentionally has an empty body — falling
                    // through the select! and looping re-evaluates `may_read`.
                }

                datagram = self.outbound_rx.recv() => {
                    let Some(datagram) = datagram else {
                        return CloseReason::PeerClosed;
                    };
                    last_activity = Instant::now();
                    if let Err(e) = socket.send(&datagram).await {
                        debug!(
                            connection = %self.connection_id,
                            stream = self.stream_id,
                            "udp send failed: {e}"
                        );
                        return CloseReason::Aborted;
                    }
                    bytes_consumed_since_update +=
                        u64::try_from(datagram.len()).unwrap_or(u64::MAX);
                    if bytes_consumed_since_update
                        >= u64::from(self.window_update_threshold)
                    {
                        let credit = u32::try_from(bytes_consumed_since_update)
                            .unwrap_or(u32::MAX);
                        self.send_window_update(credit);
                        bytes_consumed_since_update = 0;
                    }
                }

                received = async {
                    if may_read {
                        socket.recv(&mut recv_buf).await
                    } else {
                        std::future::pending::<std::io::Result<usize>>().await
                    }
                } => {
                    match received {
                        Ok(n) => {
                            last_activity = Instant::now();
                            // `n` is bounded by `read_buf.len() == max_payload_bytes` (32 KiB
                            // by default) so the `try_from` is effectively infallible; on
                            // overflow we fall back to `i64::MAX` as a safe upper bound.
                            let cost = i64::try_from(n).unwrap_or(i64::MAX);
                            self.member_credit.fetch_sub(cost, Ordering::AcqRel);
                            let frame = encode_tunnel_udp(self.stream_id, &recv_buf[..n]);
                            if !self.send_binary(&frame) {
                                return CloseReason::Aborted;
                            }
                        }
                        Err(e) => {
                            debug!(
                                connection = %self.connection_id,
                                stream = self.stream_id,
                                "udp recv failed: {e}"
                            );
                            return CloseReason::Aborted;
                        }
                    }
                }

                () = sleep_until(idle_deadline) => {
                    return CloseReason::IdleTimeout;
                }
            }
        }
    }

    fn send_json(&self, frame: &ServerFrame) {
        let Ok(json) = serde_json::to_string(frame) else {
            return;
        };
        let _ = self
            .connection_registry
            .send_to(self.connection_id, OutboundMessage::Text(json));
    }

    fn send_binary(&self, payload: &Bytes) -> bool {
        self.connection_registry
            .send_to(
                self.connection_id,
                OutboundMessage::Binary(payload.to_vec()),
            )
            .is_ok()
    }

    fn send_window_update(&self, additional_credit: u32) {
        let frame = ServerFrame::TunnelWindowUpdate(TunnelWindowUpdateData {
            stream_id: self.stream_id,
            additional_credit,
        });
        self.send_json(&frame);
    }
}
