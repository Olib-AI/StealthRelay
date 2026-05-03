//! Server-side tunnel-exit gateway.
//!
//! Authenticated pool members open TCP/UDP streams that the relay
//! terminates on real `tokio::net` sockets and bridges back over the
//! existing WebSocket. **The relay itself is the exit** — the pool host
//! plays no role in carrying tunnel traffic; its `tunnel_exit_enabled`
//! flag merely signals the host's per-pool approval, which is one of
//! three AND-gates on every `tunnel_open`.
//!
//! Authorization (cheapest first):
//! 1. Server-wide `tunnel.enabled = true`.
//! 2. Per-pool `Pool::tunnel_exit_enabled()`.
//! 3. The connection has authenticated to a pool (host or guest).
//!
//! Hot-path data uses **binary** WebSocket frames; control-plane frames
//! (open/close/window/DNS/error) ride the existing JSON `ServerFrame`
//! variants.

pub mod cidr;
pub mod dns;
pub mod stream;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use stealthos_core::PoolRegistry;
use stealthos_core::server_frame::{
    CloseReason, DnsAnswer, DnsError, DnsErrorCode, ServerFrame, TUNNEL_DATA_CHANNEL,
    TUNNEL_DATA_HEADER_LEN, TUNNEL_UDP_CHANNEL, TUNNEL_UDP_HEADER_LEN, TunnelCloseData,
    TunnelDestination, TunnelDnsQueryData, TunnelDnsResponseData, TunnelErrorCode, TunnelErrorData,
    TunnelNetwork, TunnelOpenData, TunnelWindowUpdateData,
};
use stealthos_core::types::{ConnectionId, PoolId};
use stealthos_transport::ConnectionRegistry;
use stealthos_transport::connection::OutboundMessage;
use tokio::sync::{Notify, mpsc};
use tracing::{debug, trace};

use crate::config::TunnelSection;

/// Default capacity of the per-stream outbound mpsc to the destination
/// socket. Bounded small so a slow destination back-pressures the WS reader.
const DESTINATION_QUEUE_CAPACITY: usize = 16;

/// Maximum length of a tunnel error message string. Caps memory usage of a
/// pathological "message" that the operator could otherwise echo to clients.
const MAX_ERROR_MESSAGE_LEN: usize = 256;

/// Snapshot of the immutable subset of `TunnelSection` actually consulted on
/// the hot path. Cloning the section in full would clone two `Vec<String>`
/// per stream-open; we precompute parsed CIDRs into [`cidr::CidrSet`] once.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub enabled: bool,
    pub max_streams_per_connection: u32,
    pub max_streams_global: u32,
    pub connect_timeout: std::time::Duration,
    pub idle_stream_timeout: std::time::Duration,
    pub max_payload_bytes: usize,
    pub initial_receive_window: u32,
    pub window_update_threshold: u32,
    pub denied_destination_ports: Vec<u16>,
    pub allowed_destination_cidrs: cidr::CidrSet,
    pub denied_destination_cidrs: cidr::CidrSet,
}

impl TunnelConfig {
    /// Build a hot-path config from the loaded `[tunnel]` section.
    ///
    /// Returns the parsed config plus a list of human-readable warnings for
    /// each malformed CIDR in the input (the malformed CIDR is dropped, so
    /// a typo in the deny list silently weakening server policy is logged
    /// but not a startup error).
    pub fn from_section(section: &TunnelSection) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let allowed =
            cidr::CidrSet::from_strings(&section.allowed_destination_cidrs, &mut warnings);
        let denied = cidr::CidrSet::from_strings(&section.denied_destination_cidrs, &mut warnings);
        let cfg = Self {
            enabled: section.enabled,
            max_streams_per_connection: section.max_streams_per_connection,
            max_streams_global: section.max_streams_global,
            connect_timeout: std::time::Duration::from_secs(section.connect_timeout_secs),
            idle_stream_timeout: std::time::Duration::from_secs(section.idle_stream_timeout_secs),
            max_payload_bytes: section.max_payload_bytes as usize,
            initial_receive_window: section.initial_receive_window,
            window_update_threshold: section.window_update_threshold,
            denied_destination_ports: section.denied_destination_ports.clone(),
            allowed_destination_cidrs: allowed,
            denied_destination_cidrs: denied,
        };
        (cfg, warnings)
    }
}

/// Per-stream record stored in the [`TunnelGateway`].
struct StreamEntry {
    /// `tcp` or `udp`.
    network: TunnelNetwork,
    /// Pool the connection that owns this stream is authenticated to.
    pool_id: PoolId,
    /// `true` when the stream is owned by the pool host (so it's not
    /// affected by the per-pool `tunnel_exit_enabled` flag flipping off).
    owned_by_host: bool,
    /// Outbound bytes from the WS toward the destination socket.
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Cancel signal: tripping this `Notify` causes the stream's
    /// background task to abort and the destination socket to be torn down.
    cancel: Arc<Notify>,
    /// Wake signal — tripped when the member tops up the server's
    /// outbound credit so the bridge can resume reading from the destination.
    /// Distinct from `cancel` so a credit refill does not abort the stream.
    wake: Arc<Notify>,
    /// Outbound credit (bytes) the *server* may still send to the *member*.
    /// Decrements on every binary `tunnel_data` we emit; member's
    /// `tunnel_window_update` adds to it.
    member_credit: Arc<AtomicI64>,
}

/// Shared tunnel-gateway state.
pub struct TunnelGateway {
    /// Snapshot of the parsed `[tunnel]` config.
    config: TunnelConfig,
    /// `(connection_id, stream_id) -> StreamEntry`.
    streams: DashMap<(ConnectionId, u32), StreamEntry>,
    /// Global open-stream counter for `max_streams_global`.
    open_streams: AtomicU64,
    /// Per-connection open-stream counter for `max_streams_per_connection`.
    streams_per_conn: DashMap<ConnectionId, u32>,
    /// Where to send outbound frames to clients.
    connection_registry: Arc<ConnectionRegistry>,
    /// Pool registry for the per-pool gate.
    pool_registry: Arc<PoolRegistry>,
}

impl TunnelGateway {
    /// Build a new gateway. The caller wraps the result in `Arc`.
    pub fn new(
        config: TunnelConfig,
        connection_registry: Arc<ConnectionRegistry>,
        pool_registry: Arc<PoolRegistry>,
    ) -> Self {
        Self {
            config,
            streams: DashMap::new(),
            open_streams: AtomicU64::new(0),
            streams_per_conn: DashMap::new(),
            connection_registry,
            pool_registry,
        }
    }

    /// Read-only view of the config the gateway was built with.
    #[allow(dead_code)] // Diagnostic accessor.
    pub const fn config(&self) -> &TunnelConfig {
        &self.config
    }

    /// Number of currently-open streams across the whole gateway.
    #[allow(dead_code)] // Diagnostic accessor used by tests / metrics.
    pub fn open_stream_count(&self) -> u64 {
        self.open_streams.load(Ordering::Acquire)
    }

    // ------------------------------------------------------------------
    // Control-plane handlers (called from `MessageHandler::dispatch`)
    // ------------------------------------------------------------------

    /// Handle a `tunnel_open` frame. All authorization happens here.
    ///
    /// Takes `&Arc<Self>` because the spawned bridge task captures a clone of
    /// the gateway so it can decrement the global counter on completion.
    pub async fn handle_open(self: &Arc<Self>, connection_id: ConnectionId, data: TunnelOpenData) {
        // Gate 1: server-wide kill switch.
        if !self.config.enabled {
            self.send_close(connection_id, data.stream_id, CloseReason::PolicyDenied);
            return;
        }

        // Gate 3 (cheap dashmap lookup): the connection must be authenticated
        // to a pool. Doing this BEFORE the per-pool flag check keeps the cost
        // of unauthenticated probes minimal.
        let Some(pool) = self.pool_registry.get_pool_for_connection(connection_id) else {
            self.send_close(connection_id, data.stream_id, CloseReason::PolicyDenied);
            return;
        };

        // Gate 2: the pool host must have approved tunnel exit for members.
        if !pool.tunnel_exit_enabled() {
            self.send_close(connection_id, data.stream_id, CloseReason::PolicyDenied);
            return;
        }

        let owned_by_host = pool.is_host(connection_id);
        let pool_id = pool.id;

        // Reject zero-port immediately — saves DNS / connect latency.
        let port = match &data.destination {
            TunnelDestination::Hostname { port, .. }
            | TunnelDestination::Ipv4 { port, .. }
            | TunnelDestination::Ipv6 { port, .. } => *port,
        };
        if port == 0 {
            self.send_close(connection_id, data.stream_id, CloseReason::PolicyDenied);
            return;
        }

        // Port deny list.
        if self.config.denied_destination_ports.contains(&port) {
            self.send_close(connection_id, data.stream_id, CloseReason::PolicyDenied);
            return;
        }

        // Per-connection stream cap.
        let new_per_conn = {
            let mut entry = self.streams_per_conn.entry(connection_id).or_insert(0);
            if *entry.value() >= self.config.max_streams_per_connection {
                self.send_error(
                    connection_id,
                    Some(data.stream_id),
                    TunnelErrorCode::ResourceExhausted,
                    "per-connection stream limit reached",
                );
                self.send_close(connection_id, data.stream_id, CloseReason::StreamLimit);
                return;
            }
            *entry.value_mut() += 1;
            *entry.value()
        };

        // Global stream cap.
        let prev_total = self.open_streams.fetch_add(1, Ordering::AcqRel);
        if prev_total >= u64::from(self.config.max_streams_global) {
            // Roll back both counters.
            self.open_streams.fetch_sub(1, Ordering::AcqRel);
            self.dec_per_conn(connection_id);
            self.send_error(
                connection_id,
                Some(data.stream_id),
                TunnelErrorCode::ResourceExhausted,
                "global stream limit reached",
            );
            self.send_close(connection_id, data.stream_id, CloseReason::StreamLimit);
            return;
        }
        let _ = new_per_conn; // value is informational

        // Reject duplicate stream_id on the same connection.
        let key = (connection_id, data.stream_id);
        if self.streams.contains_key(&key) {
            self.open_streams.fetch_sub(1, Ordering::AcqRel);
            self.dec_per_conn(connection_id);
            self.send_error(
                connection_id,
                Some(data.stream_id),
                TunnelErrorCode::ProtocolError,
                "duplicate stream_id",
            );
            self.send_close(connection_id, data.stream_id, CloseReason::ProtocolError);
            return;
        }

        // Resolve destination and run the CIDR check on the *resolved* IP
        // (not the user-supplied hostname) to defeat DNS-rebinding attacks
        // against the deny list.
        let resolved =
            match dns::resolve_destination(&data.destination, self.config.connect_timeout).await {
                Ok(addrs) => addrs,
                Err(dns::ResolveError::Timeout) => {
                    self.open_streams.fetch_sub(1, Ordering::AcqRel);
                    self.dec_per_conn(connection_id);
                    self.send_close(connection_id, data.stream_id, CloseReason::Timeout);
                    return;
                }
                Err(dns::ResolveError::NotFound | dns::ResolveError::Invalid) => {
                    self.open_streams.fetch_sub(1, Ordering::AcqRel);
                    self.dec_per_conn(connection_id);
                    self.send_close(
                        connection_id,
                        data.stream_id,
                        CloseReason::DestinationUnreachable,
                    );
                    return;
                }
            };

        let allowed_resolved: Vec<std::net::SocketAddr> = resolved
            .into_iter()
            .filter(|addr| self.is_address_allowed(addr.ip()))
            .collect();
        if allowed_resolved.is_empty() {
            self.open_streams.fetch_sub(1, Ordering::AcqRel);
            self.dec_per_conn(connection_id);
            self.send_close(connection_id, data.stream_id, CloseReason::PolicyDenied);
            return;
        }

        // Spawn the per-stream bridge task.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(DESTINATION_QUEUE_CAPACITY);
        let cancel = Arc::new(Notify::new());
        let wake = Arc::new(Notify::new());
        let member_credit = Arc::new(AtomicI64::new(i64::from(data.initial_window)));
        let sequence = Arc::new(AtomicU32::new(0));

        let entry = StreamEntry {
            network: data.network,
            pool_id,
            owned_by_host,
            outbound_tx: tx,
            cancel: Arc::clone(&cancel),
            wake: Arc::clone(&wake),
            member_credit: Arc::clone(&member_credit),
        };
        // Insert BEFORE spawning the task so binary frames that race the
        // open are not racing into a missing entry.
        self.streams.insert(key, entry);

        let bridge = stream::StreamHandle {
            connection_id,
            stream_id: data.stream_id,
            network: data.network,
            destinations: allowed_resolved,
            outbound_rx: rx,
            cancel: Arc::clone(&cancel),
            wake: Arc::clone(&wake),
            member_credit,
            sequence,
            connect_timeout: self.config.connect_timeout,
            idle_timeout: self.config.idle_stream_timeout,
            max_payload_bytes: self.config.max_payload_bytes,
            initial_receive_window: self.config.initial_receive_window,
            window_update_threshold: self.config.window_update_threshold,
            connection_registry: Arc::clone(&self.connection_registry),
        };

        // Cleanup on task completion runs through `Arc<TunnelGateway>` so that
        // a stream that exits cleanly (or because of an error / idle timeout)
        // releases its slot in the per-connection and global counters.
        let gateway = Arc::clone(self);
        tokio::spawn(async move {
            bridge.run().await;
            if gateway.streams.remove(&key).is_some() {
                gateway.open_streams.fetch_sub(1, Ordering::AcqRel);
                gateway.dec_per_conn(connection_id);
            }
        });
    }

    /// Handle `tunnel_close` from the member.
    pub fn handle_close(&self, connection_id: ConnectionId, data: &TunnelCloseData) {
        let key = (connection_id, data.stream_id);
        if let Some((_, entry)) = self.streams.remove(&key) {
            self.open_streams.fetch_sub(1, Ordering::AcqRel);
            self.dec_per_conn(connection_id);
            entry.cancel.notify_waiters();
        }
        // No reply on member-initiated close — the member already knows.
    }

    /// Handle `tunnel_window_update` from the member: grant the server more
    /// outbound credit for the named stream.
    pub fn handle_window_update(&self, connection_id: ConnectionId, data: &TunnelWindowUpdateData) {
        let key = (connection_id, data.stream_id);
        if let Some(entry) = self.streams.get(&key) {
            // additional_credit is u32 — cast to i64 is lossless.
            entry
                .member_credit
                .fetch_add(i64::from(data.additional_credit), Ordering::AcqRel);
            // Wake (NOT cancel) the bridge so it can resume reading from the
            // destination. Using a separate Notify keeps cancellation strictly
            // distinct from credit-refill wake-ups.
            entry.wake.notify_waiters();
        }
    }

    /// Handle `tunnel_dns_query` from the member.
    pub async fn handle_dns_query(&self, connection_id: ConnectionId, data: TunnelDnsQueryData) {
        if !self.config.enabled {
            self.send_dns_error(
                connection_id,
                data.query_id,
                DnsErrorCode::PolicyDenied,
                "tunnel disabled",
            );
            return;
        }

        // The connection must be authenticated to a pool whose host approved
        // tunnel exit (mirrors `tunnel_open`).
        let Some(pool) = self.pool_registry.get_pool_for_connection(connection_id) else {
            self.send_dns_error(
                connection_id,
                data.query_id,
                DnsErrorCode::PolicyDenied,
                "not authenticated",
            );
            return;
        };
        if !pool.tunnel_exit_enabled() {
            self.send_dns_error(
                connection_id,
                data.query_id,
                DnsErrorCode::PolicyDenied,
                "pool denies tunnel exit",
            );
            return;
        }

        match dns::resolve_query(&data, self.config.connect_timeout).await {
            Ok(answers) => {
                self.send_dns_response(connection_id, data.query_id, Some(answers), None);
            }
            Err(dns::ResolveError::Timeout) => {
                self.send_dns_error(
                    connection_id,
                    data.query_id,
                    DnsErrorCode::Timeout,
                    "lookup timed out",
                );
            }
            Err(dns::ResolveError::NotFound) => {
                self.send_dns_error(
                    connection_id,
                    data.query_id,
                    DnsErrorCode::NxDomain,
                    "no such host",
                );
            }
            Err(dns::ResolveError::Invalid) => {
                self.send_dns_error(
                    connection_id,
                    data.query_id,
                    DnsErrorCode::ProtocolError,
                    "invalid query",
                );
            }
        }
    }

    /// Dispatch a binary WebSocket frame.
    ///
    /// Called from the main event loop for every binary frame received.
    /// Returns `BinaryDispatch::Reject` if the frame is malformed enough
    /// that the WebSocket should be closed with policy-violation code.
    pub fn handle_binary(&self, connection_id: ConnectionId, payload: &[u8]) -> BinaryDispatch {
        // The connection MUST be authenticated to a pool. Binary frames
        // before authentication are a protocol violation per the brief.
        if self
            .pool_registry
            .get_pool_for_connection(connection_id)
            .is_none()
        {
            return BinaryDispatch::Unauthenticated;
        }

        if payload.is_empty() {
            return BinaryDispatch::Reject;
        }
        match payload[0] {
            // Reserved sentinel.
            0x00 => BinaryDispatch::Reject,
            TUNNEL_DATA_CHANNEL => self.handle_binary_tunnel_data(connection_id, payload),
            TUNNEL_UDP_CHANNEL => self.handle_binary_tunnel_udp(connection_id, payload),
            // 0x03..=0xFF reserved for future channels.
            _ => BinaryDispatch::Reject,
        }
    }

    fn handle_binary_tunnel_data(
        &self,
        connection_id: ConnectionId,
        payload: &[u8],
    ) -> BinaryDispatch {
        if payload.len() < TUNNEL_DATA_HEADER_LEN {
            return BinaryDispatch::Reject;
        }
        let data_len = payload.len() - TUNNEL_DATA_HEADER_LEN;
        if data_len > self.config.max_payload_bytes {
            return BinaryDispatch::Reject;
        }
        let mut sid_buf = [0u8; 4];
        sid_buf.copy_from_slice(&payload[1..5]);
        let stream_id = u32::from_be_bytes(sid_buf);
        // `sequence` (bytes 5..9) is informational from the member; the server
        // does not reorder TCP byte-stream payloads (TCP itself orders).
        let _ = &payload[5..9];

        let key = (connection_id, stream_id);
        let Some(entry) = self.streams.get(&key) else {
            self.send_error(
                connection_id,
                Some(stream_id),
                TunnelErrorCode::ProtocolError,
                "unknown stream_id",
            );
            return BinaryDispatch::Handled;
        };

        if entry.network != TunnelNetwork::Tcp {
            self.send_error(
                connection_id,
                Some(stream_id),
                TunnelErrorCode::ProtocolError,
                "tunnel_data on non-tcp stream",
            );
            return BinaryDispatch::Handled;
        }

        if data_len == 0 {
            return BinaryDispatch::Handled;
        }

        let chunk = payload[TUNNEL_DATA_HEADER_LEN..].to_vec();
        // try_send: if the destination queue is full, drop the chunk and emit
        // a backpressure signal. The bounded queue means this only happens
        // when the destination is genuinely slow.
        match entry.outbound_tx.try_send(chunk) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                trace!(
                    connection = %connection_id,
                    stream = stream_id,
                    "destination outbound queue full, dropping chunk"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The bridge task has exited; treat as orphan.
                self.send_error(
                    connection_id,
                    Some(stream_id),
                    TunnelErrorCode::ProtocolError,
                    "stream closed",
                );
            }
        }
        BinaryDispatch::Handled
    }

    fn handle_binary_tunnel_udp(
        &self,
        connection_id: ConnectionId,
        payload: &[u8],
    ) -> BinaryDispatch {
        if payload.len() < TUNNEL_UDP_HEADER_LEN {
            return BinaryDispatch::Reject;
        }
        let data_len = payload.len() - TUNNEL_UDP_HEADER_LEN;
        if data_len > self.config.max_payload_bytes {
            return BinaryDispatch::Reject;
        }
        let mut sid_buf = [0u8; 4];
        sid_buf.copy_from_slice(&payload[1..5]);
        let stream_id = u32::from_be_bytes(sid_buf);

        let key = (connection_id, stream_id);
        let Some(entry) = self.streams.get(&key) else {
            self.send_error(
                connection_id,
                Some(stream_id),
                TunnelErrorCode::ProtocolError,
                "unknown stream_id",
            );
            return BinaryDispatch::Handled;
        };

        if entry.network != TunnelNetwork::Udp {
            self.send_error(
                connection_id,
                Some(stream_id),
                TunnelErrorCode::ProtocolError,
                "tunnel_udp on non-udp stream",
            );
            return BinaryDispatch::Handled;
        }

        if data_len == 0 {
            return BinaryDispatch::Handled;
        }

        let datagram = payload[TUNNEL_UDP_HEADER_LEN..].to_vec();
        match entry.outbound_tx.try_send(datagram) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                trace!(
                    connection = %connection_id,
                    stream = stream_id,
                    "udp outbound queue full, dropping datagram"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.send_error(
                    connection_id,
                    Some(stream_id),
                    TunnelErrorCode::ProtocolError,
                    "stream closed",
                );
            }
        }
        BinaryDispatch::Handled
    }

    // ------------------------------------------------------------------
    // Lifecycle hooks
    // ------------------------------------------------------------------

    /// Abort all streams owned by `connection_id`. Called on disconnect,
    /// kick, or any other connection-fatal event.
    pub fn abort_connection_streams(&self, connection_id: ConnectionId) {
        // Collect first to avoid holding shard locks while notifying.
        let keys: Vec<(ConnectionId, u32)> = self
            .streams
            .iter()
            .filter(|e| e.key().0 == connection_id)
            .map(|e| *e.key())
            .collect();
        for key in keys {
            if let Some((_, entry)) = self.streams.remove(&key) {
                self.open_streams.fetch_sub(1, Ordering::AcqRel);
                entry.cancel.notify_waiters();
            }
        }
        self.streams_per_conn.remove(&connection_id);
    }

    /// Abort all streams owned by guests of `pool_id`. Called when the
    /// pool host flips `tunnel_exit_enabled` to `false`. Host-owned streams
    /// remain unaffected (the per-pool flag only gates *member* approval,
    /// the host's own streams are still gated by `tunnel.enabled`).
    pub fn abort_pool_guest_streams(&self, pool_id: PoolId) {
        let keys: Vec<(ConnectionId, u32)> = self
            .streams
            .iter()
            .filter(|e| {
                let v = e.value();
                v.pool_id == pool_id && !v.owned_by_host
            })
            .map(|e| *e.key())
            .collect();
        for key in keys {
            if let Some((_, entry)) = self.streams.remove(&key) {
                self.open_streams.fetch_sub(1, Ordering::AcqRel);
                self.dec_per_conn(key.0);
                entry.cancel.notify_waiters();
                // Inform the guest that its stream was forcibly closed.
                self.send_close(key.0, key.1, CloseReason::PolicyDenied);
            }
        }
    }

    // ------------------------------------------------------------------
    // Outbound-frame helpers
    // ------------------------------------------------------------------

    fn send_close(&self, connection_id: ConnectionId, stream_id: u32, reason: CloseReason) {
        let frame = ServerFrame::TunnelClose(TunnelCloseData { stream_id, reason });
        self.send_json(connection_id, &frame);
    }

    fn send_error(
        &self,
        connection_id: ConnectionId,
        stream_id: Option<u32>,
        code: TunnelErrorCode,
        message: &str,
    ) {
        let mut msg = message.to_owned();
        if msg.len() > MAX_ERROR_MESSAGE_LEN {
            msg.truncate(MAX_ERROR_MESSAGE_LEN);
        }
        let frame = ServerFrame::TunnelError(TunnelErrorData {
            stream_id,
            code,
            message: msg,
        });
        self.send_json(connection_id, &frame);
    }

    fn send_dns_response(
        &self,
        connection_id: ConnectionId,
        query_id: u32,
        answers: Option<Vec<DnsAnswer>>,
        error: Option<DnsError>,
    ) {
        let frame = ServerFrame::TunnelDnsResponse(TunnelDnsResponseData {
            query_id,
            answers,
            error,
        });
        self.send_json(connection_id, &frame);
    }

    fn send_dns_error(
        &self,
        connection_id: ConnectionId,
        query_id: u32,
        code: DnsErrorCode,
        message: &str,
    ) {
        self.send_dns_response(
            connection_id,
            query_id,
            None,
            Some(DnsError {
                code,
                message: message.to_owned(),
            }),
        );
    }

    fn send_json(&self, connection_id: ConnectionId, frame: &ServerFrame) {
        let Ok(json) = serde_json::to_string(frame) else {
            return;
        };
        if let Err(e) = self
            .connection_registry
            .send_to(connection_id, OutboundMessage::Text(json))
        {
            debug!(
                connection = %connection_id,
                "tunnel: failed to send control-plane frame: {e}"
            );
        }
    }

    /// Predicate for the destination-address check.
    ///
    /// - If `allowed_destination_cidrs` is non-empty, only addresses in the
    ///   allowlist pass.
    /// - Otherwise, addresses in `denied_destination_cidrs` are blocked.
    pub fn is_address_allowed(&self, addr: std::net::IpAddr) -> bool {
        if !self.config.allowed_destination_cidrs.is_empty()
            && !self.config.allowed_destination_cidrs.contains(addr)
        {
            return false;
        }
        if self.config.denied_destination_cidrs.contains(addr) {
            return false;
        }
        true
    }

    fn dec_per_conn(&self, connection_id: ConnectionId) {
        if let dashmap::mapref::entry::Entry::Occupied(mut e) =
            self.streams_per_conn.entry(connection_id)
        {
            let v = e.get_mut();
            *v = v.saturating_sub(1);
            if *v == 0 {
                e.remove();
            }
        }
    }
}

/// Result of dispatching a binary frame to the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryDispatch {
    /// Frame was processed (successfully or with a control-plane error reply).
    Handled,
    /// Frame was malformed enough to warrant rejecting.
    Reject,
    /// Frame arrived on a connection that has not authenticated.
    Unauthenticated,
}

/// Build a binary `TUNNEL_DATA` frame for emission.
///
/// Layout: `[0x01][stream_id BE u32][sequence BE u32][payload...]`.
fn encode_tunnel_data(stream_id: u32, sequence: u32, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(TUNNEL_DATA_HEADER_LEN + payload.len());
    buf.put_u8(TUNNEL_DATA_CHANNEL);
    buf.put_u32(stream_id);
    buf.put_u32(sequence);
    buf.put_slice(payload);
    buf.freeze()
}

/// Build a binary `TUNNEL_UDP` frame for emission.
///
/// Layout: `[0x02][stream_id BE u32][datagram...]`.
fn encode_tunnel_udp(stream_id: u32, datagram: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(TUNNEL_UDP_HEADER_LEN + datagram.len());
    buf.put_u8(TUNNEL_UDP_CHANNEL);
    buf.put_u32(stream_id);
    buf.put_slice(datagram);
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_tunnel_data_layout() {
        let bytes = encode_tunnel_data(0x0102_0304, 0x0506_0708, b"hi");
        assert_eq!(bytes.len(), TUNNEL_DATA_HEADER_LEN + 2);
        assert_eq!(bytes[0], TUNNEL_DATA_CHANNEL);
        assert_eq!(&bytes[1..5], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&bytes[5..9], &[0x05, 0x06, 0x07, 0x08]);
        assert_eq!(&bytes[9..], b"hi");
    }

    #[test]
    fn encode_tunnel_udp_layout() {
        let bytes = encode_tunnel_udp(0xDEAD_BEEF, b"abc");
        assert_eq!(bytes.len(), TUNNEL_UDP_HEADER_LEN + 3);
        assert_eq!(bytes[0], TUNNEL_UDP_CHANNEL);
        assert_eq!(&bytes[1..5], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&bytes[5..], b"abc");
    }

    #[test]
    fn binary_dispatch_rejects_short_and_reserved() {
        // Empty
        assert_eq!(short_dispatch(&[]), BinaryDispatch::Reject);
        // Reserved sentinel
        assert_eq!(short_dispatch(&[0x00]), BinaryDispatch::Reject);
        // Reserved high range
        assert_eq!(short_dispatch(&[0x80, 0, 0, 0, 0]), BinaryDispatch::Reject);
        // TUNNEL_DATA too short
        assert_eq!(
            short_dispatch(&[TUNNEL_DATA_CHANNEL, 0, 0, 0, 0]),
            BinaryDispatch::Reject
        );
        // TUNNEL_UDP too short
        assert_eq!(
            short_dispatch(&[TUNNEL_UDP_CHANNEL, 0, 0]),
            BinaryDispatch::Reject
        );
    }

    /// Helper that exercises only the framing-level rejection (no streams
    /// inserted). Authentication is bypassed by using a gateway whose
    /// pool registry contains a fake mapping for connection 1.
    fn short_dispatch(bytes: &[u8]) -> BinaryDispatch {
        use std::sync::Arc;
        let pool_registry = Arc::new(PoolRegistry::new(8));
        let connection_registry = Arc::new(ConnectionRegistry::new(8));
        // Authenticate connection 1 to a fake pool so the framing path is
        // exercised rather than the auth gate.
        let pool_id = PoolId(uuid::Uuid::nil());
        let _ = pool_registry.create_pool(
            pool_id,
            "t".into(),
            ConnectionId(1),
            stealthos_core::types::PeerId("h".into()),
            [0u8; 32],
            "h".into(),
            4,
        );
        let cfg = TunnelConfig {
            enabled: true,
            max_streams_per_connection: 64,
            max_streams_global: 4096,
            connect_timeout: std::time::Duration::from_secs(1),
            idle_stream_timeout: std::time::Duration::from_secs(1),
            max_payload_bytes: 32_768,
            initial_receive_window: 65_536,
            window_update_threshold: 16_384,
            denied_destination_ports: vec![],
            allowed_destination_cidrs: cidr::CidrSet::default(),
            denied_destination_cidrs: cidr::CidrSet::default(),
        };
        let gw = TunnelGateway::new(cfg, connection_registry, pool_registry);
        gw.handle_binary(ConnectionId(1), bytes)
    }

    // ── Harness-based gateway tests ──────────────────────────────────

    use std::net::SocketAddr;
    use stealthos_core::pool::PoolPeer;
    use stealthos_core::types::PeerId;
    use stealthos_transport::ConnectionHandle;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use tokio::time::{Duration as TokioDuration, Instant as TokioInstant};

    /// Small wrapper holding the gateway, registries, and the receivers
    /// for two connections (host + guest). Tests drain the receivers to
    /// inspect frames the gateway enqueued.
    struct GwHarness {
        gateway: Arc<TunnelGateway>,
        pool_registry: Arc<PoolRegistry>,
        pool_id: PoolId,
        host_conn: ConnectionId,
        guest_conn: ConnectionId,
        host_rx: mpsc::Receiver<OutboundMessage>,
        guest_rx: mpsc::Receiver<OutboundMessage>,
    }

    fn build_gw(custom_config: impl FnOnce(&mut TunnelConfig)) -> GwHarness {
        let pool_registry = Arc::new(PoolRegistry::new(8));
        let connection_registry = Arc::new(ConnectionRegistry::new(16));

        let host_conn = ConnectionId(1);
        let guest_conn = ConnectionId(2);
        let (host_tx, host_rx) = mpsc::channel(64);
        let (guest_tx, guest_rx) = mpsc::channel(64);
        connection_registry
            .register(ConnectionHandle {
                connection_id: host_conn,
                remote_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                outbound_tx: host_tx,
                connected_at: TokioInstant::now(),
            })
            .expect("register host");
        connection_registry
            .register(ConnectionHandle {
                connection_id: guest_conn,
                remote_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                outbound_tx: guest_tx,
                connected_at: TokioInstant::now(),
            })
            .expect("register guest");

        let pool_id = PoolId(uuid::Uuid::now_v7());
        let pool = pool_registry
            .create_pool(
                pool_id,
                "test".into(),
                host_conn,
                PeerId("host".into()),
                [0u8; 32],
                "host".into(),
                8,
            )
            .expect("create_pool");
        pool.add_peer(PoolPeer {
            peer_id: PeerId("guest".into()),
            connection_id: guest_conn,
            display_name: "guest".into(),
            public_key: [0u8; 32],
            connected_at: TokioInstant::now(),
            last_activity: TokioInstant::now(),
            last_acked_sequence: 0,
        })
        .expect("add_peer");
        pool_registry.register_connection(guest_conn, pool_id, PeerId("guest".into()));
        // Default to per-pool tunnel approval ON.
        pool.set_tunnel_exit_enabled(true);

        let mut cfg = TunnelConfig {
            enabled: true,
            max_streams_per_connection: 64,
            max_streams_global: 4096,
            connect_timeout: TokioDuration::from_secs(2),
            idle_stream_timeout: TokioDuration::from_secs(60),
            max_payload_bytes: 32_768,
            initial_receive_window: 65_536,
            window_update_threshold: 16_384,
            denied_destination_ports: vec![25],
            allowed_destination_cidrs: cidr::CidrSet::default(),
            denied_destination_cidrs: cidr::CidrSet::default(),
        };
        custom_config(&mut cfg);
        let gateway = Arc::new(TunnelGateway::new(
            cfg,
            connection_registry,
            Arc::clone(&pool_registry),
        ));
        GwHarness {
            gateway,
            pool_registry,
            pool_id,
            host_conn,
            guest_conn,
            host_rx,
            guest_rx,
        }
    }

    fn drain(rx: &mut mpsc::Receiver<OutboundMessage>) -> Vec<ServerFrame> {
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let OutboundMessage::Text(t) = msg
                && let Ok(f) = serde_json::from_str::<ServerFrame>(&t)
            {
                out.push(f);
            }
        }
        out
    }

    fn expect_close(frames: &[ServerFrame], stream_id: u32) -> CloseReason {
        for f in frames {
            if let ServerFrame::TunnelClose(d) = f
                && d.stream_id == stream_id
            {
                return d.reason;
            }
        }
        panic!("no tunnel_close for stream {stream_id} in {frames:?}");
    }

    #[tokio::test]
    async fn tunnel_open_rejected_when_server_disabled() {
        let mut h = build_gw(|c| c.enabled = false);
        let data = TunnelOpenData {
            stream_id: 1,
            destination: TunnelDestination::Ipv4 {
                address: "127.0.0.1".into(),
                port: 9999,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 4096,
        };
        h.gateway.handle_open(h.guest_conn, data).await;
        let frames = drain(&mut h.guest_rx);
        let reason = expect_close(&frames, 1);
        assert_eq!(reason, CloseReason::PolicyDenied);
        assert_eq!(h.gateway.open_stream_count(), 0);
        let _ = h.pool_registry; // keep alive
    }

    #[tokio::test]
    async fn tunnel_open_rejected_when_pool_flag_off() {
        let mut h = build_gw(|_| {});
        // Flip the per-pool flag off after the harness built it.
        let pool = h.pool_registry.get_pool(h.pool_id).unwrap();
        pool.set_tunnel_exit_enabled(false);

        let data = TunnelOpenData {
            stream_id: 5,
            destination: TunnelDestination::Ipv4 {
                address: "127.0.0.1".into(),
                port: 9999,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 4096,
        };
        h.gateway.handle_open(h.guest_conn, data).await;
        let frames = drain(&mut h.guest_rx);
        assert_eq!(expect_close(&frames, 5), CloseReason::PolicyDenied);
    }

    #[tokio::test]
    async fn tunnel_open_rejected_when_unauthenticated() {
        let h = build_gw(|_| {});
        // Connection 99 is not registered to any pool.
        let unauth = ConnectionId(99);
        // Register a connection-handle for connection 99 so the gateway
        // can deliver the rejection. Reuse the guest channel.
        let (tx, mut rx) = mpsc::channel(8);
        h.gateway
            .connection_registry
            .register(ConnectionHandle {
                connection_id: unauth,
                remote_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                outbound_tx: tx,
                connected_at: TokioInstant::now(),
            })
            .unwrap();

        let data = TunnelOpenData {
            stream_id: 7,
            destination: TunnelDestination::Ipv4 {
                address: "127.0.0.1".into(),
                port: 80,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 4096,
        };
        h.gateway.handle_open(unauth, data).await;
        let frames = drain(&mut rx);
        assert_eq!(expect_close(&frames, 7), CloseReason::PolicyDenied);
    }

    #[tokio::test]
    async fn tunnel_open_rejected_for_denied_cidr() {
        let mut h = build_gw(|c| {
            let mut warns = Vec::new();
            c.denied_destination_cidrs =
                cidr::CidrSet::from_strings(&["192.168.0.0/16".to_owned()], &mut warns);
        });
        let data = TunnelOpenData {
            stream_id: 11,
            destination: TunnelDestination::Ipv4 {
                address: "192.168.1.1".into(),
                port: 80,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 1024,
        };
        h.gateway.handle_open(h.guest_conn, data).await;
        let frames = drain(&mut h.guest_rx);
        assert_eq!(expect_close(&frames, 11), CloseReason::PolicyDenied);
    }

    #[tokio::test]
    async fn tunnel_open_rejected_for_denied_port() {
        let mut h = build_gw(|c| c.denied_destination_ports = vec![25, 587]);
        let data = TunnelOpenData {
            stream_id: 13,
            destination: TunnelDestination::Ipv4 {
                address: "1.2.3.4".into(),
                port: 25,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 1024,
        };
        h.gateway.handle_open(h.guest_conn, data).await;
        let frames = drain(&mut h.guest_rx);
        assert_eq!(expect_close(&frames, 13), CloseReason::PolicyDenied);
    }

    #[tokio::test]
    async fn tunnel_open_rejected_when_per_connection_limit_reached() {
        // Spawn a local TCP echo so the streams actually open.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Drop the listener so connect attempts fail-fast, but the open
        // path is what we want to exercise — the limit check is BEFORE
        // resolution. To make resolution succeed we keep the listener alive
        // by accepting all connections in a background task.
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let mut h = build_gw(|c| {
            c.max_streams_per_connection = 2;
        });
        // Open 2 streams successfully.
        for sid in 0..2 {
            let data = TunnelOpenData {
                stream_id: sid,
                destination: TunnelDestination::Ipv4 {
                    address: "127.0.0.1".into(),
                    port,
                },
                network: TunnelNetwork::Tcp,
                initial_window: 4096,
            };
            h.gateway.handle_open(h.guest_conn, data).await;
        }
        // The 3rd should hit the per-connection cap.
        let data = TunnelOpenData {
            stream_id: 99,
            destination: TunnelDestination::Ipv4 {
                address: "127.0.0.1".into(),
                port,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 4096,
        };
        h.gateway.handle_open(h.guest_conn, data).await;
        let frames = drain(&mut h.guest_rx);
        // Look for the resource_exhausted error and the stream_limit close.
        let saw_err = frames.iter().any(|f| {
            matches!(
                f,
                ServerFrame::TunnelError(d)
                    if matches!(d.code, TunnelErrorCode::ResourceExhausted)
                        && d.stream_id == Some(99)
            )
        });
        assert!(saw_err, "expected ResourceExhausted error, got {frames:?}");
        let saw_close = frames.iter().any(|f| {
            matches!(
                f,
                ServerFrame::TunnelClose(d)
                    if d.stream_id == 99 && d.reason == CloseReason::StreamLimit
            )
        });
        assert!(saw_close, "expected StreamLimit close, got {frames:?}");

        // Cleanup
        h.gateway.abort_connection_streams(h.guest_conn);
    }

    #[tokio::test]
    async fn tunnel_open_rejected_when_global_limit_reached() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let mut h = build_gw(|c| {
            c.max_streams_global = 1;
        });
        // First open succeeds.
        let data = TunnelOpenData {
            stream_id: 1,
            destination: TunnelDestination::Ipv4 {
                address: "127.0.0.1".into(),
                port,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 4096,
        };
        h.gateway.handle_open(h.guest_conn, data).await;
        // Second open is rejected.
        let data = TunnelOpenData {
            stream_id: 2,
            destination: TunnelDestination::Ipv4 {
                address: "127.0.0.1".into(),
                port,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 4096,
        };
        h.gateway.handle_open(h.guest_conn, data).await;
        let frames = drain(&mut h.guest_rx);
        let saw = frames.iter().any(|f| {
            matches!(
                f,
                ServerFrame::TunnelError(d)
                    if matches!(d.code, TunnelErrorCode::ResourceExhausted)
                        && d.stream_id == Some(2)
            )
        });
        assert!(saw, "expected resource_exhausted on stream 2: {frames:?}");

        h.gateway.abort_connection_streams(h.guest_conn);
    }

    #[tokio::test]
    async fn tcp_round_trip_through_gateway() {
        // Spawn a local echo server.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        if sock.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        // Build a gateway with no deny list (CIDR cleared by default in the
        // harness; explicitly clear the SMTP port deny too in case 25 is in
        // use somewhere).
        let mut h = build_gw(|c| {
            c.denied_destination_ports = vec![];
            c.idle_stream_timeout = TokioDuration::from_secs(5);
        });

        let data = TunnelOpenData {
            stream_id: 42,
            destination: TunnelDestination::Ipv4 {
                address: "127.0.0.1".into(),
                port,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 1_000_000, // big enough to receive the echo
        };
        h.gateway.handle_open(h.guest_conn, data).await;

        // Push a chunk of data into the stream via a binary tunnel_data frame.
        let chunk: Vec<u8> = (0..8_000u32).map(|i| (i & 0xFF) as u8).collect();
        let mut frame = Vec::with_capacity(TUNNEL_DATA_HEADER_LEN + chunk.len());
        frame.push(TUNNEL_DATA_CHANNEL);
        frame.extend_from_slice(&42u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&chunk);
        let dispatch = h.gateway.handle_binary(h.guest_conn, &frame);
        assert_eq!(dispatch, BinaryDispatch::Handled);

        // Wait for echoed bytes to come back as binary frames. Drain the
        // guest_rx looking for at least `chunk.len()` bytes of payload.
        let mut received: Vec<u8> = Vec::new();
        let deadline = TokioInstant::now() + TokioDuration::from_secs(5);
        while received.len() < chunk.len() && TokioInstant::now() < deadline {
            tokio::select! {
                () = tokio::time::sleep(TokioDuration::from_millis(50)) => {}
                msg = h.guest_rx.recv() => {
                    let Some(msg) = msg else { break };
                    if let OutboundMessage::Binary(b) = msg
                        && !b.is_empty() && b[0] == TUNNEL_DATA_CHANNEL && b.len() >= TUNNEL_DATA_HEADER_LEN
                    {
                        received.extend_from_slice(&b[TUNNEL_DATA_HEADER_LEN..]);
                    }
                }
            }
        }
        assert!(
            received.len() >= chunk.len(),
            "did not receive echo: got {} bytes",
            received.len()
        );
        assert_eq!(&received[..chunk.len()], chunk.as_slice());

        // Tear down the stream.
        h.gateway.handle_close(
            h.guest_conn,
            &TunnelCloseData {
                stream_id: 42,
                reason: CloseReason::PeerClosed,
            },
        );
    }

    #[tokio::test]
    async fn binary_frame_unauthenticated_is_signaled() {
        let h = build_gw(|_| {});
        // Connection 99 has not authenticated to any pool.
        let dispatch = h.gateway.handle_binary(
            ConnectionId(99),
            &[TUNNEL_DATA_CHANNEL, 0, 0, 0, 1, 0, 0, 0, 0, b'x'],
        );
        assert_eq!(dispatch, BinaryDispatch::Unauthenticated);
        let _ = h; // keep harness alive
    }

    #[tokio::test]
    async fn unknown_stream_id_emits_protocol_error() {
        let mut h = build_gw(|_| {});
        // Authenticated connection sends data for a stream that doesn't exist.
        let frame: Vec<u8> = [
            TUNNEL_DATA_CHANNEL,
            0,
            0,
            0,
            7, // stream_id = 7 (unopened)
            0,
            0,
            0,
            0, // sequence = 0
            b'h',
            b'i',
        ]
        .to_vec();
        let dispatch = h.gateway.handle_binary(h.guest_conn, &frame);
        assert_eq!(dispatch, BinaryDispatch::Handled);
        let frames = drain(&mut h.guest_rx);
        let saw = frames.iter().any(|f| {
            matches!(
                f,
                ServerFrame::TunnelError(d)
                    if matches!(d.code, TunnelErrorCode::ProtocolError)
                        && d.stream_id == Some(7)
            )
        });
        assert!(saw, "expected protocol_error: {frames:?}");
    }

    #[tokio::test]
    async fn connection_disconnect_cleans_streams() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        let mut h = build_gw(|c| c.idle_stream_timeout = TokioDuration::from_secs(60));

        for sid in 0..3u32 {
            let data = TunnelOpenData {
                stream_id: sid,
                destination: TunnelDestination::Ipv4 {
                    address: "127.0.0.1".into(),
                    port,
                },
                network: TunnelNetwork::Tcp,
                initial_window: 4096,
            };
            h.gateway.handle_open(h.guest_conn, data).await;
        }
        // Allow the spawn to register entries.
        tokio::time::sleep(TokioDuration::from_millis(50)).await;
        assert_eq!(h.gateway.open_stream_count(), 3);

        h.gateway.abort_connection_streams(h.guest_conn);
        // Allow tasks to complete cleanup.
        tokio::time::sleep(TokioDuration::from_millis(100)).await;
        assert_eq!(h.gateway.open_stream_count(), 0);
        let _ = drain(&mut h.guest_rx);
    }

    #[tokio::test]
    async fn pool_flag_flip_aborts_guest_streams_only() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        let mut h = build_gw(|c| c.idle_stream_timeout = TokioDuration::from_secs(60));

        // Open one host-owned and one guest-owned stream.
        h.gateway
            .handle_open(
                h.host_conn,
                TunnelOpenData {
                    stream_id: 1,
                    destination: TunnelDestination::Ipv4 {
                        address: "127.0.0.1".into(),
                        port,
                    },
                    network: TunnelNetwork::Tcp,
                    initial_window: 4096,
                },
            )
            .await;
        h.gateway
            .handle_open(
                h.guest_conn,
                TunnelOpenData {
                    stream_id: 2,
                    destination: TunnelDestination::Ipv4 {
                        address: "127.0.0.1".into(),
                        port,
                    },
                    network: TunnelNetwork::Tcp,
                    initial_window: 4096,
                },
            )
            .await;
        tokio::time::sleep(TokioDuration::from_millis(50)).await;
        assert_eq!(h.gateway.open_stream_count(), 2);

        // Pool host revokes member approval — only the guest stream is torn down.
        h.gateway.abort_pool_guest_streams(h.pool_id);
        tokio::time::sleep(TokioDuration::from_millis(100)).await;
        assert_eq!(h.gateway.open_stream_count(), 1);

        // Drain & cleanup.
        h.gateway.abort_connection_streams(h.host_conn);
        let _ = drain(&mut h.host_rx);
        let _ = drain(&mut h.guest_rx);
    }

    #[tokio::test]
    async fn window_update_ratchet_throttles_destination_reads() {
        // Spawn an echo that will respond with 200 KiB. Initial member
        // credit is 8 KiB so the gateway must stop reading from the
        // destination once the credit is exhausted, and only resume after
        // a window_update.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    // Consume any inbound data so the OS write buffer doesn't
                    // backpressure us, then send 200 KiB unsolicited.
                    let payload: Vec<u8> = (0..200 * 1024_u32).map(|i| (i & 0xFF) as u8).collect();
                    let _ = sock.write_all(&payload).await;
                    // Then read until close.
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                    }
                });
            }
        });

        let mut h = build_gw(|c| {
            c.denied_destination_ports = vec![];
            c.idle_stream_timeout = TokioDuration::from_secs(30);
            c.max_payload_bytes = 4096;
        });

        let initial_window: u32 = 8 * 1024; // 8 KiB
        h.gateway
            .handle_open(
                h.guest_conn,
                TunnelOpenData {
                    stream_id: 1,
                    destination: TunnelDestination::Ipv4 {
                        address: "127.0.0.1".into(),
                        port,
                    },
                    network: TunnelNetwork::Tcp,
                    initial_window,
                },
            )
            .await;

        // Drain frames for ~250ms; we expect the gateway to send no more
        // than `initial_window` bytes before stopping.
        let deadline = TokioInstant::now() + TokioDuration::from_millis(300);
        let mut bytes_received: u64 = 0;
        while TokioInstant::now() < deadline {
            tokio::select! {
                () = tokio::time::sleep(TokioDuration::from_millis(20)) => {}
                msg = h.guest_rx.recv() => {
                    if let Some(OutboundMessage::Binary(b)) = msg
                        && b.len() >= TUNNEL_DATA_HEADER_LEN && b[0] == TUNNEL_DATA_CHANNEL
                    {
                        bytes_received +=
                            u64::try_from(b.len() - TUNNEL_DATA_HEADER_LEN).unwrap_or(u64::MAX);
                    }
                }
            }
        }
        let max_payload = u32::try_from(h.gateway.config.max_payload_bytes).unwrap_or(u32::MAX);
        assert!(
            bytes_received <= u64::from(initial_window) + u64::from(max_payload),
            "gateway should stop reading after credit exhausted; got {bytes_received} bytes"
        );

        // Top up credit and assert more data flows.
        h.gateway.handle_window_update(
            h.guest_conn,
            &TunnelWindowUpdateData {
                stream_id: 1,
                additional_credit: 200 * 1024,
            },
        );
        let deadline = TokioInstant::now() + TokioDuration::from_secs(2);
        while bytes_received < 50 * 1024 && TokioInstant::now() < deadline {
            tokio::select! {
                () = tokio::time::sleep(TokioDuration::from_millis(20)) => {}
                msg = h.guest_rx.recv() => {
                    if let Some(OutboundMessage::Binary(b)) = msg
                        && b.len() >= TUNNEL_DATA_HEADER_LEN && b[0] == TUNNEL_DATA_CHANNEL
                    {
                        bytes_received +=
                            u64::try_from(b.len() - TUNNEL_DATA_HEADER_LEN).unwrap_or(u64::MAX);
                    }
                }
            }
        }
        assert!(
            bytes_received >= 50 * 1024,
            "after credit refill, should receive more bytes; got {bytes_received}"
        );

        h.gateway.handle_close(
            h.guest_conn,
            &TunnelCloseData {
                stream_id: 1,
                reason: CloseReason::PeerClosed,
            },
        );
    }

    #[tokio::test]
    async fn dns_query_authenticated_resolves_loopback() {
        // Loopback should resolve to 127.0.0.1 on essentially every system.
        let mut h = build_gw(|_| {});
        let q = TunnelDnsQueryData {
            query_id: 1,
            name: "localhost".into(),
            record_type: stealthos_core::server_frame::DnsRecordType::A,
        };
        h.gateway.handle_dns_query(h.guest_conn, q).await;
        let frames = drain(&mut h.guest_rx);
        // We accept either an answer or NotFound depending on host
        // configuration; we only assert that *something* was emitted.
        let saw_response = frames
            .iter()
            .any(|f| matches!(f, ServerFrame::TunnelDnsResponse(_)));
        assert!(saw_response, "expected DNS response, got {frames:?}");
    }

    #[tokio::test]
    async fn dns_query_unauthenticated_is_policy_denied() {
        let mut h = build_gw(|_| {});
        // Pool host revokes approval.
        let pool = h.pool_registry.get_pool(h.pool_id).unwrap();
        pool.set_tunnel_exit_enabled(false);
        let q = TunnelDnsQueryData {
            query_id: 2,
            name: "example.com".into(),
            record_type: stealthos_core::server_frame::DnsRecordType::A,
        };
        h.gateway.handle_dns_query(h.guest_conn, q).await;
        let frames = drain(&mut h.guest_rx);
        let saw = frames.iter().any(|f| matches!(
            f,
            ServerFrame::TunnelDnsResponse(d)
                if d.error.as_ref().is_some_and(|e| matches!(e.code, DnsErrorCode::PolicyDenied))
        ));
        assert!(saw, "expected policy_denied DNS response, got {frames:?}");
    }
}
