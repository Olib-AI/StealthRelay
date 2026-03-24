//! Core message handler -- dispatches incoming `ServerFrame` messages.
//!
//! This module contains the main business logic for the relay server.
//! It processes frames received from clients over WebSocket, enforces
//! authorization and rate limits, and routes messages between peers.
//!
//! **Security invariant:** The handler NEVER logs message payloads
//! (the `data` field in `Forward`/`Relayed` frames). Only metadata
//! such as pool IDs, peer IDs, and message types are logged.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use base64ct::{Base64, Encoding as _};
use dashmap::DashMap;
use rand::RngCore;
use stealthos_core::pool::PoolPeer;
use stealthos_core::ratelimit::{ConnectionThrottler, IpRateLimiter};
use stealthos_core::router::Router;
use stealthos_core::server_frame::{
    PeerInfo, PoolInfo, PowChallengeFrame, PowSolutionFrame, ServerFrame,
};
use stealthos_core::types::{ConnectionId, PeerId, PoolId};
use stealthos_core::{Pool, PoolRegistry};
use stealthos_crypto::envelope::SessionCipher;
use stealthos_crypto::handshake::{HandshakeMessage, HandshakeResponder};
use stealthos_crypto::identity::HostIdentity;
use stealthos_crypto::invitation::InvitationToken;
use stealthos_crypto::pow::PowChallenge;
use stealthos_observability::ServerMetrics;
use stealthos_transport::ConnectionRegistry;
use stealthos_transport::connection::OutboundMessage;
use tokio::time::Instant;
use tracing::{debug, info, trace, warn};

use crate::claim::{self, ClaimState};

/// Maximum allowed display name length after sanitization (bytes).
const MAX_DISPLAY_NAME_LEN: usize = 64;

/// Sanitize a client-provided display name for safe logging and storage.
///
/// Prevents log injection (CRITICAL-1) by:
/// - Stripping newlines (`\n`, `\r`), null bytes, and all control characters
/// - Retaining only alphanumeric characters, spaces, hyphens, underscores,
///   apostrophes, and periods
/// - Truncating to [`MAX_DISPLAY_NAME_LEN`] characters (on a char boundary)
///
/// The returned string is safe to embed in structured log fields without risk
/// of injecting spurious fields or synthetic log lines.
fn sanitize_display_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .filter(|c| {
            c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_' || *c == '\'' || *c == '.'
        })
        .take(MAX_DISPLAY_NAME_LEN)
        .collect();
    sanitized
}

/// Maximum number of pending join requests per pool. Prevents a single
/// attacker from flooding the pending-joins map for all pools by restricting
/// how many unresolved join requests each pool can have simultaneously.
const MAX_PENDING_JOINS_PER_POOL: usize = 16;

/// Maximum age of a pending join request before it is purged (60 seconds).
const PENDING_JOIN_TTL_SECS: u64 = 60;

/// Default `PoW` difficulty (leading zero bits). ~50ms on a single core.
/// See `stealthos_crypto::pow::recommended_difficulty` for adaptive tiers.
const POW_DEFAULT_DIFFICULTY: u8 = 18;

/// Maximum age of a `PoW` challenge before it is considered stale (120 seconds).
const POW_CHALLENGE_MAX_AGE_SECS: i64 = 120;

/// Maximum number of outstanding `PoW` challenges to prevent memory exhaustion.
const MAX_PENDING_POW_CHALLENGES: usize = 10_000;

/// State for a pending `PoW` challenge issued to a connection.
struct PendingPowChallenge {
    /// The cryptographic challenge the client must solve.
    challenge: PowChallenge,
    /// When this challenge was issued, for TTL enforcement.
    created_at: Instant,
}

/// State for a pending join request awaiting host approval.
struct PendingJoin {
    /// The connection that wants to join.
    connection_id: ConnectionId,
    /// The display name the client provided.
    display_name: String,
    /// The pool this join request is targeting.
    pool_id: PoolId,
    /// When this pending join was created, for TTL enforcement.
    created_at: Instant,
}

/// Processes incoming `ServerFrame` messages from clients.
///
/// This is the central dispatch point where pool logic, routing, and
/// security enforcement happen. Each WebSocket connection task calls
/// into the shared `MessageHandler` for every received text frame.
pub struct MessageHandler {
    pool_registry: Arc<PoolRegistry>,
    connection_registry: Arc<ConnectionRegistry>,
    metrics: Arc<ServerMetrics>,
    rate_limiter: Arc<IpRateLimiter>,
    throttler: Arc<ConnectionThrottler>,
    host_identity: Arc<HostIdentity>,
    /// Tracks pending join requests by client public key.
    ///
    /// Keyed by `client_public_key` (base64 string). Each entry includes
    /// the `pool_id` so that per-pool limits can be enforced without a
    /// secondary index.
    pending_joins: DashMap<String, PendingJoin>,
    /// Default server address used for invitation URL generation.
    server_addr: String,
    /// Per-pool host-provided server URL (overrides `server_addr` for invitation generation).
    /// Keyed by `PoolId` so multiple pools on the same server do not conflict.
    host_server_urls: DashMap<PoolId, String>,
    /// Maximum peers per pool.
    max_pool_size: usize,
    /// Maps `token_id` (16 bytes) to `pool_id` for invitation lookup.
    token_to_pool: DashMap<[u8; 16], PoolId>,
    /// Outstanding `PoW` challenges keyed by connection ID.
    /// A client that sends a `JoinRequest` without a `PoW` solution receives a
    /// challenge; on the next attempt they must include the solution.
    pending_pow_challenges: DashMap<ConnectionId, PendingPowChallenge>,
    /// Server claim state -- determines whether a host is bound.
    ///
    /// Wrapped in `Arc<Mutex<>>` so it can be shared with the setup page
    /// HTTP handler. Uses `std::sync::Mutex` (not `tokio::sync::Mutex`)
    /// because the lock is never held across `.await` points and the
    /// critical section is sub-microsecond (constant-time compare +
    /// optional file write).
    claim_state: Arc<Mutex<ClaimState>>,
    /// Key directory path, used for persisting claim bindings.
    key_dir: PathBuf,
    /// Setup page state -- used to pass the recovery key after claiming.
    setup_state: Option<Arc<crate::setup::SetupState>>,
    /// Maps `pool_id` to the host's session token. Generated at pool creation
    /// and required for all privileged host operations (`CreateInvitation`,
    /// `KickPeer`, `ClosePool`, `Forward`, `JoinApproval`, `RevokeInvitation`).
    host_session_tokens: DashMap<PoolId, String>,
    /// Maps `connection_id` to the guest peer's session token. Generated at
    /// join-approval time and required for `Forward` frames from guest peers.
    guest_session_tokens: DashMap<ConnectionId, String>,
    /// Per-connection session ciphers established via Noise NK handshake.
    /// Keyed by `ConnectionId`. The `Mutex` is `std::sync::Mutex` because
    /// the lock is never held across `.await` points — each encrypt/decrypt
    /// call is sub-microsecond.
    session_ciphers: DashMap<ConnectionId, Mutex<SessionCipher>>,
    /// Per-connection auth nonces for replay protection (SECURITY: H-3).
    ///
    /// A 32-byte random nonce is generated for each new WebSocket connection
    /// and sent to the client in an `AuthChallenge` frame. The client MUST
    /// include the nonce in its `HostAuth` signature transcript to bind the
    /// auth to this specific connection, preventing replay of captured
    /// `HostAuth` frames on a different connection.
    connection_nonces: DashMap<ConnectionId, String>,
}

impl MessageHandler {
    /// Create a new handler with shared registries and metrics.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_registry: Arc<PoolRegistry>,
        connection_registry: Arc<ConnectionRegistry>,
        metrics: Arc<ServerMetrics>,
        rate_limiter: Arc<IpRateLimiter>,
        throttler: Arc<ConnectionThrottler>,
        host_identity: Arc<HostIdentity>,
        server_addr: String,
        max_pool_size: usize,
        claim_state: Arc<Mutex<ClaimState>>,
        key_dir: PathBuf,
        setup_state: Option<Arc<crate::setup::SetupState>>,
    ) -> Self {
        Self {
            pool_registry,
            connection_registry,
            metrics,
            rate_limiter,
            throttler,
            host_identity,
            pending_joins: DashMap::new(),
            server_addr,
            host_server_urls: DashMap::new(),
            max_pool_size,
            token_to_pool: DashMap::new(),
            pending_pow_challenges: DashMap::new(),
            claim_state,
            key_dir,
            setup_state,
            host_session_tokens: DashMap::new(),
            guest_session_tokens: DashMap::new(),
            session_ciphers: DashMap::new(),
            connection_nonces: DashMap::new(),
        }
    }

    /// Periodic cleanup of stale state: pending joins, rate limiters,
    /// throttler records.
    ///
    /// Called by the housekeeping task instead of on every message to avoid
    /// contention from concurrent `DashMap::retain` calls on the hot path.
    pub fn periodic_cleanup(&self) {
        self.purge_expired_pending_joins();
        self.purge_expired_pow_challenges();
        self.rate_limiter.cleanup();
        self.throttler.cleanup();
    }

    /// Process a single raw JSON message from a connected client.
    ///
    /// # Arguments
    /// * `connection_id` -- Internal connection identifier.
    /// * `remote_addr` -- Client's socket address (for rate limiting).
    /// * `raw_message` -- The raw JSON text frame content.
    ///
    /// # Errors
    /// Returns an error if the message cannot be parsed, the client is
    /// rate-limited, or an internal dispatch failure occurs.
    pub async fn handle_message(
        &self,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        raw_message: &str,
    ) -> Result<(), anyhow::Error> {
        // Rate-limit check at the IP level — but skip for authenticated pool members.
        // When all clients connect through a proxy (e.g., Cloudflare WARP/Private Relay),
        // they share the same IP. Authenticated members have already passed auth and
        // are tracked by connection_id, so per-IP rate limiting would unfairly block them.
        let is_authenticated = self
            .pool_registry
            .get_pool_for_connection(connection_id)
            .is_some();
        if !is_authenticated && let Err(e) = self.rate_limiter.check_rate(remote_addr.ip()) {
            self.metrics.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            warn!(
                connection = %connection_id,
                remote = %remote_addr,
                "message rate limited: {e}"
            );
            return Err(anyhow::anyhow!("rate limited"));
        }

        // SECURITY: S5 - Enforce JSON nesting depth limit to prevent stack
        // overflow from deeply nested payloads. Although SessionResumed now
        // uses the non-recursive BufferedRelayedMessage type, the depth limit
        // remains as defense-in-depth against future schema changes.
        let frame: ServerFrame = {
            // Manual nesting depth guard: reject if the raw JSON has more
            // than 32 levels of nesting. We check by counting unescaped braces
            // and brackets without a full parse to avoid double-parsing overhead.
            let max_depth: usize = 32;
            let mut depth: usize = 0;
            let mut in_string = false;
            let mut escape = false;
            for byte in raw_message.bytes() {
                if escape {
                    escape = false;
                    continue;
                }
                match byte {
                    b'\\' if in_string => escape = true,
                    b'"' => in_string = !in_string,
                    b'{' | b'[' if !in_string => {
                        depth += 1;
                        if depth > max_depth {
                            return Err(anyhow::anyhow!(
                                "message rejected: JSON nesting depth exceeds limit"
                            ));
                        }
                    }
                    b'}' | b']' if !in_string => {
                        depth = depth.saturating_sub(1);
                    }
                    _ => {}
                }
            }

            serde_json::from_str(raw_message).map_err(|e| anyhow::anyhow!("invalid frame: {e}"))?
        };

        self.dispatch(connection_id, remote_addr, frame).await
    }

    /// Dispatch a parsed `ServerFrame` to the appropriate handler.
    async fn dispatch(
        &self,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        frame: ServerFrame,
    ) -> Result<(), anyhow::Error> {
        match frame {
            // ── Client -> Server frames ─────────────────────────────────
            ServerFrame::HostAuth {
                host_public_key,
                timestamp,
                signature,
                pool_id,
                server_url,
                display_name,
                nonce,
            } => {
                self.handle_host_auth(
                    connection_id,
                    remote_addr,
                    pool_id,
                    host_public_key,
                    signature,
                    timestamp,
                    server_url,
                    display_name,
                    nonce,
                )
                .await
            }

            ServerFrame::JoinRequest {
                token_id,
                proof,
                timestamp,
                nonce,
                client_public_key,
                display_name,
                pow_solution,
            } => {
                self.handle_join_request(
                    connection_id,
                    remote_addr,
                    token_id,
                    proof,
                    timestamp,
                    nonce,
                    client_public_key,
                    display_name,
                    pow_solution,
                )
                .await
            }

            ServerFrame::JoinApproval {
                client_public_key,
                approved,
                reason,
                session_token,
            } => {
                self.handle_join_approval(
                    connection_id,
                    client_public_key,
                    approved,
                    reason,
                    session_token,
                )
                .await
            }

            ServerFrame::Forward {
                data,
                target_peer_ids,
                sequence,
                session_token,
            } => {
                self.handle_forward(
                    connection_id,
                    data,
                    target_peer_ids,
                    sequence,
                    session_token,
                )
                .await
            }

            ServerFrame::KickPeer {
                peer_id,
                reason,
                session_token,
            } => {
                self.handle_kick_peer(connection_id, peer_id, reason, session_token)
                    .await
            }

            ServerFrame::CreateInvitation {
                max_uses,
                expires_in_secs,
                session_token,
            } => {
                self.handle_create_invitation(
                    connection_id,
                    max_uses,
                    expires_in_secs,
                    session_token,
                )
                .await
            }

            ServerFrame::RevokeInvitation {
                token_id,
                session_token,
            } => {
                self.handle_revoke_invitation(connection_id, token_id, session_token)
                    .await
            }

            ServerFrame::ClosePool { session_token } => {
                self.handle_close_pool(connection_id, session_token).await
            }

            ServerFrame::Ack { sequence } => self.handle_ack(connection_id, sequence).await,

            ServerFrame::HandshakeInit {
                client_ephemeral_pk,
                client_identity_pk,
                timestamp,
                signature,
            } => {
                self.handle_handshake_init(
                    connection_id,
                    client_ephemeral_pk,
                    client_identity_pk,
                    timestamp,
                    signature,
                )
                .await
            }

            ServerFrame::ClaimServer {
                claim_secret,
                host_public_key,
                display_name,
            } => {
                self.handle_claim_server(
                    connection_id,
                    remote_addr,
                    claim_secret,
                    host_public_key,
                    display_name,
                )
                .await
            }

            ServerFrame::ReclaimServer {
                recovery_key,
                new_host_public_key,
                display_name,
            } => {
                self.handle_reclaim_server(
                    connection_id,
                    remote_addr,
                    recovery_key,
                    new_host_public_key,
                    display_name,
                )
                .await
            }

            ServerFrame::HeartbeatPing { timestamp } => {
                self.handle_heartbeat_ping(connection_id, timestamp).await
            }

            // ── Server -> Client frames (should never arrive from a client) ──
            ServerFrame::AuthChallenge { .. }
            | ServerFrame::ServerHello { .. }
            | ServerFrame::HostAuthSuccess { .. }
            | ServerFrame::JoinAccepted { .. }
            | ServerFrame::JoinRejected { .. }
            | ServerFrame::PeerJoined { .. }
            | ServerFrame::PeerLeft { .. }
            | ServerFrame::Relayed { .. }
            | ServerFrame::InvitationCreated { .. }
            | ServerFrame::JoinRequestForHost { .. }
            | ServerFrame::SessionResumed { .. }
            | ServerFrame::Kicked { .. }
            | ServerFrame::HeartbeatPong { .. }
            | ServerFrame::ClaimSuccess { .. }
            | ServerFrame::ClaimRejected { .. }
            | ServerFrame::Error { .. } => {
                warn!(
                    connection = %connection_id,
                    "received server-to-client frame from client, ignoring"
                );
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------------
    // Frame handlers
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn handle_host_auth(
        &self,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        pool_id: uuid::Uuid,
        host_public_key: String,
        signature: String,
        timestamp: i64,
        server_url: Option<String>,
        display_name: Option<String>,
        client_nonce: String,
    ) -> Result<(), anyhow::Error> {
        const HOST_AUTH_PREFIX: &[u8] = b"STEALTH_HOST_AUTH_V1:";

        // Rate limit: check IP-level rate.
        if let Err(e) = self.rate_limiter.check_rate(remote_addr.ip()) {
            self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
            self.throttler.record_failure(remote_addr.ip());
            warn!(
                connection = %connection_id,
                remote = %remote_addr,
                pool = %pool_id,
                "host auth rate limited: {e}"
            );

            let error_frame = ServerFrame::Error {
                code: 429,
                message: "rate limited".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Check if this IP is blocked due to repeated auth failures.
        if let Err(e) = self.throttler.check_allowed(remote_addr.ip()) {
            self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
            warn!(
                connection = %connection_id,
                remote = %remote_addr,
                pool = %pool_id,
                "host auth blocked: {e}"
            );

            let error_frame = ServerFrame::Error {
                code: 403,
                message: "temporarily blocked".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // ── Claim state gate ───────────────────────────────────────────
        // If the server is unclaimed, reject all HostAuth frames.
        // The operator must claim the server first via ClaimServer.
        {
            let cs = self
                .claim_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !cs.is_claimed() {
                warn!(
                    connection = %connection_id,
                    pool = %pool_id,
                    "host auth rejected: server not yet claimed"
                );
                let error_frame = ServerFrame::Error {
                    code: 403,
                    message: "server not yet claimed -- send ClaimServer first".to_owned(),
                };
                self.send_to_connection(connection_id, &error_frame)?;
                return Ok(());
            }
        }

        // ── Nonce validation (SECURITY: H-3 replay protection) ─────────
        //
        // Verify the client nonce matches the server-issued nonce for this
        // connection. On match, consume it (one-time use) and enforce a
        // 30-second timestamp window.
        {
            let stored = self.connection_nonces.get(&connection_id);
            match stored {
                Some(expected) if expected.value() == &client_nonce => {
                    // Nonce matches — will be removed after successful auth.
                }
                Some(_) => {
                    self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
                    self.throttler.record_failure(remote_addr.ip());
                    warn!(
                        connection = %connection_id,
                        pool = %pool_id,
                        "host auth nonce mismatch"
                    );
                    let error_frame = ServerFrame::Error {
                        code: 401,
                        message: "auth nonce mismatch".to_owned(),
                    };
                    self.send_to_connection(connection_id, &error_frame)?;
                    return Ok(());
                }
                None => {
                    self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
                    self.throttler.record_failure(remote_addr.ip());
                    warn!(
                        connection = %connection_id,
                        pool = %pool_id,
                        "host auth nonce provided but no challenge was issued for this connection"
                    );
                    let error_frame = ServerFrame::Error {
                        code: 401,
                        message: "no auth challenge issued for this connection".to_owned(),
                    };
                    self.send_to_connection(connection_id, &error_frame)?;
                    return Ok(());
                }
            }
        }

        // Validate timestamp freshness (30-second window, nonce-bound).
        let max_skew: i64 = 30;
        let now = chrono::Utc::now().timestamp();
        let skew = (now - timestamp).abs();
        if skew > max_skew {
            self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
            self.throttler.record_failure(remote_addr.ip());
            warn!(
                connection = %connection_id,
                pool = %pool_id,
                "host auth timestamp outside acceptable window (skew={skew}s, max={max_skew}s)"
            );
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "timestamp outside acceptable window".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Verify the Ed25519 signature over (pool_id || timestamp [|| nonce]).
        let pk_bytes = Base64::decode_vec(&host_public_key)
            .map_err(|_| anyhow::anyhow!("invalid host public key encoding"))?;
        let sig_bytes = Base64::decode_vec(&signature)
            .map_err(|_| anyhow::anyhow!("invalid signature encoding"))?;

        if pk_bytes.len() != 32 || sig_bytes.len() != 64 {
            self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
            self.throttler.record_failure(remote_addr.ip());
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "invalid key or signature length".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        // Build the message that was signed:
        //   domain_prefix || pool_id bytes || timestamp bytes [|| nonce bytes]
        //
        // SECURITY: The domain prefix "STEALTH_HOST_AUTH_V1:" prevents
        // cross-context signature forgery. When a nonce is present, the
        // raw nonce bytes (base64-decoded) are appended to the transcript,
        // binding the signature to this specific connection.
        let nonce_raw = Base64::decode_vec(&client_nonce)
            .map_err(|_| anyhow::anyhow!("invalid nonce encoding"))?;

        let mut sign_msg = Vec::with_capacity(HOST_AUTH_PREFIX.len() + 24 + nonce_raw.len());
        sign_msg.extend_from_slice(HOST_AUTH_PREFIX);
        sign_msg.extend_from_slice(pool_id.as_bytes());
        sign_msg.extend_from_slice(&timestamp.to_be_bytes());
        sign_msg.extend_from_slice(&nonce_raw);

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);

        let host_pub = stealthos_crypto::HostPublicKeys {
            ed25519: pk_arr,
            x25519: [0u8; 32],      // Not needed for verification.
            fingerprint: [0u8; 32], // Not needed for verification.
        };

        if !host_pub.verify(&sign_msg, &sig_arr) {
            self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
            self.throttler.record_failure(remote_addr.ip());
            warn!(
                connection = %connection_id,
                pool = %pool_id,
                "host auth signature verification failed"
            );
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "signature verification failed".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // ── Verify the authenticated key matches the bound host ──────
        {
            let cs = self
                .claim_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !cs.is_bound_host(&pk_arr) {
                self.metrics.auth_failure.fetch_add(1, Ordering::Relaxed);
                self.throttler.record_failure(remote_addr.ip());
                warn!(
                    connection = %connection_id,
                    pool = %pool_id,
                    "host auth rejected: public key does not match bound host"
                );
                let error_frame = ServerFrame::Error {
                    code: 403,
                    message: "public key does not match bound host".to_owned(),
                };
                self.send_to_connection(connection_id, &error_frame)?;
                return Ok(());
            }
        }

        info!(
            connection = %connection_id,
            pool = %pool_id,
            "host auth accepted"
        );

        // Consume the nonce after successful verification (one-time use).
        self.connection_nonces.remove(&connection_id);

        // Record successful auth to reset failure counter.
        self.throttler.record_success(remote_addr.ip());
        self.metrics.auth_success.fetch_add(1, Ordering::Relaxed);
        self.metrics.pools_created.fetch_add(1, Ordering::Relaxed);
        self.metrics.pools_active.fetch_add(1, Ordering::Relaxed);

        // Create the pool and register the host connection.
        let host_peer_id = PeerId(host_public_key);
        let core_pool_id = PoolId(pool_id);

        // SECURITY: S3 - Pool creation uses atomic entry() API in
        // PoolRegistry::create_pool to prevent TOCTOU races. If a pool
        // with this ID already exists, create_pool returns PoolAlreadyExists.
        let host_name =
            display_name.map_or_else(|| "Host".to_owned(), |n| sanitize_display_name(&n));

        if let Err(e) = self.pool_registry.create_pool(
            core_pool_id,
            format!("pool-{pool_id}"),
            connection_id,
            host_peer_id,
            pk_arr,
            host_name,
            self.max_pool_size,
        ) {
            // SECURITY: S6 - Do not leak internal error details (e.g. pool
            // count limits, registry state) to the client. Log the full error
            // server-side but send only a generic message to the client.
            warn!(
                connection = %connection_id,
                pool = %pool_id,
                "failed to create pool: {e}"
            );
            self.metrics.pools_created.fetch_sub(1, Ordering::Relaxed);
            self.metrics.pools_active.fetch_sub(1, Ordering::Relaxed);
            let error_frame = ServerFrame::Error {
                code: 503,
                message: "pool creation failed".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // SECURITY: Store the host-provided server URL AFTER all
        // authentication checks pass. Before this point, the client is
        // unauthenticated and must not be able to influence server state.
        if let Some(url) = server_url {
            self.host_server_urls.insert(core_pool_id, url);
        }

        // Generate a random 32-byte session token, base64-encoded.
        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let session_token = Base64::encode_string(&token_bytes);

        // Store the session token so it can be validated on subsequent
        // privileged operations (CreateInvitation, KickPeer, ClosePool, etc.).
        self.host_session_tokens
            .insert(core_pool_id, session_token.clone());

        let result_frame = ServerFrame::HostAuthSuccess {
            pool_id,
            session_token,
        };
        self.send_to_connection(connection_id, &result_frame)
    }

    /// Handle a `ClaimServer` frame -- one-time server claiming.
    #[allow(clippy::too_many_arguments)]
    async fn handle_claim_server(
        &self,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        claim_secret_hex: String,
        host_public_key_b64: String,
        display_name: String,
    ) -> Result<(), anyhow::Error> {
        // Rate limit: block IPs with repeated auth failures.
        if let Err(e) = self.throttler.check_allowed(remote_addr.ip()) {
            warn!(
                connection = %connection_id,
                remote = %remote_addr,
                "claim server blocked: {e}"
            );
            let frame = ServerFrame::ClaimRejected {
                reason: "temporarily blocked".to_owned(),
            };
            self.send_to_connection(connection_id, &frame)?;
            return Ok(());
        }

        // SECURITY: CRITICAL-1 — Sanitize display_name before any logging or
        // storage to prevent log injection via crafted names.
        let display_name = sanitize_display_name(&display_name);

        warn!(
            connection = %connection_id,
            display_name = %display_name,
            "claim server attempt"
        );

        // Decode the claim secret from hex.
        let secret_bytes = match claim::hex_decode(&claim_secret_hex) {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                warn!(
                    connection = %connection_id,
                    "claim rejected: invalid claim secret encoding"
                );
                let frame = ServerFrame::ClaimRejected {
                    reason: "invalid claim secret format".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)?;
                return Ok(());
            }
        };

        // Decode the host public key from base64.
        let pk_bytes = match Base64::decode_vec(&host_public_key_b64) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                warn!(
                    connection = %connection_id,
                    "claim rejected: invalid host public key encoding"
                );
                let frame = ServerFrame::ClaimRejected {
                    reason: "invalid host public key format".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)?;
                return Ok(());
            }
        };

        // Get the server fingerprint for binding.
        let server_fingerprint = claim::hex_encode(&self.host_identity.fingerprint());

        // Attempt the claim (lock scope is minimal -- no await inside).
        let result = {
            let mut cs = self
                .claim_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cs.try_claim(&secret_bytes, &pk_bytes, &self.key_dir, &server_fingerprint)
        };

        match result {
            Ok((_binding, recovery_key)) => {
                warn!(
                    connection = %connection_id,
                    display_name = %display_name,
                    "server claimed successfully"
                );

                let recovery_hex = claim::hex_encode(&recovery_key);

                // Pass recovery key to setup page so it can display it once.
                if let Some(ref ss) = self.setup_state {
                    ss.set_recovery_key(recovery_hex.clone());
                }

                let frame = ServerFrame::ClaimSuccess {
                    server_fingerprint,
                    message: "server claimed successfully".to_owned(),
                    recovery_key: recovery_hex,
                };
                self.send_to_connection(connection_id, &frame)
            }
            Err(claim::ClaimError::AlreadyClaimed) => {
                warn!(
                    connection = %connection_id,
                    "claim rejected: server already claimed"
                );
                let frame = ServerFrame::ClaimRejected {
                    reason: "server is already claimed".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)
            }
            Err(claim::ClaimError::InvalidSecret) => {
                self.throttler.record_failure(remote_addr.ip());
                warn!(
                    connection = %connection_id,
                    "claim rejected: invalid secret"
                );
                let frame = ServerFrame::ClaimRejected {
                    reason: "invalid claim secret".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)
            }
            Err(claim::ClaimError::RateLimited) => {
                warn!(
                    connection = %connection_id,
                    "claim rejected: rate limited"
                );
                let frame = ServerFrame::ClaimRejected {
                    reason: "too many failed attempts, try again later".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)
            }
            Err(claim::ClaimError::Io(e)) => {
                warn!(
                    connection = %connection_id,
                    "claim failed: I/O error: {e}"
                );
                let frame = ServerFrame::ClaimRejected {
                    reason: "internal server error".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)
            }
        }
    }

    /// Handle a `ReclaimServer` frame -- rebind using recovery key.
    #[allow(clippy::too_many_arguments)]
    async fn handle_reclaim_server(
        &self,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        recovery_key_hex: String,
        new_host_pk_b64: String,
        display_name: String,
    ) -> Result<(), anyhow::Error> {
        // Rate limit: block IPs with repeated auth failures.
        if let Err(e) = self.throttler.check_allowed(remote_addr.ip()) {
            warn!(
                connection = %connection_id,
                remote = %remote_addr,
                "reclaim server blocked: {e}"
            );
            let frame = ServerFrame::ClaimRejected {
                reason: "temporarily blocked".to_owned(),
            };
            self.send_to_connection(connection_id, &frame)?;
            return Ok(());
        }

        // SECURITY: CRITICAL-1 — Sanitize display_name before any logging or
        // storage to prevent log injection via crafted names.
        let display_name = sanitize_display_name(&display_name);

        warn!(
            connection = %connection_id,
            display_name = %display_name,
            "reclaim server attempt"
        );

        let rk_bytes = match claim::hex_decode(&recovery_key_hex) {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                let frame = ServerFrame::ClaimRejected {
                    reason: "invalid recovery key format".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)?;
                return Ok(());
            }
        };

        let pk_bytes = match Base64::decode_vec(&new_host_pk_b64) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                let frame = ServerFrame::ClaimRejected {
                    reason: "invalid host public key format".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)?;
                return Ok(());
            }
        };

        let result = {
            let mut cs = self
                .claim_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cs.try_reclaim(&rk_bytes, &pk_bytes, &self.key_dir)
        };

        match result {
            Ok((_binding, new_recovery_key)) => {
                warn!(
                    connection = %connection_id,
                    display_name = %display_name,
                    "server reclaimed successfully"
                );

                let server_fp = claim::hex_encode(&self.host_identity.fingerprint());
                let frame = ServerFrame::ClaimSuccess {
                    server_fingerprint: server_fp,
                    message: "server reclaimed successfully — save your new recovery key"
                        .to_owned(),
                    recovery_key: claim::hex_encode(&new_recovery_key),
                };
                self.send_to_connection(connection_id, &frame)
            }
            Err(claim::ClaimError::InvalidSecret) => {
                self.throttler.record_failure(remote_addr.ip());
                warn!(connection = %connection_id, "reclaim rejected: invalid recovery key");
                let frame = ServerFrame::ClaimRejected {
                    reason: "invalid recovery key".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)
            }
            Err(e) => {
                self.throttler.record_failure(remote_addr.ip());
                warn!(connection = %connection_id, "reclaim failed: {e}");
                let frame = ServerFrame::ClaimRejected {
                    reason: "reclaim failed".to_owned(),
                };
                self.send_to_connection(connection_id, &frame)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_join_request(
        &self,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        token_id: String,
        proof: String,
        timestamp: i64,
        nonce: String,
        client_public_key: String,
        display_name: String,
        pow_solution: Option<PowSolutionFrame>,
    ) -> Result<(), anyhow::Error> {
        // SECURITY: HIGH-4 — Validate display_name length FIRST, before rate
        // limiting and PoW verification, to avoid wasting server crypto
        // resources on requests with obviously invalid input.
        if display_name.len() > MAX_DISPLAY_NAME_LEN * 2 {
            // Reject blatantly oversized names before even sanitizing.
            // The factor of 2 accounts for multi-byte UTF-8 characters that
            // might shrink after sanitization.
            warn!(
                connection = %connection_id,
                len = display_name.len(),
                "join request display_name too long"
            );
            let error_frame = ServerFrame::Error {
                code: 400,
                message: "display name too long".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // SECURITY: CRITICAL-1 — Sanitize display_name before any logging,
        // storage in PendingJoin, or forwarding to the host. This prevents
        // log injection via crafted display names containing newlines, control
        // characters, or JSON-breaking sequences.
        let display_name = sanitize_display_name(&display_name);

        // Rate limit: check IP-level rate.
        if let Err(e) = self.rate_limiter.check_rate(remote_addr.ip()) {
            self.metrics.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            warn!(
                connection = %connection_id,
                remote = %remote_addr,
                token = %token_id,
                "join request rate limited: {e}"
            );

            let error_frame = ServerFrame::Error {
                code: 429,
                message: "rate limited".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // SECURITY: Proof-of-Work anti-DoS gate.
        // If the client provided a PoW solution, verify it against the
        // challenge we previously issued. If no solution is provided,
        // generate a challenge and send it back — the client must retry
        // with the solution.
        if let Some(solution) = pow_solution {
            // Verify the provided solution against the stored challenge.
            let pending = self.pending_pow_challenges.remove(&connection_id);
            if let Some((_, pending_challenge)) = pending {
                // Verify freshness first.
                if !pending_challenge
                    .challenge
                    .is_fresh(POW_CHALLENGE_MAX_AGE_SECS)
                {
                    warn!(
                        connection = %connection_id,
                        "PoW challenge expired, issuing new one"
                    );
                    self.issue_pow_challenge(connection_id)?;
                    return Ok(());
                }

                // Decode the solution bytes from base64.
                let solution_bytes = match Base64::decode_vec(&solution.solution) {
                    Ok(b) if b.len() == 8 => {
                        let mut arr = [0u8; 8];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => {
                        warn!(
                            connection = %connection_id,
                            "PoW solution has invalid format"
                        );
                        let error_frame = ServerFrame::Error {
                            code: 400,
                            message: "invalid PoW solution format".to_owned(),
                        };
                        self.send_to_connection(connection_id, &error_frame)?;
                        return Ok(());
                    }
                };

                let pow_solution_obj = stealthos_crypto::pow::PowSolution {
                    solution: solution_bytes,
                };

                if let Err(_e) = pending_challenge.challenge.verify(&pow_solution_obj) {
                    warn!(
                        connection = %connection_id,
                        "PoW verification failed — solution does not meet difficulty"
                    );
                    self.rate_limiter.record_failure(remote_addr.ip());
                    let error_frame = ServerFrame::Error {
                        code: 403,
                        message: "proof-of-work verification failed".to_owned(),
                    };
                    self.send_to_connection(connection_id, &error_frame)?;
                    return Ok(());
                }

                debug!(
                    connection = %connection_id,
                    "PoW verification succeeded"
                );
            } else {
                // Client sent a solution but we have no record of a challenge.
                // Could be a replay or the challenge expired and was cleaned up.
                warn!(
                    connection = %connection_id,
                    "PoW solution received but no pending challenge found"
                );
                self.issue_pow_challenge(connection_id)?;
                return Ok(());
            }
        } else {
            // No PoW solution provided — issue a challenge.
            self.issue_pow_challenge(connection_id)?;
            return Ok(());
        }

        // The server cannot fully verify the invitation proof (it only holds
        // the commitment, not the verification key). Timestamp freshness is
        // checked here; the host will do full cryptographic verification
        // when it receives the JoinRequestForHost.

        info!(
            connection = %connection_id,
            token = %token_id,
            display_name = %display_name,
            "join request received, forwarding to host"
        );

        self.metrics
            .invitations_consumed
            .fetch_add(1, Ordering::Relaxed);

        // Look up which pool this token belongs to by scanning all pools.
        // The token_id is base64-encoded; decode to the 16-byte form.
        let token_id_bytes = Base64::decode_vec(&token_id).ok();
        let target_pool: Option<(Arc<Pool>, PoolId)> = if let Some(ref id_bytes) = token_id_bytes
            && id_bytes.len() == 16
        {
            let mut tid = [0u8; 16];
            tid.copy_from_slice(id_bytes);
            // Try to consume the invitation in each pool.
            // This is a scan, but pool counts are small (max ~100).
            // A production optimization would be a token_id -> pool_id index.
            self.find_pool_for_token(&tid)
        } else {
            None
        };

        let Some((pool, pool_id)) = target_pool else {
            warn!(
                connection = %connection_id,
                token = %token_id,
                "join request: pool not found for token"
            );
            let error_frame = ServerFrame::Error {
                code: 404,
                message: "invitation not found or expired".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        };

        // Enforce per-pool cap on pending joins. This prevents an attacker
        // with one valid token from flooding the global pending_joins map
        // with thousands of entries (all targeting the same pool), which
        // would block join attempts across all other pools.
        let pool_pending = self.pending_join_count_for_pool(pool_id);
        if pool_pending >= MAX_PENDING_JOINS_PER_POOL {
            warn!(
                connection = %connection_id,
                pool = %pool_id,
                pending = pool_pending,
                "per-pool pending join limit reached ({MAX_PENDING_JOINS_PER_POOL}), rejecting"
            );
            let error_frame = ServerFrame::Error {
                code: 503,
                message: "too many pending join requests for this pool, try again later".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Store pending join so we can look it up when the host approves.
        self.pending_joins.insert(
            client_public_key.clone(),
            PendingJoin {
                connection_id,
                display_name: display_name.clone(),
                pool_id,
                created_at: Instant::now(),
            },
        );

        // Forward to the host for approval.
        let host_conn = pool.host_connection_id;
        let forward_frame = ServerFrame::JoinRequestForHost {
            client_public_key,
            token_id,
            proof,
            timestamp,
            nonce,
            display_name,
        };

        self.send_to_connection(host_conn, &forward_frame)
    }

    async fn handle_join_approval(
        &self,
        connection_id: ConnectionId,
        client_public_key: String,
        approved: bool,
        reason: Option<String>,
        session_token: Option<String>,
    ) -> Result<(), anyhow::Error> {
        // Verify sender is the pool host.
        let pool = self.pool_registry.get_pool_for_connection(connection_id);
        let Some(pool) = pool else {
            warn!(
                connection = %connection_id,
                "join approval from connection not in any pool"
            );
            return Ok(());
        };

        if !pool.is_host(connection_id) {
            warn!(
                connection = %connection_id,
                "join approval from non-host connection"
            );
            let error_frame = ServerFrame::Error {
                code: 403,
                message: "only the pool host can approve joins".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Validate session token for this privileged operation.
        if self
            .validate_session_token(connection_id, pool.id, session_token.as_deref())
            .is_err()
        {
            return Ok(());
        }

        // Look up the pending join request.
        let pending = self.pending_joins.remove(&client_public_key);
        let Some((_, pending)) = pending else {
            warn!(
                connection = %connection_id,
                client_pk = %client_public_key,
                "no pending join request for this client"
            );
            return Ok(());
        };

        if approved {
            info!(
                connection = %connection_id,
                client_pk = %client_public_key,
                "join approved by host"
            );

            // Generate peer_id and session token for the new peer.
            let peer_id = PeerId(client_public_key.clone());
            let mut token_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut token_bytes);
            let peer_session_token = Base64::encode_string(&token_bytes);

            // SECURITY: Decode client public key for storage. If the key is
            // not valid base64 or not exactly 32 bytes, reject the join
            // rather than silently using an all-zeros key, which would break
            // E2E encryption for this peer.
            let pk_bytes = match Base64::decode_vec(&client_public_key) {
                Ok(bytes) if bytes.len() == 32 => bytes,
                _ => {
                    warn!(
                        connection = %connection_id,
                        client_pk = %client_public_key,
                        "join approval failed: client public key is not valid base64 or wrong length"
                    );
                    let error_frame = ServerFrame::Error {
                        code: 400,
                        message: "invalid client public key encoding".to_owned(),
                    };
                    self.send_to_connection(connection_id, &error_frame)?;

                    // Also notify the joining client that their join was rejected.
                    let reject_frame = ServerFrame::JoinRejected {
                        reason: "invalid public key".to_owned(),
                    };
                    self.send_to_connection(pending.connection_id, &reject_frame)?;
                    return Ok(());
                }
            };
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk_bytes);

            // Add peer to pool.
            let pool_peer = PoolPeer {
                peer_id: peer_id.clone(),
                connection_id: pending.connection_id,
                display_name: pending.display_name.clone(),
                public_key: pk_arr,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
                last_acked_sequence: 0,
            };

            if let Err(e) = pool.add_peer(pool_peer) {
                // SECURITY: Log the full error server-side but send only a
                // generic message to the client. The PoolError variants
                // contain internal state (e.g., PoolFull(4/4), DuplicatePeer)
                // that could help an attacker enumerate pool capacity or
                // detect whether a peer identity is already connected.
                warn!(
                    connection = %connection_id,
                    "failed to add peer to pool: {e}"
                );
                let reject_frame = ServerFrame::JoinRejected {
                    reason: "unable to join pool at this time".to_owned(),
                };
                self.send_to_connection(pending.connection_id, &reject_frame)?;
                return Ok(());
            }

            // Register the connection-to-pool mapping.
            self.pool_registry
                .register_connection(pending.connection_id, pool.id, peer_id.clone());

            self.metrics
                .connections_active
                .fetch_add(1, Ordering::Relaxed);

            // Build pool info for the response.
            let pool_info = PoolInfo {
                pool_id: pool.id.0,
                name: pool.name.clone(),
                host_peer_id: pool.host_peer_id.0.clone(),
                max_peers: pool.max_peers,
                current_peers: pool.peer_count() + 1, // +1 for host
            };

            let peers = pool.peers();

            // Store the guest's session token for validation on Forward frames.
            self.guest_session_tokens
                .insert(pending.connection_id, peer_session_token.clone());

            // Send JoinAccepted to the client.
            let accepted_frame = ServerFrame::JoinAccepted {
                session_token: peer_session_token,
                peer_id: peer_id.0.clone(),
                peers,
                pool_info,
            };
            self.send_to_connection(pending.connection_id, &accepted_frame)?;

            // Broadcast PeerJoined to all other pool members.
            let new_peer_info = PeerInfo {
                peer_id: peer_id.0,
                display_name: pending.display_name,
                public_key: client_public_key,
                connected_at: 0,
            };
            let joined_frame = ServerFrame::PeerJoined {
                peer: new_peer_info,
            };

            self.broadcast_to_pool(&pool, &joined_frame, &[pending.connection_id]);
        } else {
            info!(
                connection = %connection_id,
                client_pk = %client_public_key,
                reason = reason.as_deref().unwrap_or("none"),
                "join rejected by host"
            );

            let reject_frame = ServerFrame::JoinRejected {
                reason: reason.unwrap_or_else(|| "rejected by host".to_owned()),
            };
            self.send_to_connection(pending.connection_id, &reject_frame)?;
        }

        Ok(())
    }

    async fn handle_forward(
        &self,
        connection_id: ConnectionId,
        data: String,
        target_peer_ids: Option<Vec<String>>,
        sequence: u64,
        session_token: Option<String>,
    ) -> Result<(), anyhow::Error> {
        // NOTE: `data` is the opaque encrypted payload. We NEVER log its content.

        // SECURITY: Bound the number of target peers to prevent O(N) DoS
        // where a malicious client sends a Forward frame with millions of
        // target_peer_ids, each triggering a DashMap lookup and potential
        // buffer_message call.
        const MAX_FORWARD_TARGETS: usize = 64;
        const MAX_FORWARD_DATA_LEN: usize = 65_536; // 64 KiB

        if let Some(ref targets) = target_peer_ids
            && targets.len() > MAX_FORWARD_TARGETS
        {
            warn!(
                connection = %connection_id,
                target_count = targets.len(),
                "forward rejected: too many target_peer_ids"
            );
            let error_frame = ServerFrame::Error {
                code: 400,
                message: "too many target peers".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // SECURITY: Validate data payload size at the handler level.
        // While the transport layer enforces max_message_size on the entire
        // WebSocket frame, the `data` field within a Forward frame could
        // still be very large (up to max_message_size minus JSON overhead).
        // We enforce a tighter limit here to prevent one peer from relaying
        // excessively large payloads that consume memory across all recipients.
        if data.len() > MAX_FORWARD_DATA_LEN {
            warn!(
                connection = %connection_id,
                data_len = data.len(),
                "forward data payload too large"
            );
            let error_frame = ServerFrame::Error {
                code: 400,
                message: "data payload too large".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Determine the pool this connection belongs to.
        let pool = self.pool_registry.get_pool_for_connection(connection_id);

        let target_count = target_peer_ids
            .as_ref()
            .map_or_else(|| "broadcast".to_owned(), |t| t.len().to_string());

        // PERFORMANCE: P5 - Forward/Relayed is the hot path. Logging at
        // debug level creates measurable overhead under load because the
        // tracing infrastructure must format arguments even when filtered.
        // Use trace level so this is only active under explicit opt-in.
        trace!(
            connection = %connection_id,
            target_count = %target_count,
            sequence = sequence,
            data_len = data.len(),
            "forwarding message"
        );

        self.metrics
            .messages_relayed
            .fetch_add(1, Ordering::Relaxed);
        self.metrics.messages_bytes.fetch_add(
            u64::try_from(data.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );

        let Some(pool) = pool else {
            warn!(
                connection = %connection_id,
                "forward from connection not in any pool"
            );
            return Ok(());
        };

        // Validate session token for both host and guest peers.
        if pool.is_host(connection_id) {
            if self
                .validate_session_token(connection_id, pool.id, session_token.as_deref())
                .is_err()
            {
                return Ok(());
            }
        } else if self
            .validate_guest_session_token(connection_id, session_token.as_deref())
            .is_err()
        {
            return Ok(());
        }

        // SECURITY: Resolve the sender's peer_id from the authoritative
        // connection-to-pool mapping in the PoolRegistry, NOT from the pool's
        // peer list. This guarantees the from_peer_id in Relayed frames cannot
        // be spoofed -- it always reflects the authenticated identity that was
        // recorded at join/host-auth time.
        let Some(sender_peer_id) = self.get_peer_id_for_connection(connection_id, &pool) else {
            // The connection is not registered in any pool. This can happen
            // if a disconnect races with an in-flight Forward. Reject silently.
            warn!(
                connection = %connection_id,
                "forward from connection with no authenticated peer identity"
            );
            return Ok(());
        };
        let route_result = Router::route(
            &pool,
            &sender_peer_id,
            connection_id,
            &data,
            target_peer_ids.as_deref(),
            sequence,
        );

        // PERFORMANCE: Router now returns a single ServerFrame and a list of
        // recipient ConnectionIds. We serialize the frame once and share the
        // JSON string across all recipients via clone (cheap Arc bump on the
        // String's internal buffer).
        if let Some(result) = route_result {
            let json: Arc<str> = serde_json::to_string(&result.frame)
                .map_err(|e| anyhow::anyhow!("failed to serialize frame: {e}"))?
                .into();

            for conn_id in &result.recipients {
                if let Err(e) = self
                    .connection_registry
                    .send_to(*conn_id, OutboundMessage::SharedText(Arc::clone(&json)))
                {
                    // PERFORMANCE: P5 - Slow-consumer send failures are expected
                    // under load and already handled by the connection actor's
                    // eviction logic. Use debug to avoid log amplification storms
                    // on the hot path when many consumers are slow.
                    debug!(
                        connection = %conn_id,
                        "failed to deliver relayed message: {e}"
                    );
                }
            }
        }

        Ok(())
    }

    async fn handle_kick_peer(
        &self,
        connection_id: ConnectionId,
        peer_id: String,
        reason: String,
        session_token: Option<String>,
    ) -> Result<(), anyhow::Error> {
        // Verify sender is the pool host.
        let pool = self.pool_registry.get_pool_for_connection(connection_id);
        let Some(pool) = pool else {
            warn!(connection = %connection_id, "kick from connection not in pool");
            return Ok(());
        };

        if !pool.is_host(connection_id) {
            warn!(
                connection = %connection_id,
                "kick attempt from non-host"
            );
            let error_frame = ServerFrame::Error {
                code: 403,
                message: "only the pool host can kick peers".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Validate session token for this privileged operation.
        if self
            .validate_session_token(connection_id, pool.id, session_token.as_deref())
            .is_err()
        {
            return Ok(());
        }

        info!(
            connection = %connection_id,
            peer = %peer_id,
            reason = %reason,
            "kicking peer from pool"
        );

        let target_peer_id = PeerId(peer_id.clone());

        // Look up the peer's connection_id before removing.
        let removed = pool.remove_peer(&target_peer_id);
        if let Some(removed_peer) = removed {
            // Send Kicked frame to the target peer.
            let kicked_frame = ServerFrame::Kicked {
                reason: reason.clone(),
            };
            let _ = self.send_to_connection(removed_peer.connection_id, &kicked_frame);

            // Unregister the connection from pool mapping.
            self.pool_registry
                .unregister_connection(removed_peer.connection_id);

            // Close the connection.
            let _ = self.connection_registry.send_to(
                removed_peer.connection_id,
                OutboundMessage::Close(1000, "kicked".to_owned()),
            );

            // Broadcast PeerLeft to remaining members.
            let left_frame = ServerFrame::PeerLeft { peer_id, reason };
            self.broadcast_to_pool(
                &pool,
                &left_frame,
                &[connection_id, removed_peer.connection_id],
            );
        } else {
            warn!(
                connection = %connection_id,
                peer = %target_peer_id,
                "peer not found in pool"
            );
        }

        Ok(())
    }

    async fn handle_create_invitation(
        &self,
        connection_id: ConnectionId,
        max_uses: u8,
        expires_in_secs: u64,
        session_token: Option<String>,
    ) -> Result<(), anyhow::Error> {
        // Verify sender is the pool host.
        let pool = self.pool_registry.get_pool_for_connection(connection_id);
        let Some(pool) = pool else {
            warn!(connection = %connection_id, "create invitation from connection not in pool");
            return Ok(());
        };

        if !pool.is_host(connection_id) {
            let error_frame = ServerFrame::Error {
                code: 403,
                message: "only the pool host can create invitations".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Validate session token for this privileged operation.
        if self
            .validate_session_token(connection_id, pool.id, session_token.as_deref())
            .is_err()
        {
            return Ok(());
        }

        info!(
            connection = %connection_id,
            max_uses = max_uses,
            expires_in_secs = expires_in_secs,
            "creating invitation"
        );

        self.metrics
            .invitations_created
            .fetch_add(1, Ordering::Relaxed);

        // Generate invitation token via stealthos-crypto.
        let ttl_secs = i64::try_from(expires_in_secs).unwrap_or(i64::MAX);
        let token = InvitationToken::generate(
            &self.host_identity,
            pool.id.0,
            self.host_server_urls
                .get(&pool.id)
                .map_or_else(|| self.server_addr.clone(), |entry| entry.value().clone()),
            ttl_secs,
            max_uses,
        );

        // Store commitment in the pool.
        let commitment = token.commitment();
        let expires_at = chrono::Utc::now().timestamp() + ttl_secs;
        pool.add_invitation_commitment(token.token_id, commitment, expires_at, max_uses);

        // Index for token_id -> pool_id lookup during join requests.
        self.token_to_pool.insert(token.token_id, pool.id);

        let token_id_b64 = Base64::encode_string(&token.token_id);
        let url = token.to_url();

        let created_frame = ServerFrame::InvitationCreated {
            token_id: token_id_b64,
            url,
            expires_at,
        };

        self.send_to_connection(connection_id, &created_frame)
    }

    async fn handle_revoke_invitation(
        &self,
        connection_id: ConnectionId,
        token_id: String,
        session_token: Option<String>,
    ) -> Result<(), anyhow::Error> {
        // Verify sender is the pool host.
        let pool = self.pool_registry.get_pool_for_connection(connection_id);
        let Some(pool) = pool else {
            warn!(connection = %connection_id, "revoke invitation from connection not in pool");
            return Ok(());
        };

        if !pool.is_host(connection_id) {
            let error_frame = ServerFrame::Error {
                code: 403,
                message: "only the pool host can revoke invitations".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Validate session token for this privileged operation.
        if self
            .validate_session_token(connection_id, pool.id, session_token.as_deref())
            .is_err()
        {
            return Ok(());
        }

        info!(
            connection = %connection_id,
            token = %token_id,
            "revoking invitation"
        );

        // Decode token_id and revoke from both the pool and the token_to_pool index.
        // SECURITY: Without cleaning token_to_pool, revoked tokens would still
        // map to pool IDs, leaking memory and potentially allowing stale lookups
        // if pool IDs were ever reused.
        if let Ok(id_bytes) = Base64::decode_vec(&token_id)
            && id_bytes.len() == 16
        {
            let mut tid = [0u8; 16];
            tid.copy_from_slice(&id_bytes);
            pool.revoke_invitation(&tid);
            self.token_to_pool.remove(&tid);
        }

        Ok(())
    }

    async fn handle_close_pool(
        &self,
        connection_id: ConnectionId,
        session_token: Option<String>,
    ) -> Result<(), anyhow::Error> {
        // Verify sender is the pool host.
        let pool = self.pool_registry.get_pool_for_connection(connection_id);
        let Some(pool) = pool else {
            warn!(connection = %connection_id, "close pool from connection not in pool");
            return Ok(());
        };

        if !pool.is_host(connection_id) {
            let error_frame = ServerFrame::Error {
                code: 403,
                message: "only the pool host can close the pool".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        // Validate session token for this privileged operation.
        if self
            .validate_session_token(connection_id, pool.id, session_token.as_deref())
            .is_err()
        {
            return Ok(());
        }

        info!(
            connection = %connection_id,
            pool = %pool.id,
            "closing pool"
        );

        self.close_pool_impl(&pool);

        Ok(())
    }

    async fn handle_ack(
        &self,
        connection_id: ConnectionId,
        sequence: u64,
    ) -> Result<(), anyhow::Error> {
        // PERFORMANCE: P5 - Acks are high-frequency hot-path messages.
        trace!(
            connection = %connection_id,
            sequence = sequence,
            "ack received"
        );

        // Look up the pool and peer identity for this connection.
        let pool = self.pool_registry.get_pool_for_connection(connection_id);
        let Some(pool) = pool else {
            // Connection is not in any pool -- ignore silently.
            // This can happen if an ack arrives after the peer has been
            // removed (e.g., race with pool closure or kick).
            return Ok(());
        };

        let Some(peer_id) = self.get_peer_id_for_connection(connection_id, &pool) else {
            return Ok(());
        };

        // Update the peer's last_acked_sequence (only advances forward,
        // preventing rollback from stale or replayed acks).
        if pool.update_last_acked_sequence(&peer_id, sequence) {
            // Prune the message buffer: remove all buffered messages for
            // this peer with sequence <= the acknowledged sequence.
            pool.prune_buffer(&peer_id, sequence);

            trace!(
                connection = %connection_id,
                peer = %peer_id.0,
                sequence = sequence,
                "ack processed, buffer pruned"
            );
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_handshake_init(
        &self,
        connection_id: ConnectionId,
        client_ephemeral_pk: String,
        client_identity_pk: String,
        timestamp: i64,
        signature: String,
    ) -> Result<(), anyhow::Error> {
        info!(
            connection = %connection_id,
            "handshake init received"
        );

        // Decode the client's ephemeral X25519 public key.
        let eph_bytes = Base64::decode_vec(&client_ephemeral_pk)
            .map_err(|_| anyhow::anyhow!("invalid client_ephemeral_pk encoding"))?;
        if eph_bytes.len() != 32 {
            let error_frame = ServerFrame::Error {
                code: 400,
                message: "invalid client_ephemeral_pk length".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }
        let mut eph_arr = [0u8; 32];
        eph_arr.copy_from_slice(&eph_bytes);

        // Decode the client's Ed25519 identity public key.
        let id_bytes = Base64::decode_vec(&client_identity_pk)
            .map_err(|_| anyhow::anyhow!("invalid client_identity_pk encoding"))?;
        if id_bytes.len() != 32 {
            let error_frame = ServerFrame::Error {
                code: 400,
                message: "invalid client_identity_pk length".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }
        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(&id_bytes);

        // Decode the client's Ed25519 signature.
        let sig_bytes = Base64::decode_vec(&signature)
            .map_err(|_| anyhow::anyhow!("invalid signature encoding"))?;
        if sig_bytes.len() != 64 {
            let error_frame = ServerFrame::Error {
                code: 400,
                message: "invalid signature length".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        // Construct the HandshakeMessage the crypto crate expects.
        let init_msg = HandshakeMessage {
            ephemeral_pk: eph_arr,
            ed25519_pk: Some(id_arr),
            timestamp,
            signature: sig_arr,
        };

        // Determine the pool_id for domain separation. If the connection is
        // already in a pool, use that pool's ID. Otherwise use a zero-length
        // pool_id (pre-pool handshake for transport-level encryption).
        let pool_id_bytes: Vec<u8> = self
            .pool_registry
            .get_pool_for_connection(connection_id)
            .map(|pool| pool.id.0.as_bytes().to_vec())
            .unwrap_or_default();

        // Create the responder and process the client's init message.
        let responder = HandshakeResponder::new(&self.host_identity, pool_id_bytes);
        let (response_msg, session_keys) = match responder.process_init_message(&init_msg) {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    connection = %connection_id,
                    "handshake failed: {e}"
                );
                let error_frame = ServerFrame::Error {
                    code: 401,
                    message: "handshake verification failed".to_owned(),
                };
                self.send_to_connection(connection_id, &error_frame)?;
                return Ok(());
            }
        };

        // Create a server-side SessionCipher from the derived keys.
        let cipher = SessionCipher::new(&session_keys, true);
        self.session_ciphers
            .insert(connection_id, Mutex::new(cipher));

        // Send the handshake response as a ServerHello frame.
        let server_pub = self.host_identity.public_keys();
        let response_frame = ServerFrame::ServerHello {
            server_ephemeral_pk: Base64::encode_string(&response_msg.ephemeral_pk),
            server_identity_pk: Base64::encode_string(&server_pub.ed25519),
            pow_challenge: None,
            timestamp: response_msg.timestamp,
            signature: Base64::encode_string(&response_msg.signature),
        };

        info!(
            connection = %connection_id,
            "handshake completed, session cipher established"
        );

        self.send_to_connection(connection_id, &response_frame)
    }

    async fn handle_heartbeat_ping(
        &self,
        connection_id: ConnectionId,
        timestamp: i64,
    ) -> Result<(), anyhow::Error> {
        let pong_frame = ServerFrame::HeartbeatPong {
            timestamp,
            server_time: chrono::Utc::now().timestamp_millis(),
        };

        self.send_to_connection(connection_id, &pong_frame)
    }

    // -----------------------------------------------------------------------
    // Public helpers for the main server loop
    // -----------------------------------------------------------------------

    /// Handle a newly established WebSocket connection by generating a
    /// per-connection auth nonce and sending an `AuthChallenge` frame.
    ///
    /// SECURITY: H-3 — The nonce binds any subsequent `HostAuth` signature
    /// to this specific connection, preventing replay of captured auth
    /// frames on a different WebSocket within the timestamp window.
    pub fn handle_new_connection(&self, connection_id: ConnectionId) {
        let mut nonce_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Base64::encode_string(&nonce_bytes);

        self.connection_nonces.insert(connection_id, nonce.clone());

        let challenge_frame = ServerFrame::AuthChallenge { nonce };
        if let Err(e) = self.send_to_connection(connection_id, &challenge_frame) {
            warn!(
                connection = %connection_id,
                "failed to send auth challenge: {e}"
            );
        }
    }

    /// Handle a peer disconnection: remove from pool and notify others.
    pub fn handle_disconnect(&self, connection_id: ConnectionId) {
        // Clean up any session cipher for this connection. The cipher holds
        // key material that is zeroized on drop.
        self.session_ciphers.remove(&connection_id);
        // Clean up any guest session token for this connection.
        self.guest_session_tokens.remove(&connection_id);
        // Clean up any unused auth nonce for this connection.
        self.connection_nonces.remove(&connection_id);

        let Some((pool_id, peer_id)) = self.pool_registry.unregister_connection(connection_id)
        else {
            return;
        };

        let Some(pool) = self.pool_registry.get_pool(pool_id) else {
            return;
        };

        if pool.is_host(connection_id) {
            // Host disconnected -- close the entire pool.
            info!(
                connection = %connection_id,
                pool = %pool_id,
                "host disconnected, closing pool"
            );
            self.close_pool_impl(&pool);
        } else {
            // Guest disconnected -- remove from pool and notify others.
            pool.remove_peer(&peer_id);
            self.metrics
                .connections_active
                .fetch_sub(1, Ordering::Relaxed);

            let left_frame = ServerFrame::PeerLeft {
                peer_id: peer_id.0,
                reason: "disconnected".to_owned(),
            };
            self.broadcast_to_pool(&pool, &left_frame, &[connection_id]);
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Close a pool: kick all peers, remove from registry, update metrics.
    ///
    /// Also cleans up the `token_to_pool` index to prevent stale mappings
    /// from leaking memory or causing incorrect future lookups.
    fn close_pool_impl(&self, pool: &Pool) {
        // Send Kicked to all guest peers.
        let kicked_frame = ServerFrame::Kicked {
            reason: "pool closed".to_owned(),
        };

        for (peer_id, conn_id) in pool.guest_connection_ids() {
            let _ = self.send_to_connection(conn_id, &kicked_frame);
            let _ = self.connection_registry.send_to(
                conn_id,
                OutboundMessage::Close(1000, "pool closed".to_owned()),
            );
            pool.remove_peer(&peer_id);
            self.pool_registry.unregister_connection(conn_id);
        }

        // Clean up token_to_pool index: remove all entries pointing to this pool.
        // Without this, the map leaks memory for every closed pool's tokens.
        let pool_id = pool.id;
        self.token_to_pool.retain(|_, pid| *pid != pool_id);

        // Clean up the session token and server URL for this pool.
        self.host_session_tokens.remove(&pool_id);
        self.host_server_urls.remove(&pool_id);

        // Clean up any pending join requests targeting this pool.
        self.pending_joins
            .retain(|_, pending| pending.pool_id != pool_id);

        self.pool_registry.remove_pool(pool.id);
        self.metrics.pools_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Serialize a frame and send it to a specific connection.
    fn send_to_connection(
        &self,
        connection_id: ConnectionId,
        frame: &ServerFrame,
    ) -> Result<(), anyhow::Error> {
        let json = serde_json::to_string(frame)
            .map_err(|e| anyhow::anyhow!("failed to serialize frame: {e}"))?;

        self.connection_registry
            .send_to(connection_id, OutboundMessage::Text(json))
            .map_err(|e| anyhow::anyhow!("failed to send to {connection_id}: {e}"))
    }

    /// Broadcast a frame to all members of a pool, excluding specified connections.
    fn broadcast_to_pool(&self, pool: &Pool, frame: &ServerFrame, exclude: &[ConnectionId]) {
        let Ok(json_string) = serde_json::to_string(frame) else {
            return;
        };
        let json: Arc<str> = json_string.into();

        // Send to host if not excluded.
        if !exclude.contains(&pool.host_connection_id) {
            let _ = self.connection_registry.send_to(
                pool.host_connection_id,
                OutboundMessage::SharedText(Arc::clone(&json)),
            );
        }

        // Send to all guests not excluded.
        for (_, conn_id) in pool.guest_connection_ids() {
            if !exclude.contains(&conn_id) {
                let _ = self
                    .connection_registry
                    .send_to(conn_id, OutboundMessage::SharedText(Arc::clone(&json)));
            }
        }
    }

    /// Resolve a connection's peer ID within a pool.
    ///
    /// Uses the `PoolRegistry`'s authoritative `connection_to_pool` mapping
    /// (O(1) `DashMap` lookup) instead of iterating the pool's peer list.
    /// Returns `None` if the connection has no registered peer identity,
    /// which prevents spoofed `from_peer_id` in forwarded messages.
    fn get_peer_id_for_connection(
        &self,
        connection_id: ConnectionId,
        pool: &Pool,
    ) -> Option<PeerId> {
        if pool.is_host(connection_id) {
            return Some(pool.host_peer_id.clone());
        }
        // O(1) lookup from the connection-to-pool registry instead of
        // iterating the pool's DashMap (which holds shard locks during iter).
        self.pool_registry.get_peer_id_for_connection(connection_id)
    }

    /// Purge pending join requests older than `PENDING_JOIN_TTL_SECS`.
    ///
    /// This prevents memory exhaustion from an attacker sending thousands of
    /// `JoinRequest` frames with valid-looking tokens that the host never
    /// responds to.
    fn purge_expired_pending_joins(&self) {
        let now = Instant::now();
        let ttl = std::time::Duration::from_secs(PENDING_JOIN_TTL_SECS);
        self.pending_joins
            .retain(|_, pending| now.duration_since(pending.created_at) < ttl);
    }

    /// Purge `PoW` challenges older than `POW_CHALLENGE_MAX_AGE_SECS`.
    fn purge_expired_pow_challenges(&self) {
        let now = Instant::now();
        let ttl = std::time::Duration::from_secs(
            u64::try_from(POW_CHALLENGE_MAX_AGE_SECS).unwrap_or(120),
        );
        self.pending_pow_challenges
            .retain(|_, challenge| now.duration_since(challenge.created_at) < ttl);
    }

    /// Generate a `PoW` challenge for the given connection and send it.
    ///
    /// Returns early if the pending challenge table is full (`DoS` protection).
    fn issue_pow_challenge(&self, connection_id: ConnectionId) -> Result<(), anyhow::Error> {
        // Cap the number of outstanding challenges to prevent memory exhaustion.
        if self.pending_pow_challenges.len() >= MAX_PENDING_POW_CHALLENGES {
            let error_frame = ServerFrame::Error {
                code: 503,
                message: "server busy, try again later".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Ok(());
        }

        let challenge = PowChallenge::generate(POW_DEFAULT_DIFFICULTY);

        // Encode the challenge as a PowChallengeFrame so the client can
        // parse the structured data from the error message. The client
        // detects HTTP 428 (Precondition Required) and extracts the
        // embedded challenge JSON.
        let pow_challenge_frame = PowChallengeFrame {
            challenge: Base64::encode_string(&challenge.challenge),
            difficulty: challenge.difficulty,
            timestamp: challenge.timestamp,
        };

        // Store the challenge for later verification.
        self.pending_pow_challenges.insert(
            connection_id,
            PendingPowChallenge {
                challenge,
                created_at: Instant::now(),
            },
        );

        // Send the challenge to the client as a structured Error frame.
        let challenge_json = serde_json::to_string(&pow_challenge_frame).unwrap_or_default();
        let error_frame = ServerFrame::Error {
            code: 428,
            message: format!("proof-of-work required: {challenge_json}"),
        };
        self.send_to_connection(connection_id, &error_frame)
    }

    /// Find which pool a token belongs to using the token->pool index.
    fn find_pool_for_token(&self, token_id: &[u8; 16]) -> Option<(Arc<Pool>, PoolId)> {
        let pool_id = self.token_to_pool.get(token_id)?;
        let pool_id = *pool_id.value();
        let pool = self.pool_registry.get_pool(pool_id)?;
        Some((pool, pool_id))
    }

    /// Validate a session token for a privileged host operation.
    ///
    /// Returns `Ok(())` if the token matches the stored session token for
    /// the pool. Returns `Err(())` and sends an error frame to the
    /// connection if validation fails.
    fn validate_session_token(
        &self,
        connection_id: ConnectionId,
        pool_id: PoolId,
        provided_token: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let Some(provided) = provided_token else {
            warn!(
                connection = %connection_id,
                pool = %pool_id,
                "privileged operation rejected: missing session token"
            );
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "session token required".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Err(anyhow::anyhow!("missing session token"));
        };

        let stored = self.host_session_tokens.get(&pool_id);
        let Some(stored_ref) = stored else {
            warn!(
                connection = %connection_id,
                pool = %pool_id,
                "privileged operation rejected: no session token on file for pool"
            );
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "invalid session token".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Err(anyhow::anyhow!("no session token for pool"));
        };

        // Constant-time comparison to prevent timing side-channel.
        let tokens_match: bool =
            subtle::ConstantTimeEq::ct_eq(provided.as_bytes(), stored_ref.value().as_bytes())
                .into();

        if !tokens_match {
            warn!(
                connection = %connection_id,
                pool = %pool_id,
                "privileged operation rejected: session token mismatch"
            );
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "invalid session token".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Err(anyhow::anyhow!("session token mismatch"));
        }

        Ok(())
    }

    /// Validate a session token for a guest peer operation (e.g., `Forward`).
    ///
    /// Returns `Ok(())` if the token matches the stored guest session token
    /// for this connection. Returns `Err(())` and sends an error frame if
    /// validation fails.
    fn validate_guest_session_token(
        &self,
        connection_id: ConnectionId,
        provided_token: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let Some(provided) = provided_token else {
            warn!(
                connection = %connection_id,
                "guest forward rejected: missing session token"
            );
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "session token required".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Err(anyhow::anyhow!("missing guest session token"));
        };

        let stored = self.guest_session_tokens.get(&connection_id);
        let Some(stored_ref) = stored else {
            warn!(
                connection = %connection_id,
                "guest forward rejected: no session token on file"
            );
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "invalid session token".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Err(anyhow::anyhow!("no guest session token on file"));
        };

        let tokens_match: bool =
            subtle::ConstantTimeEq::ct_eq(provided.as_bytes(), stored_ref.value().as_bytes())
                .into();

        if !tokens_match {
            warn!(
                connection = %connection_id,
                "guest forward rejected: session token mismatch"
            );
            let error_frame = ServerFrame::Error {
                code: 401,
                message: "invalid session token".to_owned(),
            };
            self.send_to_connection(connection_id, &error_frame)?;
            return Err(anyhow::anyhow!("guest session token mismatch"));
        }

        Ok(())
    }

    /// Count the number of pending join requests targeting a specific pool.
    fn pending_join_count_for_pool(&self, pool_id: PoolId) -> usize {
        self.pending_joins
            .iter()
            .filter(|entry| entry.value().pool_id == pool_id)
            .count()
    }
}
