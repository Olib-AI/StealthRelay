use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Frames exchanged between iOS clients and the Rust relay server over WebSocket.
///
/// Serialized as JSON with an internally-tagged `frame_type` discriminator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "frame_type", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum ServerFrame {
    // ── Client -> Server ──────────────────────────────────────────────
    /// Authenticate as the pool host.
    HostAuth {
        host_public_key: String,
        timestamp: i64,
        signature: String,
        pool_id: Uuid,
        /// The server URL as seen by the host, for embedding in invitation URLs.
        #[serde(default)]
        server_url: Option<String>,
        /// The host's display name shown to other pool members.
        #[serde(default)]
        display_name: Option<String>,
        /// Server-issued per-connection nonce for replay protection.
        /// Included in the signature transcript to bind the auth to a
        /// specific connection and prevent replay attacks.
        nonce: String,
        /// Whether the host opts in to providing tunnel exit ("VPN-like")
        /// for pool members. The relay treats `None` as `Some(false)` and
        /// stores the value as the pool's initial `tunnel_exit_enabled`
        /// flag. Backward compatible: existing clients that omit the field
        /// continue to authenticate unchanged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tunnel_exit_enabled: Option<bool>,
    },

    /// Request to join a pool with an invitation token.
    JoinRequest {
        token_id: String,
        proof: String,
        timestamp: i64,
        nonce: String,
        client_public_key: String,
        display_name: String,
        pow_solution: Option<PowSolutionFrame>,
    },

    /// Forward application data (opaque E2E encrypted `PoolMessage`) to peer(s).
    Forward {
        data: String,
        target_peer_ids: Option<Vec<String>>,
        sequence: u64,
        /// Session token for host-originated forwards. Optional so that
        /// guest peers (who also send Forward frames) are not required to
        /// provide one -- guest identity is verified by connection mapping.
        #[serde(default)]
        session_token: Option<String>,
    },

    /// Host kicks a peer from the pool.
    KickPeer {
        peer_id: String,
        reason: String,
        /// Session token issued at pool creation. Required.
        #[serde(default)]
        session_token: Option<String>,
    },

    /// Host creates an invitation token.
    CreateInvitation {
        max_uses: u8,
        expires_in_secs: u64,
        /// Session token issued at pool creation. Required.
        #[serde(default)]
        session_token: Option<String>,
    },

    /// Host revokes an existing invitation.
    RevokeInvitation {
        token_id: String,
        /// Session token issued at pool creation. Required.
        #[serde(default)]
        session_token: Option<String>,
    },

    /// Host approves or rejects a pending join request.
    JoinApproval {
        client_public_key: String,
        approved: bool,
        reason: Option<String>,
        /// Session token issued at pool creation. Required.
        #[serde(default)]
        session_token: Option<String>,
    },

    /// Acknowledge receipt of a sequence number.
    Ack { sequence: u64 },

    /// Close the pool (host only).
    ClosePool {
        /// Session token issued at pool creation. Required.
        #[serde(default)]
        session_token: Option<String>,
    },

    /// Update mutable per-pool configuration flags (host only).
    ///
    /// The supported flag is `tunnel_exit_enabled`, which is one of two
    /// AND-gates that authorize a member to use the relay's server-side
    /// tunnel-exit gateway (the relay opens real TCP/UDP sockets to
    /// destinations on behalf of authenticated peers; the pool host
    /// merely *approves* their members' use of that gateway). The
    /// other gate is the server-wide `[tunnel] enabled` config flag.
    UpdatePoolConfig(UpdatePoolConfigData),

    // ── Tunnel control plane (Client -> Server) ───────────────────────
    /// Open a new tunnel stream (TCP or UDP) to a destination.
    TunnelOpen(TunnelOpenData),

    /// Close an existing tunnel stream.
    TunnelClose(TunnelCloseData),

    /// Grant additional receive credit to the server for the given stream
    /// (member-controlled flow control: server stops sending data on a
    /// stream when its outbound credit drops to zero).
    TunnelWindowUpdate(TunnelWindowUpdateData),

    /// Resolve a hostname via the server's DNS resolver.
    TunnelDnsQuery(TunnelDnsQueryData),

    /// Client handshake init (Noise NK step 1).
    HandshakeInit {
        client_ephemeral_pk: String,
        client_identity_pk: String,
        timestamp: i64,
        signature: String,
    },

    /// Client claims ownership of an unclaimed server.
    ClaimServer {
        /// The claim secret from the server logs (hex-encoded, 64 chars).
        claim_secret: String,
        /// The host's Ed25519 public key (base64-encoded).
        host_public_key: String,
        /// Display name for the host.
        display_name: String,
    },

    /// Client reclaims a server using the recovery key (if they lost access).
    ReclaimServer {
        /// The recovery key (hex-encoded, 64 chars).
        recovery_key: String,
        /// The new host's Ed25519 public key (base64-encoded).
        new_host_public_key: String,
        /// Display name for the new host.
        display_name: String,
    },

    /// Heartbeat ping.
    HeartbeatPing { timestamp: i64 },

    // ── Server -> Client ──────────────────────────────────────────────
    /// Per-connection auth challenge sent immediately after WebSocket
    /// upgrade. Contains a one-time nonce that the client MUST include
    /// in its `HostAuth` signature transcript to prevent replay attacks.
    AuthChallenge {
        /// Base64-encoded 32-byte random nonce. The client includes this
        /// in the signed transcript: `STEALTH_HOST_AUTH_V1: || pool_id || timestamp || nonce`.
        nonce: String,
    },

    /// Server hello with optional proof-of-work challenge.
    ServerHello {
        server_ephemeral_pk: String,
        server_identity_pk: String,
        pow_challenge: Option<PowChallengeFrame>,
        timestamp: i64,
        signature: String,
    },

    /// Host authentication succeeded.
    HostAuthSuccess {
        pool_id: Uuid,
        session_token: String,
    },

    /// Join request accepted.
    JoinAccepted {
        session_token: String,
        peer_id: String,
        peers: Vec<PeerInfo>,
        pool_info: PoolInfo,
    },

    /// Join request rejected.
    JoinRejected { reason: String },

    /// A new peer joined the pool.
    PeerJoined { peer: PeerInfo },

    /// A peer left the pool.
    PeerLeft { peer_id: String, reason: String },

    /// Relayed data from another peer.
    Relayed {
        data: String,
        from_peer_id: String,
        sequence: u64,
    },

    /// Invitation token created successfully.
    InvitationCreated {
        token_id: String,
        url: String,
        expires_at: i64,
    },

    /// Forward a join request to the host for approval.
    JoinRequestForHost {
        client_public_key: String,
        token_id: String,
        proof: String,
        timestamp: i64,
        nonce: String,
        display_name: String,
    },

    /// Session resumed with buffered messages the client missed.
    ///
    /// Uses `Vec<BufferedRelayedMessage>` instead of `Vec<ServerFrame>` to
    /// eliminate the recursive type definition. A recursive
    /// `SessionResumed { missed_messages: Vec<ServerFrame> }` would allow a
    /// crafted payload to nest `SessionResumed` inside itself arbitrarily,
    /// enabling stack exhaustion during deserialization.
    SessionResumed {
        missed_messages: Vec<BufferedRelayedMessage>,
        last_acked_sequence: u64,
    },

    /// Server confirms successful claim (or reclaim).
    ClaimSuccess {
        /// The server's fingerprint for the host to pin.
        server_fingerprint: String,
        /// Confirmation message.
        message: String,
        /// Recovery key (hex-encoded, 64 chars). Shown to user ONCE.
        /// Must be saved securely — it's the only way to reclaim the server.
        recovery_key: String,
    },

    /// Server rejects claim attempt.
    ClaimRejected {
        /// Reason for rejection.
        reason: String,
    },

    /// Error frame.
    Error { code: u32, message: String },

    /// Server-initiated kick.
    Kicked { reason: String },

    /// Heartbeat pong.
    HeartbeatPong { timestamp: i64, server_time: i64 },

    /// Pool configuration changed -- broadcast to every member of the pool
    /// (host + all guests) whenever a tracked flag transitions.
    PoolConfigUpdated(PoolConfigUpdatedData),

    // ── Tunnel control plane (Server -> Client) ───────────────────────
    /// Server's reply to a `TunnelDnsQuery`.
    TunnelDnsResponse(TunnelDnsResponseData),

    /// Server-initiated tunnel error (used both before any stream exists
    /// — e.g. binary frame referencing an unknown stream — and to report
    /// asynchronous failures of an open stream).
    TunnelError(TunnelErrorData),
}

/// Information about a connected peer, sent in pool membership updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub display_name: String,
    pub public_key: String,
    pub connected_at: i64,
}

/// Summary information about a pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolInfo {
    pub pool_id: Uuid,
    pub name: String,
    pub host_peer_id: String,
    pub max_peers: usize,
    pub current_peers: usize,
    /// Whether the host has opted in to providing tunnel exit. Reflects
    /// `Pool.tunnel_exit_enabled` at the moment this `PoolInfo` was built.
    pub tunnel_exit_enabled: bool,
}

/// Data payload for the `update_pool_config` client→server frame.
///
/// Each field is optional: `None` means "leave unchanged", `Some(_)`
/// means "set to this value". The current implementation only honours
/// `tunnel_exit_enabled`; additional flags can be added without breaking
/// the wire contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct UpdatePoolConfigData {
    /// If `Some`, change the flag to the given value. If `None`, leave unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_exit_enabled: Option<bool>,
    /// Session token issued at pool creation. Required for authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// Data payload for the `pool_config_updated` server→client broadcast.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct PoolConfigUpdatedData {
    /// The current (post-change) value of the host's tunnel-exit opt-in.
    pub tunnel_exit_enabled: bool,
    /// `true` when the change was triggered by an `UpdatePoolConfig` frame
    /// from the pool host. Reserved for future server-side changes (e.g.
    /// administrative overrides) which would set this field to `false`.
    pub updated_by_host: bool,
}

/// A non-recursive representation of a relayed message, used exclusively in
/// `SessionResumed::missed_messages`.
///
/// This type breaks the recursive `ServerFrame -> Vec<ServerFrame>` cycle that
/// existed when `SessionResumed` contained `Vec<ServerFrame>`. Only the fields
/// needed for replaying buffered messages are included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferedRelayedMessage {
    /// The opaque E2E encrypted payload.
    pub data: String,
    /// The peer that originally sent this message.
    pub from_peer_id: String,
    /// Monotonic sequence number for ordering and deduplication.
    pub sequence: u64,
    /// Unix timestamp (seconds) when the message was buffered.
    pub timestamp: i64,
}

/// Proof-of-work challenge issued by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallengeFrame {
    pub challenge: String,
    pub difficulty: u8,
    pub timestamp: i64,
}

/// Proof-of-work solution submitted by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowSolutionFrame {
    pub challenge: String,
    pub solution: String,
}

// ============================================================================
// Tunnel-exit gateway control plane
// ============================================================================
//
// The relay terminates tunnel streams on the *server* (this crate) and
// bridges bytes back over the WebSocket. The pool host plays no role in
// carrying tunnel traffic. See `crates/stealthos-server/src/tunnel/`.
//
// Hot-path data uses **binary** WebSocket frames (see the binary layout
// constants below). Control-plane frames (open/close/window/DNS/error)
// are JSON text frames and are the variants enumerated above.

/// Network protocol of a tunnel stream.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TunnelNetwork {
    /// Reliable, ordered byte stream over TCP.
    Tcp,
    /// Unreliable, unordered datagrams over UDP.
    Udp,
}

/// Destination of a tunnel-open request.
///
/// Hostnames are resolved server-side; `Ipv4` / `Ipv6` skip resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TunnelDestination {
    /// Resolve `host` to an IP, then connect to (`ip`, `port`).
    Hostname { host: String, port: u16 },
    /// Connect directly to a dotted-quad IPv4 address.
    Ipv4 { address: String, port: u16 },
    /// Connect directly to a canonical-hex IPv6 address.
    Ipv6 { address: String, port: u16 },
}

/// Reason a tunnel stream is being closed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// The peer (member) closed the stream cleanly.
    PeerClosed,
    /// The peer aborted the stream (RST equivalent).
    Aborted,
    /// The stream was idle for too long.
    IdleTimeout,
    /// The relay refused the open due to policy (config/CIDR/port deny).
    PolicyDenied,
    /// The destination address could not be reached or resolved.
    DestinationUnreachable,
    /// The destination actively refused the connection.
    ConnectionRefused,
    /// Connect or DNS lookup timed out.
    Timeout,
    /// Per-connection or global stream limit reached.
    StreamLimit,
    /// The peer sent a malformed binary frame or otherwise violated the protocol.
    ProtocolError,
}

/// DNS record type the client wants resolved.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordType {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    Aaaa,
    /// Canonical name (alias) record.
    Cname,
    /// Free-form text record.
    Txt,
}

/// DNS resolver error code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsErrorCode {
    /// The name does not exist (NXDOMAIN).
    NxDomain,
    /// The upstream resolver returned SERVFAIL.
    ServFail,
    /// Resolution timed out.
    Timeout,
    /// The query was denied by server policy (e.g. tunnel disabled).
    PolicyDenied,
    /// The query was malformed.
    ProtocolError,
}

/// Server-initiated tunnel error code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelErrorCode {
    /// The request was denied by policy.
    PolicyDenied,
    /// The destination could not be reached.
    DestinationUnreachable,
    /// The destination refused the connection.
    ConnectionRefused,
    /// Connect or operation timed out.
    Timeout,
    /// The peer violated the wire protocol.
    ProtocolError,
    /// A capacity limit was exhausted (per-connection / global / memory).
    ResourceExhausted,
}

/// Payload of `tunnel_open`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelOpenData {
    /// Stream identifier chosen by the member (unique within its connection).
    pub stream_id: u32,
    /// Where the relay should connect.
    pub destination: TunnelDestination,
    /// `tcp` or `udp`.
    pub network: TunnelNetwork,
    /// Initial credit (in bytes) the server has to send data to the member.
    pub initial_window: u32,
}

/// Payload of `tunnel_close`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelCloseData {
    pub stream_id: u32,
    pub reason: CloseReason,
}

/// Payload of `tunnel_window_update`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelWindowUpdateData {
    pub stream_id: u32,
    /// Additional credit (in bytes) the server may send to the member.
    pub additional_credit: u32,
}

/// Payload of `tunnel_dns_query`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelDnsQueryData {
    pub query_id: u32,
    pub name: String,
    /// Wire field is `"type"` (a Rust keyword); Rust field is `record_type`.
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
}

/// One DNS answer record in `TunnelDnsResponseData::answers`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    /// Wire field is `"type"`; Rust field is `record_type`.
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub ttl: u32,
    /// String value (dotted quad / canonical IPv6 / TXT contents / CNAME).
    pub value: String,
}

/// Payload describing a DNS resolver error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsError {
    pub code: DnsErrorCode,
    pub message: String,
}

/// Payload of `tunnel_dns_response`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelDnsResponseData {
    pub query_id: u32,
    /// Present on success. Mutually exclusive with `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers: Option<Vec<DnsAnswer>>,
    /// Present on failure. Mutually exclusive with `answers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<DnsError>,
}

/// Payload of `tunnel_error`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelErrorData {
    /// `Some` when the error is associated with a specific stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u32>,
    pub code: TunnelErrorCode,
    pub message: String,
}

// ── Binary tunnel frame layout (NOT JSON) ────────────────────────────
//
// Hot-path data rides on **binary** WebSocket frames. The first byte
// is the channel type:
//
//   0x00            reserved sentinel (reject)
//   0x01 TUNNEL_DATA   ordered TCP byte stream
//                       byte  0     = 0x01
//                       bytes 1..5  = stream_id (u32 BE)
//                       bytes 5..9  = sequence  (u32 BE)
//                       bytes 9..   = payload   (≤ 32 KiB)
//   0x02 TUNNEL_UDP    unordered UDP datagram
//                       byte  0     = 0x02
//                       bytes 1..5  = stream_id (u32 BE)
//                       bytes 5..   = payload   (single datagram)
//   0x03..=0x7F     reserved for future channels (reject)
//   0x80..=0xFF     reserved for future channels (reject)

/// Channel byte for the ordered TCP byte-stream channel.
pub const TUNNEL_DATA_CHANNEL: u8 = 0x01;
/// Channel byte for the unordered UDP datagram channel.
pub const TUNNEL_UDP_CHANNEL: u8 = 0x02;
/// Header length of a TUNNEL_DATA frame: 1-byte channel + 4-byte stream_id + 4-byte sequence.
pub const TUNNEL_DATA_HEADER_LEN: usize = 9;
/// Header length of a TUNNEL_UDP frame: 1-byte channel + 4-byte stream_id.
pub const TUNNEL_UDP_HEADER_LEN: usize = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_frame_round_trip() {
        let frame = ServerFrame::Forward {
            data: "dGVzdA==".into(),
            target_peer_ids: Some(vec!["peer-1".into()]),
            sequence: 42,
            session_token: None,
        };

        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");

        match parsed {
            ServerFrame::Forward { sequence, .. } => assert_eq!(sequence, 42),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn close_pool_round_trip() {
        let frame = ServerFrame::ClosePool {
            session_token: Some("test-token".into()),
        };
        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(parsed, ServerFrame::ClosePool { .. }));
    }

    #[test]
    fn session_resumed_round_trip() {
        let frame = ServerFrame::SessionResumed {
            missed_messages: vec![
                BufferedRelayedMessage {
                    data: "encrypted-payload-1".into(),
                    from_peer_id: "peer-a".into(),
                    sequence: 1,
                    timestamp: 1_700_000_000,
                },
                BufferedRelayedMessage {
                    data: "encrypted-payload-2".into(),
                    from_peer_id: "peer-b".into(),
                    sequence: 2,
                    timestamp: 1_700_000_001,
                },
            ],
            last_acked_sequence: 0,
        };

        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");

        match parsed {
            ServerFrame::SessionResumed {
                missed_messages,
                last_acked_sequence,
            } => {
                assert_eq!(missed_messages.len(), 2);
                assert_eq!(missed_messages[0].sequence, 1);
                assert_eq!(missed_messages[1].from_peer_id, "peer-b");
                assert_eq!(last_acked_sequence, 0);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn host_auth_round_trip() {
        let frame = ServerFrame::HostAuth {
            host_public_key: "base64key==".into(),
            timestamp: 1_700_000_000,
            signature: "sig==".into(),
            pool_id: Uuid::nil(),
            server_url: Some("wss://relay.example.com".into()),
            display_name: Some("MyHost".into()),
            nonce: "challenge-nonce-base64".into(),
            tunnel_exit_enabled: Some(true),
        };
        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::HostAuth {
                host_public_key,
                timestamp,
                pool_id,
                display_name,
                nonce,
                tunnel_exit_enabled,
                ..
            } => {
                assert_eq!(host_public_key, "base64key==");
                assert_eq!(timestamp, 1_700_000_000);
                assert_eq!(pool_id, Uuid::nil());
                assert_eq!(display_name, Some("MyHost".into()));
                assert_eq!(nonce, "challenge-nonce-base64");
                assert_eq!(tunnel_exit_enabled, Some(true));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn host_auth_without_nonce_rejected() {
        // HostAuth without nonce must fail to deserialize — nonce is required.
        let json = r#"{
            "frame_type": "host_auth",
            "data": {
                "host_public_key": "key==",
                "timestamp": 1700000000,
                "signature": "sig==",
                "pool_id": "00000000-0000-0000-0000-000000000000"
            }
        }"#;
        let result: Result<ServerFrame, _> = serde_json::from_str(json);
        assert!(result.is_err(), "HostAuth without nonce must be rejected");
    }

    #[test]
    fn auth_challenge_round_trip() {
        let frame = ServerFrame::AuthChallenge {
            nonce: "base64nonce==".into(),
        };
        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::AuthChallenge { nonce } => {
                assert_eq!(nonce, "base64nonce==");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn relayed_round_trip() {
        let frame = ServerFrame::Relayed {
            data: "encrypted-blob".into(),
            from_peer_id: "peer-xyz".into(),
            sequence: 99,
        };
        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::Relayed {
                data,
                from_peer_id,
                sequence,
            } => {
                assert_eq!(data, "encrypted-blob");
                assert_eq!(from_peer_id, "peer-xyz");
                assert_eq!(sequence, 99);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn error_frame_round_trip() {
        let frame = ServerFrame::Error {
            code: 4001,
            message: "not authorized".into(),
        };
        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::Error { code, message } => {
                assert_eq!(code, 4001);
                assert_eq!(message, "not authorized");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn heartbeat_round_trip() {
        let ping = ServerFrame::HeartbeatPing { timestamp: 12345 };
        let json = serde_json::to_string(&ping).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(
            parsed,
            ServerFrame::HeartbeatPing { timestamp: 12345 }
        ));

        let pong = ServerFrame::HeartbeatPong {
            timestamp: 12345,
            server_time: 12346,
        };
        let json = serde_json::to_string(&pong).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::HeartbeatPong {
                timestamp,
                server_time,
            } => {
                assert_eq!(timestamp, 12345);
                assert_eq!(server_time, 12346);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn ack_round_trip() {
        let frame = ServerFrame::Ack { sequence: 42 };
        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(parsed, ServerFrame::Ack { sequence: 42 }));
    }

    #[test]
    fn buffered_relayed_message_is_flat() {
        let msg = BufferedRelayedMessage {
            data: "payload".into(),
            from_peer_id: "sender".into(),
            sequence: 7,
            timestamp: 1_000_000,
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        let parsed: BufferedRelayedMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.data, "payload");
        assert_eq!(parsed.sequence, 7);
    }

    #[test]
    fn update_pool_config_serde_roundtrip() {
        // Some(true)
        let frame = ServerFrame::UpdatePoolConfig(UpdatePoolConfigData {
            tunnel_exit_enabled: Some(true),
            session_token: Some("tok".into()),
        });
        let json = serde_json::to_string(&frame).expect("serialize");
        assert!(json.contains("\"tunnel_exit_enabled\":true"));
        assert!(json.contains("\"session_token\":\"tok\""));
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::UpdatePoolConfig(data) => {
                assert_eq!(data.tunnel_exit_enabled, Some(true));
                assert_eq!(data.session_token.as_deref(), Some("tok"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        // Some(false)
        let frame = ServerFrame::UpdatePoolConfig(UpdatePoolConfigData {
            tunnel_exit_enabled: Some(false),
            session_token: Some("tok".into()),
        });
        let json = serde_json::to_string(&frame).expect("serialize");
        assert!(json.contains("\"tunnel_exit_enabled\":false"));
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::UpdatePoolConfig(data) => {
                assert_eq!(data.tunnel_exit_enabled, Some(false));
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        // None on both fields — should serialize without including them.
        let frame = ServerFrame::UpdatePoolConfig(UpdatePoolConfigData {
            tunnel_exit_enabled: None,
            session_token: None,
        });
        let json = serde_json::to_string(&frame).expect("serialize");
        assert!(
            !json.contains("tunnel_exit_enabled"),
            "None field must be skipped: {json}"
        );
        assert!(
            !json.contains("session_token"),
            "None field must be skipped: {json}"
        );
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::UpdatePoolConfig(data) => {
                assert_eq!(data.tunnel_exit_enabled, None);
                assert_eq!(data.session_token, None);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn pool_config_updated_serde_roundtrip() {
        for value in [true, false] {
            let frame = ServerFrame::PoolConfigUpdated(PoolConfigUpdatedData {
                tunnel_exit_enabled: value,
                updated_by_host: true,
            });
            let json = serde_json::to_string(&frame).expect("serialize");
            let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
            match parsed {
                ServerFrame::PoolConfigUpdated(data) => {
                    assert_eq!(data.tunnel_exit_enabled, value);
                    assert!(data.updated_by_host);
                }
                other => panic!("unexpected variant: {other:?}"),
            }
        }
    }

    #[test]
    fn host_auth_omits_tunnel_exit_enabled_when_none() {
        // When tunnel_exit_enabled is None it must be skipped during
        // serialization so legacy clients see no new field on the wire.
        let frame = ServerFrame::HostAuth {
            host_public_key: "k".into(),
            timestamp: 1,
            signature: "s".into(),
            pool_id: Uuid::nil(),
            server_url: None,
            display_name: None,
            nonce: "n".into(),
            tunnel_exit_enabled: None,
        };
        let json = serde_json::to_string(&frame).expect("serialize");
        assert!(
            !json.contains("tunnel_exit_enabled"),
            "tunnel_exit_enabled must be skipped when None: {json}"
        );
    }

    #[test]
    fn host_auth_accepts_legacy_payload_without_tunnel_exit_enabled() {
        // A legacy client that does not know about tunnel_exit_enabled
        // sends host_auth WITHOUT the field; the relay must accept it
        // and treat the missing field as None.
        let json = r#"{
            "frame_type": "host_auth",
            "data": {
                "host_public_key": "key==",
                "timestamp": 1700000000,
                "signature": "sig==",
                "pool_id": "00000000-0000-0000-0000-000000000000",
                "nonce": "nonce-b64"
            }
        }"#;
        let parsed: ServerFrame = serde_json::from_str(json).expect("legacy host_auth must parse");
        match parsed {
            ServerFrame::HostAuth {
                tunnel_exit_enabled,
                ..
            } => {
                assert_eq!(tunnel_exit_enabled, None);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    // ── Tunnel control plane ─────────────────────────────────────────

    #[test]
    fn tunnel_open_hostname_round_trip() {
        let frame = ServerFrame::TunnelOpen(TunnelOpenData {
            stream_id: 7,
            destination: TunnelDestination::Hostname {
                host: "example.com".into(),
                port: 443,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 65_536,
        });
        let json = serde_json::to_string(&frame).unwrap();
        // Wire field for the destination tag must be exactly `"kind":"hostname"`.
        assert!(json.contains(r#""kind":"hostname""#), "got: {json}");
        assert!(json.contains(r#""network":"tcp""#));
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerFrame::TunnelOpen(d) => {
                assert_eq!(d.stream_id, 7);
                assert_eq!(d.network, TunnelNetwork::Tcp);
                assert_eq!(d.initial_window, 65_536);
                assert_eq!(
                    d.destination,
                    TunnelDestination::Hostname {
                        host: "example.com".into(),
                        port: 443
                    }
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn tunnel_open_ipv4_and_ipv6_round_trip() {
        let v4 = ServerFrame::TunnelOpen(TunnelOpenData {
            stream_id: 1,
            destination: TunnelDestination::Ipv4 {
                address: "1.2.3.4".into(),
                port: 80,
            },
            network: TunnelNetwork::Udp,
            initial_window: 1024,
        });
        let json = serde_json::to_string(&v4).unwrap();
        assert!(json.contains(r#""kind":"ipv4""#), "got: {json}");
        assert!(json.contains(r#""network":"udp""#));
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ServerFrame::TunnelOpen(_)));

        let v6 = ServerFrame::TunnelOpen(TunnelOpenData {
            stream_id: 2,
            destination: TunnelDestination::Ipv6 {
                address: "2001:db8::1".into(),
                port: 443,
            },
            network: TunnelNetwork::Tcp,
            initial_window: 4096,
        });
        let json = serde_json::to_string(&v6).unwrap();
        assert!(json.contains(r#""kind":"ipv6""#), "got: {json}");
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ServerFrame::TunnelOpen(_)));
    }

    #[test]
    fn tunnel_close_reason_round_trip() {
        for reason in [
            CloseReason::PeerClosed,
            CloseReason::Aborted,
            CloseReason::IdleTimeout,
            CloseReason::PolicyDenied,
            CloseReason::DestinationUnreachable,
            CloseReason::ConnectionRefused,
            CloseReason::Timeout,
            CloseReason::StreamLimit,
            CloseReason::ProtocolError,
        ] {
            let frame = ServerFrame::TunnelClose(TunnelCloseData {
                stream_id: 11,
                reason,
            });
            let json = serde_json::to_string(&frame).unwrap();
            let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
            match parsed {
                ServerFrame::TunnelClose(d) => {
                    assert_eq!(d.stream_id, 11);
                    assert_eq!(d.reason, reason);
                }
                other => panic!("unexpected variant: {other:?}"),
            }
        }
    }

    #[test]
    fn tunnel_window_update_round_trip() {
        let frame = ServerFrame::TunnelWindowUpdate(TunnelWindowUpdateData {
            stream_id: 99,
            additional_credit: 32_768,
        });
        let json = serde_json::to_string(&frame).unwrap();
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerFrame::TunnelWindowUpdate(d) => {
                assert_eq!(d.stream_id, 99);
                assert_eq!(d.additional_credit, 32_768);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn tunnel_dns_query_uses_type_wire_field() {
        let frame = ServerFrame::TunnelDnsQuery(TunnelDnsQueryData {
            query_id: 5,
            name: "example.com".into(),
            record_type: DnsRecordType::Aaaa,
        });
        let json = serde_json::to_string(&frame).unwrap();
        // Critical: wire field MUST be `"type"`, not `"record_type"`.
        assert!(
            json.contains(r#""type":"aaaa""#),
            "wire form must use `\"type\"`: {json}"
        );
        assert!(!json.contains("record_type"), "rust field must not leak");
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerFrame::TunnelDnsQuery(d) => {
                assert_eq!(d.query_id, 5);
                assert_eq!(d.name, "example.com");
                assert_eq!(d.record_type, DnsRecordType::Aaaa);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn tunnel_dns_response_round_trip() {
        let success = ServerFrame::TunnelDnsResponse(TunnelDnsResponseData {
            query_id: 1,
            answers: Some(vec![DnsAnswer {
                name: "example.com".into(),
                record_type: DnsRecordType::A,
                ttl: 300,
                value: "1.2.3.4".into(),
            }]),
            error: None,
        });
        let json = serde_json::to_string(&success).unwrap();
        // Each answer must use `"type"` as the wire field.
        assert!(json.contains(r#""type":"a""#), "got: {json}");
        // Absent error must be skipped.
        assert!(!json.contains(r#""error""#), "got: {json}");
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ServerFrame::TunnelDnsResponse(_)));

        let failure = ServerFrame::TunnelDnsResponse(TunnelDnsResponseData {
            query_id: 2,
            answers: None,
            error: Some(DnsError {
                code: DnsErrorCode::NxDomain,
                message: "no such host".into(),
            }),
        });
        let json = serde_json::to_string(&failure).unwrap();
        assert!(json.contains(r#""code":"nx_domain""#), "got: {json}");
        // Absent answers must be skipped.
        assert!(!json.contains(r#""answers""#), "got: {json}");
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ServerFrame::TunnelDnsResponse(_)));
    }

    #[test]
    fn tunnel_error_round_trip() {
        let with_stream = ServerFrame::TunnelError(TunnelErrorData {
            stream_id: Some(42),
            code: TunnelErrorCode::PolicyDenied,
            message: "destination is in deny list".into(),
        });
        let json = serde_json::to_string(&with_stream).unwrap();
        assert!(json.contains(r#""code":"policy_denied""#));
        assert!(json.contains(r#""stream_id":42"#));
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ServerFrame::TunnelError(_)));

        let without_stream = ServerFrame::TunnelError(TunnelErrorData {
            stream_id: None,
            code: TunnelErrorCode::ProtocolError,
            message: "binary frame too short".into(),
        });
        let json = serde_json::to_string(&without_stream).unwrap();
        // None stream_id must be skipped.
        assert!(!json.contains(r#""stream_id""#), "got: {json}");
        let parsed: ServerFrame = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ServerFrame::TunnelError(_)));
    }

    /// Verify that `SessionResumed` cannot contain nested `ServerFrame` values.
    /// The `BufferedRelayedMessage` type is a flat struct with no recursive references.
    #[test]
    fn session_resumed_is_not_recursive() {
        // Attempt to deserialize a payload that tries to nest SessionResumed
        // inside missed_messages. Since missed_messages is now
        // Vec<BufferedRelayedMessage>, this should fail to parse.
        let malicious = r#"{
            "frame_type": "session_resumed",
            "data": {
                "missed_messages": [{
                    "frame_type": "session_resumed",
                    "data": {
                        "missed_messages": [],
                        "last_acked_sequence": 0
                    }
                }],
                "last_acked_sequence": 0
            }
        }"#;

        let result: Result<ServerFrame, _> = serde_json::from_str(malicious);
        assert!(result.is_err(), "recursive nesting must be rejected");
    }
}
