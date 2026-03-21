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
        };
        let json = serde_json::to_string(&frame).expect("serialize");
        let parsed: ServerFrame = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ServerFrame::HostAuth {
                host_public_key,
                timestamp,
                pool_id,
                display_name,
                ..
            } => {
                assert_eq!(host_public_key, "base64key==");
                assert_eq!(timestamp, 1_700_000_000);
                assert_eq!(pool_id, Uuid::nil());
                assert_eq!(display_name, Some("MyHost".into()));
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
        let ping = ServerFrame::HeartbeatPing {
            timestamp: 12345,
        };
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
