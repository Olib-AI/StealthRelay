use tokio::time::Instant;

use crate::pool::{BufferedMessage, Pool};
use crate::server_frame::ServerFrame;
use crate::types::{ConnectionId, PeerId};

/// Result of routing a `Forward` frame.
///
/// Contains a single `ServerFrame` and the list of `ConnectionId`s that
/// should receive it. The caller serializes the frame once and sends the
/// same JSON bytes to every recipient, avoiding N redundant serializations
/// AND N redundant String allocations for the data/from_peer_id fields.
pub struct RouteResult {
    /// The `Relayed` frame to deliver. Only one copy is constructed.
    pub frame: ServerFrame,
    /// Connection IDs that should receive this frame.
    pub recipients: Vec<ConnectionId>,
}

/// Stateless message router.
///
/// Given a pool and a forward request, produces a single `ServerFrame` and
/// the list of `ConnectionId`s that should receive it. The caller serializes
/// the frame once and reuses the JSON string for all recipients.
pub struct Router;

impl Router {
    /// Route a `Forward` frame from `sender_peer_id` to the appropriate recipients.
    ///
    /// Returns `None` if there are no online recipients (messages to offline
    /// peers are buffered internally for session resumption).
    ///
    /// # Performance
    ///
    /// Only one `ServerFrame` is allocated regardless of recipient count.
    /// Previous versions created N copies of the data `String` (one per
    /// recipient), which was wasteful since the handler pre-serializes the
    /// frame and clones the JSON string instead.
    pub fn route(
        pool: &Pool,
        sender_peer_id: &PeerId,
        sender_connection_id: ConnectionId,
        data: &str,
        target_peer_ids: Option<&[String]>,
        sequence: u64,
    ) -> Option<RouteResult> {
        let recipients = match target_peer_ids {
            None => Self::broadcast_recipients(pool, sender_peer_id, sender_connection_id),
            Some(targets) => {
                Self::targeted_recipients(pool, sender_peer_id, data, targets, sequence)
            }
        };

        if recipients.is_empty() {
            return None;
        }

        // Construct exactly ONE Relayed frame for all recipients.
        let frame = ServerFrame::Relayed {
            data: data.to_owned(),
            from_peer_id: sender_peer_id.0.clone(),
            sequence,
        };

        Some(RouteResult { frame, recipients })
    }

    /// Collect broadcast recipients (all connected peers except the sender).
    fn broadcast_recipients(
        pool: &Pool,
        sender_peer_id: &PeerId,
        sender_connection_id: ConnectionId,
    ) -> Vec<ConnectionId> {
        let mut recipients = Vec::new();

        // Deliver to the host if the sender is not the host.
        if pool.host_connection_id != sender_connection_id {
            recipients.push(pool.host_connection_id);
        }

        // Deliver to all guest peers except the sender.
        for (peer_id, conn_id) in pool.guest_connection_ids() {
            if peer_id != *sender_peer_id {
                recipients.push(conn_id);
            }
        }

        recipients
    }

    /// Collect targeted recipients, buffering messages for offline peers.
    fn targeted_recipients(
        pool: &Pool,
        sender_peer_id: &PeerId,
        data: &str,
        targets: &[String],
        sequence: u64,
    ) -> Vec<ConnectionId> {
        let mut recipients = Vec::new();

        for target_id_str in targets {
            let target_peer_id = PeerId(target_id_str.clone());

            // Check if target is the host.
            if pool.host_peer_id == target_peer_id {
                recipients.push(pool.host_connection_id);
                continue;
            }

            // Check if target is a connected guest.
            match pool.get_peer(&target_peer_id) {
                Some(peer) => {
                    recipients.push(peer.connection_id);
                }
                None => {
                    // Peer not currently connected -- buffer for session resumption.
                    pool.buffer_message(
                        &target_peer_id,
                        BufferedMessage {
                            data: data.as_bytes().to_vec(),
                            from_peer_id: sender_peer_id.clone(),
                            sequence,
                            timestamp: Instant::now(),
                        },
                    );
                }
            }
        }

        recipients
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{Pool, PoolPeer};
    use crate::types::{ConnectionId, PeerId, PoolId};
    use tokio::time::Instant;
    use uuid::Uuid;

    fn make_pool_with_peers() -> Pool {
        let pool = Pool::new(
            PoolId(Uuid::nil()),
            "test".into(),
            ConnectionId(1),
            PeerId("host".into()),
            [0u8; 32],
            "TestHost".into(),
            10,
        );

        pool.add_peer(PoolPeer {
            peer_id: PeerId("p1".into()),
            connection_id: ConnectionId(10),
            display_name: "Peer1".into(),
            public_key: [0u8; 32],
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_acked_sequence: 0,
        })
        .unwrap();

        pool.add_peer(PoolPeer {
            peer_id: PeerId("p2".into()),
            connection_id: ConnectionId(11),
            display_name: "Peer2".into(),
            public_key: [0u8; 32],
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_acked_sequence: 0,
        })
        .unwrap();

        pool
    }

    #[test]
    fn broadcast_excludes_sender() {
        let pool = make_pool_with_peers();
        let result = Router::route(
            &pool,
            &PeerId("p1".into()),
            ConnectionId(10),
            "data",
            None,
            1,
        );

        // Should deliver to host (conn 1) and p2 (conn 11), not p1 (conn 10).
        let result = result.expect("should have recipients");
        assert_eq!(result.recipients.len(), 2);
        let conn_ids: Vec<u64> = result.recipients.iter().map(|c| c.0).collect();
        assert!(conn_ids.contains(&1));
        assert!(conn_ids.contains(&11));
        assert!(!conn_ids.contains(&10));
    }

    #[test]
    fn targeted_delivery() {
        let pool = make_pool_with_peers();
        let result = Router::route(
            &pool,
            &PeerId("host".into()),
            ConnectionId(1),
            "data",
            Some(&["p2".into()]),
            1,
        );

        let result = result.expect("should have recipients");
        assert_eq!(result.recipients.len(), 1);
        assert_eq!(result.recipients[0], ConnectionId(11));
    }

    #[test]
    fn targeted_buffers_for_missing_peer() {
        let pool = make_pool_with_peers();
        let result = Router::route(
            &pool,
            &PeerId("host".into()),
            ConnectionId(1),
            "data",
            Some(&["nonexistent".into()]),
            42,
        );

        // No online recipients (peer is offline), but message should be buffered.
        assert!(result.is_none());

        let buffered = pool.drain_buffer(&PeerId("nonexistent".into()));
        assert_eq!(buffered.len(), 1);
        assert_eq!(buffered[0].sequence, 42);
    }

    #[test]
    fn broadcast_from_host_excludes_host() {
        let pool = make_pool_with_peers();
        let result = Router::route(
            &pool,
            &PeerId("host".into()),
            ConnectionId(1),
            "broadcast",
            None,
            1,
        );

        let result = result.expect("should have recipients");
        // Host broadcasts to p1 (10) and p2 (11), not to itself (1).
        assert_eq!(result.recipients.len(), 2);
        let conn_ids: Vec<u64> = result.recipients.iter().map(|c| c.0).collect();
        assert!(!conn_ids.contains(&1));
        assert!(conn_ids.contains(&10));
        assert!(conn_ids.contains(&11));
    }

    #[test]
    fn targeted_to_host() {
        let pool = make_pool_with_peers();
        let result = Router::route(
            &pool,
            &PeerId("p1".into()),
            ConnectionId(10),
            "to host",
            Some(&["host".into()]),
            5,
        );

        let result = result.expect("should have host as recipient");
        assert_eq!(result.recipients.len(), 1);
        assert_eq!(result.recipients[0], ConnectionId(1));
    }

    #[test]
    fn targeted_mixed_online_and_offline() {
        let pool = make_pool_with_peers();
        let result = Router::route(
            &pool,
            &PeerId("host".into()),
            ConnectionId(1),
            "mixed",
            Some(&["p1".into(), "offline-peer".into()]),
            10,
        );

        // p1 is online (conn 10), offline-peer is buffered.
        let result = result.expect("should have at least p1");
        assert_eq!(result.recipients.len(), 1);
        assert_eq!(result.recipients[0], ConnectionId(10));

        // Verify offline-peer got buffered.
        let buffered = pool.drain_buffer(&PeerId("offline-peer".into()));
        assert_eq!(buffered.len(), 1);
        assert_eq!(buffered[0].sequence, 10);
    }

    #[test]
    fn route_returns_none_with_no_peers() {
        let pool = Pool::new(
            PoolId(Uuid::nil()),
            "empty".into(),
            ConnectionId(1),
            PeerId("host".into()),
            [0u8; 32],
            "Host".into(),
            10,
        );

        // Host broadcasts with no guests -- should return None.
        let result = Router::route(
            &pool,
            &PeerId("host".into()),
            ConnectionId(1),
            "lonely",
            None,
            1,
        );
        assert!(result.is_none());
    }
}
