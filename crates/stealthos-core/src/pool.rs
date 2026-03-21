use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};

use base64ct::Encoding as _;
use dashmap::DashMap;
use tokio::time::Instant;

use crate::error::PoolError;
use crate::server_frame::PeerInfo;
use crate::types::{ConnectionId, PeerId, PoolId};

/// Maximum number of messages buffered per disconnected peer for session resumption.
const MAX_BUFFERED_MESSAGES: usize = 100;

/// A relay pool: one host plus zero or more guest peers.
pub struct Pool {
    pub id: PoolId,
    pub name: String,
    pub host_connection_id: ConnectionId,
    pub host_peer_id: PeerId,
    pub host_public_key: [u8; 32],
    pub host_display_name: String,
    pub max_peers: usize,
    pub created_at: Instant,
    peers: DashMap<PeerId, PoolPeer>,
    invitation_commitments: DashMap<[u8; 16], TokenCommitmentRecord>,
    message_buffer: DashMap<PeerId, VecDeque<BufferedMessage>>,
}

/// A peer that has joined a pool.
pub struct PoolPeer {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub display_name: String,
    pub public_key: [u8; 32],
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub last_acked_sequence: u64,
}

/// Record tracking a token commitment for invitation verification.
pub struct TokenCommitmentRecord {
    pub commitment: [u8; 32],
    pub expires_at: i64,
    pub max_uses: u8,
    pub use_count: AtomicU8,
    pub created_at: Instant,
}

/// A message buffered for a temporarily disconnected peer.
pub struct BufferedMessage {
    pub data: Vec<u8>,
    pub from_peer_id: PeerId,
    pub sequence: u64,
    pub timestamp: Instant,
}

impl Pool {
    /// Create a new pool.
    pub fn new(
        id: PoolId,
        name: String,
        host_connection_id: ConnectionId,
        host_peer_id: PeerId,
        host_public_key: [u8; 32],
        host_display_name: String,
        max_peers: usize,
    ) -> Self {
        Self {
            id,
            name,
            host_connection_id,
            host_peer_id,
            host_public_key,
            host_display_name,
            max_peers,
            created_at: Instant::now(),
            peers: DashMap::new(),
            invitation_commitments: DashMap::new(),
            message_buffer: DashMap::new(),
        }
    }

    /// Add a peer to the pool. Fails if the pool is at capacity or the peer
    /// is already present.
    ///
    /// Uses `DashMap::entry()` for atomic check-and-insert, preventing a
    /// TOCTOU race where two concurrent `JoinApproval` frames for the same
    /// peer_id could both pass a `contains_key` check and insert, with the
    /// second silently overwriting the first.
    pub fn add_peer(&self, peer: PoolPeer) -> Result<(), PoolError> {
        // Count includes the host, so available guest slots = max_peers - 1 - current_guests.
        let current = self.peers.len();
        if current + 1 >= self.max_peers {
            return Err(PoolError::PoolFull(current + 1, self.max_peers));
        }

        let peer_id = peer.peer_id.clone();

        // Atomic check-and-insert: only insert if the peer_id does not exist.
        match self.peers.entry(peer_id.clone()) {
            dashmap::mapref::entry::Entry::Occupied(_) => Err(PoolError::DuplicatePeer(peer_id)),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(peer);
                Ok(())
            }
        }
    }

    /// Remove a peer from the pool by ID, returning the peer if found.
    pub fn remove_peer(&self, peer_id: &PeerId) -> Option<PoolPeer> {
        self.peers.remove(peer_id).map(|(_, peer)| peer)
    }

    /// Get a snapshot of a peer's state.
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<PoolPeer> {
        self.peers.get(peer_id).map(|entry| {
            let p = entry.value();
            PoolPeer {
                peer_id: p.peer_id.clone(),
                connection_id: p.connection_id,
                display_name: p.display_name.clone(),
                public_key: p.public_key,
                connected_at: p.connected_at,
                last_activity: p.last_activity,
                last_acked_sequence: p.last_acked_sequence,
            }
        })
    }

    /// List all peers in the pool as `PeerInfo` (including the host).
    pub fn peers(&self) -> Vec<PeerInfo> {
        let mut infos = Vec::with_capacity(self.peers.len() + 1);

        // Include the host as a peer.
        infos.push(PeerInfo {
            peer_id: self.host_peer_id.0.clone(),
            display_name: self.host_display_name.clone(),
            public_key: base64ct::Base64::encode_string(&self.host_public_key),
            connected_at: 0, // host has been connected since pool creation
        });

        for entry in &self.peers {
            let p = entry.value();
            infos.push(PeerInfo {
                peer_id: p.peer_id.0.clone(),
                display_name: p.display_name.clone(),
                public_key: base64ct::Base64::encode_string(&p.public_key),
                connected_at: p
                    .connected_at
                    .duration_since(self.created_at)
                    .as_secs()
                    .try_into()
                    .unwrap_or(i64::MAX),
            });
        }

        infos
    }

    /// Number of peers in the pool (excluding the host).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Check whether the given connection is the pool host.
    pub fn is_host(&self, connection_id: ConnectionId) -> bool {
        self.host_connection_id == connection_id
    }

    /// Register an invitation token commitment.
    pub fn add_invitation_commitment(
        &self,
        token_id: [u8; 16],
        commitment: [u8; 32],
        expires_at: i64,
        max_uses: u8,
    ) {
        self.invitation_commitments.insert(
            token_id,
            TokenCommitmentRecord {
                commitment,
                expires_at,
                max_uses,
                use_count: AtomicU8::new(0),
                created_at: Instant::now(),
            },
        );
    }

    /// Atomically try to consume one use of an invitation.
    ///
    /// Uses compare-and-swap on the atomic use counter so that concurrent
    /// join attempts cannot exceed `max_uses`.
    pub fn try_consume_invitation(&self, token_id: &[u8; 16]) -> Result<(), PoolError> {
        let record = self
            .invitation_commitments
            .get(token_id)
            .ok_or(PoolError::InvitationNotFound)?;

        let now_unix = chrono::Utc::now().timestamp();
        if now_unix > record.expires_at {
            return Err(PoolError::InvitationExpired);
        }

        loop {
            let current = record.use_count.load(Ordering::Acquire);
            if current >= record.max_uses {
                return Err(PoolError::InvitationExhausted);
            }
            match record.use_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue, // CAS failed, retry
            }
        }
    }

    /// Revoke an invitation by token ID. Returns `true` if the invitation existed.
    pub fn revoke_invitation(&self, token_id: &[u8; 16]) -> bool {
        self.invitation_commitments.remove(token_id).is_some()
    }

    /// Remove all expired invitation commitments.
    pub fn cleanup_expired_invitations(&self) {
        let now_unix = chrono::Utc::now().timestamp();
        self.invitation_commitments
            .retain(|_, record| record.expires_at > now_unix);
    }

    /// Maximum number of distinct peer IDs that can have message buffers.
    ///
    /// Prevents an attacker from exhausting memory by targeting arbitrary
    /// non-existent peer IDs, each of which would create a new buffer entry.
    const MAX_BUFFER_PEERS: usize = 256;

    /// Buffer a message for a disconnected peer (for session resumption).
    ///
    /// Caps the buffer at `MAX_BUFFERED_MESSAGES` per peer, dropping the
    /// oldest messages when full. Also caps the total number of buffered
    /// peer IDs at `MAX_BUFFER_PEERS` to prevent memory exhaustion from
    /// targeted sends to arbitrary non-existent peer IDs.
    ///
    /// Uses `VecDeque` so that evicting the oldest message is O(1) via
    /// `pop_front`, rather than O(n) from `Vec::remove(0)` which shifts
    /// all remaining elements.
    pub fn buffer_message(&self, peer_id: &PeerId, message: BufferedMessage) {
        // Only buffer if the peer_id already has an entry OR we haven't
        // exceeded the per-pool buffer peer limit.
        if !self.message_buffer.contains_key(peer_id)
            && self.message_buffer.len() >= Self::MAX_BUFFER_PEERS
        {
            // Silently drop -- we cannot buffer for more peers.
            return;
        }

        let mut entry = self.message_buffer.entry(peer_id.clone()).or_default();
        let buf = entry.value_mut();
        if buf.len() >= MAX_BUFFERED_MESSAGES {
            buf.pop_front();
        }
        buf.push_back(message);
    }

    /// Drain buffered messages for a peer that have not yet been acknowledged
    /// (used on session resumption).
    ///
    /// Only returns messages with `sequence > last_acked_sequence` for this
    /// peer, ensuring that already-acknowledged messages are not replayed.
    /// The entire buffer entry is removed after filtering.
    pub fn drain_buffer(&self, peer_id: &PeerId) -> Vec<BufferedMessage> {
        let last_acked = self
            .peers
            .get(peer_id)
            .map(|p| p.last_acked_sequence)
            .unwrap_or(0);

        self.message_buffer
            .remove(peer_id)
            .map(|(_, buf)| {
                buf.into_iter()
                    .filter(|msg| msg.sequence > last_acked)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update a peer's last acknowledged sequence number.
    ///
    /// Only advances the sequence forward (prevents rollback from a stale
    /// or replayed ack). Returns `true` if the value was updated, `false`
    /// if the provided sequence was not greater than the current value or
    /// the peer was not found.
    pub fn update_last_acked_sequence(&self, peer_id: &PeerId, sequence: u64) -> bool {
        if let Some(mut peer) = self
            .peers
            .get_mut(peer_id)
            .filter(|p| sequence > p.last_acked_sequence)
        {
            peer.last_acked_sequence = sequence;
            return true;
        }
        false
    }

    /// Prune buffered messages for a peer that have been acknowledged.
    ///
    /// Removes all buffered messages with `sequence <= acked_sequence`,
    /// freeing memory for messages the peer has confirmed receipt of.
    pub fn prune_buffer(&self, peer_id: &PeerId, acked_sequence: u64) {
        if let Some(mut entry) = self.message_buffer.get_mut(peer_id) {
            let buf = entry.value_mut();
            buf.retain(|msg| msg.sequence > acked_sequence);
            // If the buffer is now empty, we leave the entry in place.
            // It will be cleaned up on the next drain_buffer call or
            // when the peer disconnects.
        }
    }

    /// Return an iterator over all guest `ConnectionId`s (excluding the host).
    pub fn guest_connection_ids(&self) -> Vec<(PeerId, ConnectionId)> {
        self.peers
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().connection_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PoolId;
    use uuid::Uuid;

    fn make_pool() -> Pool {
        Pool::new(
            PoolId(Uuid::nil()),
            "test".into(),
            ConnectionId(1),
            PeerId("host".into()),
            [0u8; 32],
            "TestHost".into(),
            4,
        )
    }

    fn make_peer(id: &str, conn: u64) -> PoolPeer {
        PoolPeer {
            peer_id: PeerId(id.into()),
            connection_id: ConnectionId(conn),
            display_name: id.into(),
            public_key: [0u8; 32],
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_acked_sequence: 0,
        }
    }

    #[test]
    fn add_and_remove_peer() {
        let pool = make_pool();
        pool.add_peer(make_peer("p1", 10)).unwrap();
        assert_eq!(pool.peer_count(), 1);

        let removed = pool.remove_peer(&PeerId("p1".into()));
        assert!(removed.is_some());
        assert_eq!(pool.peer_count(), 0);
    }

    #[test]
    fn pool_full_error() {
        let pool = make_pool(); // max_peers = 4 (1 host + 3 guests)
        pool.add_peer(make_peer("p1", 10)).unwrap();
        pool.add_peer(make_peer("p2", 11)).unwrap();
        pool.add_peer(make_peer("p3", 12)).unwrap();

        let result = pool.add_peer(make_peer("p4", 13));
        assert!(matches!(result, Err(PoolError::PoolFull(_, _))));
    }

    #[test]
    fn duplicate_peer_error() {
        let pool = make_pool();
        pool.add_peer(make_peer("p1", 10)).unwrap();

        let result = pool.add_peer(make_peer("p1", 11));
        assert!(matches!(result, Err(PoolError::DuplicatePeer(_))));
    }

    #[test]
    fn is_host_check() {
        let pool = make_pool();
        assert!(pool.is_host(ConnectionId(1)));
        assert!(!pool.is_host(ConnectionId(99)));
    }

    #[test]
    fn buffer_and_drain() {
        let pool = make_pool();
        let peer = PeerId("p1".into());

        // Add peer to pool so drain_buffer can look up last_acked_sequence.
        pool.add_peer(make_peer("p1", 10)).unwrap();

        for i in 1..=5u8 {
            pool.buffer_message(
                &peer,
                BufferedMessage {
                    data: vec![i],
                    from_peer_id: PeerId("sender".into()),
                    sequence: u64::from(i),
                    timestamp: Instant::now(),
                },
            );
        }

        let msgs = pool.drain_buffer(&peer);
        assert_eq!(msgs.len(), 5);
        // Second drain should be empty.
        assert!(pool.drain_buffer(&peer).is_empty());
    }

    #[test]
    fn buffer_caps_at_max() {
        let pool = make_pool();
        let peer = PeerId("p1".into());

        // Add peer to pool so drain_buffer can look up last_acked_sequence.
        pool.add_peer(make_peer("p1", 10)).unwrap();

        for i in 1..=150u64 {
            pool.buffer_message(
                &peer,
                BufferedMessage {
                    data: vec![],
                    from_peer_id: PeerId("s".into()),
                    sequence: i,
                    timestamp: Instant::now(),
                },
            );
        }

        let msgs = pool.drain_buffer(&peer);
        assert_eq!(msgs.len(), MAX_BUFFERED_MESSAGES);
        // The oldest 50 messages should have been dropped (sequences 1-50).
        assert_eq!(msgs[0].sequence, 51);
    }

    #[test]
    fn drain_buffer_respects_last_acked() {
        let pool = make_pool();
        let peer = PeerId("p1".into());
        pool.add_peer(make_peer("p1", 10)).unwrap();

        // Buffer messages with sequences 1-10.
        for i in 1..=10u64 {
            pool.buffer_message(
                &peer,
                BufferedMessage {
                    data: vec![],
                    from_peer_id: PeerId("s".into()),
                    sequence: i,
                    timestamp: Instant::now(),
                },
            );
        }

        // Ack through sequence 7.
        assert!(pool.update_last_acked_sequence(&peer, 7));

        // Drain should only return messages 8, 9, 10.
        let msgs = pool.drain_buffer(&peer);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].sequence, 8);
        assert_eq!(msgs[2].sequence, 10);
    }

    #[test]
    fn update_last_acked_sequence_only_advances() {
        let pool = make_pool();
        pool.add_peer(make_peer("p1", 10)).unwrap();
        let peer = PeerId("p1".into());

        // Advance to 5.
        assert!(pool.update_last_acked_sequence(&peer, 5));
        // Verify the value.
        let p = pool.get_peer(&peer).unwrap();
        assert_eq!(p.last_acked_sequence, 5);

        // Attempt rollback to 3 -- should be rejected.
        assert!(!pool.update_last_acked_sequence(&peer, 3));
        let p = pool.get_peer(&peer).unwrap();
        assert_eq!(p.last_acked_sequence, 5);

        // Same value -- should also be rejected (not strictly greater).
        assert!(!pool.update_last_acked_sequence(&peer, 5));

        // Advance to 10 -- should succeed.
        assert!(pool.update_last_acked_sequence(&peer, 10));
        let p = pool.get_peer(&peer).unwrap();
        assert_eq!(p.last_acked_sequence, 10);
    }

    #[test]
    fn prune_buffer_removes_acked_messages() {
        let pool = make_pool();
        let peer = PeerId("p1".into());
        pool.add_peer(make_peer("p1", 10)).unwrap();

        for i in 1..=5u64 {
            pool.buffer_message(
                &peer,
                BufferedMessage {
                    data: vec![],
                    from_peer_id: PeerId("s".into()),
                    sequence: i,
                    timestamp: Instant::now(),
                },
            );
        }

        // Prune messages with sequence <= 3.
        pool.prune_buffer(&peer, 3);

        // Update ack so drain won't filter further.
        pool.update_last_acked_sequence(&peer, 0);

        let msgs = pool.drain_buffer(&peer);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].sequence, 4);
        assert_eq!(msgs[1].sequence, 5);
    }

    #[test]
    fn remove_nonexistent_peer_returns_none() {
        let pool = make_pool();
        assert!(pool.remove_peer(&PeerId("ghost".into())).is_none());
    }

    #[test]
    fn get_peer_returns_snapshot() {
        let pool = make_pool();
        pool.add_peer(make_peer("p1", 10)).unwrap();

        let snap = pool.get_peer(&PeerId("p1".into()));
        assert!(snap.is_some());
        let snap = snap.unwrap();
        assert_eq!(snap.peer_id, PeerId("p1".into()));
        assert_eq!(snap.connection_id, ConnectionId(10));
    }

    #[test]
    fn get_nonexistent_peer_returns_none() {
        let pool = make_pool();
        assert!(pool.get_peer(&PeerId("missing".into())).is_none());
    }

    #[test]
    fn peers_includes_host() {
        let pool = make_pool();
        pool.add_peer(make_peer("p1", 10)).unwrap();

        let peer_list = pool.peers();
        // Should include host + p1 = 2.
        assert_eq!(peer_list.len(), 2);

        let host_info = peer_list.iter().find(|p| p.peer_id == "host");
        assert!(host_info.is_some());
        assert_eq!(host_info.unwrap().display_name, "TestHost");
    }

    #[test]
    fn guest_connection_ids_excludes_host() {
        let pool = make_pool();
        pool.add_peer(make_peer("p1", 10)).unwrap();
        pool.add_peer(make_peer("p2", 11)).unwrap();

        let guests = pool.guest_connection_ids();
        assert_eq!(guests.len(), 2);
        let ids: Vec<u64> = guests.iter().map(|(_, c)| c.0).collect();
        assert!(!ids.contains(&1)); // host connection not included
    }

    #[test]
    fn buffer_message_for_unknown_peer_respects_max_buffer_peers() {
        let pool = make_pool();

        // Fill up to MAX_BUFFER_PEERS distinct peer buffers.
        for i in 0..Pool::MAX_BUFFER_PEERS {
            let peer = PeerId(format!("peer-{i}"));
            pool.buffer_message(
                &peer,
                BufferedMessage {
                    data: vec![],
                    from_peer_id: PeerId("s".into()),
                    sequence: 1,
                    timestamp: Instant::now(),
                },
            );
        }

        // One more distinct peer should be silently dropped.
        let overflow_peer = PeerId("overflow-peer".into());
        pool.buffer_message(
            &overflow_peer,
            BufferedMessage {
                data: vec![1],
                from_peer_id: PeerId("s".into()),
                sequence: 1,
                timestamp: Instant::now(),
            },
        );

        let msgs = pool.drain_buffer(&overflow_peer);
        assert!(msgs.is_empty(), "overflow peer buffer should be empty");
    }

    #[test]
    fn invitation_commitment_lifecycle() {
        let pool = make_pool();
        let token_id = [1u8; 16];
        let commitment = [2u8; 32];
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        pool.add_invitation_commitment(token_id, commitment, expires_at, 3);

        // Consume one use.
        assert!(pool.try_consume_invitation(&token_id).is_ok());
        assert!(pool.try_consume_invitation(&token_id).is_ok());
        assert!(pool.try_consume_invitation(&token_id).is_ok());

        // Fourth should fail (max_uses = 3).
        assert!(matches!(
            pool.try_consume_invitation(&token_id),
            Err(PoolError::InvitationExhausted)
        ));
    }

    #[test]
    fn invitation_not_found() {
        let pool = make_pool();
        let missing = [99u8; 16];
        assert!(matches!(
            pool.try_consume_invitation(&missing),
            Err(PoolError::InvitationNotFound)
        ));
    }

    #[test]
    fn revoke_invitation() {
        let pool = make_pool();
        let token_id = [5u8; 16];
        pool.add_invitation_commitment(
            token_id,
            [0u8; 32],
            chrono::Utc::now().timestamp() + 3600,
            1,
        );

        assert!(pool.revoke_invitation(&token_id));
        assert!(!pool.revoke_invitation(&token_id)); // already revoked
        assert!(matches!(
            pool.try_consume_invitation(&token_id),
            Err(PoolError::InvitationNotFound)
        ));
    }
}
