use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::DashMap;

use crate::error::PoolError;
use crate::pool::Pool;
use crate::types::{ConnectionId, PeerId, PoolId};

/// Global registry of all active pools on this relay server.
pub struct PoolRegistry {
    pools: DashMap<PoolId, Arc<Pool>>,
    connection_to_pool: DashMap<ConnectionId, (PoolId, PeerId)>,
    max_pools: usize,
    /// Atomic counter tracking the number of pools. Incremented before
    /// insertion and decremented on failure or removal, ensuring the
    /// capacity check is race-free (no TOCTOU between `len()` and `insert`).
    pool_count: AtomicUsize,
}

impl PoolRegistry {
    /// Create a new registry with a maximum pool capacity.
    pub fn new(max_pools: usize) -> Self {
        Self {
            pools: DashMap::new(),
            connection_to_pool: DashMap::new(),
            max_pools,
            pool_count: AtomicUsize::new(0),
        }
    }

    /// Create a new pool and register it.
    ///
    /// Uses an `AtomicUsize` counter for the capacity check, incremented
    /// **before** the `DashMap::entry()` insert and decremented on any
    /// failure path. This eliminates the TOCTOU race where two concurrent
    /// requests could both pass a `DashMap::len()` check and exceed the
    /// pool limit.
    ///
    /// The `entry()` API is still used for the duplicate-ID check, ensuring
    /// that two requests with the same `pool_id` cannot both insert.
    ///
    /// Fails with `MaxPoolsReached` if the registry is at capacity.
    /// Fails with `PoolAlreadyExists` if a pool with the given ID already exists.
    pub fn create_pool(
        &self,
        id: PoolId,
        name: String,
        host_connection_id: ConnectionId,
        host_peer_id: PeerId,
        host_public_key: [u8; 32],
        host_display_name: String,
        max_peers: usize,
    ) -> Result<Arc<Pool>, PoolError> {
        // Atomically reserve a slot. If the counter is already at the limit,
        // no slot is reserved and we return an error immediately.
        loop {
            let current = self.pool_count.load(Ordering::Acquire);
            if current >= self.max_pools {
                return Err(PoolError::MaxPoolsReached(self.max_pools));
            }
            // Try to claim one slot with CAS.
            if self
                .pool_count
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
            // CAS failed (contention), retry.
        }

        // Slot reserved. If any subsequent step fails, we must release it.

        let pool = Arc::new(Pool::new(
            id,
            name,
            host_connection_id,
            host_peer_id.clone(),
            host_public_key,
            host_display_name,
            max_peers,
        ));

        // Atomic check-and-insert: only insert if the key does not exist.
        let entry = self.pools.entry(id);
        match entry {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                // Release the reserved slot -- pool was not actually created.
                self.pool_count.fetch_sub(1, Ordering::AcqRel);
                return Err(PoolError::PoolAlreadyExists(id));
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(Arc::clone(&pool));
            }
        }

        self.connection_to_pool
            .insert(host_connection_id, (id, host_peer_id));

        Ok(pool)
    }

    /// Look up a pool by ID.
    pub fn get_pool(&self, pool_id: PoolId) -> Option<Arc<Pool>> {
        self.pools
            .get(&pool_id)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Remove a pool entirely.
    pub fn remove_pool(&self, pool_id: PoolId) {
        if self.pools.remove(&pool_id).is_some() {
            self.pool_count.fetch_sub(1, Ordering::AcqRel);
        }
        // Clean up all connection mappings pointing to this pool.
        self.connection_to_pool
            .retain(|_, (pid, _)| *pid != pool_id);
    }

    /// Register a connection as belonging to a pool with a specific peer identity.
    pub fn register_connection(
        &self,
        connection_id: ConnectionId,
        pool_id: PoolId,
        peer_id: PeerId,
    ) {
        self.connection_to_pool
            .insert(connection_id, (pool_id, peer_id));
    }

    /// Unregister a connection, returning the pool ID and peer ID it was associated with.
    pub fn unregister_connection(&self, connection_id: ConnectionId) -> Option<(PoolId, PeerId)> {
        self.connection_to_pool
            .remove(&connection_id)
            .map(|(_, v)| v)
    }

    /// Return the `PeerId` associated with a connection, if any.
    ///
    /// This is an O(1) DashMap lookup -- no iteration required.
    pub fn get_peer_id_for_connection(&self, connection_id: ConnectionId) -> Option<PeerId> {
        self.connection_to_pool
            .get(&connection_id)
            .map(|entry| entry.value().1.clone())
    }

    /// Find which pool a connection belongs to.
    pub fn get_pool_for_connection(&self, connection_id: ConnectionId) -> Option<Arc<Pool>> {
        self.connection_to_pool
            .get(&connection_id)
            .and_then(|entry| {
                let (pool_id, _) = entry.value();
                self.pools.get(pool_id).map(|p| Arc::clone(p.value()))
            })
    }

    /// Number of active pools (uses the atomic counter, not `DashMap::len()`).
    pub fn pool_count(&self) -> usize {
        self.pool_count.load(Ordering::Acquire)
    }

    /// Remove pools that have had no guest peers for longer than `max_idle`.
    ///
    /// A pool is considered idle if it has zero guest peers and has existed
    /// for longer than `max_idle`. The host connection is cleaned up as well.
    pub fn cleanup_idle_pools(&self, max_idle: Duration) {
        let now = tokio::time::Instant::now();
        let mut to_remove = Vec::new();

        for entry in &self.pools {
            let pool = entry.value();
            if pool.peer_count() == 0 && now.duration_since(pool.created_at) > max_idle {
                to_remove.push(*entry.key());
            }
        }

        for pool_id in to_remove {
            self.remove_pool(pool_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn create_and_get_pool() {
        let registry = PoolRegistry::new(10);
        let pool_id = PoolId(Uuid::nil());

        let pool = registry
            .create_pool(
                pool_id,
                "test".into(),
                ConnectionId(1),
                PeerId("host".into()),
                [0u8; 32],
                "TestHost".into(),
                8,
            )
            .unwrap();

        assert_eq!(pool.id, pool_id);
        assert!(registry.get_pool(pool_id).is_some());
        assert_eq!(registry.pool_count(), 1);
    }

    #[test]
    fn max_pools_reached() {
        let registry = PoolRegistry::new(1);

        registry
            .create_pool(
                PoolId(Uuid::from_u128(1)),
                "pool1".into(),
                ConnectionId(1),
                PeerId("h1".into()),
                [0u8; 32],
                "TestHost".into(),
                4,
            )
            .unwrap();

        let result = registry.create_pool(
            PoolId(Uuid::from_u128(2)),
            "pool2".into(),
            ConnectionId(2),
            PeerId("h2".into()),
            [0u8; 32],
            "TestHost2".into(),
            4,
        );

        assert!(matches!(result, Err(PoolError::MaxPoolsReached(1))));
    }

    #[test]
    fn connection_mapping() {
        let registry = PoolRegistry::new(10);
        let pool_id = PoolId(Uuid::nil());
        let conn = ConnectionId(1);

        registry
            .create_pool(
                pool_id,
                "test".into(),
                conn,
                PeerId("host".into()),
                [0u8; 32],
                "TestHost".into(),
                4,
            )
            .unwrap();

        assert!(registry.get_pool_for_connection(conn).is_some());

        let guest_conn = ConnectionId(2);
        registry.register_connection(guest_conn, pool_id, PeerId("guest".into()));
        assert!(registry.get_pool_for_connection(guest_conn).is_some());

        let removed = registry.unregister_connection(guest_conn);
        assert!(removed.is_some());
        assert!(registry.get_pool_for_connection(guest_conn).is_none());
    }

    #[test]
    fn remove_pool_cleans_connections() {
        let registry = PoolRegistry::new(10);
        let pool_id = PoolId(Uuid::nil());
        let host_conn = ConnectionId(1);

        registry
            .create_pool(
                pool_id,
                "test".into(),
                host_conn,
                PeerId("host".into()),
                [0u8; 32],
                "TestHost".into(),
                4,
            )
            .unwrap();

        let guest_conn = ConnectionId(2);
        registry.register_connection(guest_conn, pool_id, PeerId("guest".into()));

        registry.remove_pool(pool_id);

        assert!(registry.get_pool(pool_id).is_none());
        assert!(registry.get_pool_for_connection(host_conn).is_none());
        assert!(registry.get_pool_for_connection(guest_conn).is_none());
        assert_eq!(registry.pool_count(), 0);
    }
}
