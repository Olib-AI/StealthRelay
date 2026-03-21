use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Strongly-typed peer identifier (wraps String, derived from device UUID).
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl AsRef<str> for PeerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Strongly-typed pool identifier.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct PoolId(pub Uuid);

impl fmt::Display for PoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for PoolId {
    fn from(u: Uuid) -> Self {
        Self(u)
    }
}

/// Connection identifier (internal, per-WebSocket).
///
/// Assigned by the server on each new WebSocket connection.
/// Uses a global atomic counter to guarantee uniqueness within a process lifetime.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct ConnectionId(pub u64);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conn-{}", self.0)
    }
}

/// Global atomic counter for generating unique `ConnectionId` values.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

impl ConnectionId {
    /// Generate a new unique `ConnectionId`.
    ///
    /// Uses `SeqCst` ordering for visibility guarantees across threads and
    /// saturates at `u64::MAX - 1` to prevent wraparound. If the counter
    /// is exhausted (requires ~585 thousand years at 1M IDs/sec), returns
    /// `u64::MAX - 1` repeatedly (safe but prevents new unique IDs).
    pub fn next() -> Self {
        // Saturating increment: if we are at the ceiling, stay there.
        // This prevents wraparound to 0 which could reuse old ConnectionIds.
        loop {
            let current = NEXT_CONNECTION_ID.load(Ordering::SeqCst);
            if current >= u64::MAX - 1 {
                return Self(current);
            }
            match NEXT_CONNECTION_ID.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(prev) => return Self(prev),
                Err(_) => continue, // CAS failed, retry
            }
        }
    }
}
