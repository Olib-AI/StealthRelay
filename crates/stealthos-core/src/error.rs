use std::net::IpAddr;

use crate::types::{PeerId, PoolId};

/// Errors arising from pool operations.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("pool is full ({0}/{1})")]
    PoolFull(usize, usize),

    #[error("pool not found: {0}")]
    PoolNotFound(PoolId),

    #[error("peer not found: {0}")]
    PeerNotFound(PeerId),

    #[error("not authorized: {0}")]
    NotAuthorized(String),

    #[error("invitation exhausted")]
    InvitationExhausted,

    #[error("invitation expired")]
    InvitationExpired,

    #[error("invitation not found")]
    InvitationNotFound,

    #[error("max pools reached ({0})")]
    MaxPoolsReached(usize),

    #[error("duplicate peer: {0}")]
    DuplicatePeer(PeerId),

    #[error("pool already exists: {0}")]
    PoolAlreadyExists(PoolId),
}

/// Errors arising from rate-limiting decisions.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("rate limit exceeded for {0}")]
    RateLimitExceeded(IpAddr),

    #[error("IP blocked until {0}")]
    IpBlocked(String),

    #[error("global rate limit exceeded")]
    GlobalRateLimitExceeded,
}
