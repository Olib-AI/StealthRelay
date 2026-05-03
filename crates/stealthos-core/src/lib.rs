#![forbid(unsafe_code)]

pub mod error;
pub mod message;
pub mod pool;
pub mod pool_registry;
pub mod ratelimit;
pub mod router;
pub mod server_frame;
pub mod types;

pub use error::{PoolError, RateLimitError};
pub use message::{MessageType, PoolMessage};
pub use pool::{BufferedMessage, Pool, PoolPeer, TokenCommitmentRecord};
pub use pool_registry::PoolRegistry;
pub use ratelimit::{ConnectionThrottler, IpRateLimiter, RateLimitConfig, TokenBucket};
pub use router::{RouteResult, Router};
pub use server_frame::{
    BufferedRelayedMessage, CloseReason, DnsAnswer, DnsError, DnsErrorCode, DnsRecordType,
    PeerInfo, PoolConfigUpdatedData, PoolInfo, PowChallengeFrame, PowSolutionFrame, ServerFrame,
    TUNNEL_DATA_CHANNEL, TUNNEL_DATA_HEADER_LEN, TUNNEL_UDP_CHANNEL, TUNNEL_UDP_HEADER_LEN,
    TunnelCloseData, TunnelDestination, TunnelDnsQueryData, TunnelDnsResponseData, TunnelErrorCode,
    TunnelErrorData, TunnelNetwork, TunnelOpenData, TunnelWindowUpdateData, UpdatePoolConfigData,
};
pub use types::{ConnectionId, PeerId, PoolId};
