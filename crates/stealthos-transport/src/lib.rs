#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)] // Allow e.g. `TransportError` in `error` module

//! # stealthos-transport
//!
//! WebSocket transport layer for the StealthOS Relay Server.
//!
//! Provides a per-connection actor model with bounded backpressure,
//! heartbeat/idle detection, and slow-consumer eviction. The transport
//! layer is protocol-agnostic — it passes raw text frames to the
//! application layer without parsing.

pub mod config;
pub mod connection;
pub mod connection_registry;
pub mod error;
pub mod listener;
pub mod server;
pub mod types;

pub use config::TransportConfig;
pub use connection::{ConnectionActor, ConnectionActorParams, ConnectionEvent, OutboundMessage};
pub use connection_registry::{ConnectionHandle, ConnectionRegistry};
pub use error::TransportError;
pub use listener::WebSocketListener;
pub use server::{ShutdownHandle, TransportServer};
pub use types::{ConnectionId, PeerId, PoolId};
