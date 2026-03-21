//! # stealthos-observability
//!
//! Observability layer for the `StealthOS` Relay Server: structured logging,
//! atomic metrics counters, and health-check HTTP endpoints.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

pub mod health;
pub mod logging;
pub mod metrics;

pub use health::{HealthState, health_router};
pub use logging::{LogConfig, LogFormat, init_logging};
pub use metrics::ServerMetrics;
