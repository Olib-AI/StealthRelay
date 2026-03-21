//! StealthOS Relay Server — library entry point.
//!
//! This crate is primarily a binary (`stealth-relay`). The library target
//! re-exports modules needed by integration tests and downstream tooling.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

pub mod config;
