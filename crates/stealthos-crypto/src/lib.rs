//! # `StealthOS` Crypto
//!
//! Cryptographic primitives for the `StealthOS` relay server. This crate provides:
//!
//! - **Host identity** — Ed25519 signing + X25519 key agreement, with
//!   fingerprinting and persistent seed storage.
//! - **Peer identity** — Lightweight Ed25519 signing for relay clients.
//! - **Key exchange** — Noise NK-inspired handshake producing session keys.
//! - **Session encryption** — ChaCha20-Poly1305 AEAD with monotonic nonces,
//!   anti-replay sliding window, and automatic symmetric ratcheting.
//! - **Invitation tokens** — Capability-based join tokens with HKDF-derived
//!   commitments and HMAC-based join proofs.
//! - **Proof of work** — BLAKE2b-based hashcash for rate limiting.
//!
//! # Security Guarantees
//!
//! - `#![forbid(unsafe_code)]` — no unsafe blocks anywhere in this crate.
//! - All secret key material implements `Zeroize + ZeroizeOnDrop`.
//! - All secret comparisons use constant-time operations (`subtle`).
//! - `Debug` implementations on secret-bearing types print `[REDACTED]`.
//! - Nonces are never reused — enforced by monotonic counters.
//! - All randomness sourced from `OsRng` (CSPRNG).

#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

pub mod envelope;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod invitation;
pub mod peer_identity;
pub mod pow;
mod serde_helpers;

pub use envelope::{SealedEnvelope, SessionCipher};
pub use error::{CryptoError, Result};
pub use handshake::{HandshakeInitiator, HandshakeMessage, HandshakeResponder, SessionKeys};
pub use identity::{HostIdentity, HostPublicKeys};
pub use invitation::{InvitationToken, JoinProof, TokenCommitment};
pub use peer_identity::{PeerIdentity, PeerPublicKey};
pub use pow::{PowChallenge, PowSolution};
