//! Cryptographic error types for StealthOS.
//!
//! All error variants are designed to avoid leaking secret material.
//! Error messages are intentionally vague about *which* key or *what* value
//! failed to prevent oracle attacks.

use std::fmt;

/// Unified error type for all cryptographic operations in the StealthOS relay.
///
/// # Security Properties
///
/// - No error variant contains secret key material.
/// - Error messages are generic enough to prevent distinguishing attacks
///   (e.g., "decryption failed" does not reveal whether the key, nonce, or
///   tag was wrong).
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The provided key, nonce, or seed has an incorrect length.
    #[error("invalid key length")]
    InvalidKeyLength,

    /// An Ed25519 signature did not verify against the public key and message.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// AEAD decryption failed — the ciphertext was tampered with, the key is
    /// wrong, or the nonce/AAD mismatch.
    #[error("decryption failed")]
    DecryptionFailed,

    /// The message counter has already been seen within the sliding window,
    /// indicating a potential replay attack.
    #[error("replay detected: counter {0} already seen")]
    ReplayDetected(u64),

    /// The message counter falls below the sliding window base, meaning it is
    /// too old to be accepted.
    #[error("counter too old: {0} < window base {1}")]
    CounterTooOld(u64, u64),

    /// The nonce counter has reached its maximum safe value. The session must
    /// be terminated and re-established to prevent nonce reuse.
    #[error("nonce counter exhausted — session must be re-established")]
    CounterExhausted,

    /// The key-exchange handshake failed at a protocol level.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// The invitation token has passed its `expires_at` timestamp.
    #[error("invitation expired")]
    InvitationExpired,

    /// The invitation token is structurally invalid or fails verification.
    #[error("invitation invalid: {0}")]
    InvitationInvalid(String),

    /// The proof-of-work solution does not satisfy the required difficulty.
    #[error("proof of work failed")]
    PowFailed,

    /// An underlying I/O error occurred (e.g., reading/writing identity files).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, CryptoError>;

impl CryptoError {
    /// Construct a [`CryptoError::HandshakeFailed`] from any displayable value.
    pub fn handshake(msg: impl fmt::Display) -> Self {
        Self::HandshakeFailed(msg.to_string())
    }

    /// Construct a [`CryptoError::InvitationInvalid`] from any displayable value.
    pub fn invitation(msg: impl fmt::Display) -> Self {
        Self::InvitationInvalid(msg.to_string())
    }

    /// Construct a [`CryptoError::Serialization`] from any displayable value.
    pub fn serialization(msg: impl fmt::Display) -> Self {
        Self::Serialization(msg.to_string())
    }
}
