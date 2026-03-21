//! Peer identity — lightweight Ed25519 signing for relay clients.
//!
//! Unlike [`crate::identity::HostIdentity`], a peer identity only needs a
//! signing keypair (no static X25519). Peers prove their identity by signing
//! challenge messages during handshake and message exchanges.

use std::fmt;

use ed25519_dalek::{Signer, Verifier};
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// CryptoError and Result are available via crate::error if needed in future expansions.

/// Wrapper for the 32-byte signing key seed, ensuring zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
struct PeerSeed([u8; 32]);

/// A peer's Ed25519 signing identity.
///
/// # Security Properties
///
/// - The signing key seed is zeroized on drop.
/// - `Debug` prints `[REDACTED]`.
/// - All generation uses `OsRng`.
pub struct PeerIdentity {
    _seed: PeerSeed,
    signing_key: ed25519_dalek::SigningKey,
}

impl Drop for PeerIdentity {
    fn drop(&mut self) {
        // _seed handles its own zeroization via ZeroizeOnDrop.
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerIdentity")
            .field("public_key", &hex::encode(self.public_key()))
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

/// The public half of a [`PeerIdentity`], used for signature verification.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerPublicKey {
    /// The Ed25519 verifying key bytes.
    pub bytes: [u8; 32],
}

impl fmt::Debug for PeerPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerPublicKey")
            .field("bytes", &hex::encode(self.bytes))
            .finish()
    }
}

/// Minimal hex encoder for debug output (avoids pulling in the `hex` crate).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        use std::fmt::Write;
        let bytes = bytes.as_ref();
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    }
}

impl PeerIdentity {
    /// Generate a new peer identity from OS-level CSPRNG.
    ///
    /// # Security Properties
    ///
    /// - Uses `OsRng` for key generation.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let identity = Self {
            _seed: PeerSeed(seed),
            signing_key,
        };
        seed.zeroize();
        identity
    }

    /// Return the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Return the public key as a [`PeerPublicKey`] struct.
    pub fn public(&self) -> PeerPublicKey {
        PeerPublicKey {
            bytes: self.public_key(),
        }
    }

    /// Sign a message with the Ed25519 signing key.
    ///
    /// # Security Properties
    ///
    /// - Deterministic Ed25519 signature (RFC 8032).
    /// - Returns a 64-byte signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }
}

impl PeerPublicKey {
    /// Verify an Ed25519 signature against this public key.
    ///
    /// # Security Properties
    ///
    /// - Uses `ed25519-dalek` constant-time verification.
    /// - Returns `true` only if the signature is valid.
    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&self.bytes) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        verifying_key.verify(msg, &sig).is_ok()
    }

    /// Construct from raw 32-byte public key.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Constant-time comparison of two public keys.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl From<[u8; 32]> for PeerPublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_verify() {
        let peer = PeerIdentity::generate();
        let msg = b"peer auth message";
        let sig = peer.sign(msg);
        let pk = peer.public();
        assert!(pk.verify(msg, &sig));
        assert!(!pk.verify(b"tampered", &sig));
    }

    #[test]
    fn debug_redacts_secrets() {
        let peer = PeerIdentity::generate();
        let debug = format!("{peer:?}");
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn public_key_roundtrip() {
        let peer = PeerIdentity::generate();
        let pk_bytes = peer.public_key();
        let pk = PeerPublicKey::from_bytes(pk_bytes);
        let msg = b"roundtrip test";
        let sig = peer.sign(msg);
        assert!(pk.verify(msg, &sig));
    }
}
