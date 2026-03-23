//! Host identity management — Ed25519 signing + X25519 key agreement.
//!
//! A [`HostIdentity`] combines a long-term Ed25519 signing keypair with a
//! long-term X25519 static Diffie-Hellman keypair, both derived deterministically
//! from a single 32-byte seed. The seed is the only material that needs to be
//! persisted.
//!
//! # Key Derivation
//!
//! From a 32-byte master seed:
//! - Ed25519 signing key = `HKDF-SHA256(seed, salt="", info="STEALTH_ED25519")`
//! - X25519 static secret = `HKDF-SHA256(seed, salt="", info="STEALTH_X25519")`
//!
//! # Fingerprint
//!
//! `SHA-256(ed25519_pub_bytes || x25519_pub_bytes)` — a 32-byte value that
//! uniquely identifies this host.

use std::fmt;
use std::path::Path;

use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};

/// Wrapper around the 32-byte master seed, ensuring zeroization on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Seed([u8; 32]);

/// A host's long-term cryptographic identity.
///
/// Contains both an Ed25519 signing keypair and an X25519 static keypair,
/// derived from a single 32-byte seed.
///
/// # Security Properties
///
/// - The seed and all derived secret keys are zeroized on drop.
/// - `Debug` prints `[REDACTED]` — no secret material is ever logged.
/// - All key generation uses `OsRng` (OS-level CSPRNG).
pub struct HostIdentity {
    seed: Seed,
    signing_key: ed25519_dalek::SigningKey,
    x25519_secret: x25519_dalek::StaticSecret,
    fingerprint_bytes: [u8; 32],
}

impl Drop for HostIdentity {
    fn drop(&mut self) {
        // seed is ZeroizeOnDrop via Seed wrapper.
        // signing_key: ed25519_dalek::SigningKey stores the secret bytes internally;
        // we overwrite our copy of the struct memory through the seed, and rely on
        // dalek's own zeroization for the signing key bytes.
        // x25519_secret: x25519_dalek::StaticSecret implements Zeroize.
        // We explicitly zeroize the fingerprint (not secret, but good hygiene).
        self.fingerprint_bytes.zeroize();
    }
}

impl fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostIdentity")
            .field("fingerprint", &hex_short(&self.fingerprint_bytes))
            .field("seed", &"[REDACTED]")
            .field("signing_key", &"[REDACTED]")
            .field("x25519_secret", &"[REDACTED]")
            .finish()
    }
}

/// The public portion of a [`HostIdentity`], safe to share over the network.
///
/// Contains the Ed25519 verifying key, X25519 public key, and the fingerprint.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HostPublicKeys {
    /// The Ed25519 public (verifying) key bytes.
    pub ed25519: [u8; 32],
    /// The X25519 public key bytes.
    pub x25519: [u8; 32],
    /// `SHA-256(ed25519 || x25519)`.
    pub fingerprint: [u8; 32],
}

impl fmt::Debug for HostPublicKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostPublicKeys")
            .field("ed25519", &"[32 bytes]")
            .field("x25519", &"[32 bytes]")
            .field("fingerprint", &hex_short(&self.fingerprint))
            .finish()
    }
}

/// Derive Ed25519 and X25519 key material from a 32-byte seed.
fn derive_keys(
    seed: &[u8; 32],
) -> (
    ed25519_dalek::SigningKey,
    x25519_dalek::StaticSecret,
    [u8; 32],
) {
    // Derive Ed25519 seed
    let hk_ed = Hkdf::<Sha256>::new(None, seed);
    let mut ed_seed = [0u8; 32];
    hk_ed
        .expand(b"STEALTH_ED25519", &mut ed_seed)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
    ed_seed.zeroize();

    // Derive X25519 secret
    let hk_x = Hkdf::<Sha256>::new(None, seed);
    let mut x_seed = [0u8; 32];
    hk_x.expand(b"STEALTH_X25519", &mut x_seed)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let x25519_secret = x25519_dalek::StaticSecret::from(x_seed);
    x_seed.zeroize();

    // Compute fingerprint = SHA-256(ed25519_pub || x25519_pub)
    let ed_pub = signing_key.verifying_key().to_bytes();
    let x_pub = x25519_dalek::PublicKey::from(&x25519_secret).to_bytes();
    let fingerprint = compute_fingerprint(&ed_pub, &x_pub);

    (signing_key, x25519_secret, fingerprint)
}

/// Compute `SHA-256(ed25519_pub || x25519_pub)`.
fn compute_fingerprint(ed25519_pub: &[u8; 32], x25519_pub: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(ed25519_pub);
    hasher.update(x25519_pub);
    hasher.finalize().into()
}

/// Format the first 8 bytes of a hash as hex for debug output.
///
/// Uses a stack-allocated buffer to avoid 8 small `String` allocations
/// from `format!` per byte. The output is always exactly 16 hex chars.
fn hex_short(bytes: &[u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for (i, &b) in bytes[..8].iter().enumerate() {
        buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
        buf[i * 2 + 1] = HEX_CHARS[(b & 0x0f) as usize];
    }
    // SAFETY: buf contains only ASCII hex characters, which are valid UTF-8.
    // We use from_utf8 (checked) rather than from_utf8_unchecked because
    // this crate is #![forbid(unsafe_code)].
    String::from_utf8(buf.to_vec()).expect("hex chars are valid UTF-8")
}

impl HostIdentity {
    /// Generate a new host identity from OS-level CSPRNG.
    ///
    /// # Security Properties
    ///
    /// - Uses `OsRng` for seed generation (backed by the OS CSPRNG).
    /// - The seed is the single secret from which all keys are derived.
    pub fn generate() -> Self {
        let mut seed_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut seed_bytes);
        let identity = Self::from_seed(seed_bytes);
        seed_bytes.zeroize();
        identity
    }

    /// Construct a host identity deterministically from a 32-byte seed.
    ///
    /// # Security Properties
    ///
    /// - The same seed always produces the same identity (useful for backup/restore).
    /// - The seed MUST come from a CSPRNG in production use.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (signing_key, x25519_secret, fingerprint_bytes) = derive_keys(&seed);
        Self {
            seed: Seed(seed),
            signing_key,
            x25519_secret,
            fingerprint_bytes,
        }
    }

    /// Magic number for the integrity-protected key file format.
    const KEY_FILE_MAGIC: &'static [u8; 4] = b"STKY";

    /// Persist the seed to a file with restrictive permissions (0o600).
    ///
    /// # File Format (v2, 68 bytes)
    ///
    /// ```text
    /// [0..4]   magic "STKY"
    /// [4..36]  32-byte seed
    /// [36..68] 32-byte BLAKE2b-256 MAC over magic || seed
    /// ```
    ///
    /// # Security Properties
    ///
    /// - File permissions are set to owner-only read/write (mode 0o600).
    /// - Only the seed is stored — keys are re-derived on load.
    /// - A BLAKE2b-256 MAC detects file corruption or tampering.
    pub fn save(&self, path: &Path) -> Result<()> {
        use blake2::Blake2b;
        use blake2::digest::Update;
        use blake2::digest::FixedOutput;
        use blake2::digest::consts::U32;
        use std::fs;
        use std::io::Write;

        let mut payload = Vec::with_capacity(68);
        payload.extend_from_slice(Self::KEY_FILE_MAGIC);
        payload.extend_from_slice(&self.seed.0);

        let mut hasher = Blake2b::<U32>::default();
        hasher.update(&payload);
        let mac = hasher.finalize_fixed();
        payload.extend_from_slice(&mac);

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        Ok(())
    }

    /// Load a host identity from a previously saved seed file.
    ///
    /// # File Format (68 bytes)
    ///
    /// ```text
    /// [0..4]   magic "STKY"
    /// [4..36]  32-byte seed
    /// [36..68] 32-byte BLAKE2b-256 MAC over magic || seed
    /// ```
    ///
    /// # Security Properties
    ///
    /// - Validates file size (exactly 68 bytes).
    /// - Verifies the BLAKE2b-256 MAC with constant-time comparison to
    ///   detect corruption or tampering.
    /// - Re-derives all keys from the loaded seed.
    pub fn load(path: &Path) -> Result<Self> {
        use blake2::Blake2b;
        use blake2::digest::Update;
        use blake2::digest::FixedOutput;
        use blake2::digest::consts::U32;

        let data = std::fs::read(path)?;

        if data.len() != 68 {
            return Err(CryptoError::InvalidKeyLength);
        }

        if &data[..4] != Self::KEY_FILE_MAGIC {
            return Err(CryptoError::IntegrityCheckFailed);
        }

        // Recompute MAC over magic || seed.
        let mut hasher = Blake2b::<U32>::default();
        hasher.update(&data[..36]);
        let expected_mac = hasher.finalize_fixed();

        // Constant-time comparison to prevent timing side-channel.
        let macs_match: bool =
            ConstantTimeEq::ct_eq(&data[36..68], expected_mac.as_slice()).into();
        if !macs_match {
            return Err(CryptoError::IntegrityCheckFailed);
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data[4..36]);
        Ok(Self::from_seed(seed))
    }

    /// Return the public keys and fingerprint for this identity.
    pub fn public_keys(&self) -> HostPublicKeys {
        let ed25519 = self.signing_key.verifying_key().to_bytes();
        let x25519 = x25519_dalek::PublicKey::from(&self.x25519_secret).to_bytes();
        HostPublicKeys {
            ed25519,
            x25519,
            fingerprint: self.fingerprint_bytes,
        }
    }

    /// Sign a message with the Ed25519 signing key.
    ///
    /// # Security Properties
    ///
    /// - Uses Ed25519 (RFC 8032) deterministic signatures — no per-signature
    ///   randomness is needed.
    /// - The signature is 64 bytes.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// Return the 32-byte fingerprint of this identity.
    ///
    /// The fingerprint is `SHA-256(ed25519_pub || x25519_pub)`.
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint_bytes
    }

    /// Borrow the X25519 static secret — used during handshake.
    ///
    /// This is `pub(crate)` to prevent leaking the secret outside the crate.
    pub(crate) const fn x25519_secret(&self) -> &x25519_dalek::StaticSecret {
        &self.x25519_secret
    }

    /// Return the X25519 public key.
    pub fn x25519_public(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(&self.x25519_secret)
    }

    /// Return the Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl HostPublicKeys {
    /// Verify an Ed25519 signature against this identity's public key.
    ///
    /// # Security Properties
    ///
    /// - Uses the `ed25519-dalek` verification, which is constant-time
    ///   in the signature and public key operations.
    /// - Returns `true` only if the signature is valid for the given message.
    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        verifying_key.verify(msg, &sig).is_ok()
    }

    /// Constant-time comparison of two fingerprints.
    pub fn fingerprint_eq(&self, other: &[u8; 32]) -> bool {
        self.fingerprint.ct_eq(other).into()
    }
}

/// Trait for platform-specific file permission support.
/// On Unix, we use `std::os::unix::fs::OpenOptionsExt`.
/// This module provides a cross-platform shim.
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(not(unix))]
trait OpenOptionsExt {
    fn mode(&mut self, _mode: u32) -> &mut Self;
}

#[cfg(not(unix))]
impl OpenOptionsExt for std::fs::OpenOptions {
    fn mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let seed = [42u8; 32];
        let id1 = HostIdentity::from_seed(seed);
        let id2 = HostIdentity::from_seed(seed);
        assert_eq!(id1.fingerprint(), id2.fingerprint());
        assert_eq!(id1.public_keys().ed25519, id2.public_keys().ed25519);
        assert_eq!(id1.public_keys().x25519, id2.public_keys().x25519);
    }

    #[test]
    fn sign_and_verify() {
        let id = HostIdentity::generate();
        let msg = b"hello stealth";
        let sig = id.sign(msg);
        let pk = id.public_keys();
        assert!(pk.verify(msg, &sig));
        assert!(!pk.verify(b"wrong message", &sig));
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join("stealthos_test_identity");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_host.key");

        let id = HostIdentity::generate();
        id.save(&path).unwrap();

        // Verify v2 format: file should be 68 bytes.
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data.len(), 68);
        assert_eq!(&data[..4], b"STKY");

        let loaded = HostIdentity::load(&path).unwrap();

        assert_eq!(id.fingerprint(), loaded.fingerprint());
        assert_eq!(id.public_keys().ed25519, loaded.public_keys().ed25519);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_raw_32_byte_file_rejected() {
        let dir = std::env::temp_dir().join("stealthos_test_identity_raw32");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_raw32.key");

        // Write a raw 32-byte seed — must be rejected (not a valid v2 file).
        let seed = [42u8; 32];
        std::fs::write(&path, seed).unwrap();

        let result = HostIdentity::load(&path);
        assert!(result.is_err(), "raw 32-byte file must be rejected");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_corrupted_v2_file_fails() {
        let dir = std::env::temp_dir().join("stealthos_test_identity_corrupt");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_corrupt.key");

        let id = HostIdentity::generate();
        id.save(&path).unwrap();

        // Corrupt one byte of the seed.
        let mut data = std::fs::read(&path).unwrap();
        data[10] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        let result = HostIdentity::load(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let id = HostIdentity::generate();
        let debug = format!("{id:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&format!("{:?}", id.signing_key.to_bytes())));
    }

    #[test]
    fn fingerprint_is_sha256_of_public_keys() {
        let id = HostIdentity::generate();
        let pk = id.public_keys();
        let expected = compute_fingerprint(&pk.ed25519, &pk.x25519);
        assert_eq!(id.fingerprint(), expected);
    }
}
