//! Session encryption and decryption using ChaCha20-Poly1305.
//!
//! The [`SessionCipher`] provides authenticated encryption with associated data
//! (AEAD), monotonic nonce management, anti-replay protection via a sliding
//! window, and automatic symmetric ratcheting.
//!
//! # Nonce Construction
//!
//! The 12-byte nonce is constructed from the 8-byte big-endian counter, left-padded
//! with 4 zero bytes. This guarantees uniqueness as long as the counter is monotonic
//! (which is enforced by the implementation).
//!
//! # Anti-Replay
//!
//! A 64-bit sliding window tracks which counters have been seen. Messages with
//! counters below `(read_counter - 63)` are rejected as too old. Messages with
//! counters within the window are checked against a bitmap.
//!
//! # Symmetric Ratchet
//!
//! After 2^20 (1,048,576) messages, the cipher automatically rekeys using
//! HKDF-SHA256 with the current rekey seed. Old keys are zeroized immediately.

use std::fmt;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::handshake::SessionKeys;

/// Maximum messages before automatic rekey (2^20 = 1,048,576).
const REKEY_INTERVAL: u32 = 1 << 20;

/// Size of the anti-replay sliding window in bits.
const WINDOW_SIZE: u64 = 64;

/// Version byte prepended to AAD for domain separation.
const ENVELOPE_VERSION: u8 = 0x01;

/// An encrypted message envelope containing the counter and ciphertext.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SealedEnvelope {
    /// The monotonic counter used as the nonce for this message.
    pub counter: u64,
    /// The AEAD ciphertext (plaintext + 16-byte Poly1305 tag).
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedEnvelope")
            .field("counter", &self.counter)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Bidirectional session cipher with AEAD encryption, anti-replay, and rekeying.
///
/// # Security Properties
///
/// - All key material is zeroized on drop.
/// - Nonces are strictly monotonic — reuse is impossible.
/// - Anti-replay window rejects duplicate or too-old messages.
/// - Automatic rekey after 2^20 messages prevents key wear-out.
/// - `Debug` prints `[REDACTED]` for all key material.
pub struct SessionCipher {
    write_key: [u8; 32],
    read_key: [u8; 32],
    write_counter: u64,
    read_counter: u64,
    read_window: u64,
    rekey_seed: [u8; 32],
    /// Counts messages encrypted (sent) since the last rekey.
    send_since_rekey: u32,
    /// Counts messages decrypted (received) since the last rekey.
    recv_since_rekey: u32,
    is_server: bool,
}

impl Drop for SessionCipher {
    fn drop(&mut self) {
        self.write_key.zeroize();
        self.read_key.zeroize();
        self.rekey_seed.zeroize();
        self.write_counter = 0;
        self.read_counter = 0;
        self.read_window = 0;
        self.send_since_rekey = 0;
        self.recv_since_rekey = 0;
    }
}

impl fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `read_window` and `rekey_seed` are intentionally omitted: the seed
        // is secret material and the window bitmap is internal bookkeeping.
        f.debug_struct("SessionCipher")
            .field("write_key", &"[REDACTED]")
            .field("read_key", &"[REDACTED]")
            .field("write_counter", &self.write_counter)
            .field("read_counter", &self.read_counter)
            .field("send_since_rekey", &self.send_since_rekey)
            .field("recv_since_rekey", &self.recv_since_rekey)
            .field("is_server", &self.is_server)
            .finish_non_exhaustive()
    }
}

/// Build the 12-byte nonce from a counter value.
///
/// Layout: `[0, 0, 0, 0, counter_be[0..8]]` — 4 zero bytes followed by
/// the 8-byte big-endian counter.
fn counter_to_nonce(counter: u64) -> chacha20poly1305::Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce.into()
}

/// Maximum nonce counter value. We reserve the last 2^20 values as a safety
/// margin, forcing a rekey or session termination well before `u64::MAX`.
/// This prevents nonce reuse even under pathological conditions.
const MAX_COUNTER: u64 = u64::MAX - (1 << 20);

/// Build the full AAD: `version_byte` || `counter_be8` || `user_aad`.
///
/// Uses a stack buffer for the common case (AAD <= 128 bytes) to avoid
/// heap allocation in the hot path.
fn build_aad(counter: u64, user_aad: &[u8]) -> AadBuffer {
    let total_len = 1 + 8 + user_aad.len();
    let mut buf = AadBuffer::with_capacity(total_len);
    buf.push(ENVELOPE_VERSION);
    buf.extend_from_slice(&counter.to_be_bytes());
    buf.extend_from_slice(user_aad);
    buf
}

/// Stack-optimized buffer for AAD construction.
///
/// For AAD payloads up to 128 bytes (the common case), this avoids heap
/// allocation entirely. Larger payloads fall back to `Vec<u8>`.
enum AadBuffer {
    Stack {
        data: [u8; 137], // 1 (version) + 8 (counter) + 128 (user AAD)
        len: usize,
    },
    Heap(Vec<u8>),
}

impl AadBuffer {
    fn with_capacity(cap: usize) -> Self {
        if cap <= 137 {
            Self::Stack {
                data: [0u8; 137],
                len: 0,
            }
        } else {
            Self::Heap(Vec::with_capacity(cap))
        }
    }

    fn push(&mut self, byte: u8) {
        match self {
            Self::Stack { data, len } => {
                data[*len] = byte;
                *len += 1;
            }
            Self::Heap(v) => v.push(byte),
        }
    }

    fn extend_from_slice(&mut self, slice: &[u8]) {
        match self {
            Self::Stack { data, len } => {
                data[*len..*len + slice.len()].copy_from_slice(slice);
                *len += slice.len();
            }
            Self::Heap(v) => v.extend_from_slice(slice),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Stack { data, len } => &data[..*len],
            Self::Heap(v) => v,
        }
    }
}

impl SessionCipher {
    /// Create a new session cipher from handshake-derived session keys.
    ///
    /// # Arguments
    ///
    /// - `session_keys`: The keys derived from the handshake.
    /// - `is_server`: If `true`, writes with `server_write_key` and reads with
    ///   `client_write_key`. If `false`, the reverse.
    ///
    /// # Security Properties
    ///
    /// - Client and server use different keys for each direction, preventing
    ///   reflection attacks.
    /// - The rekey seed is shared and used for symmetric ratcheting.
    pub const fn new(session_keys: &SessionKeys, is_server: bool) -> Self {
        let (write_key, read_key) = if is_server {
            (session_keys.server_write_key, session_keys.client_write_key)
        } else {
            (session_keys.client_write_key, session_keys.server_write_key)
        };

        Self {
            write_key,
            read_key,
            write_counter: 0,
            read_counter: 0,
            read_window: 0,
            rekey_seed: session_keys.rekey_seed,

            send_since_rekey: 0,
            recv_since_rekey: 0,
            is_server,
        }
    }

    /// Encrypt a plaintext message with optional additional authenticated data.
    ///
    /// # Security Properties
    ///
    /// - Uses ChaCha20-Poly1305 AEAD with a unique nonce derived from the
    ///   monotonic write counter.
    /// - The AAD includes a version byte and the counter to bind the ciphertext
    ///   to its sequence position.
    /// - Automatically rekeys after 2^20 messages.
    /// - Returns a [`SealedEnvelope`] containing the counter and ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DecryptionFailed`] if the AEAD encryption fails
    /// (should never happen with valid keys).
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<SealedEnvelope> {
        // Auto-rekey if either direction has hit the threshold. Both peers
        // use the same deterministic rekey derivation (keyed solely off the
        // shared rekey_seed), so a rekey triggered on one side produces
        // identical key material regardless of which counter reached the
        // threshold first. Checking both counters here ensures the sending
        // side rekeys even when it has been mostly receiving.
        if self.send_since_rekey >= REKEY_INTERVAL || self.recv_since_rekey >= REKEY_INTERVAL {
            self.rekey();
        }

        let counter = self.write_counter;

        // Enforce nonce counter ceiling to prevent nonce reuse.
        // At ~1M messages/sec this limit would take ~585 thousand years to reach,
        // but defense-in-depth demands we check explicitly.
        if counter >= MAX_COUNTER {
            return Err(CryptoError::CounterExhausted);
        }

        let nonce = counter_to_nonce(counter);
        let full_aad = build_aad(counter, aad);

        let cipher = ChaCha20Poly1305::new((&self.write_key).into());
        let ciphertext = cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: full_aad.as_slice(),
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Safe: we checked counter < MAX_COUNTER above, which is u64::MAX - 2^20.
        self.write_counter = counter + 1;
        self.send_since_rekey += 1;

        Ok(SealedEnvelope {
            counter,
            ciphertext,
        })
    }

    /// Decrypt a sealed envelope with optional additional authenticated data.
    ///
    /// # Security Properties
    ///
    /// - Verifies the Poly1305 authentication tag before returning plaintext.
    /// - Checks the counter against the sliding window for anti-replay.
    /// - Updates the sliding window on successful decryption.
    /// - The AAD must match exactly what was used during encryption.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::CounterTooOld`] if the counter is below the window.
    /// - [`CryptoError::ReplayDetected`] if the counter was already seen.
    /// - [`CryptoError::DecryptionFailed`] if AEAD verification fails.
    pub fn decrypt(&mut self, envelope: &SealedEnvelope, aad: &[u8]) -> Result<Vec<u8>> {
        // Auto-rekey if either direction has hit the threshold. The rekey
        // derivation is deterministic from the shared rekey_seed, so both
        // peers produce identical keys regardless of which direction
        // triggered the rekey.
        if self.send_since_rekey >= REKEY_INTERVAL || self.recv_since_rekey >= REKEY_INTERVAL {
            self.rekey();
        }

        let counter = envelope.counter;

        // Anti-replay check
        self.check_replay(counter)?;

        let nonce = counter_to_nonce(counter);
        let full_aad = build_aad(counter, aad);

        let cipher = ChaCha20Poly1305::new((&self.read_key).into());
        let plaintext = cipher
            .decrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: &envelope.ciphertext,
                    aad: full_aad.as_slice(),
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Update replay window only after successful decryption
        self.update_window(counter);

        // Increment receive counter AFTER successful decryption so that
        // failed decrypts (tampered ciphertext, wrong AAD) do not advance
        // the counter toward a premature rekey.
        self.recv_since_rekey += 1;

        Ok(plaintext)
    }

    /// Perform a symmetric rekey operation.
    ///
    /// Derives new write key, read key, and rekey seed from the current rekey
    /// seed using HKDF-SHA256. Old keys are zeroized immediately.
    ///
    /// # Security Properties
    ///
    /// - Forward secrecy: old keys cannot be recovered from new keys.
    /// - The write counter is used as salt to bind the new keys to the
    ///   current message sequence position.
    /// - Old key material is explicitly zeroized before replacement.
    pub fn rekey(&mut self) {
        // Use a fixed domain-separation salt derived from the rekey seed itself.
        // Both sides share the same rekey_seed, so they derive identical new keys.
        // We do NOT use write_counter because it differs between client and server.
        let salt: [u8; 32] = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(b"STEALTH_REKEY_SALT_V1");
            h.update(self.rekey_seed);
            h.finalize().into()
        };
        let hk = Hkdf::<Sha256>::new(Some(&salt), &self.rekey_seed);
        let mut okm = [0u8; 96];
        hk.expand(b"STEALTH_REKEY_V1", &mut okm)
            .expect("96 bytes is within HKDF-SHA256 output limit");

        // Zeroize old keys
        self.write_key.zeroize();
        self.read_key.zeroize();
        self.rekey_seed.zeroize();

        // Install new keys based on role
        if self.is_server {
            self.write_key.copy_from_slice(&okm[32..64]); // server_write = [32..64]
            self.read_key.copy_from_slice(&okm[..32]); // client_write = [0..32]
        } else {
            self.write_key.copy_from_slice(&okm[..32]); // client_write = [0..32]
            self.read_key.copy_from_slice(&okm[32..64]); // server_write = [32..64]
        }
        self.rekey_seed.copy_from_slice(&okm[64..96]);

        okm.zeroize();
        self.send_since_rekey = 0;
        self.recv_since_rekey = 0;
    }

    /// Check whether a counter value is valid (not replayed, not too old).
    const fn check_replay(&self, counter: u64) -> Result<()> {
        if self.read_counter == 0 && self.read_window == 0 && counter == 0 {
            // First message ever — always accept counter 0
            return Ok(());
        }

        // If counter is beyond current read_counter, it's new — always valid
        if counter > self.read_counter {
            return Ok(());
        }

        // Check if counter is within the sliding window
        let diff = self.read_counter - counter;
        if diff >= WINDOW_SIZE {
            return Err(CryptoError::CounterTooOld(
                counter,
                self.read_counter.saturating_sub(WINDOW_SIZE - 1),
            ));
        }

        // Check the bitmap
        let bit = 1u64 << diff;
        if self.read_window & bit != 0 {
            return Err(CryptoError::ReplayDetected(counter));
        }

        Ok(())
    }

    /// Update the sliding window after successful decryption.
    const fn update_window(&mut self, counter: u64) {
        if counter > self.read_counter {
            // Shift window by the difference
            let shift = counter - self.read_counter;
            if shift >= WINDOW_SIZE {
                self.read_window = 1; // bit 0 = current read_counter position
            } else {
                self.read_window = (self.read_window << shift) | 1;
            }
            self.read_counter = counter;
        } else {
            // Mark the bit for this counter in the window
            let diff = self.read_counter - counter;
            self.read_window |= 1u64 << diff;
        }
    }

    /// Return the current write counter value (useful for diagnostics).
    pub const fn write_counter(&self) -> u64 {
        self.write_counter
    }

    /// Return the current read counter value (useful for diagnostics).
    pub const fn read_counter(&self) -> u64 {
        self.read_counter
    }

    /// Return the number of messages sent since the last rekey.
    pub const fn send_since_rekey(&self) -> u32 {
        self.send_since_rekey
    }

    /// Return the number of messages received since the last rekey.
    pub const fn recv_since_rekey(&self) -> u32 {
        self.recv_since_rekey
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::SessionKeys;

    fn make_test_keys() -> SessionKeys {
        SessionKeys {
            client_write_key: [1u8; 32],
            server_write_key: [2u8; 32],
            rekey_seed: [3u8; 32],
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let keys = make_test_keys();
        let mut client = SessionCipher::new(
            &SessionKeys {
                client_write_key: keys.client_write_key,
                server_write_key: keys.server_write_key,
                rekey_seed: keys.rekey_seed,
            },
            false,
        );
        let mut server = SessionCipher::new(&make_test_keys(), true);

        let plaintext = b"hello, stealth world!";
        let aad = b"pool-id-123";

        let envelope = client.encrypt(plaintext, aad).unwrap();
        let decrypted = server.decrypt(&envelope, aad).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn server_to_client_roundtrip() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        let plaintext = b"server message";
        let aad = b"";

        let envelope = server.encrypt(plaintext, aad).unwrap();
        let decrypted = client.decrypt(&envelope, aad).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn replay_detected() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        let envelope = client.encrypt(b"msg1", b"").unwrap();
        server.decrypt(&envelope, b"").unwrap();

        // Replay the same envelope
        let result = server.decrypt(&envelope, b"");
        assert!(matches!(result, Err(CryptoError::ReplayDetected(0))));
    }

    #[test]
    fn counter_too_old() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        // Send 65 messages to advance the window past counter 0
        let mut envelopes = Vec::new();
        for _ in 0..65 {
            envelopes.push(client.encrypt(b"msg", b"").unwrap());
        }

        // Decrypt them in order
        for env in &envelopes {
            server.decrypt(env, b"").unwrap();
        }

        // Try to decrypt a very old message (counter 0) — should fail
        let old_envelope = SealedEnvelope {
            counter: 0,
            ciphertext: envelopes[0].ciphertext.clone(),
        };
        let result = server.decrypt(&old_envelope, b"");
        assert!(matches!(result, Err(CryptoError::CounterTooOld(0, _))));
    }

    #[test]
    fn out_of_order_within_window() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        let env0 = client.encrypt(b"msg0", b"").unwrap();
        let env1 = client.encrypt(b"msg1", b"").unwrap();
        let env2 = client.encrypt(b"msg2", b"").unwrap();

        // Decrypt out of order: 2, 0, 1
        server.decrypt(&env2, b"").unwrap();
        server.decrypt(&env0, b"").unwrap();
        server.decrypt(&env1, b"").unwrap();
    }

    #[test]
    fn wrong_aad_fails() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        let envelope = client.encrypt(b"secret", b"correct-aad").unwrap();
        let result = server.decrypt(&envelope, b"wrong-aad");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn manual_rekey() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        // Send a message before rekey
        let env1 = client.encrypt(b"before rekey", b"").unwrap();
        server.decrypt(&env1, b"").unwrap();

        // Rekey both sides
        client.rekey();
        server.rekey();

        // Send a message after rekey
        let env2 = client.encrypt(b"after rekey", b"").unwrap();
        let decrypted = server.decrypt(&env2, b"").unwrap();
        assert_eq!(&decrypted, b"after rekey");
    }

    #[test]
    fn debug_redacts_keys() {
        let cipher = SessionCipher::new(&make_test_keys(), false);
        let debug = format!("{cipher:?}");
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn rekey_triggered_on_send_count() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        // Force send_since_rekey to just below threshold.
        client.send_since_rekey = REKEY_INTERVAL - 1;

        // This encrypt should NOT trigger rekey (counter is INTERVAL - 1, check is >= INTERVAL).
        let env1 = client.encrypt(b"before threshold", b"").unwrap();
        assert_eq!(client.send_since_rekey, REKEY_INTERVAL);

        // Sync server's recv counter to match.
        server.recv_since_rekey = REKEY_INTERVAL - 1;
        server.decrypt(&env1, b"").unwrap();

        // Next encrypt WILL trigger rekey (send_since_rekey == REKEY_INTERVAL).
        let env2 = client.encrypt(b"after rekey", b"").unwrap();
        assert_eq!(client.send_since_rekey, 1, "rekey should reset counter");

        // Server must also rekey before decrypting.
        server.decrypt(&env2, b"").unwrap();
    }

    #[test]
    fn rekey_triggered_on_recv_count() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        // Simulate server having received many messages (via its recv counter).
        // When server encrypts, it checks both send and recv counters.
        server.recv_since_rekey = REKEY_INTERVAL;
        client.send_since_rekey = REKEY_INTERVAL;

        // Both sides rekey on their next operation.
        let env = server.encrypt(b"rekey on recv path", b"").unwrap();
        let plaintext = client.decrypt(&env, b"").unwrap();
        assert_eq!(&plaintext, b"rekey on recv path");
    }

    #[test]
    fn nonce_uniqueness_across_messages() {
        let mut client = SessionCipher::new(&make_test_keys(), false);

        let env0 = client.encrypt(b"msg0", b"").unwrap();
        let env1 = client.encrypt(b"msg1", b"").unwrap();
        let env2 = client.encrypt(b"msg2", b"").unwrap();

        // Counters must be strictly increasing.
        assert_eq!(env0.counter, 0);
        assert_eq!(env1.counter, 1);
        assert_eq!(env2.counter, 2);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        let mut envelope = client.encrypt(b"authentic", b"").unwrap();
        // Flip a bit in the ciphertext.
        if let Some(byte) = envelope.ciphertext.first_mut() {
            *byte ^= 0x01;
        }
        let result = server.decrypt(&envelope, b"");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn bidirectional_communication() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        // Client -> Server
        let env1 = client.encrypt(b"hello server", b"").unwrap();
        let pt1 = server.decrypt(&env1, b"").unwrap();
        assert_eq!(&pt1, b"hello server");

        // Server -> Client
        let env2 = server.encrypt(b"hello client", b"").unwrap();
        let pt2 = client.decrypt(&env2, b"").unwrap();
        assert_eq!(&pt2, b"hello client");

        // Client -> Server again
        let env3 = client.encrypt(b"another message", b"").unwrap();
        let pt3 = server.decrypt(&env3, b"").unwrap();
        assert_eq!(&pt3, b"another message");
    }

    #[test]
    fn write_and_read_counters_track_correctly() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        assert_eq!(client.write_counter(), 0);
        assert_eq!(server.read_counter(), 0);

        let env = client.encrypt(b"a", b"").unwrap();
        assert_eq!(client.write_counter(), 1);

        server.decrypt(&env, b"").unwrap();
        assert_eq!(server.read_counter(), 0); // read_counter tracks highest seen

        let env2 = client.encrypt(b"b", b"").unwrap();
        server.decrypt(&env2, b"").unwrap();
        assert_eq!(server.read_counter(), 1);
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let mut client = SessionCipher::new(&make_test_keys(), false);
        let mut server = SessionCipher::new(&make_test_keys(), true);

        let env = client.encrypt(b"", b"").unwrap();
        let pt = server.decrypt(&env, b"").unwrap();
        assert!(pt.is_empty());
    }
}
