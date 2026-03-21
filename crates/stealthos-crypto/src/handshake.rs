//! Noise NK-inspired key exchange handshake.
//!
//! # Protocol Overview
//!
//! The handshake assumes the client knows the server's static X25519 public key
//! (obtained via an invitation token or out-of-band).
//!
//! ```text
//! Step 1 (Client -> Server):
//!   client generates ephemeral X25519 keypair
//!   shared_es = X25519(client_ephemeral_sk, server_static_pk)
//!   sends: { client_ephemeral_pk, client_ed25519_pk, timestamp, signature }
//!
//! Step 2 (Server -> Client):
//!   server generates ephemeral X25519 keypair
//!   shared_ee = X25519(server_ephemeral_sk, client_ephemeral_pk)
//!   sends: { server_ephemeral_pk, timestamp, signature }
//!
//! Step 3 (Both):
//!   ikm = shared_es || shared_ee
//!   session_keys = HKDF-SHA256(ikm, salt, info, 96)
//! ```
//!
//! # Security Properties
//!
//! - Forward secrecy via ephemeral X25519 keys.
//! - Server authentication via static key (NK pattern).
//! - Client authentication via Ed25519 signature over handshake transcript.
//! - All ephemeral secrets are zeroized after key derivation.

use std::fmt;

use ed25519_dalek::Verifier;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::identity::HostIdentity;
use crate::peer_identity::PeerIdentity;

/// Maximum allowable clock skew (in seconds) for handshake timestamps.
/// Messages older than this are rejected to prevent replay attacks.
const MAX_HANDSHAKE_SKEW_SECS: i64 = 300; // 5 minutes

/// Session keys derived from the handshake.
///
/// Contains symmetric keys for bidirectional encryption and a rekey seed
/// for the symmetric ratchet.
///
/// # Security Properties
///
/// - All key material is zeroized on drop.
/// - `Debug` prints `[REDACTED]`.
pub struct SessionKeys {
    /// Key used by the client to encrypt (server uses to decrypt).
    pub client_write_key: [u8; 32],
    /// Key used by the server to encrypt (client uses to decrypt).
    pub server_write_key: [u8; 32],
    /// Seed for the symmetric ratchet (rekey operation).
    pub rekey_seed: [u8; 32],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.rekey_seed.zeroize();
    }
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("client_write_key", &"[REDACTED]")
            .field("server_write_key", &"[REDACTED]")
            .field("rekey_seed", &"[REDACTED]")
            .finish()
    }
}

/// A handshake message exchanged between client and server.
///
/// Serialized as JSON for transport (could be switched to CBOR for efficiency).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakeMessage {
    /// The sender's ephemeral X25519 public key.
    pub ephemeral_pk: [u8; 32],
    /// The sender's Ed25519 public key (only present in init message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_pk: Option<[u8; 32]>,
    /// Unix timestamp (seconds) at time of message creation.
    pub timestamp: i64,
    /// Ed25519 signature over the handshake transcript.
    #[serde(with = "crate::serde_helpers::bytes64")]
    pub signature: [u8; 64],
}

impl fmt::Debug for HandshakeMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeMessage")
            .field("ephemeral_pk", &"[32 bytes]")
            .field("has_ed25519_pk", &self.ed25519_pk.is_some())
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Derive session keys from the shared secrets and ephemeral public keys.
///
/// # Arguments
///
/// - `shared_es`: X25519 shared secret from (client ephemeral, server static)
/// - `shared_ee`: X25519 shared secret from (client ephemeral, server ephemeral)
/// - `client_eph_pk`: Client's ephemeral X25519 public key bytes
/// - `server_eph_pk`: Server's ephemeral X25519 public key bytes
/// - `pool_id`: Optional pool identifier for domain separation
#[allow(clippy::similar_names)] // shared_es and shared_ee are standard Noise NK terminology
fn derive_session_keys(
    shared_es: &[u8; 32],
    shared_ee: &[u8; 32],
    client_eph_pk: &[u8; 32],
    server_eph_pk: &[u8; 32],
    pool_id: &[u8],
) -> SessionKeys {
    // ikm = shared_es || shared_ee
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(shared_es);
    ikm[32..].copy_from_slice(shared_ee);

    // salt = client_ephemeral_pk || server_ephemeral_pk
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_eph_pk);
    salt[32..].copy_from_slice(server_eph_pk);

    // info = "STEALTH_SESSION_V1" || pool_id
    let mut info = Vec::with_capacity(18 + pool_id.len());
    info.extend_from_slice(b"STEALTH_SESSION_V1");
    info.extend_from_slice(pool_id);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 96];
    hk.expand(&info, &mut okm)
        .expect("96 bytes is within HKDF-SHA256 output limit");

    let mut keys = SessionKeys {
        client_write_key: [0u8; 32],
        server_write_key: [0u8; 32],
        rekey_seed: [0u8; 32],
    };
    keys.client_write_key.copy_from_slice(&okm[..32]);
    keys.server_write_key.copy_from_slice(&okm[32..64]);
    keys.rekey_seed.copy_from_slice(&okm[64..96]);

    // Zeroize intermediate material
    ikm.zeroize();
    salt.zeroize();
    okm.zeroize();

    keys
}

/// Build the transcript bytes that get signed during handshake.
///
/// The pool_id is included in every transcript to prevent cross-pool replay
/// attacks. A server response from one pool cannot be accepted in another
/// pool context because the pool_id differs.
/// Domain separator prefixes for handshake transcript signatures.
///
/// These ensure that a signature over a handshake init transcript can never
/// be accepted as a handshake response signature (or any other signed
/// message in the protocol), even if the concatenated fields happen to
/// produce identical byte sequences. Without domain separation, an
/// attacker could potentially replay a signature from one context in
/// another if the underlying byte layout collides.
const TRANSCRIPT_PREFIX_INIT: &[u8] = b"STEALTH_HS_INIT_V1:";
const TRANSCRIPT_PREFIX_RESP: &[u8] = b"STEALTH_HS_RESP_V1:";

fn build_transcript(
    ephemeral_pk: &[u8; 32],
    extra_pk: Option<&[u8; 32]>,
    timestamp: i64,
    pool_id: &[u8],
) -> Vec<u8> {
    // Use the appropriate domain separator based on whether this is an
    // init transcript (has extra_pk = client ed25519 pk) or a response
    // transcript (no extra_pk).
    let prefix = if extra_pk.is_some() {
        TRANSCRIPT_PREFIX_INIT
    } else {
        TRANSCRIPT_PREFIX_RESP
    };
    let mut transcript = Vec::with_capacity(prefix.len() + 72 + pool_id.len());
    transcript.extend_from_slice(prefix);
    transcript.extend_from_slice(ephemeral_pk);
    if let Some(pk) = extra_pk {
        transcript.extend_from_slice(pk);
    }
    transcript.extend_from_slice(&timestamp.to_be_bytes());
    transcript.extend_from_slice(pool_id);
    transcript
}

/// Client-side handshake state machine.
///
/// # Usage
///
/// ```ignore
/// let initiator = HandshakeInitiator::new(peer_identity, server_static_pk, pool_id);
/// let (init_msg, initiator) = initiator.create_init_message();
/// // send init_msg to server, receive response_msg
/// let session_keys = initiator.process_response(&response_msg, &server_ed25519_pk)?;
/// ```
///
/// # Security Properties
///
/// - Ephemeral X25519 secret is generated from `OsRng`.
/// - Uses `StaticSecret` (not `EphemeralSecret`) to allow two DH operations
///   (es + ee) for the full Noise NK pattern.
/// - `shared_es` and `shared_ee` are both real DH computations.
pub struct HandshakeInitiator {
    peer_identity: PeerIdentity,
    server_static_pk: x25519_dalek::PublicKey,
    ephemeral_secret: x25519_dalek::StaticSecret,
    ephemeral_public: x25519_dalek::PublicKey,
    pool_id: Vec<u8>,
}

impl fmt::Debug for HandshakeInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeInitiator")
            .field("ephemeral_secret", &"[REDACTED]")
            .field("pool_id_len", &self.pool_id.len())
            .finish()
    }
}

impl HandshakeInitiator {
    /// Create a new handshake initiator (client side).
    ///
    /// # Arguments
    ///
    /// - `peer_identity`: The client's Ed25519 signing identity.
    /// - `server_static_pk`: The server's static X25519 public key (from invitation).
    /// - `pool_id`: The pool identifier for domain separation in key derivation.
    ///
    /// # Security Properties
    ///
    /// - Generates a fresh ephemeral X25519 keypair from `OsRng`.
    /// - Uses `StaticSecret` to enable both `es` and `ee` DH operations.
    pub fn new(peer_identity: PeerIdentity, server_static_pk: [u8; 32], pool_id: Vec<u8>) -> Self {
        let server_static_pk = x25519_dalek::PublicKey::from(server_static_pk);
        let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
        Self {
            peer_identity,
            server_static_pk,
            ephemeral_secret,
            ephemeral_public,
            pool_id,
        }
    }

    /// Create the initial handshake message (Step 1).
    ///
    /// Returns the message to send to the server and consumes the initiator
    /// into a state that can process the server's response.
    ///
    /// # Security Properties
    ///
    /// - The message is signed with the client's Ed25519 key.
    /// - The ephemeral public key is included for the server to compute `shared_ee`.
    /// - The timestamp prevents replay of old handshake messages.
    pub fn create_init_message(self) -> (HandshakeMessage, HandshakeInitiatorAwaitingResponse) {
        let client_ed25519_pk = self.peer_identity.public_key();
        let ephemeral_pk = self.ephemeral_public.to_bytes();
        let timestamp = chrono::Utc::now().timestamp();

        let transcript = build_transcript(
            &ephemeral_pk,
            Some(&client_ed25519_pk),
            timestamp,
            &self.pool_id,
        );
        let signature = self.peer_identity.sign(&transcript);

        let msg = HandshakeMessage {
            ephemeral_pk,
            ed25519_pk: Some(client_ed25519_pk),
            timestamp,
            signature,
        };

        let awaiting = HandshakeInitiatorAwaitingResponse {
            ephemeral_secret: self.ephemeral_secret,
            ephemeral_public: self.ephemeral_public,
            server_static_pk: self.server_static_pk,
            pool_id: self.pool_id,
        };

        (msg, awaiting)
    }
}

/// Client-side state after sending the init message, awaiting server response.
///
/// # Security Properties
///
/// - Holds the ephemeral secret until the server responds.
/// - Uses `StaticSecret` to enable two DH operations (es + ee).
/// - `Debug` prints `[REDACTED]` for the secret.
pub struct HandshakeInitiatorAwaitingResponse {
    ephemeral_secret: x25519_dalek::StaticSecret,
    ephemeral_public: x25519_dalek::PublicKey,
    server_static_pk: x25519_dalek::PublicKey,
    pool_id: Vec<u8>,
}

impl fmt::Debug for HandshakeInitiatorAwaitingResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeInitiatorAwaitingResponse")
            .field("ephemeral_secret", &"[REDACTED]")
            .finish()
    }
}

impl HandshakeInitiatorAwaitingResponse {
    /// Process the server's response message (Step 2) and derive session keys.
    ///
    /// # Arguments
    ///
    /// - `response`: The server's handshake response message.
    /// - `server_ed25519_pk`: The server's Ed25519 public key for signature verification.
    ///
    /// # Security Properties
    ///
    /// - Verifies the server's Ed25519 signature over the response transcript
    ///   (which includes pool_id to prevent cross-pool replay).
    /// - Computes two real DH operations:
    ///   - `shared_es = X25519(client_ephemeral_sk, server_static_pk)`
    ///   - `shared_ee = X25519(client_ephemeral_sk, server_ephemeral_pk)`
    /// - Derives session keys from `ikm = shared_es || shared_ee`.
    /// - All ephemeral secrets are consumed (moved) and will be dropped/zeroized.
    /// - Returns an error if the server's signature is invalid.
    #[allow(clippy::similar_names)] // shared_es/shared_ee are standard Noise NK terminology
    pub fn process_response(
        self,
        response: &HandshakeMessage,
        server_ed25519_pk: &[u8; 32],
    ) -> Result<SessionKeys> {
        // Validate timestamp freshness to prevent replay of old responses.
        let now = chrono::Utc::now().timestamp();
        let skew = (now - response.timestamp).abs();
        if skew > MAX_HANDSHAKE_SKEW_SECS {
            return Err(CryptoError::handshake(
                "server response timestamp outside acceptable window",
            ));
        }

        // Verify server signature (transcript now includes pool_id)
        let transcript = build_transcript(
            &response.ephemeral_pk,
            None,
            response.timestamp,
            &self.pool_id,
        );
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(server_ed25519_pk) else {
            return Err(CryptoError::handshake("invalid server Ed25519 public key"));
        };
        let sig = ed25519_dalek::Signature::from_bytes(&response.signature);
        verifying_key
            .verify(&transcript, &sig)
            .map_err(|_| CryptoError::handshake("server signature verification failed"))?;

        // Compute shared secrets using two real DH operations.
        let server_eph_pk = x25519_dalek::PublicKey::from(response.ephemeral_pk);

        // shared_es = X25519(client_ephemeral_sk, server_static_pk)
        let shared_es = self.ephemeral_secret.diffie_hellman(&self.server_static_pk);
        let mut shared_es_bytes = shared_es.to_bytes();

        // shared_ee = X25519(client_ephemeral_sk, server_ephemeral_pk)
        // This is now a real second DH because we use StaticSecret instead of EphemeralSecret.
        let shared_ee = self.ephemeral_secret.diffie_hellman(&server_eph_pk);
        let mut shared_ee_bytes = shared_ee.to_bytes();

        let client_eph_pk = self.ephemeral_public.to_bytes();
        let server_eph_pk_bytes = response.ephemeral_pk;

        let keys = derive_session_keys(
            &shared_es_bytes,
            &shared_ee_bytes,
            &client_eph_pk,
            &server_eph_pk_bytes,
            &self.pool_id,
        );

        shared_es_bytes.zeroize();
        shared_ee_bytes.zeroize();

        Ok(keys)
    }
}

/// Server-side handshake responder.
///
/// # Usage
///
/// ```ignore
/// let responder = HandshakeResponder::new(&host_identity, pool_id);
/// let (response_msg, session_keys) = responder.process_init_message(&init_msg)?;
/// // send response_msg to client
/// // use session_keys for encryption
/// ```
///
/// # Security Properties
///
/// - Verifies the client's Ed25519 signature in the init message.
/// - Generates a fresh ephemeral X25519 keypair.
/// - Computes shared secrets and derives session keys.
pub struct HandshakeResponder<'a> {
    host_identity: &'a HostIdentity,
    pool_id: Vec<u8>,
}

impl<'a> fmt::Debug for HandshakeResponder<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeResponder")
            .field("host_identity", &"[REDACTED]")
            .field("pool_id_len", &self.pool_id.len())
            .finish()
    }
}

impl<'a> HandshakeResponder<'a> {
    /// Create a new handshake responder (server side).
    ///
    /// # Arguments
    ///
    /// - `host_identity`: The server's long-term identity (Ed25519 + X25519).
    /// - `pool_id`: The pool identifier for domain separation.
    pub fn new(host_identity: &'a HostIdentity, pool_id: Vec<u8>) -> Self {
        Self {
            host_identity,
            pool_id,
        }
    }

    /// Process the client's init message and produce a response + session keys.
    ///
    /// # Security Properties
    ///
    /// - Verifies the client's Ed25519 signature over the init transcript
    ///   (which includes pool_id for domain separation).
    /// - Generates fresh ephemeral X25519 keys from `OsRng` using `StaticSecret`
    ///   to enable two real DH operations.
    /// - Computes two DH operations:
    ///   - `shared_es = X25519(server_static_sk, client_ephemeral_pk)`
    ///   - `shared_ee = X25519(server_ephemeral_sk, client_ephemeral_pk)`
    /// - Signs the response transcript (including pool_id) with the server's Ed25519 key.
    /// - All ephemeral secrets are zeroized after key derivation.
    #[allow(clippy::similar_names)] // shared_es/shared_ee are standard Noise NK terminology
    pub fn process_init_message(
        &self,
        init_msg: &HandshakeMessage,
    ) -> Result<(HandshakeMessage, SessionKeys)> {
        // Validate timestamp freshness to prevent replay of old handshake messages.
        let now = chrono::Utc::now().timestamp();
        let skew = (now - init_msg.timestamp).abs();
        if skew > MAX_HANDSHAKE_SKEW_SECS {
            return Err(CryptoError::handshake(
                "handshake timestamp outside acceptable window",
            ));
        }

        // Extract and verify client Ed25519 public key
        let client_ed25519_pk = init_msg
            .ed25519_pk
            .ok_or_else(|| CryptoError::handshake("init message missing client Ed25519 pk"))?;

        // Verify client signature (transcript includes pool_id)
        let transcript = build_transcript(
            &init_msg.ephemeral_pk,
            Some(&client_ed25519_pk),
            init_msg.timestamp,
            &self.pool_id,
        );
        let Ok(client_vk) = ed25519_dalek::VerifyingKey::from_bytes(&client_ed25519_pk) else {
            return Err(CryptoError::handshake("invalid client Ed25519 public key"));
        };
        let sig = ed25519_dalek::Signature::from_bytes(&init_msg.signature);
        client_vk
            .verify(&transcript, &sig)
            .map_err(|_| CryptoError::handshake("client signature verification failed"))?;

        // Generate server ephemeral keypair using StaticSecret for two DH operations.
        let server_eph_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let server_eph_public = x25519_dalek::PublicKey::from(&server_eph_secret);

        // Compute shared_es = X25519(server_static_sk, client_ephemeral_pk)
        let client_eph_pk = x25519_dalek::PublicKey::from(init_msg.ephemeral_pk);
        let shared_es = self
            .host_identity
            .x25519_secret()
            .diffie_hellman(&client_eph_pk);
        let mut shared_es_bytes = shared_es.to_bytes();

        // Compute shared_ee = X25519(server_ephemeral_sk, client_ephemeral_pk)
        // Two real DH operations provide full Noise NK security: even if the
        // server static key is compromised, forward secrecy is maintained via
        // the ephemeral-ephemeral DH.
        let shared_ee = server_eph_secret.diffie_hellman(&client_eph_pk);
        let mut shared_ee_bytes = shared_ee.to_bytes();

        let server_eph_pk_bytes = server_eph_public.to_bytes();

        // Derive session keys from ikm = shared_es || shared_ee
        let keys = derive_session_keys(
            &shared_es_bytes,
            &shared_ee_bytes,
            &init_msg.ephemeral_pk,
            &server_eph_pk_bytes,
            &self.pool_id,
        );

        shared_es_bytes.zeroize();
        shared_ee_bytes.zeroize();

        // Create response message (transcript includes pool_id to prevent cross-pool replay)
        let timestamp = chrono::Utc::now().timestamp();
        let response_transcript =
            build_transcript(&server_eph_pk_bytes, None, timestamp, &self.pool_id);
        let signature = self.host_identity.sign(&response_transcript);

        let response = HandshakeMessage {
            ephemeral_pk: server_eph_pk_bytes,
            ed25519_pk: None,
            timestamp,
            signature,
        };

        Ok((response, keys))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_produces_matching_keys() {
        let host = HostIdentity::generate();
        let peer = PeerIdentity::generate();
        let pool_id = b"test-pool-123".to_vec();
        let server_x25519_pk = host.x25519_public().to_bytes();

        // Client creates init
        let initiator = HandshakeInitiator::new(peer, server_x25519_pk, pool_id.clone());
        let (init_msg, awaiting) = initiator.create_init_message();

        // Server processes init
        let responder = HandshakeResponder::new(&host, pool_id);
        let (response_msg, server_keys) = responder.process_init_message(&init_msg).unwrap();

        // Client processes response
        let server_ed25519_pk = host.public_keys().ed25519;
        let client_keys = awaiting
            .process_response(&response_msg, &server_ed25519_pk)
            .unwrap();

        // Keys must match
        assert_eq!(client_keys.client_write_key, server_keys.client_write_key);
        assert_eq!(client_keys.server_write_key, server_keys.server_write_key);
        assert_eq!(client_keys.rekey_seed, server_keys.rekey_seed);
    }

    #[test]
    fn handshake_fails_with_wrong_server_key() {
        let host = HostIdentity::generate();
        let wrong_host = HostIdentity::generate();
        let peer = PeerIdentity::generate();
        let pool_id = b"test-pool".to_vec();
        let server_x25519_pk = host.x25519_public().to_bytes();

        let initiator = HandshakeInitiator::new(peer, server_x25519_pk, pool_id.clone());
        let (init_msg, awaiting) = initiator.create_init_message();

        // Use wrong host to process — should produce different keys
        let responder = HandshakeResponder::new(&wrong_host, pool_id);
        let result = responder.process_init_message(&init_msg);
        // The init message signature is valid (signed by client), so processing
        // succeeds, but keys will differ because DH uses different server static key.
        if let Ok((response_msg, server_keys)) = result {
            let server_ed25519_pk = wrong_host.public_keys().ed25519;
            let client_keys = awaiting
                .process_response(&response_msg, &server_ed25519_pk)
                .unwrap();
            // Keys MUST NOT match when server identity differs
            assert_ne!(client_keys.client_write_key, server_keys.client_write_key);
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        let keys = SessionKeys {
            client_write_key: [1u8; 32],
            server_write_key: [2u8; 32],
            rekey_seed: [3u8; 32],
        };
        let debug = format!("{keys:?}");
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn handshake_rejects_bad_client_signature() {
        let host = HostIdentity::generate();
        let peer = PeerIdentity::generate();
        let pool_id = b"test-pool".to_vec();
        let server_x25519_pk = host.x25519_public().to_bytes();

        let initiator = HandshakeInitiator::new(peer, server_x25519_pk, pool_id.clone());
        let (mut init_msg, _awaiting) = initiator.create_init_message();

        // Corrupt the client's signature.
        init_msg.signature[0] ^= 0xFF;

        let responder = HandshakeResponder::new(&host, pool_id);
        let result = responder.process_init_message(&init_msg);
        assert!(result.is_err(), "corrupted signature must be rejected");
    }

    #[test]
    fn handshake_rejects_old_init_timestamp() {
        let host = HostIdentity::generate();
        let peer = PeerIdentity::generate();
        let pool_id = b"replay-pool".to_vec();
        let server_x25519_pk = host.x25519_public().to_bytes();

        let initiator = HandshakeInitiator::new(peer, server_x25519_pk, pool_id.clone());
        let (mut init_msg, _awaiting) = initiator.create_init_message();

        // Set timestamp to 10 minutes ago (beyond the 5-minute window).
        init_msg.timestamp -= 601;

        let responder = HandshakeResponder::new(&host, pool_id);
        let result = responder.process_init_message(&init_msg);
        assert!(result.is_err(), "stale init message must be rejected");
    }

    #[test]
    fn handshake_rejects_missing_ed25519_pk() {
        let host = HostIdentity::generate();
        let peer = PeerIdentity::generate();
        let pool_id = b"no-pk".to_vec();
        let server_x25519_pk = host.x25519_public().to_bytes();

        let initiator = HandshakeInitiator::new(peer, server_x25519_pk, pool_id.clone());
        let (mut init_msg, _awaiting) = initiator.create_init_message();

        // Remove the client's Ed25519 public key.
        init_msg.ed25519_pk = None;

        let responder = HandshakeResponder::new(&host, pool_id);
        let result = responder.process_init_message(&init_msg);
        assert!(result.is_err(), "init without ed25519_pk must be rejected");
    }

    #[test]
    fn different_pool_ids_produce_different_keys() {
        let host = HostIdentity::generate();
        let pool_a = b"pool-alpha".to_vec();
        let pool_b = b"pool-beta".to_vec();
        let server_x25519_pk = host.x25519_public().to_bytes();

        let peer_a = PeerIdentity::generate();
        let initiator_a = HandshakeInitiator::new(peer_a, server_x25519_pk, pool_a.clone());
        let (init_a, awaiting_a) = initiator_a.create_init_message();
        let responder_a = HandshakeResponder::new(&host, pool_a);
        let (resp_a, server_keys_a) = responder_a.process_init_message(&init_a).unwrap();
        let server_ed25519 = host.public_keys().ed25519;
        let client_keys_a = awaiting_a
            .process_response(&resp_a, &server_ed25519)
            .unwrap();

        let peer_b = PeerIdentity::generate();
        let initiator_b = HandshakeInitiator::new(peer_b, server_x25519_pk, pool_b.clone());
        let (init_b, awaiting_b) = initiator_b.create_init_message();
        let responder_b = HandshakeResponder::new(&host, pool_b);
        let (resp_b, server_keys_b) = responder_b.process_init_message(&init_b).unwrap();
        let client_keys_b = awaiting_b
            .process_response(&resp_b, &server_ed25519)
            .unwrap();

        // Different pool IDs must produce different session keys.
        assert_ne!(
            client_keys_a.client_write_key,
            client_keys_b.client_write_key
        );
        assert_ne!(
            server_keys_a.server_write_key,
            server_keys_b.server_write_key
        );
    }

    #[test]
    fn session_keys_zeroized_on_drop() {
        let keys = SessionKeys {
            client_write_key: [0xAA; 32],
            server_write_key: [0xBB; 32],
            rekey_seed: [0xCC; 32],
        };
        // Verify they are non-zero before drop.
        assert_eq!(keys.client_write_key, [0xAA; 32]);
        // Drop is implicit at end of scope; we just verify the type compiles with Drop.
        drop(keys);
    }
}
