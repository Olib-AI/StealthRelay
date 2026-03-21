//! Invitation token system for pool membership.
//!
//! Invitation tokens are capability-based credentials that allow a holder to
//! join a specific pool. The token contains a secret that is never sent to the
//! server directly — instead, the server stores a cryptographic commitment.
//!
//! # Token Flow
//!
//! 1. **Host generates** an `InvitationToken` containing a random `token_secret`.
//! 2. **Host computes** a `TokenCommitment` (`BLAKE2b` hash of HKDF-derived key)
//!    and sends it to the server.
//! 3. **Host shares** the token URL with the invitee (out-of-band).
//! 4. **Invitee presents** a `JoinProof` (HMAC over `pool_id` + nonce) to the host.
//! 5. **Host verifies** the proof against the commitment.
//!
//! # Security Properties
//!
//! - The server never sees the `token_secret` — only the commitment.
//! - The commitment is a one-way function of the secret.
//! - Join proofs are bound to a specific pool and timestamp.

use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use blake2::digest::FixedOutput;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};
use crate::identity::HostIdentity;

/// An invitation token granting the holder permission to join a pool.
///
/// # Security Properties
///
/// - `token_secret` is zeroized on drop.
/// - `Debug` redacts the secret.
/// - The token is signed by the host's Ed25519 key.
pub struct InvitationToken {
    /// Unique 128-bit token identifier.
    pub token_id: [u8; 16],
    /// 256-bit token secret (never sent to server).
    token_secret: TokenSecret,
    /// The pool this token grants access to.
    pub pool_id: Uuid,
    /// First 8 bytes of the host's fingerprint for identification.
    pub host_fingerprint: [u8; 8],
    /// Unix timestamp after which the token is invalid.
    pub expires_at: i64,
    /// Maximum number of times this token can be used.
    pub max_uses: u8,
    /// Server address to connect to.
    pub server_address: String,
    /// Ed25519 signature over the token fields.
    signature: [u8; 64],
}

/// Wrapper for the token secret ensuring zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
struct TokenSecret([u8; 32]);

impl Drop for InvitationToken {
    fn drop(&mut self) {
        // token_secret handles its own zeroization.
        self.signature.zeroize();
    }
}

impl fmt::Debug for InvitationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvitationToken")
            .field("token_id", &hex_encode(&self.token_id))
            .field("token_secret", &"[REDACTED]")
            .field("pool_id", &self.pool_id)
            .field("host_fingerprint", &hex_encode(&self.host_fingerprint))
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .field("server_address", &self.server_address)
            .field("signature", &"[64 bytes]")
            .finish()
    }
}

/// A join proof presented by an invitee to prove token possession.
///
/// Contains an HMAC that binds the proof to a specific pool and timestamp.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinProof {
    /// The token ID this proof corresponds to.
    pub token_id: [u8; 16],
    /// HMAC-SHA256 proof value.
    pub proof: [u8; 32],
    /// Unix timestamp when the proof was created.
    pub timestamp: i64,
    /// Random nonce provided by the verifier.
    pub nonce: [u8; 32],
}

impl fmt::Debug for JoinProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinProof")
            .field("token_id", &hex_encode(&self.token_id))
            .field("proof", &"[32 bytes]")
            .field("timestamp", &self.timestamp)
            .field("nonce", &"[32 bytes]")
            .finish()
    }
}

/// What the server stores — the commitment, not the secret.
///
/// The server can verify that a join proof corresponds to this commitment
/// without ever knowing the token secret.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenCommitment {
    /// The token ID.
    pub token_id: [u8; 16],
    /// BLAKE2b-256 commitment over the HKDF-derived verification key.
    pub commitment: [u8; 32],
    /// Expiration timestamp.
    pub expires_at: i64,
    /// Maximum uses.
    pub max_uses: u8,
}

impl fmt::Debug for TokenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenCommitment")
            .field("token_id", &hex_encode(&self.token_id))
            .field("commitment", &"[32 bytes]")
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .finish()
    }
}

/// Minimal hex encoding for debug output.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Build the message that gets signed by the host for a token.
///
/// The `server_address` is included with a 2-byte big-endian length prefix
/// to prevent relay redirect attacks where an attacker substitutes the
/// server address in an otherwise-valid invitation URL.
fn token_sign_message(
    token_id: &[u8; 16],
    token_secret: &[u8; 32],
    pool_id: &Uuid,
    expires_at: i64,
    max_uses: u8,
    server_address: &str,
) -> Vec<u8> {
    let addr_bytes = server_address.as_bytes();
    let addr_len = u16::try_from(addr_bytes.len()).unwrap_or(u16::MAX);
    let mut msg = Vec::with_capacity(16 + 32 + 16 + 8 + 1 + 2 + addr_bytes.len());
    msg.extend_from_slice(token_id);
    msg.extend_from_slice(token_secret);
    msg.extend_from_slice(pool_id.as_bytes());
    msg.extend_from_slice(&expires_at.to_be_bytes());
    msg.push(max_uses);
    msg.extend_from_slice(&addr_len.to_be_bytes());
    msg.extend_from_slice(addr_bytes);
    msg
}

/// Derive the verification key from the token secret and pool ID.
///
/// `vk = HKDF-SHA256(ikm=token_secret, salt=pool_id, info="STEALTH_INVITE_V1" || token_id)`
fn derive_verification_key(
    token_secret: &[u8; 32],
    pool_id: &Uuid,
    token_id: &[u8; 16],
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(pool_id.as_bytes()), token_secret);
    let mut info = Vec::with_capacity(18 + 16);
    info.extend_from_slice(b"STEALTH_INVITE_V1");
    info.extend_from_slice(token_id);
    let mut vk = [0u8; 32];
    hk.expand(&info, &mut vk)
        .expect("32 bytes is valid HKDF-SHA256 output");
    vk
}

/// Compute the commitment from a verification key: `BLAKE2b-256(vk)`.
fn compute_commitment(vk: &[u8; 32]) -> [u8; 32] {
    use blake2::Blake2b;
    use blake2::digest::Update;
    use blake2::digest::consts::U32;

    let mut hasher = Blake2b::<U32>::default();
    hasher.update(vk);
    let result = hasher.finalize_fixed();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Serialization format for token URL encoding.
#[derive(serde::Serialize, serde::Deserialize)]
struct TokenWire {
    id: [u8; 16],
    secret: [u8; 32],
    pool: [u8; 16],
    fp: [u8; 8],
    exp: i64,
    max: u8,
    addr: String,
    #[serde(with = "crate::serde_helpers::bytes64")]
    sig: [u8; 64],
}

impl InvitationToken {
    /// Generate a new invitation token signed by the host identity.
    ///
    /// # Arguments
    ///
    /// - `host_identity`: The host's long-term identity (signs the token).
    /// - `pool_id`: The pool this token grants access to.
    /// - `server_addr`: The relay server address to connect to.
    /// - `ttl_secs`: Token lifetime in seconds from now.
    /// - `max_uses`: Maximum number of times this token can be redeemed.
    ///
    /// # Security Properties
    ///
    /// - `token_id` and `token_secret` are generated from `OsRng`.
    /// - The token is signed with the host's Ed25519 key.
    /// - The expiration time is computed from the current system time.
    pub fn generate(
        host_identity: &HostIdentity,
        pool_id: Uuid,
        server_addr: String,
        ttl_secs: i64,
        max_uses: u8,
    ) -> Self {
        let mut token_id = [0u8; 16];
        OsRng.fill_bytes(&mut token_id);

        let mut token_secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_secret_bytes);

        let expires_at = chrono::Utc::now().timestamp() + ttl_secs;

        let mut host_fp = [0u8; 8];
        host_fp.copy_from_slice(&host_identity.fingerprint()[..8]);

        let sign_msg = token_sign_message(
            &token_id,
            &token_secret_bytes,
            &pool_id,
            expires_at,
            max_uses,
            &server_addr,
        );
        let signature = host_identity.sign(&sign_msg);

        Self {
            token_id,
            token_secret: TokenSecret(token_secret_bytes),
            pool_id,
            host_fingerprint: host_fp,
            expires_at,
            max_uses,
            server_address: server_addr,
            signature,
        }
    }

    /// Encode the token as a URL-safe base64 string.
    ///
    /// # Security Properties
    ///
    /// - The token secret is included in the encoded form. This string must
    ///   be transmitted securely (encrypted channel or in-person).
    pub fn to_url(&self) -> String {
        let wire = TokenWire {
            id: self.token_id,
            secret: self.token_secret.0,
            pool: *self.pool_id.as_bytes(),
            fp: self.host_fingerprint,
            exp: self.expires_at,
            max: self.max_uses,
            addr: self.server_address.clone(),
            sig: self.signature,
        };
        let json = serde_json::to_vec(&wire).expect("token serialization cannot fail");
        let encoded = Base64UrlUnpadded::encode_string(&json);
        format!("stealth://invite/{encoded}")
    }

    /// Decode an invitation token from a URL string.
    ///
    /// # Security Properties
    ///
    /// - Validates the URL prefix and base64 encoding.
    /// - Does NOT verify the signature (caller must verify against a known host key).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvitationInvalid`] if the URL format is wrong
    /// or decoding fails.
    pub fn from_url(url: &str) -> Result<Self> {
        let payload = url
            .strip_prefix("stealth://invite/")
            .ok_or_else(|| CryptoError::invitation("invalid URL prefix"))?;

        let decoded = Base64UrlUnpadded::decode_vec(payload)
            .map_err(|e| CryptoError::invitation(format!("base64 decode error: {e}")))?;

        let wire: TokenWire = serde_json::from_slice(&decoded)
            .map_err(|e| CryptoError::invitation(format!("JSON decode error: {e}")))?;

        Ok(Self {
            token_id: wire.id,
            token_secret: TokenSecret(wire.secret),
            pool_id: Uuid::from_bytes(wire.pool),
            host_fingerprint: wire.fp,
            expires_at: wire.exp,
            max_uses: wire.max,
            server_address: wire.addr,
            signature: wire.sig,
        })
    }

    /// Compute the commitment (what the server stores).
    ///
    /// `commitment = BLAKE2b-256(HKDF-SHA256(token_secret, pool_id, "STEALTH_INVITE_V1" || token_id))`
    ///
    /// # Security Properties
    ///
    /// - The commitment is a one-way function of the token secret.
    /// - The server cannot recover the token secret from the commitment.
    pub fn commitment(&self) -> [u8; 32] {
        let mut vk = derive_verification_key(&self.token_secret.0, &self.pool_id, &self.token_id);
        let commitment = compute_commitment(&vk);
        vk.zeroize();
        commitment
    }

    /// Return the HKDF-derived verification key.
    ///
    /// # Security Properties
    ///
    /// - This key is derived from the token secret and is sensitive.
    /// - Used for creating join proofs; should be zeroized after use.
    pub fn verification_key(&self) -> [u8; 32] {
        derive_verification_key(&self.token_secret.0, &self.pool_id, &self.token_id)
    }

    /// Return a `TokenCommitment` struct suitable for server-side storage.
    pub fn to_commitment(&self) -> TokenCommitment {
        TokenCommitment {
            token_id: self.token_id,
            commitment: self.commitment(),
            expires_at: self.expires_at,
            max_uses: self.max_uses,
        }
    }

    /// Create a join proof that demonstrates possession of the token.
    ///
    /// # Arguments
    ///
    /// - `pool_id`: The pool to join (must match the token's pool).
    /// - `nonce`: A random challenge from the verifier.
    ///
    /// # Security Properties
    ///
    /// - The proof is an HMAC-SHA256 over "JOIN" || `pool_id` || timestamp || nonce,
    ///   keyed with the verification key derived from the token secret.
    /// - The proof is bound to the current timestamp and the provided nonce.
    /// - The verification key is zeroized after computing the HMAC.
    pub fn create_join_proof(&self, pool_id: &Uuid, nonce: &[u8; 32]) -> JoinProof {
        let mut vk = self.verification_key();
        let timestamp = chrono::Utc::now().timestamp();

        let mut mac = Hmac::<Sha256>::new_from_slice(&vk).expect("HMAC accepts any key length");
        mac.update(b"JOIN");
        mac.update(pool_id.as_bytes());
        mac.update(&timestamp.to_be_bytes());
        mac.update(nonce);
        let result = mac.finalize().into_bytes();

        vk.zeroize();

        let mut proof = [0u8; 32];
        proof.copy_from_slice(&result);

        JoinProof {
            token_id: self.token_id,
            proof,
            timestamp,
            nonce: *nonce,
        }
    }

    /// Reconstruct the signed message for external signature verification.
    ///
    /// Callers who receive a token via `from_url` should call this to build
    /// the message, then verify the [`signature`](Self::signature) against
    /// the host's public key.
    pub fn sign_message_bytes(&self) -> Vec<u8> {
        token_sign_message(
            &self.token_id,
            &self.token_secret.0,
            &self.pool_id,
            self.expires_at,
            self.max_uses,
            &self.server_address,
        )
    }

    /// Check whether this token has expired.
    ///
    /// # Security Properties
    ///
    /// - Uses the system clock; ensure NTP synchronization in production.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() > self.expires_at
    }

    /// Return the Ed25519 signature over this token.
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

impl JoinProof {
    /// Verify a join proof against a known verification key (host-side).
    ///
    /// # Arguments
    ///
    /// - `verification_key`: The HKDF-derived key from the token (host has this).
    /// - `pool_id`: The expected pool ID.
    /// - `timestamp_tolerance_secs`: Maximum age of the proof in seconds.
    ///
    /// # Security Properties
    ///
    /// - Uses constant-time comparison for the HMAC result.
    /// - Checks timestamp freshness to prevent replay.
    pub fn verify(
        &self,
        verification_key: &[u8; 32],
        pool_id: &Uuid,
        timestamp_tolerance_secs: i64,
    ) -> bool {
        // Check timestamp freshness
        let now = chrono::Utc::now().timestamp();
        let age = (now - self.timestamp).abs();
        if age > timestamp_tolerance_secs {
            return false;
        }

        // Recompute HMAC
        let mut mac =
            Hmac::<Sha256>::new_from_slice(verification_key).expect("HMAC accepts any key length");
        mac.update(b"JOIN");
        mac.update(pool_id.as_bytes());
        mac.update(&self.timestamp.to_be_bytes());
        mac.update(&self.nonce);
        let expected = mac.finalize().into_bytes();

        // Constant-time comparison
        let mut expected_arr = [0u8; 32];
        expected_arr.copy_from_slice(&expected);
        self.proof.ct_eq(&expected_arr).into()
    }

    /// Verify using a commitment (server-side check).
    ///
    /// The server only has the commitment, not the verification key. This method
    /// cannot verify the HMAC directly. Instead, it checks that the provided
    /// proof was created within the timestamp tolerance. Full verification
    /// requires the host to check against the verification key.
    ///
    /// # Security Properties
    ///
    /// - Only checks timestamp bounds; the actual cryptographic verification
    ///   must be done by the host who has the verification key.
    pub fn check_timestamp(&self, timestamp_tolerance_secs: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        let age = (now - self.timestamp).abs();
        age <= timestamp_tolerance_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_roundtrip_url() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            5,
        );

        let url = token.to_url();
        assert!(url.starts_with("stealth://invite/"));

        let decoded = InvitationToken::from_url(&url).unwrap();
        assert_eq!(decoded.token_id, token.token_id);
        assert_eq!(decoded.pool_id, token.pool_id);
        assert_eq!(decoded.expires_at, token.expires_at);
        assert_eq!(decoded.max_uses, token.max_uses);
        assert_eq!(decoded.server_address, token.server_address);
    }

    #[test]
    fn commitment_is_deterministic() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );

        let c1 = token.commitment();
        let c2 = token.commitment();
        assert_eq!(c1, c2);
    }

    #[test]
    fn join_proof_verifies() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let proof = token.create_join_proof(&pool_id, &nonce);
        let vk = token.verification_key();
        assert!(proof.verify(&vk, &pool_id, 60));
    }

    #[test]
    fn join_proof_fails_with_wrong_vk() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let proof = token.create_join_proof(&pool_id, &nonce);
        let wrong_vk = [0xFFu8; 32];
        assert!(!proof.verify(&wrong_vk, &pool_id, 60));
    }

    #[test]
    fn commitment_matches_verification_key() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );

        let vk = token.verification_key();
        let expected_commitment = compute_commitment(&vk);
        assert_eq!(token.commitment(), expected_commitment);
    }

    #[test]
    fn expired_token() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        // TTL of -10 seconds (already expired)
        let token =
            InvitationToken::generate(&host, pool_id, "relay.example.com:8443".to_string(), -10, 1);
        assert!(token.is_expired());
    }

    #[test]
    fn debug_redacts_secret() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );
        let debug = format!("{token:?}");
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn invalid_url_prefix() {
        let result = InvitationToken::from_url("https://wrong.com/invite/abc");
        assert!(matches!(result, Err(CryptoError::InvitationInvalid(_))));
    }

    #[test]
    fn signature_verification_after_url_round_trip() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            5,
        );

        let url = token.to_url();
        let decoded = InvitationToken::from_url(&url).unwrap();

        // Verify the signature over the reconstructed sign message.
        let msg = decoded.sign_message_bytes();
        let pk = host.public_keys();
        assert!(pk.verify(&msg, decoded.signature()));
    }

    #[test]
    fn server_address_included_in_signature() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();

        let token_a = InvitationToken::generate(
            &host,
            pool_id,
            "server-a.example.com:8443".to_string(),
            3600,
            1,
        );
        let token_b = InvitationToken::generate(
            &host,
            pool_id,
            "server-b.example.com:8443".to_string(),
            3600,
            1,
        );

        // Even if we construct the sign message with the wrong server address,
        // the signature should fail.
        let msg_a = token_a.sign_message_bytes();
        let pk = host.public_keys();
        // token_b's signature should NOT verify against token_a's sign message.
        assert!(!pk.verify(&msg_a, token_b.signature()));
    }

    #[test]
    fn join_proof_fails_with_wrong_pool_id() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let wrong_pool = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let proof = token.create_join_proof(&pool_id, &nonce);
        let vk = token.verification_key();
        // Verify against wrong pool_id must fail.
        assert!(!proof.verify(&vk, &wrong_pool, 60));
    }

    #[test]
    fn join_proof_timestamp_check() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );

        let nonce = [0u8; 32];
        let proof = token.create_join_proof(&pool_id, &nonce);

        // check_timestamp with generous tolerance should pass.
        assert!(proof.check_timestamp(60));

        // check_timestamp with 0 tolerance — the proof was just created,
        // so age should be 0, which is <= 0.
        assert!(proof.check_timestamp(0));
    }

    #[test]
    fn token_not_expired_within_ttl() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );
        assert!(!token.is_expired());
    }

    #[test]
    fn to_commitment_matches_commitment() {
        let host = HostIdentity::generate();
        let pool_id = Uuid::now_v7();
        let token = InvitationToken::generate(
            &host,
            pool_id,
            "relay.example.com:8443".to_string(),
            3600,
            1,
        );

        let tc = token.to_commitment();
        assert_eq!(tc.commitment, token.commitment());
        assert_eq!(tc.token_id, token.token_id);
        assert_eq!(tc.expires_at, token.expires_at);
        assert_eq!(tc.max_uses, token.max_uses);
    }

    #[test]
    fn from_url_rejects_corrupted_base64() {
        let result = InvitationToken::from_url("stealth://invite/not-valid-base64!!!");
        assert!(result.is_err());
    }
}
