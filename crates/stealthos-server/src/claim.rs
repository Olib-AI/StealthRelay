//! Server claiming -- binds a host's Ed25519 public key to this server instance.
//!
//! On first boot (no host bound), the server generates a one-time claim secret
//! and displays it as an ASCII banner in the logs. The server operator copies
//! this code into the StealthOS app to claim ownership.
//!
//! After a successful claim the secret is zeroized from memory and the binding
//! is persisted to `host_binding.json`. All future `HostAuth` frames must come
//! from the bound host key.

use std::path::Path;
use std::time::Instant;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::warn;
use zeroize::Zeroize;

/// Binding file name within the key directory.
const BINDING_FILENAME: &str = "host_binding.json";

/// Maximum claim attempts before the server blocks for a cooldown period.
const MAX_CLAIM_ATTEMPTS: u32 = 3;

/// Cooldown duration after exceeding the claim attempt limit (10 minutes).
const CLAIM_COOLDOWN_SECS: u64 = 600;

/// Persistent host binding -- saved to disk after successful claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostBinding {
    /// The bound host's Ed25519 public key (32 bytes, hex-encoded).
    pub host_public_key: String,
    /// When the server was claimed (RFC 3339).
    pub claimed_at: String,
    /// Server fingerprint at time of claim.
    pub server_fingerprint: String,
    /// BLAKE2b-256 hash of the recovery key (hex-encoded).
    /// The raw recovery key is shown to the user ONCE at claim time and never stored.
    #[serde(default)]
    pub recovery_key_hash: String,
}

/// Errors that can occur during the claim process.
#[derive(Debug)]
pub enum ClaimError {
    /// The server is already claimed by a different host key.
    AlreadyClaimed,
    /// The provided claim secret does not match.
    InvalidSecret,
    /// Too many failed claim attempts; the server is in cooldown.
    RateLimited,
    /// Filesystem error when persisting the binding.
    Io(std::io::Error),
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyClaimed => write!(f, "server is already claimed"),
            Self::InvalidSecret => write!(f, "invalid claim secret"),
            Self::RateLimited => write!(f, "too many failed attempts, try again later"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

/// Tracks rate-limiting state for claim attempts.
pub(crate) struct ClaimRateLimiter {
    /// Number of failed attempts since last reset.
    failed_attempts: u32,
    /// When the cooldown started (if active).
    cooldown_start: Option<Instant>,
}

impl ClaimRateLimiter {
    const fn new() -> Self {
        Self {
            failed_attempts: 0,
            cooldown_start: None,
        }
    }

    /// Check if a claim attempt is allowed. Returns `Err(ClaimError::RateLimited)`
    /// if the caller must wait.
    fn check(&mut self) -> Result<(), ClaimError> {
        if let Some(start) = self.cooldown_start {
            if start.elapsed().as_secs() < CLAIM_COOLDOWN_SECS {
                return Err(ClaimError::RateLimited);
            }
            // Cooldown expired -- reset.
            self.failed_attempts = 0;
            self.cooldown_start = None;
        }
        Ok(())
    }

    /// Record a failed attempt. Activates cooldown if the limit is exceeded.
    fn record_failure(&mut self) {
        self.failed_attempts += 1;
        if self.failed_attempts >= MAX_CLAIM_ATTEMPTS {
            self.cooldown_start = Some(Instant::now());
        }
    }

    /// Reset on successful claim.
    fn reset(&mut self) {
        self.failed_attempts = 0;
        self.cooldown_start = None;
    }
}

/// Server claim state machine.
pub enum ClaimState {
    /// No host bound yet -- waiting for claim with this secret.
    Unclaimed {
        /// The one-time claim secret. Zeroized after successful claim.
        claim_secret: [u8; 32],
        /// Rate limiter for claim attempts.
        rate_limiter: ClaimRateLimiter,
    },
    /// Host is bound -- only this key can authenticate.
    Claimed {
        /// The persisted binding.
        binding: HostBinding,
    },
}

impl ClaimState {
    /// Load an existing binding from disk, or generate a new claim secret.
    ///
    /// If `host_binding.json` exists in `key_dir`, the server starts in
    /// `Claimed` state. Otherwise, a 32-byte claim secret is generated
    /// from `OsRng` and the server starts in `Unclaimed` state.
    pub fn load_or_create(key_dir: &Path) -> Self {
        let binding_path = key_dir.join(BINDING_FILENAME);

        if binding_path.exists() {
            match std::fs::read_to_string(&binding_path) {
                Ok(contents) => match serde_json::from_str::<HostBinding>(&contents) {
                    Ok(binding) => {
                        return Self::Claimed { binding };
                    }
                    Err(e) => {
                        warn!(
                            path = %binding_path.display(),
                            "failed to parse host binding file, treating as unclaimed: {e}"
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        path = %binding_path.display(),
                        "failed to read host binding file, treating as unclaimed: {e}"
                    );
                }
            }
        }

        let mut claim_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut claim_secret);

        Self::Unclaimed {
            claim_secret,
            rate_limiter: ClaimRateLimiter::new(),
        }
    }

    /// Attempt to claim the server with a secret and host public key.
    ///
    /// On success, the binding is saved to disk and the claim secret is
    /// zeroized from memory. The state transitions to `Claimed`.
    ///
    /// Uses `subtle::ConstantTimeEq` for the secret comparison to prevent
    /// timing side-channel attacks.
    /// Attempt to claim the server with a secret and host public key.
    ///
    /// On success:
    /// - A 32-byte recovery key is generated and returned (shown to user ONCE)
    /// - Only the BLAKE2b-256 hash of the recovery key is stored on disk
    /// - The claim secret is zeroized from memory
    /// - The state transitions to `Claimed`
    ///
    /// Uses `subtle::ConstantTimeEq` for the secret comparison.
    pub fn try_claim(
        &mut self,
        provided_secret: &[u8; 32],
        host_public_key: &[u8; 32],
        key_dir: &Path,
        server_fingerprint: &str,
    ) -> Result<(HostBinding, [u8; 32]), ClaimError> {
        match self {
            Self::Claimed { .. } => Err(ClaimError::AlreadyClaimed),
            Self::Unclaimed {
                claim_secret,
                rate_limiter,
            } => {
                rate_limiter.check()?;

                let secrets_match: bool = claim_secret.ct_eq(provided_secret).into();

                if !secrets_match {
                    rate_limiter.record_failure();
                    warn!("claim attempt with invalid secret");
                    return Err(ClaimError::InvalidSecret);
                }

                // Generate a recovery key for the owner (shown ONCE, never stored raw).
                let mut recovery_key = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut recovery_key);
                let recovery_key_hash = hash_recovery_key(&recovery_key);

                let binding = HostBinding {
                    host_public_key: hex_encode(host_public_key),
                    claimed_at: chrono::Utc::now().to_rfc3339(),
                    server_fingerprint: server_fingerprint.to_owned(),
                    recovery_key_hash: hex_encode(&recovery_key_hash),
                };

                save_binding(key_dir, &binding)?;
                rate_limiter.reset();
                claim_secret.zeroize();

                let result = binding.clone();
                *self = Self::Claimed { binding };

                warn!(
                    host_key = %result.host_public_key,
                    "server successfully claimed — recovery key issued"
                );

                // Print the READY banner now that the server is claimed.
                print_ready_banner(&result.host_public_key);

                Ok((result, recovery_key))
            }
        }
    }

    /// Reclaim the server using the recovery key.
    ///
    /// This allows the owner to rebind a new host public key if they lose
    /// access to the original device. The recovery key is verified against
    /// the stored BLAKE2b-256 hash using constant-time comparison.
    ///
    /// On success, the binding is updated with the new host key and a NEW
    /// recovery key is generated (the old one is invalidated).
    pub fn try_reclaim(
        &mut self,
        recovery_key: &[u8; 32],
        new_host_public_key: &[u8; 32],
        key_dir: &Path,
    ) -> Result<(HostBinding, [u8; 32]), ClaimError> {
        match self {
            Self::Unclaimed { .. } => Err(ClaimError::InvalidSecret),
            Self::Claimed { binding } => {
                // Verify the recovery key against stored hash.
                let provided_hash = hash_recovery_key(recovery_key);
                let stored_hash = hex_decode(&binding.recovery_key_hash).unwrap_or_default();

                if stored_hash.len() != 32 {
                    warn!("reclaim failed: corrupted recovery key hash on disk");
                    return Err(ClaimError::InvalidSecret);
                }

                let hashes_match: bool = provided_hash.ct_eq(stored_hash.as_slice()).into();

                if !hashes_match {
                    warn!("reclaim attempt with invalid recovery key");
                    return Err(ClaimError::InvalidSecret);
                }

                // Generate a NEW recovery key (old one is now invalid).
                let mut new_recovery_key = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut new_recovery_key);
                let new_recovery_hash = hash_recovery_key(&new_recovery_key);

                let new_binding = HostBinding {
                    host_public_key: hex_encode(new_host_public_key),
                    claimed_at: chrono::Utc::now().to_rfc3339(),
                    server_fingerprint: binding.server_fingerprint.clone(),
                    recovery_key_hash: hex_encode(&new_recovery_hash),
                };

                save_binding(key_dir, &new_binding)?;

                warn!(
                    old_host = %binding.host_public_key,
                    new_host = %new_binding.host_public_key,
                    "server reclaimed with recovery key — new recovery key issued"
                );

                let result = new_binding.clone();
                *self = Self::Claimed {
                    binding: new_binding,
                };

                Ok((result, new_recovery_key))
            }
        }
    }

    /// Check if a given public key (raw 32 bytes) is the bound host.
    pub fn is_bound_host(&self, public_key: &[u8; 32]) -> bool {
        match self {
            Self::Unclaimed { .. } => false,
            Self::Claimed { binding } => {
                let pk_hex = hex_encode(public_key);
                // Constant-time comparison for defense in depth.
                pk_hex
                    .as_bytes()
                    .ct_eq(binding.host_public_key.as_bytes())
                    .into()
            }
        }
    }

    /// Check if the server is claimed.
    pub const fn is_claimed(&self) -> bool {
        matches!(self, Self::Claimed { .. })
    }

    /// Get the claim secret for display (only valid in `Unclaimed` state).
    pub const fn claim_secret(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Unclaimed { claim_secret, .. } => Some(claim_secret),
            Self::Claimed { .. } => None,
        }
    }
}

/// Compute BLAKE2b-256 hash of a recovery key.
///
/// We store only the hash — the raw key is shown to the user once and never persisted.
fn hash_recovery_key(key: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::Digest;
    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    hasher.update(b"STEALTH_RECOVERY_KEY_V1");
    hasher.update(key);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Print the READY banner after successful claim.
pub fn print_ready_banner(host_key_hex: &str) {
    let short = if host_key_hex.len() >= 16 {
        &host_key_hex[..16]
    } else {
        host_key_hex
    };
    eprintln!();
    eprintln!("======================================================================");
    eprintln!("                       SERVER READY");
    eprintln!();
    eprintln!("  Server has been claimed and is ready to accept connections.");
    eprintln!("  Bound host: {short}...");
    eprintln!();
    eprintln!("======================================================================");
    eprintln!();
}

/// Save the host binding to disk with restrictive permissions.
fn save_binding(key_dir: &Path, binding: &HostBinding) -> Result<(), ClaimError> {
    let binding_path = key_dir.join(BINDING_FILENAME);
    let json = serde_json::to_string_pretty(binding)
        .map_err(|e| ClaimError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    std::fs::write(&binding_path, json.as_bytes()).map_err(ClaimError::Io)?;

    // Set file permissions to 0600 (owner read/write only) on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&binding_path, perms).map_err(ClaimError::Io)?;
    }

    Ok(())
}

/// Encode bytes as lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        result.push(char::from(HEX_CHARS[(b >> 4) as usize]));
        result.push(char::from(HEX_CHARS[(b & 0x0f) as usize]));
    }
    result
}

/// Decode a hex string into bytes. Returns `None` on invalid input.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let high = hi.to_digit(16)?;
        let low = lo.to_digit(16)?;
        #[allow(clippy::cast_possible_truncation)]
        bytes.push((high as u8) << 4 | low as u8);
    }
    Some(bytes)
}

/// Render a QR code as pure Unicode — no ANSI escape codes.
///
/// Single char per module, half-blocks for vertical compression.
/// Inverted: dark = space, light = block.
fn render_qr_to_string(data: &str) -> String {
    use qrcode::{EcLevel, QrCode};
    use std::fmt::Write;

    let code = match QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L) {
        Ok(c) => c,
        Err(_) => return String::from("    [QR generation failed]\n"),
    };

    let w = code.width();
    let mut out = String::new();
    let q = 1_isize;

    let is_dark = |r: isize, c: isize| -> bool {
        if r < 0 || c < 0 || r >= w as isize || c >= w as isize {
            return false;
        }
        #[allow(clippy::cast_sign_loss)]
        {
            code[(c as usize, r as usize)] == qrcode::Color::Dark
        }
    };

    let mut r: isize = -q;
    #[allow(clippy::cast_possible_wrap)]
    while r < (w as isize) + q {
        let _ = write!(out, "    ");
        for c in -q..(w as isize) + q {
            let top = is_dark(r, c);
            let bot = is_dark(r + 1, c);
            let _ = write!(
                out,
                "{}",
                match (top, bot) {
                    (true, true) => ' ',
                    (true, false) => '▄',
                    (false, true) => '▀',
                    (false, false) => '█',
                }
            );
        }
        let _ = writeln!(out);
        r += 2;
    }

    out
}

/// Print the claim banner with a scannable QR code to stderr.
///
/// Builds the entire output as a single string and writes it with one
/// `eprint!` call to prevent async log lines from interleaving with
/// the QR code. The QR uses ANSI colors so it renders correctly on
/// both light and dark terminals.
pub fn print_claim_banner(claim_secret: &[u8; 32]) {
    use std::fmt::Write;

    let full_hex = hex_encode(claim_secret);

    // Format the FULL 64-char hex as XXXX-XXXX-... for manual entry.
    // All 64 chars are needed — the server requires the complete 32-byte secret.
    let formatted: String = full_hex
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("????"))
        .collect::<Vec<_>>()
        .join("-");

    let url = format!("stealth://claim/{full_hex}");

    // Build the entire banner as one string to write atomically.
    let mut banner = String::with_capacity(8192);

    let _ = writeln!(banner);
    let _ = writeln!(
        banner,
        "╔══════════════════════════════════════════════════════════╗"
    );
    let _ = writeln!(
        banner,
        "║              SERVER CLAIM REQUIRED                      ║"
    );
    let _ = writeln!(
        banner,
        "╠══════════════════════════════════════════════════════════╣"
    );
    let _ = writeln!(
        banner,
        "║                                                          ║"
    );
    let _ = writeln!(
        banner,
        "║  Scan the QR code below with StealthOS to claim this     ║"
    );
    let _ = writeln!(
        banner,
        "║  server, or enter the code manually in the app.          ║"
    );
    let _ = writeln!(
        banner,
        "║                                                          ║"
    );

    let _ = write!(banner, "{}", render_qr_to_string(&url));

    let _ = writeln!(banner);
    let _ = writeln!(banner, "  Manual code:");
    let _ = writeln!(banner, "  {formatted}");
    let _ = writeln!(banner);
    let _ = writeln!(
        banner,
        "  WARNING: ONE-TIME USE — destroyed after claiming."
    );
    let _ = writeln!(banner, "  Only the server operator should see this.");
    let _ = writeln!(banner);

    // Lock stderr and write the entire banner in one shot.
    // This prevents tracing log lines from interleaving.
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    let _ = std::io::Write::write_all(&mut lock, banner.as_bytes());
    let _ = std::io::Write::flush(&mut lock);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, "deadbeef01234567");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn hex_decode_invalid() {
        assert!(hex_decode("zz").is_none());
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn claim_state_unclaimed_flow() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path();

        let mut state = ClaimState::load_or_create(key_dir);
        assert!(!state.is_claimed());

        let secret = *state.claim_secret().unwrap();
        let host_key = [42u8; 32];

        // Wrong secret should fail.
        let wrong_secret = [0u8; 32];
        let result = state.try_claim(&wrong_secret, &host_key, key_dir, "test-fp");
        assert!(matches!(result, Err(ClaimError::InvalidSecret)));

        // Correct secret should succeed.
        let result = state.try_claim(&secret, &host_key, key_dir, "test-fp");
        assert!(result.is_ok());
        assert!(state.is_claimed());
        assert!(state.is_bound_host(&host_key));
        assert!(!state.is_bound_host(&[99u8; 32]));

        // Trying again should fail with AlreadyClaimed.
        let result = state.try_claim(&secret, &host_key, key_dir, "test-fp");
        assert!(matches!(result, Err(ClaimError::AlreadyClaimed)));
    }

    #[test]
    fn claim_state_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path();

        let mut state = ClaimState::load_or_create(key_dir);
        let secret = *state.claim_secret().unwrap();
        let host_key = [7u8; 32];
        state
            .try_claim(&secret, &host_key, key_dir, "fp-123")
            .unwrap();

        // Second boot: should load as claimed.
        let state2 = ClaimState::load_or_create(key_dir);
        assert!(state2.is_claimed());
        assert!(state2.is_bound_host(&host_key));
    }

    #[test]
    fn rate_limiting_kicks_in() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path();

        let mut state = ClaimState::load_or_create(key_dir);
        let host_key = [1u8; 32];
        let wrong = [0u8; 32];

        for _ in 0..MAX_CLAIM_ATTEMPTS {
            let _ = state.try_claim(&wrong, &host_key, key_dir, "fp");
        }

        let result = state.try_claim(&wrong, &host_key, key_dir, "fp");
        assert!(matches!(result, Err(ClaimError::RateLimited)));
    }

    #[test]
    fn binding_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path();

        let mut state = ClaimState::load_or_create(key_dir);
        let secret = *state.claim_secret().unwrap();
        let host_key = [55u8; 32];
        state.try_claim(&secret, &host_key, key_dir, "fp").unwrap();

        let binding_path = key_dir.join(BINDING_FILENAME);
        assert!(binding_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&binding_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "binding file should have 0600 permissions");
        }
    }

    #[test]
    fn print_banner_does_not_panic() {
        let secret = [0xab; 32];
        print_claim_banner(&secret);
    }

    #[test]
    fn reclaim_with_recovery_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path();

        let mut state = ClaimState::load_or_create(key_dir);
        let secret = *state.claim_secret().unwrap();
        let host_key = [10u8; 32];

        let (_, recovery_key) = state.try_claim(&secret, &host_key, key_dir, "fp").unwrap();
        assert!(state.is_claimed());

        // Reclaim with recovery key and a new host key.
        let new_host_key = [20u8; 32];
        let (binding, _new_recovery) = state
            .try_reclaim(&recovery_key, &new_host_key, key_dir)
            .unwrap();

        assert_eq!(binding.host_public_key, hex_encode(&new_host_key));
        assert!(state.is_bound_host(&new_host_key));
        assert!(!state.is_bound_host(&host_key)); // old key no longer bound
    }

    #[test]
    fn reclaim_with_wrong_recovery_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path();

        let mut state = ClaimState::load_or_create(key_dir);
        let secret = *state.claim_secret().unwrap();
        let host_key = [10u8; 32];
        state.try_claim(&secret, &host_key, key_dir, "fp").unwrap();

        let wrong_key = [0xFF; 32];
        let result = state.try_reclaim(&wrong_key, &[30u8; 32], key_dir);
        assert!(matches!(result, Err(ClaimError::InvalidSecret)));
    }

    #[test]
    fn reclaim_unclaimed_server_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path();

        let mut state = ClaimState::load_or_create(key_dir);
        let recovery = [0u8; 32];
        let result = state.try_reclaim(&recovery, &[1u8; 32], key_dir);
        assert!(matches!(result, Err(ClaimError::InvalidSecret)));
    }

    #[test]
    fn claim_secret_none_after_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path();

        let mut state = ClaimState::load_or_create(key_dir);
        assert!(state.claim_secret().is_some());

        let secret = *state.claim_secret().unwrap();
        state
            .try_claim(&secret, &[1u8; 32], key_dir, "fp")
            .unwrap();

        assert!(state.claim_secret().is_none());
    }

    #[test]
    fn rate_limiter_resets_on_success() {
        let mut rl = ClaimRateLimiter::new();
        rl.record_failure();
        rl.record_failure();
        assert!(rl.check().is_ok()); // not at limit yet (need 3)
        rl.reset();
        assert_eq!(rl.failed_attempts, 0);
        assert!(rl.cooldown_start.is_none());
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_decode_empty() {
        assert_eq!(hex_decode(""), Some(vec![]));
    }

    #[test]
    fn is_bound_host_unclaimed_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let state = ClaimState::load_or_create(dir.path());
        assert!(!state.is_bound_host(&[1u8; 32]));
    }
}
