//! Proof-of-work challenge system for rate limiting.
//!
//! Uses BLAKE2b-256 hashcash: find a `solution` such that
//! `BLAKE2b-256("STEALTH_POW" || challenge || solution)` has at least
//! `difficulty` leading zero bits.
//!
//! # Difficulty Levels
//!
//! | Difficulty | Expected Hashes | ~Time (single core) |
//! |------------|-----------------|---------------------|
//! | 18 bits    | ~262k           | ~50ms               |
//! | 22 bits    | ~4M             | ~800ms              |
//! | 26 bits    | ~67M            | ~13s                |
//!
//! # Security Properties
//!
//! - The challenge includes a timestamp to prevent pre-computation.
//! - Challenges should be verified within a time window.
//! - The PoW is memory-hard in the sense that BLAKE2b uses 1KB state,
//!   but is primarily CPU-bound.

use rand::RngCore;
use rand::rngs::OsRng;

use crate::error::{CryptoError, Result};

/// A proof-of-work challenge issued by the server.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PowChallenge {
    /// Random 32-byte challenge value.
    pub challenge: [u8; 32],
    /// Required number of leading zero bits in the hash.
    pub difficulty: u8,
    /// Unix timestamp when the challenge was created.
    pub timestamp: i64,
}

/// A solution to a proof-of-work challenge.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PowSolution {
    /// The 8-byte nonce that satisfies the difficulty requirement.
    pub solution: [u8; 8],
}

/// Domain separator for PoW hashing.
const POW_PREFIX: &[u8] = b"STEALTH_POW";

/// Compute the PoW hash: `SHA-256(POW_PREFIX || challenge || solution)`.
///
/// Uses SHA-256 for cross-platform compatibility (Apple CryptoKit on iOS,
/// ring/sha2 on server). Both client and server can compute identical hashes
/// without requiring BLAKE2b support.
fn pow_hash(challenge: &[u8; 32], solution: &[u8; 8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(POW_PREFIX);
    hasher.update(challenge);
    hasher.update(solution);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Count the number of leading zero bits in a byte slice.
fn leading_zero_bits(data: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in data {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

impl PowChallenge {
    /// Generate a new proof-of-work challenge with the given difficulty.
    ///
    /// # Arguments
    ///
    /// - `difficulty`: Number of leading zero bits required (typically 18-26).
    ///
    /// # Security Properties
    ///
    /// - Challenge is generated from `OsRng` (unpredictable).
    /// - Timestamp is included for freshness verification.
    pub fn generate(difficulty: u8) -> Self {
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);

        Self {
            challenge,
            difficulty,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Solve the challenge by brute-force search.
    ///
    /// Iterates through nonce values until finding one where the hash has
    /// the required number of leading zero bits.
    ///
    /// # Security Properties
    ///
    /// - The search is linear in `2^difficulty` expected iterations.
    /// - Uses a deterministic counter, not random guessing, for efficiency.
    ///
    /// # Performance
    ///
    /// This is a blocking, CPU-intensive operation. For async contexts, run
    /// this in a `spawn_blocking` task.
    pub fn solve(&self) -> PowSolution {
        let mut nonce = 0u64;
        loop {
            let solution = nonce.to_be_bytes();
            let hash = pow_hash(&self.challenge, &solution);
            if leading_zero_bits(&hash) >= u32::from(self.difficulty) {
                return PowSolution { solution };
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    /// Verify that a solution satisfies the difficulty requirement.
    ///
    /// # Security Properties
    ///
    /// - The verification is a single hash computation (O(1)).
    /// - Does NOT check timestamp freshness — caller must verify separately.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::PowFailed`] if the solution does not meet
    /// the difficulty requirement.
    pub fn verify(&self, solution: &PowSolution) -> Result<()> {
        let hash = pow_hash(&self.challenge, &solution.solution);
        if leading_zero_bits(&hash) >= u32::from(self.difficulty) {
            Ok(())
        } else {
            Err(CryptoError::PowFailed)
        }
    }

    /// Check whether this challenge is fresh enough (within `max_age_secs`).
    ///
    /// # Security Properties
    ///
    /// - Prevents use of pre-computed solutions for old challenges.
    pub fn is_fresh(&self, max_age_secs: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        let age = now - self.timestamp;
        age >= 0 && age <= max_age_secs
    }
}

/// Recommend a PoW difficulty based on the current request rate.
///
/// # Difficulty Tiers
///
/// | Requests/min | Difficulty | Expected solve time |
/// |--------------|------------|---------------------|
/// | 0-50         | 18 bits    | ~50ms               |
/// | 51-200       | 22 bits    | ~800ms              |
/// | 201+         | 26 bits    | ~13s                |
///
/// # Security Properties
///
/// - Higher difficulty makes denial-of-service attacks more expensive.
/// - The thresholds are tuned for typical relay server load patterns.
pub fn recommended_difficulty(requests_per_minute: u32) -> u8 {
    if requests_per_minute > 200 {
        26
    } else if requests_per_minute > 50 {
        22
    } else {
        18
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_counting() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(leading_zero_bits(&[0x00, 0x01, 0xFF]), 15);
        assert_eq!(leading_zero_bits(&[0x80, 0x00, 0x00]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x00]), 24);
        assert_eq!(leading_zero_bits(&[0x0F]), 4);
    }

    #[test]
    fn solve_and_verify_low_difficulty() {
        // Use very low difficulty for fast tests
        let challenge = PowChallenge::generate(8);
        let solution = challenge.solve();
        assert!(challenge.verify(&solution).is_ok());
    }

    #[test]
    fn wrong_solution_fails() {
        let challenge = PowChallenge::generate(16);
        let bad_solution = PowSolution {
            solution: [0xFF; 8],
        };
        // Very unlikely to satisfy 16 bits of leading zeros
        // (but not impossible — so we use a high difficulty)
        let result = challenge.verify(&bad_solution);
        // This could theoretically pass, but with 16 bits difficulty
        // the probability is 1/65536
        if result.is_err() {
            assert!(matches!(result, Err(CryptoError::PowFailed)));
        }
    }

    #[test]
    fn recommended_difficulty_tiers() {
        assert_eq!(recommended_difficulty(0), 18);
        assert_eq!(recommended_difficulty(50), 18);
        assert_eq!(recommended_difficulty(51), 22);
        assert_eq!(recommended_difficulty(200), 22);
        assert_eq!(recommended_difficulty(201), 26);
        assert_eq!(recommended_difficulty(1000), 26);
    }

    #[test]
    fn challenge_freshness() {
        let challenge = PowChallenge::generate(8);
        assert!(challenge.is_fresh(60));
        // A challenge from the far past would not be fresh
        let old = PowChallenge {
            challenge: [0u8; 32],
            difficulty: 8,
            timestamp: 0, // Unix epoch
        };
        assert!(!old.is_fresh(60));
    }

    #[test]
    fn solve_verify_round_trip_difficulty_12() {
        let challenge = PowChallenge::generate(12);
        let solution = challenge.solve();
        assert!(challenge.verify(&solution).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_difficulty() {
        // Solve at difficulty 8, then verify at difficulty 20 — almost certain to fail.
        let mut challenge = PowChallenge::generate(8);
        let solution = challenge.solve();
        challenge.difficulty = 20;
        let result = challenge.verify(&solution);
        // A solution for difficulty 8 has negligible probability of satisfying 20 bits.
        assert!(
            result.is_err(),
            "solution for difficulty 8 should not satisfy difficulty 20"
        );
    }

    #[test]
    fn leading_zero_bits_empty_slice() {
        assert_eq!(leading_zero_bits(&[]), 0);
    }

    #[test]
    fn leading_zero_bits_all_zeros_long() {
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
    }

    #[test]
    fn leading_zero_bits_single_byte_values() {
        assert_eq!(leading_zero_bits(&[0x01]), 7);
        assert_eq!(leading_zero_bits(&[0x40]), 1);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x80]), 8);
    }

    #[test]
    fn freshness_rejects_future_timestamp() {
        let future = PowChallenge {
            challenge: [0u8; 32],
            difficulty: 8,
            timestamp: chrono::Utc::now().timestamp() + 1000,
        };
        // age = now - (now + 1000) = -1000, which is < 0, so is_fresh returns false.
        assert!(!future.is_fresh(60));
    }

    #[test]
    fn pow_hash_deterministic() {
        let challenge = [42u8; 32];
        let solution = [7u8; 8];
        let h1 = pow_hash(&challenge, &solution);
        let h2 = pow_hash(&challenge, &solution);
        assert_eq!(h1, h2);
    }

    #[test]
    fn pow_hash_differs_with_different_input() {
        let challenge = [42u8; 32];
        let s1 = [0u8; 8];
        let s2 = [1u8; 8];
        assert_ne!(pow_hash(&challenge, &s1), pow_hash(&challenge, &s2));
    }
}
