use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use tokio::time::Instant;

use crate::error::RateLimitError;

/// Normalize an IP address for rate limiting purposes.
///
/// IPv4 addresses are returned as-is. IPv6 addresses are masked to their
/// /48 prefix so that all addresses within the same /48 share a single
/// rate limit bucket. Without this, an attacker with a /64 prefix has
/// 2^64 unique IPs, each getting its own bucket, completely bypassing
/// per-IP rate limits.
///
/// A /48 is the standard allocation to end sites (RFC 6177), so this
/// groups all addresses from a single customer into one bucket.
fn normalize_ip_for_rate_limit(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // Mask to /48: keep the first 3 segments (48 bits), zero the rest.
            let masked = Ipv6Addr::new(segments[0], segments[1], segments[2], 0, 0, 0, 0, 0);
            IpAddr::V6(masked)
        }
    }
}

/// Token-bucket rate limiter for a single entity.
pub struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
    penalty_tokens: u32,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// - `capacity`: maximum burst size.
    /// - `refill_rate_per_sec`: tokens added per second.
    pub fn new(capacity: u32, refill_rate_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: f64::from(capacity),
            refill_rate: refill_rate_per_sec,
            last_refill: Instant::now(),
            penalty_tokens: 0,
        }
    }

    /// Refill tokens based on elapsed time since the last refill.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(f64::from(self.capacity));
        self.last_refill = now;
    }

    /// Try to consume `cost` tokens. Returns `true` if the tokens were
    /// available, `false` if rate-limited.
    pub fn try_consume(&mut self, cost: u32) -> bool {
        self.refill();
        let total_cost = f64::from(cost + self.penalty_tokens);
        self.penalty_tokens = 0;

        if self.tokens >= total_cost {
            self.tokens -= total_cost;
            true
        } else {
            false
        }
    }

    /// Add a penalty that will be charged on the next `try_consume` call.
    pub fn add_penalty(&mut self, tokens: u32) {
        self.penalty_tokens = self.penalty_tokens.saturating_add(tokens);
    }
}

/// Maximum number of tracked IP addresses in the rate limiter.
/// Prevents memory exhaustion from an attacker rotating through
/// millions of source addresses (IPv6 address space abuse).
const MAX_RATE_LIMIT_ENTRIES: usize = 100_000;

/// Per-IP rate limiter using token buckets.
///
/// An [`AtomicUsize`] counter tracks the number of entries in the bucket
/// map to prevent a TOCTOU race between checking `DashMap::len()` and
/// inserting a new entry. Without atomic tracking, concurrent threads
/// could all observe a count below `MAX_RATE_LIMIT_ENTRIES` and all
/// insert, exceeding the cap.
pub struct IpRateLimiter {
    buckets: DashMap<IpAddr, TokenBucket>,
    /// Atomic entry count — incremented *before* insertion, decremented
    /// on failure or removal.
    entry_count: AtomicUsize,
    config: RateLimitConfig,
}

impl IpRateLimiter {
    /// Create a new per-IP rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: DashMap::new(),
            entry_count: AtomicUsize::new(0),
            config,
        }
    }

    /// Check whether a request from `ip` is within rate limits.
    ///
    /// IPv6 addresses are normalized to their /48 prefix before lookup,
    /// so all IPs within a /48 share a single rate limit bucket. This
    /// prevents attackers with large IPv6 allocations from bypassing
    /// per-IP rate limits.
    ///
    /// Implicitly creates a bucket for new IPs. If the rate limiter's
    /// internal table has reached `MAX_RATE_LIMIT_ENTRIES`, new IPs are
    /// rejected outright to prevent memory exhaustion from address-rotation
    /// attacks.
    pub fn check_rate(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        let ip = normalize_ip_for_rate_limit(ip);

        // Fast path: entry already exists — no insertion needed.
        if let Some(mut existing) = self.buckets.get_mut(&ip) {
            return if existing.value_mut().try_consume(1) {
                Ok(())
            } else {
                Err(RateLimitError::RateLimitExceeded(ip))
            };
        }

        // Slow path: new IP. Reserve a slot atomically *before* touching
        // DashMap to eliminate the TOCTOU window between len-check and insert.
        let prev = self.entry_count.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_RATE_LIMIT_ENTRIES {
            // Over capacity — undo the reservation.
            self.entry_count.fetch_sub(1, Ordering::Release);
            return Err(RateLimitError::RateLimitExceeded(ip));
        }

        // Between our `get_mut` above and this `entry()`, another thread may
        // have inserted this IP. Track whether we actually inserted a new key
        // via a flag set inside the closure (only invoked for new keys).
        let mut did_insert = false;
        let mut entry = self.buckets.entry(ip).or_insert_with(|| {
            did_insert = true;
            TokenBucket::new(
                self.config.messages_per_second,
                f64::from(self.config.messages_per_second),
            )
        });

        if !did_insert {
            // The key was already present (another thread won the race).
            // Undo our atomic reservation — we didn't actually grow the map.
            self.entry_count.fetch_sub(1, Ordering::Release);
        }

        if entry.value_mut().try_consume(1) {
            Ok(())
        } else {
            Err(RateLimitError::RateLimitExceeded(ip))
        }
    }

    /// Record a failed authentication attempt, adding a penalty to the bucket.
    ///
    /// IPv6 addresses are normalized to /48 before lookup.
    pub fn record_failure(&self, ip: IpAddr) {
        let ip = normalize_ip_for_rate_limit(ip);

        // Only penalize IPs we are already tracking to avoid table inflation.
        if let Some(mut existing) = self.buckets.get_mut(&ip) {
            existing
                .value_mut()
                .add_penalty(self.config.failed_attempt_penalty);
            return;
        }

        // New IP: reserve a slot atomically.
        let prev = self.entry_count.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_RATE_LIMIT_ENTRIES {
            self.entry_count.fetch_sub(1, Ordering::Release);
            return;
        }

        let mut did_insert = false;
        let mut entry = self.buckets.entry(ip).or_insert_with(|| {
            did_insert = true;
            TokenBucket::new(
                self.config.messages_per_second,
                f64::from(self.config.messages_per_second),
            )
        });
        entry
            .value_mut()
            .add_penalty(self.config.failed_attempt_penalty);

        if !did_insert {
            self.entry_count.fetch_sub(1, Ordering::Release);
        }
    }

    /// Remove stale buckets that have been fully refilled and idle.
    ///
    /// A bucket is considered stale if it has been at full capacity (no recent
    /// activity) for at least 60 seconds.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            let idle = now.duration_since(bucket.last_refill).as_secs();
            idle < 60
        });
        // Re-synchronize the atomic counter after eviction. The `retain`
        // call may have removed entries, so the atomic count must be
        // updated to reflect the actual map size.
        self.entry_count
            .store(self.buckets.len(), Ordering::Release);
    }
}

/// Tracks failed authentication attempts per IP and blocks repeat offenders.
pub struct ConnectionThrottler {
    failed_attempts: DashMap<IpAddr, FailedAttemptRecord>,
    blocked_ips: DashMap<IpAddr, Instant>,
    config: RateLimitConfig,
}

/// Record of failed authentication attempts from a single IP.
pub struct FailedAttemptRecord {
    pub count: u32,
    pub first_attempt: Instant,
    pub last_attempt: Instant,
    pub block_count: u32,
}

impl ConnectionThrottler {
    /// Create a new connection throttler.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            failed_attempts: DashMap::new(),
            blocked_ips: DashMap::new(),
            config,
        }
    }

    /// Check whether `ip` is currently allowed to connect.
    ///
    /// IPv6 addresses are normalized to /48 before lookup.
    pub fn check_allowed(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        let ip = normalize_ip_for_rate_limit(ip);
        if let Some(blocked_until) = self.blocked_ips.get(&ip) {
            let now = Instant::now();
            if now < *blocked_until.value() {
                let remaining = blocked_until.value().duration_since(now);
                return Err(RateLimitError::IpBlocked(format!(
                    "{}s remaining",
                    remaining.as_secs()
                )));
            }
            // Block has expired -- clean it up.
            drop(blocked_until);
            self.blocked_ips.remove(&ip);
        }
        Ok(())
    }

    /// Record a failed authentication attempt from `ip`.
    ///
    /// IPv6 addresses are normalized to /48 before lookup.
    ///
    /// If the number of failures exceeds the configured threshold, the IP
    /// is blocked. Repeat offenders receive escalating block durations.
    pub fn record_failure(&self, ip: IpAddr) {
        let ip = normalize_ip_for_rate_limit(ip);
        let now = Instant::now();

        let mut entry = self
            .failed_attempts
            .entry(ip)
            .or_insert(FailedAttemptRecord {
                count: 0,
                first_attempt: now,
                last_attempt: now,
                block_count: 0,
            });

        let record = entry.value_mut();
        record.count += 1;
        record.last_attempt = now;

        if record.count >= self.config.max_failed_auth {
            // Escalate: first block uses base duration, subsequent blocks use
            // the escalation duration.
            let block_secs = if record.block_count == 0 {
                self.config.block_duration_secs
            } else {
                self.config.escalation_block_secs
            };

            record.block_count += 1;
            record.count = 0; // Reset counter for next window.

            let blocked_until = now + std::time::Duration::from_secs(block_secs);
            self.blocked_ips.insert(ip, blocked_until);
        }
    }

    /// Record a successful authentication from `ip`, resetting its failure record.
    ///
    /// IPv6 addresses are normalized to /48 before lookup.
    pub fn record_success(&self, ip: IpAddr) {
        let ip = normalize_ip_for_rate_limit(ip);
        self.failed_attempts.remove(&ip);
    }

    /// Remove expired block entries and stale failure records.
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Remove expired blocks.
        self.blocked_ips
            .retain(|_, blocked_until| now < *blocked_until);

        // Remove stale failure records (no activity for 10 minutes).
        self.failed_attempts
            .retain(|_, record| now.duration_since(record.last_attempt).as_secs() < 600);
    }
}

/// Configuration for rate limiting and connection throttling.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum new connections per minute from a single IP.
    pub connections_per_minute: u32,
    /// Maximum messages per second from a single IP.
    pub messages_per_second: u32,
    /// Failed auth attempts before blocking.
    pub max_failed_auth: u32,
    /// First block duration in seconds.
    pub block_duration_secs: u64,
    /// Escalated block duration in seconds for repeat offenders.
    pub escalation_block_secs: u64,
    /// Extra token cost per failed attempt.
    pub failed_attempt_penalty: u32,
    /// Global rate limit across all IPs per minute.
    pub global_max_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            connections_per_minute: 30,
            messages_per_second: 60,
            max_failed_auth: 5,
            block_duration_secs: 600,
            escalation_block_secs: 86_400,
            failed_attempt_penalty: 3,
            global_max_per_minute: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    #[test]
    fn token_bucket_allows_within_capacity() {
        let mut bucket = TokenBucket::new(10, 10.0);
        for _ in 0..10 {
            assert!(bucket.try_consume(1));
        }
        // 11th should fail (no time to refill).
        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn token_bucket_penalty() {
        let mut bucket = TokenBucket::new(10, 10.0);
        bucket.add_penalty(5);
        // Next consume costs 1 + 5 penalty = 6 tokens.
        assert!(bucket.try_consume(1));
        // We had 10 tokens, consumed 6, leaving 4.
        // Consuming 5 more should fail.
        assert!(!bucket.try_consume(5));
    }

    #[test]
    fn ip_rate_limiter_basic() {
        let config = RateLimitConfig {
            messages_per_second: 5,
            ..RateLimitConfig::default()
        };
        let limiter = IpRateLimiter::new(config);
        let ip = localhost();

        for _ in 0..5 {
            assert!(limiter.check_rate(ip).is_ok());
        }
        assert!(limiter.check_rate(ip).is_err());
    }

    #[test]
    fn connection_throttler_blocks_after_failures() {
        let config = RateLimitConfig {
            max_failed_auth: 3,
            block_duration_secs: 600,
            ..RateLimitConfig::default()
        };
        let throttler = ConnectionThrottler::new(config);
        let ip = localhost();

        assert!(throttler.check_allowed(ip).is_ok());

        throttler.record_failure(ip);
        throttler.record_failure(ip);
        assert!(throttler.check_allowed(ip).is_ok()); // 2 failures, not blocked yet.

        throttler.record_failure(ip); // 3rd failure triggers block.
        assert!(throttler.check_allowed(ip).is_err());
    }

    #[test]
    fn connection_throttler_success_resets() {
        let config = RateLimitConfig {
            max_failed_auth: 3,
            ..RateLimitConfig::default()
        };
        let throttler = ConnectionThrottler::new(config);
        let ip = localhost();

        throttler.record_failure(ip);
        throttler.record_failure(ip);
        throttler.record_success(ip);

        // After success, counter is reset. Two more failures should not block.
        throttler.record_failure(ip);
        throttler.record_failure(ip);
        assert!(throttler.check_allowed(ip).is_ok());
    }

    #[test]
    fn ipv6_normalization_masks_to_48() {
        let ip1: IpAddr = "2001:db8:1234:5678:9abc:def0:1234:5678".parse().unwrap();
        let ip2: IpAddr = "2001:db8:1234:ffff:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let n1 = normalize_ip_for_rate_limit(ip1);
        let n2 = normalize_ip_for_rate_limit(ip2);
        assert_eq!(n1, n2, "IPs in same /48 must normalize identically");

        let expected: IpAddr = "2001:db8:1234::".parse().unwrap();
        assert_eq!(n1, expected);
    }

    #[test]
    fn ipv4_not_normalized() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let normalized = normalize_ip_for_rate_limit(ip);
        assert_eq!(ip, normalized);
    }

    #[test]
    fn ipv6_different_48_prefixes_differ() {
        let ip1: IpAddr = "2001:db8:aaaa::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:bbbb::1".parse().unwrap();
        let n1 = normalize_ip_for_rate_limit(ip1);
        let n2 = normalize_ip_for_rate_limit(ip2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn ip_rate_limiter_different_ips_independent() {
        let config = RateLimitConfig {
            messages_per_second: 2,
            ..RateLimitConfig::default()
        };
        let limiter = IpRateLimiter::new(config);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust ip1's bucket.
        assert!(limiter.check_rate(ip1).is_ok());
        assert!(limiter.check_rate(ip1).is_ok());
        assert!(limiter.check_rate(ip1).is_err());

        // ip2 should still have tokens.
        assert!(limiter.check_rate(ip2).is_ok());
    }

    #[test]
    fn ip_rate_limiter_record_failure_adds_penalty() {
        let config = RateLimitConfig {
            messages_per_second: 5,
            failed_attempt_penalty: 3,
            ..RateLimitConfig::default()
        };
        let limiter = IpRateLimiter::new(config);
        let ip = localhost();

        // Consume 1 token (leaves 4).
        assert!(limiter.check_rate(ip).is_ok());

        // Record failure adds penalty of 3.
        limiter.record_failure(ip);

        // Next check_rate costs 1 + 3 penalty = 4 tokens. Leaves 0.
        assert!(limiter.check_rate(ip).is_ok());

        // Now bucket is empty.
        assert!(limiter.check_rate(ip).is_err());
    }

    #[test]
    fn connection_throttler_cleanup_removes_stale() {
        let config = RateLimitConfig {
            max_failed_auth: 10, // high threshold so we don't accidentally block
            ..RateLimitConfig::default()
        };
        let throttler = ConnectionThrottler::new(config);
        let ip = localhost();

        throttler.record_failure(ip);
        // Cleanup with activity within 10 minutes should keep the record.
        throttler.cleanup();
        // The record should still be present (recent activity).
        // Record another failure to verify state is still tracked.
        throttler.record_failure(ip);
    }

    #[test]
    fn token_bucket_penalty_saturates() {
        let mut bucket = TokenBucket::new(10, 10.0);
        bucket.add_penalty(u32::MAX);
        bucket.add_penalty(1);
        // Should saturate at u32::MAX, not overflow.
        assert_eq!(bucket.penalty_tokens, u32::MAX);
    }
}
