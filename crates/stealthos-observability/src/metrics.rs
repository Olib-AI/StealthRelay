//! Simple atomic counters for server-wide metrics.
//!
//! No external metrics registry is needed for v1. The counters are
//! `AtomicU64` fields read with `Ordering::Relaxed` -- this is fine for
//! monotonic counters and gauges that tolerate slight staleness.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// Server-wide metric counters.
///
/// All fields are `AtomicU64` and can be shared via `Arc<ServerMetrics>`
/// across all connection tasks with zero contention.
pub struct ServerMetrics {
    /// Total connections accepted since server start.
    pub connections_total: AtomicU64,
    /// Currently active connections (gauge).
    pub connections_active: AtomicU64,
    /// Total messages relayed between peers.
    pub messages_relayed: AtomicU64,
    /// Total bytes relayed (sum of message payloads).
    pub messages_bytes: AtomicU64,
    /// Successful authentication attempts.
    pub auth_success: AtomicU64,
    /// Failed authentication attempts.
    pub auth_failure: AtomicU64,
    /// Invitation tokens created.
    pub invitations_created: AtomicU64,
    /// Invitation tokens consumed (used to join).
    pub invitations_consumed: AtomicU64,
    /// Requests rejected by rate limiting.
    pub rate_limit_hits: AtomicU64,
    /// Total pools created since server start.
    pub pools_created: AtomicU64,
    /// Currently active pools (gauge).
    pub pools_active: AtomicU64,
}

impl ServerMetrics {
    /// Create a new zeroed metrics set.
    pub const fn new() -> Self {
        Self {
            connections_total: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
            messages_relayed: AtomicU64::new(0),
            messages_bytes: AtomicU64::new(0),
            auth_success: AtomicU64::new(0),
            auth_failure: AtomicU64::new(0),
            invitations_created: AtomicU64::new(0),
            invitations_consumed: AtomicU64::new(0),
            rate_limit_hits: AtomicU64::new(0),
            pools_created: AtomicU64::new(0),
            pools_active: AtomicU64::new(0),
        }
    }

    /// Render all counters in Prometheus text exposition format.
    ///
    /// Each metric is prefixed with `stealth_relay_` and annotated with
    /// `# HELP` and `# TYPE` lines.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        write_metric(
            &mut out,
            "stealth_relay_connections_total",
            "Total WebSocket connections accepted",
            "counter",
            self.connections_total.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_connections_active",
            "Currently active WebSocket connections",
            "gauge",
            self.connections_active.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_messages_relayed_total",
            "Total messages relayed between peers",
            "counter",
            self.messages_relayed.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_messages_bytes_total",
            "Total bytes relayed",
            "counter",
            self.messages_bytes.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_auth_success_total",
            "Successful authentication attempts",
            "counter",
            self.auth_success.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_auth_failure_total",
            "Failed authentication attempts",
            "counter",
            self.auth_failure.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_invitations_created_total",
            "Invitation tokens created",
            "counter",
            self.invitations_created.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_invitations_consumed_total",
            "Invitation tokens consumed",
            "counter",
            self.invitations_consumed.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_rate_limit_hits_total",
            "Requests rejected by rate limiter",
            "counter",
            self.rate_limit_hits.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_pools_created_total",
            "Total connection pools created",
            "counter",
            self.pools_created.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "stealth_relay_pools_active",
            "Currently active connection pools",
            "gauge",
            self.pools_active.load(Ordering::Relaxed),
        );

        out
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Append a single Prometheus metric block to `out`.
fn write_metric(out: &mut String, name: &str, help: &str, metric_type: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
    let _ = writeln!(out, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_format_is_valid() {
        let m = ServerMetrics::new();
        m.connections_total.store(42, Ordering::Relaxed);
        m.pools_active.store(3, Ordering::Relaxed);

        let output = m.to_prometheus();
        assert!(output.contains("stealth_relay_connections_total 42"));
        assert!(output.contains("stealth_relay_pools_active 3"));
        assert!(output.contains("# TYPE stealth_relay_connections_total counter"));
        assert!(output.contains("# TYPE stealth_relay_pools_active gauge"));
    }

    #[test]
    fn default_is_zeroed() {
        let m = ServerMetrics::default();
        assert_eq!(m.connections_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.messages_relayed.load(Ordering::Relaxed), 0);
    }
}
