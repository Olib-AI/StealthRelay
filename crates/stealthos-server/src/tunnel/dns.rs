//! Async DNS resolution for the tunnel gateway.
//!
//! Uses `tokio::net::lookup_host`, which delegates to the OS resolver. No
//! third-party DNS dependency. CNAME and TXT records are not directly
//! supported by `lookup_host`; they fall through to NXDOMAIN-equivalent
//! errors (the iOS agent's resolver should fall back to A/AAAA queries).

use std::net::SocketAddr;
use std::time::Duration;

use stealthos_core::server_frame::{
    DnsAnswer, DnsRecordType, TunnelDestination, TunnelDnsQueryData,
};
use tokio::time;

/// Internal resolver error.
#[derive(Debug, Clone, Copy)]
pub enum ResolveError {
    /// The DNS query timed out.
    Timeout,
    /// The name does not exist (or returned no records of the requested type).
    NotFound,
    /// The query was malformed (e.g. invalid hostname syntax).
    Invalid,
}

/// Resolve a `TunnelDestination` to one or more `SocketAddr` values.
pub async fn resolve_destination(
    destination: &TunnelDestination,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, ResolveError> {
    match destination {
        TunnelDestination::Hostname { host, port } => {
            if !is_valid_hostname(host) {
                return Err(ResolveError::Invalid);
            }
            let target = format!("{host}:{port}");
            resolve_with_timeout(&target, timeout).await
        }
        TunnelDestination::Ipv4 { address, port } => {
            let ip: std::net::Ipv4Addr = address.parse().map_err(|_| ResolveError::Invalid)?;
            Ok(vec![SocketAddr::from((ip, *port))])
        }
        TunnelDestination::Ipv6 { address, port } => {
            let ip: std::net::Ipv6Addr = address.parse().map_err(|_| ResolveError::Invalid)?;
            Ok(vec![SocketAddr::from((ip, *port))])
        }
    }
}

/// Resolve a `tunnel_dns_query` record to a list of answers.
pub async fn resolve_query(
    query: &TunnelDnsQueryData,
    timeout: Duration,
) -> Result<Vec<DnsAnswer>, ResolveError> {
    if !is_valid_hostname(&query.name) {
        return Err(ResolveError::Invalid);
    }
    match query.record_type {
        DnsRecordType::A | DnsRecordType::Aaaa => {
            // `lookup_host` doesn't take a record-type filter; we use
            // port 0 as a no-op and filter the IP family ourselves.
            let target = format!("{}:0", query.name);
            let resolved = resolve_with_timeout(&target, timeout).await?;
            let want_v4 = matches!(query.record_type, DnsRecordType::A);
            let answers: Vec<DnsAnswer> = resolved
                .into_iter()
                .filter(|addr| addr.is_ipv4() == want_v4)
                .map(|addr| DnsAnswer {
                    name: query.name.clone(),
                    record_type: query.record_type,
                    // The OS resolver doesn't expose TTL; use a conservative
                    // 60-second hint so clients re-query soon.
                    ttl: 60,
                    value: addr.ip().to_string(),
                })
                .collect();
            if answers.is_empty() {
                Err(ResolveError::NotFound)
            } else {
                Ok(answers)
            }
        }
        // CNAME and TXT are not exposed by `lookup_host`. Returning NXDOMAIN
        // forces the client to fall back to A/AAAA, which is fine for the
        // current iOS use case.
        DnsRecordType::Cname | DnsRecordType::Txt => Err(ResolveError::NotFound),
    }
}

async fn resolve_with_timeout(
    target: &str,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, ResolveError> {
    match time::timeout(timeout, tokio::net::lookup_host(target)).await {
        Ok(Ok(iter)) => {
            let addrs: Vec<SocketAddr> = iter.collect();
            if addrs.is_empty() {
                Err(ResolveError::NotFound)
            } else {
                Ok(addrs)
            }
        }
        Ok(Err(_)) => Err(ResolveError::NotFound),
        Err(_) => Err(ResolveError::Timeout),
    }
}

/// Conservative hostname validator.
///
/// Allows ASCII letters/digits/hyphen/dot. Rejects empty strings, leading
/// or trailing dot/hyphen at the label level, and labels longer than 63
/// chars. The OS resolver would reject many malformed names too, but this
/// short-circuit avoids round-tripping obviously bad input through libc.
fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || *bytes.last().expect("label is non-empty") == b'-' {
            return false;
        }
        for &b in bytes {
            let ok = b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
            if !ok {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_validator() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("a.b.c.example.com"));
        assert!(is_valid_hostname("example_underscore.com"));
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("."));
        assert!(!is_valid_hostname("-foo.com"));
        assert!(!is_valid_hostname("foo-.com"));
        assert!(!is_valid_hostname("foo..com"));
        assert!(!is_valid_hostname("foo bar.com"));
        // Excessive length
        let label = "a".repeat(64);
        assert!(!is_valid_hostname(&label));
        let too_long = "a".repeat(254);
        assert!(!is_valid_hostname(&too_long));
    }

    #[tokio::test]
    async fn ipv4_destination_resolves_synchronously() {
        let dest = TunnelDestination::Ipv4 {
            address: "1.2.3.4".into(),
            port: 80,
        };
        let addrs = resolve_destination(&dest, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 80);
    }

    #[tokio::test]
    async fn ipv6_destination_resolves_synchronously() {
        let dest = TunnelDestination::Ipv6 {
            address: "2001:db8::1".into(),
            port: 443,
        };
        let addrs = resolve_destination(&dest, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv6());
        assert_eq!(addrs[0].port(), 443);
    }

    #[tokio::test]
    async fn ipv4_invalid_address_rejected() {
        let dest = TunnelDestination::Ipv4 {
            address: "not.an.ip".into(),
            port: 80,
        };
        let r = resolve_destination(&dest, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(ResolveError::Invalid)));
    }

    #[tokio::test]
    async fn invalid_hostname_rejected() {
        let dest = TunnelDestination::Hostname {
            host: "-bad-.example.com".into(),
            port: 80,
        };
        let r = resolve_destination(&dest, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(ResolveError::Invalid)));
    }
}
