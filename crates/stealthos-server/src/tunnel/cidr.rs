//! Minimal CIDR matcher.
//!
//! Implemented in-tree because no CIDR crate is currently in the workspace
//! dependency graph and the brief forbids new deps. Supports IPv4 and IPv6,
//! both stored as `[u8; 16]` (IPv4 mapped to `::ffff:a.b.c.d`-style for
//! comparison purposes, but kept in a 4-byte form internally so we don't
//! have to deal with the IPv4-mapped IPv6 ambiguity at lookup time).

use std::net::IpAddr;

/// One CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Block {
    /// `(network, prefix_len)` where `prefix_len` is in `0..=32`.
    V4([u8; 4], u8),
    /// `(network, prefix_len)` where `prefix_len` is in `0..=128`.
    V6([u8; 16], u8),
}

/// A set of CIDR blocks. `contains` is O(N) linear scan — N is small
/// (single-digit to low-double-digit entries from config) so a tree-based
/// representation is overkill.
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    blocks: Vec<Block>,
}

impl CidrSet {
    /// Parse a list of CIDR strings, dropping malformed entries with a
    /// warning appended to `warnings`.
    pub fn from_strings(items: &[String], warnings: &mut Vec<String>) -> Self {
        let mut blocks = Vec::with_capacity(items.len());
        for item in items {
            match parse_cidr(item) {
                Some(block) => blocks.push(block),
                None => warnings.push(format!("ignoring malformed CIDR: {item}")),
            }
        }
        Self { blocks }
    }

    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        for block in &self.blocks {
            match (addr, block) {
                (IpAddr::V4(a), Block::V4(net, pl)) => {
                    if matches_prefix(&a.octets(), net, *pl) {
                        return true;
                    }
                }
                (IpAddr::V6(a), Block::V6(net, pl)) => {
                    if matches_prefix(&a.octets(), net, *pl) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}

/// Return `true` when the first `prefix_len` bits of `value` and `net`
/// match. `value` and `net` must be the same length.
fn matches_prefix(value: &[u8], net: &[u8], prefix_len: u8) -> bool {
    debug_assert_eq!(value.len(), net.len());
    // value.len() is at most 16 (IPv6) so the conversion is safe; on overflow
    // use u32::MAX which causes the prefix_len check below to short-circuit.
    let total_bits = u32::try_from(value.len())
        .unwrap_or(u32::MAX)
        .saturating_mul(8);
    if u32::from(prefix_len) > total_bits {
        return false;
    }
    let full_bytes = (prefix_len / 8) as usize;
    let remainder = prefix_len % 8;
    if value[..full_bytes] != net[..full_bytes] {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    let mask: u8 = 0xFFu8 << (8 - remainder);
    (value[full_bytes] & mask) == (net[full_bytes] & mask)
}

/// Parse a CIDR string of the form `a.b.c.d/N` or `xx:xx::/N`.
/// Bare addresses (no `/N`) are treated as host routes (`/32` or `/128`).
fn parse_cidr(s: &str) -> Option<Block> {
    let (addr_part, prefix_part) = s
        .find('/')
        .map_or((s, None), |i| (&s[..i], Some(&s[i + 1..])));
    let ip: IpAddr = addr_part.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            let prefix = match prefix_part {
                Some(p) => {
                    let n: u8 = p.parse().ok()?;
                    if n > 32 {
                        return None;
                    }
                    n
                }
                None => 32,
            };
            // Mask the network bits so a slightly-malformed CIDR like
            // `10.1.2.3/8` (host bits set) still matches the intended block.
            let mut octets = v4.octets();
            apply_mask(&mut octets, prefix);
            Some(Block::V4(octets, prefix))
        }
        IpAddr::V6(v6) => {
            let prefix = match prefix_part {
                Some(p) => {
                    let n: u8 = p.parse().ok()?;
                    if n > 128 {
                        return None;
                    }
                    n
                }
                None => 128,
            };
            let mut octets = v6.octets();
            apply_mask(&mut octets, prefix);
            Some(Block::V6(octets, prefix))
        }
    }
}

fn apply_mask(bytes: &mut [u8], prefix_len: u8) {
    // bytes.len() is 4 (IPv4) or 16 (IPv6) so the conversion is safe.
    let total_bits = u32::try_from(bytes.len())
        .unwrap_or(u32::MAX)
        .saturating_mul(8);
    if u32::from(prefix_len) >= total_bits {
        return;
    }
    let full_bytes = (prefix_len / 8) as usize;
    let remainder = prefix_len % 8;
    if remainder != 0 {
        let mask: u8 = 0xFFu8 << (8 - remainder);
        bytes[full_bytes] &= mask;
    }
    let zero_start = full_bytes + usize::from(remainder != 0);
    for byte in &mut bytes[zero_start..] {
        *byte = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_cidr_basic() {
        let mut warns = Vec::new();
        let set = CidrSet::from_strings(
            &[
                "10.0.0.0/8".to_owned(),
                "192.168.0.0/16".to_owned(),
                "8.8.8.8/32".to_owned(),
            ],
            &mut warns,
        );
        assert!(warns.is_empty());
        assert!(set.contains("10.1.2.3".parse::<Ipv4Addr>().unwrap().into()));
        assert!(set.contains("10.255.255.255".parse::<Ipv4Addr>().unwrap().into()));
        assert!(set.contains("192.168.0.1".parse::<Ipv4Addr>().unwrap().into()));
        assert!(set.contains("8.8.8.8".parse::<Ipv4Addr>().unwrap().into()));
        assert!(!set.contains("8.8.8.9".parse::<Ipv4Addr>().unwrap().into()));
        assert!(!set.contains("11.0.0.1".parse::<Ipv4Addr>().unwrap().into()));
        assert!(!set.contains("172.16.0.1".parse::<Ipv4Addr>().unwrap().into()));
    }

    #[test]
    fn ipv4_partial_byte_prefix() {
        let mut warns = Vec::new();
        let set = CidrSet::from_strings(&["172.16.0.0/12".to_owned()], &mut warns);
        assert!(warns.is_empty());
        assert!(set.contains("172.16.0.1".parse::<Ipv4Addr>().unwrap().into()));
        assert!(set.contains("172.31.255.255".parse::<Ipv4Addr>().unwrap().into()));
        assert!(!set.contains("172.32.0.0".parse::<Ipv4Addr>().unwrap().into()));
        assert!(!set.contains("172.15.255.255".parse::<Ipv4Addr>().unwrap().into()));
    }

    #[test]
    fn ipv6_cidr_basic() {
        let mut warns = Vec::new();
        let set = CidrSet::from_strings(
            &[
                "::1/128".to_owned(),
                "fc00::/7".to_owned(),
                "fe80::/10".to_owned(),
            ],
            &mut warns,
        );
        assert!(warns.is_empty());
        assert!(set.contains("::1".parse::<Ipv6Addr>().unwrap().into()));
        assert!(set.contains("fc00::1".parse::<Ipv6Addr>().unwrap().into()));
        assert!(set.contains("fdff:ffff:ffff::1".parse::<Ipv6Addr>().unwrap().into()));
        assert!(set.contains("fe80::1".parse::<Ipv6Addr>().unwrap().into()));
        assert!(!set.contains("2001:db8::1".parse::<Ipv6Addr>().unwrap().into()));
        assert!(!set.contains("::2".parse::<Ipv6Addr>().unwrap().into()));
    }

    #[test]
    fn malformed_cidr_emits_warning() {
        let mut warns = Vec::new();
        let set = CidrSet::from_strings(
            &[
                "not-an-ip".to_owned(),
                "10.0.0.0/99".to_owned(),
                "10.0.0.0/8".to_owned(),
            ],
            &mut warns,
        );
        assert_eq!(warns.len(), 2);
        // The valid block was kept.
        assert!(set.contains("10.1.2.3".parse::<Ipv4Addr>().unwrap().into()));
    }

    #[test]
    fn empty_set_does_not_match_anything() {
        let set = CidrSet::default();
        assert!(set.is_empty());
        assert!(!set.contains("1.2.3.4".parse::<Ipv4Addr>().unwrap().into()));
    }

    #[test]
    fn host_address_without_prefix() {
        let mut warns = Vec::new();
        let set = CidrSet::from_strings(&["127.0.0.1".to_owned()], &mut warns);
        assert!(warns.is_empty());
        assert!(set.contains("127.0.0.1".parse::<Ipv4Addr>().unwrap().into()));
        assert!(!set.contains("127.0.0.2".parse::<Ipv4Addr>().unwrap().into()));
    }
}
