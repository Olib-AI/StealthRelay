//! Minimal CIDR matcher.
//!
//! Implemented in-tree because no CIDR crate is currently in the workspace
//! dependency graph and the brief forbids new deps. Supports IPv4 and IPv6,
//! stored in their native 4-byte / 16-byte forms.
//!
//! # IPv4-in-IPv6 spellings
//!
//! A dual-stack socket that dials `::ffff:10.0.0.1` reaches `10.0.0.1`, so an
//! address family alone does not decide which blocks apply. Two entry points
//! keep that from turning into a policy bypass:
//!
//! * [`canonicalize`] rewrites an IPv4-mapped address to its IPv4 form. Call
//!   it before *anything* looks at an address, so the address that is checked
//!   is the address that is dialled.
//! * [`CidrSet::contains_any_form`] additionally tries every alternate
//!   spelling that reaches the same IPv4 host (IPv4-compatible, 6to4, NAT64).
//!   Deny lists must use it; a spelling that is not recognised here still has
//!   to survive the allowlist, which matches exact identities only.

use std::net::{IpAddr, Ipv4Addr};

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

    /// Exact match: `addr` is tested against blocks of its own family only.
    ///
    /// Use this for allowlists, where a spelling the matcher does not
    /// recognise must *fail* the check rather than inherit an allowance.
    /// Callers are expected to have run [`canonicalize`] first.
    pub fn contains(&self, addr: IpAddr) -> bool {
        for block in &self.blocks {
            match (addr, block) {
                (IpAddr::V4(a), Block::V4(net, pl)) if matches_prefix(&a.octets(), net, *pl) => {
                    return true;
                }
                (IpAddr::V6(a), Block::V6(net, pl)) if matches_prefix(&a.octets(), net, *pl) => {
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Fail-closed match: `addr` and every alternate spelling that reaches the
    /// same IPv4 host are tested.
    ///
    /// Use this for deny lists. `10.0.0.0/8` then also blocks
    /// `::ffff:10.0.0.1`, `::10.0.0.1`, `2002:0a00:0001::` and
    /// `64:ff9b::10.0.0.1`, none of which an IPv6-vs-IPv4 family comparison
    /// would catch.
    pub fn contains_any_form(&self, addr: IpAddr) -> bool {
        if self.contains(addr) {
            return true;
        }
        alternate_forms(addr)
            .into_iter()
            .flatten()
            .any(|alt| self.contains(alt))
    }
}

/// Rewrite an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form.
///
/// The two spellings name the same host: a dual-stack socket connecting to
/// `::ffff:10.0.0.1` performs an IPv4 connection to `10.0.0.1`. Collapsing
/// them here means the address a policy check sees is the address that is
/// dialled. Every other address is returned unchanged.
pub fn canonicalize(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// Other spellings of `addr` that name the same host, for deny-list matching.
///
/// Returns a fixed-size array so the hot path does not allocate; unused slots
/// are `None`.
///
/// * IPv4 gains its IPv4-mapped form, so a deny entry written as
///   `::ffff:0:0/96` still catches a plain IPv4 destination.
/// * IPv6 gains the embedded IPv4 of the mapped (RFC 4291), IPv4-compatible
///   (RFC 4291 2.5.5.1, deprecated), 6to4 (RFC 3056) and well-known NAT64
///   (RFC 6052) forms.
fn alternate_forms(addr: IpAddr) -> [Option<IpAddr>; 2] {
    match addr {
        IpAddr::V4(v4) => [Some(IpAddr::V6(v4.to_ipv6_mapped())), None],
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let embedded = v6.to_ipv4_mapped().or_else(|| {
                if seg[..6] == [0, 0, 0, 0, 0, 0] && seg[6] != 0 {
                    // `::a.b.c.d`. The `seg[6] != 0` guard keeps `::`, `::1`
                    // and the rest of `::/112` as IPv6 -- they are loopback
                    // and unspecified, not IPv4-compatible addresses.
                    Some(embedded_v4(seg[6], seg[7]))
                } else if seg[0] == 0x2002 {
                    // 6to4: `2002:WWXX:YYZZ::/48` carries w.x.y.z.
                    Some(embedded_v4(seg[1], seg[2]))
                } else if seg[..4] == [0x0064, 0xff9b, 0, 0] && seg[4..6] == [0, 0] {
                    // NAT64 well-known prefix `64:ff9b::/96`.
                    Some(embedded_v4(seg[6], seg[7]))
                } else {
                    None
                }
            });
            // The canonical IPv4 form, plus that form re-mapped, so an
            // operator's `::ffff:0:0/96` entry catches embedded spellings too.
            embedded.map_or([None, None], |v4| {
                [
                    Some(IpAddr::V4(v4)),
                    Some(IpAddr::V6(v4.to_ipv6_mapped())),
                ]
            })
        }
    }
}

/// Rebuild an IPv4 address from the two IPv6 segments that carry it.
const fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (hi >> 8) as u8,
        (hi & 0xff) as u8,
        (lo >> 8) as u8,
        (lo & 0xff) as u8,
    )
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
    fn ipv4_mapped_ipv6_canonicalizes_to_ipv4() {
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        assert!(mapped.is_ipv6());
        assert_eq!(canonicalize(mapped), "10.1.2.3".parse::<IpAddr>().unwrap());

        // Addresses with no IPv4 inside them are untouched.
        for s in ["::1", "fc00::1", "2001:db8::1", "::"] {
            let addr: IpAddr = s.parse().unwrap();
            assert_eq!(canonicalize(addr), addr, "{s} must not be rewritten");
        }
        let v4: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(canonicalize(v4), v4);
    }

    /// An IPv4 deny list must block the IPv6 spellings of the same host.
    /// Regression test for the IPv4-mapped IPv6 SSRF bypass: `contains`
    /// compares within an address family, so `::ffff:10.0.0.1` slipped past
    /// a `10.0.0.0/8` deny entry and the relay dialled the internal host.
    #[test]
    fn deny_list_catches_ipv4_in_ipv6_spellings() {
        let mut warns = Vec::new();
        let set = CidrSet::from_strings(
            &[
                "10.0.0.0/8".to_owned(),
                "127.0.0.0/8".to_owned(),
                "169.254.0.0/16".to_owned(),
            ],
            &mut warns,
        );
        assert!(warns.is_empty());

        for spelling in [
            "::ffff:10.0.0.1",       // IPv4-mapped
            "::ffff:169.254.169.254", // cloud metadata service
            "::10.0.0.1",            // IPv4-compatible (deprecated)
            "2002:0a00:0001::",      // 6to4
            "64:ff9b::10.0.0.1",     // NAT64 well-known prefix
            "::ffff:127.0.0.1",
        ] {
            let addr: IpAddr = spelling.parse().unwrap();
            assert!(
                set.contains_any_form(addr),
                "{spelling} must be denied by the IPv4 deny list"
            );
        }

        // Genuinely external addresses still pass, in either family.
        for spelling in ["::ffff:8.8.8.8", "2001:db8::1", "8.8.8.8"] {
            let addr: IpAddr = spelling.parse().unwrap();
            assert!(!set.contains_any_form(addr), "{spelling} must be allowed");
        }
    }

    /// `::1` sits inside `::/112`, but it is loopback rather than an
    /// IPv4-compatible address, so it must not be rewritten to `0.0.0.1`
    /// and must keep matching an IPv6 deny entry.
    #[test]
    fn loopback_and_unspecified_are_not_treated_as_embedded_ipv4() {
        let mut warns = Vec::new();
        let v6_set = CidrSet::from_strings(&["::1/128".to_owned()], &mut warns);
        assert!(v6_set.contains_any_form("::1".parse().unwrap()));

        // `0.0.0.1/32` must NOT pick up `::1`.
        let v4_set = CidrSet::from_strings(&["0.0.0.1/32".to_owned()], &mut warns);
        assert!(!v4_set.contains_any_form("::1".parse().unwrap()));
        assert!(!v4_set.contains_any_form("::".parse().unwrap()));
        assert!(warns.is_empty());
    }

    /// An IPv6 deny entry written in mapped form catches plain IPv4 too.
    #[test]
    fn ipv6_mapped_deny_entry_catches_plain_ipv4() {
        let mut warns = Vec::new();
        let set = CidrSet::from_strings(&["::ffff:10.0.0.0/104".to_owned()], &mut warns);
        assert!(warns.is_empty());
        assert!(set.contains_any_form("10.1.2.3".parse().unwrap()));
        assert!(!set.contains_any_form("11.1.2.3".parse().unwrap()));
    }

    /// Allowlists match exact identities: an unrecognised IPv6 spelling must
    /// not inherit an IPv4 allowance and reach a 6to4 relay by accident.
    #[test]
    fn allowlist_matching_stays_exact() {
        let mut warns = Vec::new();
        let set = CidrSet::from_strings(&["8.8.8.8/32".to_owned()], &mut warns);
        assert!(warns.is_empty());
        // Canonicalized mapped form is the same host, so it passes.
        assert!(set.contains(canonicalize("::ffff:8.8.8.8".parse().unwrap())));
        // 6to4 is a different host (a relay), so it does not.
        assert!(!set.contains("2002:0808:0808::".parse().unwrap()));
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
