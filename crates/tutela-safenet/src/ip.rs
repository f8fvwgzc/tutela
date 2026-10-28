//! Which addresses are on the public internet (THREAT-MODEL.md TM-18).
//! Ported from onto-intelli `crates/onto-intelli/src/net.rs` (MIT).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local() // 169.254.0.0/16, cloud metadata included
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0 // 0.0.0.0/8 "this network"
        || (a == 100 && (64..128).contains(&b)) // 100.64.0.0/10 CGNAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24 protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 benchmarking
        || a >= 240) // 240.0.0.0/4 reserved
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = ip.segments();
    // NAT64 (64:ff9b::/96): judge the IPv4 address in the last 32 bits.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [_, _, _, _, _, _, hi, lo] = s;
        return public_v4(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local (AWS metadata fd00:ec2::254 too)
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        || s[..6] == [0, 0, 0, 0, 0, 0]) // ::/96 IPv4-compatible (deprecated)
}

/// `true` if `ip` is on the public internet: not loopback, private,
/// link-local (cloud metadata included), CGNAT, multicast, unspecified,
/// broadcast, documentation, benchmarking or reserved, in IPv4 or IPv6.
/// IPv4-mapped and NAT64 IPv6 addresses are judged by the IPv4 address
/// inside.
#[must_use]
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tm18_internal_addresses_are_not_public() {
        for bad in [
            "127.0.0.1",
            "127.255.255.254",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.100.100.200",
            "224.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "192.0.0.10",
            "198.18.0.1",
            "203.0.113.5",
            "240.0.0.1",
            "::1",
            "::",
            "fd00::1",
            "fd00:ec2::254",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "2001:db8::1",
        ] {
            assert!(!public_ip(bad.parse().unwrap()), "{bad}");
        }
        for good in [
            "8.8.8.8",
            "1.1.1.1",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(public_ip(good.parse().unwrap()), "{good}");
        }
    }
}
