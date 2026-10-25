//! Crate-private character and grammar helpers. Every grammar is ASCII and
//! byte-exact (CONTRACTS.md section 0).

/// `%x21-7E`: a visible ASCII character.
pub(crate) const fn is_visible_ascii(b: u8) -> bool {
    matches!(b, 0x21..=0x7e)
}

/// `true` when `s` has `min..=max` bytes and every byte is visible ASCII.
pub(crate) fn is_visible_ascii_str(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(is_visible_ascii)
}

/// `0-9` or `a-f`.
pub(crate) const fn is_lower_hex(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

/// `true` when `s` has exactly `len` bytes of lowercase hex.
pub(crate) fn is_lower_hex_str(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(is_lower_hex)
}

/// `[a-z][a-z0-9-]{0,62}`: the grammar of audiences and service names.
pub(crate) fn is_service_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b'a'..=b'z') => {}
        _ => return false,
    }
    s.len() <= 63 && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// The value (0 to 63) of one base64url character, or `None`.
pub(crate) const fn b64url_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// `true` when `s` is the canonical unpadded base64url encoding of exactly
/// `byte_len` bytes: the right length, only base64url characters, and the
/// unused low bits of the last character are zero.
pub(crate) fn is_canonical_b64url(s: &str, byte_len: usize) -> bool {
    let full_groups = byte_len / 3;
    let rest = byte_len % 3;
    let expected_len = full_groups * 4 + if rest == 0 { 0 } else { rest + 1 };
    if s.len() != expected_len {
        return false;
    }
    let mut last = 0u8;
    for b in s.bytes() {
        match b64url_value(b) {
            Some(v) => last = v,
            None => return false,
        }
    }
    match rest {
        // One trailing byte: 2 characters, the last one has 4 unused bits.
        1 => last.is_multiple_of(16),
        // Two trailing bytes: 3 characters, the last one has 2 unused bits.
        2 => last.is_multiple_of(4),
        _ => true,
    }
}

/// The port, when `s` is 1 to 5 ASCII digits with no leading zero and a
/// value from 1 to 65535.
pub(crate) fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_b64url_lengths() {
        // 32 bytes -> 43 characters, last character index % 4 == 0.
        let ok = "A".repeat(43);
        assert!(is_canonical_b64url(&ok, 32));
        let bad_last = format!("{}B", "A".repeat(42));
        assert!(!is_canonical_b64url(&bad_last, 32));
        assert!(!is_canonical_b64url(&"A".repeat(44), 32));
        // 64 bytes -> 86 characters, last character index % 16 == 0.
        assert!(is_canonical_b64url(&format!("{}Q", "A".repeat(85)), 64));
        assert!(is_canonical_b64url(&format!("{}w", "A".repeat(85)), 64));
        assert!(!is_canonical_b64url(&format!("{}E", "A".repeat(85)), 64));
        // Padding and the standard alphabet are rejected.
        assert!(!is_canonical_b64url(&format!("{}+", "A".repeat(42)), 32));
        assert!(!is_canonical_b64url(&format!("{}=", "A".repeat(42)), 32));
    }

    #[test]
    fn ports() {
        assert_eq!(parse_port("8443"), Some(8443));
        assert_eq!(parse_port("65535"), Some(65535));
        assert_eq!(parse_port("1"), Some(1));
        for bad in ["", "0", "08443", "65536", "123456", "+1", "-1", " 1"] {
            assert_eq!(parse_port(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn service_names() {
        for ok in [
            "symphony",
            "onto",
            "crm-api",
            "tutela-admin",
            "a",
            &"a".repeat(63),
        ] {
            assert!(is_service_name(ok), "{ok:?}");
        }
        for bad in [
            "",
            "Crm",
            "1crm",
            "-crm",
            "crm_api",
            "crm.api",
            &"a".repeat(64),
        ] {
            assert!(!is_service_name(bad), "{bad:?}");
        }
    }
}
