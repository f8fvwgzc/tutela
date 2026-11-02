//! UUIDv7 text and the Tutela ids that are not principals (CONTRACTS.md 1.1
//! and 1.2).
//!
//! The principal ids (`usr_`, `sa_`, `key_`, `agt_`) are in
//! [`crate::principal`]. The tenant and org ids (`ten_`, `org_`) are in
//! [`crate::tenant`].

use core::fmt;
use core::str::FromStr;

use crate::text::is_lower_hex;

/// Why a UUIDv7 text was rejected (CONTRACTS.md 1.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UuidError {
    /// The text is not exactly 36 characters.
    #[error("a UUIDv7 must be exactly 36 characters")]
    Length,
    /// A `-` is missing or in the wrong place.
    #[error("a UUIDv7 must have `-` after the 8th, 12th, 16th and 20th hex digit")]
    Hyphen,
    /// A character is not `0-9` or `a-f`.
    #[error("a UUIDv7 must use lowercase hex digits (0-9, a-f) only")]
    NotLowerHex,
    /// The version digit is not `7`.
    #[error("the UUID version digit must be 7")]
    Version,
    /// The variant digit is not `8`, `9`, `a` or `b`.
    #[error("the UUID variant digit must be 8, 9, a or b")]
    Variant,
}

/// Why a prefixed Tutela id (`usr_<uuidv7>`, `ten_<uuidv7>`, ...) was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// The id does not start with the expected prefix.
    #[error("the id must start with `{expected}`")]
    Prefix {
        /// The prefix this id type needs, for example `usr_`.
        expected: &'static str,
    },
    /// The part after the prefix is not a valid UUIDv7.
    #[error("invalid UUIDv7 in the id")]
    Uuid(#[from] UuidError),
}

/// A UUID version 7 (RFC 9562) in Tutela's exact text form: 36 characters,
/// lowercase hex, version digit `7`, variant digit `8`, `9`, `a` or `b`.
///
/// Used bare for token ids (`jti`), event ids and audit record ids, and inside
/// every prefixed id. Uppercase, braces, `urn:uuid:`, missing hyphens, other
/// versions, nil and max are rejected, never repaired.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Uuid7(uuid::Uuid);

impl Uuid7 {
    /// The length of the text form.
    pub const TEXT_LEN: usize = 36;

    /// Parses the exact text form.
    ///
    /// # Errors
    ///
    /// Returns a [`UuidError`] when `s` is not a lowercase, hyphenated UUIDv7.
    pub fn parse(s: &str) -> Result<Self, UuidError> {
        let text: &[u8; Self::TEXT_LEN] = s.as_bytes().try_into().map_err(|_| UuidError::Length)?;
        let mut bytes = [0u8; 16];
        let mut nibbles = 0usize;
        for (i, &c) in text.iter().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if c != b'-' {
                    return Err(UuidError::Hyphen);
                }
                continue;
            }
            if !is_lower_hex(c) {
                return Err(UuidError::NotLowerHex);
            }
            let value = hex_value(c);
            if let Some(byte) = bytes.get_mut(nibbles / 2) {
                *byte = if nibbles.is_multiple_of(2) {
                    value << 4
                } else {
                    *byte | value
                };
            }
            nibbles += 1;
        }
        if text[14] != b'7' {
            return Err(UuidError::Version);
        }
        if !matches!(text[19], b'8' | b'9' | b'a' | b'b') {
            return Err(UuidError::Variant);
        }
        Ok(Self(uuid::Uuid::from_bytes(bytes)))
    }

    /// Wraps a [`uuid::Uuid`] after checking its version and variant.
    ///
    /// # Errors
    ///
    /// Returns [`UuidError::Version`] or [`UuidError::Variant`] when `uuid` is
    /// not an RFC 9562 version 7 UUID.
    pub fn from_uuid(uuid: uuid::Uuid) -> Result<Self, UuidError> {
        if uuid.get_version_num() != 7 {
            return Err(UuidError::Version);
        }
        if uuid.get_variant() != uuid::Variant::RFC4122 {
            return Err(UuidError::Variant);
        }
        Ok(Self(uuid))
    }

    /// The inner [`uuid::Uuid`].
    #[must_use]
    pub const fn as_uuid(&self) -> &uuid::Uuid {
        &self.0
    }

    /// The millisecond Unix timestamp in the first 48 bits.
    #[must_use]
    pub fn unix_millis(&self) -> u64 {
        let b = self.0.as_bytes();
        u64::from_be_bytes([0, 0, b[0], b[1], b[2], b[3], b[4], b[5]])
    }
}

/// The value of one lowercase hex digit. Only called on checked input.
const fn hex_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

impl fmt::Display for Uuid7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `uuid` prints lowercase, hyphenated text: the exact form above.
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

impl FromStr for Uuid7 {
    type Err = UuidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(Uuid7, "a lowercase UUIDv7 string");

prefixed_id!(
    /// A session id, `ses_<uuidv7>` (CONTRACTS.md 1.2). The `sid` claim.
    SessionId,
    "ses_"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::uuid7_strategy;
    use proptest::prelude::*;

    const GOOD: &str = "0193a1b2-c3d5-7000-8000-0000000000e1";

    #[test]
    fn parses_and_prints_the_exact_form() {
        let id = Uuid7::parse(GOOD).unwrap();
        assert_eq!(id.to_string(), GOOD);
        assert_eq!(id.unix_millis(), 0x0193_a1b2_c3d5);
        for variant in ['8', '9', 'a', 'b'] {
            let s = format!("0193a1b2-c3d5-7000-{variant}000-0000000000e1");
            assert_eq!(Uuid7::parse(&s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn rejects_every_other_form() {
        let cases: &[(&str, UuidError)] = &[
            (
                "0193A1B2-C3D5-7000-8000-0000000000E1",
                UuidError::NotLowerHex,
            ),
            ("{0193a1b2-c3d5-7000-8000-0000000000e1}", UuidError::Length),
            (
                "urn:uuid:0193a1b2-c3d5-7000-8000-0000000000e1",
                UuidError::Length,
            ),
            ("0193a1b2c3d570008000000000000e1", UuidError::Length),
            ("0193a1b2c3d5700080000000000000e1", UuidError::Length),
            ("0193a1b2-c3d5-4000-8000-0000000000e1", UuidError::Version),
            ("00000000-0000-0000-0000-000000000000", UuidError::Version),
            ("ffffffff-ffff-ffff-ffff-ffffffffffff", UuidError::Version),
            ("0193a1b2-c3d5-7000-c000-0000000000e1", UuidError::Variant),
            ("0193a1b2-c3d5-7000-0000-0000000000e1", UuidError::Variant),
            ("0193a1b2_c3d5-7000-8000-0000000000e1", UuidError::Hyphen),
            (
                "0193a1b2-c3d5-7000-8000-0000000000g1",
                UuidError::NotLowerHex,
            ),
            (
                " 193a1b2-c3d5-7000-8000-0000000000e1",
                UuidError::NotLowerHex,
            ),
            ("0193a1b2-c3d5-7000-8000-0000000000e1 ", UuidError::Length),
            ("", UuidError::Length),
        ];
        for (input, err) in cases {
            assert_eq!(Uuid7::parse(input), Err(*err), "{input:?}");
        }
    }

    #[test]
    fn from_uuid_checks_version_and_variant() {
        let v7 = uuid::Uuid::parse_str(GOOD).unwrap();
        assert!(Uuid7::from_uuid(v7).is_ok());
        let v4 = uuid::Uuid::parse_str("0193a1b2-c3d5-4000-8000-0000000000e1").unwrap();
        assert_eq!(Uuid7::from_uuid(v4), Err(UuidError::Version));
        let ncs = uuid::Uuid::parse_str("0193a1b2-c3d5-7000-0000-0000000000e1").unwrap();
        assert_eq!(Uuid7::from_uuid(ncs), Err(UuidError::Variant));
        assert_eq!(Uuid7::from_uuid(uuid::Uuid::nil()), Err(UuidError::Version));
        assert_eq!(Uuid7::from_uuid(uuid::Uuid::max()), Err(UuidError::Version));
    }

    #[test]
    fn session_id() {
        let s = "ses_0193a1b2-c3d4-7123-8456-789abcdef012";
        let id: SessionId = s.parse().unwrap();
        assert_eq!(id.to_string(), s);
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{s}\""));
        assert_eq!(
            serde_json::from_str::<SessionId>(&format!("\"{s}\"")).unwrap(),
            id
        );
        assert_eq!(
            "usr_0193a1b2-c3d4-7123-8456-789abcdef012".parse::<SessionId>(),
            Err(IdError::Prefix { expected: "ses_" })
        );
        assert_eq!(
            "ses_0193a1b2-c3d4-4123-8456-789abcdef012".parse::<SessionId>(),
            Err(IdError::Uuid(UuidError::Version))
        );
        assert!(serde_json::from_str::<SessionId>("null").is_err());
        assert!(serde_json::from_str::<SessionId>("42").is_err());
    }

    #[test]
    fn serde_is_a_string() {
        let id = Uuid7::parse(GOOD).unwrap();
        assert_eq!(serde_json::to_value(id).unwrap(), serde_json::json!(GOOD));
        assert_eq!(
            serde_json::from_value::<Uuid7>(serde_json::json!(GOOD)).unwrap(),
            id
        );
        assert!(serde_json::from_value::<Uuid7>(serde_json::json!(GOOD.to_uppercase())).is_err());
    }

    proptest! {
        #[test]
        fn round_trip(id in uuid7_strategy()) {
            let text = id.to_string();
            prop_assert_eq!(text.len(), 36);
            prop_assert_eq!(Uuid7::parse(&text), Ok(id));
            let ses = SessionId::new(id);
            prop_assert_eq!(ses.to_string().parse::<SessionId>(), Ok(ses));
        }

        #[test]
        fn rejects_other_versions(mut b in any::<[u8; 16]>(), version in 0u8..16) {
            prop_assume!(version != 7);
            b[6] = (b[6] & 0x0f) | (version << 4);
            b[8] = (b[8] & 0x3f) | 0x80;
            let text = uuid::Uuid::from_bytes(b).hyphenated().to_string();
            prop_assert_eq!(Uuid7::parse(&text), Err(UuidError::Version));
        }

        #[test]
        fn rejects_uppercase(id in uuid7_strategy()) {
            let upper = id.to_string().to_uppercase();
            prop_assume!(upper != id.to_string());
            prop_assert!(Uuid7::parse(&upper).is_err());
        }

        #[test]
        fn never_panics(s in "\\PC{0,40}") {
            let _ = Uuid7::parse(&s);
        }
    }
}
