//! Fixed-size base64url values (unpadded, canonical) and the JSON integer
//! range.

use core::fmt;
use core::str::FromStr;

use crate::text::is_canonical_b64url;

/// The largest JSON integer: 2^53 − 1 (CONTRACTS.md section 0).
pub const MAX_JSON_INT: u64 = (1 << 53) - 1;

/// Why a base64url value was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Base64UrlError {
    /// The value is not the canonical unpadded base64url form of the right
    /// number of bytes.
    #[error("expected {chars} characters of canonical unpadded base64url ({bytes} bytes)")]
    Invalid {
        /// The number of characters expected.
        chars: usize,
        /// The number of bytes the value encodes.
        bytes: usize,
    },
}

/// Defines a newtype for a fixed-size base64url value.
macro_rules! b64url_type {
    ($(#[$meta:meta])* $name:ident, bytes = $bytes:literal, chars = $chars:literal, $expecting:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $name(String);

        impl $name {
            /// The number of bytes the value encodes.
            pub const BYTES: usize = $bytes;
            /// The number of characters in the text form.
            pub const LEN: usize = $chars;

            /// Parses the canonical unpadded base64url text.
            ///
            /// # Errors
            ///
            /// Returns [`Base64UrlError::Invalid`] when `s` has the wrong
            /// length, a character outside `A-Z a-z 0-9 - _`, or non-zero
            /// unused bits in its last character.
            pub fn parse(s: &str) -> Result<Self, Base64UrlError> {
                if is_canonical_b64url(s, $bytes) {
                    Ok(Self(s.to_owned()))
                } else {
                    Err(Base64UrlError::Invalid { chars: $chars, bytes: $bytes })
                }
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Base64UrlError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        string_serde!($name, $expecting);
    };
}

b64url_type!(
    /// A SHA-256 value in unpadded base64url: 43 characters.
    ///
    /// Used for RFC 7638 JWK thumbprints (the JOSE `kid`, the audit
    /// `signature.key_id`) and for the RFC 8705 `x5t#S256` certificate
    /// thumbprint.
    Thumbprint,
    bytes = 32,
    chars = 43,
    "43 characters of base64url (a SHA-256 value)"
);

b64url_type!(
    /// An Ed25519 signature (RFC 8032) in unpadded base64url: 86 characters.
    SignatureValue,
    bytes = 64,
    chars = 86,
    "86 characters of base64url (an Ed25519 signature)"
);

/// Serde helpers for `u64` fields that must stay inside the JSON integer
/// range (0 to 2^53 − 1).
pub(crate) mod json_int {
    use serde::{Deserialize, Deserializer, Serializer, de, ser};

    use super::MAX_JSON_INT;

    pub(crate) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *value > MAX_JSON_INT {
            return Err(ser::Error::custom("integer is above 2^53 - 1"));
        }
        serializer.serialize_u64(*value)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value > MAX_JSON_INT {
            return Err(de::Error::custom("integer is above 2^53 - 1"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint() {
        let kid = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
        let t = Thumbprint::parse(kid).unwrap();
        assert_eq!(t.as_str(), kid);
        assert_eq!(serde_json::to_string(&t).unwrap(), format!("\"{kid}\""));
        let err = Base64UrlError::Invalid {
            chars: 43,
            bytes: 32,
        };
        for bad in [
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xt",
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X",
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs=",
            "NzbLsXh8uDCcd+6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
            "",
        ] {
            assert_eq!(Thumbprint::parse(bad), Err(err), "{bad:?}");
        }
    }

    #[test]
    fn signature_value() {
        let ok = format!("{}A", "x".repeat(85));
        assert!(SignatureValue::parse(&ok).is_ok());
        let bad = format!("{}B", "x".repeat(85));
        assert!(SignatureValue::parse(&bad).is_err());
        assert!(SignatureValue::parse(&"x".repeat(86)).is_err());
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Holder {
        #[serde(with = "json_int")]
        n: u64,
    }

    #[test]
    fn json_int_range() {
        let max = Holder { n: MAX_JSON_INT };
        let json = serde_json::to_string(&max).unwrap();
        assert_eq!(json, "{\"n\":9007199254740991}");
        assert_eq!(serde_json::from_str::<Holder>(&json).unwrap(), max);
        assert!(
            serde_json::to_string(&Holder {
                n: MAX_JSON_INT + 1
            })
            .is_err()
        );
        assert!(serde_json::from_str::<Holder>("{\"n\":9007199254740992}").is_err());
        assert!(serde_json::from_str::<Holder>("{\"n\":-1}").is_err());
        assert!(serde_json::from_str::<Holder>("{\"n\":1.5}").is_err());
        assert!(serde_json::from_str::<Holder>("{\"n\":\"1\"}").is_err());
        assert!(serde_json::from_str::<Holder>("{\"n\":null}").is_err());
    }
}
