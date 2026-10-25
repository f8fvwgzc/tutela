//! API keys: parse, format check and display prefix (CONTRACTS.md section 5).
//!
//! Format: `tut_<kind>_<prefix>_<secret>`, exactly 59 characters, for example
//! `tut_sk_7f3k9q2m_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`.
//!
//! Hashing, storage, verification and rotation are Phase A (`tutela-store`)
//! and Phase B (`tutelad`). The full key is shown once, when it is created.
//! After that only the display prefix (`tut_sk_7f3k9q2m`) is ever shown or
//! logged. [`ApiKey`] never prints its secret: not in `Debug`, not in
//! `Display`, not in errors.

use core::fmt;
use core::str::FromStr;

use zeroize::Zeroizing;

use crate::text::is_canonical_b64url;

/// The fixed start of every Tutela key.
pub const MARKER: &str = "tut_";

/// Why an API key was rejected. A caller answers only "invalid API key";
/// the variants are for logs. None of them holds any part of the key.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiKeyError {
    /// The key is not exactly 59 bytes.
    #[error("invalid API key: wrong length")]
    Length,
    /// The key does not start with `tut_`.
    #[error("invalid API key: missing `tut_`")]
    Marker,
    /// The kind is not `sk` or `ak`.
    #[error("invalid API key: unknown kind")]
    Kind,
    /// A `_` separator is missing.
    #[error("invalid API key: missing separator")]
    Separator,
    /// The prefix is not 8 characters from `a-z 0-9`.
    #[error("invalid API key: bad prefix")]
    Prefix,
    /// The secret is not 43 characters of canonical base64url (32 bytes).
    #[error("invalid API key: bad secret encoding")]
    Secret,
}

/// The kind of an API key. A closed set.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ApiKeyKind {
    /// `sk`: a key of an app or a service account.
    Sk,
    /// `ak`: an agent key.
    Ak,
}

impl ApiKeyKind {
    /// The wire form: `sk` or `ak`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sk => "sk",
            Self::Ak => "ak",
        }
    }

    fn from_bytes(b: [u8; 2]) -> Result<Self, ApiKeyError> {
        match &b {
            b"sk" => Ok(Self::Sk),
            b"ak" => Ok(Self::Ak),
            _ => Err(ApiKeyError::Kind),
        }
    }
}

impl fmt::Display for ApiKeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ApiKeyKind {
    type Err = ApiKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b: [u8; 2] = s.as_bytes().try_into().map_err(|_| ApiKeyError::Kind)?;
        Self::from_bytes(b)
    }
}

string_serde!(ApiKeyKind, "an API key kind: sk or ak");

/// The public 8-character prefix of a key, from `a-z 0-9`. Used to find the
/// key's row. Not a secret.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct KeyPrefix([u8; 8]);

impl KeyPrefix {
    /// The length of a prefix.
    pub const LEN: usize = 8;

    fn from_bytes(b: [u8; 8]) -> Result<Self, ApiKeyError> {
        if b.iter().all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9')) {
            Ok(Self(b))
        } else {
            Err(ApiKeyError::Prefix)
        }
    }

    /// The prefix text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only `a-z 0-9` bytes are ever stored, so this is always valid UTF-8.
        core::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Display for KeyPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KeyPrefix {
    type Err = ApiKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b: [u8; 8] = s.as_bytes().try_into().map_err(|_| ApiKeyError::Prefix)?;
        Self::from_bytes(b)
    }
}

string_serde!(KeyPrefix, "an 8-character API key prefix");

/// The display prefix: the first 15 characters of a key, for example
/// `tut_sk_7f3k9q2m`. The only part of a key that is ever shown or logged
/// after creation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DisplayPrefix {
    kind: ApiKeyKind,
    prefix: KeyPrefix,
}

impl DisplayPrefix {
    /// The length of a display prefix.
    pub const LEN: usize = 15;

    /// Makes a display prefix.
    #[must_use]
    pub const fn new(kind: ApiKeyKind, prefix: KeyPrefix) -> Self {
        Self { kind, prefix }
    }

    /// The key kind.
    #[must_use]
    pub const fn kind(&self) -> ApiKeyKind {
        self.kind
    }

    /// The 8-character prefix.
    #[must_use]
    pub const fn prefix(&self) -> KeyPrefix {
        self.prefix
    }

    /// Parses `tut_<kind>_<prefix>`.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiKeyError`] when `s` is not a display prefix.
    pub fn parse(s: &str) -> Result<Self, ApiKeyError> {
        let b: &[u8; Self::LEN] = s.as_bytes().try_into().map_err(|_| ApiKeyError::Length)?;
        parse_head(b)
    }
}

/// Parses the first 15 bytes of a key: `tut_`, kind, `_`, prefix.
fn parse_head(b: &[u8; DisplayPrefix::LEN]) -> Result<DisplayPrefix, ApiKeyError> {
    let [t, u, t2, us1, k1, k2, us2, p @ ..] = *b;
    if [t, u, t2, us1] != *b"tut_" {
        return Err(ApiKeyError::Marker);
    }
    let kind = ApiKeyKind::from_bytes([k1, k2])?;
    if us2 != b'_' {
        return Err(ApiKeyError::Separator);
    }
    let prefix = KeyPrefix::from_bytes(p)?;
    Ok(DisplayPrefix { kind, prefix })
}

impl fmt::Display for DisplayPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{MARKER}{}_{}", self.kind, self.prefix)
    }
}

impl FromStr for DisplayPrefix {
    type Err = ApiKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(
    DisplayPrefix,
    "an API key display prefix `tut_<kind>_<prefix>`"
);

/// A parsed Tutela API key. It holds the secret.
///
/// - `Debug` and `Display` show only the display prefix, never the secret.
/// - It has no `Serialize`, no `Clone` and no `PartialEq`: a key is hashed
///   and compared as a hash in constant time (Phase A), never with `==`.
/// - [`ApiKey::expose_secret`] returns the full key, for hashing only.
/// - Its copy of the key is overwritten with zeros when it is dropped.
pub struct ApiKey {
    head: DisplayPrefix,
    full: Zeroizing<String>,
}

impl ApiKey {
    /// The length of a key.
    pub const LEN: usize = 59;
    /// The length of the secret part.
    pub const SECRET_LEN: usize = 43;

    /// Parses a key by fixed positions (CONTRACTS.md 5.2).
    ///
    /// Spaces and line breaks are not trimmed: a key with them is invalid.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiKeyError`] when `s` is not a valid key. The error
    /// holds no part of the key.
    pub fn parse(s: &str) -> Result<Self, ApiKeyError> {
        let b: &[u8; Self::LEN] = s.as_bytes().try_into().map_err(|_| ApiKeyError::Length)?;
        let (head, rest) = b
            .split_first_chunk::<{ DisplayPrefix::LEN }>()
            .ok_or(ApiKeyError::Length)?;
        let head = parse_head(head)?;
        let (sep, secret) = rest.split_first().ok_or(ApiKeyError::Length)?;
        if *sep != b'_' {
            return Err(ApiKeyError::Separator);
        }
        let secret = core::str::from_utf8(secret).map_err(|_| ApiKeyError::Secret)?;
        if !is_canonical_b64url(secret, 32) {
            return Err(ApiKeyError::Secret);
        }
        Ok(Self {
            head,
            full: Zeroizing::new(s.to_owned()),
        })
    }

    /// The key kind.
    #[must_use]
    pub const fn kind(&self) -> ApiKeyKind {
        self.head.kind
    }

    /// The 8-character public prefix.
    #[must_use]
    pub const fn prefix(&self) -> KeyPrefix {
        self.head.prefix
    }

    /// The display prefix: the first 15 characters, for example
    /// `tut_sk_7f3k9q2m`. Safe to show and log.
    #[must_use]
    pub const fn display_prefix(&self) -> DisplayPrefix {
        self.head
    }

    /// The **full key, including the secret**. Use it only to compute
    /// `SHA-256(pepper ‖ key)`. Never log, print, store or send it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.full
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("display_prefix", &format_args!("{}", self.head))
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.head, f)
    }
}

impl FromStr for ApiKey {
    type Err = ApiKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const DOC_KEY: &str = "tut_sk_7f3k9q2m_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const SECRET: &str = "Zm9vYmFyLWJhei1xdXV4LWNvcmdlLWdyYXVsdC1nYXA";

    fn key_with_secret(secret: &str) -> String {
        format!("tut_ak_ab12cd34_{secret}")
    }

    #[test]
    fn doc_example() {
        assert_eq!(DOC_KEY.len(), 59);
        let key = ApiKey::parse(DOC_KEY).unwrap();
        assert_eq!(key.kind(), ApiKeyKind::Sk);
        assert_eq!(key.prefix().as_str(), "7f3k9q2m");
        assert_eq!(key.display_prefix().to_string(), "tut_sk_7f3k9q2m");
        assert_eq!(key.expose_secret(), DOC_KEY);
        assert_eq!(
            &DOC_KEY[..DisplayPrefix::LEN],
            key.display_prefix().to_string()
        );
    }

    #[test]
    fn secret_never_in_debug_or_display() {
        let full = key_with_secret(SECRET);
        let key = ApiKey::parse(&full).unwrap();
        let debug = format!("{key:?}");
        let pretty = format!("{key:#?}");
        let display = key.to_string();
        for out in [&debug, &pretty, &display] {
            assert!(!out.contains(SECRET), "{out}");
            assert!(!out.contains(&SECRET[..8]), "{out}");
            assert!(!out.contains(&full), "{out}");
        }
        assert_eq!(display, "tut_ak_ab12cd34");
        assert!(debug.contains("tut_ak_ab12cd34"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn secret_with_underscores_parses_by_position() {
        let secret = format!("{}A", "_".repeat(42));
        let key = ApiKey::parse(&key_with_secret(&secret)).unwrap();
        assert_eq!(key.prefix().as_str(), "ab12cd34");
        let secret = "a_b-c_d-e_f-g_h-i_j-k_l-m_n-o_p-q_r-s_t-u_w";
        assert!(ApiKey::parse(&key_with_secret(secret)).is_ok());
    }

    #[test]
    fn rejects_bad_keys() {
        let cases: Vec<(String, ApiKeyError)> = vec![
            (String::new(), ApiKeyError::Length),
            (format!("{DOC_KEY} "), ApiKeyError::Length),
            (format!(" {DOC_KEY}"), ApiKeyError::Length),
            (format!("{DOC_KEY}\n"), ApiKeyError::Length),
            (DOC_KEY[..58].to_owned(), ApiKeyError::Length),
            (DOC_KEY.replacen("tut_", "tit_", 1), ApiKeyError::Marker),
            (DOC_KEY.replacen("tut_", "TUT_", 1), ApiKeyError::Marker),
            (DOC_KEY.replacen("_sk_", "_pk_", 1), ApiKeyError::Kind),
            (DOC_KEY.replacen("_sk_", "_SK_", 1), ApiKeyError::Kind),
            (DOC_KEY.replacen("_sk_", "_sk-", 1), ApiKeyError::Separator),
            (
                DOC_KEY.replacen("7f3k9q2m_", "7f3k9q2m-", 1),
                ApiKeyError::Separator,
            ),
            (
                DOC_KEY.replacen("7f3k9q2m", "7F3K9Q2M", 1),
                ApiKeyError::Prefix,
            ),
            (
                DOC_KEY.replacen("7f3k9q2m", "7f3k9q2_", 1),
                ApiKeyError::Prefix,
            ),
            (
                key_with_secret(&format!("{}B", "A".repeat(42))),
                ApiKeyError::Secret,
            ),
            (
                key_with_secret(&format!("{}+", "A".repeat(42))),
                ApiKeyError::Secret,
            ),
            (
                key_with_secret(&format!("{}=", "A".repeat(42))),
                ApiKeyError::Secret,
            ),
            (
                key_with_secret(&format!("{} A", "A".repeat(41))),
                ApiKeyError::Secret,
            ),
            // 59 bytes, but a multi-byte character: never sliced, still rejected.
            (
                key_with_secret(&format!("{}\u{e9}", "A".repeat(41))),
                ApiKeyError::Secret,
            ),
            (format!("\u{e9}{}", &DOC_KEY[2..]), ApiKeyError::Marker),
        ];
        for (input, err) in cases {
            assert_eq!(
                ApiKey::parse(&input).map(|k| k.display_prefix()),
                Err(err),
                "{input:?}"
            );
        }
        // Every canonical last character is accepted.
        for c in "AEIMQUYcgkosw048".chars() {
            let secret = format!("{}{c}", "A".repeat(42));
            assert!(ApiKey::parse(&key_with_secret(&secret)).is_ok(), "{c}");
        }
    }

    #[test]
    fn errors_never_hold_the_key() {
        let bad = key_with_secret(&format!("{}B", SECRET.get(..42).unwrap()));
        let err = ApiKey::parse(&bad).map(|_| ()).unwrap_err();
        assert!(!err.to_string().contains(&SECRET[..20]));
        assert!(!format!("{err:?}").contains(&SECRET[..20]));
        assert!(err.to_string().starts_with("invalid API key"));
    }

    #[test]
    fn prefixes_and_kinds() {
        let p: DisplayPrefix = "tut_ak_0000zzzz".parse().unwrap();
        assert_eq!(p.kind(), ApiKeyKind::Ak);
        assert_eq!(p.prefix().to_string(), "0000zzzz");
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"tut_ak_0000zzzz\"");
        assert_eq!(
            serde_json::from_str::<DisplayPrefix>("\"tut_ak_0000zzzz\"").unwrap(),
            p
        );
        assert!("tut_ak_0000zzz".parse::<DisplayPrefix>().is_err());
        assert!("tut_xk_0000zzzz".parse::<DisplayPrefix>().is_err());
        assert_eq!("sk".parse::<ApiKeyKind>(), Ok(ApiKeyKind::Sk));
        assert!("SK".parse::<ApiKeyKind>().is_err());
        assert!("s".parse::<ApiKeyKind>().is_err());
        assert_eq!(serde_json::to_string(&ApiKeyKind::Ak).unwrap(), "\"ak\"");
        assert!("abcdefgh".parse::<KeyPrefix>().is_ok());
        assert!("abcdefg".parse::<KeyPrefix>().is_err());
        assert!("abcdefgH".parse::<KeyPrefix>().is_err());
    }

    fn secret_strategy() -> impl Strategy<Value = String> {
        ("[A-Za-z0-9_-]{42}", "[AEIMQUYcgkosw048]").prop_map(|(a, b)| format!("{a}{b}"))
    }

    proptest! {
        #[test]
        fn round_trip(kind in prop::sample::select(vec!["sk", "ak"]), prefix in "[a-z0-9]{8}", secret in secret_strategy()) {
            let s = format!("tut_{kind}_{prefix}_{secret}");
            let key = ApiKey::parse(&s).unwrap();
            prop_assert_eq!(key.expose_secret(), s.as_str());
            prop_assert_eq!(key.kind().as_str(), kind);
            let got = key.prefix();
            prop_assert_eq!(got.as_str(), prefix.as_str());
            prop_assert_eq!(key.display_prefix().to_string(), format!("tut_{kind}_{prefix}"));
            prop_assert_eq!(key.display_prefix().to_string().parse::<DisplayPrefix>(), Ok(key.display_prefix()));
            let debug = format!("{key:?}");
            prop_assert!(!debug.contains(&secret));
            prop_assert!(!key.to_string().contains(&secret));
        }

        #[test]
        fn non_canonical_secret_is_rejected(prefix in "[a-z0-9]{8}", head in "[A-Za-z0-9_-]{42}", last in "[BCDFGHJKLNOPRSTVWXZabdefhijlmnpqrtuvxyz1235679_-]") {
            let s = format!("tut_sk_{prefix}_{head}{last}");
            prop_assert_eq!(ApiKey::parse(&s).map(|k| k.display_prefix()), Err(ApiKeyError::Secret));
        }

        #[test]
        fn whitespace_anywhere_is_rejected(prefix in "[a-z0-9]{8}", secret in secret_strategy(), at in 0usize..60, ws in "[ \\t\\r\\n]") {
            let mut s = format!("tut_sk_{prefix}_{secret}");
            s.insert_str(at.min(s.len()), &ws);
            prop_assert!(ApiKey::parse(&s).is_err());
        }

        #[test]
        fn never_panics(s in "\\PC{0,70}") {
            let _ = ApiKey::parse(&s);
            let _ = DisplayPrefix::parse(&s);
        }
    }
}
