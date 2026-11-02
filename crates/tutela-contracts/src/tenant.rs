//! Tenants, orgs, issuers and the tenant key `(iss, tid)` (CONTRACTS.md 1.5
//! and 1.6).

use core::fmt;
use core::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

prefixed_id!(
    /// A tenant id, `ten_<uuidv7>`: the unit of isolation. Never use it alone
    /// as a key; the tenant is always the pair [`TenantKey`] `(iss, tid)`.
    TenantId,
    "ten_"
);

prefixed_id!(
    /// An org id, `org_<uuidv7>`: an organization inside a tenant, the root of
    /// every resource tree in it.
    OrgId,
    "org_"
);

/// Why an issuer URL was rejected (CONTRACTS.md 1.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IssuerError {
    /// The issuer is longer than 255 characters.
    #[error("an issuer is at most 255 characters")]
    TooLong,
    /// The issuer has a character that is not visible ASCII.
    #[error("an issuer may only contain visible ASCII characters")]
    Char,
    /// The issuer does not start with `https://` (or `http://`).
    #[error("an issuer must be an absolute `https://` URL")]
    Scheme,
    /// The issuer has user info (`user@host`).
    #[error("an issuer must not have user info")]
    UserInfo,
    /// The issuer has a query (`?`).
    #[error("an issuer must not have a query")]
    Query,
    /// The issuer has a fragment (`#`).
    #[error("an issuer must not have a fragment")]
    Fragment,
    /// The host is empty or not a DNS name, IPv4 address or `[IPv6]` literal.
    #[error("an issuer must have a valid host")]
    Host,
    /// The port is not a number from 1 to 65535 without a leading zero.
    #[error("an issuer port must be a number from 1 to 65535")]
    Port,
    /// The path has a character that a URL path cannot have unencoded, or a
    /// bad percent-encoding.
    #[error("an issuer path has an invalid character")]
    Path,
    /// `http` is used with a host that is not `localhost`, `127.0.0.1` or `[::1]`.
    #[error("`http` issuers are allowed only for a loopback host in dev mode")]
    HttpNotLoopback,
}

/// An issuer (`iss`): an absolute URL, compared as exact text
/// (CONTRACTS.md 1.6).
///
/// Rules: `https://` (lowercase), a host (DNS name, IPv4 or `[IPv6]`), an
/// optional `:port`, an optional path; no user info, no query, no fragment; at
/// most 255 visible ASCII characters. No trailing-slash fix-ups and no case
/// folding.
///
/// `http://` parses only with a loopback host (`localhost`, `127.0.0.1`,
/// `[::1]`). Such an issuer is for dev mode only: a [`TrustList`] accepts it
/// only when it was made with [`TrustList::dev_mode`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Issuer(String);

impl Issuer {
    /// The longest issuer in characters.
    pub const MAX_LEN: usize = 255;

    /// Parses an issuer URL.
    ///
    /// # Errors
    ///
    /// Returns an [`IssuerError`] when `s` breaks a rule above.
    pub fn parse(s: &str) -> Result<Self, IssuerError> {
        if s.len() > Self::MAX_LEN {
            return Err(IssuerError::TooLong);
        }
        if !s.bytes().all(crate::text::is_visible_ascii) {
            return Err(IssuerError::Char);
        }
        let (rest, https) = if let Some(rest) = s.strip_prefix("https://") {
            (rest, true)
        } else if let Some(rest) = s.strip_prefix("http://") {
            (rest, false)
        } else {
            return Err(IssuerError::Scheme);
        };
        if s.contains('?') {
            return Err(IssuerError::Query);
        }
        if s.contains('#') {
            return Err(IssuerError::Fragment);
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(IssuerError::UserInfo);
        }
        let (host, port) = split_host_port(authority)?;
        if !is_valid_host(host) {
            return Err(IssuerError::Host);
        }
        if let Some(port) = port
            && crate::text::parse_port(port).is_none()
        {
            return Err(IssuerError::Port);
        }
        if !is_valid_path(path) {
            return Err(IssuerError::Path);
        }
        if !https && !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
            return Err(IssuerError::HttpNotLoopback);
        }
        Ok(Self(s.to_owned()))
    }

    /// The issuer text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` for an `https://` issuer.
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.0.starts_with("https://")
    }

    /// `true` for an `http://` loopback issuer, which is allowed in dev mode
    /// only.
    #[must_use]
    pub fn is_dev_only(&self) -> bool {
        !self.is_https()
    }
}

/// Splits `host[:port]`. An IPv6 literal keeps its brackets.
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), IssuerError> {
    if authority.starts_with('[') {
        let end = authority.find(']').ok_or(IssuerError::Host)?;
        let (host, after) = authority.split_at(end + 1);
        if after.is_empty() {
            Ok((host, None))
        } else {
            let port = after.strip_prefix(':').ok_or(IssuerError::Host)?;
            Ok((host, Some(port)))
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => Ok((host, Some(port))),
            None => Ok((authority, None)),
        }
    }
}

/// A DNS name, an IPv4 address in dotted decimal, or an `[IPv6]` literal.
///
/// A DNS name is labels of `A-Z a-z 0-9 -`, 1 to 63 characters each, not
/// starting or ending with `-`, joined by single `.` (no empty label, no
/// trailing `.`). A host of only digits and dots must be a valid IPv4 address
/// (four parts, each 0 to 255, no leading zeros).
fn is_valid_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return false;
        };
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host.parse::<std::net::Ipv4Addr>().is_ok();
    }
    host.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// An empty path, or `/` followed by RFC 3986 path characters.
fn is_valid_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let ok = matches!(
                (bytes.get(i + 1), bytes.get(i + 2)),
                (Some(h), Some(l)) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit()
            );
            if !ok {
                return false;
            }
            i += 3;
            continue;
        }
        let allowed = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'/' | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            );
        if !allowed {
            return false;
        }
        i += 1;
    }
    true
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Issuer {
    type Err = IssuerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(Issuer, "an issuer URL string");

/// The tenant key `(iss, tid)` (CONTRACTS.md 1.6).
///
/// The tenant is always this pair: in the PDP, database keys, caches and
/// audit records. There is no one-string form on the wire.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct TenantKey {
    /// The issuer.
    pub iss: Issuer,
    /// The tenant id.
    pub tid: TenantId,
}

impl TenantKey {
    /// Makes a tenant key.
    #[must_use]
    pub const fn new(iss: Issuer, tid: TenantId) -> Self {
        Self { iss, tid }
    }
}

/// Why an entry was refused by a [`TrustList`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TrustListError {
    /// An `http` issuer was added to a trust list that is not in dev mode.
    #[error("an `http` issuer can only be trusted in dev mode")]
    DevOnlyIssuer,
}

/// The trust list: each trusted issuer and the tenants it may speak for
/// (CONTRACTS.md 1.6).
///
/// A token is accepted only if its `(iss, tid)` pair is on the list. A
/// production list refuses `http` issuers; a list made with
/// [`TrustList::dev_mode`] accepts `http` loopback issuers too.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TrustList {
    dev_mode: bool,
    issuers: BTreeMap<Issuer, BTreeSet<TenantId>>,
    /// Issuers trusted for every tenant of a directory the holder checks on
    /// each request ([`TrustList::insert_directory`]).
    directory: BTreeSet<Issuer>,
}

impl TrustList {
    /// An empty production trust list (`https` issuers only).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty dev-mode trust list. It also accepts `http` loopback issuers.
    #[must_use]
    pub fn dev_mode() -> Self {
        Self {
            dev_mode: true,
            ..Self::default()
        }
    }

    /// `true` if this list was made with [`TrustList::dev_mode`].
    #[must_use]
    pub const fn is_dev_mode(&self) -> bool {
        self.dev_mode
    }

    /// Trusts `issuer` to speak for `tenant`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustListError::DevOnlyIssuer`] for an `http` issuer when the
    /// list is not in dev mode.
    pub fn insert(&mut self, issuer: Issuer, tenant: TenantId) -> Result<(), TrustListError> {
        if issuer.is_dev_only() && !self.dev_mode {
            return Err(TrustListError::DevOnlyIssuer);
        }
        self.issuers.entry(issuer).or_default().insert(tenant);
        Ok(())
    }

    /// Like [`TrustList::insert`], but takes and returns the list, for
    /// building one in a chain.
    ///
    /// # Errors
    ///
    /// The same as [`TrustList::insert`].
    pub fn with(mut self, issuer: Issuer, tenant: TenantId) -> Result<Self, TrustListError> {
        self.insert(issuer, tenant)?;
        Ok(self)
    }

    /// Trusts `issuer` for every tenant of the holder's own tenant
    /// directory. **Only for a service that is that issuer and checks each
    /// request's `(iss, tid)` against its directory**, as `tutelad` does for
    /// its own tokens: its tenants are made at runtime, so no static list
    /// can name them. A token of such an issuer whose tenant is not in the
    /// directory is still refused, by the directory. A product never uses
    /// this; it names its tenants.
    ///
    /// Such an issuer has no [`TrustList::sole_tenant`], so it can never be
    /// an external issuer (CONTRACTS.md 1.6).
    ///
    /// # Errors
    ///
    /// Returns [`TrustListError::DevOnlyIssuer`] for an `http` issuer when the
    /// list is not in dev mode.
    pub fn insert_directory(&mut self, issuer: Issuer) -> Result<(), TrustListError> {
        if issuer.is_dev_only() && !self.dev_mode {
            return Err(TrustListError::DevOnlyIssuer);
        }
        self.directory.insert(issuer);
        Ok(())
    }

    /// `true` if `issuer` was added with [`TrustList::insert_directory`].
    #[must_use]
    pub fn is_directory(&self, issuer: &Issuer) -> bool {
        self.directory.contains(issuer)
    }

    /// `true` if `issuer` is on the list.
    #[must_use]
    pub fn has_issuer(&self, issuer: &Issuer) -> bool {
        self.issuers.contains_key(issuer) || self.directory.contains(issuer)
    }

    /// `true` if the pair `(issuer, tenant)` is on the list. For an issuer
    /// of [`TrustList::insert_directory`] the holder's directory decides,
    /// so this is `true` for every tenant id.
    #[must_use]
    pub fn allows(&self, issuer: &Issuer, tenant: &TenantId) -> bool {
        self.directory.contains(issuer)
            || self
                .issuers
                .get(issuer)
                .is_some_and(|tenants| tenants.contains(tenant))
    }

    /// `true` if the tenant key is on the list.
    #[must_use]
    pub fn allows_key(&self, key: &TenantKey) -> bool {
        self.allows(&key.iss, &key.tid)
    }

    /// The tenants that `issuer` may speak for.
    #[must_use]
    pub fn tenants(&self, issuer: &Issuer) -> Option<&BTreeSet<TenantId>> {
        self.issuers.get(issuer)
    }

    /// The single tenant of an issuer that maps to **exactly one** tenant.
    ///
    /// An external issuer whose tokens carry no `tid` (Phase A) must map to
    /// exactly one tenant. Returns `None` when the issuer is unknown or maps
    /// to more than one tenant.
    #[must_use]
    pub fn sole_tenant(&self, issuer: &Issuer) -> Option<&TenantId> {
        let tenants = self.issuers.get(issuer)?;
        if tenants.len() == 1 {
            tenants.first()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::uuid7_strategy;
    use proptest::prelude::*;

    const TEN: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";
    const ORG: &str = "org_0193a1b2-c3d4-7f00-9a00-000000000002";

    #[test]
    fn tenant_and_org_ids() {
        let t: TenantId = TEN.parse().unwrap();
        assert_eq!(t.to_string(), TEN);
        let o: OrgId = ORG.parse().unwrap();
        assert_eq!(o.to_string(), ORG);
        assert!(ORG.parse::<TenantId>().is_err());
        assert!(TEN.parse::<OrgId>().is_err());
    }

    #[test]
    fn tenant_key_json_matches_the_doc() {
        let doc = r#"{ "iss": "https://auth.example.test", "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b" }"#;
        let key: TenantKey = serde_json::from_str(doc).unwrap();
        assert_eq!(key.iss.as_str(), "https://auth.example.test");
        assert_eq!(key.tid.to_string(), TEN);
        assert_eq!(
            serde_json::to_value(&key).unwrap(),
            serde_json::from_str::<serde_json::Value>(doc).unwrap()
        );
        // Unknown fields are ignored; missing or null required fields are not.
        assert!(
            serde_json::from_str::<TenantKey>(&format!(
                r#"{{"iss":"https://a.test","tid":"{TEN}","extra":1}}"#
            ))
            .is_ok()
        );
        assert!(serde_json::from_str::<TenantKey>(r#"{"iss":"https://a.test"}"#).is_err());
        assert!(
            serde_json::from_str::<TenantKey>(r#"{"iss":"https://a.test","tid":null}"#).is_err()
        );
    }

    #[test]
    fn valid_issuers() {
        for ok in [
            "https://auth.example.test",
            "https://auth.example.test/",
            "https://auth.example.test/realms/main",
            "https://auth.example.test:8443/realms/main",
            "https://Auth.Example.test",
            "https://10.0.0.1",
            "https://[2001:db8::1]:8443/x",
            "https://auth.example.test/a%20b",
            "http://localhost",
            "http://localhost:8080/realms/dev",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            let iss = Issuer::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert_eq!(iss.as_str(), ok);
            assert_eq!(iss.is_dev_only(), ok.starts_with("http://"));
        }
    }

    #[test]
    fn invalid_issuers() {
        let long = format!("https://a.test/{}", "x".repeat(241));
        assert_eq!(long.len(), 256);
        let cases: Vec<(&str, IssuerError)> = vec![
            ("", IssuerError::Scheme),
            ("auth.example.test", IssuerError::Scheme),
            ("HTTPS://auth.example.test", IssuerError::Scheme),
            ("ftp://auth.example.test", IssuerError::Scheme),
            ("https://", IssuerError::Host),
            ("https:///path", IssuerError::Host),
            ("https://user@auth.example.test", IssuerError::UserInfo),
            ("https://user:pw@auth.example.test", IssuerError::UserInfo),
            ("https://auth.example.test?x=1", IssuerError::Query),
            ("https://auth.example.test/#frag", IssuerError::Fragment),
            ("https://auth.example.test:", IssuerError::Port),
            ("https://auth.example.test:0", IssuerError::Port),
            ("https://auth.example.test:65536", IssuerError::Port),
            ("https://auth.example.test:08443", IssuerError::Port),
            ("https://auth.example.test/a b", IssuerError::Char),
            ("https://auth.example.test/caf\u{e9}", IssuerError::Char),
            ("https://auth.example.test/a\\b", IssuerError::Path),
            ("https://auth.example.test/a%2", IssuerError::Path),
            ("https://auth.example.test/a%zz", IssuerError::Path),
            ("https://auth_example.test", IssuerError::Host),
            // Regression: these hosts were accepted before.
            ("https://auth..example.test", IssuerError::Host),
            ("https://auth.example.test.", IssuerError::Host),
            ("https://auth.example.test./x", IssuerError::Host),
            ("https://auth-.example.test", IssuerError::Host),
            ("https://-auth.example.test", IssuerError::Host),
            ("https://auth.-example.test", IssuerError::Host),
            ("https://.auth.example.test", IssuerError::Host),
            ("https://999.0.0.1", IssuerError::Host),
            ("https://10.0.0", IssuerError::Host),
            ("https://010.0.0.1", IssuerError::Host),
            ("https://10.0.0.1.", IssuerError::Host),
            ("http://localhost.", IssuerError::Host),
            ("https://[::1", IssuerError::Host),
            ("https://[zz::1]", IssuerError::Host),
            ("https://[::1]x", IssuerError::Host),
            ("http://auth.example.test", IssuerError::HttpNotLoopback),
            ("http://127.0.0.2", IssuerError::HttpNotLoopback),
            (
                "http://localhost.example.test",
                IssuerError::HttpNotLoopback,
            ),
            (&long, IssuerError::TooLong),
        ];
        for (input, err) in cases {
            assert_eq!(Issuer::parse(input), Err(err), "{input:?}");
        }
        let max = format!("https://a.test/{}", "x".repeat(240));
        assert_eq!(max.len(), 255);
        assert!(Issuer::parse(&max).is_ok());
        // DNS label length: 63 is fine, 64 is not.
        let label63 = format!("https://{}.test", "a".repeat(63));
        assert!(Issuer::parse(&label63).is_ok());
        let label64 = format!("https://{}.test", "a".repeat(64));
        assert_eq!(Issuer::parse(&label64), Err(IssuerError::Host));
        // Labels may hold `-` inside, and a label may be all digits when the
        // host is not only digits and dots.
        assert!(Issuer::parse("https://a-b.c-d.example.test").is_ok());
        assert!(Issuer::parse("https://10.0.0.1.example.test").is_ok());
        assert!(Issuer::parse("https://255.255.255.255").is_ok());
    }

    #[test]
    fn trust_list() {
        let iss = Issuer::parse("https://auth.example.test").unwrap();
        let other = Issuer::parse("https://other.example.test").unwrap();
        let t1: TenantId = TEN.parse().unwrap();
        let t2: TenantId = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c".parse().unwrap();
        let list = TrustList::new().with(iss.clone(), t1).unwrap();
        assert!(list.has_issuer(&iss));
        assert!(!list.has_issuer(&other));
        assert!(list.allows(&iss, &t1));
        assert!(!list.allows(&iss, &t2));
        assert!(!list.allows(&other, &t1));
        assert!(list.allows_key(&TenantKey::new(iss.clone(), t1)));
        assert_eq!(list.sole_tenant(&iss), Some(&t1));
        let list = list.with(iss.clone(), t2).unwrap();
        assert_eq!(list.sole_tenant(&iss), None);
        assert_eq!(list.tenants(&iss).map(BTreeSet::len), Some(2));
        assert_eq!(list.sole_tenant(&other), None);

        let dev = Issuer::parse("http://localhost:8080").unwrap();
        let mut prod = TrustList::new();
        assert_eq!(
            prod.insert(dev.clone(), t1),
            Err(TrustListError::DevOnlyIssuer)
        );
        assert!(!prod.has_issuer(&dev));
        let dev_list = TrustList::dev_mode().with(dev.clone(), t1).unwrap();
        assert!(dev_list.is_dev_mode());
        assert!(dev_list.allows(&dev, &t1));
    }

    #[test]
    fn tm05_a_directory_issuer_speaks_for_any_tenant_but_is_never_external() {
        let own = Issuer::parse("https://tutela.example.test").unwrap();
        let other = Issuer::parse("https://other.example.test").unwrap();
        let t1: TenantId = TEN.parse().unwrap();
        let t2: TenantId = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c".parse().unwrap();
        let mut list = TrustList::new().with(other.clone(), t1).unwrap();
        list.insert_directory(own.clone()).unwrap();
        assert!(list.is_directory(&own));
        assert!(!list.is_directory(&other));
        assert!(list.has_issuer(&own));
        assert!(list.allows(&own, &t1) && list.allows(&own, &t2));
        // The other issuer keeps its own list.
        assert!(list.allows(&other, &t1) && !list.allows(&other, &t2));
        // No sole tenant: a directory issuer can never stand in for an
        // external issuer's one tenant.
        assert_eq!(list.sole_tenant(&own), None);
        assert_eq!(list.tenants(&own), None);
        let dev = Issuer::parse("http://localhost:8080").unwrap();
        assert_eq!(
            TrustList::new().insert_directory(dev.clone()),
            Err(TrustListError::DevOnlyIssuer)
        );
        TrustList::dev_mode().insert_directory(dev).unwrap();
    }

    proptest! {
        #[test]
        fn ids_round_trip(u in uuid7_strategy()) {
            let t = TenantId::new(u);
            prop_assert_eq!(t.to_string().parse::<TenantId>(), Ok(t));
            let o = OrgId::new(u);
            prop_assert_eq!(o.to_string().parse::<OrgId>(), Ok(o));
        }

        #[test]
        fn https_issuers_round_trip(
            host in "[a-z][a-z0-9]{0,9}(\\.[a-z0-9]{1,10}){0,3}",
            port in proptest::option::of(1u16..),
            path in "(/[A-Za-z0-9._~-]{0,10}){0,4}",
        ) {
            let port = port.map(|p| format!(":{p}")).unwrap_or_default();
            let s = format!("https://{host}{port}{path}");
            let iss = Issuer::parse(&s).unwrap();
            prop_assert_eq!(iss.to_string(), s.clone());
            let json = serde_json::to_string(&iss).unwrap();
            prop_assert_eq!(serde_json::from_str::<Issuer>(&json).unwrap(), iss);
        }

        #[test]
        fn ip_issuers_round_trip(v4 in any::<[u8; 4]>(), v6 in any::<[u16; 8]>()) {
            let v4 = std::net::Ipv4Addr::from(v4);
            let s = format!("https://{v4}/x");
            prop_assert_eq!(Issuer::parse(&s).map(|i| i.to_string()), Ok(s));
            let v6 = std::net::Ipv6Addr::from(v6);
            let s = format!("https://[{v6}]:8443");
            prop_assert_eq!(Issuer::parse(&s).map(|i| i.to_string()), Ok(s));
        }

        #[test]
        fn issuer_parse_never_panics(s in "\\PC{0,64}") {
            let _ = Issuer::parse(&s);
            let _ = Issuer::parse(&format!("https://{s}"));
            let _ = Issuer::parse(&format!("https://[{s}"));
        }
    }
}
