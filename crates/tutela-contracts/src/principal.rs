//! Principals: who is asking (CONTRACTS.md 1.3 and 1.4).
//!
//! On the wire a principal is one string, `<kind>:<id>`:
//! `user:usr_<uuidv7>`, `sa:sa_<uuidv7>`, `key:key_<uuidv7>`,
//! `agent:agt_<uuidv7>` or `workload:spiffe://...`.
//!
//! Phase B adds the trust-bundle binding of workload principals. This module
//! only checks the text.

use core::fmt;
use core::str::FromStr;

use crate::id::IdError;

prefixed_id!(
    /// A user id, `usr_<uuidv7>`: a person.
    UserId,
    "usr_"
);

prefixed_id!(
    /// A service account id, `sa_<uuidv7>`: an app or service that acts as itself.
    ServiceAccountId,
    "sa_"
);

prefixed_id!(
    /// An API key id, `key_<uuidv7>`: one API key.
    KeyId,
    "key_"
);

prefixed_id!(
    /// An agent id, `agt_<uuidv7>`: an AI agent. attache owns its runtime.
    AgentId,
    "agt_"
);

/// Why a SPIFFE ID was rejected (CONTRACTS.md 1.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpiffeError {
    /// The whole SPIFFE ID is longer than 2048 bytes.
    #[error("a SPIFFE ID is at most 2048 bytes")]
    TooLong,
    /// The text does not start with `spiffe://`.
    #[error("a SPIFFE ID must start with `spiffe://`")]
    Scheme,
    /// The trust domain is empty.
    #[error("the trust domain must not be empty")]
    EmptyTrustDomain,
    /// The trust domain is longer than 255 characters.
    #[error("the trust domain is at most 255 characters")]
    TrustDomainTooLong,
    /// The trust domain has a character outside `a-z 0-9 . - _` (this also
    /// rejects uppercase, a port and user info).
    #[error("the trust domain may only contain a-z, 0-9, `.`, `-` and `_`")]
    TrustDomainChar,
    /// There is no path: the ID names a trust domain, not a workload.
    #[error("a workload SPIFFE ID must have a path")]
    EmptyPath,
    /// A path segment is empty (`//` or a trailing `/`).
    #[error("a path segment must not be empty")]
    EmptySegment,
    /// A path segment is `.` or `..`.
    #[error("a path segment must not be `.` or `..`")]
    DotSegment,
    /// A path segment has a character outside `a-z A-Z 0-9 . - _` (this also
    /// rejects a query, a fragment and percent-encoding).
    #[error("a path segment may only contain a-z, A-Z, 0-9, `.`, `-` and `_`")]
    SegmentChar,
}

/// A workload id: a SPIFFE ID with a non-empty path (CONTRACTS.md 1.4).
///
/// The text form is `spiffe://<trust-domain>/<segment>/...`. attache runs
/// workload mTLS; Tutela only names the workload.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WorkloadId {
    text: String,
    /// The byte index of the first `/` of the path.
    path_start: usize,
}

impl WorkloadId {
    /// The longest SPIFFE ID in bytes.
    pub const MAX_LEN: usize = 2048;
    /// The longest trust domain in characters.
    pub const MAX_TRUST_DOMAIN_LEN: usize = 255;
    /// The scheme, always lowercase.
    pub const SCHEME: &'static str = "spiffe://";

    /// Parses a SPIFFE ID with Tutela's extra rules.
    ///
    /// # Errors
    ///
    /// Returns a [`SpiffeError`] when `s` breaks a rule of CONTRACTS.md 1.4.
    pub fn parse(s: &str) -> Result<Self, SpiffeError> {
        if s.len() > Self::MAX_LEN {
            return Err(SpiffeError::TooLong);
        }
        let rest = s.strip_prefix(Self::SCHEME).ok_or(SpiffeError::Scheme)?;
        let (trust_domain, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if trust_domain.is_empty() {
            return Err(SpiffeError::EmptyTrustDomain);
        }
        if trust_domain.len() > Self::MAX_TRUST_DOMAIN_LEN {
            return Err(SpiffeError::TrustDomainTooLong);
        }
        if !trust_domain
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
        {
            return Err(SpiffeError::TrustDomainChar);
        }
        let Some(segments) = path.strip_prefix('/') else {
            return Err(SpiffeError::EmptyPath);
        };
        for segment in segments.split('/') {
            if segment.is_empty() {
                return Err(SpiffeError::EmptySegment);
            }
            if segment == "." || segment == ".." {
                return Err(SpiffeError::DotSegment);
            }
            if !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return Err(SpiffeError::SegmentChar);
            }
        }
        Ok(Self {
            text: s.to_owned(),
            path_start: Self::SCHEME.len() + trust_domain.len(),
        })
    }

    /// The whole SPIFFE ID, `spiffe://...`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The trust domain, for example `prod-eu1.attache.example.test`.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        self.text
            .get(Self::SCHEME.len()..self.path_start)
            .unwrap_or_default()
    }

    /// The path, starting with `/`, for example `/ns/shop/svc/orders`.
    #[must_use]
    pub fn path(&self) -> &str {
        self.text.get(self.path_start..).unwrap_or_default()
    }
}

impl fmt::Display for WorkloadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl FromStr for WorkloadId {
    type Err = SpiffeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(WorkloadId, "a SPIFFE ID string");

/// The kind of a principal: the text before the first `:`. A closed set.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PrincipalKind {
    /// `user`: a person.
    User,
    /// `sa`: a service account.
    ServiceAccount,
    /// `key`: one API key.
    Key,
    /// `agent`: an AI agent.
    Agent,
    /// `workload`: a workload with a SPIFFE ID.
    Workload,
}

impl PrincipalKind {
    /// Every kind, in the order of CONTRACTS.md 1.3.
    pub const ALL: [Self; 5] = [
        Self::User,
        Self::ServiceAccount,
        Self::Key,
        Self::Agent,
        Self::Workload,
    ];

    /// The wire name: `user`, `sa`, `key`, `agent` or `workload`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "sa",
            Self::Key => "key",
            Self::Agent => "agent",
            Self::Workload => "workload",
        }
    }
}

impl fmt::Display for PrincipalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PrincipalKind {
    type Err = PrincipalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or(PrincipalError::UnknownKind)
    }
}

string_serde!(
    PrincipalKind,
    "a principal kind: user, sa, key, agent or workload"
);

/// Why a principal string was rejected (CONTRACTS.md 1.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PrincipalError {
    /// There is no `:`.
    #[error("a principal must be `<kind>:<id>`")]
    MissingKind,
    /// The kind is not `user`, `sa`, `key`, `agent` or `workload`.
    #[error("unknown principal kind; expected user, sa, key, agent or workload")]
    UnknownKind,
    /// The id does not fit the kind (wrong prefix or bad UUIDv7).
    #[error("invalid principal id")]
    Id(#[from] IdError),
    /// The workload id is not a valid SPIFFE ID.
    #[error("invalid workload SPIFFE ID")]
    Workload(#[from] SpiffeError),
}

/// A principal: who is asking (CONTRACTS.md 1.3). A group is never a
/// principal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Principal {
    /// `user:usr_<uuidv7>`.
    User(UserId),
    /// `sa:sa_<uuidv7>`.
    ServiceAccount(ServiceAccountId),
    /// `key:key_<uuidv7>`.
    Key(KeyId),
    /// `agent:agt_<uuidv7>`.
    Agent(AgentId),
    /// `workload:spiffe://...`.
    Workload(WorkloadId),
}

impl Principal {
    /// The longest principal string in bytes (`workload:` plus 2048).
    pub const MAX_LEN: usize = 9 + WorkloadId::MAX_LEN;

    /// The kind of this principal.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        match self {
            Self::User(_) => PrincipalKind::User,
            Self::ServiceAccount(_) => PrincipalKind::ServiceAccount,
            Self::Key(_) => PrincipalKind::Key,
            Self::Agent(_) => PrincipalKind::Agent,
            Self::Workload(_) => PrincipalKind::Workload,
        }
    }

    /// The user id, if this is a user.
    #[must_use]
    pub const fn as_user(&self) -> Option<&UserId> {
        match self {
            Self::User(id) => Some(id),
            _ => None,
        }
    }

    /// The service account id, if this is a service account.
    #[must_use]
    pub const fn as_service_account(&self) -> Option<&ServiceAccountId> {
        match self {
            Self::ServiceAccount(id) => Some(id),
            _ => None,
        }
    }

    /// The key id, if this is an API key.
    #[must_use]
    pub const fn as_key(&self) -> Option<&KeyId> {
        match self {
            Self::Key(id) => Some(id),
            _ => None,
        }
    }

    /// The agent id, if this is an agent.
    #[must_use]
    pub const fn as_agent(&self) -> Option<&AgentId> {
        match self {
            Self::Agent(id) => Some(id),
            _ => None,
        }
    }

    /// The workload id, if this is a workload.
    #[must_use]
    pub const fn as_workload(&self) -> Option<&WorkloadId> {
        match self {
            Self::Workload(id) => Some(id),
            _ => None,
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.kind())?;
        match self {
            Self::User(id) => fmt::Display::fmt(id, f),
            Self::ServiceAccount(id) => fmt::Display::fmt(id, f),
            Self::Key(id) => fmt::Display::fmt(id, f),
            Self::Agent(id) => fmt::Display::fmt(id, f),
            Self::Workload(id) => fmt::Display::fmt(id, f),
        }
    }
}

impl FromStr for Principal {
    type Err = PrincipalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kind, id) = s.split_once(':').ok_or(PrincipalError::MissingKind)?;
        Ok(match kind.parse::<PrincipalKind>()? {
            PrincipalKind::User => Self::User(id.parse()?),
            PrincipalKind::ServiceAccount => Self::ServiceAccount(id.parse()?),
            PrincipalKind::Key => Self::Key(id.parse()?),
            PrincipalKind::Agent => Self::Agent(id.parse()?),
            PrincipalKind::Workload => Self::Workload(id.parse()?),
        })
    }
}

string_serde!(Principal, "a principal string `<kind>:<id>`");

impl From<UserId> for Principal {
    fn from(id: UserId) -> Self {
        Self::User(id)
    }
}

impl From<ServiceAccountId> for Principal {
    fn from(id: ServiceAccountId) -> Self {
        Self::ServiceAccount(id)
    }
}

impl From<KeyId> for Principal {
    fn from(id: KeyId) -> Self {
        Self::Key(id)
    }
}

impl From<AgentId> for Principal {
    fn from(id: AgentId) -> Self {
        Self::Agent(id)
    }
}

impl From<WorkloadId> for Principal {
    fn from(id: WorkloadId) -> Self {
        Self::Workload(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::UuidError;
    use crate::test_support::uuid7_strategy;
    use proptest::prelude::*;

    const USER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081";
    const SA: &str = "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3";
    const KEY: &str = "key:key_0193a1b2-c3d4-7d77-be88-9fa0b1c2d3e4";
    const AGENT: &str = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";
    const WORKLOAD: &str = "workload:spiffe://prod-eu1.attache.example.test/ns/shop/svc/orders";

    #[test]
    fn doc_examples_round_trip_with_their_lengths() {
        for (s, kind, len) in [
            (USER, PrincipalKind::User, Some(45)),
            (SA, PrincipalKind::ServiceAccount, Some(42)),
            (KEY, PrincipalKind::Key, Some(44)),
            (AGENT, PrincipalKind::Agent, Some(46)),
            (WORKLOAD, PrincipalKind::Workload, None),
        ] {
            let p: Principal = s.parse().unwrap();
            assert_eq!(p.kind(), kind);
            assert_eq!(p.to_string(), s);
            if let Some(len) = len {
                assert_eq!(s.len(), len);
            }
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{s}\""));
            assert_eq!(serde_json::from_str::<Principal>(&json).unwrap(), p);
        }
    }

    #[test]
    fn accessors() {
        let p: Principal = USER.parse().unwrap();
        assert!(p.as_user().is_some());
        assert!(p.as_agent().is_none());
        let p: Principal = AGENT.parse().unwrap();
        assert_eq!(
            p.as_agent().unwrap().to_string(),
            "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102"
        );
        let p: Principal = SA.parse().unwrap();
        assert!(p.as_service_account().is_some());
        let p: Principal = KEY.parse().unwrap();
        assert!(p.as_key().is_some());
        let p: Principal = WORKLOAD.parse().unwrap();
        let w = p.as_workload().unwrap();
        assert_eq!(w.trust_domain(), "prod-eu1.attache.example.test");
        assert_eq!(w.path(), "/ns/shop/svc/orders");
    }

    #[test]
    fn rejects_bad_principals() {
        let u = "0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081";
        let cases: Vec<(String, PrincipalError)> = vec![
            (
                format!("user:sa_{u}"),
                PrincipalError::Id(IdError::Prefix { expected: "usr_" }),
            ),
            (
                format!("sa:usr_{u}"),
                PrincipalError::Id(IdError::Prefix { expected: "sa_" }),
            ),
            (
                format!("agent:usr_{u}"),
                PrincipalError::Id(IdError::Prefix { expected: "agt_" }),
            ),
            (format!("usr_{u}"), PrincipalError::MissingKind),
            (format!("group:grp_{u}"), PrincipalError::UnknownKind),
            (format!("User:usr_{u}"), PrincipalError::UnknownKind),
            (format!(" user:usr_{u}"), PrincipalError::UnknownKind),
            (
                format!("user:usr_{u} "),
                PrincipalError::Id(IdError::Uuid(UuidError::Length)),
            ),
            (
                format!("user:usr_{u}x"),
                PrincipalError::Id(IdError::Uuid(UuidError::Length)),
            ),
            (
                "user:usr_0193A1B2-C3D4-7A11-8B22-3C4D5E6F7081".to_owned(),
                PrincipalError::Id(IdError::Uuid(UuidError::NotLowerHex)),
            ),
            (
                "user:usr_0193a1b2-c3d4-4a11-8b22-3c4d5e6f7081".to_owned(),
                PrincipalError::Id(IdError::Uuid(UuidError::Version)),
            ),
            ("".to_owned(), PrincipalError::MissingKind),
            (
                "user:".to_owned(),
                PrincipalError::Id(IdError::Prefix { expected: "usr_" }),
            ),
            (
                "workload:".to_owned(),
                PrincipalError::Workload(SpiffeError::Scheme),
            ),
        ];
        for (input, err) in cases {
            assert_eq!(input.parse::<Principal>(), Err(err), "{input:?}");
        }
    }

    #[test]
    fn spiffe_table_from_the_doc() {
        let cases: &[(&str, Result<(), PrincipalError>)] = &[
            (
                "workload:spiffe://prod-eu1.attache.example.test/ns/shop/svc/orders",
                Ok(()),
            ),
            (
                "workload:spiffe://Prod.example.test/ns/shop",
                Err(SpiffeError::TrustDomainChar.into()),
            ),
            (
                "workload:spiffe://prod.example.test",
                Err(SpiffeError::EmptyPath.into()),
            ),
            (
                "workload:spiffe://prod.example.test/ns//shop",
                Err(SpiffeError::EmptySegment.into()),
            ),
            (
                "workload:spiffe://prod.example.test/ns/shop/",
                Err(SpiffeError::EmptySegment.into()),
            ),
            (
                "workload:spiffe://prod.example.test/ns/../shop",
                Err(SpiffeError::DotSegment.into()),
            ),
            (
                "workload:spiffe://prod.example.test:8443/ns/shop",
                Err(SpiffeError::TrustDomainChar.into()),
            ),
            (
                "workload:spiffe://prod.example.test/ns/shop%2Fx",
                Err(SpiffeError::SegmentChar.into()),
            ),
        ];
        for (input, want) in cases {
            let got = input.parse::<Principal>().map(|_| ());
            assert_eq!(&got, want, "{input:?}");
        }
    }

    #[test]
    fn more_spiffe_rejections() {
        let cases: &[(&str, SpiffeError)] = &[
            ("SPIFFE://prod.example.test/ns", SpiffeError::Scheme),
            ("spiffe:/prod.example.test/ns", SpiffeError::Scheme),
            ("https://prod.example.test/ns", SpiffeError::Scheme),
            ("spiffe:///ns", SpiffeError::EmptyTrustDomain),
            (
                "spiffe://user@prod.example.test/ns",
                SpiffeError::TrustDomainChar,
            ),
            (
                "spiffe://prod.example.test/ns?x=1",
                SpiffeError::SegmentChar,
            ),
            (
                "spiffe://prod.example.test/ns#frag",
                SpiffeError::SegmentChar,
            ),
            ("spiffe://prod.example.test/./ns", SpiffeError::DotSegment),
            ("spiffe://prod.example.test/", SpiffeError::EmptySegment),
            (
                "spiffe://prod.example.test/ns/sh op",
                SpiffeError::SegmentChar,
            ),
            (
                "spiffe://prod.example.test/ns/caf\u{e9}",
                SpiffeError::SegmentChar,
            ),
        ];
        for (input, err) in cases {
            assert_eq!(WorkloadId::parse(input), Err(*err), "{input:?}");
        }
        // Segments may use uppercase, `.` and `..` inside longer names.
        assert!(WorkloadId::parse("spiffe://td/NS/a..b/.hidden/x_y-z").is_ok());
        // Trust domain length limits.
        let td255 = "a".repeat(255);
        assert!(WorkloadId::parse(&format!("spiffe://{td255}/x")).is_ok());
        let td256 = "a".repeat(256);
        assert_eq!(
            WorkloadId::parse(&format!("spiffe://{td256}/x")),
            Err(SpiffeError::TrustDomainTooLong)
        );
        // Total length limit: exactly 2048 bytes is fine, 2049 is not.
        let head = "spiffe://td/";
        let ok = format!("{head}{}", "s".repeat(2048 - head.len()));
        assert_eq!(ok.len(), 2048);
        assert!(WorkloadId::parse(&ok).is_ok());
        let principal = format!("workload:{ok}");
        assert_eq!(principal.len(), Principal::MAX_LEN);
        assert!(principal.parse::<Principal>().is_ok());
        let too_long = format!("{ok}s");
        assert_eq!(WorkloadId::parse(&too_long), Err(SpiffeError::TooLong));
    }

    #[test]
    fn kinds_are_a_closed_set() {
        for kind in PrincipalKind::ALL {
            assert_eq!(kind.as_str().parse::<PrincipalKind>(), Ok(kind));
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(serde_json::from_str::<PrincipalKind>(&json).unwrap(), kind);
        }
        for bad in ["\"group\"", "\"User\"", "\"\"", "null", "1"] {
            assert!(serde_json::from_str::<PrincipalKind>(bad).is_err(), "{bad}");
        }
    }

    fn segment() -> impl Strategy<Value = String> {
        "[A-Za-z0-9._-]{1,12}".prop_filter("not a dot segment", |s| s != "." && s != "..")
    }

    fn workload_strategy() -> impl Strategy<Value = WorkloadId> {
        ("[a-z0-9._-]{1,40}", prop::collection::vec(segment(), 1..5)).prop_map(|(td, segs)| {
            WorkloadId::parse(&format!("spiffe://{td}/{}", segs.join("/"))).unwrap()
        })
    }

    fn principal_strategy() -> impl Strategy<Value = Principal> {
        prop_oneof![
            uuid7_strategy().prop_map(|u| Principal::User(UserId::new(u))),
            uuid7_strategy().prop_map(|u| Principal::ServiceAccount(ServiceAccountId::new(u))),
            uuid7_strategy().prop_map(|u| Principal::Key(KeyId::new(u))),
            uuid7_strategy().prop_map(|u| Principal::Agent(AgentId::new(u))),
            workload_strategy().prop_map(Principal::Workload),
        ]
    }

    proptest! {
        #[test]
        fn principal_round_trip(p in principal_strategy()) {
            let text = p.to_string();
            prop_assert!(text.len() <= Principal::MAX_LEN);
            prop_assert_eq!(text.parse::<Principal>(), Ok(p.clone()));
            let json = serde_json::to_string(&p).unwrap();
            prop_assert_eq!(serde_json::from_str::<Principal>(&json).unwrap(), p);
        }

        #[test]
        fn kind_and_prefix_must_agree(u in uuid7_strategy(), kind in 0usize..4, prefix in 0usize..4) {
            prop_assume!(kind != prefix);
            let kinds = ["user", "sa", "key", "agent"];
            let prefixes = ["usr_", "sa_", "key_", "agt_"];
            let s = format!("{}:{}{u}", kinds[kind], prefixes[prefix]);
            prop_assert!(s.parse::<Principal>().is_err());
        }

        #[test]
        fn trailing_or_leading_junk_is_rejected(p in principal_strategy(), junk in "[ \\t\\r\\n/]") {
            let text = p.to_string();
            let suffixed = format!("{text}{junk}");
            let prefixed = format!("{junk}{text}");
            prop_assert!(suffixed.parse::<Principal>().is_err());
            prop_assert!(prefixed.parse::<Principal>().is_err());
        }

        #[test]
        fn parse_never_panics(s in "\\PC{0,80}") {
            let _ = s.parse::<Principal>();
            let _ = WorkloadId::parse(&s);
        }
    }
}
