//! Events: the CloudEvents 1.0 envelope, the event type grammar and the v1
//! event list (CONTRACTS.md 8.1 to 8.3).
//!
//! Events are notifications only. They carry ids, not state; a receiver
//! re-reads state through the API. The outbox, webhook delivery and signing
//! and SSE are Phase B.

use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

use crate::apikey::DisplayPrefix;
use crate::encoding::json_int;
use crate::id::{IdError, SessionId, Uuid7};
use crate::keys::{NameError, check_name};
use crate::principal::Principal;
use crate::tenant::{OrgId, TenantId};
use crate::timestamp::Timestamp;

/// Why an event part was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EventError {
    /// The event type does not start with `tutela.`.
    #[error("an event type must start with `tutela.`")]
    TypePrefix,
    /// The event type is not `tutela.<entity>.<verb>.v<major>`.
    #[error("an event type must be `tutela.<entity>.<verb>.v<major>`")]
    TypeShape,
    /// The entity or verb is not a name.
    #[error("invalid entity or verb in the event type")]
    TypeName(#[from] NameError),
    /// The major version is not `1`, `2`, ... without a leading zero.
    #[error("the event major version must be 1, 2, ... with no leading zero")]
    TypeMajor,
    /// The source does not start with `tutela://`.
    #[error("an event source must start with `tutela://`")]
    SourceScheme,
    /// The source is not `tutela://<host>/<tid>`.
    #[error("an event source must be `tutela://<host>/<tid>`")]
    SourceShape,
    /// The source host is not a lowercase DNS name.
    #[error("the event source host must be a lowercase DNS name")]
    SourceHost,
    /// The source port is not a number from 1 to 65535.
    #[error("the event source port must be a number from 1 to 65535")]
    SourcePort,
    /// The source tenant is not a tenant id.
    #[error("invalid tenant id in the event source")]
    SourceTenant(#[source] IdError),
    /// The subject is empty or not visible ASCII.
    #[error("an event subject must be 1 or more visible ASCII characters")]
    Subject,
    /// The `traceparent` is not a W3C traceparent.
    #[error("invalid W3C traceparent")]
    TraceParent,
    /// The tenant in `source` is not `tenantid`.
    #[error("the tenant in `source` must equal `tenantid`")]
    TenantMismatch,
    /// `data` is not a JSON object (for example `null`, a string or an array).
    #[error("the event `data` must be a JSON object")]
    DataNotObject,
}

/// An event type: `tutela.<entity>.<verb>.v<major>` (CONTRACTS.md 8.2).
///
/// An open set: receivers ignore event types they do not know.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EventType(Cow<'static, str>);

impl EventType {
    /// `tutela.user.created.v1`: a user was created.
    pub const USER_CREATED: Self = Self(Cow::Borrowed("tutela.user.created.v1"));
    /// `tutela.user.disabled.v1`: a user was disabled.
    pub const USER_DISABLED: Self = Self(Cow::Borrowed("tutela.user.disabled.v1"));
    /// `tutela.user.deleted.v1`: a user was deleted.
    pub const USER_DELETED: Self = Self(Cow::Borrowed("tutela.user.deleted.v1"));
    /// `tutela.org.created.v1`: an org was created.
    pub const ORG_CREATED: Self = Self(Cow::Borrowed("tutela.org.created.v1"));
    /// `tutela.org.updated.v1`: an org changed; re-read it.
    pub const ORG_UPDATED: Self = Self(Cow::Borrowed("tutela.org.updated.v1"));
    /// `tutela.org.deleted.v1`: an org was soft-deleted.
    pub const ORG_DELETED: Self = Self(Cow::Borrowed("tutela.org.deleted.v1"));
    /// `tutela.membership.changed.v1`: a principal joined or left an org, or
    /// its groups changed.
    pub const MEMBERSHIP_CHANGED: Self = Self(Cow::Borrowed("tutela.membership.changed.v1"));
    /// `tutela.session.revoked.v1`: sessions were revoked.
    pub const SESSION_REVOKED: Self = Self(Cow::Borrowed("tutela.session.revoked.v1"));
    /// `tutela.principal.disabled.v1`: a principal of any kind was disabled.
    pub const PRINCIPAL_DISABLED: Self = Self(Cow::Borrowed("tutela.principal.disabled.v1"));
    /// `tutela.principal.enabled.v1` (Phase B, additive): a disabled principal
    /// may act again, with tokens of the new `epoch`.
    pub const PRINCIPAL_ENABLED: Self = Self(Cow::Borrowed("tutela.principal.enabled.v1"));
    /// `tutela.model.published.v1`: a new model version was published.
    pub const MODEL_PUBLISHED: Self = Self(Cow::Borrowed("tutela.model.published.v1"));
    /// `tutela.permissions.changed.v1`: assignments, groups or rules changed.
    pub const PERMISSIONS_CHANGED: Self = Self(Cow::Borrowed("tutela.permissions.changed.v1"));
    /// `tutela.key.created.v1`: an API key was created.
    pub const KEY_CREATED: Self = Self(Cow::Borrowed("tutela.key.created.v1"));
    /// `tutela.key.revoked.v1`: an API key was revoked.
    pub const KEY_REVOKED: Self = Self(Cow::Borrowed("tutela.key.revoked.v1"));

    /// Every v1 event type of CONTRACTS.md 8.3. A slice, so that a new event
    /// type does not change its type.
    pub const KNOWN_V1: &'static [Self] = &[
        Self::USER_CREATED,
        Self::USER_DISABLED,
        Self::USER_DELETED,
        Self::ORG_CREATED,
        Self::ORG_UPDATED,
        Self::ORG_DELETED,
        Self::MEMBERSHIP_CHANGED,
        Self::SESSION_REVOKED,
        Self::PRINCIPAL_DISABLED,
        Self::PRINCIPAL_ENABLED,
        Self::MODEL_PUBLISHED,
        Self::PERMISSIONS_CHANGED,
        Self::KEY_CREATED,
        Self::KEY_REVOKED,
    ];

    /// Parses an event type.
    ///
    /// # Errors
    ///
    /// Returns an [`EventError`] when `s` breaks the grammar of 8.2.
    pub fn parse(s: &str) -> Result<Self, EventError> {
        let rest = s.strip_prefix("tutela.").ok_or(EventError::TypePrefix)?;
        let mut parts = rest.split('.');
        let (Some(entity), Some(verb), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(EventError::TypeShape);
        };
        check_name(entity)?;
        check_name(verb)?;
        let major = version.strip_prefix('v').ok_or(EventError::TypeMajor)?;
        let mut digits = major.bytes();
        let first_ok = matches!(digits.next(), Some(b'1'..=b'9'));
        if !first_ok || !digits.all(|b| b.is_ascii_digit()) {
            return Err(EventError::TypeMajor);
        }
        Ok(Self(Cow::Owned(s.to_owned())))
    }

    /// The type text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The entity, for example `user`.
    #[must_use]
    pub fn entity(&self) -> &str {
        self.0.split('.').nth(1).unwrap_or_default()
    }

    /// The verb, for example `created`.
    #[must_use]
    pub fn verb(&self) -> &str {
        self.0.split('.').nth(2).unwrap_or_default()
    }

    /// The major version, for example `1`. `None` if it does not fit a `u32`.
    #[must_use]
    pub fn major(&self) -> Option<u32> {
        self.0
            .split('.')
            .nth(3)
            .and_then(|v| v.strip_prefix('v'))
            .and_then(|v| v.parse().ok())
    }

    /// `true` for a type in [`EventType::KNOWN_V1`].
    #[must_use]
    pub fn is_known(&self) -> bool {
        Self::KNOWN_V1.contains(self)
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EventType {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(EventType, "an event type `tutela.<entity>.<verb>.v<major>`");

/// The event `source`: `tutela://<host>/<tid>` (CONTRACTS.md 8.1).
///
/// `<host>` is the lowercase DNS name of the `tutelad` deployment with an
/// optional `:port`. A receiver maps the host to an issuer through its own
/// trust list; it never uses the tenant id without that issuer.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EventSource {
    host: String,
    port: Option<u16>,
    tenant: TenantId,
}

impl EventSource {
    /// The scheme.
    pub const SCHEME: &'static str = "tutela://";

    /// Makes a source.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::SourceHost`] when `host` is not a lowercase DNS
    /// name, or [`EventError::SourcePort`] for port 0.
    pub fn new(host: &str, port: Option<u16>, tenant: TenantId) -> Result<Self, EventError> {
        if !is_dns_name(host) {
            return Err(EventError::SourceHost);
        }
        if port == Some(0) {
            return Err(EventError::SourcePort);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            tenant,
        })
    }

    /// Parses `tutela://<host>[:port]/<tid>`.
    ///
    /// # Errors
    ///
    /// Returns an [`EventError`] when `s` breaks a rule.
    pub fn parse(s: &str) -> Result<Self, EventError> {
        let rest = s
            .strip_prefix(Self::SCHEME)
            .ok_or(EventError::SourceScheme)?;
        let (authority, tid) = rest.split_once('/').ok_or(EventError::SourceShape)?;
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (
                host,
                Some(crate::text::parse_port(port).ok_or(EventError::SourcePort)?),
            ),
            None => (authority, None),
        };
        let tenant = tid.parse::<TenantId>().map_err(EventError::SourceTenant)?;
        Self::new(host, port, tenant)
    }

    /// The host, without the port.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, if any.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// The tenant id.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
}

/// A lowercase DNS name: labels of `a-z 0-9 -`, 1 to 63 characters, not
/// starting or ending with `-`, joined by `.`; at most 253 characters.
fn is_dns_name(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        })
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::SCHEME)?;
        f.write_str(&self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        write!(f, "/{}", self.tenant)
    }
}

impl FromStr for EventSource {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(EventSource, "an event source `tutela://<host>/<tid>`");

/// The event `subject`: the id of the thing the event is about
/// (CONTRACTS.md 8.3). Order is kept per subject.
///
/// Kept as text so that a receiver can still read the envelope of an event
/// type it does not know. Typed views: [`EventSubject::as_principal`],
/// [`EventSubject::as_org`], [`EventSubject::as_tenant`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EventSubject(String);

impl EventSubject {
    /// Parses a subject: 1 or more visible ASCII characters.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Subject`] when `s` is empty or not visible ASCII.
    pub fn parse(s: &str) -> Result<Self, EventError> {
        if !s.is_empty() && s.bytes().all(crate::text::is_visible_ascii) {
            Ok(Self(s.to_owned()))
        } else {
            Err(EventError::Subject)
        }
    }

    /// The subject text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The subject as a principal, if it is one.
    #[must_use]
    pub fn as_principal(&self) -> Option<Principal> {
        self.0.parse().ok()
    }

    /// The subject as an org id, if it is one.
    #[must_use]
    pub fn as_org(&self) -> Option<OrgId> {
        self.0.parse().ok()
    }

    /// The subject as a tenant id, if it is one.
    #[must_use]
    pub fn as_tenant(&self) -> Option<TenantId> {
        self.0.parse().ok()
    }
}

impl From<&Principal> for EventSubject {
    fn from(p: &Principal) -> Self {
        Self(p.to_string())
    }
}

impl From<OrgId> for EventSubject {
    fn from(id: OrgId) -> Self {
        Self(id.to_string())
    }
}

impl From<TenantId> for EventSubject {
    fn from(id: TenantId) -> Self {
        Self(id.to_string())
    }
}

impl fmt::Display for EventSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EventSubject {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(EventSubject, "an event subject string");

/// A W3C `traceparent` (Trace Context): `<version>-<trace-id>-<parent-id>-<flags>`.
///
/// Version `00` is exactly 55 characters. A later version may add `-...`
/// after the first 55 characters. Version `ff`, an all-zero trace id and an
/// all-zero parent id are invalid.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TraceParent(String);

impl TraceParent {
    /// Parses a traceparent.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::TraceParent`] when `s` is not valid.
    pub fn parse(s: &str) -> Result<Self, EventError> {
        let part = |range: core::ops::Range<usize>| s.get(range).ok_or(EventError::TraceParent);
        let version = part(0..2)?;
        let trace_id = part(3..35)?;
        let parent_id = part(36..52)?;
        let flags = part(53..55)?;
        let dashes = [2usize, 35, 52]
            .iter()
            .all(|&i| s.as_bytes().get(i) == Some(&b'-'));
        let hex = |v: &str, n| crate::text::is_lower_hex_str(v, n);
        let valid = dashes
            && hex(version, 2)
            && version != "ff"
            && hex(trace_id, 32)
            && trace_id.bytes().any(|b| b != b'0')
            && hex(parent_id, 16)
            && parent_id.bytes().any(|b| b != b'0')
            && hex(flags, 2)
            && match s.len() {
                55 => true,
                // A later version may add `-...`. Only visible ASCII: no
                // spaces, no control characters, no line breaks.
                _ => {
                    version != "00"
                        && s.as_bytes().get(55) == Some(&b'-')
                        && s.bytes().all(crate::text::is_visible_ascii)
                }
            };
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(EventError::TraceParent)
        }
    }

    /// The traceparent text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 32-character trace id.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        self.0.get(3..35).unwrap_or_default()
    }

    /// The 16-character parent (span) id.
    #[must_use]
    pub fn parent_id(&self) -> &str {
        self.0.get(36..52).unwrap_or_default()
    }
}

impl fmt::Display for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TraceParent {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(TraceParent, "a W3C traceparent string");

fixed_string!(
    /// The CloudEvents `specversion`: always `"1.0"`.
    SpecVersion,
    "1.0"
);

fixed_string!(
    /// The CloudEvents `datacontenttype`: always `"application/json"`.
    DataContentType,
    "application/json"
);

/// A Tutela event: the CloudEvents 1.0 envelope in structured JSON mode
/// (`application/cloudevents+json`) (CONTRACTS.md 8.1).
///
/// `T` is the `data` object: one of the data types of this module, or
/// [`serde_json::Value`] for a receiver that reads any event. Unknown
/// attributes are ignored. On the wire `data` is always a JSON object:
/// readers reject `null`, strings, numbers and arrays, and writers refuse a
/// `T` that does not serialize to an object.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CloudEvent<T> {
    /// Always `1.0`.
    pub specversion: SpecVersion,
    /// The event id, a UUIDv7. Also the idempotency key: receivers dedupe by it.
    pub id: Uuid7,
    /// `tutela://<host>/<tid>`.
    pub source: EventSource,
    /// `tutela.<entity>.<verb>.v<major>`.
    pub event_type: EventType,
    /// The id of the thing the event is about. Always set.
    pub subject: EventSubject,
    /// When the change happened.
    pub time: Timestamp,
    /// Always `application/json`.
    pub datacontenttype: DataContentType,
    /// Extension attribute: the tenant id. Equal to the tenant in `source`.
    pub tenantid: TenantId,
    /// Extension attribute: the org id, when the event is about one org.
    pub orgid: Option<OrgId>,
    /// Extension attribute: the W3C traceparent of the change. Sent only to
    /// receivers inside the deployment.
    pub traceparent: Option<TraceParent>,
    /// A small JSON object. Never personal data, secrets or field values.
    pub data: T,
}

/// A JSON object: the only valid wire form of `data`.
type JsonObject = serde_json::Map<String, serde_json::Value>;

/// The serde shape of [`CloudEvent`] when it is written. Private, so it cannot
/// be used without the checks in the trait impls below.
#[derive(Serialize)]
struct CloudEventOut<'a> {
    specversion: &'a SpecVersion,
    id: &'a Uuid7,
    source: &'a EventSource,
    #[serde(rename = "type")]
    event_type: &'a EventType,
    subject: &'a EventSubject,
    time: &'a Timestamp,
    datacontenttype: &'a DataContentType,
    tenantid: &'a TenantId,
    #[serde(skip_serializing_if = "Option::is_none")]
    orgid: Option<&'a OrgId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    traceparent: Option<&'a TraceParent>,
    data: JsonObject,
}

/// The serde shape of [`CloudEvent`] when it is read. `data` must be a JSON
/// object; it becomes `T` only after that. Private, like [`CloudEventOut`].
#[derive(Deserialize)]
struct CloudEventIn {
    specversion: SpecVersion,
    id: Uuid7,
    source: EventSource,
    #[serde(rename = "type")]
    event_type: EventType,
    subject: EventSubject,
    time: Timestamp,
    datacontenttype: DataContentType,
    tenantid: TenantId,
    #[serde(default)]
    orgid: Option<OrgId>,
    #[serde(default)]
    traceparent: Option<TraceParent>,
    data: JsonObject,
}

impl<T> CloudEvent<T> {
    /// Makes an event. `tenantid` is taken from `source`; `orgid` and
    /// `traceparent` start empty.
    #[must_use]
    pub fn new(
        id: Uuid7,
        source: EventSource,
        event_type: EventType,
        subject: EventSubject,
        time: Timestamp,
        data: T,
    ) -> Self {
        Self {
            specversion: SpecVersion,
            id,
            tenantid: source.tenant(),
            source,
            event_type,
            subject,
            time,
            datacontenttype: DataContentType,
            orgid: None,
            traceparent: None,
            data,
        }
    }

    /// Checks that the tenant in `source` equals `tenantid`.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::TenantMismatch`] when they differ.
    pub fn check(&self) -> Result<(), EventError> {
        if self.source.tenant() == self.tenantid {
            Ok(())
        } else {
            Err(EventError::TenantMismatch)
        }
    }
}

impl<T: Serialize> Serialize for CloudEvent<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.check().map_err(ser::Error::custom)?;
        let serde_json::Value::Object(data) =
            serde_json::to_value(&self.data).map_err(ser::Error::custom)?
        else {
            return Err(ser::Error::custom(EventError::DataNotObject));
        };
        CloudEventOut {
            specversion: &self.specversion,
            id: &self.id,
            source: &self.source,
            event_type: &self.event_type,
            subject: &self.subject,
            time: &self.time,
            datacontenttype: &self.datacontenttype,
            tenantid: &self.tenantid,
            orgid: self.orgid.as_ref(),
            traceparent: self.traceparent.as_ref(),
            data,
        }
        .serialize(serializer)
    }
}

impl<'de, T: de::DeserializeOwned> Deserialize<'de> for CloudEvent<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CloudEventIn::deserialize(deserializer)?;
        let data =
            T::deserialize(serde_json::Value::Object(wire.data)).map_err(de::Error::custom)?;
        let event = Self {
            specversion: wire.specversion,
            id: wire.id,
            source: wire.source,
            event_type: wire.event_type,
            subject: wire.subject,
            time: wire.time,
            datacontenttype: wire.datacontenttype,
            tenantid: wire.tenantid,
            orgid: wire.orgid,
            traceparent: wire.traceparent,
            data,
        };
        event.check().map_err(de::Error::custom)?;
        Ok(event)
    }
}

/// Serde helpers for a principal field that must be of one kind, for example
/// `user` in [`UserData`] or `key` in [`KeyCreatedData`] (CONTRACTS.md 8.3).
/// Readers reject another kind, and writers refuse to emit one.
macro_rules! principal_of_kind {
    ($module:ident, $kind:expr, $msg:literal) => {
        mod $module {
            use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

            use crate::principal::Principal;

            pub(super) fn serialize<S>(p: &Principal, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if p.kind() != $kind {
                    return Err(ser::Error::custom($msg));
                }
                p.serialize(serializer)
            }

            pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Principal, D::Error>
            where
                D: Deserializer<'de>,
            {
                let p = Principal::deserialize(deserializer)?;
                if p.kind() != $kind {
                    return Err(de::Error::custom($msg));
                }
                Ok(p)
            }
        }
    };
}

principal_of_kind!(
    user_principal,
    crate::principal::PrincipalKind::User,
    "this field must be a `user` principal"
);

principal_of_kind!(
    key_principal,
    crate::principal::PrincipalKind::Key,
    "this field must be a `key` principal"
);

/// `data` of `tutela.user.created.v1` and `tutela.user.deleted.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UserData {
    /// The user principal.
    /// Must be of kind `user`.
    #[serde(with = "user_principal")]
    pub user: Principal,
}

/// `data` of `tutela.user.disabled.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UserDisabledData {
    /// The user principal.
    /// Must be of kind `user`.
    #[serde(with = "user_principal")]
    pub user: Principal,
    /// The user's new session epoch.
    #[serde(with = "json_int")]
    pub epoch: u64,
}

/// `data` of `tutela.org.created.v1` and `tutela.org.updated.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OrgData {
    /// The org id.
    pub org: OrgId,
}

/// `data` of `tutela.org.deleted.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OrgDeletedData {
    /// The org id.
    pub org: OrgId,
    /// When the data is purged, at the end of the grace period.
    pub purge_after: Timestamp,
}

/// `data` of `tutela.membership.changed.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MembershipChangedData {
    /// The org id.
    pub org: OrgId,
    /// The principal that joined or left, or whose groups changed.
    pub principal: Principal,
}

/// `data` of `tutela.session.revoked.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SessionRevokedData {
    /// The user principal. Must be of kind `user`: only users have sessions.
    #[serde(with = "user_principal")]
    pub principal: Principal,
    /// The new session epoch. Tokens with a lower `epoch` are refused.
    #[serde(with = "json_int")]
    pub epoch: u64,
    /// The one revoked session; missing when all sessions were revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<SessionId>,
}

/// `data` of `tutela.principal.disabled.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PrincipalDisabledData {
    /// The disabled principal (any kind).
    pub principal: Principal,
    /// The principal's new session epoch.
    #[serde(with = "json_int")]
    pub epoch: u64,
}

/// `data` of `tutela.principal.enabled.v1` (Phase B, additive).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PrincipalEnabledData {
    /// The principal enabled again (any kind).
    pub principal: Principal,
    /// Its epoch: tokens of an older epoch stay refused.
    #[serde(with = "json_int")]
    pub epoch: u64,
}

/// `data` of `tutela.model.published.v1` and `tutela.permissions.changed.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RevData {
    /// The new tenant revision.
    #[serde(with = "json_int")]
    pub rev: u64,
}

/// `data` of `tutela.key.created.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyCreatedData {
    /// The key principal, `key:key_<uuidv7>`.
    /// Must be of kind `key`.
    #[serde(with = "key_principal")]
    pub key: Principal,
    /// The display prefix, for example `tut_sk_7f3k9q2m`.
    pub prefix: DisplayPrefix,
    /// The owner principal.
    pub owner: Principal,
}

/// `data` of `tutela.key.revoked.v1`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyRevokedData {
    /// The key principal, `key:key_<uuidv7>`.
    /// Must be of kind `key`.
    #[serde(with = "key_principal")]
    pub key: Principal,
    /// The display prefix.
    pub prefix: DisplayPrefix,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{Value, json};

    const TEN: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";
    const DOC_EVENT: &str = r#"{
      "specversion": "1.0",
      "id": "0193a1b2-c3d5-7000-8000-0000000000e1",
      "source": "tutela://auth.example.test/ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
      "type": "tutela.permissions.changed.v1",
      "subject": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
      "time": "2026-10-25T09:31:00.000Z",
      "datacontenttype": "application/json",
      "tenantid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
      "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      "data": { "rev": 43 }
    }"#;

    #[test]
    fn doc_example_round_trips_exactly() {
        let e: CloudEvent<RevData> = serde_json::from_str(DOC_EVENT).unwrap();
        assert_eq!(e.event_type, EventType::PERMISSIONS_CHANGED);
        assert_eq!(e.data.rev, 43);
        assert_eq!(e.source.host(), "auth.example.test");
        assert_eq!(e.subject.as_tenant(), Some(e.tenantid));
        assert_eq!(
            e.traceparent.as_ref().unwrap().trace_id(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(
            e.traceparent.as_ref().unwrap().parent_id(),
            "00f067aa0ba902b7"
        );
        let doc: Value = serde_json::from_str(DOC_EVENT).unwrap();
        assert_eq!(serde_json::to_value(&e).unwrap(), doc);
        let any: CloudEvent<Value> = serde_json::from_str(DOC_EVENT).unwrap();
        assert_eq!(serde_json::to_value(&any).unwrap(), doc);
    }

    #[test]
    fn explicit_deserialize_calls_still_check() {
        // Regression: `CloudEvent::deserialize(..)` must run `check()`.
        let mut v: Value = serde_json::from_str(DOC_EVENT).unwrap();
        v["tenantid"] = json!("ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c");
        let text = v.to_string();
        let mut de = serde_json::Deserializer::from_str(&text);
        assert!(CloudEvent::<Value>::deserialize(&mut de).is_err());
    }

    #[test]
    fn envelope_rules() {
        let base: Value = serde_json::from_str(DOC_EVENT).unwrap();
        for (k, bad) in [
            ("specversion", json!("1.1")),
            ("specversion", json!(1.0)),
            ("datacontenttype", json!("text/plain")),
            ("id", json!("0193a1b2-c3d5-4000-8000-0000000000e1")),
            (
                "source",
                json!("https://auth.example.test/ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"),
            ),
            (
                "source",
                json!("tutela://Auth.example.test/ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"),
            ),
            (
                "source",
                json!("tutela://auth.example.test/ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c"),
            ),
            ("type", json!("tutela.permissions.changed")),
            ("subject", json!("")),
            ("time", json!("2026-10-25T09:31:00Z")),
            (
                "tenantid",
                json!("org_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"),
            ),
            (
                "traceparent",
                json!("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
            ),
        ] {
            let mut v = base.clone();
            v[k] = bad.clone();
            assert!(
                serde_json::from_value::<CloudEvent<Value>>(v).is_err(),
                "{k} = {bad}"
            );
        }
        for k in [
            "specversion",
            "id",
            "source",
            "type",
            "subject",
            "time",
            "datacontenttype",
            "tenantid",
            "data",
        ] {
            let mut v = base.clone();
            v.as_object_mut().unwrap().remove(k);
            assert!(
                serde_json::from_value::<CloudEvent<Value>>(v).is_err(),
                "missing {k}"
            );
        }
        // Optional extensions may be missing or null; unknown attributes are ignored.
        let mut v = base.clone();
        v["traceparent"] = Value::Null;
        v["orgid"] = Value::Null;
        v["someext"] = json!("x");
        let e: CloudEvent<Value> = serde_json::from_value(v).unwrap();
        assert!(e.traceparent.is_none() && e.orgid.is_none());
        let out = serde_json::to_value(&e).unwrap();
        assert!(
            out.get("traceparent").is_none()
                && out.get("orgid").is_none()
                && out.get("someext").is_none()
        );
        // Writers cannot emit a tenant mismatch either.
        let mut bad = e;
        bad.tenantid = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c".parse().unwrap();
        assert_eq!(bad.check(), Err(EventError::TenantMismatch));
        assert!(serde_json::to_value(&bad).is_err());
    }

    #[test]
    fn data_must_be_an_object() {
        // Regression: `CloudEvent<Value>` accepted `"data": null`, a string or
        // an array. CONTRACTS.md 8.1: `data` is a required JSON object, and a
        // `null` is the same as a missing field (section 0).
        let base: Value = serde_json::from_str(DOC_EVENT).unwrap();
        for bad in [json!(null), json!("x"), json!(1), json!([]), json!([{}])] {
            let mut v = base.clone();
            v["data"] = bad.clone();
            assert!(
                serde_json::from_value::<CloudEvent<Value>>(v.clone()).is_err(),
                "{bad}"
            );
            assert!(
                serde_json::from_value::<CloudEvent<RevData>>(v).is_err(),
                "{bad}"
            );
        }
        let mut v = base.clone();
        v["data"] = json!({});
        let empty: CloudEvent<Value> = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&empty).unwrap(), v);
        // A known type still checks its own data shape.
        v["data"] = json!({ "rev": -1 });
        assert!(serde_json::from_value::<CloudEvent<RevData>>(v).is_err());

        // Writers refuse non-object data.
        let tenant: TenantId = TEN.parse().unwrap();
        let source = EventSource::new("auth.example.test", None, tenant).unwrap();
        for data in [Value::Null, json!("x"), json!([1])] {
            let e = CloudEvent::new(
                "0193a1b2-c3d5-7000-8000-0000000000e1".parse().unwrap(),
                source.clone(),
                EventType::MODEL_PUBLISHED,
                tenant.into(),
                Timestamp::parse("2026-10-25T09:31:00.000Z").unwrap(),
                data,
            );
            let err = serde_json::to_value(&e).unwrap_err();
            assert!(err.to_string().contains("JSON object"), "{err}");
        }
    }

    #[test]
    fn data_principals_have_the_right_kind() {
        // Regression: `user` and `key` accepted any principal kind.
        let sa = "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3";
        let user = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081";
        let key = "key:key_0193a1b2-c3d4-7d77-be88-9fa0b1c2d3e4";
        assert!(serde_json::from_value::<UserData>(json!({ "user": sa })).is_err());
        assert!(
            serde_json::from_value::<UserDisabledData>(json!({ "user": key, "epoch": 1 })).is_err()
        );
        assert!(
            serde_json::from_value::<KeyCreatedData>(
                json!({ "key": user, "prefix": "tut_sk_7f3k9q2m", "owner": sa })
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<KeyRevokedData>(
                json!({ "key": sa, "prefix": "tut_sk_7f3k9q2m" })
            )
            .is_err()
        );
        // Writers refuse the wrong kind too.
        let wrong = UserData {
            user: sa.parse().unwrap(),
        };
        assert!(serde_json::to_value(&wrong).is_err());
        let wrong = KeyRevokedData {
            key: user.parse().unwrap(),
            prefix: "tut_sk_7f3k9q2m".parse().unwrap(),
        };
        assert!(serde_json::to_value(&wrong).is_err());
        // Only users have sessions.
        assert!(
            serde_json::from_value::<SessionRevokedData>(json!({ "principal": sa, "epoch": 2 }))
                .is_err()
        );
        assert!(
            serde_json::from_value::<SessionRevokedData>(json!({ "principal": user, "epoch": 2 }))
                .is_ok()
        );
        // `owner` and `principal` may be any kind.
        assert!(
            serde_json::from_value::<KeyCreatedData>(
                json!({ "key": key, "prefix": "tut_ak_7f3k9q2m", "owner": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102" })
            )
            .is_ok()
        );
    }

    #[test]
    fn new_event() {
        let tenant: TenantId = TEN.parse().unwrap();
        let source = EventSource::new("auth.example.test", Some(8443), tenant).unwrap();
        assert_eq!(
            source.to_string(),
            format!("tutela://auth.example.test:8443/{TEN}")
        );
        let e = CloudEvent::new(
            "0193a1b2-c3d5-7000-8000-0000000000e1".parse().unwrap(),
            source,
            EventType::MODEL_PUBLISHED,
            tenant.into(),
            Timestamp::parse("2026-10-25T09:31:00.000Z").unwrap(),
            RevData { rev: 7 },
        );
        assert_eq!(e.check(), Ok(()));
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["tenantid"], json!(TEN));
        assert_eq!(json["specversion"], json!("1.0"));
        assert_eq!(json["datacontenttype"], json!("application/json"));
        assert_eq!(
            serde_json::from_value::<CloudEvent<RevData>>(json).unwrap(),
            e
        );
    }

    #[test]
    fn event_types() {
        let names = [
            "tutela.user.created.v1",
            "tutela.user.disabled.v1",
            "tutela.user.deleted.v1",
            "tutela.org.created.v1",
            "tutela.org.updated.v1",
            "tutela.org.deleted.v1",
            "tutela.membership.changed.v1",
            "tutela.session.revoked.v1",
            "tutela.principal.disabled.v1",
            "tutela.model.published.v1",
            "tutela.permissions.changed.v1",
            "tutela.key.created.v1",
            "tutela.key.revoked.v1",
        ];
        assert_eq!(EventType::KNOWN_V1.len(), names.len());
        for (t, name) in EventType::KNOWN_V1.iter().zip(names) {
            assert_eq!(t.as_str(), name);
            assert_eq!(&EventType::parse(name).unwrap(), t);
            assert!(t.is_known());
            assert_eq!(t.major(), Some(1));
        }
        let t = EventType::parse("tutela.signing_key.revoked.v12").unwrap();
        assert_eq!(
            (t.entity(), t.verb(), t.major()),
            ("signing_key", "revoked", Some(12))
        );
        assert!(!t.is_known());
        let cases: &[(&str, EventError)] = &[
            ("user.created.v1", EventError::TypePrefix),
            ("Tutela.user.created.v1", EventError::TypePrefix),
            ("tutela.user.created", EventError::TypeShape),
            ("tutela.user.created.v1.x", EventError::TypeShape),
            ("tutela.user.v1", EventError::TypeShape),
            (
                "tutela.User.created.v1",
                EventError::TypeName(NameError::Start),
            ),
            (
                "tutela.user.created-now.v1",
                EventError::TypeName(NameError::Char),
            ),
            ("tutela.user.created.v0", EventError::TypeMajor),
            ("tutela.user.created.v01", EventError::TypeMajor),
            ("tutela.user.created.V1", EventError::TypeMajor),
            ("tutela.user.created.v", EventError::TypeMajor),
            ("tutela.user.created.1", EventError::TypeMajor),
            ("tutela.user.created.v1a", EventError::TypeMajor),
        ];
        for (input, err) in cases {
            assert_eq!(EventType::parse(input), Err(*err), "{input:?}");
        }
    }

    #[test]
    fn sources() {
        for ok in [
            format!("tutela://auth.example.test/{TEN}"),
            format!("tutela://localhost:8080/{TEN}"),
            format!("tutela://a-b.c1.example/{TEN}"),
        ] {
            assert_eq!(EventSource::parse(&ok).unwrap().to_string(), ok);
        }
        let cases: Vec<(String, EventError)> = vec![
            (
                format!("tutela:/auth.example.test/{TEN}"),
                EventError::SourceScheme,
            ),
            (
                "tutela://auth.example.test".to_owned(),
                EventError::SourceShape,
            ),
            (
                format!("tutela://auth.example.test:0/{TEN}"),
                EventError::SourcePort,
            ),
            (
                format!("tutela://auth.example.test:/{TEN}"),
                EventError::SourcePort,
            ),
            (
                format!("tutela://auth.example.test:99999/{TEN}"),
                EventError::SourcePort,
            ),
            (
                format!("tutela://Auth.example.test/{TEN}"),
                EventError::SourceHost,
            ),
            (format!("tutela://auth..test/{TEN}"), EventError::SourceHost),
            (format!("tutela://-auth.test/{TEN}"), EventError::SourceHost),
            (
                format!("tutela://auth_x.test/{TEN}"),
                EventError::SourceHost,
            ),
            (format!("tutela:///{TEN}"), EventError::SourceHost),
            (format!("tutela://10.0.0.1:x/{TEN}"), EventError::SourcePort),
            (
                "tutela://auth.example.test/org_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b".to_owned(),
                EventError::SourceTenant(IdError::Prefix { expected: "ten_" }),
            ),
            (
                format!("tutela://auth.example.test/{TEN}/x"),
                EventError::SourceTenant(IdError::Uuid(crate::id::UuidError::Length)),
            ),
        ];
        for (input, err) in cases {
            assert_eq!(EventSource::parse(&input), Err(err), "{input:?}");
        }
        let long_label = "a".repeat(64);
        assert_eq!(
            EventSource::new(&long_label, None, TEN.parse().unwrap()),
            Err(EventError::SourceHost)
        );
    }

    #[test]
    fn subjects() {
        let p: EventSubject = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081"
            .parse()
            .unwrap();
        assert!(p.as_principal().is_some());
        assert!(p.as_org().is_none());
        let o: EventSubject = "org_0193a1b2-c3d4-7f00-9a00-000000000002".parse().unwrap();
        assert!(o.as_org().is_some());
        assert!(o.as_principal().is_none());
        assert_eq!(EventSubject::parse(""), Err(EventError::Subject));
        assert_eq!(EventSubject::parse("a b"), Err(EventError::Subject));
    }

    #[test]
    fn trace_parents() {
        let ok = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(TraceParent::parse(ok).is_ok());
        assert!(
            TraceParent::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra")
                .is_ok()
        );
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b\u{e9}",
            // A later version's suffix is visible ASCII only.
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-a\nb",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-a b",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-\u{7f}",
        ] {
            assert_eq!(
                TraceParent::parse(bad),
                Err(EventError::TraceParent),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn data_shapes() {
        let cases: Vec<(EventType, Value)> = vec![
            (
                EventType::USER_CREATED,
                json!({ "user": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081" }),
            ),
            (
                EventType::USER_DISABLED,
                json!({ "user": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081", "epoch": 4 }),
            ),
            (
                EventType::ORG_CREATED,
                json!({ "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002" }),
            ),
            (
                EventType::ORG_DELETED,
                json!({ "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002", "purge_after": "2026-11-24T00:00:00.000Z" }),
            ),
            (
                EventType::MEMBERSHIP_CHANGED,
                json!({ "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002", "principal": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102" }),
            ),
            (
                EventType::SESSION_REVOKED,
                json!({ "principal": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081", "epoch": 5, "sid": "ses_0193a1b2-c3d4-7123-8456-789abcdef012" }),
            ),
            (
                EventType::SESSION_REVOKED,
                json!({ "principal": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081", "epoch": 6 }),
            ),
            (
                EventType::PRINCIPAL_DISABLED,
                json!({ "principal": "workload:spiffe://td/ns/x", "epoch": 1 }),
            ),
            (EventType::MODEL_PUBLISHED, json!({ "rev": 44 })),
            (
                EventType::KEY_CREATED,
                json!({ "key": "key:key_0193a1b2-c3d4-7d77-be88-9fa0b1c2d3e4", "prefix": "tut_sk_7f3k9q2m", "owner": "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3" }),
            ),
            (
                EventType::KEY_REVOKED,
                json!({ "key": "key:key_0193a1b2-c3d4-7d77-be88-9fa0b1c2d3e4", "prefix": "tut_sk_7f3k9q2m" }),
            ),
        ];
        fn round<T: Serialize + for<'de> Deserialize<'de>>(v: &Value) -> Value {
            let t: T = serde_json::from_value(v.clone()).unwrap();
            serde_json::to_value(&t).unwrap()
        }
        for (t, v) in &cases {
            let back = match t.as_str() {
                "tutela.user.created.v1" | "tutela.user.deleted.v1" => round::<UserData>(v),
                "tutela.user.disabled.v1" => round::<UserDisabledData>(v),
                "tutela.org.created.v1" | "tutela.org.updated.v1" => round::<OrgData>(v),
                "tutela.org.deleted.v1" => round::<OrgDeletedData>(v),
                "tutela.membership.changed.v1" => round::<MembershipChangedData>(v),
                "tutela.session.revoked.v1" => round::<SessionRevokedData>(v),
                "tutela.principal.disabled.v1" => round::<PrincipalDisabledData>(v),
                "tutela.model.published.v1" | "tutela.permissions.changed.v1" => {
                    round::<RevData>(v)
                }
                "tutela.key.created.v1" => round::<KeyCreatedData>(v),
                "tutela.key.revoked.v1" => round::<KeyRevokedData>(v),
                other => panic!("unexpected {other}"),
            };
            assert_eq!(&back, v, "{t}");
        }
        assert!(serde_json::from_value::<KeyCreatedData>(json!({ "key": "key_0193a1b2-c3d4-7d77-be88-9fa0b1c2d3e4", "prefix": "tut_sk_7f3k9q2m", "owner": "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3" })).is_err());
        assert!(serde_json::from_value::<KeyRevokedData>(json!({ "key": "key:key_0193a1b2-c3d4-7d77-be88-9fa0b1c2d3e4", "prefix": "tut_sk_7f3k9q2m_AAAA" })).is_err());
    }

    proptest! {
        #[test]
        fn event_type_round_trip(e in "[a-z][a-z0-9]{0,8}(_[a-z0-9]{1,4}){0,2}", v in "[a-z][a-z0-9]{0,8}", major in 1u32..1000) {
            let s = format!("tutela.{e}.{v}.v{major}");
            let t = EventType::parse(&s).unwrap();
            prop_assert_eq!(t.to_string(), s);
            prop_assert_eq!(t.entity(), e.as_str());
            prop_assert_eq!(t.verb(), v.as_str());
            prop_assert_eq!(t.major(), Some(major));
        }

        #[test]
        fn source_round_trip(labels in prop::collection::vec("[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?", 1..4), port in proptest::option::of(1u16..), u in crate::test_support::uuid7_strategy()) {
            let host = labels.join(".");
            let source = EventSource::new(&host, port, TenantId::new(u)).unwrap();
            prop_assert_eq!(EventSource::parse(&source.to_string()), Ok(source));
        }

        #[test]
        fn parsers_never_panic(s in "\\PC{0,70}") {
            let _ = EventType::parse(&s);
            let _ = EventSource::parse(&s);
            let _ = TraceParent::parse(&s);
            let _ = EventSubject::parse(&s);
        }
    }
}
