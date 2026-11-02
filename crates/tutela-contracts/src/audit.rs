//! The audit.v1 record (CONTRACTS.md section 9).
//!
//! This module has the record and its format rules, the [`AuditDraft`] a
//! producer fills before the record has its `seq`, and the canonical bytes
//! (RFC 8785) that the producer signs and Tutela's local chain hashes
//! (CONTRACTS.md 9.3, 9.4). The chain itself is in `tutela-store`.

use core::fmt;
use core::str::FromStr;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use serde_json::Value;

use crate::decision::{Decision, Effect, Reason, RuleId};
use crate::encoding::{SignatureValue, Thumbprint, json_int};
use crate::id::Uuid7;
use crate::jcs::to_canonical_string;
use crate::keys::{Label, PermissionKey, ResourceId, ResourceType};
use crate::principal::{Principal, PrincipalKind};
use crate::tenant::{OrgId, TenantKey};
use crate::timestamp::Timestamp;

fixed_string!(
    /// The audit `schema` field: always `"audit.v1"`.
    AuditSchema,
    "audit.v1"
);

/// Why an audit value or record was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// `actor.kind` is not the kind of `actor.id`.
    #[error("`actor.kind` must equal the kind of `actor.id`")]
    ActorKindMismatch,
    /// `actor.on_behalf_of` is set but is not a user.
    #[error("`actor.on_behalf_of` must be a user principal")]
    OnBehalfOfNotUser,
    /// `actor.on_behalf_of` is set but the actor is not an agent.
    #[error("for delegated work, `actor.id` must be the agent")]
    DelegatedActorNotAgent,
    /// `outcome` does not fit `decision.effect`.
    #[error("`outcome` must be `denied` exactly when `decision.effect` is `deny`")]
    OutcomeMismatch,
    /// `labels` is not sorted or has a duplicate.
    #[error("`labels` must be sorted with no duplicates")]
    LabelsNotSorted,
    /// `seq` is 0.
    #[error("`seq` starts at 1")]
    SeqZero,
    /// An integer is above 2^53 − 1.
    #[error("integers must be at most 2^53 - 1")]
    IntTooLarge,
    /// `service` is not `[a-z][a-z0-9-]{0,62}`.
    #[error("a service name must match [a-z][a-z0-9-]{{0,62}}")]
    ServiceName,
    /// `request_id` is not 1 to 128 visible ASCII characters.
    #[error("a request id must be 1 to 128 visible ASCII characters")]
    RequestId,
    /// `trace_id` is not 32 lowercase hex characters (not all zero).
    #[error("a trace id must be 32 lowercase hex characters, not all zero")]
    TraceId,
    /// `span_id` is not 16 lowercase hex characters (not all zero).
    #[error("a span id must be 16 lowercase hex characters, not all zero")]
    SpanId,
    /// `ip` is not IPv4 dotted decimal or IPv6 in RFC 5952 text.
    #[error("an ip must be IPv4 dotted decimal or IPv6 in RFC 5952 form")]
    Ip,
    /// `payload_digest` is not `hmac-sha256:v<n>:<64 lowercase hex>`.
    #[error("a payload digest must be `hmac-sha256:v<n>:<64 lowercase hex>`")]
    PayloadDigest,
    /// `outcome` is not `success`, `failure` or `denied`.
    #[error("an outcome must be `success`, `failure` or `denied`")]
    Outcome,
    /// `details` is not a JSON object of at most 8 KiB of strings, whole
    /// numbers, booleans, arrays and objects.
    #[error("`details` must be a JSON object of at most 8 KiB, with no null and no fraction")]
    Details,
    /// The record has no canonical JSON form, or it does not parse.
    #[error("the record has no canonical JSON form")]
    Canonical,
}

/// The result of the action. A closed set.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Outcome {
    /// `success`: allowed, and the action worked.
    Success,
    /// `failure`: allowed, but the action itself failed.
    Failure,
    /// `denied`: the decision was deny.
    Denied,
}

impl Outcome {
    /// The JSON spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Outcome {
    type Err = AuditError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "denied" => Ok(Self::Denied),
            _ => Err(AuditError::Outcome),
        }
    }
}

string_serde!(Outcome, "an outcome: success, failure or denied");

/// Defines a validated string newtype for an audit field.
macro_rules! audit_string {
    ($(#[$meta:meta])* $name:ident, $check:expr, $err:expr, $expecting:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $name(String);

        impl $name {
            /// Parses the value.
            ///
            /// # Errors
            ///
            /// Returns an [`AuditError`] when `s` breaks the grammar.
            pub fn parse(s: &str) -> Result<Self, AuditError> {
                let check: fn(&str) -> bool = $check;
                if check(s) { Ok(Self(s.to_owned())) } else { Err($err) }
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
            type Err = AuditError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        string_serde!($name, $expecting);
    };
}

audit_string!(
    /// The producer service, for example `tutelad` or `crm-api`:
    /// `[a-z][a-z0-9-]{0,62}`.
    ServiceName,
    crate::text::is_service_name,
    AuditError::ServiceName,
    "a service name"
);

audit_string!(
    /// A request id: 1 to 128 visible ASCII characters.
    RequestId,
    |s| crate::text::is_visible_ascii_str(s, 1, 128),
    AuditError::RequestId,
    "a request id"
);

audit_string!(
    /// A W3C trace id: 32 lowercase hex characters, not all zero.
    TraceId,
    |s| crate::text::is_lower_hex_str(s, 32) && s.bytes().any(|b| b != b'0'),
    AuditError::TraceId,
    "a W3C trace id"
);

audit_string!(
    /// A W3C span id: 16 lowercase hex characters, not all zero.
    SpanId,
    |s| crate::text::is_lower_hex_str(s, 16) && s.bytes().any(|b| b != b'0'),
    AuditError::SpanId,
    "a W3C span id"
);

/// The client IP: IPv4 dotted decimal or IPv6 in RFC 5952 text. Only the
/// canonical text is accepted (no leading zeros, lowercase, shortest form).
/// This is personal data (CONTRACTS.md 9.5).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ClientIp(IpAddr);

impl ClientIp {
    /// Parses the canonical text.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Ip`] when `s` is not an IP address in canonical
    /// text.
    pub fn parse(s: &str) -> Result<Self, AuditError> {
        let ip: IpAddr = s.parse().map_err(|_| AuditError::Ip)?;
        // Rust prints IPv6 in RFC 5952 form; a different text is not canonical.
        if ip.to_string() == s {
            Ok(Self(ip))
        } else {
            Err(AuditError::Ip)
        }
    }

    /// The address.
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.0
    }
}

impl From<IpAddr> for ClientIp {
    fn from(ip: IpAddr) -> Self {
        Self(ip)
    }
}

impl fmt::Display for ClientIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for ClientIp {
    type Err = AuditError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(ClientIp, "an IP address string");

/// A keyed digest: `hmac-sha256:v<n>:<64 lowercase hex>` (CONTRACTS.md 9.1).
///
/// HMAC-SHA256 with a per-tenant audit key of version `n` (1, 2, ...), so a
/// short hidden value cannot be guessed from the digest.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PayloadDigest {
    key_version: u32,
    hex: String,
}

impl PayloadDigest {
    /// Makes a digest from the key version and the 64 lowercase hex characters.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::PayloadDigest`] when the version is 0 or `hex` is
    /// not 64 lowercase hex characters.
    pub fn new(key_version: u32, hex: &str) -> Result<Self, AuditError> {
        if key_version == 0 || !crate::text::is_lower_hex_str(hex, 64) {
            return Err(AuditError::PayloadDigest);
        }
        Ok(Self {
            key_version,
            hex: hex.to_owned(),
        })
    }

    /// Parses `hmac-sha256:v<n>:<hex>`.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::PayloadDigest`] when `s` breaks the format.
    pub fn parse(s: &str) -> Result<Self, AuditError> {
        let rest = s
            .strip_prefix("hmac-sha256:v")
            .ok_or(AuditError::PayloadDigest)?;
        let (version, hex) = rest.split_once(':').ok_or(AuditError::PayloadDigest)?;
        let canonical = !version.is_empty()
            && !version.starts_with('0')
            && version.bytes().all(|b| b.is_ascii_digit());
        if !canonical {
            return Err(AuditError::PayloadDigest);
        }
        let key_version = version
            .parse::<u32>()
            .map_err(|_| AuditError::PayloadDigest)?;
        Self::new(key_version, hex)
    }

    /// The audit key version `n`.
    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    /// The 64 lowercase hex characters.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl fmt::Display for PayloadDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hmac-sha256:v{}:{}", self.key_version, self.hex)
    }
}

impl FromStr for PayloadDigest {
    type Err = AuditError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(PayloadDigest, "a payload digest `hmac-sha256:v<n>:<hex>`");

/// The `actor` of an audit record.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Actor {
    /// The kind of `id`.
    pub kind: PrincipalKind,
    /// The principal. For delegated work this is the **agent** (the current
    /// actor).
    pub id: Principal,
    /// The person the agent acted for (the token's `sub`). Required when the
    /// work was delegated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<Principal>,
}

impl Actor {
    /// An actor that acts for itself. `kind` is taken from `id`.
    #[must_use]
    pub fn new(id: Principal) -> Self {
        Self {
            kind: id.kind(),
            id,
            on_behalf_of: None,
        }
    }

    /// An agent acting for a person. `kind` is taken from `agent`.
    #[must_use]
    pub fn delegated(agent: Principal, person: Principal) -> Self {
        Self {
            kind: agent.kind(),
            id: agent,
            on_behalf_of: Some(person),
        }
    }

    /// Checks `kind` against `id`, and the delegation shape.
    ///
    /// # Errors
    ///
    /// Returns the [`AuditError`] of the first broken rule.
    pub fn check(&self) -> Result<(), AuditError> {
        if self.kind != self.id.kind() {
            return Err(AuditError::ActorKindMismatch);
        }
        if let Some(person) = &self.on_behalf_of {
            if person.kind() != PrincipalKind::User {
                return Err(AuditError::OnBehalfOfNotUser);
            }
            if self.kind != PrincipalKind::Agent {
                return Err(AuditError::DelegatedActorNotAgent);
            }
        }
        Ok(())
    }
}

/// The `resource` of an audit record: `{"type", "id"}`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct ResourceRef {
    /// The type name. JSON `type`.
    #[serde(rename = "type")]
    pub resource_type: ResourceType,
    /// The resource id.
    pub id: ResourceId,
}

/// The `decision` of an audit record: `{"effect", "rule_ids", "rev"}`,
/// copied from the [`Decision`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DecisionSummary {
    /// The effect.
    pub effect: Effect,
    /// The rules that decided.
    pub rule_ids: Vec<RuleId>,
    /// The tenant revision used.
    #[serde(with = "json_int")]
    pub rev: u64,
}

impl From<&Decision> for DecisionSummary {
    fn from(d: &Decision) -> Self {
        Self {
            effect: d.effect,
            rule_ids: d.rule_ids.clone(),
            rev: d.rev,
        }
    }
}

/// The producer's signature (CONTRACTS.md 9.3, Phase B).
///
/// Pure Ed25519 over the RFC 8785 (JCS) canonical JSON of the whole record
/// without `signature`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// The RFC 7638 JWK thumbprint of the producer's public key.
    pub key_id: Thumbprint,
    /// The Ed25519 signature, base64url without padding.
    pub value: SignatureValue,
}

/// One audit.v1 record (CONTRACTS.md 9.1).
///
/// Writers never write `null`: an empty optional field is left out, so the
/// signed bytes do not change when a record is parsed and written again.
/// Never put tokens, secrets or raw field values in any field.
///
/// Readers ignore unknown fields, so this struct drops a field that a newer
/// v1 writer added. Verify the producer signature (Phase B) over the JSON
/// object as it was received, not over this struct written out again, and
/// forward the received bytes, not a re-serialized copy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuditEventV1 {
    /// Always `audit.v1`.
    pub schema: AuditSchema,
    /// The record id, a UUIDv7.
    pub id: Uuid7,
    /// When it happened.
    pub time: Timestamp,
    /// The tenant key `(iss, tid)`.
    pub tenant: TenantKey,
    /// The org, when the action happened inside one.
    pub org: Option<OrgId>,
    /// Who acted.
    pub actor: Actor,
    /// A permission key. Tutela's own admin actions use `tutela_*` types.
    pub action: PermissionKey,
    /// What was touched.
    pub resource: ResourceRef,
    /// The decision summary.
    pub decision: DecisionSummary,
    /// `denied` exactly when `decision.effect` is `deny`.
    pub outcome: Outcome,
    /// Same format as `Decision.reason`. Break-glass:
    /// `break_glass: <the actor's typed reason>`.
    pub reason: Reason,
    /// The W3C trace id.
    pub trace_id: Option<TraceId>,
    /// The W3C span id.
    pub span_id: Option<SpanId>,
    /// The producer service.
    pub service: ServiceName,
    /// The request id.
    pub request_id: Option<RequestId>,
    /// The client IP. Personal data.
    pub ip: Option<ClientIp>,
    /// A keyed digest of the payload or of the before and after values.
    pub payload_digest: Option<PayloadDigest>,
    /// The labels of the data touched. Sorted, no duplicates, may be empty.
    pub labels: Vec<Label>,
    /// What else happened, as ids, numbers and codes (Phase B, additive).
    /// Never a token, a secret, an e-mail or a field value.
    pub details: Option<Details>,
    /// The producer's sequence number per (service, tenant), from 1.
    pub seq: u64,
    /// The producer's signature.
    pub signature: Signature,
}

/// The serde shape of [`AuditEventV1`]. Private, so the derived functions
/// cannot be called without the checks in the trait impls below.
#[derive(Serialize, Deserialize)]
#[serde(remote = "AuditEventV1")]
struct AuditEventV1Def {
    schema: AuditSchema,
    id: Uuid7,
    time: Timestamp,
    tenant: TenantKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    org: Option<OrgId>,
    actor: Actor,
    action: PermissionKey,
    resource: ResourceRef,
    decision: DecisionSummary,
    outcome: Outcome,
    reason: Reason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trace_id: Option<TraceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    span_id: Option<SpanId>,
    service: ServiceName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_id: Option<RequestId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<ClientIp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload_digest: Option<PayloadDigest>,
    labels: Vec<Label>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    details: Option<Details>,
    #[serde(with = "json_int")]
    seq: u64,
    signature: Signature,
}

impl AuditEventV1 {
    /// Checks the rules that join fields: actor kinds, outcome against effect,
    /// sorted labels, `seq` from 1, integers in the JSON range.
    ///
    /// # Errors
    ///
    /// Returns the [`AuditError`] of the first broken rule.
    pub fn check(&self) -> Result<(), AuditError> {
        check_parts(&self.actor, &self.decision, self.outcome, &self.labels)?;
        check_seq(self.seq)
    }

    /// The bytes the producer signs and the local chain hashes: the RFC 8785
    /// canonical JSON of the whole record without `signature`
    /// (CONTRACTS.md 9.3).
    ///
    /// # Errors
    ///
    /// The [`AuditError`] of a broken rule.
    pub fn signing_bytes(&self) -> Result<String, AuditError> {
        let mut v = serde_json::to_value(self).map_err(|_| AuditError::Canonical)?;
        if let Value::Object(map) = &mut v {
            map.remove("signature");
        }
        to_canonical_string(&v).map_err(|_| AuditError::Canonical)
    }

    /// The record of `body` (the canonical JSON without `signature`, as
    /// [`AuditDraft::body`] wrote it) with its producer `signature`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Canonical`] when `body` is not a JSON object, or the
    /// [`AuditError`] of a broken rule.
    pub fn from_body(body: &str, signature: &Signature) -> Result<Self, AuditError> {
        let mut v: Value = serde_json::from_str(body).map_err(|_| AuditError::Canonical)?;
        let Value::Object(map) = &mut v else {
            return Err(AuditError::Canonical);
        };
        map.insert(
            "signature".to_owned(),
            serde_json::to_value(signature).map_err(|_| AuditError::Canonical)?,
        );
        serde_json::from_value(v).map_err(|_| AuditError::Canonical)
    }
}

/// The rules that join fields, shared by [`AuditEventV1`] and
/// [`AuditDraft`].
fn check_parts(
    actor: &Actor,
    decision: &DecisionSummary,
    outcome: Outcome,
    labels: &[Label],
) -> Result<(), AuditError> {
    actor.check()?;
    let outcome_ok = match decision.effect {
        Effect::Deny => outcome == Outcome::Denied,
        Effect::Allow => outcome != Outcome::Denied,
    };
    if !outcome_ok {
        return Err(AuditError::OutcomeMismatch);
    }
    if !labels.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
        return Err(AuditError::LabelsNotSorted);
    }
    if decision.rev > crate::encoding::MAX_JSON_INT {
        return Err(AuditError::IntTooLarge);
    }
    Ok(())
}

fn check_seq(seq: u64) -> Result<(), AuditError> {
    if seq == 0 {
        return Err(AuditError::SeqZero);
    }
    if seq > crate::encoding::MAX_JSON_INT {
        return Err(AuditError::IntTooLarge);
    }
    Ok(())
}

/// The most `details` may hold, as canonical JSON.
pub const MAX_DETAILS_BYTES: usize = 8 * 1024;

/// The `details` of an audit record: a JSON object of ids, numbers and codes
/// that say what else happened, for example a token's `jti` and audience, or
/// a published version. It has no `null` and no fraction, so it has one
/// canonical form, and it is at most [`MAX_DETAILS_BYTES`].
///
/// Never put a token, a secret, an e-mail or a field value in it
/// (CONTRACTS.md 9.5).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Details(serde_json::Map<String, Value>);

impl Details {
    /// Checks `map`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Details`] for a `null`, a fraction, a number out of the
    /// JSON range, or more than [`MAX_DETAILS_BYTES`].
    pub fn new(map: serde_json::Map<String, Value>) -> Result<Self, AuditError> {
        let text =
            to_canonical_string(&Value::Object(map.clone())).map_err(|_| AuditError::Details)?;
        if text.len() > MAX_DETAILS_BYTES {
            return Err(AuditError::Details);
        }
        Ok(Self(map))
    }

    /// The object.
    #[must_use]
    pub const fn as_map(&self) -> &serde_json::Map<String, Value> {
        &self.0
    }

    /// One member.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }
}

impl Serialize for Details {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Details {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        Self::new(map).map_err(de::Error::custom)
    }
}

/// An audit record before the producer gives it its `seq` and signs it:
/// every field of [`AuditEventV1`] but `schema`, `seq` and `signature`.
///
/// Tutela's local log stores [`AuditDraft::body`] with the chain's `seq`,
/// and signs it when it forwards the record (CONTRACTS.md 9.3, 9.4).
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct AuditDraft {
    /// The record id, a UUIDv7.
    pub id: Uuid7,
    /// When it happened.
    pub time: Timestamp,
    /// The tenant key `(iss, tid)`.
    pub tenant: TenantKey,
    /// The org, when the action happened inside one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgId>,
    /// Who acted.
    pub actor: Actor,
    /// A permission key. Tutela's own admin actions use `tutela_*` types.
    pub action: PermissionKey,
    /// What was touched.
    pub resource: ResourceRef,
    /// The decision summary.
    pub decision: DecisionSummary,
    /// `denied` exactly when `decision.effect` is `deny`.
    pub outcome: Outcome,
    /// Same format as `Decision.reason`.
    pub reason: Reason,
    /// The W3C trace id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<TraceId>,
    /// The W3C span id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<SpanId>,
    /// The producer service.
    pub service: ServiceName,
    /// The request id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    /// The client IP. Personal data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<ClientIp>,
    /// A keyed digest of the payload or of the before and after values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<PayloadDigest>,
    /// The labels of the data touched. Sorted, no duplicates, may be empty.
    pub labels: Vec<Label>,
    /// What else happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Details>,
}

impl AuditDraft {
    /// Checks the rules that join fields, as [`AuditEventV1::check`] does.
    ///
    /// # Errors
    ///
    /// The [`AuditError`] of the first broken rule.
    pub fn check(&self) -> Result<(), AuditError> {
        check_parts(&self.actor, &self.decision, self.outcome, &self.labels)
    }

    /// The canonical JSON of the record with `seq` and without `signature`:
    /// the bytes the local chain hashes and the producer signs.
    ///
    /// # Errors
    ///
    /// The [`AuditError`] of a broken rule.
    pub fn body(&self, seq: u64) -> Result<String, AuditError> {
        self.check()?;
        check_seq(seq)?;
        let mut v = serde_json::to_value(self).map_err(|_| AuditError::Canonical)?;
        let Value::Object(map) = &mut v else {
            return Err(AuditError::Canonical);
        };
        map.insert("schema".to_owned(), Value::from(AuditSchema::VALUE));
        map.insert("seq".to_owned(), Value::from(seq));
        to_canonical_string(&v).map_err(|_| AuditError::Canonical)
    }
}

impl Serialize for AuditEventV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.check().map_err(ser::Error::custom)?;
        AuditEventV1Def::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for AuditEventV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let record = AuditEventV1Def::deserialize(deserializer)?;
        record.check().map_err(de::Error::custom)?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const HEX64: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const KEY_ID: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    fn sig_value() -> String {
        format!("{}w", "AbCd".repeat(22).get(..85).unwrap())
    }

    /// The CONTRACTS.md 9.2 example with its placeholders filled with test
    /// values.
    fn doc_record() -> Value {
        let doc = r#"{
          "schema": "audit.v1",
          "id": "0193a1b2-c3d5-7001-8000-0000000000a1",
          "time": "2026-10-25T09:31:12.345Z",
          "tenant": { "iss": "https://auth.example.test", "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b" },
          "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002",
          "actor": {
            "kind": "agent",
            "id": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102",
            "on_behalf_of": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081"
          },
          "action": "invoice:approve",
          "resource": { "type": "invoice", "id": "inv-881" },
          "decision": { "effect": "deny", "rule_ids": ["ra_0193a1b2-c3d4-7a00-8000-0000000000a2"], "rev": 42 },
          "outcome": "denied",
          "reason": "delegation_overlap: agent has read at project p-77",
          "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
          "span_id": "00f067aa0ba902b7",
          "service": "crm-api",
          "request_id": "req-7f3k9q",
          "ip": "203.0.113.7",
          "payload_digest": "hmac-sha256:v1:<64 lowercase hex>",
          "labels": ["internal"],
          "seq": 1042,
          "signature": { "key_id": "<43 base64url characters>", "value": "<86 base64url characters>" }
        }"#;
        let filled = doc
            .replace("<64 lowercase hex>", HEX64)
            .replace("<43 base64url characters>", KEY_ID)
            .replace("<86 base64url characters>", &sig_value());
        serde_json::from_str(&filled).unwrap()
    }

    #[test]
    fn doc_example_round_trips_exactly() {
        let v = doc_record();
        let r: AuditEventV1 = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(r.actor.kind, PrincipalKind::Agent);
        assert_eq!(r.outcome, Outcome::Denied);
        assert_eq!(r.payload_digest.as_ref().unwrap().key_version(), 1);
        assert_eq!(r.payload_digest.as_ref().unwrap().hex(), HEX64);
        assert_eq!(
            r.tenant.tid.to_string(),
            "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"
        );
        assert!(matches!(r.action, PermissionKey::Action(_)));
        assert_eq!(serde_json::to_value(&r).unwrap(), v);
    }

    #[test]
    fn minimal_record_writes_no_nulls() {
        let mut v = doc_record();
        let obj = v.as_object_mut().unwrap();
        for k in [
            "org",
            "trace_id",
            "span_id",
            "request_id",
            "ip",
            "payload_digest",
        ] {
            obj.remove(k);
        }
        obj["actor"] = json!({ "kind": "sa", "id": "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3" });
        obj["labels"] = json!([]);
        obj["decision"]["effect"] = json!("allow");
        obj["outcome"] = json!("failure");
        obj["action"] = json!("tutela_role:write");
        let r: AuditEventV1 = serde_json::from_value(v.clone()).unwrap();
        let out = serde_json::to_string(&r).unwrap();
        assert!(!out.contains("null"), "{out}");
        assert_eq!(serde_json::to_value(&r).unwrap(), v);

        // Readers treat `null` like a missing optional field.
        let mut with_nulls = v.clone();
        with_nulls["org"] = Value::Null;
        with_nulls["ip"] = Value::Null;
        with_nulls["actor"]["on_behalf_of"] = Value::Null;
        let r2: AuditEventV1 = serde_json::from_value(with_nulls).unwrap();
        assert_eq!(r2, r);
    }

    #[test]
    fn explicit_deserialize_calls_still_check() {
        // Regression: `AuditEventV1::deserialize(..)` must run `check()`.
        let mut v = doc_record();
        v["outcome"] = json!("success");
        let text = v.to_string();
        let mut de = serde_json::Deserializer::from_str(&text);
        assert!(AuditEventV1::deserialize(&mut de).is_err());
    }

    #[test]
    fn cross_field_rules() {
        let base = doc_record();
        let cases: Vec<(&str, Value)> = vec![
            (
                "kind mismatch",
                json!({ "kind": "user", "id": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102" }),
            ),
            (
                "on_behalf_of not a user",
                json!({ "kind": "agent", "id": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102", "on_behalf_of": "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3" }),
            ),
            (
                "delegated actor not an agent",
                json!({ "kind": "sa", "id": "sa:sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3", "on_behalf_of": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081" }),
            ),
            (
                "unknown kind",
                json!({ "kind": "group", "id": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102" }),
            ),
        ];
        for (why, actor) in cases {
            let mut v = base.clone();
            v["actor"] = actor;
            assert!(serde_json::from_value::<AuditEventV1>(v).is_err(), "{why}");
        }
        for (effect, outcome, ok) in [
            ("deny", "denied", true),
            ("deny", "success", false),
            ("deny", "failure", false),
            ("allow", "success", true),
            ("allow", "failure", true),
            ("allow", "denied", false),
        ] {
            let mut v = base.clone();
            v["decision"]["effect"] = json!(effect);
            v["outcome"] = json!(outcome);
            assert_eq!(
                serde_json::from_value::<AuditEventV1>(v).is_ok(),
                ok,
                "{effect}/{outcome}"
            );
        }
        for labels in [
            json!(["secret", "internal"]),
            json!(["internal", "internal"]),
            json!(["Internal"]),
        ] {
            let mut v = base.clone();
            v["labels"] = labels.clone();
            assert!(
                serde_json::from_value::<AuditEventV1>(v).is_err(),
                "{labels}"
            );
        }
        let mut v = base.clone();
        v["labels"] = json!(["confidential", "internal", "secret"]);
        assert!(serde_json::from_value::<AuditEventV1>(v).is_ok());

        let mut v = base.clone();
        v["seq"] = json!(0);
        assert!(serde_json::from_value::<AuditEventV1>(v).is_err());

        // Writers cannot emit a broken record either.
        let mut r: AuditEventV1 = serde_json::from_value(base).unwrap();
        r.outcome = Outcome::Success;
        assert_eq!(r.check(), Err(AuditError::OutcomeMismatch));
        assert!(serde_json::to_value(&r).is_err());
        r.outcome = Outcome::Denied;
        r.seq = 0;
        assert_eq!(r.check(), Err(AuditError::SeqZero));
        r.seq = crate::encoding::MAX_JSON_INT + 1;
        assert_eq!(r.check(), Err(AuditError::IntTooLarge));
    }

    #[test]
    fn field_formats() {
        let base = doc_record();
        for (k, bad) in [
            ("schema", json!("audit.v2")),
            ("schema", json!(null)),
            ("time", json!("2026-10-25T09:31:12Z")),
            ("tenant", json!({ "iss": "https://auth.example.test" })),
            ("action", json!("invoice")),
            ("action", json!("invoices.approve.button")),
            ("resource", json!({ "type": "invoice", "id": "" })),
            ("resource", json!({ "kind": "invoice", "id": "inv-881" })),
            ("outcome", json!("ok")),
            ("reason", json!("delegation_overlap:agent")),
            ("trace_id", json!("4BF92F3577B34DA6A3CE929D0E0E4736")),
            ("trace_id", json!("00000000000000000000000000000000")),
            ("span_id", json!("00f067aa0ba902b")),
            ("service", json!("CRM")),
            ("service", json!("crm_api")),
            ("request_id", json!("")),
            ("request_id", json!("has space")),
            ("ip", json!("203.0.113.007")),
            ("ip", json!("2001:DB8::1")),
            ("ip", json!("2001:db8:0:0:0:0:0:1")),
            ("ip", json!("::FFFF:1.2.3.4")),
            ("ip", json!("localhost")),
            ("payload_digest", json!(format!("hmac-sha256:v0:{HEX64}"))),
            ("payload_digest", json!(format!("hmac-sha256:v01:{HEX64}"))),
            ("payload_digest", json!(format!("hmac-sha256:v:{HEX64}"))),
            ("payload_digest", json!(format!("hmac-sha256:1:{HEX64}"))),
            ("payload_digest", json!(format!("sha256:v1:{HEX64}"))),
            (
                "payload_digest",
                json!(format!("hmac-sha256:v1:{}", HEX64.to_uppercase())),
            ),
            ("payload_digest", json!("hmac-sha256:v1:abc")),
            ("seq", json!(-1)),
            ("seq", json!("1")),
            ("signature", json!({ "key_id": KEY_ID })),
            (
                "signature",
                json!({ "key_id": "short", "value": sig_value() }),
            ),
            (
                "signature",
                json!({ "key_id": KEY_ID, "value": format!("{}B", "A".repeat(85)) }),
            ),
        ] {
            let mut v = base.clone();
            v[k] = bad.clone();
            assert!(
                serde_json::from_value::<AuditEventV1>(v).is_err(),
                "{k} = {bad}"
            );
        }
        for k in [
            "schema",
            "id",
            "time",
            "tenant",
            "actor",
            "action",
            "resource",
            "decision",
            "outcome",
            "reason",
            "service",
            "labels",
            "seq",
            "signature",
        ] {
            let mut v = base.clone();
            v.as_object_mut().unwrap().remove(k);
            assert!(
                serde_json::from_value::<AuditEventV1>(v).is_err(),
                "missing {k}"
            );
        }
        for ok in [
            "2001:db8::1",
            "::1",
            "::ffff:1.2.3.4",
            "10.0.0.1",
            "0.0.0.0",
        ] {
            assert_eq!(ClientIp::parse(ok).unwrap().to_string(), ok);
        }
        let d = PayloadDigest::parse(&format!("hmac-sha256:v12:{HEX64}")).unwrap();
        assert_eq!(d.key_version(), 12);
        assert_eq!(d.to_string(), format!("hmac-sha256:v12:{HEX64}"));
        assert_eq!(PayloadDigest::new(0, HEX64), Err(AuditError::PayloadDigest));
    }

    #[test]
    fn actor_constructors() {
        let agent: Principal = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102"
            .parse()
            .unwrap();
        let person: Principal = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081"
            .parse()
            .unwrap();
        let delegated = Actor::delegated(agent.clone(), person.clone());
        assert_eq!(delegated.kind, PrincipalKind::Agent);
        assert_eq!(delegated.check(), Ok(()));
        let own = Actor::new(agent);
        assert_eq!(own.on_behalf_of, None);
        assert_eq!(own.check(), Ok(()));
        assert_eq!(
            Actor::delegated(person.clone(), person).check(),
            Err(AuditError::DelegatedActorNotAgent)
        );
    }

    #[test]
    fn summary_from_decision() {
        let d: Decision = serde_json::from_value(json!({
            "effect": "allow", "level": "read",
            "field_mask": { "read": ["status"], "write": [] },
            "rule_ids": ["ra_1"], "reason": "allowed", "rev": 9, "obligations": []
        }))
        .unwrap();
        let s = DecisionSummary::from(&d);
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            json!({ "effect": "allow", "rule_ids": ["ra_1"], "rev": 9 })
        );
        assert_eq!(AuditSchema.to_string(), "audit.v1");
    }

    fn draft_of(r: &AuditEventV1) -> AuditDraft {
        AuditDraft {
            id: r.id,
            time: r.time,
            tenant: r.tenant.clone(),
            org: r.org,
            actor: r.actor.clone(),
            action: r.action.clone(),
            resource: r.resource.clone(),
            decision: r.decision.clone(),
            outcome: r.outcome,
            reason: r.reason.clone(),
            trace_id: r.trace_id.clone(),
            span_id: r.span_id.clone(),
            service: r.service.clone(),
            request_id: r.request_id.clone(),
            ip: r.ip,
            payload_digest: r.payload_digest.clone(),
            labels: r.labels.clone(),
            details: r.details.clone(),
        }
    }

    #[test]
    fn a_draft_body_is_the_signing_bytes_of_its_record() {
        let mut v = doc_record();
        v["details"] = json!({"jti": "0193a1b2-c3d5-7000-8000-0000000000e1", "act": [{"sub": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102"}], "exp": 1_792_920_750, "ok": true});
        let r: AuditEventV1 = serde_json::from_value(v.clone()).unwrap();
        let body = draft_of(&r).body(r.seq).unwrap();
        assert_eq!(body, r.signing_bytes().unwrap());
        assert!(!body.contains("signature"));
        assert!(body.starts_with("{\"action\":"), "{body}");
        let back = AuditEventV1::from_body(&body, &r.signature).unwrap();
        assert_eq!(back, r);
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
        // The draft checks the same rules as the record.
        let mut bad = draft_of(&r);
        bad.outcome = Outcome::Success;
        assert_eq!(bad.body(1), Err(AuditError::OutcomeMismatch));
        assert_eq!(draft_of(&r).body(0), Err(AuditError::SeqZero));
    }

    #[test]
    fn details_have_one_canonical_form() {
        let ok = json!({"a": 1, "b": ["x"], "c": {"d": false}});
        assert!(Details::new(ok.as_object().unwrap().clone()).is_ok());
        for bad in [
            json!({"a": null}),
            json!({"a": 1.5}),
            json!({"a": "x".repeat(MAX_DETAILS_BYTES)}),
        ] {
            assert_eq!(
                Details::new(bad.as_object().unwrap().clone()),
                Err(AuditError::Details)
            );
        }
        let mut v = doc_record();
        v["details"] = json!({"a": null});
        assert!(serde_json::from_value::<AuditEventV1>(v).is_err());
        let mut v = doc_record();
        v["details"] = json!("not an object");
        assert!(serde_json::from_value::<AuditEventV1>(v).is_err());
    }
}
