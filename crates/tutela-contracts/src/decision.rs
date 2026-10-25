//! The Decision object, reason codes and obligations (CONTRACTS.md 6.1 to
//! 6.3).
//!
//! The `Pdp` API that makes decisions (`check`, `batch`, `list_filter`,
//! `write_check`) is Phase A, in `tutela-pdp`.

use core::fmt;
use core::str::FromStr;

use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

use crate::encoding::json_int;
use crate::keys::{FieldName, Label, NameError, check_name};
use crate::level::Level;
use crate::principal::{Principal, PrincipalKind};

/// The error text when an `audit` obligation names a principal that is not a
/// user (CONTRACTS.md 6.3).
const ON_BEHALF_OF_KIND: &str = "`on_behalf_of` must be a `user` principal";

/// The effect was not `allow` or `deny`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("an effect must be `allow` or `deny`")]
pub struct EffectError;

/// The answer for the requested action. A closed set: any other value is an
/// error, which means deny.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Effect {
    /// `allow`.
    Allow,
    /// `deny`.
    Deny,
}

impl Effect {
    /// The JSON spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Effect {
    type Err = EffectError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(EffectError),
        }
    }
}

string_serde!(Effect, "an effect: allow or deny");

/// Why a field mask was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FieldMaskError {
    /// `read` is not sorted or has a duplicate.
    #[error("`field_mask.read` must be sorted with no duplicates")]
    ReadNotSorted,
    /// `write` is not sorted or has a duplicate.
    #[error("`field_mask.write` must be sorted with no duplicates")]
    WriteNotSorted,
    /// A name in `write` is not in `read`.
    #[error("`field_mask.write` must be a subset of `field_mask.read`")]
    WriteNotInRead,
}

/// The field mask: `{"read": [...], "write": [...]}` (CONTRACTS.md 6.1).
///
/// Allow-lists of field names and feature names (`@ai`) of the item's type.
/// A field not in `read` is masked. `write` is a subset of `read`. Both lists
/// are sorted by bytes with no duplicates; a reader rejects a mask that is
/// not.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct FieldMask {
    read: Vec<FieldName>,
    write: Vec<FieldName>,
}

/// The serde shape of [`FieldMask`]. Private, so the derived functions
/// cannot be called without the checks in the trait impls below.
#[derive(Serialize, Deserialize)]
#[serde(remote = "FieldMask")]
struct FieldMaskDef {
    read: Vec<FieldName>,
    write: Vec<FieldName>,
}

impl FieldMask {
    /// Makes a mask. The lists are sorted and de-duplicated.
    ///
    /// # Errors
    ///
    /// Returns [`FieldMaskError::WriteNotInRead`] when a `write` name is not
    /// in `read`.
    pub fn new<R, W>(read: R, write: W) -> Result<Self, FieldMaskError>
    where
        R: IntoIterator<Item = FieldName>,
        W: IntoIterator<Item = FieldName>,
    {
        let mut read: Vec<FieldName> = read.into_iter().collect();
        read.sort();
        read.dedup();
        let mut write: Vec<FieldName> = write.into_iter().collect();
        write.sort();
        write.dedup();
        let mask = Self { read, write };
        mask.check()?;
        Ok(mask)
    }

    /// The empty mask: everything masked.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            read: Vec::new(),
            write: Vec::new(),
        }
    }

    /// The names the principal may read, sorted.
    #[must_use]
    pub fn read(&self) -> &[FieldName] {
        &self.read
    }

    /// The names the principal may change, sorted.
    #[must_use]
    pub fn write(&self) -> &[FieldName] {
        &self.write
    }

    /// `true` if `field` is in `read`.
    #[must_use]
    pub fn can_read(&self, field: &FieldName) -> bool {
        self.read.binary_search(field).is_ok()
    }

    /// `true` if `field` is in `write`.
    #[must_use]
    pub fn can_write(&self, field: &FieldName) -> bool {
        self.write.binary_search(field).is_ok()
    }

    /// `true` if both lists are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }

    /// The names in both masks: the delegation overlap (CONTRACTS.md 6.4).
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            read: self
                .read
                .iter()
                .filter(|f| other.can_read(f))
                .cloned()
                .collect(),
            write: self
                .write
                .iter()
                .filter(|f| other.can_write(f))
                .cloned()
                .collect(),
        }
    }

    /// Checks the rules: both lists sorted with no duplicates, `write` a
    /// subset of `read`.
    ///
    /// # Errors
    ///
    /// Returns the [`FieldMaskError`] of the first broken rule.
    pub fn check(&self) -> Result<(), FieldMaskError> {
        if !self.read.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
            return Err(FieldMaskError::ReadNotSorted);
        }
        if !self.write.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
            return Err(FieldMaskError::WriteNotSorted);
        }
        if !self.write.iter().all(|f| self.can_read(f)) {
            return Err(FieldMaskError::WriteNotInRead);
        }
        Ok(())
    }
}

impl Serialize for FieldMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.check().map_err(ser::Error::custom)?;
        FieldMaskDef::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for FieldMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mask = FieldMaskDef::deserialize(deserializer)?;
        mask.check().map_err(de::Error::custom)?;
        Ok(mask)
    }
}

/// A rule id was not 1 to 128 visible ASCII characters.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("a rule id must be 1 to 128 visible ASCII characters")]
pub struct RuleIdError;

/// The id of a stored rule that decided: a role assignment, field rule,
/// condition or boundary rule. Opaque: 1 to 128 visible ASCII characters. For
/// explain and audit only; never parse it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RuleId(String);

impl RuleId {
    /// Parses a rule id.
    ///
    /// # Errors
    ///
    /// Returns [`RuleIdError`] when `s` is empty, longer than 128 characters
    /// or not visible ASCII.
    pub fn parse(s: &str) -> Result<Self, RuleIdError> {
        if crate::text::is_visible_ascii_str(s, 1, 128) {
            Ok(Self(s.to_owned()))
        } else {
            Err(RuleIdError)
        }
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RuleId {
    type Err = RuleIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(RuleId, "a rule id string");

/// The reason codes of CONTRACTS.md 6.2. An open set on the wire: a code this
/// version does not know is treated like [`ReasonCode::NotAllowed`].
///
/// New codes may be added inside v1, so the enum is `#[non_exhaustive]`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum ReasonCode {
    /// `allowed`: a role on the path allows it.
    Allowed,
    /// `no_role`: no role on the path. Default deny.
    NoRole,
    /// `level_too_low`: a role was found, but its level is too low.
    LevelTooLow,
    /// `missing_grant`: the custom action needs a grant the role lacks.
    MissingGrant,
    /// `admin_only`: an owner-only admin action the principal does not hold.
    AdminOnly,
    /// `condition_failed`: a condition on the role was false.
    ConditionFailed,
    /// `private_scope`: a private scope stopped inheritance.
    PrivateScope,
    /// `delegation_overlap`: the person or the agent lacks the level.
    DelegationOverlap,
    /// `outside_ai_reach`: the agent works outside its `ai_reach`.
    OutsideAiReach,
    /// `principal_disabled`: the subject or an actor is disabled.
    PrincipalDisabled,
    /// `tenant_mismatch`: the resource or a principal is of another tenant.
    TenantMismatch,
    /// `break_glass`: an org Owner opened hidden data through break-glass.
    BreakGlass,
    /// `not_allowed`: a generic deny, where the real reason must stay hidden.
    NotAllowed,
}

impl ReasonCode {
    /// Every known code. A slice, so that a new code does not change its type.
    pub const ALL: &'static [Self] = &[
        Self::Allowed,
        Self::NoRole,
        Self::LevelTooLow,
        Self::MissingGrant,
        Self::AdminOnly,
        Self::ConditionFailed,
        Self::PrivateScope,
        Self::DelegationOverlap,
        Self::OutsideAiReach,
        Self::PrincipalDisabled,
        Self::TenantMismatch,
        Self::BreakGlass,
        Self::NotAllowed,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::NoRole => "no_role",
            Self::LevelTooLow => "level_too_low",
            Self::MissingGrant => "missing_grant",
            Self::AdminOnly => "admin_only",
            Self::ConditionFailed => "condition_failed",
            Self::PrivateScope => "private_scope",
            Self::DelegationOverlap => "delegation_overlap",
            Self::OutsideAiReach => "outside_ai_reach",
            Self::PrincipalDisabled => "principal_disabled",
            Self::TenantMismatch => "tenant_mismatch",
            Self::BreakGlass => "break_glass",
            Self::NotAllowed => "not_allowed",
        }
    }

    /// The known code with this name.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == code)
    }

    /// `true` if the code is safe to show to the end user. The permission map
    /// sends other codes as `not_allowed`.
    #[must_use]
    pub const fn is_safe_to_show(self) -> bool {
        matches!(
            self,
            Self::Allowed
                | Self::LevelTooLow
                | Self::MissingGrant
                | Self::AdminOnly
                | Self::ConditionFailed
                | Self::DelegationOverlap
                | Self::NotAllowed
        )
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a reason string was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReasonError {
    /// The reason is longer than 512 characters.
    #[error("a reason is at most 512 characters")]
    TooLong,
    /// The code is not a name.
    #[error("invalid reason code: {0}")]
    Code(#[from] NameError),
    /// The `:` after the code is not followed by one space.
    #[error("a reason must be `<code>` or `<code>: <detail>`")]
    Separator,
    /// The detail after `: ` is empty.
    #[error("the detail after `<code>: ` must not be empty")]
    EmptyDetail,
    /// The detail has a control character or a line break (this includes
    /// U+2028 and U+2029).
    #[error("the detail must not contain control characters or line breaks")]
    DetailChar,
}

/// A reason: `<code>` or `<code>: <detail>` (CONTRACTS.md 6.1 and 6.2).
///
/// The code uses the name grammar. The detail is short English for logs and
/// the Console's explain view, with ids but never names, e-mails or field
/// values. At most 512 characters in total; no control characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Reason(String);

impl Reason {
    /// The longest reason, in characters.
    pub const MAX_CHARS: usize = 512;

    /// A reason with only a code.
    #[must_use]
    pub fn new(code: ReasonCode) -> Self {
        Self(code.as_str().to_owned())
    }

    /// A reason with a code and a detail.
    ///
    /// # Errors
    ///
    /// Returns a [`ReasonError`] when the detail is empty, has a control
    /// character, or makes the reason longer than 512 characters.
    pub fn with_detail(code: ReasonCode, detail: &str) -> Result<Self, ReasonError> {
        Self::parse(&format!("{code}: {detail}"))
    }

    /// Parses a reason.
    ///
    /// # Errors
    ///
    /// Returns a [`ReasonError`] when `s` breaks a rule above.
    pub fn parse(s: &str) -> Result<Self, ReasonError> {
        if s.chars().count() > Self::MAX_CHARS {
            return Err(ReasonError::TooLong);
        }
        let code = match s.split_once(':') {
            None => s,
            Some((code, rest)) => {
                let detail = rest.strip_prefix(' ').ok_or(ReasonError::Separator)?;
                if detail.is_empty() {
                    return Err(ReasonError::EmptyDetail);
                }
                if detail.chars().any(is_control_or_line_break) {
                    return Err(ReasonError::DetailChar);
                }
                code
            }
        };
        check_name(code)?;
        Ok(Self(s.to_owned()))
    }

    /// The code: the text before the first `:`, or the whole reason.
    #[must_use]
    pub fn code(&self) -> &str {
        self.0
            .split_once(':')
            .map_or(self.0.as_str(), |(code, _)| code)
    }

    /// The detail after `<code>: `, if any.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.0
            .split_once(':')
            .and_then(|(_, rest)| rest.strip_prefix(' '))
    }

    /// The code, if this version knows it.
    #[must_use]
    pub fn known_code(&self) -> Option<ReasonCode> {
        ReasonCode::from_code(self.code())
    }

    /// The code to show an end user: the code if it is known and safe to
    /// show, else `not_allowed`.
    #[must_use]
    pub fn public_code(&self) -> ReasonCode {
        match self.known_code() {
            Some(code) if code.is_safe_to_show() => code,
            _ => ReasonCode::NotAllowed,
        }
    }

    /// The whole reason text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A control character (`Cc`), or the Unicode line and paragraph separators
/// U+2028 and U+2029, which break lines in logs and JSON-in-JS too.
fn is_control_or_line_break(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Reason {
    type Err = ReasonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

string_serde!(Reason, "a reason string `<code>` or `<code>: <detail>`");

/// An obligation kind this version does not know. The caller must treat the
/// whole decision as **deny** (CONTRACTS.md 6.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnknownObligation {
    kind: String,
    object: serde_json::Map<String, serde_json::Value>,
}

impl UnknownObligation {
    /// The unknown `kind`.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The whole obligation object, with `kind`.
    #[must_use]
    pub const fn object(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.object
    }
}

/// Something the caller must do with a decision (CONTRACTS.md 6.3). An open
/// set by `kind`. Final kind names are fixed in Phase A.
///
/// New kinds may be added inside v1, so the enum is `#[non_exhaustive]`.
/// When you match on it, the wildcard arm must **deny**, exactly like
/// [`Obligation::Unknown`]: a kind you do not handle is a kind you cannot
/// carry out.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Obligation {
    /// `audit`: write an audit.v1 record for this access before data is
    /// returned.
    Audit {
        /// The person the record must name, if set. Must be of kind `user`.
        on_behalf_of: Option<Principal>,
        /// Ask the actor for a short reason and record it. Default `false`.
        reason_required: bool,
    },
    /// `label`: mark everything built from this item with at least this label.
    Label {
        /// The label.
        value: Label,
    },
    /// `restricted`: show these masked fields as "Restricted" instead of
    /// removing them. Exports still remove them.
    Restricted {
        /// The field names.
        fields: Vec<FieldName>,
    },
    /// `recheck_online`: ask `tutelad` again before acting (Phase B). If it
    /// cannot answer, deny.
    RecheckOnline,
    /// A kind this version does not know: treat the decision as deny.
    Unknown(UnknownObligation),
}

impl Obligation {
    /// The `kind` text.
    #[must_use]
    pub fn kind(&self) -> &str {
        match self {
            Self::Audit { .. } => "audit",
            Self::Label { .. } => "label",
            Self::Restricted { .. } => "restricted",
            Self::RecheckOnline => "recheck_online",
            Self::Unknown(u) => u.kind(),
        }
    }

    /// `true` if this version knows the kind.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl Serialize for Obligation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Self::Unknown(u) = self {
            return u.object.serialize(serializer);
        }
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("kind", self.kind())?;
        match self {
            Self::Audit {
                on_behalf_of,
                reason_required,
            } => {
                if let Some(p) = on_behalf_of {
                    if p.kind() != PrincipalKind::User {
                        return Err(ser::Error::custom(ON_BEHALF_OF_KIND));
                    }
                    map.serialize_entry("on_behalf_of", p)?;
                }
                map.serialize_entry("reason_required", reason_required)?;
            }
            Self::Label { value } => map.serialize_entry("value", value)?,
            Self::Restricted { fields } => map.serialize_entry("fields", fields)?,
            Self::RecheckOnline | Self::Unknown(_) => {}
        }
        map.end()
    }
}

#[derive(Deserialize)]
struct AuditBody {
    #[serde(default)]
    on_behalf_of: Option<Principal>,
    #[serde(default)]
    reason_required: Option<bool>,
}

#[derive(Deserialize)]
struct LabelBody {
    value: Label,
}

#[derive(Deserialize)]
struct RestrictedBody {
    fields: Vec<FieldName>,
}

impl<'de> Deserialize<'de> for Obligation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let object = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let Some(serde_json::Value::String(kind)) = object.get("kind") else {
            return Err(de::Error::custom("an obligation needs a string `kind`"));
        };
        let kind = kind.clone();
        let obligation = match kind.as_str() {
            "audit" => {
                let body: AuditBody = body_of(object)?;
                if body
                    .on_behalf_of
                    .as_ref()
                    .is_some_and(|p| p.kind() != PrincipalKind::User)
                {
                    return Err(de::Error::custom(ON_BEHALF_OF_KIND));
                }
                Self::Audit {
                    on_behalf_of: body.on_behalf_of,
                    reason_required: body.reason_required.unwrap_or(false),
                }
            }
            "label" => {
                let body: LabelBody = body_of(object)?;
                Self::Label { value: body.value }
            }
            "restricted" => {
                let body: RestrictedBody = body_of(object)?;
                Self::Restricted {
                    fields: body.fields,
                }
            }
            "recheck_online" => Self::RecheckOnline,
            _ => Self::Unknown(UnknownObligation { kind, object }),
        };
        Ok(obligation)
    }
}

/// Reads the fields of a known obligation kind from its object.
fn body_of<T, E>(object: serde_json::Map<String, serde_json::Value>) -> Result<T, E>
where
    T: de::DeserializeOwned,
    E: de::Error,
{
    serde_json::from_value(serde_json::Value::Object(object)).map_err(E::custom)
}

/// Why a Decision was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecisionError {
    /// `level` is `none` but the field mask is not empty.
    #[error("both field mask lists must be empty when the level is `none`")]
    MaskNotEmptyAtNone,
    /// `rev` is above 2^53 − 1.
    #[error("`rev` must be at most 2^53 - 1")]
    RevTooLarge,
}

/// The Decision object (CONTRACTS.md 6.1).
///
/// What a caller must do: on `deny`, do not do the action; remove every field
/// and feature not in `field_mask.read` before data leaves the server; never
/// change a field not in `field_mask.write`; carry out every obligation, and
/// treat an unknown obligation kind as deny. [`Decision::is_allowed`] folds
/// the effect and the unknown-obligation rule into one answer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Decision {
    /// The answer for the requested action.
    pub effect: Effect,
    /// The effective level on the item, after the delegation overlap. It can
    /// be above `none` when `effect` is `deny`.
    pub level: Level,
    /// The fields and features the principal may read and change.
    pub field_mask: FieldMask,
    /// The stored rules that decided. Empty for a default deny.
    pub rule_ids: Vec<RuleId>,
    /// `<code>` or `<code>: <detail>`. The effect decides; the reason only
    /// explains.
    pub reason: Reason,
    /// The tenant revision of the bundle that was used.
    pub rev: u64,
    /// Things the caller must do. Often empty.
    pub obligations: Vec<Obligation>,
}

/// The serde shape of [`Decision`]. Private, so the derived functions
/// cannot be called without the checks in the trait impls below.
#[derive(Serialize, Deserialize)]
#[serde(remote = "Decision")]
struct DecisionDef {
    effect: Effect,
    level: Level,
    field_mask: FieldMask,
    rule_ids: Vec<RuleId>,
    reason: Reason,
    #[serde(with = "json_int")]
    rev: u64,
    obligations: Vec<Obligation>,
}

impl Decision {
    /// Checks the rules that join fields: an empty mask at level `none`, and
    /// `rev` in the JSON integer range.
    ///
    /// # Errors
    ///
    /// Returns the [`DecisionError`] of the first broken rule.
    pub fn check(&self) -> Result<(), DecisionError> {
        if self.level == Level::None && !self.field_mask.is_empty() {
            return Err(DecisionError::MaskNotEmptyAtNone);
        }
        if self.rev > crate::encoding::MAX_JSON_INT {
            return Err(DecisionError::RevTooLarge);
        }
        Ok(())
    }

    /// `true` only when `effect` is `allow` **and** every obligation kind is
    /// known. An unknown kind means deny.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.effect == Effect::Allow && self.obligations.iter().all(Obligation::is_known)
    }
}

impl Serialize for Decision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.check().map_err(ser::Error::custom)?;
        DecisionDef::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for Decision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let decision = DecisionDef::deserialize(deserializer)?;
        decision.check().map_err(de::Error::custom)?;
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{Value, json};

    const DOC_DECISION: &str = r#"{
      "effect": "allow",
      "level": "write",
      "field_mask": {
        "read":  ["@ai", "assignee", "number", "status"],
        "write": ["status"]
      },
      "rule_ids": ["ra_0193a1b2-c3d4-7a00-8000-0000000000a1", "fr_0193a1b2-c3d4-7a00-8000-0000000000f1"],
      "reason": "allowed: role assignment at project p-77; amount hidden by a field rule at the org root",
      "rev": 42,
      "obligations": [
        { "kind": "label", "value": "internal" }
      ]
    }"#;

    const REMOTE_DECISION: &str = r#"{
      "effect": "deny",
      "level": "read",
      "field_mask": { "read": ["status"], "write": [] },
      "rule_ids": ["ra_0193a1b2-c3d4-7a00-8000-0000000000a1", "ra_0193a1b2-c3d4-7a00-8000-0000000000a2"],
      "reason": "delegation_overlap: agent has read at project p-77",
      "rev": 42,
      "obligations": []
    }"#;

    fn f(s: &str) -> FieldName {
        FieldName::parse(s).unwrap()
    }

    #[test]
    fn doc_examples_round_trip_exactly() {
        for doc in [DOC_DECISION, REMOTE_DECISION] {
            let d: Decision = serde_json::from_str(doc).unwrap();
            let back = serde_json::to_value(&d).unwrap();
            assert_eq!(back, serde_json::from_str::<Value>(doc).unwrap());
        }
        let d: Decision = serde_json::from_str(DOC_DECISION).unwrap();
        assert!(d.is_allowed());
        assert!(d.field_mask.can_read(&f("@ai")));
        assert!(!d.field_mask.can_read(&f("amount")));
        assert!(d.field_mask.can_write(&f("status")));
        assert!(!d.field_mask.can_write(&f("number")));
        assert_eq!(d.reason.code(), "allowed");
        assert_eq!(d.reason.known_code(), Some(ReasonCode::Allowed));
        assert_eq!(
            d.obligations,
            vec![Obligation::Label {
                value: Label::INTERNAL
            }]
        );
        let r: Decision = serde_json::from_str(REMOTE_DECISION).unwrap();
        assert!(!r.is_allowed());
        assert_eq!(r.reason.public_code(), ReasonCode::DelegationOverlap);
        assert_eq!(r.reason.detail(), Some("agent has read at project p-77"));
    }

    #[test]
    fn closed_sets_are_exact() {
        let base: Value = serde_json::from_str(REMOTE_DECISION).unwrap();
        for (k, bad) in [
            ("effect", json!("Allow")),
            ("effect", json!("permit")),
            ("effect", json!(true)),
            ("effect", json!(null)),
            ("level", json!("admin")),
            ("level", json!("None")),
            ("level", json!(2)),
            ("rev", json!(-1)),
            ("rev", json!(9_007_199_254_740_992u64)),
            ("rule_ids", json!([""])),
            ("rule_ids", json!(["has space"])),
            ("reason", json!("Allowed")),
            ("reason", json!("allowed:no space")),
            ("reason", json!("allowed: ")),
            ("reason", json!("allowed: line\nbreak")),
            ("reason", json!("")),
            ("obligations", json!([{ "value": "internal" }])),
            ("obligations", json!([{ "kind": 7 }])),
            ("obligations", json!([{ "kind": "label" }])),
            (
                "obligations",
                json!([{ "kind": "label", "value": "Internal" }]),
            ),
            (
                "obligations",
                json!([{ "kind": "restricted", "fields": ["Amount"] }]),
            ),
            (
                "obligations",
                json!([{ "kind": "audit", "on_behalf_of": "usr_x" }]),
            ),
            (
                "obligations",
                json!([{ "kind": "audit", "on_behalf_of": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102" }]),
            ),
        ] {
            let mut v = base.clone();
            v[k] = bad.clone();
            assert!(
                serde_json::from_value::<Decision>(v).is_err(),
                "{k} = {bad}"
            );
        }
        for k in [
            "effect",
            "level",
            "field_mask",
            "rule_ids",
            "reason",
            "rev",
            "obligations",
        ] {
            let mut v = base.clone();
            v.as_object_mut().unwrap().remove(k);
            assert!(
                serde_json::from_value::<Decision>(v).is_err(),
                "missing {k}"
            );
        }
        let mut v = base.clone();
        v["future_field"] = json!({"x": 1});
        assert!(serde_json::from_value::<Decision>(v).is_ok());
    }

    #[test]
    fn field_mask_rules() {
        let mut v: Value = serde_json::from_str(DOC_DECISION).unwrap();
        for (mask, err) in [
            (json!({"read": ["b", "a"], "write": []}), "sorted"),
            (json!({"read": ["a", "a"], "write": []}), "sorted"),
            (json!({"read": ["a", "b"], "write": ["b", "a"]}), "sorted"),
            (json!({"read": ["a"], "write": ["b"]}), "subset"),
            (json!({"read": ["amount", "@ai"], "write": []}), "sorted"),
            (json!({"read": ["a"]}), "missing"),
            (json!({"read": ["A"], "write": []}), "name"),
        ] {
            v["field_mask"] = mask.clone();
            assert!(
                serde_json::from_value::<Decision>(v.clone()).is_err(),
                "{err}: {mask}"
            );
        }
        let m = FieldMask::new([f("status"), f("@ai"), f("status")], [f("status")]).unwrap();
        assert_eq!(m.read(), [f("@ai"), f("status")]);
        assert_eq!(
            FieldMask::new([f("a")], [f("b")]),
            Err(FieldMaskError::WriteNotInRead)
        );
        assert!(FieldMask::empty().is_empty());
        assert_eq!(
            serde_json::to_value(FieldMask::empty()).unwrap(),
            json!({"read": [], "write": []})
        );
    }

    #[test]
    fn explicit_deserialize_calls_still_check() {
        // Regression: `Decision::deserialize(..)` and `FieldMask::deserialize(..)`
        // must be the checked trait functions, never an unchecked inherent one.
        let bad = r#"{"effect":"allow","level":"none","field_mask":{"read":["a"],"write":[]},"rule_ids":[],"reason":"allowed","rev":1,"obligations":[]}"#;
        let mut de = serde_json::Deserializer::from_str(bad);
        assert!(Decision::deserialize(&mut de).is_err());
        let mut de = serde_json::Deserializer::from_str(r#"{"read":["b","a"],"write":[]}"#);
        assert!(FieldMask::deserialize(&mut de).is_err());
    }

    #[test]
    fn level_none_needs_an_empty_mask() {
        let mut v: Value = serde_json::from_str(REMOTE_DECISION).unwrap();
        v["level"] = json!("none");
        assert!(serde_json::from_value::<Decision>(v.clone()).is_err());
        v["field_mask"] = json!({"read": [], "write": []});
        let d: Decision = serde_json::from_value(v).unwrap();
        assert_eq!(d.check(), Ok(()));
        let mut bad = d.clone();
        bad.field_mask = FieldMask::new([f("status")], []).unwrap();
        assert_eq!(bad.check(), Err(DecisionError::MaskNotEmptyAtNone));
        assert!(
            serde_json::to_value(&bad).is_err(),
            "writers never emit an invalid decision"
        );
        let mut big = d;
        big.rev = crate::encoding::MAX_JSON_INT + 1;
        assert_eq!(big.check(), Err(DecisionError::RevTooLarge));
        assert!(serde_json::to_value(&big).is_err());
    }

    #[test]
    fn obligations() {
        let list = json!([
            { "kind": "audit", "on_behalf_of": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081", "reason_required": true },
            { "kind": "audit" },
            { "kind": "audit", "reason_required": null },
            { "kind": "label", "value": "confidential" },
            { "kind": "restricted", "fields": ["amount", "@files"] },
            { "kind": "recheck_online" }
        ]);
        let parsed: Vec<Obligation> = serde_json::from_value(list).unwrap();
        assert!(matches!(
            &parsed[0],
            Obligation::Audit {
                on_behalf_of: Some(_),
                reason_required: true
            }
        ));
        assert!(matches!(
            &parsed[1],
            Obligation::Audit {
                on_behalf_of: None,
                reason_required: false
            }
        ));
        assert!(matches!(
            &parsed[2],
            Obligation::Audit {
                on_behalf_of: None,
                reason_required: false
            }
        ));
        assert_eq!(
            parsed[3],
            Obligation::Label {
                value: Label::CONFIDENTIAL
            }
        );
        assert_eq!(parsed[4].kind(), "restricted");
        assert_eq!(parsed[5], Obligation::RecheckOnline);
        assert!(parsed.iter().all(Obligation::is_known));
        let back = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            back[0],
            json!({ "kind": "audit", "on_behalf_of": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081", "reason_required": true })
        );
        assert_eq!(
            back[1],
            json!({ "kind": "audit", "reason_required": false })
        );
        assert_eq!(back[5], json!({ "kind": "recheck_online" }));
        let again: Vec<Obligation> = serde_json::from_value(back).unwrap();
        assert_eq!(again, parsed);
    }

    #[test]
    fn unknown_obligation_means_deny() {
        let mut v: Value = serde_json::from_str(DOC_DECISION).unwrap();
        v["obligations"] = json!([{ "kind": "watermark", "text": "x" }]);
        let d: Decision = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(d.effect, Effect::Allow);
        assert!(!d.is_allowed());
        let Obligation::Unknown(u) = &d.obligations[0] else {
            panic!("expected an unknown obligation");
        };
        assert_eq!(u.kind(), "watermark");
        assert_eq!(u.object().get("text"), Some(&json!("x")));
        // Unknown obligations are passed on unchanged.
        assert_eq!(serde_json::to_value(&d).unwrap(), v);
    }

    #[test]
    fn reasons() {
        let r = Reason::new(ReasonCode::NoRole);
        assert_eq!(r.as_str(), "no_role");
        assert_eq!(r.detail(), None);
        assert_eq!(r.public_code(), ReasonCode::NotAllowed);
        let r = Reason::with_detail(ReasonCode::BreakGlass, "incident 42: payroll check").unwrap();
        assert_eq!(r.code(), "break_glass");
        assert_eq!(r.detail(), Some("incident 42: payroll check"));
        assert_eq!(r.public_code(), ReasonCode::NotAllowed);
        let unknown = Reason::parse("quota_exceeded: try later").unwrap();
        assert_eq!(unknown.known_code(), None);
        assert_eq!(unknown.public_code(), ReasonCode::NotAllowed);
        let shown: Vec<_> = ReasonCode::ALL
            .iter()
            .copied()
            .filter(|c| c.is_safe_to_show())
            .collect();
        assert_eq!(shown.len(), 7);
        assert_eq!(ReasonCode::ALL.len(), 13);
        for &code in ReasonCode::ALL {
            assert_eq!(ReasonCode::from_code(code.as_str()), Some(code));
            assert_eq!(Reason::new(code).known_code(), Some(code));
        }
        // Non-ASCII detail is allowed; the limit counts characters.
        let max = format!("allowed: {}", "\u{d55c}".repeat(512 - 9));
        assert_eq!(max.chars().count(), 512);
        assert!(Reason::parse(&max).is_ok());
        let over = format!("{max}x");
        assert_eq!(Reason::parse(&over), Err(ReasonError::TooLong));
        assert_eq!(Reason::parse("allowed:x"), Err(ReasonError::Separator));
        assert_eq!(Reason::parse("allowed: "), Err(ReasonError::EmptyDetail));
        assert_eq!(Reason::parse("allowed: a\tb"), Err(ReasonError::DetailChar));
        // Unicode line breaks are line breaks too (CONTRACTS.md 6.1).
        for c in ['\u{2028}', '\u{2029}', '\u{85}', '\u{7f}', '\r'] {
            assert_eq!(
                Reason::parse(&format!("allowed: a{c}b")),
                Err(ReasonError::DetailChar),
                "{c:?}"
            );
        }
        assert_eq!(
            Reason::parse("Allowed"),
            Err(ReasonError::Code(NameError::Start))
        );
        assert_eq!(
            Reason::parse(": x"),
            Err(ReasonError::Code(NameError::Empty))
        );
        assert_eq!(
            Reason::parse("allowed : x"),
            Err(ReasonError::Code(NameError::Char))
        );
    }

    #[test]
    fn rule_ids() {
        assert!(RuleId::parse(&"r".repeat(128)).is_ok());
        assert_eq!(RuleId::parse(&"r".repeat(129)), Err(RuleIdError));
        assert_eq!(RuleId::parse(""), Err(RuleIdError));
        assert_eq!(RuleId::parse("a b"), Err(RuleIdError));
    }

    fn name() -> impl Strategy<Value = FieldName> {
        ("@?", "[a-z][a-z0-9]{0,6}").prop_map(|(at, n)| f(&format!("{at}{n}")))
    }

    proptest! {
        #[test]
        fn mask_round_trip(read in prop::collection::vec(name(), 0..8), pick in prop::collection::vec(any::<bool>(), 8)) {
            let write: Vec<FieldName> = read.iter().zip(&pick).filter(|(_, p)| **p).map(|(n, _)| n.clone()).collect();
            let mask = FieldMask::new(read, write).unwrap();
            prop_assert!(mask.check().is_ok());
            let json = serde_json::to_string(&mask).unwrap();
            prop_assert_eq!(serde_json::from_str::<FieldMask>(&json).unwrap(), mask);
        }

        #[test]
        fn intersection_narrows(a in prop::collection::vec(name(), 0..8), b in prop::collection::vec(name(), 0..8)) {
            let ma = FieldMask::new(a.clone(), a).unwrap();
            let mb = FieldMask::new(b.clone(), Vec::new()).unwrap();
            let both = ma.intersection(&mb);
            prop_assert!(both.check().is_ok());
            prop_assert!(both.read().iter().all(|n| ma.can_read(n) && mb.can_read(n)));
            prop_assert!(both.write().is_empty());
            let (ab, ba) = (ma.intersection(&mb), mb.intersection(&ma));
            prop_assert_eq!(ab.read(), ba.read());
        }

        #[test]
        fn reason_round_trip(detail in "[ -~]{1,100}") {
            let r = Reason::with_detail(ReasonCode::LevelTooLow, &detail).unwrap();
            prop_assert_eq!(r.code(), "level_too_low");
            prop_assert_eq!(r.detail(), Some(detail.as_str()));
            prop_assert_eq!(r.to_string().parse::<Reason>(), Ok(r));
        }
    }
}
