//! Requests, answers and errors of the evaluator (CONTRACTS.md 6.5 to 6.8).

use core::fmt;
use std::collections::BTreeMap;

use serde::Serialize;
use tutela_contracts::decision::{Effect, Reason, RuleId};
use tutela_contracts::keys::{ActionKey, FieldName, KeyError, ResourceId, ResourceType};
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{OrgId, TenantKey};

/// The longest path: at most 32 ancestors (CONTRACTS.md 6.5, ADR-0011).
pub const MAX_PATH: usize = 32;

/// The longest `act` chain of a delegated token (CONTRACTS.md 4.5).
pub const MAX_ACTORS: usize = 4;

/// The most requests in one `batch` (CONTRACTS.md 6.5).
pub const MAX_BATCH: usize = 1_000;

/// The most entries in `fields`, `attrs` or `new_attrs` of one request. A
/// type has at most 256 fields and features (MANIFEST.md 11).
pub const MAX_FIELDS: usize = 512;

/// One node of a resource tree: a type and the product's own id
/// (CONTRACTS.md 6.5). In JSON: `{"type": "matter", "id": "m-12"}`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize)]
pub struct PathEntry {
    /// The type. `org` for the root of the tree.
    #[serde(rename = "type")]
    pub type_name: ResourceType,
    /// The product's own id; for an org, the org id.
    pub id: ResourceId,
}

impl PathEntry {
    /// Makes a path entry.
    #[must_use]
    pub const fn new(type_name: ResourceType, id: ResourceId) -> Self {
        Self { type_name, id }
    }

    /// The entry of an org: the root of its tree.
    ///
    /// # Errors
    ///
    /// Never in practice: an org id is 40 visible ASCII characters, so it is
    /// a valid resource id. The error is the resource id check.
    pub fn org(org: &OrgId) -> Result<Self, KeyError> {
        Ok(Self {
            type_name: ResourceType::ORG,
            id: ResourceId::parse(&org.to_string())?,
        })
    }

    /// `true` for an `org` entry.
    #[must_use]
    pub fn is_org(&self) -> bool {
        self.type_name == ResourceType::ORG
    }

    /// The org id of an `org` entry, if the id is one.
    #[must_use]
    pub fn org_id(&self) -> Option<OrgId> {
        if self.is_org() {
            self.id.as_str().parse().ok()
        } else {
            None
        }
    }
}

impl fmt::Display for PathEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.type_name, self.id)
    }
}

/// A field value that conditions read (CONTRACTS.md 6.5): a string, an
/// integer, a boolean, `null` or an array of strings. A missing field is
/// `null`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AttrValue {
    /// `null`.
    Null,
    /// A string. A principal field holds a principal string.
    String(String),
    /// A 64-bit integer.
    Integer(i64),
    /// A boolean.
    Boolean(bool),
    /// An array of strings.
    Strings(Vec<String>),
}

/// The field values of one resource, by field name.
pub type Attrs = BTreeMap<FieldName, AttrValue>;

/// The resource a request is about (CONTRACTS.md 6.5).
///
/// `path` and `attrs` are loaded **server-side by id** from the product's
/// database. They never come from the request body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResourceRef {
    /// The type.
    pub type_name: ResourceType,
    /// The product's own id.
    pub id: ResourceId,
    /// Every ancestor, nearest first; the last entry is the org. Empty only
    /// when the resource is an org itself. At most [`MAX_PATH`] entries.
    pub path: Vec<PathEntry>,
    /// The field values that conditions read.
    pub attrs: Attrs,
}

/// One check: may this principal do this action on this resource?
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CheckRequest {
    /// The tenant, from the verified token: (iss, tid).
    pub tenant: TenantKey,
    /// The token's `sub`.
    pub subject: Principal,
    /// The token's `act` chain, current actor first. Empty: no delegation.
    pub actors: Vec<Principal>,
    /// The action, for example `invoice:approve`. Its type is the resource's
    /// type.
    pub action: ActionKey,
    /// The resource.
    pub resource: ResourceRef,
    /// Limits the field mask to these fields and features.
    pub fields: Option<Vec<FieldName>>,
    /// Sent by callers after their own writes.
    pub at_least_revision: Option<u64>,
}

/// A request for a list filter (CONTRACTS.md 6.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ListFilterRequest {
    /// The tenant, from the verified token.
    pub tenant: TenantKey,
    /// The token's `sub`.
    pub subject: Principal,
    /// The token's `act` chain, current actor first.
    pub actors: Vec<Principal>,
    /// Usually `<type>:read`. The type to list comes from here.
    pub action: ActionKey,
    /// Sent by callers after their own writes.
    pub at_least_revision: Option<u64>,
}

/// A request for per-field write verdicts (CONTRACTS.md 6.7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WriteCheckRequest {
    /// The tenant, from the verified token.
    pub tenant: TenantKey,
    /// The token's `sub`.
    pub subject: Principal,
    /// The token's `act` chain, current actor first.
    pub actors: Vec<Principal>,
    /// The stored item, before the write.
    pub resource: ResourceRef,
    /// The changed fields only, with their new values. At least one.
    pub new_attrs: Attrs,
    /// `Some` when the write moves the item to a new parent. Moves are
    /// refused until boundary rules exist (ROADMAP Phase A item 5).
    pub new_path: Option<Vec<PathEntry>>,
    /// Sent by callers after their own writes.
    pub at_least_revision: Option<u64>,
}

/// The answer of `write_check` (CONTRACTS.md 6.7).
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WriteDecision {
    /// Allow only if every changed field is allowed.
    pub effect: Effect,
    /// The tenant revision that was used.
    pub rev: u64,
    /// One verdict per changed field, sorted by field name.
    pub fields: Vec<FieldVerdict>,
}

/// The verdict for one changed field.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct FieldVerdict {
    /// The field.
    pub field: FieldName,
    /// Allow or deny.
    pub effect: Effect,
    /// `<type>:write`, or `<type>:manage_access` for a `grants_access` field.
    pub needs: ActionKey,
    /// Same format as `Decision.reason`.
    pub reason: Reason,
    /// The stored rules that decided.
    pub rule_ids: Vec<RuleId>,
}

/// What `list_filter` found wrong with the path of a scope (ADR-0011 F1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ScopePathProblem {
    /// The provider does not know the scope.
    NotFound,
    /// The provider could not answer.
    Unavailable,
    /// The path is longer than [`MAX_PATH`].
    TooLong,
    /// The path does not end at an org of this tenant.
    WrongTenant,
    /// The path is empty, has an `org` entry before its end, holds the
    /// scope itself, or holds one entry twice.
    Malformed,
    /// Two placed paths disagree: a scope on one path has another path of
    /// its own (this includes a cycle).
    Inconsistent,
}

impl ScopePathProblem {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "the scope-path provider does not know the scope",
            Self::Unavailable => "the scope-path provider could not answer",
            Self::TooLong => "the path is longer than 32 entries",
            Self::WrongTenant => "the path does not end at an org of this tenant",
            Self::Malformed => {
                "the path is empty, has an org before its end, holds the scope itself or repeats an entry"
            }
            Self::Inconsistent => "the paths of two scopes disagree",
        }
    }
}

impl fmt::Display for ScopePathProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error of the evaluator (CONTRACTS.md 6.8). An error is **never** an
/// allow: the caller fails closed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PdpError {
    /// The loaded revision is below `at_least_revision`.
    #[error("the loaded revision {have_rev} is below the needed revision {need_rev}")]
    StaleBundle {
        /// The loaded revision.
        have_rev: u64,
        /// The needed revision.
        need_rev: u64,
    },
    /// The bundle is older than its max age. Phase B (signed bundles); never
    /// returned in Phase A.
    #[error("the bundle has expired")]
    ExpiredBundle,
    /// No model is loaded for this tenant.
    #[error("no model is loaded for this tenant")]
    NoBundle,
    /// The bundle needs a newer PDP. Phase B; never returned in Phase A.
    #[error("the bundle needs a newer PDP")]
    UnsupportedBundle,
    /// The model does not declare this type.
    #[error("unknown resource type `{0}`")]
    UnknownType(ResourceType),
    /// The type has no such action.
    #[error("unknown action `{0}`")]
    UnknownAction(ActionKey),
    /// A path has more than [`MAX_PATH`] entries.
    #[error("a path has more than 32 entries")]
    PathTooLong,
    /// The request breaks a rule. In a batch, `index` names the request.
    #[error("invalid input{}: {detail}", index.map(|i| format!(" (request {i})")).unwrap_or_default())]
    InvalidInput {
        /// The request in a batch.
        index: Option<usize>,
        /// What is wrong, in short English. No field values.
        detail: String,
    },
    /// `list_filter` could not place a scope it needs (ADR-0011 F1). The
    /// list fails closed: no rows.
    #[error("the path of scope {scope} cannot be used: {problem}")]
    ScopePath {
        /// The scope.
        scope: PathEntry,
        /// What went wrong.
        problem: ScopePathProblem,
    },
    /// The list filter would pass a limit of CONTRACTS.md 6.6. The list fails
    /// closed: no rows.
    #[error("the list filter would pass the limit on {0}")]
    FilterTooLarge(&'static str),
}

impl PdpError {
    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        Self::InvalidInput {
            index: None,
            detail: detail.into(),
        }
    }
}

/// What a scope-path provider can answer instead of a path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ScopePathError {
    /// The provider has no scope with this (tenant, type, id).
    NotFound,
    /// The provider could not answer (for example, the database is down).
    Unavailable,
}

/// Where `list_filter` gets the paths of the scopes it must place
/// (ADR-0011 F1).
///
/// Tutela does not store the product's tree. To build a filter, the
/// evaluator must know how the deciding scopes nest: the scopes where the
/// principal has an assignment, and the private scopes inside them. It asks
/// this provider for their paths.
///
/// Rules for an implementation:
/// - The answer is keyed by **(tenant, type, id)**: never answer with a scope
///   of another tenant, also when ids are the same across tenants.
/// - Return the ancestors **nearest first**, not the scope itself. The last
///   entry is the tenant's own org. At most [`MAX_PATH`] entries.
/// - Return an error for an unknown scope. Never answer "no ancestors".
/// - The path must be current: a stale path makes `list_filter` and `check`
///   disagree. A cache of paths needs a test that a move changes list results
///   at once.
///
/// `list_filter` turns every error, and every path that breaks a rule, into
/// [`PdpError::ScopePath`]: the list fails closed.
pub trait ScopePaths {
    /// The ancestors of `scope` in `tenant`, nearest first; the last entry is
    /// the org.
    ///
    /// # Errors
    ///
    /// [`ScopePathError::NotFound`] for an unknown scope,
    /// [`ScopePathError::Unavailable`] when the provider cannot answer.
    fn ancestors(
        &self,
        tenant: &TenantKey,
        scope: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError>;
}

impl<T: ScopePaths + ?Sized> ScopePaths for &T {
    fn ancestors(
        &self,
        tenant: &TenantKey,
        scope: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError> {
        (**self).ancestors(tenant, scope)
    }
}
