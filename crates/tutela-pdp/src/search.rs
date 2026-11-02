//! Search: "which resources may this subject act on?" and "who may do this
//! action on this resource?" (CONTRACTS.md 7.4).
//!
//! Tutela never stores a product's records, so a search names only what it
//! knows: registered scopes, and the principals of the tenant's assignments
//! and groups. Both searches decide with the same rules as `check`:
//!
//! - A resource comes from [`ListFilter`], which `check` is proved equal to,
//!   read for one known resource. Tutela does not hold a resource's field
//!   values, so a condition on a field has no answer here. Such a resource
//!   is not listed; the filter still covers it in the product's own SQL. A
//!   resource is listed only when it passes **whatever** its field values
//!   are.
//! - A subject is asked for with `check` itself, on the resource the caller
//!   sent. Only principals with an assignment on the path can pass, so only
//!   they are asked. The walk in `check` decides.
//!
//! A page is bounded twice: by the caller's limit, and by
//! [`MAX_SEARCH_SCAN`] candidates looked at, so one call costs a bounded
//! amount whatever the answer is. A page cut short still has a cursor, so
//! nothing is lost; it never silently ends a list early.

use std::collections::{BTreeSet, HashSet};
use std::ops::Bound;

use tutela_contracts::keys::{ActionKey, ResourceId};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::TenantKey;

use crate::api::{
    CheckRequest, ListFilterRequest, MAX_PATH, PathEntry, PdpError, ResourceRef, ScopePathError,
    ScopePathProblem, ScopePaths,
};
use crate::eval::action_kind;
use crate::filter::{FilterExpr, ListFilter};
use crate::pdp::{Pdp, check_attrs, this_entry};

/// The most results in one page of a search.
pub const MAX_SEARCH_PAGE: usize = 1_000;

/// The most candidates one page of a search looks at.
pub const MAX_SEARCH_SCAN: usize = 10_000;

/// One page of a resource search.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResourcePage {
    /// The filter, for the product's own SQL.
    pub filter: ListFilter,
    /// The known resources that pass, sorted by type and id.
    pub results: Vec<PathEntry>,
    /// Where the next page starts. `None`: this is the last page.
    pub next: Option<PathEntry>,
}

/// "Who may do this action on this resource?"
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SubjectSearchRequest {
    /// The tenant, from the verified token.
    pub tenant: TenantKey,
    /// The kind of principal to list.
    pub kind: PrincipalKind,
    /// The action.
    pub action: ActionKey,
    /// The resource, as for `check`.
    pub resource: ResourceRef,
    /// Sent by callers after their own writes.
    pub at_least_revision: Option<u64>,
}

/// One page of a subject search.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SubjectPage {
    /// The tenant revision that was used.
    pub rev: u64,
    /// The principals `check` allows, sorted.
    pub results: Vec<Principal>,
    /// Where the next page starts. `None`: this is the last page.
    pub next: Option<Principal>,
}

/// A truth value with "cannot tell", for a filter read without field values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tri {
    True,
    False,
    Unknown,
}

impl Tri {
    const fn of(b: bool) -> Self {
        if b { Self::True } else { Self::False }
    }

    const fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    /// The false of `self` and `other`, else unknown, else true.
    const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    const fn or(self, other: Self) -> Self {
        self.not().and(other.not()).not()
    }
}

/// A condition with its id and scope lists hashed: it runs once per
/// candidate, and a list can hold thousands of entries.
enum Test<'a> {
    Constant(Tri),
    All(Vec<Test<'a>>),
    Any(Vec<Test<'a>>),
    Not(Box<Test<'a>>),
    IdIn(HashSet<&'a ResourceId>),
    Under(HashSet<&'a PathEntry>),
}

impl<'a> Test<'a> {
    fn of(e: &'a FilterExpr) -> Self {
        match e {
            FilterExpr::True => Self::Constant(Tri::True),
            FilterExpr::False => Self::Constant(Tri::False),
            FilterExpr::And { args } => Self::All(args.iter().map(Self::of).collect()),
            FilterExpr::Or { args } => Self::Any(args.iter().map(Self::of).collect()),
            FilterExpr::Not { arg } => Self::Not(Box::new(Self::of(arg))),
            FilterExpr::IdIn { ids } => Self::IdIn(ids.iter().collect()),
            FilterExpr::Under { scopes } => Self::Under(scopes.iter().collect()),
            // A field value Tutela does not hold.
            FilterExpr::Eq { .. }
            | FilterExpr::Ne { .. }
            | FilterExpr::In { .. }
            | FilterExpr::Contains { .. }
            | FilterExpr::IsNull { .. } => Self::Constant(Tri::Unknown),
        }
    }

    fn run(&self, id: &ResourceId, path: &[PathEntry]) -> Tri {
        match self {
            Self::Constant(t) => *t,
            Self::All(args) => args.iter().fold(Tri::True, |t, a| t.and(a.run(id, path))),
            Self::Any(args) => args.iter().fold(Tri::False, |t, a| t.or(a.run(id, path))),
            Self::Not(arg) => arg.run(id, path).not(),
            Self::IdIn(ids) => Tri::of(ids.contains(id)),
            Self::Under(scopes) => Tri::of(path.iter().any(|a| scopes.contains(a))),
        }
    }
}

pub(crate) fn path_error(scope: &PathEntry, e: ScopePathError) -> PdpError {
    PdpError::ScopePath {
        scope: scope.clone(),
        problem: match e {
            ScopePathError::NotFound => ScopePathProblem::NotFound,
            _ => ScopePathProblem::Unavailable,
        },
    }
}

impl Pdp {
    /// The known resources of the action's type that `subject` may act on,
    /// whatever their field values, and the filter for all the others.
    ///
    /// `after` is the `next` of the page before. `limit` is lowered to
    /// [`MAX_SEARCH_PAGE`].
    ///
    /// # Errors
    ///
    /// As [`Pdp::list_filter`]. Also [`PdpError::ScopePath`] for a scope the
    /// filter names and the provider cannot place, and
    /// [`PdpError::InvalidInput`] for a provider that cannot say what is
    /// below a scope. The caller fails closed: no partial list.
    pub fn search_resources<P: ScopePaths + ?Sized>(
        &self,
        req: &ListFilterRequest,
        paths: &P,
        after: Option<&PathEntry>,
        limit: usize,
    ) -> Result<ResourcePage, PdpError> {
        let filter = self.list_filter(req, paths)?;
        let mut candidates: BTreeSet<PathEntry> = BTreeSet::new();
        if let Some(first) = filter.container_in.first() {
            let below = paths
                .below(&req.tenant, &filter.container_in)
                .ok_or_else(|| PdpError::invalid("this provider cannot list scopes"))?
                .map_err(|e| path_error(first, e))?;
            candidates.extend(
                below
                    .into_iter()
                    .filter(|s| s.type_name == filter.type_name),
            );
        }
        candidates.extend(
            filter
                .ids_in
                .iter()
                .map(|id| PathEntry::new(filter.type_name.clone(), id.clone())),
        );

        // Every candidate is in `ids_in` or below a scope of `container_in`,
        // so only the row's bound and the condition are left to test.
        let condition = filter.condition.as_ref().map(Test::of);
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let limit = limit.clamp(1, MAX_SEARCH_PAGE);

        let mut results = Vec::new();
        let mut next = None;
        let mut last = after;
        for (scanned, scope) in candidates.range((start, Bound::Unbounded)).enumerate() {
            if results.len() == limit || scanned == MAX_SEARCH_SCAN {
                next = last.cloned();
                break;
            }
            last = Some(scope);
            let path = paths
                .ancestors(&req.tenant, scope)
                .map_err(|e| path_error(scope, e))?;
            let passes = path.len() <= MAX_PATH
                && condition
                    .as_ref()
                    .is_none_or(|c| c.run(&scope.id, &path) == Tri::True);
            if passes {
                results.push(scope.clone());
            }
        }
        Ok(ResourcePage {
            filter,
            results,
            next,
        })
    }

    /// The principals of `kind` that `check` allows on this resource.
    ///
    /// `after` is the `next` of the page before. `limit` is lowered to
    /// [`MAX_SEARCH_PAGE`].
    ///
    /// # Errors
    ///
    /// As [`Pdp::check`]. Never a partial list.
    pub fn search_subjects(
        &self,
        req: &SubjectSearchRequest,
        after: Option<&Principal>,
        limit: usize,
    ) -> Result<SubjectPage, PdpError> {
        let b = self.bundle(&req.tenant, req.at_least_revision)?;
        if req.action.resource_type() != &req.resource.type_name {
            return Err(PdpError::invalid(
                "the action's type is not the resource's type",
            ));
        }
        action_kind(&b.model, &req.action)?;
        let this = this_entry(&req.resource)?;
        check_attrs(&b.model, &req.resource.type_name, &req.resource.attrs, true)?;

        // No assignment on the path means default deny, so these are all
        // the principals `check` could allow.
        let mut candidates: BTreeSet<&Principal> = BTreeSet::new();
        let mut groups: BTreeSet<usize> = BTreeSet::new();
        for scope in core::iter::once(&this).chain(&req.resource.path) {
            if let Some(s) = b.index.scopes.get(scope) {
                candidates.extend(s.direct.keys().filter(|p| p.kind() == req.kind));
                groups.extend(s.groups.keys().copied());
            }
        }
        if !groups.is_empty() {
            candidates.extend(
                b.index
                    .member_of
                    .iter()
                    .filter(|(p, of)| p.kind() == req.kind && !of.is_disjoint(&groups))
                    .map(|(p, _)| p),
            );
        }

        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let limit = limit.clamp(1, MAX_SEARCH_PAGE);
        let mut results: Vec<Principal> = Vec::new();
        let mut next = None;
        let mut last = after;
        let range = candidates.range::<Principal, _>((start, Bound::Unbounded));
        for (scanned, &p) in range.enumerate() {
            if results.len() == limit || scanned == MAX_SEARCH_SCAN {
                next = last.cloned();
                break;
            }
            last = Some(p);
            let decision = self.check(&CheckRequest {
                tenant: req.tenant.clone(),
                subject: p.clone(),
                actors: Vec::new(),
                action: req.action.clone(),
                resource: req.resource.clone(),
                fields: Some(Vec::new()),
                at_least_revision: req.at_least_revision,
            })?;
            if decision.is_allowed() {
                results.push(p.clone());
            }
        }
        Ok(SubjectPage {
            rev: b.rev,
            results,
            next,
        })
    }
}
