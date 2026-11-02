//! Tutela's embedded decision engine (`tutela-pdp`).
//!
//! Phase A. Two parts:
//!
//! - the model language and its compiler ([`model`]). It reads a product's
//!   `tutela.resources.toml` ([`docs/MANIFEST.md`]), checks it, and returns a
//!   compiled [`model::Model`] or every problem it found. It also compares
//!   two models and classifies each change as narrowing, neutral or
//!   widening;
//! - the evaluator [`Pdp`]: [`Pdp::check`], [`Pdp::batch`],
//!   [`Pdp::list_filter`] and [`Pdp::write_check`] ([`docs/CONTRACTS.md`]
//!   section 6, [`docs/PERMISSION-MODEL.md`] section 7). It reads a compiled
//!   model and the tenant's [`TenantData`] (role assignments, groups, private
//!   scopes, field rules at one scope), and evaluates delegation as person
//!   AND agent. `list_filter` comes from the same code as `check`, and
//!   [`Pdp::search_resources`] and [`Pdp::search_subjects`] from those two.
//!
//! An error is never an allow: callers fail closed.
//!
//! [`docs/MANIFEST.md`]: https://github.com/f8fvwgzc/tutela/blob/main/docs/MANIFEST.md
//! [`docs/CONTRACTS.md`]: https://github.com/f8fvwgzc/tutela/blob/main/docs/CONTRACTS.md
//! [`docs/PERMISSION-MODEL.md`]: https://github.com/f8fvwgzc/tutela/blob/main/docs/PERMISSION-MODEL.md

mod api;
mod data;
mod eval;
mod explain;
mod filter;
mod grant;
mod impact;
pub mod model;
mod moves;
mod pdp;
mod search;

#[cfg(test)]
mod testgen;
#[cfg(test)]
mod testref;
#[cfg(test)]
mod tests_check;
#[cfg(test)]
mod tests_explain;
#[cfg(test)]
mod tests_filter;
#[cfg(test)]
mod tests_grant;
#[cfg(test)]
mod tests_impact;
#[cfg(test)]
mod tests_moves;
#[cfg(test)]
mod tests_props;
#[cfg(test)]
mod tests_search;

pub use api::{
    AttrValue, Attrs, CheckRequest, FieldVerdict, LinkVerdict, ListFilterRequest, MAX_ACTORS,
    MAX_APPROVERS, MAX_BATCH, MAX_FIELDS, MAX_LINKS, MAX_PATH, MoveDecision, MoveOutcome,
    PathEntry, PdpError, ResourceRef, ScopePathError, ScopePathProblem, ScopePaths,
    WriteCheckRequest, WriteDecision,
};
pub use data::{
    Binding, BoundaryRule, Group, LinksFrom, LoadError, MAX_GROUP_CLOSURE, MAX_GROUP_DEPTH,
    MAX_GROUP_WORK, Member, MoveRule, OnLooser, ScopeFieldRule, Subject, TenantData,
};
pub use explain::{Explanation, RuleExplained, SideExplained, StepExplained};
pub use filter::{
    FilterExpr, FilterSize, FilterValue, ListFilter, MAX_CONTAINER_IN, MAX_FILTER_DEPTH,
    MAX_FILTER_ENTRIES, MAX_FILTER_NODES, MAX_IDS_IN,
};
pub use grant::grant_excess;
pub use impact::{Change, ImpactLine, ImpactReport, MAX_IMPACT_WORK, model_impact};
pub use moves::{MAX_MOVE_CANDIDATES, MAX_MOVE_LINES, MAX_MOVE_WORK};
pub use pdp::Pdp;
pub use search::{
    MAX_SEARCH_PAGE, MAX_SEARCH_SCAN, ResourcePage, SubjectPage, SubjectSearchRequest,
};
