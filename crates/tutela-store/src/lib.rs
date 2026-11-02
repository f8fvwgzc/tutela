//! Tutela's permission tables in Postgres (`tutela-store`), Phase A.
//!
//! The schema `tutela` holds a tenant's role assignments, groups, field
//! rules at one scope, boundary settings (the private flag), scope paths and
//! model revisions ([`docs/PERMISSION-MODEL.md`] section 18, ADR-0014). In
//! library mode it lives in the product's own database; `tutelad` uses the
//! same schema (Phase B). Tutela never stores app records: resources are
//! referenced only by type and id.
//!
//! Every function takes the product's own [`Transaction`], so a change to
//! Tutela's tables commits or rolls back with the product's change (for
//! example a move and its new scope path). In that transaction each function:
//!
//! 1. checks the tenant key and sets `tutela.tenant_id` with
//!    `set_config(..., true)` (the same as `SET LOCAL`), as [`enter`] does;
//!    every tenant table has `FORCE ROW LEVEL SECURITY`, so no other
//!    tenant's row is read or written;
//! 2. for a write, bumps the tenant revision first (this locks the
//!    tenant's revision row, so writes to one tenant are serialized), then
//!    makes the change;
//! 3. checks the whole tenant data with the evaluator's own load checks
//!    ([`tutela_pdp::Pdp::load`]): unknown or duplicate groups, group
//!    cycles, groups nested more than 32 deep, closure limits, two
//!    assignments for one (subject, scope). A change that breaks one is an
//!    error, and the caller rolls back.
//!
//! [`load`] reads a tenant's revision, [`TenantData`] and scope paths in one
//! consistent view.
//!
//! [`docs/PERMISSION-MODEL.md`]: https://github.com/f8fvwgzc/tutela/blob/main/docs/PERMISSION-MODEL.md

pub mod approval;
mod approvers;
pub mod audit;
mod bindings;
mod connect;
pub mod events;
mod isolation;
mod load;
mod manifest;
mod migrate;
mod models;
mod principals;
mod proposals;
pub mod signing_keys;
pub mod webhooks;
mod write;

#[cfg(test)]
mod tests_pg;

use std::sync::{Arc, OnceLock};

use tokio_postgres::Transaction;
use tutela_contracts::id::Uuid7;
use tutela_contracts::tenant::{OrgId, TenantId, TenantKey};
use tutela_pdp::model::Model;
use tutela_pdp::{LoadError, PathEntry, Pdp, TenantData};

pub use approvers::{Approver, add_approver, approver, approver_id, approvers, revoke_approver};
pub use audit::{
    AuditEntry, BrokenLink, ChainProblem, ChainReport, append_audit, append_deployment_audit,
    audit_records, deployment_audit_records, verify_audit_chain, verify_deployment_audit_chain,
};
pub use bindings::{
    Assignment, AssignmentQuery, GroupInfo, MAX_PAGE, ancestors, assignment, assignments,
    assignments_for, group_members, groups, groups_of, members_of, scopes_below, tenants,
};
pub use connect::{Transport, database_config};
pub use events::{
    Cursor, MAX_EVENT_PAGE, OutboxEvent, StoredEvent, emit, event_cursor, events_after, events_now,
    prune_events,
};
pub use isolation::{check_isolation, grant_service};
pub use load::{ScopePathSnapshot, TenantBundle, load, rev};
pub use manifest::{Publish, StoredManifest, applied_manifest, digest, manifest, publish_manifest};
pub use migrate::{applied as applied_migration, latest as latest_migration, migrate};
pub use models::{
    ActiveModel, MAX_VERSION_PAGE, ModelVersion, TenantPublish, active_model, model_version,
    model_versions, publish_tenant_model,
};
pub use principals::{
    MAX_AGENT_PAGE, PrincipalState, Revocations, agent_for_workload, agents, is_attache_path,
    note_exchange, principal_state, provision_user, register_agent, revocations, revoke_sessions,
    set_disabled,
};
pub use proposals::{
    MAX_PROPOSAL_PAGE, NewProposal, Proposal, TwoPerson, close_proposal, proposal, proposals,
    propose, publish_proposal, set_two_person, two_person,
};
pub use signing_keys::{
    KeySet, KeyTimes, Rotation, StoredKey, deny_signing_key, ensure_signing_key,
    rewrap_signing_keys, rotate_signing_key, signing_keys,
};
pub use tokio_postgres;
pub use write::{
    Expired, add_member, add_org, assign, assign_until, create_group, create_tenant,
    delete_field_rule, delete_group, delete_scope, expire_assignments, move_scope, put_field_rule,
    put_scope, remove_member, remove_principal, set_assignment_expiry, set_boundary, set_private,
    unassign,
};

/// What kind of failure a [`StoreError`] is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum StoreErrorKind {
    /// The database refused or failed the statement.
    /// [`StoreError::sqlstate`] gives the code.
    Database,
    /// The database has a migration this build does not know.
    SchemaTooNew,
    /// No tenant with this (iss, tid).
    UnknownTenant,
    /// The named row does not exist in this tenant.
    NotFound,
    /// The row already exists in this tenant.
    Exists,
    /// The input breaks a rule of the store (the text says which).
    Invalid,
    /// The change would break a rule of the tenant data; nothing may commit.
    /// [`StoreError::refusal`] gives the rule.
    Refused,
    /// A stored value does not parse. The table was changed outside the
    /// store.
    Corrupt,
    /// The revision is past the JSON integer range.
    RevOutOfRange,
    /// The role or the schema does not isolate tenants
    /// ([`check_isolation`]). The text says which rule failed.
    Isolation,
    /// This transaction already entered another tenant. A transaction
    /// belongs to one tenant, so a bug that passes the wrong key fails here.
    TenantMismatch,
    /// The tenant publishes only through an approved proposal (ADR-0029).
    TwoPerson,
}

/// Why a store call failed. A failed call leaves the caller's transaction in a
/// state it must roll back. Branch on [`StoreError::kind`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct StoreError(#[from] Repr);

#[derive(Debug, thiserror::Error)]
pub(crate) enum Repr {
    #[error("database error")]
    Db(#[source] tokio_postgres::Error),
    #[error("the database has migration {0}, which this build does not know")]
    SchemaTooNew(i32),
    #[error("unknown tenant")]
    UnknownTenant,
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("already exists: {0}")]
    Exists(&'static str),
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("the change is refused")]
    Refused(#[source] LoadError),
    #[error("stored data does not parse: {0}")]
    Corrupt(&'static str),
    #[error("the tenant revision is out of range")]
    RevOutOfRange,
    #[error("tenant isolation is not in force: {0}")]
    Isolation(&'static str),
    #[error("this transaction belongs to another tenant")]
    TenantMismatch,
    #[error("this tenant publishes only through an approved proposal")]
    TwoPerson,
}

impl StoreError {
    /// What kind of failure this is.
    #[must_use]
    pub const fn kind(&self) -> StoreErrorKind {
        match self.0 {
            Repr::Db(_) => StoreErrorKind::Database,
            Repr::SchemaTooNew(_) => StoreErrorKind::SchemaTooNew,
            Repr::UnknownTenant => StoreErrorKind::UnknownTenant,
            Repr::NotFound(_) => StoreErrorKind::NotFound,
            Repr::Exists(_) => StoreErrorKind::Exists,
            Repr::Invalid(_) => StoreErrorKind::Invalid,
            Repr::Refused(_) => StoreErrorKind::Refused,
            Repr::Corrupt(_) => StoreErrorKind::Corrupt,
            Repr::RevOutOfRange => StoreErrorKind::RevOutOfRange,
            Repr::Isolation(_) => StoreErrorKind::Isolation,
            Repr::TenantMismatch => StoreErrorKind::TenantMismatch,
            Repr::TwoPerson => StoreErrorKind::TwoPerson,
        }
    }

    /// The short text of a [`NotFound`](StoreErrorKind::NotFound),
    /// [`Exists`](StoreErrorKind::Exists),
    /// [`Invalid`](StoreErrorKind::Invalid),
    /// [`Corrupt`](StoreErrorKind::Corrupt) or
    /// [`Isolation`](StoreErrorKind::Isolation) error.
    #[must_use]
    pub const fn detail(&self) -> Option<&'static str> {
        match self.0 {
            Repr::NotFound(d)
            | Repr::Exists(d)
            | Repr::Invalid(d)
            | Repr::Corrupt(d)
            | Repr::Isolation(d) => Some(d),
            _ => None,
        }
    }

    /// The rule a [`Refused`](StoreErrorKind::Refused) change breaks.
    #[must_use]
    pub const fn refusal(&self) -> Option<&LoadError> {
        match &self.0 {
            Repr::Refused(e) => Some(e),
            _ => None,
        }
    }

    /// The Postgres SQLSTATE of a [`Database`](StoreErrorKind::Database)
    /// error, for example `42501` when row-level security refuses a row.
    /// `None` when the server sent no code (a lost connection).
    #[must_use]
    pub fn sqlstate(&self) -> Option<&str> {
        match &self.0 {
            Repr::Db(e) => e.code().map(tokio_postgres::error::SqlState::code),
            _ => None,
        }
    }

    const fn not_found(detail: &'static str) -> Self {
        Self(Repr::NotFound(detail))
    }

    const fn exists(detail: &'static str) -> Self {
        Self(Repr::Exists(detail))
    }

    const fn invalid(detail: &'static str) -> Self {
        Self(Repr::Invalid(detail))
    }

    const fn corrupt(detail: &'static str) -> Self {
        Self(Repr::Corrupt(detail))
    }

    const fn unknown_tenant() -> Self {
        Self(Repr::UnknownTenant)
    }

    const fn rev_out_of_range() -> Self {
        Self(Repr::RevOutOfRange)
    }

    const fn schema_too_new(version: i32) -> Self {
        Self(Repr::SchemaTooNew(version))
    }

    const fn isolation(detail: &'static str) -> Self {
        Self(Repr::Isolation(detail))
    }
}

impl From<LoadError> for StoreError {
    fn from(e: LoadError) -> Self {
        Self(Repr::Refused(e))
    }
}

/// `.db()?` turns a driver result into a store result. There is no public
/// `From<tokio_postgres::Error>`: it would put the driver's type in this
/// crate's API (#43).
trait DbResult<T> {
    fn db(self) -> Result<T, StoreError>;
}

impl<T> DbResult<T> for Result<T, tokio_postgres::Error> {
    fn db(self) -> Result<T, StoreError> {
        self.map_err(|e| StoreError(Repr::Db(e)))
    }
}

/// A new UUIDv7.
pub(crate) fn uuid7() -> Result<Uuid7, StoreError> {
    Uuid7::from_uuid(uuid::Uuid::now_v7()).map_err(|_| StoreError::corrupt("uuid"))
}

/// A new rule id: `<prefix>_<uuidv7>`.
fn new_rule_id(prefix: &str) -> Result<tutela_contracts::decision::RuleId, StoreError> {
    format!("{prefix}_{}", uuid7()?)
        .parse()
        .map_err(|_| StoreError::corrupt("rule id"))
}

/// Enters a tenant: checks the tenant key against the directory and sets
/// `tutela.tenant_id` for the rest of the transaction (`SET LOCAL`). Every
/// other call here does this first. A caller that runs its own statements
/// calls this at the start of the transaction.
///
/// A transaction belongs to one tenant. Entering a second one fails, so a
/// bug that passes the wrong key is an error and never a switch.
///
/// # Errors
///
/// [`UnknownTenant`](StoreErrorKind::UnknownTenant) for an unknown (iss,
/// tid), [`TenantMismatch`](StoreErrorKind::TenantMismatch) when this
/// transaction already entered another tenant, or a database error.
pub async fn enter(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<(), StoreError> {
    let tid = tenant.tid.to_string();
    let row = tx
        .query_opt(
            "SELECT current_setting('tutela.tenant_id', true) \
             FROM tutela.tenant WHERE tenant_id = $1 AND iss = $2",
            &[&tid, &tenant.iss.as_str()],
        )
        .await
        .db()?
        .ok_or(StoreError::unknown_tenant())?;
    let current: Option<&str> = row.try_get(0).db()?;
    match current.filter(|c| !c.is_empty()) {
        Some(c) if c == tid => Ok(()),
        Some(_) => Err(StoreError(Repr::TenantMismatch)),
        None => set_tenant(tx, &tenant.tid).await,
    }
}

/// Sets `tutela.tenant_id` for the rest of the transaction.
async fn set_tenant(tx: &Transaction<'_>, tid: &TenantId) -> Result<(), StoreError> {
    tx.query_one(
        "SELECT set_config('tutela.tenant_id', $1, true)",
        &[&tid.to_string()],
    )
    .await
    .db()?;
    Ok(())
}

/// Starts a write: enters the tenant and bumps its revision. Returns the new
/// revision. The revision row stays locked until the transaction ends.
async fn begin_write(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<u64, StoreError> {
    enter(tx, tenant).await?;
    let row = tx
        .query_opt(
            "UPDATE tutela.tenant_rev SET rev = rev + 1 WHERE tenant_id = $1 RETURNING rev",
            &[&tenant.tid.to_string()],
        )
        .await
        .db()?
        .ok_or(StoreError::corrupt("tenant revision row"))?;
    to_rev(row.try_get(0).db()?)
}

/// Ends a write: the whole tenant data must pass the evaluator's load
/// checks, and `tutela.permissions.changed.v1` with the new revision goes
/// into the outbox in the same transaction (ADR-0035).
async fn finish_write(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    rev: u64,
) -> Result<u64, StoreError> {
    let data = load::tenant_data(tx, tenant).await?;
    check(tenant, rev, data)?;
    events::insert(
        tx,
        &tenant.tid,
        &events::OutboxEvent::PermissionsChanged { rev },
    )
    .await?;
    Ok(rev)
}

/// The evaluator's load checks on `data`. They do not depend on the model,
/// so a fixed one is used.
fn check(tenant: &TenantKey, rev: u64, data: TenantData) -> Result<(), StoreError> {
    let model = check_model()?;
    Pdp::new().load(tenant.clone(), rev, model, data)?;
    Ok(())
}

fn check_model() -> Result<Arc<Model>, StoreError> {
    static MODEL: OnceLock<Option<Arc<Model>>> = OnceLock::new();
    MODEL
        .get_or_init(|| {
            Model::from_toml("version = 1\n[app]\nname = \"tutela_store_check\"\n")
                .ok()
                .map(Arc::new)
        })
        .clone()
        .ok_or(StoreError::corrupt("check model"))
}

fn to_rev(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::rev_out_of_range())
}

/// `type:id`, the stored form of one path entry.
fn entry_text(e: &PathEntry) -> String {
    format!("{}:{}", e.type_name, e.id)
}

/// Parses `type:id`. A type name never holds `:`.
fn parse_entry(s: &str) -> Result<PathEntry, StoreError> {
    let (t, id) = s.split_once(':').ok_or(StoreError::corrupt("path entry"))?;
    entry(t, id)
}

fn entry(t: &str, id: &str) -> Result<PathEntry, StoreError> {
    Ok(PathEntry::new(
        t.parse().map_err(|_| StoreError::corrupt("scope type"))?,
        id.parse().map_err(|_| StoreError::corrupt("scope id"))?,
    ))
}

fn parse_org(s: &str) -> Result<OrgId, StoreError> {
    s.parse().map_err(|_| StoreError::corrupt("org id"))
}
