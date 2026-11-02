//! What `tutelad` writes to the local audit log (ADR-0034, CONTRACTS.md 9).
//!
//! Each operation builds its [`Record`]s and writes them with [`write()`] in
//! the transaction of its change, last, just before the commit. An answer
//! that changes nothing (a refused publish, an explain, a write check) gets
//! a transaction of its own from [`write_alone`], and leaves only after its
//! record is committed: if the record cannot be written, the caller gets
//! the same 503 as for any database failure. A token-exchange refusal is the
//! exception: it is refused either way, so a failed record is logged and
//! counted, never turned into a different answer.
//!
//! A record never holds a token, a secret, an e-mail or a field value: ids,
//! numbers and codes only (CONTRACTS.md 9.5).
//!
//! **To audit a new operation:** build a `Record::new(tenant, actor, action,
//! (type, id))`, finish it with [`Record::allowed`], [`Record::denied`] or
//! [`Record::failed`], add what else happened with [`Record::detail`], and
//! pass it to [`write()`] in the change's transaction.

use serde_json::{Map, Value};
use tutela_contracts::audit::{
    Actor, AuditDraft, DecisionSummary, Details, Outcome, ResourceRef, ServiceName,
};
use tutela_contracts::decision::{Effect, Reason, RuleId};
use tutela_contracts::id::Uuid7;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{OrgId, TenantKey};
use tutela_contracts::timestamp::Timestamp;
use tutela_sdk::Identity;

use crate::api::{AppState, Problem};
use crate::db::{DbError, TenantTx};
use crate::tenant::Tenant;

/// The `service` of every record `tutelad` writes.
pub const SERVICE: &str = "tutelad";

/// `tutelad` itself: the actor of what no principal asked for (the expiry
/// sweep, the deployment's signing keys) and of a refusal before any
/// principal is known. No token is ever issued for it, and the API refuses
/// one that names it.
pub const SYSTEM: &str = "sa:sa_00000000-0000-7000-8000-000000000000";

/// [`SYSTEM`] as a principal.
///
/// # Errors
///
/// Never in practice: the constant parses, and a test proves it.
pub fn system() -> Result<Principal, BuildError> {
    SYSTEM.parse().map_err(|_| BuildError("system principal"))
}

/// The actor of a verified token: its subject, or for a delegated token the
/// agent that acts now on behalf of the person. An external token has no
/// principal yet.
#[must_use]
pub fn actor_of(id: &Identity) -> Option<Actor> {
    match id {
        Identity::Access(c) => Some(Actor::new(c.sub.clone())),
        Identity::Delegated(c) => Some(Actor::delegated(c.act.sub.clone(), c.sub.clone())),
        _ => None,
    }
}

/// The actor chain of a delegated token, current actor first, as strings.
#[must_use]
pub fn chain_of(id: &Identity) -> Vec<String> {
    match id {
        Identity::Delegated(c) => c.act.chain().into_iter().map(ToString::to_string).collect(),
        _ => Vec::new(),
    }
}

/// One record being built. Unknown until [`Record::allowed`],
/// [`Record::denied`] or [`Record::failed`] says how it ended.
#[derive(Clone, Debug)]
pub struct Record {
    tenant: TenantKey,
    org: Option<OrgId>,
    actor: Actor,
    action: String,
    resource: (String, String),
    effect: Effect,
    outcome: Outcome,
    reason: String,
    rule_ids: Vec<RuleId>,
    rev: u64,
    details: Map<String, Value>,
}

impl Record {
    /// A record of `actor` doing `action` (a permission key, for Tutela's
    /// own actions `tutela_<thing>:<verb>`) on `(type, id)` in `tenant`.
    #[must_use]
    pub fn new(tenant: &TenantKey, actor: Actor, action: &str, resource: (&str, &str)) -> Self {
        Self {
            tenant: tenant.clone(),
            org: None,
            actor,
            action: action.to_owned(),
            resource: (resource.0.to_owned(), resource.1.to_owned()),
            effect: Effect::Allow,
            outcome: Outcome::Success,
            reason: "allowed".to_owned(),
            rule_ids: Vec::new(),
            rev: 0,
            details: Map::new(),
        }
    }

    /// It was allowed and it worked, at revision `rev`.
    #[must_use]
    pub fn allowed(mut self, rev: u64) -> Self {
        self.effect = Effect::Allow;
        self.outcome = Outcome::Success;
        self.reason = "allowed".to_owned();
        self.rev = rev;
        self
    }

    /// It was refused, with `reason` (`<code>` or `<code>: <detail>`).
    #[must_use]
    pub fn denied(mut self, rev: u64, reason: &str) -> Self {
        self.effect = Effect::Deny;
        self.outcome = Outcome::Denied;
        self.reason = reason.to_owned();
        self.rev = rev;
        self
    }

    /// It was allowed, but the action itself did not happen, with `reason`.
    #[must_use]
    pub fn failed(mut self, rev: u64, reason: &str) -> Self {
        self.effect = Effect::Allow;
        self.outcome = Outcome::Failure;
        self.reason = reason.to_owned();
        self.rev = rev;
        self
    }

    /// The rules that decided.
    #[must_use]
    pub fn rules(mut self, ids: &[RuleId]) -> Self {
        self.rule_ids = ids.to_vec();
        self
    }

    /// The org it happened in.
    #[must_use]
    pub const fn org(mut self, org: OrgId) -> Self {
        self.org = Some(org);
        self
    }

    /// What else happened. `None` and `null` are left out.
    #[must_use]
    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        let v = value.into();
        if !v.is_null() {
            self.details.insert(key.to_owned(), v);
        }
        self
    }

    /// The draft, checked.
    ///
    /// # Errors
    ///
    /// A value that breaks an audit.v1 rule. That is a bug here, never the
    /// caller's input: every value comes from a parsed type.
    pub fn build(self) -> Result<AuditDraft, BuildError> {
        let id = Uuid7::from_uuid(uuid::Uuid::now_v7()).map_err(|_| BuildError("id"))?;
        let time = Timestamp::from_unix_millis(
            i64::try_from(id.unix_millis()).map_err(|_| BuildError("time"))?,
        )
        .map_err(|_| BuildError("time"))?;
        let reason = Reason::parse(&self.reason)
            .or_else(|_| Reason::parse(self.reason.split(':').next().unwrap_or("not_allowed")))
            .map_err(|_| BuildError("reason"))?;
        let draft = AuditDraft {
            id,
            time,
            tenant: self.tenant,
            org: self.org,
            actor: self.actor,
            action: self.action.parse().map_err(|_| BuildError("action"))?,
            resource: ResourceRef {
                resource_type: self.resource.0.parse().map_err(|_| BuildError("type"))?,
                id: self
                    .resource
                    .1
                    .parse()
                    .map_err(|_| BuildError("resource id"))?,
            },
            decision: DecisionSummary {
                effect: self.effect,
                rule_ids: self.rule_ids,
                rev: self.rev,
            },
            outcome: self.outcome,
            reason,
            trace_id: None,
            span_id: None,
            service: ServiceName::parse(SERVICE).map_err(|_| BuildError("service"))?,
            request_id: None,
            ip: None,
            payload_digest: None,
            labels: Vec::new(),
            details: if self.details.is_empty() {
                None
            } else {
                Some(Details::new(self.details).map_err(|_| BuildError("details"))?)
            },
        };
        draft.check().map_err(|_| BuildError("record"))?;
        Ok(draft)
    }

    /// The outcome label for metrics.
    const fn outcome_label(&self) -> &'static str {
        match self.outcome {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Denied => "denied",
        }
    }
}

/// A record could not be built. A bug: the text names the field.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("an audit record has an invalid {0}")]
pub struct BuildError(&'static str);

impl BuildError {
    /// A record whose `what` is invalid.
    #[must_use]
    pub const fn new(what: &'static str) -> Self {
        Self(what)
    }
}

impl From<BuildError> for Problem {
    fn from(e: BuildError) -> Self {
        tracing::error!(error = %e, "an audit record could not be built");
        Self::stale("unavailable")
    }
}

fn drafts(state: &AppState, records: Vec<Record>) -> Result<Vec<AuditDraft>, BuildError> {
    records
        .into_iter()
        .map(|r| {
            let label = r.outcome_label();
            let action = r.resource.0.clone();
            let d = r.build();
            if d.is_ok() {
                state.metrics.count_audit(audit_label(&action), label);
            }
            d
        })
        .collect()
}

/// A bounded label: Tutela's own resource types, else `product`.
fn audit_label(resource_type: &str) -> &'static str {
    match resource_type {
        "tutela_model" => "model",
        "tutela_proposal" => "proposal",
        "tutela_setting" => "setting",
        "tutela_token" => "token",
        "tutela_principal" => "principal",
        "tutela_assignment" => "assignment",
        "tutela_signing_key" => "signing_key",
        "tutela_access" => "access",
        "tutela_boundary" => "boundary",
        "tutela_org" => "org",
        "tutela_tenant" => "tenant",
        "tutela_webhook" => "webhook",
        _ => "write_check",
    }
}

/// Writes `records` in `tx`, the transaction of the change they describe.
/// Call it last before the commit: it holds the chain's lock until then.
///
/// # Errors
///
/// The 503 of a database failure. The caller's change must not commit.
pub async fn write(
    state: &AppState,
    tx: &TenantTx<'_>,
    records: Vec<Record>,
) -> Result<(), Problem> {
    let drafts = drafts(state, records)?;
    tutela_store::append_audit(tx, tx.tenant(), &drafts)
        .await
        .map_err(|e| {
            state.metrics.count_audit("write", "error");
            Problem::from(e)
        })?;
    Ok(())
}

/// Writes `records` in a transaction of their own, for an answer that
/// changes nothing. The answer leaves only after this returns `Ok`.
///
/// # Errors
///
/// The 503 of a database failure.
pub async fn write_alone(
    state: &AppState,
    tenant: &Tenant,
    records: Vec<Record>,
) -> Result<(), Problem> {
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(tenant).await?;
    write(state, &tx, records).await?;
    tx.commit().await.map_err(|e: DbError| {
        state.metrics.count_audit("write", "error");
        Problem::from(e)
    })
}

/// [`write_alone`], for records that name the tenant's revision now.
///
/// # Errors
///
/// The 503 of a database failure.
pub async fn write_alone_now(
    state: &AppState,
    tenant: &Tenant,
    records: impl FnOnce(u64) -> Vec<Record>,
) -> Result<(), Problem> {
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(tenant).await?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    write(state, &tx, records(rev)).await?;
    tx.commit().await.map_err(|e: DbError| {
        state.metrics.count_audit("write", "error");
        Problem::from(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_principal_parses_and_is_a_service_account() {
        let p: Principal = SYSTEM.parse().unwrap();
        assert_eq!(p, system().unwrap());
        assert_eq!(
            p.kind(),
            tutela_contracts::principal::PrincipalKind::ServiceAccount
        );
    }
}
