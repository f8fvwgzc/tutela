//! The principals `tutelad` issues tokens for (ADR-0031): people made by
//! just-in-time provisioning from an external issuer, and agents that
//! attache registers. Each has an `epoch` and can be disabled
//! (CONTRACTS.md 4.2).
//!
//! - A person is found by the upstream `(iss, sub)` of its external issuer,
//!   never by e-mail (ADR-0008, TM-04). [`provision_user`] makes the
//!   principal the first time, and finds it after that.
//! - [`revoke_sessions`] and [`set_disabled`] raise the epoch and the tenant
//!   revision in one transaction, so every replica's view of the tenant moves
//!   and refuses the old tokens.
//! - [`note_exchange`] records an external subject token's `jti`, so each is
//!   exchanged once.
//! - [`register_agent`] adds an agent, with the SPIFFE id of the workload it
//!   runs as when it has one (CONTRACTS.md 1.4). Part 3c puts these calls
//!   behind `tutela.admin.v1`.
//!
//! A principal with no row has epoch 0 and is enabled: it may hold tokens of
//! a trusted issuer that is not `tutelad`.

use std::time::SystemTime;

use sha2::{Digest as _, Sha256};
use tokio_postgres::{Row, Transaction};
use tutela_contracts::principal::{Principal, PrincipalKind, WorkloadId};
use tutela_contracts::tenant::{Issuer, TenantKey};

use crate::{DbResult as _, StoreError, begin_write, enter, uuid7};

/// What the store knows of one principal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrincipalState {
    /// The principal.
    pub principal: Principal,
    /// Its epoch. A token with a lower one is refused.
    pub epoch: u64,
    /// `true` while it is disabled: no token is issued for it, and none it
    /// holds is accepted.
    pub disabled: bool,
    /// For an agent that runs as a workload, its SPIFFE id.
    pub workload: Option<WorkloadId>,
}

/// The principals of a tenant that refuse something: a raised epoch, or
/// disabled. Every other principal is current at epoch 0.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Revocations {
    /// The principals, each once.
    pub entries: Vec<PrincipalState>,
}

const COLUMNS: &str = "p.principal, p.epoch, p.disabled_at IS NOT NULL, p.workload";

fn state(r: &Row) -> Result<PrincipalState, StoreError> {
    let principal: String = r.try_get(0).db()?;
    let epoch: i64 = r.try_get(1).db()?;
    let workload: Option<String> = r.try_get(3).db()?;
    Ok(PrincipalState {
        principal: principal
            .parse()
            .map_err(|_| StoreError::corrupt("principal"))?,
        epoch: u64::try_from(epoch).map_err(|_| StoreError::corrupt("epoch"))?,
        disabled: r.try_get(2).db()?,
        workload: workload
            .map(|w| WorkloadId::parse(&w))
            .transpose()
            .map_err(|_| StoreError::corrupt("workload"))?,
    })
}

/// The principal of the upstream account `(iss, sub)` in `tenant`, made
/// the first time it is seen, and `true` when this call made it. `iss` is
/// the external issuer, `sub` its own subject. Two accounts never merge,
/// whatever their e-mail says.
///
/// Making a principal changes no decision, so it does not bump the
/// revision: with no assignment, a new principal holds nothing.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a `sub` that is empty or
/// over 255 bytes, [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant),
/// or a database error.
pub async fn provision_user(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    iss: &Issuer,
    sub: &str,
) -> Result<(PrincipalState, bool), StoreError> {
    if sub.is_empty() || sub.len() > 255 {
        return Err(StoreError::invalid("an upstream subject is 1 to 255 bytes"));
    }
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let find = format!(
        "SELECT {COLUMNS} FROM tutela.principal p JOIN tutela.upstream_account a \
         ON a.tenant_id = p.tenant_id AND a.principal = p.principal \
         WHERE a.tenant_id = $1 AND a.iss = $2 AND a.sub = $3"
    );
    if let Some(r) = tx
        .query_opt(&find, &[&tid, &iss.as_str(), &sub])
        .await
        .db()?
    {
        return Ok((state(&r)?, false));
    }
    let user = format!("user:usr_{}", uuid7()?);
    tx.execute(
        "INSERT INTO tutela.principal (tenant_id, principal) VALUES ($1, $2)",
        &[&tid, &user],
    )
    .await
    .db()?;
    // Two first sign-ins at once: one row wins, and both get it.
    tx.execute(
        "INSERT INTO tutela.upstream_account (tenant_id, iss, sub, principal) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        &[&tid, &iss.as_str(), &sub, &user],
    )
    .await
    .db()?;
    let r = tx
        .query_one(&find, &[&tid, &iss.as_str(), &sub])
        .await
        .db()?;
    let found = state(&r)?;
    let created = found.principal.to_string() == user;
    if created {
        crate::events::insert(
            tx,
            &tenant.tid,
            &crate::events::OutboxEvent::UserCreated {
                user: found.principal.clone(),
            },
        )
        .await?;
    }
    Ok((found, created))
}

/// What the store knows of `principal` in `tenant`, or `None` when it has
/// no row.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn principal_state(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    principal: &Principal,
) -> Result<Option<PrincipalState>, StoreError> {
    enter(tx, tenant).await?;
    tx.query_opt(
        &format!(
            "SELECT {COLUMNS} FROM tutela.principal p WHERE p.tenant_id = $1 AND p.principal = $2"
        ),
        &[&tenant.tid.to_string(), &principal.to_string()],
    )
    .await
    .db()?
    .as_ref()
    .map(state)
    .transpose()
}

fn person_or_agent(p: &Principal) -> Result<(), StoreError> {
    match p.kind() {
        PrincipalKind::User | PrincipalKind::Agent => Ok(()),
        _ => Err(StoreError::invalid(
            "only a user or an agent principal has an epoch here",
        )),
    }
}

/// Raises `principal`'s epoch in the tenant revision's transaction: every
/// token it holds is refused from then on, and the next exchange issues
/// tokens with the new epoch. Returns the new epoch.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a principal that is not a
/// user or an agent, [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant),
/// or a database error.
pub async fn revoke_sessions(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    principal: &Principal,
) -> Result<u64, StoreError> {
    person_or_agent(principal)?;
    begin_write(tx, tenant).await?;
    let r = tx
        .query_one(
            "INSERT INTO tutela.principal (tenant_id, principal, epoch) VALUES ($1, $2, 1) \
             ON CONFLICT (tenant_id, principal) DO UPDATE SET epoch = tutela.principal.epoch + 1 \
             RETURNING epoch",
            &[&tenant.tid.to_string(), &principal.to_string()],
        )
        .await
        .db()?;
    let epoch: i64 = r.try_get(0).db()?;
    let epoch = u64::try_from(epoch).map_err(|_| StoreError::corrupt("epoch"))?;
    // Only a person has sessions (CONTRACTS.md 8.3). An agent's raised
    // epoch refuses its own tokens at the next exchange; to stop its
    // delegated tokens at once, disable it.
    if principal.kind() == PrincipalKind::User {
        crate::events::insert(
            tx,
            &tenant.tid,
            &crate::events::OutboxEvent::SessionRevoked {
                principal: principal.clone(),
                epoch,
                sid: None,
            },
        )
        .await?;
    }
    Ok(epoch)
}

/// Disables `principal`, or enables it again. Disabling raises the epoch
/// too, so enabling again never brings an old token back. Returns the
/// epoch. Both bump the tenant revision.
///
/// # Errors
///
/// As [`revoke_sessions`].
pub async fn set_disabled(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    principal: &Principal,
    disabled: bool,
) -> Result<u64, StoreError> {
    person_or_agent(principal)?;
    begin_write(tx, tenant).await?;
    let sql = if disabled {
        "INSERT INTO tutela.principal (tenant_id, principal, epoch, disabled_at) \
         VALUES ($1, $2, 1, now()) \
         ON CONFLICT (tenant_id, principal) DO UPDATE \
         SET epoch = tutela.principal.epoch + 1, \
             disabled_at = coalesce(tutela.principal.disabled_at, now()) \
         RETURNING epoch"
    } else {
        "INSERT INTO tutela.principal (tenant_id, principal) VALUES ($1, $2) \
         ON CONFLICT (tenant_id, principal) DO UPDATE SET disabled_at = NULL \
         RETURNING epoch"
    };
    let r = tx
        .query_one(sql, &[&tenant.tid.to_string(), &principal.to_string()])
        .await
        .db()?;
    let epoch: i64 = r.try_get(0).db()?;
    let epoch = u64::try_from(epoch).map_err(|_| StoreError::corrupt("epoch"))?;
    let mut out = Vec::new();
    if disabled {
        out.push(crate::events::OutboxEvent::PrincipalDisabled {
            principal: principal.clone(),
            epoch,
        });
        if principal.kind() == PrincipalKind::User {
            out.push(crate::events::OutboxEvent::UserDisabled {
                user: principal.clone(),
                epoch,
            });
        }
    } else {
        out.push(crate::events::OutboxEvent::PrincipalEnabled {
            principal: principal.clone(),
            epoch,
        });
    }
    for e in &out {
        crate::events::insert(tx, &tenant.tid, e).await?;
    }
    Ok(epoch)
}

/// Registers an agent of the tenant, with the workload it runs as when it
/// has one. The workload's path must be attache's
/// `/ns/<namespace>/svc/<service>` (CONTRACTS.md 1.4): a `/sa/...` path
/// never names an attache workload. One workload names one agent.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a principal that is not
/// an agent or a workload on another path,
/// [`Exists`](crate::StoreErrorKind::Exists) for an agent or a workload
/// already registered, or a database error.
pub async fn register_agent(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    agent: &Principal,
    workload: Option<&WorkloadId>,
) -> Result<(), StoreError> {
    if agent.kind() != PrincipalKind::Agent {
        return Err(StoreError::invalid("only an agent principal is registered"));
    }
    if let Some(w) = workload
        && !is_attache_path(w)
    {
        return Err(StoreError::invalid(
            "a workload agent's path is /ns/<namespace>/svc/<service>",
        ));
    }
    enter(tx, tenant).await?;
    let n = tx
        .execute(
            "INSERT INTO tutela.principal (tenant_id, principal, workload) VALUES ($1, $2, $3) \
             ON CONFLICT DO NOTHING",
            &[
                &tenant.tid.to_string(),
                &agent.to_string(),
                &workload.map(WorkloadId::as_str),
            ],
        )
        .await
        .db()?;
    if n == 0 {
        return Err(StoreError::exists("this agent or this workload"));
    }
    Ok(())
}

/// `/ns/<namespace>/svc/<service>`, and nothing more.
#[must_use]
pub fn is_attache_path(w: &WorkloadId) -> bool {
    let parts: Vec<&str> = w.path().split('/').collect();
    matches!(parts.as_slice(), ["", "ns", ns, "svc", svc] if !ns.is_empty() && !svc.is_empty())
}

/// The agent registered for workload `w` in `tenant`.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn agent_for_workload(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    w: &WorkloadId,
) -> Result<Option<PrincipalState>, StoreError> {
    enter(tx, tenant).await?;
    tx.query_opt(
        &format!(
            "SELECT {COLUMNS} FROM tutela.principal p WHERE p.tenant_id = $1 AND p.workload = $2"
        ),
        &[&tenant.tid.to_string(), &w.as_str()],
    )
    .await
    .db()?
    .as_ref()
    .map(state)
    .transpose()
}

/// The principals of `tenant` with a raised epoch or disabled.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn revocations(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<Revocations, StoreError> {
    enter(tx, tenant).await?;
    let rows = tx
        .query(
            &format!(
                "SELECT {COLUMNS} FROM tutela.principal p \
                 WHERE p.tenant_id = $1 AND (p.epoch > 0 OR p.disabled_at IS NOT NULL)"
            ),
            &[&tenant.tid.to_string()],
        )
        .await
        .db()?;
    Ok(Revocations {
        entries: rows.iter().map(state).collect::<Result<_, _>>()?,
    })
}

/// Records that the subject token `jti` of external issuer `iss` was
/// exchanged, and keeps the record until `expires_at`. Returns `false` when
/// it was recorded already: a replay. Expired records of the tenant go on
/// the way.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for an empty `jti`,
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn note_exchange(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    iss: &Issuer,
    jti: &str,
    expires_at: SystemTime,
) -> Result<bool, StoreError> {
    if jti.is_empty() {
        return Err(StoreError::invalid("a subject token needs a jti"));
    }
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    tx.execute(
        "DELETE FROM tutela.exchanged_token WHERE tenant_id = $1 AND expires_at < now()",
        &[&tid],
    )
    .await
    .db()?;
    let digest: String = Sha256::digest(jti.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let n = tx
        .execute(
            "INSERT INTO tutela.exchanged_token (tenant_id, iss, jti_digest, expires_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[&tid, &iss.as_str(), &digest, &expires_at],
        )
        .await
        .db()?;
    Ok(n == 1)
}
