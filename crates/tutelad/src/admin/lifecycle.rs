//! The tenant, its orgs and its people (CONTRACTS.md 7.13.5, ADR-0041).
//!
//! **Who may ask.** A tenant's owner, holding **every admin key at every
//! org** ([`TENANT_KEYS`]), names the tenant, soft-deletes it, and makes,
//! deletes and restores orgs. Making an org gives the caller the seeded
//! Owner role there, in the same transaction: the new org must have an
//! admin, and the caller holds those keys everywhere already. Renaming an
//! org takes `manage_access` on that org. Deleting a person takes
//! `manage_access` at every org, as disabling one does. Reading takes
//! `read_audit` at every org. Making a tenant is the operator's
//! ([`crate::lifecycle`]): no route makes one.
//!
//! **Events** (CONTRACTS.md 8.3), in the change's transaction:
//! `tutela.org.created.v1`, `tutela.org.updated.v1` (a rename or a restore),
//! `tutela.org.deleted.v1 {org, purge_after}`, `tutela.user.deleted.v1`. A
//! tenant's own deletion has none: its outbox stops with it.

use axum::http::StatusCode;
use tutela_contracts::audit::Actor;
use tutela_contracts::keys::{ActionKey, ResourceId, ResourceType};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::OrgId;
use tutela_contracts::timestamp::Timestamp;
use tutela_pdp::model::RoleKey;
use tutela_pdp::{Attrs, CheckRequest, PathEntry, ResourceRef, Subject};
use tutela_sdk::Identity;
use tutela_store::{OutboxEvent, StoreErrorKind};

use super::principals::PEOPLE_KEYS;
use super::wire::{NameBody, OrgOut, OrgsOut, PrincipalBody, PrincipalOut, TenantOut};
use super::{guard, refused, required, store_problem};
use crate::api::{AppState, Problem};
use crate::audit::{self, Record};
use crate::authz::floor;
use crate::cache::ActionClass;
use crate::models::READ_KEYS;
use crate::models::wire::time;
use crate::tenant::Tenant;

/// Every admin key (MANIFEST.md 6): what the tenant's owner holds at every
/// org.
pub const TENANT_KEYS: [&str; 6] = [
    "manage_access",
    "manage_fields",
    "manage_boundaries",
    "manage_agents",
    "approve_move",
    "read_audit",
];

fn not_found() -> Problem {
    Problem::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "no such org in this tenant",
    )
}

fn org_id(text: &str) -> Result<OrgId, Problem> {
    text.parse().map_err(|_| not_found())
}

fn millis(t: std::time::SystemTime) -> Option<Timestamp> {
    let ms = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis();
    Timestamp::from_unix_millis(i64::try_from(ms).ok()?).ok()
}

fn tenant_out(
    info: &tutela_store::TenantInfo,
    purge_after: Option<std::time::SystemTime>,
) -> TenantOut {
    TenantOut {
        tid: info.key.tid.to_string(),
        iss: info.key.iss.to_string(),
        name: info.name.clone(),
        created_at: time(info.created_at),
        purge_after: purge_after.and_then(time),
    }
}

/// `GET /v1/admin/tenant`.
///
/// # Errors
///
/// A [`Problem`].
pub async fn tenant(state: &AppState, id: &Identity) -> Result<TenantOut, Problem> {
    let tenant = Tenant::of(id);
    let tid = tenant.key().tid.to_string();
    guard(
        state,
        id,
        &tenant,
        &READ_KEYS,
        "tutela_tenant:read",
        ("tutela_tenant", &tid),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let info = tutela_store::tenant_info(&tx, tenant.key()).await?;
    tx.commit().await?;
    Ok(tenant_out(&info, None))
}

/// `PATCH /v1/admin/tenant`: its display name. No revision moves.
///
/// # Errors
///
/// A [`Problem`].
pub async fn update_tenant(
    state: &AppState,
    id: &Identity,
    body: NameBody,
) -> Result<TenantOut, Problem> {
    let tenant = Tenant::of(id);
    let tid = tenant.key().tid.to_string();
    let action = "tutela_tenant:update";
    let by = guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        action,
        ("tutela_tenant", &tid),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    tutela_store::set_tenant_name(&tx, tenant.key(), body.name.as_deref())
        .await
        .map_err(store_problem)?;
    let info = tutela_store::tenant_info(&tx, tenant.key()).await?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by),
                action,
                ("tutela_tenant", &tid),
            )
            .allowed(rev)
            .detail("named", body.name.is_some()),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(tenant_out(&info, None))
}

/// `DELETE /v1/admin/tenant`: a soft delete (ADR-0041). From the commit on
/// the tenant answers nothing, and no job visits it; its data is purged
/// after `TUTELA_PURGE_GRACE_SECS`; its audit chain stays. The deletion is
/// the last record of its own chain, and is recorded in the deployment's.
///
/// # Errors
///
/// A [`Problem`].
pub async fn delete_tenant(state: &AppState, id: &Identity) -> Result<TenantOut, Problem> {
    let tenant = Tenant::of(id);
    let tid = tenant.key().tid.to_string();
    let action = "tutela_tenant:delete";
    let by = guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        action,
        ("tutela_tenant", &tid),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let info = tutela_store::tenant_info(&tx, tenant.key()).await?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    let purge_after = tutela_store::delete_tenant(&tx, tenant.key(), state.purge_grace).await?;
    let when = millis(purge_after).map(|t| t.to_string());
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by.clone()),
                action,
                ("tutela_tenant", &tid),
            )
            .allowed(rev)
            .detail("purge_after", when.clone()),
        ],
    )
    .await?;
    tx.commit().await?;
    drop(conn);
    tracing::warn!("a tenant was soft-deleted");
    // The tenant's chain has the deletion; the deployment's chain, which is
    // still forwarded, gets it too.
    let record =
        crate::lifecycle::deployment_record(&state.own, action, tenant.key(), Actor::new(by))?
            .detail("purge_after", when);
    let written = match state.db.conn().await {
        Ok(mut c) => c
            .deployment_records(vec![record])
            .await
            .map_err(Problem::from),
        Err(e) => Err(Problem::from(e)),
    };
    if written.is_err() {
        state.metrics.count_audit("write", "error");
        tracing::error!("a tenant's deletion could not be recorded in the deployment's chain");
    }
    Ok(tenant_out(&info, Some(purge_after)))
}

/// `GET /v1/admin/orgs`: every org, the deleted ones too.
///
/// # Errors
///
/// A [`Problem`].
pub async fn orgs(state: &AppState, id: &Identity) -> Result<OrgsOut, Problem> {
    let tenant = Tenant::of(id);
    guard(
        state,
        id,
        &tenant,
        &READ_KEYS,
        "tutela_org:list",
        ("tutela_org", "orgs"),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let list = tutela_store::orgs(&tx, tenant.key()).await?;
    tx.commit().await?;
    Ok(OrgsOut {
        orgs: list.iter().map(|o| OrgOut::of(o, None)).collect(),
    })
}

/// `POST /v1/admin/orgs`: a new org, with the caller as its owner, in one
/// transaction. Emits `tutela.org.created.v1`.
///
/// # Errors
///
/// A [`Problem`].
pub async fn create_org(
    state: &AppState,
    id: &Identity,
    body: NameBody,
) -> Result<OrgOut, Problem> {
    let tenant = Tenant::of(id);
    let action = "tutela_org:create";
    let by = guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        action,
        ("tutela_org", "new"),
    )
    .await?;
    let role =
        RoleKey::parse(crate::lifecycle::OWNER_ROLE).map_err(|_| Problem::stale("unavailable"))?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let (org, _) = tutela_store::add_org(&tx, tenant.key()).await?;
    if body.name.is_some() {
        tutela_store::set_org_name(&tx, tenant.key(), &org, body.name.as_deref())
            .await
            .map_err(store_problem)?;
    }
    let at = PathEntry::org(&org).map_err(|_| Problem::stale("unavailable"))?;
    let (assignment, rev) = tutela_store::assign(
        &tx,
        tenant.key(),
        &Subject::Principal(by.clone()),
        &role,
        &at,
        None,
    )
    .await?;
    tutela_store::emit(&tx, tenant.key(), OutboxEvent::OrgCreated { org }).await?;
    let info = tutela_store::org(&tx, tenant.key(), &org)
        .await?
        .ok_or_else(|| Problem::stale("unavailable"))?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by.clone()),
                action,
                ("tutela_org", &org.to_string()),
            )
            .allowed(rev)
            .org(org)
            .rules(std::slice::from_ref(&assignment))
            .detail("owner", by.to_string())
            .detail("role", crate::lifecycle::OWNER_ROLE)
            .detail("rev", rev),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::info!(rev, "an org was made");
    Ok(OrgOut::of(&info, Some(rev)))
}

/// The caller, when it holds every one of `keys` on `org` itself, on data
/// that has just been checked, at least as new as the org. An org this
/// tenant does not have, or that is deleted, is 404.
async fn org_admin(
    state: &AppState,
    id: &Identity,
    tenant: &Tenant,
    org: &OrgId,
    keys: &[&str],
    action: &str,
) -> Result<Principal, Problem> {
    let name = org.to_string();
    let resource = ("tutela_org", name.as_str());
    let Some(who) = crate::models::principal(id, |acr| state.audiences.is_step_up(acr)).cloned()
    else {
        return Err(refused(state, id, tenant, action, resource, Problem::forbidden()).await);
    };
    let rev = {
        let mut conn = state.db.conn().await?;
        let tx = conn.begin(tenant).await?;
        let found = tutela_store::org(&tx, tenant.key(), org).await?;
        let rev = tutela_store::rev(&tx, tenant.key()).await?;
        tx.commit().await?;
        if found.is_none_or(|o| o.deleted_at.is_some()) {
            return Err(not_found());
        }
        rev
    };
    let need = floor(id, Some(rev));
    let view = state
        .cache
        .view(tenant, need)
        .await
        .map_err(Problem::from)?;
    let snapshot = view.for_class(ActionClass::Admin).map_err(Problem::from)?;
    let rid = ResourceId::parse(&name).map_err(|_| Problem::stale("unavailable"))?;
    for key in keys {
        let action_key =
            ActionKey::parse(&format!("org:{key}")).map_err(|_| Problem::stale("unavailable"))?;
        let d = snapshot
            .pdp
            .check(&CheckRequest {
                tenant: tenant.key().clone(),
                subject: who.clone(),
                actors: Vec::new(),
                action: action_key,
                resource: ResourceRef {
                    type_name: ResourceType::ORG,
                    id: rid.clone(),
                    path: Vec::new(),
                    attrs: Attrs::new(),
                },
                fields: Some(Vec::new()),
                at_least_revision: need,
            })
            .map_err(|_| Problem::stale("unavailable"))?;
        if !d.is_allowed() {
            return Err(refused(state, id, tenant, action, resource, Problem::forbidden()).await);
        }
    }
    Ok(who)
}

/// `PATCH /v1/admin/orgs/{org}`: its display name, by an admin of that org
/// (`manage_access` on it). Emits `tutela.org.updated.v1`; no revision
/// moves.
///
/// # Errors
///
/// A [`Problem`].
pub async fn update_org(
    state: &AppState,
    id: &Identity,
    org: &str,
    body: NameBody,
) -> Result<OrgOut, Problem> {
    let tenant = Tenant::of(id);
    let org = org_id(org)?;
    let action = "tutela_org:update";
    let by = org_admin(state, id, &tenant, &org, &["manage_access"], action).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    tutela_store::set_org_name(&tx, tenant.key(), &org, body.name.as_deref())
        .await
        .map_err(store_problem)?;
    tutela_store::emit(&tx, tenant.key(), OutboxEvent::OrgUpdated { org }).await?;
    let info = tutela_store::org(&tx, tenant.key(), &org)
        .await?
        .ok_or_else(not_found)?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by),
                action,
                ("tutela_org", &org.to_string()),
            )
            .allowed(rev)
            .org(org)
            .detail("named", body.name.is_some()),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(OrgOut::of(&info, None))
}

/// `DELETE /v1/admin/orgs/{org}`: a soft delete. In the same revision the
/// org and everything under it leave every decision. Emits
/// `tutela.org.deleted.v1` with `purge_after`. Never the last org.
///
/// # Errors
///
/// A [`Problem`]: 409 `last_org`.
pub async fn delete_org(state: &AppState, id: &Identity, org: &str) -> Result<OrgOut, Problem> {
    let tenant = Tenant::of(id);
    let org = org_id(org)?;
    let action = "tutela_org:delete";
    let by = guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        action,
        ("tutela_org", &org.to_string()),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let (purge_after, rev) = tutela_store::delete_org(&tx, tenant.key(), &org, state.purge_grace)
        .await
        .map_err(|e| match e.kind() {
            StoreErrorKind::Invalid => Problem::new(
                StatusCode::CONFLICT,
                "last_org",
                "a tenant keeps at least one org",
            ),
            StoreErrorKind::NotFound => not_found(),
            _ => e.into(),
        })?;
    let when = millis(purge_after).ok_or_else(|| Problem::stale("unavailable"))?;
    tutela_store::emit(
        &tx,
        tenant.key(),
        OutboxEvent::OrgDeleted {
            org,
            purge_after: when,
        },
    )
    .await?;
    let info = tutela_store::org(&tx, tenant.key(), &org)
        .await?
        .ok_or_else(not_found)?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by),
                action,
                ("tutela_org", &org.to_string()),
            )
            .allowed(rev)
            .org(org)
            .detail("purge_after", when.to_string())
            .detail("rev", rev),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::warn!(rev, "an org was soft-deleted");
    Ok(OrgOut::of(&info, Some(rev)))
}

/// `POST /v1/admin/orgs/{org}/restore`: undoes a soft delete before the
/// purge. Emits `tutela.org.updated.v1`.
///
/// # Errors
///
/// A [`Problem`]: 404 for an org that is not deleted or already purged.
pub async fn restore_org(state: &AppState, id: &Identity, org: &str) -> Result<OrgOut, Problem> {
    let tenant = Tenant::of(id);
    let org = org_id(org)?;
    let action = "tutela_org:restore";
    let by = guard(
        state,
        id,
        &tenant,
        &TENANT_KEYS,
        action,
        ("tutela_org", &org.to_string()),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let rev = tutela_store::restore_org(&tx, tenant.key(), &org)
        .await
        .map_err(store_problem)?;
    tutela_store::emit(&tx, tenant.key(), OutboxEvent::OrgUpdated { org }).await?;
    let info = tutela_store::org(&tx, tenant.key(), &org)
        .await?
        .ok_or_else(not_found)?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by),
                action,
                ("tutela_org", &org.to_string()),
            )
            .allowed(rev)
            .org(org)
            .detail("rev", rev),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(OrgOut::of(&info, Some(rev)))
}

/// `POST /v1/admin/users/delete`: deletes a person of the tenant
/// (`tutela_store::delete_user`). Emits `tutela.user.deleted.v1` and
/// `tutela.principal.disabled.v1`.
///
/// # Errors
///
/// A [`Problem`]: 400 for a principal that is not a user, 404 for one
/// deleted already.
pub async fn delete_user(
    state: &AppState,
    id: &Identity,
    body: PrincipalBody,
) -> Result<PrincipalOut, Problem> {
    let tenant = Tenant::of(id);
    let text = required(body.principal, "principal")?;
    let user: Principal = text.parse().map_err(|_| {
        Problem::invalid(
            "invalid_request",
            "`principal` is not a principal string".to_owned(),
        )
    })?;
    if user.kind() != PrincipalKind::User {
        return Err(Problem::invalid(
            "invalid_request",
            "only a user is deleted here".to_owned(),
        ));
    }
    let name = user.to_string();
    let action = "tutela_principal:delete";
    let by = guard(
        state,
        id,
        &tenant,
        &PEOPLE_KEYS,
        action,
        ("tutela_principal", &name),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let (epoch, rev) = tutela_store::delete_user(&tx, tenant.key(), &user)
        .await
        .map_err(store_problem)?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by),
                action,
                ("tutela_principal", &name),
            )
            .allowed(rev)
            .detail("principal", name.clone())
            .detail("epoch", epoch)
            .detail("rev", rev),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::info!(epoch, rev, "a person was deleted");
    Ok(PrincipalOut {
        principal: name,
        epoch,
        disabled: true,
        workload: None,
        rev: Some(rev),
    })
}
