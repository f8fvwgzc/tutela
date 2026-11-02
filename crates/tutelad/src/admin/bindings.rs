//! Role assignments, groups and roles over the admin API (CONTRACTS.md
//! 7.13.7, ADR-0043; issue #107).
//!
//! **Who may ask** (PERMISSION-MODEL.md 15: bindings are day-to-day admin
//! work):
//!
//! - an assignment: `<type>:manage_access` on its scope, at the path the
//!   store holds for it; a group and its members: `org:manage_access` on the
//!   group's org;
//! - and nobody grants what they do not hold (7.1 step 6): every change is
//!   compared before and after, and a change that gives anyone more than the
//!   caller holds at the same place is refused with 403 `not_held`. A
//!   removal counts too: taking away a narrower assignment can uncover a
//!   wider one;
//! - a page at one scope or org: `read_audit` or `manage_access` there; a
//!   page of the whole tenant: `read_audit` at every org.
//!
//! The keys and the rule are checked on the data the change writes, under
//! the tenant's write lock (`admin::locked`). The store bumps the revision
//! and emits `tutela.permissions.changed.v1` in the same transaction; the
//! record of who asked is written last in it.

use std::time::SystemTime;

use axum::http::StatusCode;
use tutela_contracts::audit::Actor;
use tutela_contracts::decision::RuleId;
use tutela_contracts::keys::{ActionKey, ResourceType};
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::OrgId;
use tutela_contracts::timestamp::Timestamp;
use tutela_pdp::model::{GroupKey, Model, RoleKey, SubjectKind};
use tutela_pdp::{Attrs, CheckRequest, Member, PathEntry, ResourceRef, Subject};
use tutela_sdk::Identity;

use super::boundaries::scope;
use super::locked::{self, Before};
use super::wire::{
    AssignBody, AssignmentChangeOut, AssignmentOut, AssignmentsOut, AssignmentsQuery, ExpiryBody,
    FieldOut, GroupBody, GroupOut, GroupsOut, GroupsQuery, MemberBody, MembersOut, MembersQuery,
    RevOut, RoleOut, RolesOut, RolesQuery, TypeOut,
};
use super::{guard, refused, required, store_problem};
use crate::api::{AppState, Problem};
use crate::audit::{self, Record};
use crate::authz::floor;
use crate::cache::ActionClass;
use crate::db::TenantTx;
use crate::tenant::Tenant;

/// The default page.
const PAGE: usize = 100;

/// What looking at one scope or org needs there: either key.
const LOOK: [&str; 2] = ["read_audit", "manage_access"];

/// What looking at the whole tenant needs, at every org.
const LOOK_ALL: [&str; 1] = ["read_audit"];

fn invalid(detail: &str) -> Problem {
    Problem::invalid("invalid_request", detail.to_owned())
}

/// `type:id` of a scope.
pub(crate) fn scope_text(s: &PathEntry) -> String {
    format!("{}:{}", s.type_name, s.id)
}

/// A scope written `type:id`, as a query names it.
pub(crate) fn parse_scope(text: &str, name: &str) -> Result<PathEntry, Problem> {
    let bad = || invalid(&format!("`{name}` is `type:id` of a scope"));
    let (t, id) = text.split_once(':').ok_or_else(bad)?;
    Ok(PathEntry::new(
        ResourceType::parse(t).map_err(|_| bad())?,
        id.parse().map_err(|_| bad())?,
    ))
}

fn subject_of(text: Option<String>, name: &str) -> Result<Subject, Problem> {
    let text = required(text, name)?;
    match text.strip_prefix("group:") {
        Some(g) => GroupKey::parse(g)
            .map(Subject::Group)
            .map_err(|_| invalid(&format!("`{name}` names no group key"))),
        None => text
            .parse::<Principal>()
            .map(Subject::Principal)
            .map_err(|_| invalid(&format!("`{name}` is a principal or `group:<key>`"))),
    }
}

fn member_text(m: &Member) -> String {
    match m {
        Member::Principal(p) => p.to_string(),
        Member::Group(g) => format!("group:{g}"),
    }
}

fn group_key(text: &str) -> Result<GroupKey, Problem> {
    GroupKey::parse(text).map_err(|_| invalid("not a group key"))
}

fn org_of(text: Option<String>) -> Result<OrgId, Problem> {
    required(text, "org")?
        .parse()
        .map_err(|_| invalid("`org` is not an org id"))
}

fn org_scope(org: &OrgId) -> Result<PathEntry, Problem> {
    PathEntry::org(org).map_err(|_| invalid("`org` is not an org id"))
}

fn time_of(text: &str) -> Result<SystemTime, Problem> {
    let t = Timestamp::parse(text).map_err(|_| invalid("`expires_at` is an RFC 3339 time"))?;
    let ms = u64::try_from(t.unix_millis()).map_err(|_| invalid("`expires_at` is before 1970"))?;
    Ok(SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms))
}

pub(crate) fn page(limit: Option<usize>) -> Result<usize, Problem> {
    match limit.unwrap_or(PAGE) {
        n @ 1..=tutela_store::MAX_PAGE => Ok(n),
        _ => Err(invalid("`limit` is 1 to 1000")),
    }
}

/// The caller's principal on the admin routes (ADR-0032), or a recorded
/// refusal.
pub(crate) async fn caller(
    state: &AppState,
    id: &Identity,
    tenant: &Tenant,
    action: &str,
    resource: (&str, &str),
) -> Result<Principal, Problem> {
    match crate::models::principal(id, |acr| state.audiences.is_step_up(acr)) {
        Some(p) => Ok(p.clone()),
        None => Err(refused(state, id, tenant, action, resource, Problem::forbidden()).await),
    }
}

/// The role must be one the model has, and one this subject may hold.
fn check_role(model: &Model, role: &RoleKey, subject: &Subject) -> Result<(), Problem> {
    let def = model
        .roles()
        .get(role)
        .ok_or_else(|| invalid("the tenant's model has no such role"))?;
    let kind = match subject {
        Subject::Principal(p) => SubjectKind::Principal(p.kind()),
        Subject::Group(_) => SubjectKind::Group,
    };
    if def.assignable_to.contains(&kind) {
        Ok(())
    } else {
        Err(invalid(
            "this role may not be given to this kind of subject",
        ))
    }
}

/// What a change is, for its refusal.
pub(crate) struct Change<'a> {
    pub action: &'a str,
    pub resource: (&'a str, &'a str),
    pub who: &'a Principal,
}

/// The end of a change: refused when it gives more than the caller holds,
/// else recorded last in its transaction and committed.
pub(crate) async fn finish(
    state: &AppState,
    id: &Identity,
    tenant: &Tenant,
    tx: TenantTx<'_>,
    before: Before,
    change: Change<'_>,
    record: Record,
) -> Result<(), Problem> {
    let Change {
        action,
        resource,
        who,
    } = change;
    let report = locked::excess(state, &tx, before, who).await?;
    if !report.no_impact() {
        drop(tx);
        tracing::info!(
            lines = report.lines.len(),
            complete = report.complete,
            "an admin change gave more than its caller holds"
        );
        return Err(refused(
            state,
            id,
            tenant,
            action,
            resource,
            locked::not_held(&report),
        )
        .await);
    }
    audit::write(state, &tx, vec![record]).await?;
    tx.commit().await?;
    Ok(())
}

/// A key `who` lacks on `scope`, refused and recorded.
pub(crate) async fn without_key(
    state: &AppState,
    id: &Identity,
    tenant: &Tenant,
    tx: TenantTx<'_>,
    action: &str,
    resource: (&str, &str),
) -> Problem {
    drop(tx);
    refused(state, id, tenant, action, resource, Problem::forbidden()).await
}

/// The caller, when it holds `read_audit` or `manage_access` on `scope` (an
/// org or a registered scope), on data that has just been checked.
pub(crate) async fn look_at(
    state: &AppState,
    id: &Identity,
    tenant: &Tenant,
    scope: &PathEntry,
    action: &str,
    resource: (&str, &str),
) -> Result<Principal, Problem> {
    let who = caller(state, id, tenant, action, resource).await?;
    let path = if scope.is_org() {
        Vec::new()
    } else {
        let mut conn = state.db.conn().await?;
        let tx = conn.begin(tenant).await?;
        let path = tutela_store::ancestors(&tx, tenant.key(), scope).await?;
        tx.commit().await?;
        path.ok_or_else(locked::no_scope)?
    };
    let need = floor(id, None);
    let view = state
        .cache
        .view(tenant, need)
        .await
        .map_err(Problem::from)?;
    let snapshot = view.for_class(ActionClass::Admin).map_err(Problem::from)?;
    for key in LOOK {
        let Ok(action_key) = ActionKey::parse(&format!("{}:{key}", scope.type_name)) else {
            continue;
        };
        let d = snapshot.pdp.check(&CheckRequest {
            tenant: tenant.key().clone(),
            subject: who.clone(),
            actors: Vec::new(),
            action: action_key,
            resource: ResourceRef {
                type_name: scope.type_name.clone(),
                id: scope.id.clone(),
                path: path.clone(),
                attrs: Attrs::new(),
            },
            fields: Some(Vec::new()),
            at_least_revision: need,
        });
        if d.is_ok_and(|d| d.is_allowed()) {
            return Ok(who);
        }
    }
    Err(refused(state, id, tenant, action, resource, Problem::forbidden()).await)
}

// ---------- Role assignments ----------

/// `POST /v1/admin/assignments/list`: a page of the assignments that still
/// count, by id; at one scope, for one subject, or both.
///
/// # Errors
///
/// A [`Problem`]: 403 without the key, 404 for an unknown scope or group.
pub async fn assignments(
    state: &AppState,
    id: &Identity,
    q: AssignmentsQuery,
) -> Result<AssignmentsOut, Problem> {
    let tenant = Tenant::of(id);
    let limit = page(q.limit)?;
    let at = q.scope.map(|s| scope(Some(s))).transpose()?;
    let subject = q
        .subject
        .map(|s| subject_of(Some(s), "subject"))
        .transpose()?;
    let after: Option<RuleId> = q
        .after
        .map(|a| {
            a.parse()
                .map_err(|_| invalid("`after` is an assignment id"))
        })
        .transpose()?;
    let action = "tutela_assignment:read";
    match &at {
        Some(s) => {
            let what = scope_text(s);
            look_at(state, id, &tenant, s, action, ("tutela_assignment", &what)).await?;
        }
        None => {
            guard(
                state,
                id,
                &tenant,
                &LOOK_ALL,
                action,
                ("tutela_assignment", "*"),
            )
            .await?;
        }
    }
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let rows = tutela_store::assignments(
        &tx,
        tenant.key(),
        &tutela_store::AssignmentQuery {
            subject: subject.as_ref(),
            scope: at.as_ref(),
            after: after.as_ref(),
            limit: Some(limit),
        },
    )
    .await
    .map_err(store_problem)?;
    tx.commit().await?;
    let next_after = (rows.len() == limit)
        .then(|| rows.last().map(|a| a.id.to_string()))
        .flatten();
    Ok(AssignmentsOut {
        assignments: rows.iter().map(AssignmentOut::of).collect(),
        next_after,
    })
}

/// `POST /v1/admin/assignments`: gives `role` to a principal or a group at
/// a scope, until `expires_at` if it is set.
///
/// # Errors
///
/// A [`Problem`]: 400 for a role the model lacks or may not give to this
/// subject, 404 for an unknown scope or group, 409 `exists` for a subject
/// that has an assignment at the scope, 403 `forbidden` without
/// `manage_access` on the scope, 403 `not_held` for a grant beyond the
/// caller's own.
pub async fn assign(
    state: &AppState,
    id: &Identity,
    body: AssignBody,
) -> Result<AssignmentChangeOut, Problem> {
    let tenant = Tenant::of(id);
    let subject = subject_of(body.subject, "subject")?;
    let role = RoleKey::parse(&required(body.role, "role")?)
        .map_err(|_| invalid("`role` is not a role key"))?;
    let at = scope(body.scope)?;
    let until = body.expires_at.as_deref().map(time_of).transpose()?;
    let action = "tutela_assignment:create";
    let what = scope_text(&at);
    let resource = ("tutela_assignment", what.as_str());
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    check_role(&before.model, &role, &subject)?;
    let decision = locked::decide(&before, tenant.key(), &who, &at, "manage_access")?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let s = &subject;
    let (rule, rev) = match until {
        Some(t) => {
            tutela_store::assign_until(&tx, tenant.key(), s, &role, &at, Some(&who), t).await
        }
        None => tutela_store::assign(&tx, tenant.key(), s, &role, &at, Some(&who)).await,
    }
    .map_err(store_problem)?;
    let made = tutela_store::assignment(&tx, tenant.key(), &rule).await?;
    let out = AssignmentOut::of(&made);
    let record = Record::new(
        tenant.key(),
        Actor::new(who.clone()),
        action,
        ("tutela_assignment", rule.as_str()),
    )
    .allowed(rev)
    .rules(&decision.rule_ids)
    .detail("subject", out.subject.clone())
    .detail("role", out.role.clone())
    .detail("scope", what.clone())
    .detail("expires_at", out.expires_at.clone())
    .detail("rev", rev);
    finish(
        state,
        id,
        &tenant,
        tx,
        before,
        Change {
            action,
            resource,
            who: &who,
        },
        record,
    )
    .await?;
    tracing::info!(rev, "a role was assigned");
    Ok(AssignmentChangeOut {
        assignment: Some(out),
        rev,
    })
}

/// The assignment `text` names, and its scope's `type:id`.
async fn stored(
    tx: &TenantTx<'_>,
    tenant: &Tenant,
    text: &str,
) -> Result<tutela_store::Assignment, Problem> {
    let rule: RuleId = text.parse().map_err(|_| invalid("not an assignment id"))?;
    tutela_store::assignment(tx, tenant.key(), &rule)
        .await
        .map_err(store_problem)
}

/// `DELETE /v1/admin/assignments/{id}`.
///
/// # Errors
///
/// A [`Problem`]: 404 for an assignment that is not there (or is of another
/// tenant), 403 without `manage_access` on its scope, 403 `not_held` when
/// the removal uncovers access the caller does not hold.
pub async fn unassign(
    state: &AppState,
    id: &Identity,
    assignment: &str,
) -> Result<RevOut, Problem> {
    let tenant = Tenant::of(id);
    let action = "tutela_assignment:delete";
    let resource = ("tutela_assignment", assignment);
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    let a = stored(&tx, &tenant, assignment).await?;
    let decision = locked::decide(&before, tenant.key(), &who, &a.scope, "manage_access")?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let rev = tutela_store::unassign(&tx, tenant.key(), &a.id)
        .await
        .map_err(store_problem)?;
    let out = AssignmentOut::of(&a);
    let record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .allowed(rev)
        .rules(&decision.rule_ids)
        .detail("subject", out.subject)
        .detail("role", out.role)
        .detail("scope", scope_text(&a.scope))
        .detail("rev", rev);
    finish(
        state,
        id,
        &tenant,
        tx,
        before,
        Change {
            action,
            resource,
            who: &who,
        },
        record,
    )
    .await?;
    tracing::info!(rev, "a role assignment was removed");
    Ok(RevOut { rev })
}

/// `PATCH /v1/admin/assignments/{id}`: when it ends, or `null` for never.
/// A later end is a grant for the extra time: the narrow-only rule then
/// takes the assignment as new.
///
/// # Errors
///
/// A [`Problem`]: 400 for a time that has passed or a body without
/// `expires_at`, 404, 403 as for [`unassign`].
pub async fn set_expiry(
    state: &AppState,
    id: &Identity,
    assignment: &str,
    body: ExpiryBody,
) -> Result<AssignmentChangeOut, Problem> {
    let tenant = Tenant::of(id);
    let until = required(body.expires_at, "expires_at")?
        .as_deref()
        .map(time_of)
        .transpose()?;
    let action = "tutela_assignment:update";
    let resource = ("tutela_assignment", assignment);
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let mut before = locked::read(state, &tx).await?;
    let a = stored(&tx, &tenant, assignment).await?;
    let decision = locked::decide(&before, tenant.key(), &who, &a.scope, "manage_access")?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let longer = match (a.expires_at, until) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(old), Some(new)) => new > old,
    };
    if longer {
        before = locked::without(before, tenant.key(), &a.id).await?;
    }
    let rev = tutela_store::set_assignment_expiry(&tx, tenant.key(), &a.id, until)
        .await
        .map_err(store_problem)?;
    let now = tutela_store::assignment(&tx, tenant.key(), &a.id).await?;
    let out = AssignmentOut::of(&now);
    let record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .allowed(rev)
        .rules(&decision.rule_ids)
        .detail("subject", out.subject.clone())
        .detail("role", out.role.clone())
        .detail("scope", scope_text(&a.scope))
        .detail("expires_at", out.expires_at.clone())
        .detail("longer", longer)
        .detail("rev", rev);
    finish(
        state,
        id,
        &tenant,
        tx,
        before,
        Change {
            action,
            resource,
            who: &who,
        },
        record,
    )
    .await?;
    Ok(AssignmentChangeOut {
        assignment: Some(out),
        rev,
    })
}

// ---------- Groups ----------

/// `GET /v1/admin/groups`: a page of groups by key, with how many direct
/// members each has.
///
/// # Errors
///
/// A [`Problem`]: 403 without the key.
pub async fn groups(state: &AppState, id: &Identity, q: GroupsQuery) -> Result<GroupsOut, Problem> {
    let tenant = Tenant::of(id);
    let limit = page(q.limit)?;
    let org = q.org.map(|o| org_of(Some(o))).transpose()?;
    let after = q.after.as_deref().map(group_key).transpose()?;
    let action = "tutela_group:read";
    match &org {
        Some(o) => {
            let text = o.to_string();
            look_at(
                state,
                id,
                &tenant,
                &org_scope(o)?,
                action,
                ("tutela_group", &text),
            )
            .await?;
        }
        None => {
            guard(state, id, &tenant, &LOOK_ALL, action, ("tutela_group", "*")).await?;
        }
    }
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let rows = tutela_store::group_page(&tx, tenant.key(), org.as_ref(), after.as_ref(), limit)
        .await
        .map_err(store_problem)?;
    tx.commit().await?;
    let next_after = (rows.len() == limit)
        .then(|| rows.last().map(|g| g.group.key.to_string()))
        .flatten();
    Ok(GroupsOut {
        groups: rows
            .iter()
            .map(|g| GroupOut::of(&g.group, Some(g.members), None))
            .collect(),
        next_after,
    })
}

/// `POST /v1/admin/groups`: a new, empty group in an org.
///
/// # Errors
///
/// A [`Problem`]: 400 for a bad key or name, 404 for an org that is not
/// the tenant's, 409 `exists` for a key in use, 403 without
/// `org:manage_access` there.
pub async fn create_group(
    state: &AppState,
    id: &Identity,
    body: GroupBody,
) -> Result<GroupOut, Problem> {
    let tenant = Tenant::of(id);
    let org = org_of(body.org)?;
    let key = group_key(&required(body.key, "key")?)?;
    let name = required(body.name, "name")?;
    let action = "tutela_group:create";
    let text = key.to_string();
    let resource = ("tutela_group", text.as_str());
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    let decision = locked::decide(
        &before,
        tenant.key(),
        &who,
        &org_scope(&org)?,
        "manage_access",
    )?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let rev = tutela_store::create_group(&tx, tenant.key(), &org, &key, &name)
        .await
        .map_err(store_problem)?;
    let made = tutela_store::group(&tx, tenant.key(), &key).await?;
    let record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .allowed(rev)
        .org(org)
        .rules(&decision.rule_ids)
        .detail("group", text.clone())
        .detail("rev", rev);
    finish(
        state,
        id,
        &tenant,
        tx,
        before,
        Change {
            action,
            resource,
            who: &who,
        },
        record,
    )
    .await?;
    Ok(GroupOut::of(&made, Some(0), Some(rev)))
}

/// The group a path names, its org checked for `manage_access` by `who`.
async fn managed_group(
    before: &Before,
    tx: &TenantTx<'_>,
    tenant: &Tenant,
    who: &Principal,
    key: &GroupKey,
) -> Result<
    (
        tutela_store::GroupInfo,
        tutela_contracts::decision::Decision,
    ),
    Problem,
> {
    let g = tutela_store::group(tx, tenant.key(), key)
        .await
        .map_err(store_problem)?;
    let d = locked::decide(
        before,
        tenant.key(),
        who,
        &org_scope(&g.org)?,
        "manage_access",
    )?;
    Ok((g, d))
}

/// `DELETE /v1/admin/groups/{key}`: the group, its assignments and its
/// places in other groups go in one revision.
///
/// # Errors
///
/// A [`Problem`]: 404, 403 without `org:manage_access` on its org, 403
/// `not_held` when its members would get more than the caller holds.
pub async fn delete_group(state: &AppState, id: &Identity, key: &str) -> Result<RevOut, Problem> {
    let tenant = Tenant::of(id);
    let key = group_key(key)?;
    let action = "tutela_group:delete";
    let text = key.to_string();
    let resource = ("tutela_group", text.as_str());
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    let (g, decision) = managed_group(&before, &tx, &tenant, &who, &key).await?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let rev = tutela_store::delete_group(&tx, tenant.key(), &key)
        .await
        .map_err(store_problem)?;
    let record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .allowed(rev)
        .org(g.org)
        .rules(&decision.rule_ids)
        .detail("group", text.clone())
        .detail("rev", rev);
    finish(
        state,
        id,
        &tenant,
        tx,
        before,
        Change {
            action,
            resource,
            who: &who,
        },
        record,
    )
    .await?;
    Ok(RevOut { rev })
}

/// `GET /v1/admin/groups/{key}/members`: a page of direct members.
///
/// # Errors
///
/// A [`Problem`]: 404, 403 without `read_audit` or `manage_access` on the
/// group's org.
pub async fn members(
    state: &AppState,
    id: &Identity,
    key: &str,
    q: MembersQuery,
) -> Result<MembersOut, Problem> {
    let tenant = Tenant::of(id);
    let key = group_key(key)?;
    let limit = page(q.limit)?;
    let action = "tutela_group:read";
    let text = key.to_string();
    let g = {
        let mut conn = state.db.conn().await?;
        let tx = conn.begin(&tenant).await?;
        let g = tutela_store::group(&tx, tenant.key(), &key).await;
        tx.commit().await?;
        g.map_err(store_problem)?
    };
    look_at(
        state,
        id,
        &tenant,
        &org_scope(&g.org)?,
        action,
        ("tutela_group", &text),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let rows = tutela_store::group_member_page(&tx, tenant.key(), &key, q.after.as_deref(), limit)
        .await
        .map_err(store_problem)?;
    tx.commit().await?;
    let members: Vec<String> = rows.iter().map(member_text).collect();
    let next_after = (members.len() == limit)
        .then(|| members.last().cloned())
        .flatten();
    Ok(MembersOut {
        members,
        next_after,
    })
}

/// `POST /v1/admin/groups/{key}/members` (`add`) and `…/members/remove`.
///
/// # Errors
///
/// A [`Problem`]: 404 for an unknown group or member group, 409 for a
/// member that is there (add) or a cycle or a group nested too deep, 403
/// without `org:manage_access` on the group's org, 403 `not_held` when the
/// member would get more than the caller holds.
pub async fn change_member(
    state: &AppState,
    id: &Identity,
    key: &str,
    body: MemberBody,
    add: bool,
) -> Result<RevOut, Problem> {
    let tenant = Tenant::of(id);
    let key = group_key(key)?;
    let member = match subject_of(body.member, "member")? {
        Subject::Principal(p) => Member::Principal(p),
        Subject::Group(g) => Member::Group(g),
    };
    let action = if add {
        "tutela_group:add_member"
    } else {
        "tutela_group:remove_member"
    };
    let text = key.to_string();
    let resource = ("tutela_group", text.as_str());
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    let (g, decision) = managed_group(&before, &tx, &tenant, &who, &key).await?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let rev = if add {
        tutela_store::add_member(&tx, tenant.key(), &key, &member, Some(&who)).await
    } else {
        tutela_store::remove_member(&tx, tenant.key(), &key, &member).await
    }
    .map_err(|e| match e.kind() {
        tutela_store::StoreErrorKind::Refused => Problem {
            detail: Some("the group would hold itself, nest too deep or grow too large".to_owned()),
            ..Problem::new(
                StatusCode::CONFLICT,
                "refused",
                "the store refused the change",
            )
        },
        _ => store_problem(e),
    })?;
    let record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .allowed(rev)
        .org(g.org)
        .rules(&decision.rule_ids)
        .detail("group", text.clone())
        .detail("member", member_text(&member))
        .detail("rev", rev);
    finish(
        state,
        id,
        &tenant,
        tx,
        before,
        Change {
            action,
            resource,
            who: &who,
        },
        record,
    )
    .await?;
    Ok(RevOut { rev })
}

// ---------- Roles ----------

/// `GET /v1/admin/roles`: the roles and types of the tenant's active model,
/// the rows and columns of the permission matrix.
///
/// # Errors
///
/// A [`Problem`]: 403 without the key, 404 for an unknown scope.
pub async fn roles(state: &AppState, id: &Identity, q: RolesQuery) -> Result<RolesOut, Problem> {
    let tenant = Tenant::of(id);
    let action = "tutela_role:read";
    match q.scope.as_deref() {
        Some(s) => {
            let at = parse_scope(s, "scope")?;
            look_at(state, id, &tenant, &at, action, ("tutela_role", s)).await?;
        }
        None => {
            guard(state, id, &tenant, &LOOK_ALL, action, ("tutela_role", "*")).await?;
        }
    }
    let active = {
        let mut conn = state.db.conn().await?;
        let tx = conn.begin(&tenant).await?;
        let a = tutela_store::active_model(&tx, tenant.key()).await?;
        tx.commit().await?;
        a.ok_or_else(|| Problem::stale("no_data"))?
    };
    let model = state
        .cache
        .compiled(active.source, &active.digest)
        .await
        .map_err(Problem::from)?;
    Ok(RolesOut {
        version: active.version,
        roles: model
            .roles()
            .iter()
            .map(|(k, r)| RoleOut {
                key: k.to_string(),
                label: r.label.clone(),
                seeded: r.seeded.map(|s| s.key().to_owned()),
                levels: r
                    .levels
                    .iter()
                    .map(|(t, l)| (t.to_string(), l.as_str().to_owned()))
                    .collect(),
                field_levels: r
                    .field_levels
                    .iter()
                    .map(|(f, l)| (f.to_string(), l.as_str().to_owned()))
                    .collect(),
                grants: r.grants.iter().map(ToString::to_string).collect(),
                assignable_to: r
                    .assignable_to
                    .iter()
                    .map(|k| k.as_str().to_owned())
                    .collect(),
            })
            .collect(),
        types: model
            .types()
            .iter()
            .map(|(t, d)| TypeOut {
                name: t.to_string(),
                label: d.label.clone(),
                parents: d.parents.iter().map(ToString::to_string).collect(),
                container: d.container,
                starts_private: d.starts == tutela_pdp::model::Starts::Private,
                fields: d
                    .fields
                    .iter()
                    .map(|(n, f)| FieldOut {
                        name: n.to_string(),
                        sensitivity: sensitivity(f.sensitivity).to_owned(),
                        label: f.label.clone(),
                    })
                    .collect(),
                features: d.features.iter().map(ToString::to_string).collect(),
                actions: d.actions.keys().map(ToString::to_string).collect(),
            })
            .collect(),
    })
}

const fn sensitivity(s: tutela_pdp::model::Sensitivity) -> &'static str {
    use tutela_pdp::model::Sensitivity;
    match s {
        Sensitivity::Public => "public",
        Sensitivity::Internal => "internal",
        Sensitivity::Confidential => "confidential",
        Sensitivity::Secret => "secret",
    }
}
