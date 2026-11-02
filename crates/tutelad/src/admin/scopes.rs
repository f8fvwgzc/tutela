//! A product's scopes in service mode: register, move, delete, the private
//! flag, and a page of them (CONTRACTS.md 7.13.2, ADR-0043; issue #107).
//!
//! In library mode a product calls the store in its own transaction. In
//! service mode it calls these routes, with its service's token, as its
//! users make, move and delete what they own; the Console calls them too.
//!
//! **Who may ask:**
//!
//! - register: `write` on the parent (a new child is a write on its parent,
//!   PERMISSION-MODEL.md 5.2);
//! - move: the move verdict of `write_check` (PERMISSION-MODEL.md 10,
//!   ADR-0025), run on the data the move writes, under the tenant's write
//!   lock. What the verdict refuses, or makes wait for an owner, is not
//!   moved: 403 `move_refused`. A route that moved a scope without it would
//!   skip the boundary rules themselves;
//! - delete: `delete` on the scope;
//! - the private flag: `manage_boundaries` on the scope, and the narrow-only
//!   rule: letting inheritance in gives no one more than the caller holds;
//! - a page below a scope or org: `read_audit` or `manage_access` there.
//!
//! The path of a scope is always the store's, never the caller's: a body
//! names a parent, and the parent's own path follows.

use axum::http::StatusCode;
use tutela_contracts::audit::Actor;
use tutela_contracts::decision::Effect;
use tutela_contracts::principal::Principal;
use tutela_pdp::{Attrs, LinksFrom, MoveRule, OnLooser, PathEntry, ResourceRef, WriteCheckRequest};
use tutela_sdk::Identity;

use super::bindings::{
    Change, caller, finish, look_at, page, parse_scope, scope_text, without_key,
};
use super::boundaries::scope;
use super::locked::{self, Before};
use super::wire::{
    MoveScopeBody, PrivateBody, PutScopeBody, RevOut, ScopeBody, ScopeChangeOut, ScopeOut,
    ScopeRef, ScopesOut, ScopesQuery,
};
use super::{refused, required, store_problem};
use crate::api::{AppState, Problem};
use crate::audit::{self, Record};
use crate::authz::{is_service, pdp_problem};
use crate::tenant::Tenant;

fn invalid(detail: &str) -> Problem {
    Problem::invalid("invalid_request", detail.to_owned())
}

fn reference(e: &PathEntry) -> ScopeRef {
    ScopeRef {
        kind: e.type_name.to_string(),
        id: e.id.to_string(),
    }
}

fn out(info: &tutela_store::ScopeInfo) -> ScopeOut {
    let b = &info.boundary;
    let moves = |r: Option<MoveRule>| {
        r.map(|r| {
            match r {
                MoveRule::Members => "members",
                MoveRule::Owners => "owners",
                MoveRule::Nobody => "none",
            }
            .to_owned()
        })
    };
    ScopeOut {
        scope: reference(&info.scope),
        ancestors: info.ancestors.iter().map(reference).collect(),
        private: info.private,
        moves_out: moves(b.moves_out),
        moves_in: moves(b.moves_in),
        on_looser: b.on_looser.map(|r| {
            match r {
                OnLooser::Approve => "approve",
                OnLooser::Block => "block",
            }
            .to_owned()
        }),
        links_from: b.links_from.map(|r| {
            match r {
                LinksFrom::Any => "any",
                LinksFrom::Team => "team",
                LinksFrom::Nobody => "none",
            }
            .to_owned()
        }),
    }
}

/// The path below `parent`: the parent first, then its own stored path.
fn under(before: &Before, tenant: &Tenant, parent: &PathEntry) -> Result<Vec<PathEntry>, Problem> {
    let mut path = vec![parent.clone()];
    path.extend(locked::path(before, tenant.key(), parent)?);
    Ok(path)
}

/// A scope's state as the store holds it after a change, from the data
/// `before` and what the change set.
fn after_change(
    before: &Before,
    scope: &PathEntry,
    ancestors: Vec<PathEntry>,
    private: bool,
) -> ScopeOut {
    out(&tutela_store::ScopeInfo {
        scope: scope.clone(),
        ancestors,
        private,
        boundary: before
            .bundle
            .data
            .boundaries
            .get(scope)
            .copied()
            .unwrap_or_default(),
    })
}

/// `POST /v1/admin/scopes`: registers a scope of the product's tree under
/// its parent, private when the body says so or, without a word, when its
/// type starts private.
///
/// # Errors
///
/// A [`Problem`]: 400 for a type that is not a container of the model or
/// may not sit under the parent's type, 404 for an unknown parent, 409
/// `exists` for a registered scope, 403 without `write` on the parent.
pub async fn put(
    state: &AppState,
    id: &Identity,
    body: PutScopeBody,
) -> Result<ScopeChangeOut, Problem> {
    let tenant = Tenant::of(id);
    let at = scope(body.scope)?;
    let parent = required(body.parent, "parent").and_then(|p| scope(Some(p)))?;
    if at.is_org() {
        return Err(invalid("an org is made with `POST /v1/admin/orgs`"));
    }
    let action = "tutela_scope:create";
    let what = scope_text(&at);
    let resource = ("tutela_scope", what.as_str());
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    let def = before
        .model
        .types()
        .get(&at.type_name)
        .filter(|d| d.container)
        .ok_or_else(|| invalid("the scope's type is not a container of the tenant's model"))?;
    if !def.parents.contains(&parent.type_name) {
        return Err(invalid(
            "the model does not let the scope's type sit under the parent's type",
        ));
    }
    let private = body
        .private
        .unwrap_or(def.starts == tutela_pdp::model::Starts::Private);
    let ancestors = under(&before, &tenant, &parent)?;
    let decision = locked::decide(&before, tenant.key(), &who, &parent, "write")?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let rev = tutela_store::put_scope(&tx, tenant.key(), &at, &ancestors, private)
        .await
        .map_err(store_problem)?;
    let shown = after_change(&before, &at, ancestors, private);
    let record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .allowed(rev)
        .rules(&decision.rule_ids)
        .detail("scope", what.clone())
        .detail("parent", scope_text(&parent))
        .detail("private", private)
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
    tracing::info!(rev, "a scope was registered");
    Ok(ScopeChangeOut { scope: shown, rev })
}

fn entries(path: &[PathEntry]) -> Vec<String> {
    path.iter().map(scope_text).collect()
}

/// 403 `move_refused`: the verdict did not allow the move. The detail says
/// how it ended and, for a move that waits, the scopes whose owner must
/// agree.
fn move_refused(m: Option<&tutela_pdp::MoveDecision>) -> Problem {
    let detail = m.map_or_else(
        || "the item may not be written".to_owned(),
        |m| {
            let outcome = match m.outcome {
                tutela_pdp::MoveOutcome::Allowed => "allowed",
                tutela_pdp::MoveOutcome::NeedsApproval => "needs_approval",
                tutela_pdp::MoveOutcome::Refused => "refused",
            };
            let mut d = format!("{outcome}: {}", m.reason);
            if !m.approve_at.is_empty() {
                d.push_str(&format!(
                    "; an owner must agree at {}",
                    entries(&m.approve_at).join(", ")
                ));
            }
            d
        },
    );
    Problem {
        detail: Some(detail),
        ..Problem::new(
            StatusCode::FORBIDDEN,
            "move_refused",
            "the move is not allowed",
        )
    }
}

/// `POST /v1/admin/scopes/move`: moves a registered scope, and every scope
/// below it, under a new parent, when the move verdict of `write_check`
/// allows it for the caller (PERMISSION-MODEL.md 10.1). The verdict and the
/// move run on one read of the tenant, under its write lock, so nothing can
/// change between them.
///
/// # Errors
///
/// A [`Problem`]: 400 for an org or a path the store refuses, 404 for an
/// unknown scope or parent, 403 `forbidden` for `approved_by` from a person,
/// 403 `move_refused` for a move the verdict refuses or makes wait.
pub async fn move_scope(
    state: &AppState,
    id: &Identity,
    body: MoveScopeBody,
) -> Result<ScopeChangeOut, Problem> {
    let tenant = Tenant::of(id);
    let at = scope(body.scope)?;
    let parent = required(body.parent, "parent").and_then(|p| scope(Some(p)))?;
    if at.is_org() {
        return Err(invalid("an org has no parent"));
    }
    let approved_by = body
        .approved_by
        .unwrap_or_default()
        .iter()
        .map(|p| {
            p.parse::<Principal>()
                .map_err(|_| invalid("`approved_by` holds principals"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let action = "tutela_scope:move";
    let what = scope_text(&at);
    let resource = ("tutela_scope", what.as_str());
    let who = caller(state, id, &tenant, action, resource).await?;
    if !approved_by.is_empty() && !is_service(id) {
        // Only a service speaks for its users' approvals (CONTRACTS.md 7.8).
        return Err(refused(state, id, &tenant, action, resource, Problem::forbidden()).await);
    }
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    let old = locked::path(&before, tenant.key(), &at)?;
    let new = under(&before, &tenant, &parent)?;
    let names: Vec<String> = approved_by.iter().map(ToString::to_string).collect();
    let verdict = before
        .pdp
        .write_check(&WriteCheckRequest {
            tenant: tenant.key().clone(),
            subject: who.clone(),
            actors: Vec::new(),
            resource: ResourceRef {
                type_name: at.type_name.clone(),
                id: at.id.clone(),
                path: old.clone(),
                attrs: Attrs::new(),
            },
            new_attrs: Attrs::new(),
            new_path: Some(new.clone()),
            new_links: Vec::new(),
            approved_by,
            at_least_revision: None,
        })
        .map_err(|e| pdp_problem(&e))?;
    let moved = verdict.moved.as_ref();
    let mut record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .detail("scope", what.clone())
        .detail("from", entries(&old))
        .detail("to", entries(&new))
        .detail("approved_by", names);
    if let Some(m) = moved {
        record = record.rules(&m.rule_ids).detail(
            "move",
            serde_json::json!({
                "outcome": m.outcome,
                "left": entries(&m.left),
                "entered": entries(&m.entered),
                "looser": m.looser,
                "complete": m.complete,
                "approve_at": entries(&m.approve_at),
            }),
        );
    }
    if verdict.effect != Effect::Allow {
        drop(tx);
        let p = move_refused(moved);
        let rev = before.bundle.rev;
        audit::write_alone(state, &tenant, vec![record.denied(rev, "move_refused")]).await?;
        return Err(p);
    }
    let rev = tutela_store::move_scope(&tx, tenant.key(), &at, &new)
        .await
        .map_err(store_problem)?;
    let private = before.bundle.data.private_scopes.contains(&at);
    let shown = after_change(&before, &at, new, private);
    audit::write(state, &tx, vec![record.allowed(rev).detail("rev", rev)]).await?;
    tx.commit().await?;
    tracing::info!(rev, "a scope was moved");
    Ok(ScopeChangeOut { scope: shown, rev })
}

/// `POST /v1/admin/scopes/delete`: the scope and every registered scope
/// below it, with their assignments and rules, in one revision.
///
/// # Errors
///
/// A [`Problem`]: 400 for an org, 404 for an unknown scope, 403 without
/// `delete` on it.
pub async fn delete(state: &AppState, id: &Identity, body: ScopeBody) -> Result<RevOut, Problem> {
    let tenant = Tenant::of(id);
    let at = scope(body.scope)?;
    if at.is_org() {
        return Err(invalid(
            "an org is deleted with `DELETE /v1/admin/orgs/{org}`",
        ));
    }
    let action = "tutela_scope:delete";
    let what = scope_text(&at);
    let resource = ("tutela_scope", what.as_str());
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    let decision = locked::decide(&before, tenant.key(), &who, &at, "delete")?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let rev = tutela_store::delete_scope(&tx, tenant.key(), &at)
        .await
        .map_err(store_problem)?;
    let record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .allowed(rev)
        .rules(&decision.rule_ids)
        .detail("scope", what.clone())
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
    tracing::info!(rev, "a scope was deleted");
    Ok(RevOut { rev })
}

/// `PUT /v1/admin/scopes/private`.
///
/// # Errors
///
/// A [`Problem`]: 400 for an org, 404, 403 without `manage_boundaries` on
/// the scope, 403 `not_held` when letting inheritance in gives someone more
/// than the caller holds.
pub async fn set_private(
    state: &AppState,
    id: &Identity,
    body: PrivateBody,
) -> Result<RevOut, Problem> {
    let tenant = Tenant::of(id);
    let at = scope(body.scope)?;
    let private = required(body.private, "private")?;
    if at.is_org() {
        return Err(invalid("an org is never private"));
    }
    let action = "tutela_scope:update";
    let what = scope_text(&at);
    let resource = ("tutela_scope", what.as_str());
    let who = caller(state, id, &tenant, action, resource).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = locked::read(state, &tx).await?;
    let decision = locked::decide(&before, tenant.key(), &who, &at, "manage_boundaries")?;
    if !decision.is_allowed() {
        return Err(without_key(state, id, &tenant, tx, action, resource).await);
    }
    let rev = tutela_store::set_private(&tx, tenant.key(), &at, private)
        .await
        .map_err(store_problem)?;
    let record = Record::new(tenant.key(), Actor::new(who.clone()), action, resource)
        .allowed(rev)
        .rules(&decision.rule_ids)
        .detail("scope", what.clone())
        .detail("private", private)
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

/// `GET /v1/admin/scopes?under=`: a page of the registered scopes below an
/// org or a scope, by `type:id`, with their paths and rules.
///
/// # Errors
///
/// A [`Problem`]: 400 without `under`, 404 for an unknown scope, 403
/// without `read_audit` or `manage_access` there.
pub async fn list(state: &AppState, id: &Identity, q: ScopesQuery) -> Result<ScopesOut, Problem> {
    let tenant = Tenant::of(id);
    let text = required(q.under, "under")?;
    let below = parse_scope(&text, "under")?;
    let after = q
        .after
        .as_deref()
        .map(|a| parse_scope(a, "after"))
        .transpose()?;
    let limit = page(q.limit)?;
    look_at(
        state,
        id,
        &tenant,
        &below,
        "tutela_scope:read",
        ("tutela_scope", &text),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let rows = tutela_store::scope_page(&tx, tenant.key(), &below, after.as_ref(), limit)
        .await
        .map_err(store_problem)?;
    tx.commit().await?;
    let next_after = (rows.len() == limit)
        .then(|| rows.last().map(|s| scope_text(&s.scope)))
        .flatten();
    Ok(ScopesOut {
        scopes: rows.iter().map(out).collect(),
        next_after,
    })
}
