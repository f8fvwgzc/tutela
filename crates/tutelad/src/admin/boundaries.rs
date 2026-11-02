//! A scope's move and link rules (PERMISSION-MODEL.md 9, 10; CONTRACTS.md
//! 7.13.2, ADR-0040).
//!
//! **Who may ask:** the caller's own principal holds `<type>:manage_boundaries`
//! on the scope, at the path the store holds for it, on data that has just
//! been checked: an org admin for every scope, a scope owner for its own
//! (MANIFEST.md 6). The path is the store's, never the caller's, so a caller
//! cannot place a scope under one it owns to set its rules.
//!
//! `move_scope` has no route here: a move is the product's write after its
//! `write_check` (CONTRACTS.md 6.7, ADR-0025 item 8), and a route that moved
//! a scope without that check would skip the boundary rules themselves.

use tutela_contracts::audit::Actor;
use tutela_contracts::keys::{ActionKey, ResourceId, ResourceType};
use tutela_pdp::{
    Attrs, BoundaryRule, CheckRequest, LinksFrom, MoveRule, OnLooser, PathEntry, ResourceRef,
};
use tutela_sdk::Identity;

use super::wire::{BoundaryBody, RevOut, ScopeRef};
use super::{refused, required, store_problem};
use crate::api::{AppState, Problem};
use crate::audit::{self, Record};
use crate::authz::floor;
use crate::cache::ActionClass;
use crate::tenant::Tenant;

fn invalid(detail: &str) -> Problem {
    Problem::invalid("invalid_request", detail.to_owned())
}

fn move_rule(v: Option<&str>, name: &str) -> Result<Option<MoveRule>, Problem> {
    v.map(|t| match t {
        "members" => Ok(MoveRule::Members),
        "owners" => Ok(MoveRule::Owners),
        "none" => Ok(MoveRule::Nobody),
        _ => Err(invalid(&format!("`{name}` is members, owners or none"))),
    })
    .transpose()
}

/// The rule of a body.
fn rule(b: &BoundaryBody) -> Result<BoundaryRule, Problem> {
    Ok(BoundaryRule {
        moves_out: move_rule(b.moves_out.as_deref(), "moves_out")?,
        moves_in: move_rule(b.moves_in.as_deref(), "moves_in")?,
        on_looser: b
            .on_looser
            .as_deref()
            .map(|t| match t {
                "approve" => Ok(OnLooser::Approve),
                "block" => Ok(OnLooser::Block),
                _ => Err(invalid("`on_looser` is approve or block")),
            })
            .transpose()?,
        links_from: b
            .links_from
            .as_deref()
            .map(|t| match t {
                "any" => Ok(LinksFrom::Any),
                "team" => Ok(LinksFrom::Team),
                "none" => Ok(LinksFrom::Nobody),
                _ => Err(invalid("`links_from` is any, team or none")),
            })
            .transpose()?,
    })
}

/// A scope of a body.
pub(crate) fn scope(s: Option<ScopeRef>) -> Result<PathEntry, Problem> {
    let s = required(s, "scope")?;
    let kind =
        ResourceType::parse(&s.kind).map_err(|_| invalid("`scope.type` is not a type name"))?;
    let id = ResourceId::parse(&s.id).map_err(|_| invalid("`scope.id` is not a resource id"))?;
    Ok(PathEntry::new(kind, id))
}

/// `PUT /v1/admin/boundaries`: replaces the move and link rules of a
/// registered scope. The store bumps the revision and emits
/// `tutela.permissions.changed.v1` in the same transaction.
///
/// # Errors
///
/// A [`Problem`]: 400 for an org (it has no rules), 404 for a scope that is
/// not registered, 403 without `manage_boundaries` on it.
pub async fn set_boundary(
    state: &AppState,
    id: &Identity,
    body: BoundaryBody,
) -> Result<RevOut, Problem> {
    let tenant = Tenant::of(id);
    let scope = scope(body.scope.clone())?;
    let rule = rule(&body)?;
    if scope.is_org() {
        return Err(invalid("an org has no boundary rule"));
    }
    let action = "tutela_boundary:write";
    let what = format!("{}:{}", scope.type_name, scope.id);
    let resource = ("tutela_boundary", what.as_str());
    let Some(who) = crate::models::principal(id, |acr| state.audiences.is_step_up(acr)).cloned()
    else {
        return Err(refused(state, id, &tenant, action, resource, Problem::forbidden()).await);
    };
    // The path is the store's.
    let path = {
        let mut conn = state.db.conn().await?;
        let tx = conn.begin(&tenant).await?;
        let path = tutela_store::ancestors(&tx, tenant.key(), &scope).await?;
        tx.commit().await?;
        path.ok_or_else(|| {
            Problem::new(
                axum::http::StatusCode::NOT_FOUND,
                "not_found",
                "no such registered scope",
            )
        })?
    };
    let org = path
        .last()
        .and_then(PathEntry::org_id)
        .ok_or_else(|| Problem::stale("unavailable"))?;
    let need = floor(id, None);
    let view = state
        .cache
        .view(&tenant, need)
        .await
        .map_err(Problem::from)?;
    let snapshot = view.for_class(ActionClass::Admin).map_err(Problem::from)?;
    let key = ActionKey::parse(&format!("{}:manage_boundaries", scope.type_name))
        .map_err(|_| Problem::stale("unavailable"))?;
    let decision = snapshot
        .pdp
        .check(&CheckRequest {
            tenant: tenant.key().clone(),
            subject: who.clone(),
            actors: Vec::new(),
            action: key,
            resource: ResourceRef {
                type_name: scope.type_name.clone(),
                id: scope.id.clone(),
                path: path.clone(),
                attrs: Attrs::new(),
            },
            fields: Some(Vec::new()),
            at_least_revision: need,
        })
        .map_err(|_| Problem::stale("unavailable"))?;
    if !decision.is_allowed() {
        return Err(refused(state, id, &tenant, action, resource, Problem::forbidden()).await);
    }
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let rev = tutela_store::set_boundary(&tx, tenant.key(), &scope, &rule)
        .await
        .map_err(store_problem)?;
    let text = |r: Option<&str>| r.map(str::to_owned);
    audit::write(
        state,
        &tx,
        vec![
            Record::new(tenant.key(), Actor::new(who), action, resource)
                .allowed(rev)
                .org(org)
                .rules(&decision.rule_ids)
                .detail("scope_type", scope.type_name.to_string())
                .detail("scope_id", scope.id.to_string())
                .detail("moves_out", text(body.moves_out.as_deref()))
                .detail("moves_in", text(body.moves_in.as_deref()))
                .detail("on_looser", text(body.on_looser.as_deref()))
                .detail("links_from", text(body.links_from.as_deref()))
                .detail("rev", rev),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::info!(rev, "a scope's boundary rules were set");
    Ok(RevOut { rev })
}
