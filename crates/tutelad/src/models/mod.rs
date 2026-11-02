//! Model versions over the API (CONTRACTS.md 7.10, ADR-0026).
//!
//! A tenant's model is its own: a publish here writes one tenant's version
//! and bumps one tenant's revision, so the cache picks it up as it picks up
//! any change. Every function takes the verified [`Identity`]; the tenant
//! comes from it and from nowhere else.
//!
//! **Who may ask.** These calls show or change what every role of a tenant
//! means, so they need admin keys at every org of the tenant, read from
//! data that has just been checked: `read_audit` to look, `manage_access` and
//! `manage_fields` to change. An agent never holds an admin key, and a
//! delegated or an external token never passes one on.

pub mod http;
pub mod wire;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use tutela_contracts::keys::{ActionKey, ResourceId, ResourceType};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_pdp::model::{Model, ModelDiff, diff};
use tutela_pdp::{Attrs, CheckRequest, ResourceRef};
use tutela_sdk::Identity;
use tutela_store::approval;
use tutela_store::{ActiveModel, StoreError, StoreErrorKind, TenantBundle, TenantPublish};

use crate::api::{AppState, Problem};
use crate::authz::floor;
use crate::cache::ActionClass;
use crate::tenant::Tenant;
use wire::{ActiveOut, PublishBody, PublishResult, VersionOut, VersionsOut};

/// What looking at a tenant's model needs, at every org.
pub const READ_KEYS: [&str; 1] = ["read_audit"];

/// What changing a tenant's model needs, at every org.
pub const WRITE_KEYS: [&str; 2] = ["manage_access", "manage_fields"];

fn conflict(code: &'static str, title: &'static str) -> Problem {
    Problem::new(StatusCode::CONFLICT, code, title)
}

/// Counts how a call ended. The label says what kind of end it was, and
/// holds no tenant and no principal.
pub(crate) fn observed<T>(
    state: &AppState,
    op: &'static str,
    r: Result<T, Problem>,
) -> Result<T, Problem> {
    let outcome = match &r {
        Ok(_) => "ok",
        Err(p) => match (p.status.as_u16(), p.code) {
            (403, "forbidden") => "forbidden",
            (403, _) => "refused",
            (409, "stale_proposal") => "stale",
            (409, _) => "conflict",
            (400 | 404 | 413 | 415, _) => "invalid",
            _ => "error",
        },
    };
    state.metrics.count_model(op, outcome);
    r
}

/// The person or service behind a token. A delegated token and an external
/// one have no right here: admin keys never pass through delegation.
fn principal(id: &Identity) -> Option<&Principal> {
    match id {
        Identity::Access(c)
            if matches!(
                c.sub.kind(),
                PrincipalKind::User | PrincipalKind::ServiceAccount | PrincipalKind::Key
            ) =>
        {
            Some(&c.sub)
        }
        _ => None,
    }
}

/// The caller, if it holds every one of `keys` at every org of its tenant,
/// on data that has just been checked. A tenant with no org has no admin.
///
/// # Errors
///
/// 403 `forbidden`, or the 503 of a view that cannot be had.
pub(crate) async fn admin(
    state: &AppState,
    id: &Identity,
    tenant: &Tenant,
    keys: &[&str],
) -> Result<Principal, Problem> {
    let who = principal(id).ok_or_else(Problem::forbidden)?.clone();
    let need = floor(id, None);
    let view = state
        .cache
        .view(tenant, need)
        .await
        .map_err(Problem::from)?;
    let snapshot = view.for_class(ActionClass::Admin).map_err(Problem::from)?;
    let orgs = snapshot.pdp.orgs(tenant.key());
    if orgs.is_empty() {
        return Err(Problem::forbidden());
    }
    let unavailable = |_| Problem::stale("unavailable");
    for org in orgs {
        let org = ResourceId::parse(&org.to_string()).map_err(|_| Problem::stale("unavailable"))?;
        for key in keys {
            let action = ActionKey::parse(&format!("org:{key}"))
                .map_err(|_| Problem::stale("unavailable"))?;
            let decision = snapshot
                .pdp
                .check(&CheckRequest {
                    tenant: tenant.key().clone(),
                    subject: who.clone(),
                    actors: Vec::new(),
                    action,
                    resource: ResourceRef {
                        type_name: ResourceType::ORG,
                        id: org.clone(),
                        path: Vec::new(),
                        attrs: Attrs::new(),
                    },
                    fields: Some(Vec::new()),
                    at_least_revision: need,
                })
                .map_err(unavailable)?;
            if !decision.is_allowed() {
                return Err(Problem::forbidden());
            }
        }
    }
    Ok(who)
}

/// Compiles a candidate. The problems go back to the caller: it sent the
/// text, and the compiler cuts and escapes what it quotes.
pub(crate) async fn compile(source: String) -> Result<Model, Problem> {
    tokio::task::spawn_blocking(move || Model::from_toml(&source))
        .await
        .map_err(|_| Problem::stale("unavailable"))?
        .map_err(|issues| Problem::invalid("invalid_manifest", issues.to_string()))
}

/// The tenant now: one view of its data and its active model.
pub(crate) struct Current {
    #[allow(dead_code)] // the impact report reads it
    pub bundle: TenantBundle,
    pub active: ActiveModel,
    pub model: Arc<Model>,
}

pub(crate) async fn current(state: &AppState, tenant: &Tenant) -> Result<Current, Problem> {
    let (bundle, active) = state.cache.read(tenant).await.map_err(Problem::from)?;
    let model = state
        .cache
        .compiled(active.source.clone(), &active.digest)
        .await
        .map_err(Problem::from)?;
    Ok(Current {
        bundle,
        active,
        model,
    })
}

/// The diff from the active model, as the store keeps it.
pub(crate) fn diff_of(old: &Model, new: &Model) -> Result<(ModelDiff, String), Problem> {
    let d = diff(old, new).map_err(|_| {
        Problem::invalid(
            "app_mismatch",
            "the model belongs to another app".to_owned(),
        )
    })?;
    let mut text = String::new();
    for c in d.changes() {
        text.push_str(&c.to_string());
        text.push('\n');
    }
    if d.omitted() > 0 {
        text.push_str(&format!("and {} more\n", d.omitted()));
    }
    Ok((d, text))
}

/// The text of a publish: what the caller sent, or a kept version.
pub(crate) async fn candidate_text(
    state: &AppState,
    tenant: &Tenant,
    source: Option<String>,
    restore: Option<i64>,
) -> Result<(String, Option<i64>), Problem> {
    match (source, restore) {
        (Some(s), None) => Ok((s, None)),
        (None, Some(v)) => {
            let mut conn = state.db.conn().await?;
            let tx = conn.begin(tenant).await?;
            let found = tutela_store::model_version(&tx, tenant.key(), v).await?;
            tx.commit().await?;
            let found = found.ok_or_else(not_found)?;
            let text = found.source.ok_or_else(|| {
                conflict(
                    "no_source",
                    "this version is from before texts were kept, so it cannot be restored",
                )
            })?;
            Ok((text, Some(v)))
        }
        _ => Err(Problem::invalid(
            "invalid_request",
            "send `source` or `restore`, one of them".to_owned(),
        )),
    }
}

fn not_found() -> Problem {
    Problem::new(StatusCode::NOT_FOUND, "not_found", "no such model version")
}

fn refused(detail: String) -> Problem {
    Problem {
        detail: Some(detail),
        ..Problem::new(
            StatusCode::FORBIDDEN,
            "approval_required",
            "a widening change needs an approval token",
        )
    }
}

/// Checks an approval token for exactly this change in this tenant. Returns
/// the approver key's id. A token bound to no tenant approves nothing here:
/// the same change can mean something else in another tenant.
pub(crate) async fn approved(
    state: &AppState,
    tenant: &Tenant,
    token: Option<&str>,
    app: &str,
    from: &str,
    to: &str,
) -> Result<String, Problem> {
    let token = token.ok_or_else(|| refused(format!("from {from} to {to}")))?;
    let bad = |e: approval::ApprovalError| refused(e.to_string());
    let kid = approval::peek(token).map_err(bad)?.kid;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(tenant).await?;
    let key = tutela_store::approver(&tx, &kid).await?;
    tx.commit().await?;
    let key = key.ok_or_else(|| bad(approval::ApprovalError::UnknownKey))?;
    if key.revoked {
        return Err(bad(approval::ApprovalError::RevokedKey));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let tid = tenant.key().tid.to_string();
    approval::verify(token, &key.public_key, app, from, to, Some(&tid), now).map_err(bad)?;
    Ok(kid)
}

fn store_conflict(e: StoreError) -> Problem {
    if e.kind() == StoreErrorKind::Exists {
        return conflict("version_conflict", "a newer model; compare again");
    }
    e.into()
}

/// `POST /v1/models/publish`: a new version, from new text or from a kept
/// version. A rollback is this same call, so it passes the same checks.
///
/// # Errors
///
/// A [`Problem`].
pub async fn publish(
    state: &AppState,
    id: &Identity,
    body: PublishBody,
) -> Result<PublishResult, Problem> {
    let tenant = Tenant::of(id);
    let actor = admin(state, id, &tenant, &WRITE_KEYS).await?;
    let expected = body.expected_version.ok_or_else(|| {
        Problem::invalid(
            "invalid_request",
            "`expected_version` is missing".to_owned(),
        )
    })?;
    let (source, restores) = candidate_text(state, &tenant, body.source, body.restore).await?;
    let candidate = compile(source.clone()).await?;
    let now = current(state, &tenant).await?;
    if now.active.version != expected {
        return Err(conflict("version_conflict", "a newer model; compare again"));
    }
    let to = tutela_store::digest(&source);
    if to == now.active.digest {
        return Err(conflict("no_change", "this is the active model"));
    }
    let (d, text) = diff_of(&now.model, &candidate)?;
    let mut approvers = Vec::new();
    if d.is_widening() {
        let app = candidate.app().as_str();
        let kid = approved(
            state,
            &tenant,
            body.approval.as_deref(),
            app,
            &now.active.digest,
            &to,
        )
        .await?;
        approvers.push(kid);
    }
    let author = actor.to_string();
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let (version, rev) = tutela_store::publish_tenant_model(
        &tx,
        tenant.key(),
        &TenantPublish {
            app: candidate.app(),
            source: &source,
            expected,
            class: d.class(),
            diff: &text,
            impact: None,
            author: Some(&author),
            approvers: &approvers,
            restores,
        },
    )
    .await
    .map_err(store_conflict)?;
    tx.commit().await?;
    tracing::info!(version, rev, class = %d.class(), "a model was published");
    Ok(PublishResult {
        version,
        rev,
        digest: to,
        class: d.class().as_str().to_ascii_lowercase(),
        restores,
    })
}

/// `GET /v1/models`: the active model, and a page of what came before.
///
/// # Errors
///
/// A [`Problem`].
pub async fn versions(
    state: &AppState,
    id: &Identity,
    before: Option<i64>,
    limit: Option<usize>,
) -> Result<VersionsOut, Problem> {
    let tenant = Tenant::of(id);
    admin(state, id, &tenant, &READ_KEYS).await?;
    let limit = limit.unwrap_or(tutela_store::MAX_VERSION_PAGE);
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let active = tutela_store::active_model(&tx, tenant.key())
        .await?
        .ok_or_else(|| Problem::stale("no_data"))?;
    let page = tutela_store::model_versions(&tx, tenant.key(), before, limit).await?;
    tx.commit().await?;
    let next_before = (page.len() >= limit.clamp(1, tutela_store::MAX_VERSION_PAGE))
        .then(|| page.last().map(|v| v.version))
        .flatten();
    Ok(VersionsOut {
        active: ActiveOut {
            version: active.version,
            digest: active.digest,
            own: active.own,
        },
        versions: page.into_iter().map(VersionOut::of).collect(),
        next_before,
    })
}

/// `GET /v1/models/{version}`, with its text.
///
/// # Errors
///
/// A [`Problem`]. 404 for a version this tenant does not have.
pub async fn version(state: &AppState, id: &Identity, version: i64) -> Result<VersionOut, Problem> {
    let tenant = Tenant::of(id);
    admin(state, id, &tenant, &READ_KEYS).await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let found = tutela_store::model_version(&tx, tenant.key(), version).await?;
    tx.commit().await?;
    found.map(VersionOut::of).ok_or_else(not_found)
}
