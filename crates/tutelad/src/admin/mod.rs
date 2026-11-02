//! The admin API: `tutela.admin.v1` and its HTTP routes (CONTRACTS.md 7.13,
//! ADR-0040).
//!
//! As for the decision APIs, each operation is one function here over the
//! types of [`wire`]; [`http`] and [`grpc`] only adapt. The model routes of
//! [`crate::models`] are part of this API: [`grpc`] gives them their gRPC
//! methods.
//!
//! **Which token** (ADR-0032). Every route and method takes a person's admin
//! token (`aud=tutela-admin`, after step-up) or a service's `tutela-authz`
//! token, over HTTP and over gRPC alike (`api::admin_auth`). An agent, a
//! delegated token and an external token never pass: admin keys never pass
//! through delegation.
//!
//! **Who may ask.** The admin keys of MANIFEST.md 6, on data that has just
//! been checked: at every org of the tenant for what reaches the whole
//! tenant (agents, people, the model, webhooks), and on the scope itself for
//! a scope's rules ([`boundaries`]).
//!
//! **Audit** (ADR-0034). Every call writes an audit.v1 record with who
//! asked: in the change's transaction, last; a refusal for want of a key in
//! a transaction of its own before the answer (`guard`).

pub mod apps;
pub mod bindings;
pub mod boundaries;
pub mod grpc;
pub mod http;
pub mod lifecycle;
mod locked;
pub mod principals;
pub mod scopes;
pub mod types;
pub mod webhooks;
pub mod wire;

use axum::http::StatusCode;
use tutela_contracts::principal::Principal;
use tutela_sdk::Identity;
use tutela_store::{StoreError, StoreErrorKind};

use crate::api::{AppState, Problem};
use crate::audit::{self, Record};
use crate::tenant::Tenant;

/// Counts how an admin call ended, by operation and outcome. The labels
/// hold no tenant and no principal.
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
            (404, _) => "not_found",
            (409, _) => "conflict",
            (400 | 413 | 415, _) => "invalid",
            _ => "error",
        },
    };
    state.metrics.count_admin(op, outcome);
    r
}

/// The caller, when it holds every one of `keys` at every org of its tenant
/// (`models::admin`). A refusal for want of a key is recorded first, as a
/// denied `action` on `resource` by whoever asked: an admin call is never
/// refused unseen.
///
/// # Errors
///
/// 403 `forbidden`, or a 503.
pub(crate) async fn guard(
    state: &AppState,
    id: &Identity,
    tenant: &Tenant,
    keys: &[&str],
    action: &str,
    resource: (&str, &str),
) -> Result<Principal, Problem> {
    match crate::models::admin(state, id, tenant, keys).await {
        Err(p) if p.code == "forbidden" => {
            Err(refused(state, id, tenant, action, resource, p).await)
        }
        r => r,
    }
}

/// Records `p`, a refusal of `action` on `resource`, with who asked, and
/// gives it back. A token with no principal (an external one) is refused
/// before any tenant data is read, and leaves no record.
pub(crate) async fn refused(
    state: &AppState,
    id: &Identity,
    tenant: &Tenant,
    action: &str,
    resource: (&str, &str),
    p: Problem,
) -> Problem {
    let Some(actor) = audit::actor_of(id) else {
        return p;
    };
    let reason = p.code;
    let written = audit::write_alone_now(state, tenant, |rev| {
        vec![Record::new(tenant.key(), actor, action, resource).denied(rev, reason)]
    })
    .await;
    match written {
        Ok(()) => p,
        Err(e) => e,
    }
}

/// A store refusal as the caller's problem: a missing row is 404, a row
/// that exists 409, a bad input 400. The store's texts are fixed English
/// with no value in them.
pub(crate) fn store_problem(e: StoreError) -> Problem {
    match e.kind() {
        StoreErrorKind::NotFound => Problem {
            detail: e.detail().map(str::to_owned),
            ..Problem::new(StatusCode::NOT_FOUND, "not_found", "no such thing here")
        },
        StoreErrorKind::Exists => Problem {
            detail: e.detail().map(str::to_owned),
            ..Problem::new(StatusCode::CONFLICT, "exists", "it exists already")
        },
        StoreErrorKind::Invalid => Problem::invalid(
            "invalid_request",
            e.detail().unwrap_or("the request is not valid").to_owned(),
        ),
        _ => e.into(),
    }
}

/// A required field of a body.
pub(crate) fn required<T>(v: Option<T>, name: &str) -> Result<T, Problem> {
    v.ok_or_else(|| Problem::invalid("invalid_request", format!("`{name}` is missing")))
}
