//! The two searches (CONTRACTS.md 7.4). The rules are in
//! `tutela_pdp::Pdp::search_resources` and `search_subjects`, next to the
//! evaluator, where the property tests prove them equal to `check`. This
//! file checks who asks, finds a view, and turns a cursor into a token.
//!
//! A page token is opaque to the caller. It only says where a sorted list
//! goes on, and the list is decided again on every page, so a made-up token
//! can skip results and can never add one.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use tutela_contracts::keys::ResourceId;
use tutela_contracts::principal::Principal;
use tutela_pdp::{ListFilterRequest, PathEntry, SubjectSearchRequest};
use tutela_sdk::Identity;

use super::wire::{
    self, Entry, Invalid, PageOut, ResourceContext, ResourceContextOut, ResourceResults,
    SearchBody, SubjectContext, SubjectContextOut, SubjectOut, SubjectResults,
};
use super::{floor, may_ask, may_list_subjects, pdp_problem, view};
use crate::api::{AppState, Problem};
use crate::cache::ActionClass;
use crate::telemetry::Outcome;
use crate::tenant::Tenant;

/// The default page size.
const DEFAULT_LIMIT: usize = 100;

fn limit(body: &SearchBody) -> usize {
    match body.page.as_ref().and_then(|p| p.limit) {
        None | Some(0) => DEFAULT_LIMIT,
        Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
    }
}

fn bad_token() -> Problem {
    Problem::invalid("invalid_page", "`page.token` is not valid".to_owned())
}

fn token_text(body: &SearchBody) -> Result<Option<String>, Problem> {
    let Some(token) = body.page.as_ref().and_then(|p| p.token.as_deref()) else {
        return Ok(None);
    };
    if token.is_empty() {
        return Ok(None);
    }
    let bytes = B64.decode(token).map_err(|_| bad_token())?;
    String::from_utf8(bytes).map(Some).map_err(|_| bad_token())
}

fn entry_token(e: &PathEntry) -> String {
    B64.encode(format!("{}/{}", e.type_name, e.id))
}

fn entry_of_token(text: &str) -> Result<PathEntry, Problem> {
    let (kind, id) = text.split_once('/').ok_or_else(bad_token)?;
    let kind = wire::type_name(kind).map_err(|_| bad_token())?;
    let id = ResourceId::parse(id).map_err(|_| bad_token())?;
    Ok(PathEntry::new(kind, id))
}

/// Runs `work` on a blocking thread: a search can look at thousands of
/// candidates. Fails closed if the thread dies.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Problem> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| Problem::stale("unavailable"))
}

/// `POST /access/v1/search/resource`.
///
/// # Errors
///
/// A [`Problem`]. There is never a partial list.
pub async fn search_resource(
    state: &AppState,
    id: &Identity,
    body: SearchBody,
) -> Result<ResourceResults, Problem> {
    const OP: &str = "search_resource";
    let limit = limit(&body);
    let after = token_text(&body)?
        .as_deref()
        .map(entry_of_token)
        .transpose()?;
    let subject = body.subject.ok_or(Invalid("`subject` is missing"))?;
    let action = body.action.ok_or(Invalid("`action` is missing"))?;
    let resource = body.resource.ok_or(Invalid("`resource` is missing"))?;
    let (subject, actors) = wire::principal(&subject)?;
    let action = wire::action(&action)?;
    if action.resource_type() != &wire::type_name(&resource.kind)? {
        return Err(Invalid("the action's type is not `resource.type`").into());
    }
    may_ask(id, &subject, &actors)?;

    let need = floor(id, body.context.as_ref().and_then(|c| c.at_least_revision));
    let tenant = Tenant::of(id);
    let view = view(state, OP, &tenant, need).await?;
    let class = ActionClass::of(view.model(), &action);
    let snapshot = view.shared_for_class(class).map_err(|e| {
        state.metrics.count_decision(OP, Outcome::Error);
        Problem::from(e)
    })?;
    let req = ListFilterRequest {
        tenant: tenant.key().clone(),
        subject,
        actors,
        action,
        at_least_revision: need,
    };
    let page = blocking(move || {
        snapshot
            .pdp
            .search_resources(&req, &snapshot.paths, after.as_ref(), limit)
    })
    .await?
    .map_err(|e| {
        state.metrics.count_decision(OP, Outcome::Error);
        pdp_problem(&e)
    })?;

    state.metrics.count_decision(OP, listed(page.results.len()));
    Ok(ResourceResults {
        page: PageOut {
            next_token: page.next.as_ref().map_or_else(String::new, entry_token),
            count: page.results.len(),
        },
        results: page
            .results
            .into_iter()
            .map(|e| Entry {
                kind: e.type_name.to_string(),
                id: e.id.to_string(),
            })
            .collect(),
        context: ResourceContextOut {
            tutela: ResourceContext {
                rev: page.filter.rev,
                filter: page.filter,
            },
        },
    })
}

/// A search that lists nothing is a deny.
const fn listed(results: usize) -> Outcome {
    if results == 0 {
        Outcome::Deny
    } else {
        Outcome::Allow
    }
}

/// `POST /access/v1/search/subject`.
///
/// # Errors
///
/// A [`Problem`]. There is never a partial list.
pub async fn search_subject(
    state: &AppState,
    id: &Identity,
    body: SearchBody,
) -> Result<SubjectResults, Problem> {
    const OP: &str = "search_subject";
    may_list_subjects(id)?;
    let limit = limit(&body);
    let after: Option<Principal> = token_text(&body)?
        .map(|t| t.parse().map_err(|_| bad_token()))
        .transpose()?;
    let subject = body.subject.ok_or(Invalid("`subject` is missing"))?;
    let action = body.action.ok_or(Invalid("`action` is missing"))?;
    let resource = body.resource.ok_or(Invalid("`resource` is missing"))?;
    let kind = wire::kind(&subject)?;
    let action = wire::action(&action)?;
    let resource = wire::resource(resource)?;

    let need = floor(id, body.context.as_ref().and_then(|c| c.at_least_revision));
    let tenant = Tenant::of(id);
    let view = view(state, OP, &tenant, need).await?;
    let class = ActionClass::of(view.model(), &action);
    let snapshot = view.shared_for_class(class).map_err(|e| {
        state.metrics.count_decision(OP, Outcome::Error);
        Problem::from(e)
    })?;
    let req = SubjectSearchRequest {
        tenant: tenant.key().clone(),
        kind,
        action,
        resource,
        at_least_revision: need,
    };
    let page = blocking(move || snapshot.pdp.search_subjects(&req, after.as_ref(), limit))
        .await?
        .map_err(|e| {
            state.metrics.count_decision(OP, Outcome::Error);
            pdp_problem(&e)
        })?;

    state.metrics.count_decision(OP, listed(page.results.len()));
    let next_token = page
        .next
        .as_ref()
        .map_or_else(String::new, |p| B64.encode(p.to_string()));
    Ok(SubjectResults {
        page: PageOut {
            next_token,
            count: page.results.len(),
        },
        results: page
            .results
            .into_iter()
            .map(|p| SubjectOut {
                kind: p.kind().as_str().to_owned(),
                id: p.to_string(),
            })
            .collect(),
        context: SubjectContextOut {
            tutela: SubjectContext { rev: page.rev },
        },
    })
}
