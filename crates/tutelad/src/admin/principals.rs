//! Agent principals and people (CONTRACTS.md 7.13.1, ADR-0040).
//!
//! attache registers its agents here, quarantines them by disabling them and
//! enables them again (INTEGRATION.md, attache step 5); the Console disables
//! people and revokes their sessions. Each change raises what it must in the
//! store (`tutela_store::set_disabled`, `revoke_sessions`), which emits the
//! event of CONTRACTS.md 8.3 in the same transaction, and is recorded here
//! with who asked.
//!
//! **Who may ask:** `manage_agents` at every org of the tenant for an agent,
//! `manage_access` at every org for a person. An agent lives in the whole
//! tenant, not in one org, so one org's admin must not reach it.

use tutela_contracts::audit::Actor;
use tutela_contracts::principal::{Principal, PrincipalKind, WorkloadId};
use tutela_sdk::Identity;
use tutela_store::PrincipalState;

use super::wire::{
    AgentsOut, AgentsQuery, PrincipalBody, PrincipalOut, RegisterAgentBody, SetDisabledBody,
};
use super::{guard, required, store_problem};
use crate::api::{AppState, Problem};
use crate::audit::{self, Record};
use crate::tenant::Tenant;

/// What managing an agent needs, at every org.
pub const AGENT_KEYS: [&str; 1] = ["manage_agents"];

/// What managing a person needs, at every org.
pub const PEOPLE_KEYS: [&str; 1] = ["manage_access"];

/// The default page of agents.
const PAGE: usize = 100;

fn invalid(detail: &str) -> Problem {
    Problem::invalid("invalid_request", detail.to_owned())
}

/// The principal a body names: a user or an agent.
fn target(text: Option<String>) -> Result<Principal, Problem> {
    let text = required(text, "principal")?;
    let p: Principal = text
        .parse()
        .map_err(|_| invalid("`principal` is not a principal string"))?;
    match p.kind() {
        PrincipalKind::User | PrincipalKind::Agent => Ok(p),
        _ => Err(invalid("only a user or an agent principal is managed here")),
    }
}

/// The keys a change to `p` needs.
const fn keys_for(p: &Principal) -> &'static [&'static str] {
    match p.kind() {
        PrincipalKind::Agent => &AGENT_KEYS,
        _ => &PEOPLE_KEYS,
    }
}

fn workload(text: Option<String>) -> Result<Option<WorkloadId>, Problem> {
    text.filter(|w| !w.is_empty())
        .map(|w| WorkloadId::parse(&w))
        .transpose()
        .map_err(|_| invalid("`workload` is not a SPIFFE id"))
}

fn not_found() -> Problem {
    Problem::new(
        axum::http::StatusCode::NOT_FOUND,
        "not_found",
        "no such principal in this tenant",
    )
}

/// `POST /v1/admin/agents`: a new agent of the caller's tenant, with the
/// workload it runs as. `tutelad` makes its id (CONTRACTS.md 1.2). No
/// revision moves: with no assignment, a new agent holds nothing.
///
/// # Errors
///
/// A [`Problem`]: 400 for a workload that is not on attache's path, 409
/// `exists` for a workload another agent has.
pub async fn register_agent(
    state: &AppState,
    id: &Identity,
    body: RegisterAgentBody,
) -> Result<PrincipalOut, Problem> {
    let tenant = Tenant::of(id);
    let workload = workload(body.workload)?;
    let action = "tutela_principal:register";
    let by = guard(
        state,
        id,
        &tenant,
        &AGENT_KEYS,
        action,
        ("tutela_principal", "agent"),
    )
    .await?;
    let uuid = tutela_contracts::id::Uuid7::from_uuid(uuid::Uuid::now_v7())
        .map_err(|_| Problem::stale("unavailable"))?;
    let agent: Principal = format!("agent:agt_{uuid}")
        .parse()
        .map_err(|_| Problem::stale("unavailable"))?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    tutela_store::register_agent(&tx, tenant.key(), &agent, workload.as_ref())
        .await
        .map_err(store_problem)?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    let name = agent.to_string();
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
            .detail("workload", workload.as_ref().map(ToString::to_string)),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::info!("an agent was registered");
    Ok(PrincipalOut {
        principal: name,
        epoch: 0,
        disabled: false,
        workload: workload.map(|w| w.to_string()),
        rev: None,
    })
}

/// `GET /v1/admin/agents`: the tenant's agents, by principal, or the one of
/// a workload.
///
/// # Errors
///
/// A [`Problem`].
pub async fn agents(state: &AppState, id: &Identity, q: AgentsQuery) -> Result<AgentsOut, Problem> {
    let tenant = Tenant::of(id);
    let after = q
        .after
        .filter(|a| !a.is_empty())
        .map(|a| a.parse::<Principal>())
        .transpose()
        .map_err(|_| invalid("`after` is not a principal string"))?;
    let workload = workload(q.workload)?;
    guard(
        state,
        id,
        &tenant,
        &AGENT_KEYS,
        "tutela_principal:list",
        ("tutela_principal", "agents"),
    )
    .await?;
    let limit = q
        .limit
        .unwrap_or(PAGE)
        .clamp(1, tutela_store::MAX_AGENT_PAGE);
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let found = match &workload {
        Some(w) => tutela_store::agent_for_workload(&tx, tenant.key(), w)
            .await?
            .into_iter()
            .collect(),
        None => tutela_store::agents(&tx, tenant.key(), after.as_ref(), limit).await?,
    };
    tx.commit().await?;
    let next_after = (workload.is_none() && found.len() >= limit)
        .then(|| found.last().map(|s| s.principal.to_string()))
        .flatten();
    Ok(AgentsOut {
        agents: found.iter().map(|s| PrincipalOut::of(s, None)).collect(),
        next_after,
    })
}

/// What the store knows of `p` in the caller's tenant. An agent must be
/// registered here; a person may have no row yet (a person of a trusted
/// Tutela-format issuer is enabled at epoch 0 until changed).
async fn known(
    tx: &crate::db::TenantTx<'_>,
    tenant: &Tenant,
    p: &Principal,
) -> Result<PrincipalState, Problem> {
    match tutela_store::principal_state(tx, tenant.key(), p).await? {
        Some(s) => Ok(s),
        None if p.kind() == PrincipalKind::User => Ok(PrincipalState {
            principal: p.clone(),
            epoch: 0,
            disabled: false,
            workload: None,
        }),
        None => Err(not_found()),
    }
}

/// `POST /v1/admin/principals/state`: one principal of the tenant.
///
/// # Errors
///
/// A [`Problem`]: 404 for an agent this tenant has not registered.
pub async fn principal(
    state: &AppState,
    id: &Identity,
    body: PrincipalBody,
) -> Result<PrincipalOut, Problem> {
    let tenant = Tenant::of(id);
    let p = target(body.principal)?;
    let name = p.to_string();
    guard(
        state,
        id,
        &tenant,
        keys_for(&p),
        "tutela_principal:read",
        ("tutela_principal", &name),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let s = known(&tx, &tenant, &p).await?;
    tx.commit().await?;
    Ok(PrincipalOut::of(&s, None))
}

/// `POST /v1/admin/principals/disabled`: disables a principal (attache's
/// quarantine of an agent), or enables it again. Disabling raises its
/// epoch, so enabling never brings an old token back; both bump the
/// revision and emit `tutela.principal.disabled.v1` or `.enabled.v1`.
///
/// # Errors
///
/// A [`Problem`]: 404 for an agent this tenant has not registered.
pub async fn set_disabled(
    state: &AppState,
    id: &Identity,
    body: SetDisabledBody,
) -> Result<PrincipalOut, Problem> {
    let tenant = Tenant::of(id);
    let p = target(body.principal)?;
    let disabled = required(body.disabled, "disabled")?;
    let name = p.to_string();
    let action = if disabled {
        "tutela_principal:disable"
    } else {
        "tutela_principal:enable"
    };
    let by = guard(
        state,
        id,
        &tenant,
        keys_for(&p),
        action,
        ("tutela_principal", &name),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = known(&tx, &tenant, &p).await?;
    let epoch = tutela_store::set_disabled(&tx, tenant.key(), &p, disabled)
        .await
        .map_err(store_problem)?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
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
    tracing::info!(disabled, epoch, rev, "a principal was disabled or enabled");
    Ok(PrincipalOut::of(
        &PrincipalState {
            epoch,
            disabled,
            ..before
        },
        Some(rev),
    ))
}

/// `POST /v1/admin/principals/revoke-sessions`: raises the epoch, so every
/// token the principal holds is refused. For a person it emits
/// `tutela.session.revoked.v1`; an agent has no sessions, and its issued
/// delegated tokens end with their life (disable it to stop them at once).
///
/// # Errors
///
/// A [`Problem`]: 404 for an agent this tenant has not registered.
pub async fn revoke_sessions(
    state: &AppState,
    id: &Identity,
    body: PrincipalBody,
) -> Result<PrincipalOut, Problem> {
    let tenant = Tenant::of(id);
    let p = target(body.principal)?;
    let name = p.to_string();
    let action = "tutela_principal:revoke_sessions";
    let by = guard(
        state,
        id,
        &tenant,
        keys_for(&p),
        action,
        ("tutela_principal", &name),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let before = known(&tx, &tenant, &p).await?;
    let epoch = tutela_store::revoke_sessions(&tx, tenant.key(), &p)
        .await
        .map_err(store_problem)?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
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
    tracing::info!(epoch, rev, "sessions were revoked");
    Ok(PrincipalOut::of(
        &PrincipalState { epoch, ..before },
        Some(rev),
    ))
}
