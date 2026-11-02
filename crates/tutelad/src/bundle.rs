//! `GET /v1/authz/bundle`: a tenant's data and its active model, signed by
//! the service's own issuer, for checks in a product's own process
//! (ADR-0024, ADR-0038, THREAT-MODEL.md TM-13).
//!
//! **Who may pull one.** A bundle is every assignment, group and scope path
//! of the tenant: it shows everyone's access, as the impact report does. So
//! it takes a service (`sa`, `key`) with a token of the service's own
//! audience that holds `read_audit` at every org of the tenant, on data that
//! has just been checked (ADR-0026 item 8, ADR-0027 item 8). A person, an
//! agent, a delegated or an external token gets 403: a person never needs a
//! whole tenant offline. Every pull is in the audit log.
//!
//! **What is in it.** A JWS with `typ: tutela-bundle+jwt` (never a token's
//! type), signed with `KeyRing::signer()`; claims `iss` (the service's own
//! issuer, the signer), `tid` and `tenant_iss` (the tenant key), `rev`,
//! `iat`, `exp`, `jti`, `format: 1`, `model {digest, source}` (the tenant's
//! active model, ADR-0026), `data` (`TenantData`) and `paths`.
//!
//! **How long.** `exp` is the earlier of now + `TUTELA_BUNDLE_TTL_SECS` and
//! the first assignment in it that expires (`TenantBundle::next_expiry`),
//! measured from the database's clock and counted from before the read, as
//! `cache::deadline` does: a clock that disagrees with the database cannot
//! make a bundle outlive an expired grant.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tutela_contracts::principal::PrincipalKind;
use tutela_sdk::Identity;
use tutela_sdk::bundle::{BUNDLE_FORMAT, BUNDLE_TYP};

use crate::api::{AppState, Problem};
use crate::audit::{self, Record};
use crate::tenant::Tenant;

/// The route.
pub const BUNDLE_PATH: &str = "/v1/authz/bundle";

/// When a bundle read at `started` (this clock, before the read) stops:
/// now + `ttl`, or the first expiry in it, measured from the database's
/// clock `read_at`. Whole seconds, rounded down.
#[must_use]
pub fn expires_at(
    started: SystemTime,
    ttl: Duration,
    next_expiry: Option<SystemTime>,
    read_at: SystemTime,
) -> u64 {
    let mut end = started + ttl;
    if let Some(next) = next_expiry {
        let left = next.duration_since(read_at).unwrap_or(Duration::ZERO);
        end = end.min(started + left);
    }
    end.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `GET /v1/authz/bundle`.
pub async fn bundle(State(state): State<AppState>, Extension(id): Extension<Identity>) -> Response {
    let r = pull(&state, &id).await;
    let result = match &r {
        Ok(_) => "issued",
        Err(p) if p.status == StatusCode::FORBIDDEN => "forbidden",
        Err(_) => "unavailable",
    };
    state.metrics.count_bundle(result);
    match r {
        Ok(jws) => {
            let mut res = (StatusCode::OK, jws).into_response();
            let h = res.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/jwt"),
            );
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        Err(p) => p.into_response(),
    }
}

async fn pull(state: &AppState, id: &Identity) -> Result<String, Problem> {
    let service = matches!(
        id,
        Identity::Access(c) if matches!(c.sub.kind(), PrincipalKind::ServiceAccount | PrincipalKind::Key)
    );
    if !service {
        return Err(Problem::forbidden());
    }
    let tenant = Tenant::of(id);
    let who = crate::models::admin(state, id, &tenant, &crate::models::READ_KEYS).await?;
    let started = SystemTime::now();
    let (bundle, active) = state.cache.read(&tenant).await.map_err(Problem::from)?;
    let iat = started
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let exp = expires_at(
        started,
        state.bundle_ttl,
        bundle.next_expiry,
        bundle.read_at,
    );
    if exp <= iat {
        // An assignment in it expires now: the sweep has not run yet.
        return Err(Problem::stale("stale"));
    }
    let jti = uuid::Uuid::now_v7().to_string();
    let paths: Vec<serde_json::Value> = bundle
        .paths
        .entries()
        .map(|(scope, ancestors)| serde_json::json!({ "scope": scope, "ancestors": ancestors }))
        .collect();
    let claims = serde_json::json!({
        "iss": state.keys.iss().as_str(),
        "tid": tenant.key().tid.to_string(),
        "tenant_iss": tenant.key().iss.as_str(),
        "rev": bundle.rev,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "format": BUNDLE_FORMAT,
        "model": { "digest": active.digest, "source": active.source },
        "data": bundle.data,
        "paths": paths,
    });
    let jws = state.keys.sign_jwt(BUNDLE_TYP, &claims).map_err(|e| {
        tracing::error!(error = %e, "no bundle could be signed");
        Problem::stale("unavailable")
    })?;
    // It shows everyone's access: who pulled it is recorded first.
    audit::write_alone(
        state,
        &tenant,
        vec![
            Record::new(
                tenant.key(),
                tutela_contracts::audit::Actor::new(who),
                "tutela_bundle:pull",
                ("tutela_bundle", &jti),
            )
            .allowed(bundle.rev)
            .detail("jti", jti.clone())
            .detail("rev", bundle.rev)
            .detail("exp", exp)
            .detail("model_digest", active.digest.clone()),
        ],
    )
    .await?;
    tracing::info!(rev = bundle.rev, exp, jti, "a bundle was issued");
    Ok(jws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_ends_at_the_first_expiry_on_the_database_clock() {
        let started = UNIX_EPOCH + Duration::from_secs(1_000);
        let ttl = Duration::from_secs(300);
        // No expiry: the TTL.
        assert_eq!(expires_at(started, ttl, None, started), 1_300);
        // The database runs 100 s ahead of this clock: an expiry 10 s after
        // its read is 10 s from now here, not 110.
        let read_at = started + Duration::from_secs(100);
        let next = read_at + Duration::from_secs(10);
        assert_eq!(expires_at(started, ttl, Some(next), read_at), 1_010);
        // Already past on the database's clock: now.
        let past = read_at - Duration::from_secs(5);
        assert_eq!(expires_at(started, ttl, Some(past), read_at), 1_000);
        // Far off: the TTL still holds.
        let far = read_at + Duration::from_secs(10_000);
        assert_eq!(expires_at(started, ttl, Some(far), read_at), 1_300);
    }
}
