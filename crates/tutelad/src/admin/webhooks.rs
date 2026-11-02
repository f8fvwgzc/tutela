//! Webhooks over the admin API (CONTRACTS.md 7.13.6, ADR-0036 item 9).
//!
//! A webhook gets every event of its types in its tenant, at a URL the
//! tenant names: a standing outbound channel. So registering one, and
//! everything else about one, takes the keys that look at and change the
//! whole tenant's access: `read_audit` **and** `manage_access` at every org
//! ([`WEBHOOK_KEYS`]), from a person's admin token or a service's own token.
//!
//! **A secret is shown once**: in the answer that makes it (registration
//! or rotation), and nowhere else. The store keeps it sealed by
//! `tutela-vault`; a list never has it; an audit record names the webhook
//! and the URL's host, never the secret or the whole URL (it may carry a
//! token in its query).

use std::time::Duration;

use axum::http::StatusCode;
use tutela_contracts::audit::Actor;
use tutela_contracts::events::EventType;
use tutela_sdk::Identity;

use super::wire::{
    DeliveriesOut, DeliveriesQuery, DeliveryOut, RegisterWebhookBody, RotateBody, WebhookOut,
    WebhookSecretOut, WebhooksOut,
};
use super::{guard, required};
use crate::api::{AppState, Problem};
use crate::audit::{self, Record};
use crate::tenant::Tenant;
use crate::webhooks::RegisterError;

/// What every webhook call needs, at every org (ADR-0036 item 9).
pub const WEBHOOK_KEYS: [&str; 2] = ["read_audit", "manage_access"];

/// How long the old secret keeps signing after a rotation, by default.
const OVERLAP: Duration = Duration::from_secs(3600);

/// The longest overlap a rotation may ask for.
const MAX_OVERLAP: Duration = Duration::from_secs(7 * 24 * 3600);

/// The default page of deliveries.
const PAGE: usize = 100;

fn not_found() -> Problem {
    Problem::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "no such webhook in this tenant",
    )
}

/// The host of `url`, for a record: never the path or the query.
fn host(url: &str) -> String {
    url.split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(""))
        .map(|h| h.rsplit('@').next().unwrap_or(h))
        .unwrap_or("")
        .to_owned()
}

fn out(w: tutela_store::webhooks::Webhook) -> WebhookOut {
    WebhookOut {
        id: w.id,
        url: w.url,
        types: w.types,
        disabled: w.disabled,
        created_by: w.created_by,
    }
}

/// `POST /v1/admin/webhooks`: registers a webhook of the caller's tenant
/// for `types` (none: every type) after `tutela-safenet` checked its URL and
/// its DNS answer. The answer holds its secret, the one time it is shown.
///
/// # Errors
///
/// A [`Problem`]: 400 `invalid_url` for a URL that is not https, has
/// credentials, or names or resolves to an address that is not public.
pub async fn register(
    state: &AppState,
    id: &Identity,
    body: RegisterWebhookBody,
) -> Result<WebhookSecretOut, Problem> {
    let tenant = Tenant::of(id);
    let url = required(body.url, "url")?;
    let types = body
        .types
        .unwrap_or_default()
        .iter()
        .map(|t| EventType::parse(t))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            Problem::invalid("invalid_request", "a type is not an event type".to_owned())
        })?;
    let action = "tutela_webhook:register";
    let by = guard(
        state,
        id,
        &tenant,
        &WEBHOOK_KEYS,
        action,
        ("tutela_webhook", "new"),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let made =
        crate::webhooks::register(&tx, &state.vault, &state.safenet, &url, &types, &by).await;
    let (wid, secret) = match made {
        Ok(m) => m,
        Err(RegisterError::Url(why)) => {
            drop(tx);
            drop(conn);
            // A refused URL may be an attempt to reach inside: recorded.
            let rejected = Problem::invalid("invalid_url", why.to_owned());
            audit::write_alone_now(state, &tenant, |rev| {
                vec![
                    Record::new(
                        tenant.key(),
                        Actor::new(by.clone()),
                        action,
                        ("tutela_webhook", "new"),
                    )
                    .denied(rev, "invalid_url")
                    .detail("host", host(&url)),
                ]
            })
            .await?;
            return Err(rejected);
        }
        Err(RegisterError::Db(e)) => return Err(e.into()),
    };
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    let names: Vec<String> = types.iter().map(ToString::to_string).collect();
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by.clone()),
                action,
                ("tutela_webhook", &wid),
            )
            .allowed(rev)
            .detail("webhook", wid.clone())
            .detail("host", host(&url))
            .detail("types", names.clone()),
        ],
    )
    .await?;
    tx.commit().await?;
    tracing::info!("a webhook was registered");
    Ok(WebhookSecretOut {
        webhook: WebhookOut {
            id: wid,
            url,
            types: names,
            disabled: false,
            created_by: by.to_string(),
        },
        secret: secret.expose().to_owned(),
    })
}

/// `GET /v1/admin/webhooks`: the tenant's webhooks, oldest first. Never a
/// secret.
///
/// # Errors
///
/// A [`Problem`].
pub async fn list(state: &AppState, id: &Identity) -> Result<WebhooksOut, Problem> {
    let tenant = Tenant::of(id);
    guard(
        state,
        id,
        &tenant,
        &WEBHOOK_KEYS,
        "tutela_webhook:list",
        ("tutela_webhook", "webhooks"),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let all = tutela_store::webhooks::webhooks(&tx, tenant.key()).await?;
    tx.commit().await?;
    Ok(WebhooksOut {
        webhooks: all.into_iter().map(out).collect(),
    })
}

/// `POST /v1/admin/webhooks/{id}/rotate`: a new secret, shown this once;
/// the old one keeps signing for `overlap_secs` (default 3600, at most
/// 7 days), so receivers can move to the new one.
///
/// # Errors
///
/// A [`Problem`]: 404 for a webhook this tenant does not have.
pub async fn rotate(
    state: &AppState,
    id: &Identity,
    wid: &str,
    body: RotateBody,
) -> Result<WebhookSecretOut, Problem> {
    let tenant = Tenant::of(id);
    let overlap = body.overlap_secs.map_or(OVERLAP, Duration::from_secs);
    if overlap > MAX_OVERLAP {
        return Err(Problem::invalid(
            "invalid_request",
            "`overlap_secs` is at most 604800".to_owned(),
        ));
    }
    let action = "tutela_webhook:rotate";
    let by = guard(
        state,
        id,
        &tenant,
        &WEBHOOK_KEYS,
        action,
        ("tutela_webhook", wid),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    let found = tutela_store::webhooks::webhook(&tx, tenant.key(), wid)
        .await?
        .ok_or_else(not_found)?;
    let secret = tutela_store::webhooks::rotate_webhook_secret(
        &tx,
        tenant.key(),
        &state.vault,
        wid,
        overlap,
    )
    .await
    .map_err(super::store_problem)?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by),
                action,
                ("tutela_webhook", wid),
            )
            .allowed(rev)
            .detail("webhook", wid)
            .detail("overlap_secs", overlap.as_secs()),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(WebhookSecretOut {
        webhook: out(found),
        secret: secret.expose().to_owned(),
    })
}

/// `POST /v1/admin/webhooks/{id}/disable`: it gets no new event, and its
/// pending deliveries are not sent.
///
/// # Errors
///
/// A [`Problem`]: 404 for a webhook this tenant does not have.
pub async fn disable(state: &AppState, id: &Identity, wid: &str) -> Result<WebhookOut, Problem> {
    let tenant = Tenant::of(id);
    let action = "tutela_webhook:disable";
    let by = guard(
        state,
        id,
        &tenant,
        &WEBHOOK_KEYS,
        action,
        ("tutela_webhook", wid),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    tutela_store::webhooks::disable_webhook(&tx, tenant.key(), wid)
        .await
        .map_err(|e| match e.kind() {
            tutela_store::StoreErrorKind::NotFound => not_found(),
            _ => e.into(),
        })?;
    let found = tutela_store::webhooks::webhook(&tx, tenant.key(), wid)
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
                ("tutela_webhook", wid),
            )
            .allowed(rev)
            .detail("webhook", wid),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(out(found))
}

/// `GET /v1/admin/webhooks/{id}/deliveries`: its deliveries by event
/// number, the dead ones only with `state=dead`.
///
/// # Errors
///
/// A [`Problem`]: 404 for a webhook this tenant does not have.
pub async fn deliveries(
    state: &AppState,
    id: &Identity,
    wid: &str,
    q: DeliveriesQuery,
) -> Result<DeliveriesOut, Problem> {
    let tenant = Tenant::of(id);
    let dead_only = match q.state.as_deref() {
        None => false,
        Some("dead") => true,
        Some(_) => {
            return Err(Problem::invalid(
                "invalid_request",
                "`state` is `dead` or left out".to_owned(),
            ));
        }
    };
    guard(
        state,
        id,
        &tenant,
        &WEBHOOK_KEYS,
        "tutela_webhook:deliveries",
        ("tutela_webhook", wid),
    )
    .await?;
    let limit = q
        .limit
        .unwrap_or(PAGE)
        .clamp(1, tutela_store::webhooks::MAX_DELIVERY_PAGE);
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    tutela_store::webhooks::webhook(&tx, tenant.key(), wid)
        .await?
        .ok_or_else(not_found)?;
    let page = tutela_store::webhooks::delivery_page(
        &tx,
        tenant.key(),
        wid,
        q.after.unwrap_or(0),
        limit,
        dead_only,
    )
    .await?;
    tx.commit().await?;
    let next_after = (page.len() >= limit)
        .then(|| page.last().map(|d| d.seq))
        .flatten();
    Ok(DeliveriesOut {
        deliveries: page.into_iter().map(DeliveryOut::of).collect(),
        next_after,
    })
}

/// `POST /v1/admin/webhooks/{id}/deliveries/{seq}/redeliver`: a dead
/// delivery is sent again, now.
///
/// # Errors
///
/// A [`Problem`]: 404 when it is not dead, or not this tenant's.
pub async fn redeliver(
    state: &AppState,
    id: &Identity,
    wid: &str,
    seq: u64,
) -> Result<DeliveryOut, Problem> {
    let tenant = Tenant::of(id);
    let action = "tutela_webhook:redeliver";
    let by = guard(
        state,
        id,
        &tenant,
        &WEBHOOK_KEYS,
        action,
        ("tutela_webhook", wid),
    )
    .await?;
    let mut conn = state.db.conn().await?;
    let tx = conn.begin(&tenant).await?;
    tutela_store::webhooks::redeliver(&tx, tenant.key(), wid, seq)
        .await
        .map_err(|e| match e.kind() {
            tutela_store::StoreErrorKind::NotFound => Problem::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "no such dead delivery of this webhook",
            ),
            _ => e.into(),
        })?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    let now = tutela_store::webhooks::delivery_page(
        &tx,
        tenant.key(),
        wid,
        seq.saturating_sub(1),
        1,
        false,
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(not_found)?;
    audit::write(
        state,
        &tx,
        vec![
            Record::new(
                tenant.key(),
                Actor::new(by),
                action,
                ("tutela_webhook", wid),
            )
            .allowed(rev)
            .detail("webhook", wid)
            .detail("seq", seq),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(DeliveryOut::of(now))
}

#[cfg(test)]
mod tests {
    use super::host;

    #[test]
    fn a_record_names_the_host_only() {
        assert_eq!(
            host("https://hooks.example.test/x?token=abc"),
            "hooks.example.test"
        );
        assert_eq!(
            host("https://u:p@hooks.example.test:8443/x"),
            "hooks.example.test:8443"
        );
        assert_eq!(host("nonsense"), "");
    }
}
