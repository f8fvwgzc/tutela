//! Webhooks: a tenant's endpoints for its events, and the deliveries made
//! from the outbox (CONTRACTS.md 8.4, 8.5, ADR-0036).
//!
//! - [`register_webhook`] stores an endpoint with a new secret, sealed by
//!   `tutela-vault`, and returns the secret once. The URL is checked by the
//!   caller with `tutela-safenet` first, and again before each send.
//! - [`fan_out`] makes a delivery row for each new event of an endpoint's
//!   types, in `seq` order, and moves the endpoint's `after_seq`.
//! - [`claim_deliveries`] gives due deliveries to one replica for a lease,
//!   oldest first, never one whose subject has an earlier pending delivery
//!   to the same endpoint (order per subject), and never one another
//!   replica holds.
//! - [`finish_delivery`] records how an attempt ended: delivered, retried
//!   later, or dead.
//! - [`rotate_webhook_secret`] makes a new secret and keeps the old one
//!   signing until the overlap ends.

use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio_postgres::{Row, Transaction};
use tutela_contracts::events::EventType;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;
use tutela_vault::{Kms, Vault};
use zeroize::Zeroizing;

use crate::events::StoredEvent;
use crate::{DbResult as _, StoreError, enter, uuid7};

/// The vault purpose of a webhook secret.
const PURPOSE: &str = "webhook_secret";

/// The prefix of a webhook secret (CONTRACTS.md 8.4).
pub const SECRET_PREFIX: &str = "whsec_";

/// The most deliveries [`claim_deliveries`] gives at once.
pub const MAX_CLAIM: usize = 100;

/// The most events [`fan_out`] hands to one webhook at once.
const FAN_OUT_PAGE: i64 = 1000;

/// A webhook secret, `whsec_<base64 of 32 random bytes>`. Shown once, at
/// registration or rotation; its `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookSecret(Zeroizing<String>);

impl WebhookSecret {
    /// The text, `whsec_...`.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The HMAC key: the decoded bytes after the prefix.
    ///
    /// # Errors
    ///
    /// [`Corrupt`](crate::StoreErrorKind::Corrupt) for a text that is not a
    /// secret.
    pub fn key(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let b64 = self
            .0
            .strip_prefix(SECRET_PREFIX)
            .ok_or(StoreError::corrupt("webhook secret"))?;
        STANDARD
            .decode(b64)
            .map(Zeroizing::new)
            .map_err(|_| StoreError::corrupt("webhook secret"))
    }

    /// A secret from its text, `whsec_<base64>` (a test vector, or a
    /// secret moved from another system).
    ///
    /// # Errors
    ///
    /// [`Invalid`](crate::StoreErrorKind::Invalid) for a text that is not
    /// one.
    pub fn parse(text: &str) -> Result<Self, StoreError> {
        let s = Self(Zeroizing::new(text.to_owned()));
        s.key()
            .map_err(|_| StoreError::invalid("a webhook secret is whsec_<base64>"))?;
        Ok(s)
    }

    fn new() -> Result<Self, StoreError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(bytes.as_mut()).map_err(|_| StoreError::corrupt("random"))?;
        Ok(Self(Zeroizing::new(format!(
            "{SECRET_PREFIX}{}",
            STANDARD.encode(bytes.as_ref())
        ))))
    }
}

impl std::fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}

/// One webhook, as stored. The secrets stay sealed here.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Webhook {
    /// `whk_<uuidv7>`.
    pub id: String,
    /// The endpoint.
    pub url: String,
    /// The event types it gets; empty: every type.
    pub types: Vec<String>,
    /// How far the tenant's events were handed to it.
    pub after_seq: u64,
    /// `true` once it is disabled: it gets nothing more.
    pub disabled: bool,
    /// Who registered it.
    pub created_by: String,
}

fn seal_context(tenant: &TenantKey, id: &str, version: i32) -> Vec<u8> {
    format!("{}/{id}/{version}", tenant.tid).into_bytes()
}

fn seal<K: Kms>(
    vault: &Vault<K>,
    tenant: &TenantKey,
    id: &str,
    version: i32,
    secret: &WebhookSecret,
) -> Result<Vec<u8>, StoreError> {
    vault
        .seal(
            PURPOSE,
            &seal_context(tenant, id, version),
            secret.expose().as_bytes(),
        )
        .map_err(|_| StoreError::corrupt("webhook secret seal"))
}

fn open<K: Kms>(
    vault: &Vault<K>,
    tenant: &TenantKey,
    id: &str,
    version: i32,
    sealed: &[u8],
) -> Result<WebhookSecret, StoreError> {
    let bytes = vault
        .open(PURPOSE, &seal_context(tenant, id, version), sealed)
        .map_err(|_| StoreError::corrupt("webhook secret"))?;
    let text =
        String::from_utf8(bytes.to_vec()).map_err(|_| StoreError::corrupt("webhook secret"))?;
    Ok(WebhookSecret(Zeroizing::new(text)))
}

/// Registers a webhook of `tenant` at `url` for `types` (empty: every
/// type), by `by`. It gets the events written after this call. Returns its
/// id and its secret, which is never shown again.
///
/// Check `url` with `tutela-safenet` before: this stores what it is given.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a URL that is not
/// `https://` or `http://` text of 8 to 2048 bytes,
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database or
/// vault error.
pub async fn register_webhook<K: Kms>(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    vault: &Vault<K>,
    url: &str,
    types: &[EventType],
    by: &Principal,
) -> Result<(String, WebhookSecret), StoreError> {
    if !(8..=2048).contains(&url.len())
        || !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err(StoreError::invalid("a webhook URL is https"));
    }
    enter(tx, tenant).await?;
    let id = format!("whk_{}", uuid7()?);
    let secret = WebhookSecret::new()?;
    let sealed = seal(vault, tenant, &id, 1, &secret)?;
    let types: Vec<String> = types.iter().map(ToString::to_string).collect();
    let now = crate::events::events_now(tx, tenant).await?;
    tx.execute(
        "INSERT INTO tutela.webhook (tenant_id, id, url, types, secret, after_seq, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            &tenant.tid.to_string(),
            &id,
            &url,
            &types,
            &sealed,
            &i64::try_from(now).map_err(|_| StoreError::corrupt("event seq"))?,
            &by.to_string(),
        ],
    )
    .await
    .db()?;
    Ok((id, secret))
}

/// Makes a new secret for webhook `id`, and keeps the current one signing
/// for `overlap` more (CONTRACTS.md 10.4): receivers move to the new one in
/// that time. Returns the new secret, which is never shown again.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) for a webhook this tenant
/// does not have, or a database or vault error.
pub async fn rotate_webhook_secret<K: Kms>(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    vault: &Vault<K>,
    id: &str,
    overlap: Duration,
) -> Result<WebhookSecret, StoreError> {
    enter(tx, tenant).await?;
    let row = tx
        .query_opt(
            "SELECT secret_version FROM tutela.webhook WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            &[&tenant.tid.to_string(), &id],
        )
        .await
        .db()?
        .ok_or(StoreError::not_found("webhook"))?;
    let version: i32 = row.try_get(0).db()?;
    let next = version
        .checked_add(1)
        .ok_or(StoreError::corrupt("secret version"))?;
    let secret = WebhookSecret::new()?;
    let sealed = seal(vault, tenant, id, next, &secret)?;
    let until = SystemTime::now() + overlap;
    tx.execute(
        "UPDATE tutela.webhook SET previous = secret, previous_version = secret_version, \
         previous_until = $3, secret = $4, secret_version = $5 \
         WHERE tenant_id = $1 AND id = $2",
        &[&tenant.tid.to_string(), &id, &until, &sealed, &next],
    )
    .await
    .db()?;
    Ok(secret)
}

/// Disables webhook `id`: it gets no new event, and its pending deliveries
/// are not sent.
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound), or a database error.
pub async fn disable_webhook(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
) -> Result<(), StoreError> {
    enter(tx, tenant).await?;
    let n = tx
        .execute(
            "UPDATE tutela.webhook SET disabled_at = coalesce(disabled_at, now()) \
             WHERE tenant_id = $1 AND id = $2",
            &[&tenant.tid.to_string(), &id],
        )
        .await
        .db()?;
    if n == 0 {
        return Err(StoreError::not_found("webhook"));
    }
    Ok(())
}

/// The webhooks of `tenant`, oldest first.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn webhooks(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
) -> Result<Vec<Webhook>, StoreError> {
    enter(tx, tenant).await?;
    let rows = tx
        .query(
            "SELECT id, url, types, after_seq, disabled_at IS NOT NULL, created_by \
             FROM tutela.webhook WHERE tenant_id = $1 ORDER BY created_at, id",
            &[&tenant.tid.to_string()],
        )
        .await
        .db()?;
    rows.iter()
        .map(|r| {
            Ok(Webhook {
                id: r.try_get(0).db()?,
                url: r.try_get(1).db()?,
                types: r.try_get(2).db()?,
                after_seq: u64::try_from(r.try_get::<_, i64>(3).db()?)
                    .map_err(|_| StoreError::corrupt("webhook"))?,
                disabled: r.try_get(4).db()?,
                created_by: r.try_get(5).db()?,
            })
        })
        .collect()
}

/// Hands the tenant's new events to each enabled webhook of their type: one
/// delivery row per event, in `seq` order. Returns how many rows it made.
/// Two replicas may run it at once; each webhook is handed out by one.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn fan_out(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<u64, StoreError> {
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let hooks = tx
        .query(
            "SELECT id, after_seq, types FROM tutela.webhook \
             WHERE tenant_id = $1 AND disabled_at IS NULL FOR UPDATE SKIP LOCKED",
            &[&tid],
        )
        .await
        .db()?;
    let mut made = 0;
    for h in &hooks {
        let id: String = h.try_get(0).db()?;
        let after: i64 = h.try_get(1).db()?;
        let types: Vec<String> = h.try_get(2).db()?;
        let row = tx
            .query_one(
                "WITH ev AS (SELECT seq, subject, type FROM tutela.event \
                   WHERE tenant_id = $1 AND seq > $3 ORDER BY seq LIMIT $5), \
                 ins AS (INSERT INTO tutela.webhook_delivery (tenant_id, webhook_id, seq, subject) \
                   SELECT $1, $2, seq, subject FROM ev \
                   WHERE cardinality($4::text[]) = 0 OR type = ANY($4::text[]) \
                   ON CONFLICT DO NOTHING RETURNING 1) \
                 SELECT (SELECT max(seq) FROM ev), (SELECT count(*) FROM ins)",
                &[&tid, &id, &after, &types, &FAN_OUT_PAGE],
            )
            .await
            .db()?;
        let last: Option<i64> = row.try_get(0).db()?;
        let n: i64 = row.try_get(1).db()?;
        made += u64::try_from(n).unwrap_or(0);
        if let Some(last) = last {
            tx.execute(
                "UPDATE tutela.webhook SET after_seq = $3 WHERE tenant_id = $1 AND id = $2",
                &[&tid, &id, &last],
            )
            .await
            .db()?;
        }
    }
    Ok(made)
}

/// One delivery given to a replica: what to send, where, and with which
/// secrets.
#[derive(Debug)]
pub struct Claimed {
    /// The webhook.
    pub webhook_id: String,
    /// Its URL.
    pub url: String,
    /// The event's number in the tenant.
    pub seq: u64,
    /// This attempt's number, from 1.
    pub attempt: u32,
    /// When the first attempt was made.
    pub first_at: SystemTime,
    /// The current secret, and the previous one while the overlap lasts.
    pub secrets: Vec<WebhookSecret>,
    /// The event, or `None` when it was pruned before it could be sent.
    pub event: Option<StoredEvent>,
}

/// Gives up to `limit` due deliveries of `tenant` to `replica` for `lease`:
/// pending, due, not held by another replica, and with no earlier pending
/// delivery of the same subject to the same webhook. Each attempt is
/// counted now, so a replica that dies mid-send still counts its try.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database or
/// vault error.
pub async fn claim_deliveries<K: Kms>(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    vault: &Vault<K>,
    replica: &str,
    lease: Duration,
    limit: usize,
) -> Result<Vec<Claimed>, StoreError> {
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    let limit =
        i64::try_from(limit.clamp(1, MAX_CLAIM)).map_err(|_| StoreError::invalid("limit"))?;
    let lease_secs = lease.as_secs_f64();
    let rows = tx
        .query(
            "WITH due AS (SELECT d.webhook_id, d.seq FROM tutela.webhook_delivery d \
               JOIN tutela.webhook w ON w.tenant_id = d.tenant_id AND w.id = d.webhook_id \
               WHERE d.tenant_id = $1 AND d.state = 'pending' AND w.disabled_at IS NULL \
               AND d.next_at <= clock_timestamp() \
               AND (d.claimed_until IS NULL OR d.claimed_until < clock_timestamp()) \
               AND NOT EXISTS (SELECT 1 FROM tutela.webhook_delivery e \
                 WHERE e.tenant_id = d.tenant_id AND e.webhook_id = d.webhook_id \
                 AND e.subject = d.subject AND e.state = 'pending' AND e.seq < d.seq) \
               ORDER BY d.seq LIMIT $2 FOR UPDATE OF d SKIP LOCKED) \
             UPDATE tutela.webhook_delivery d SET claimed_by = $3, \
               claimed_until = clock_timestamp() + make_interval(secs => $4), \
               attempts = d.attempts + 1, first_at = coalesce(d.first_at, clock_timestamp()) \
             FROM due WHERE d.tenant_id = $1 AND d.webhook_id = due.webhook_id AND d.seq = due.seq \
             RETURNING d.webhook_id, d.seq, d.attempts, d.first_at",
            &[&tid, &limit, &replica, &lease_secs],
        )
        .await
        .db()?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let webhook_id: String = r.try_get(0).db()?;
        let seq: i64 = r.try_get(1).db()?;
        let attempts: i32 = r.try_get(2).db()?;
        let first_at: SystemTime = r.try_get(3).db()?;
        let hook = tx
            .query_one(
                "SELECT url, secret, secret_version, previous, previous_version, \
                 previous_until > clock_timestamp() FROM tutela.webhook \
                 WHERE tenant_id = $1 AND id = $2",
                &[&tid, &webhook_id],
            )
            .await
            .db()?;
        let mut secrets = vec![open(
            vault,
            tenant,
            &webhook_id,
            hook.try_get(2).db()?,
            &hook.try_get::<_, Vec<u8>>(1).db()?,
        )?];
        let previous: Option<Vec<u8>> = hook.try_get(3).db()?;
        let previous_version: Option<i32> = hook.try_get(4).db()?;
        let overlapping: Option<bool> = hook.try_get(5).db()?;
        if let (Some(p), Some(v), Some(true)) = (previous, previous_version, overlapping) {
            secrets.push(open(vault, tenant, &webhook_id, v, &p)?);
        }
        let event = crate::events::event_at(tx, tenant, u64::try_from(seq).unwrap_or(0)).await?;
        out.push(Claimed {
            url: hook.try_get(0).db()?,
            webhook_id,
            seq: u64::try_from(seq).map_err(|_| StoreError::corrupt("delivery"))?,
            attempt: u32::try_from(attempts).unwrap_or(u32::MAX),
            first_at,
            secrets,
            event,
        });
    }
    Ok(out)
}

/// How an attempt ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attempt {
    /// A 2xx answer in time: delivered.
    Delivered {
        /// The status.
        status: u16,
    },
    /// Not delivered; try again at `next_at`.
    Retry {
        /// When to try again.
        next_at: SystemTime,
        /// The status, when there was an answer.
        status: Option<u16>,
        /// What went wrong, without values: a code such as `timeout`,
        /// `not_public` or `status`.
        error: String,
    },
    /// Not delivered, and retried long enough: dead-lettered.
    Dead {
        /// The status, when there was an answer.
        status: Option<u16>,
        /// What went wrong, as for [`Attempt::Retry`].
        error: String,
    },
}

/// Records how `replica`'s attempt at delivery (`webhook_id`, `seq`) ended.
/// Returns `false` when the replica no longer holds it: its lease ran out
/// and another replica took it.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn finish_delivery(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    replica: &str,
    webhook_id: &str,
    seq: u64,
    how: &Attempt,
) -> Result<bool, StoreError> {
    enter(tx, tenant).await?;
    let (state, next_at, status, error) = match how {
        Attempt::Delivered { status } => ("delivered", None, Some(*status), None),
        Attempt::Retry {
            next_at,
            status,
            error,
        } => ("pending", Some(*next_at), *status, Some(error.as_str())),
        Attempt::Dead { status, error } => ("dead", None, *status, Some(error.as_str())),
    };
    let n = tx
        .execute(
            "UPDATE tutela.webhook_delivery SET state = $5, \
             next_at = coalesce($6, next_at), last_status = $7, last_error = $8, \
             claimed_by = NULL, claimed_until = NULL, \
             done_at = CASE WHEN $5 = 'pending' THEN NULL ELSE clock_timestamp() END \
             WHERE tenant_id = $1 AND webhook_id = $2 AND seq = $3 AND claimed_by = $4 \
             AND state = 'pending'",
            &[
                &tenant.tid.to_string(),
                &webhook_id,
                &i64::try_from(seq).map_err(|_| StoreError::invalid("seq"))?,
                &replica,
                &state,
                &next_at,
                &status.map(i32::from),
                &error,
            ],
        )
        .await
        .db()?;
    Ok(n == 1)
}

/// One delivery, as stored: for the Console and for tests.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Delivery {
    /// The webhook.
    pub webhook_id: String,
    /// The event's number.
    pub seq: u64,
    /// `pending`, `delivered` or `dead`.
    pub state: String,
    /// Attempts made.
    pub attempts: u32,
    /// The last answer's status.
    pub last_status: Option<u16>,
    /// The last error code.
    pub last_error: Option<String>,
}

/// The deliveries of webhook `id`, by event number.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn deliveries(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
) -> Result<Vec<Delivery>, StoreError> {
    enter(tx, tenant).await?;
    let rows = tx
        .query(
            "SELECT webhook_id, seq, state, attempts, last_status, last_error \
             FROM tutela.webhook_delivery WHERE tenant_id = $1 AND webhook_id = $2 ORDER BY seq",
            &[&tenant.tid.to_string(), &id],
        )
        .await
        .db()?;
    rows.iter().map(delivery).collect()
}

fn delivery(r: &Row) -> Result<Delivery, StoreError> {
    Ok(Delivery {
        webhook_id: r.try_get(0).db()?,
        seq: u64::try_from(r.try_get::<_, i64>(1).db()?)
            .map_err(|_| StoreError::corrupt("delivery"))?,
        state: r.try_get(2).db()?,
        attempts: u32::try_from(r.try_get::<_, i32>(3).db()?).unwrap_or(0),
        last_status: r
            .try_get::<_, Option<i32>>(4)
            .db()?
            .and_then(|s| u16::try_from(s).ok()),
        last_error: r.try_get(5).db()?,
    })
}

/// Sends a dead delivery again: it is pending and due now, with its count
/// of attempts kept (for the Console).
///
/// # Errors
///
/// [`NotFound`](crate::StoreErrorKind::NotFound) when it is not dead, or a
/// database error.
pub async fn redeliver(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
    seq: u64,
) -> Result<(), StoreError> {
    enter(tx, tenant).await?;
    let n = tx
        .execute(
            "UPDATE tutela.webhook_delivery SET state = 'pending', next_at = clock_timestamp(), \
             first_at = NULL, done_at = NULL WHERE tenant_id = $1 AND webhook_id = $2 \
             AND seq = $3 AND state = 'dead'",
            &[
                &tenant.tid.to_string(),
                &id,
                &i64::try_from(seq).map_err(|_| StoreError::invalid("seq"))?,
            ],
        )
        .await
        .db()?;
    if n == 0 {
        return Err(StoreError::not_found("dead delivery"));
    }
    Ok(())
}

/// Removes deliveries that ended before `before`, and then the events
/// before it that no pending delivery needs. Returns how many events went.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn prune(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    before: SystemTime,
) -> Result<u64, StoreError> {
    enter(tx, tenant).await?;
    let tid = tenant.tid.to_string();
    tx.execute(
        "DELETE FROM tutela.webhook_delivery WHERE tenant_id = $1 AND state <> 'pending' \
         AND done_at < $2",
        &[&tid, &before],
    )
    .await
    .db()?;
    tx.execute(
        "DELETE FROM tutela.event e WHERE e.tenant_id = $1 AND e.time < $2 \
         AND NOT EXISTS (SELECT 1 FROM tutela.webhook_delivery d \
           WHERE d.tenant_id = e.tenant_id AND d.seq = e.seq AND d.state = 'pending')",
        &[&tid, &before],
    )
    .await
    .db()
}

/// Webhook `id` of `tenant`, if it has one.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn webhook(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
) -> Result<Option<Webhook>, StoreError> {
    Ok(webhooks(tx, tenant).await?.into_iter().find(|w| w.id == id))
}

/// The most deliveries [`delivery_page`] returns at once.
pub const MAX_DELIVERY_PAGE: usize = 1000;

/// Up to `limit` (1 to [`MAX_DELIVERY_PAGE`]) deliveries of webhook `id`
/// after event number `after`, by number; with `dead_only`, the dead ones
/// only, for the Console to send again.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn delivery_page(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &str,
    after: u64,
    limit: usize,
    dead_only: bool,
) -> Result<Vec<Delivery>, StoreError> {
    enter(tx, tenant).await?;
    let limit = i64::try_from(limit.clamp(1, MAX_DELIVERY_PAGE)).unwrap_or(1);
    let after = i64::try_from(after).map_err(|_| StoreError::invalid("after"))?;
    let rows = tx
        .query(
            "SELECT webhook_id, seq, state, attempts, last_status, last_error \
             FROM tutela.webhook_delivery WHERE tenant_id = $1 AND webhook_id = $2 \
             AND seq > $3 AND (NOT $4 OR state = 'dead') ORDER BY seq LIMIT $5",
            &[&tenant.tid.to_string(), &id, &after, &dead_only, &limit],
        )
        .await
        .db()?;
    rows.iter().map(delivery).collect()
}
