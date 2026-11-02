//! Webhook delivery (CONTRACTS.md 8.4, 8.5, ADR-0036).
//!
//! The [`Relay`] runs on every replica. On each tick it goes through the
//! tenants of the directory, as the expiry sweep does, and for each one:
//!
//! 1. hands new events to the tenant's webhooks (`tutela_store::fan_out`);
//! 2. claims due deliveries for a lease, in a transaction of their own, so
//!    no database connection is held while a receiver answers, and two
//!    replicas never send one event to one webhook at once;
//! 3. sends each one through `tutela-safenet` (https only, public addresses
//!    only, DNS checked at each send, no redirects, 15 s), signed with
//!    Standard Webhooks signatures ([`sign`]), one per secret while a
//!    rotation overlaps;
//! 4. records the end: delivered on a 2xx; else retried with exponential
//!    backoff and jitter; dead after [`Settings::give_up`] (24 hours by
//!    default, CONTRACTS.md 8.5) and kept for the Console to send again.
//!
//! Webhooks are registered with [`register`], which checks the URL with
//! `tutela-safenet` (also its DNS answer) before the store keeps it. The
//! route that calls it is part 3c's (`tutela.admin.v1`).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::watch;
use tutela_contracts::events::EventType;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{Issuer, TenantKey};
use tutela_safenet::{Client, Policy, SafenetErrorKind};
use tutela_store::webhooks::{Attempt, Claimed, WebhookSecret};
use tutela_vault::Vault;

use crate::db::{Db, DbError};
use crate::telemetry::Metrics;

/// How a relay behaves. [`Settings::default`] is the contract's.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// How long a claim holds a delivery: longer than one send.
    pub lease: Duration,
    /// The first retry's delay; each next one doubles.
    pub first_backoff: Duration,
    /// The longest delay between two tries.
    pub max_backoff: Duration,
    /// How long after the first try a delivery is retried before it is dead.
    pub give_up: Duration,
    /// How long one send may take, connect included.
    pub timeout: Duration,
    /// Deliveries one tenant sends per tick.
    pub batch: usize,
    /// How long events and ended deliveries are kept.
    pub retention: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lease: Duration::from_secs(60),
            first_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(3600),
            give_up: Duration::from_secs(24 * 3600),
            timeout: Duration::from_secs(15),
            batch: 32,
            retention: Duration::from_secs(7 * 24 * 3600),
        }
    }
}

/// The delay before try `attempt + 1`: `first_backoff × 2^(attempt − 1)`,
/// at most `max_backoff`, with up to a fifth taken off at random so that
/// receivers that failed together are not tried together.
#[must_use]
pub fn backoff(s: &Settings, attempt: u32, jitter: f64) -> Duration {
    let exp = attempt.saturating_sub(1).min(30);
    let base = s
        .first_backoff
        .saturating_mul(1u32 << exp)
        .min(s.max_backoff);
    let cut = base.mul_f64(jitter.clamp(0.0, 1.0) * 0.2);
    base.saturating_sub(cut)
}

/// The Standard Webhooks signature header of one attempt: `v1,<base64
/// HMAC-SHA256>` over `<id>.<timestamp>.<body>` for each secret, separated
/// by a space (CONTRACTS.md 8.4).
///
/// # Errors
///
/// A secret that does not decode.
pub fn sign(
    secrets: &[WebhookSecret],
    id: &str,
    timestamp: u64,
    body: &[u8],
) -> Result<String, tutela_store::StoreError> {
    let mut msg = Vec::with_capacity(id.len() + body.len() + 24);
    msg.extend_from_slice(id.as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(body);
    let mut out = Vec::with_capacity(secrets.len());
    for s in secrets {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &s.key()?);
        out.push(format!(
            "v1,{}",
            STANDARD.encode(hmac::sign(&key, &msg).as_ref())
        ));
    }
    Ok(out.join(" "))
}

/// Why a webhook could not be registered.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegisterError {
    /// The URL is not https, has credentials, or names or resolves to an
    /// address that is not public (TM-18). The text says which, never the
    /// URL.
    #[error("the webhook URL is refused: {0}")]
    Url(&'static str),
    /// The database failed.
    #[error("the webhook could not be stored")]
    Db(#[from] DbError),
}

/// Registers a webhook of `tenant` (in `tx`) at `url` for `types`, by `by`,
/// after `client` checked the URL and its DNS answer (CONTRACTS.md 8.5:
/// checked when registered and before each send). Returns its id and its
/// secret, shown once.
///
/// # Errors
///
/// [`RegisterError`].
pub async fn register(
    tx: &crate::db::TenantTx<'_>,
    vault: &Vault,
    client: &Client,
    url: &str,
    types: &[EventType],
    by: &Principal,
) -> Result<(String, WebhookSecret), RegisterError> {
    client.check(url).await.map_err(|e| {
        RegisterError::Url(match e.kind() {
            SafenetErrorKind::NotPublic => "it is not a public address",
            SafenetErrorKind::NoAddress => "it does not resolve",
            _ => "it is not an https URL without credentials",
        })
    })?;
    Ok(
        tutela_store::webhooks::register_webhook(tx, tx.tenant(), vault, url, types, by)
            .await
            .map_err(DbError::from)?,
    )
}

/// Delivers events to webhooks, on every replica.
pub struct Relay {
    db: Db,
    vault: Vault,
    own: Issuer,
    client: Client,
    replica: String,
    settings: Settings,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("replica", &self.replica)
            .finish_non_exhaustive()
    }
}

/// What one tick did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tick {
    /// Delivery rows made from new events.
    pub handed: u64,
    /// Answered 2xx.
    pub delivered: usize,
    /// To be tried again.
    pub retried: usize,
    /// Given up.
    pub dead: usize,
    /// Tenants that failed; the others still ran.
    pub failed: usize,
}

impl Relay {
    /// A relay over `db`, sending with `policy`, named `replica` in its
    /// claims.
    ///
    /// # Errors
    ///
    /// When the HTTP client cannot be set up.
    pub fn new(
        db: Db,
        vault: Vault,
        own: Issuer,
        policy: Policy,
        replica: String,
        settings: Settings,
        metrics: Arc<Metrics>,
    ) -> Result<Self, tutela_safenet::SafenetError> {
        let client = Client::new(
            policy
                .timeout(settings.timeout)
                .connect_timeout(settings.timeout)
                .max_body(64 * 1024),
        )?;
        Ok(Self {
            db,
            vault,
            own,
            client,
            replica,
            settings,
            metrics,
        })
    }

    /// The client webhooks are checked and sent with.
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// One pass over every tenant.
    ///
    /// # Errors
    ///
    /// When no connection can be had, or the tenants cannot be listed.
    pub async fn tick(&self) -> Result<Tick, DbError> {
        let tenants = self.db.conn().await?.tenants().await?;
        let mut out = Tick::default();
        for tenant in &tenants {
            if let Err(e) = self.tenant(tenant, &mut out).await {
                out.failed += 1;
                tracing::error!(
                    tid = %tenant.tid,
                    error = %e,
                    kind = ?e.store_kind(),
                    sqlstate = e.sqlstate(),
                    "webhook delivery failed for one tenant"
                );
            }
        }
        Ok(out)
    }

    async fn tenant(&self, tenant: &TenantKey, out: &mut Tick) -> Result<(), DbError> {
        let mut conn = self.db.conn().await?;
        let claimed = conn
            .webhook_claims(
                tenant,
                &self.vault,
                &self.replica,
                &self.settings,
                &mut out.handed,
            )
            .await?;
        drop(conn);
        for c in claimed {
            let how = self.send(tenant, &c).await;
            let result = match &how {
                Attempt::Delivered { .. } => {
                    out.delivered += 1;
                    "delivered"
                }
                Attempt::Retry { error, .. } => {
                    out.retried += 1;
                    if error == "not_public" {
                        "blocked"
                    } else {
                        "retry"
                    }
                }
                Attempt::Dead { .. } => {
                    out.dead += 1;
                    "dead"
                }
                _ => "error",
            };
            self.metrics.count_webhook(result);
            let mut conn = self.db.conn().await?;
            if !conn
                .webhook_finish(tenant, &self.replica, &c.webhook_id, c.seq, &how)
                .await?
            {
                tracing::warn!(
                    tid = %tenant.tid,
                    webhook = c.webhook_id,
                    seq = c.seq,
                    "a delivery's lease ran out before its end was recorded"
                );
            }
        }
        Ok(())
    }

    /// One attempt. Never an error: every failure is an [`Attempt`].
    async fn send(&self, tenant: &TenantKey, c: &Claimed) -> Attempt {
        let give_up = |error: &str, status: Option<u16>| {
            let age = SystemTime::now()
                .duration_since(c.first_at)
                .unwrap_or_default();
            if age >= self.settings.give_up {
                Attempt::Dead {
                    status,
                    error: error.to_owned(),
                }
            } else {
                let jitter = f64::from(rand_u16()) / f64::from(u16::MAX);
                Attempt::Retry {
                    next_at: SystemTime::now() + backoff(&self.settings, c.attempt, jitter),
                    status,
                    error: error.to_owned(),
                }
            }
        };
        let Some(event) = &c.event else {
            return Attempt::Dead {
                status: None,
                error: "pruned".to_owned(),
            };
        };
        let body = match crate::events::envelope(&self.own, tenant.tid, event)
            .ok()
            .and_then(|e| serde_json::to_vec(&e).ok())
        {
            Some(b) => b,
            None => return give_up("envelope", None),
        };
        let id = event.id.to_string();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let Ok(signature) = sign(&c.secrets, &id, ts, &body) else {
            return give_up("secret", None);
        };
        let ts = ts.to_string();
        let headers = [
            ("webhook-id", id.as_str()),
            ("webhook-timestamp", ts.as_str()),
            ("webhook-signature", signature.as_str()),
        ];
        match self
            .client
            .post(&c.url, "application/cloudevents+json", body, &headers)
            .await
        {
            Ok(r) if r.is_success() => Attempt::Delivered { status: r.status },
            Ok(r) => give_up("status", Some(r.status)),
            Err(e) => {
                let code = match e.kind() {
                    SafenetErrorKind::NotPublic => "not_public",
                    SafenetErrorKind::NoAddress => "no_address",
                    SafenetErrorKind::Url => "url",
                    SafenetErrorKind::Timeout => "timeout",
                    SafenetErrorKind::TooLarge => "too_large",
                    _ => "connect",
                };
                give_up(code, None)
            }
        }
    }
}

/// A random number for jitter.
fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    let _ = aws_lc_rs::rand::fill(&mut b);
    u16::from_le_bytes(b)
}

/// Runs `relay` every `every` until `stop` turns true.
pub async fn run(relay: Relay, every: Duration, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        if let Err(e) = relay.tick().await {
            tracing::warn!(error = %e, "webhook delivery did not run");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test vector of the Standard Webhooks specification.
    #[test]
    fn signatures_match_the_standard_webhooks_vector() {
        let secret = WebhookSecret::parse("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
        let sig = sign(
            std::slice::from_ref(&secret),
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            1_614_265_330,
            br#"{"test": 2432232314}"#,
        )
        .unwrap();
        assert_eq!(sig, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
        let two = sign(&[secret.clone(), secret], "m", 1, b"{}").unwrap();
        assert_eq!(two.split(' ').count(), 2);
    }

    #[test]
    fn backoff_doubles_to_its_cap_and_jitter_only_shortens() {
        let s = Settings::default();
        assert_eq!(backoff(&s, 1, 0.0), Duration::from_secs(5));
        assert_eq!(backoff(&s, 2, 0.0), Duration::from_secs(10));
        assert_eq!(backoff(&s, 4, 0.0), Duration::from_secs(40));
        assert_eq!(backoff(&s, 40, 0.0), Duration::from_secs(3600));
        assert_eq!(backoff(&s, 1, 1.0), Duration::from_secs(4));
        // 24 hours of tries: about 30 of them.
        let mut t = Duration::ZERO;
        let mut n = 0;
        while t < s.give_up {
            n += 1;
            t += backoff(&s, n, 0.5);
        }
        assert!((25..=40).contains(&n), "{n}");
    }
}
