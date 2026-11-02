//! Forwarding audit records to attache's evidence ledger (CONTRACTS.md 9.3,
//! 9.4, THREAT-MODEL.md TM-20, ADR-0039).
//!
//! Off unless `TUTELA_LEDGER_URL` is set. Then every replica's
//! [`Forwarder`] walks each chain (every tenant of the directory, and the
//! deployment's own): it claims the chain for a lease, reads up to
//! [`BATCH`] records past what the ledger has acknowledged, signs each with
//! the service's Ed25519 producer key (`TUTELA_AUDIT_KEY`), and sends them
//! to attache's acknowledged Append API, `POST /api/v1/ledger/append`, with
//! its token (`TUTELA_LEDGER_TOKEN`). Only a `200` that acknowledges every
//! record moves the chain's `shipped_seq`; anything else leaves it, and the
//! next tick sends the same batch again (the ledger dedupes by
//! `(service, id)`).
//!
//! It never touches a local write: records are written in their change's
//! transaction whatever the ledger does, and wait in the local log until it
//! takes them. It resumes from `shipped_seq` after a restart or an outage.
//!
//! The producer signature is CONTRACTS.md 9.3: pure Ed25519 over the
//! record's canonical JSON without `signature` (the body the local log
//! keeps), `signature.key_id` the RFC 7638 thumbprint of the OKP public key,
//! and `signature.value` base64url without padding. attache's operator
//! names the public key in `ledger.producers` (its `operations.md`); this
//! logs it at start.

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use serde_json::Value;
use tokio::sync::watch;
use tutela_safenet::{Client, Policy};
use tutela_store::audit::Chain;
use zeroize::Zeroizing;

use crate::db::{Db, DbError};
use crate::telemetry::Metrics;

/// Records sent in one request (attache takes at most 500).
pub const BATCH: usize = 500;

/// The ledger's settings, from `TUTELA_LEDGER_URL`, `TUTELA_LEDGER_TOKEN` and
/// `TUTELA_AUDIT_KEY`. `Debug` shows neither secret.
#[derive(Clone)]
pub struct LedgerConfig {
    /// The Append API, for example
    /// `https://embassy.example/api/v1/ledger/append`.
    pub url: String,
    /// The `att_` token of the producer (attache's `auth.tokens`).
    pub token: Zeroizing<String>,
    /// The 32-byte Ed25519 seed of the producer key.
    pub key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for LedgerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerConfig")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// Why forwarding could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// `TUTELA_AUDIT_KEY` is not a 32-byte Ed25519 seed.
    #[error("TUTELA_AUDIT_KEY is not a 32-byte Ed25519 seed in base64")]
    Key,
    /// The URL is not one `tutela-safenet` sends to.
    #[error("TUTELA_LEDGER_URL is not an https URL")]
    Url,
}

/// The producer key: its RFC 7638 thumbprint and its public key in standard
/// base64 (what attache's `ledger.producers[].keys` takes).
#[must_use]
pub fn key_id(public: &[u8]) -> String {
    let jwk = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        B64.encode(public)
    );
    B64.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        jwk.as_bytes(),
    ))
}

/// What one tick did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Forwarded {
    /// Records the ledger acknowledged.
    pub shipped: usize,
    /// Chains whose batch the ledger did not take; they wait.
    pub refused: usize,
    /// Chains that failed in the database; the others still ran.
    pub failed: usize,
}

/// Sends the local log to the ledger, on every replica.
pub struct Forwarder {
    db: Db,
    url: String,
    token: Zeroizing<String>,
    pair: Ed25519KeyPair,
    kid: String,
    client: Client,
    replica: String,
    lease: Duration,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for Forwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forwarder")
            .field("url", &self.url)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl Forwarder {
    /// A forwarder to `ledger`, sending with `policy` (the ledger's own host
    /// is allowed even when it is private: it is the operator's, not a
    /// tenant's).
    ///
    /// # Errors
    ///
    /// [`LedgerError`].
    pub fn new(
        db: Db,
        ledger: &LedgerConfig,
        policy: Policy,
        replica: String,
        metrics: Arc<Metrics>,
    ) -> Result<Self, LedgerError> {
        let pair =
            Ed25519KeyPair::from_seed_unchecked(&ledger.key).map_err(|_| LedgerError::Key)?;
        let url = tutela_safenet::Url::parse(&ledger.url).map_err(|_| LedgerError::Url)?;
        let host = url.host_str().ok_or(LedgerError::Url)?;
        let policy = policy
            .allow_private_host(host)
            .map_err(|_| LedgerError::Url)?
            .timeout(Duration::from_secs(30))
            .max_body(1024 * 1024);
        tutela_safenet::check_url(&ledger.url, &policy).map_err(|_| LedgerError::Url)?;
        let client = Client::new(policy).map_err(|_| LedgerError::Url)?;
        let kid = key_id(pair.public_key().as_ref());
        Ok(Self {
            db,
            url: ledger.url.clone(),
            token: ledger.token.clone(),
            pair,
            kid,
            client,
            replica,
            lease: Duration::from_secs(60),
            metrics,
        })
    }

    /// The producer key's id (`signature.key_id`).
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// The producer's public key in standard base64, for attache's
    /// `ledger.producers[].keys`.
    #[must_use]
    pub fn public_key(&self) -> String {
        STANDARD.encode(self.pair.public_key().as_ref())
    }

    /// One pass over every chain: each tenant of the directory, then the
    /// deployment's own.
    ///
    /// # Errors
    ///
    /// When no connection can be had, or the tenants cannot be listed.
    pub async fn tick(&self) -> Result<Forwarded, DbError> {
        let tenants = self.db.conn().await?.tenants().await?;
        let mut out = Forwarded::default();
        let chains = tenants
            .into_iter()
            .map(Chain::Tenant)
            .chain(std::iter::once(Chain::Deployment));
        for chain in chains {
            if let Err(e) = self.chain(&chain, &mut out).await {
                out.failed += 1;
                tracing::error!(
                    error = %e,
                    kind = ?e.store_kind(),
                    sqlstate = e.sqlstate(),
                    "forwarding failed for one chain"
                );
            }
        }
        Ok(out)
    }

    async fn chain(&self, chain: &Chain, out: &mut Forwarded) -> Result<(), DbError> {
        let mut conn = self.db.conn().await?;
        let Some(entries) = conn
            .forward_claim(chain, &self.replica, self.lease, BATCH)
            .await?
        else {
            return Ok(());
        };
        drop(conn);
        let last = entries.last().map(|e| e.seq);
        let acked = match last {
            None => None,
            Some(last) => match self.send(&entries).await {
                Ok(()) => {
                    out.shipped += entries.len();
                    self.metrics
                        .add_forwarded(u64::try_from(entries.len()).unwrap_or(u64::MAX));
                    Some(last)
                }
                Err(why) => {
                    out.refused += 1;
                    self.metrics.count_forward_refused();
                    tracing::warn!(reason = why, "the ledger did not take a batch; it waits");
                    None
                }
            },
        };
        let mut conn = self.db.conn().await?;
        conn.forward_done(chain, &self.replica, acked).await?;
        Ok(())
    }

    /// Signs `entries` and sends them. `Err` names why the ledger did not
    /// take them, never a record or the token.
    async fn send(&self, entries: &[tutela_store::AuditEntry]) -> Result<(), &'static str> {
        let mut records = Vec::with_capacity(entries.len());
        for e in entries {
            let mut v: Value = serde_json::from_str(&e.body).map_err(|_| "body")?;
            let sig = self.pair.sign(e.body.as_bytes());
            let Value::Object(map) = &mut v else {
                return Err("body");
            };
            map.insert(
                "signature".to_owned(),
                serde_json::json!({ "key_id": self.kid, "value": B64.encode(sig.as_ref()) }),
            );
            records.push(v);
        }
        let body =
            serde_json::to_vec(&serde_json::json!({ "records": records })).map_err(|_| "body")?;
        let auth = format!("Bearer {}", self.token.as_str());
        let r = self
            .client
            .post(
                &self.url,
                "application/json",
                body,
                &[("authorization", auth.as_str()), ("x-agentsc-csrf", "1")],
            )
            .await
            .map_err(|_| "unreachable")?;
        if r.status != 200 {
            return Err("status");
        }
        let ack: Value = serde_json::from_slice(&r.body).map_err(|_| "answer")?;
        let n = ack["acknowledged"].as_array().map_or(0, Vec::len);
        if n == entries.len() {
            Ok(())
        } else {
            Err("acknowledgement")
        }
    }
}

/// Runs `fwd` every `every` until `stop` turns true.
pub async fn run(fwd: Forwarder, every: Duration, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        if let Err(e) = fwd.tick().await {
            tracing::warn!(error = %e, "forwarding did not run");
        }
    }
}
