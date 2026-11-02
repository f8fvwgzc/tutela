//! `tutela keys`: the operator's work on `tutelad`'s signing keys, through
//! the key store (ADR-0030, ADR-0045). The keys are sealed with
//! `tutela-vault` under `TUTELA_MASTER_KEY` (and `TUTELA_MASTER_KEY_PREVIOUS`
//! for a re-wrap); the database is `TUTELA_DATABASE_URL`. Every change is
//! recorded in the deployment's audit chain, as `tutelad` records its own.
//!
//! - `list`: the published keys, the one that signs, and the denied ones;
//! - `rotate`: a next key, published now, that signs after twice the JWKS
//!   cache time (`TUTELA_JWKS_CACHE_SECS`, default 300), so every cache has
//!   it first (CONTRACTS.md 10.4);
//! - `deny <kid>`: the key is refused at once by every replica, and a new
//!   key signs;
//! - `rotate --audit`: the audit producer key (ADR-0045) is retired and
//!   the next one signs; the retired one is kept, so its records verify;
//! - `rewrap`: every key sealed under the previous master key, signing and
//!   audit keys, is sealed again under the current one.
//!
//! Replicas read the table every `TUTELA_KEY_REFRESH_SECS`.

use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use tutela_contracts::audit::{Actor, AuditDraft, DecisionSummary, Outcome, ResourceRef};
use tutela_contracts::claims::{CLOCK_SKEW_SECS, MAX_ACCESS_TOKEN_LIFETIME_SECS};
use tutela_contracts::decision::{Effect, Reason};
use tutela_contracts::id::Uuid7;
use tutela_contracts::tenant::{Issuer, TenantKey};
use tutela_contracts::timestamp::Timestamp;
use tutela_store::KeyTimes;
use tutela_store::tokio_postgres::Client;
use tutela_vault::Vault;

use crate::CliError;

/// `tutelad`'s own principal for what no person does: the actor of the
/// records `tutelad` writes about its keys (`tutelad::audit::SYSTEM`).
const SYSTEM: &str = "sa:sa_00000000-0000-7000-8000-000000000000";

/// The rotation times of `tutelad` (`tutelad::keys::rotation_times`): the
/// next key is published twice the JWKS cache time before it signs, and a
/// key stays published for the longest token life and the clock skew after.
#[must_use]
pub const fn rotation_times(jwks_cache: Duration) -> KeyTimes {
    KeyTimes {
        lead: Duration::from_secs(jwks_cache.as_secs().saturating_mul(2)),
        keep: Duration::from_secs(MAX_ACCESS_TOKEN_LIFETIME_SECS + CLOCK_SKEW_SECS),
    }
}

fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn internal(_: impl std::fmt::Debug) -> CliError {
    CliError::Internal("an audit record could not be built")
}

/// A record of `tutela_<thing>:<verb>` on `id` in the deployment's chain,
/// whose tenant key names `iss` (`TUTELA_ISSUER`), by the operator.
///
/// # Errors
///
/// [`CliError::Internal`]: a value breaks an audit.v1 rule, a bug.
pub fn deployment_record(
    iss: &Issuer,
    thing: &str,
    verb: &str,
    id: &str,
    details: Map<String, Value>,
) -> Result<AuditDraft, CliError> {
    let rid = Uuid7::from_uuid(uuid::Uuid::now_v7()).map_err(internal)?;
    let time = Timestamp::from_unix_millis(i64::try_from(rid.unix_millis()).map_err(internal)?)
        .map_err(internal)?;
    let tid = tutela_store::audit::deployment_tenant()?;
    let mut details = details;
    details.insert("by".into(), Value::String("operator".into()));
    let draft = AuditDraft {
        id: rid,
        time,
        tenant: TenantKey::new(iss.clone(), tid),
        org: None,
        actor: Actor::new(SYSTEM.parse().map_err(internal)?),
        action: format!("tutela_{thing}:{verb}").parse().map_err(internal)?,
        resource: ResourceRef {
            resource_type: format!("tutela_{thing}").parse().map_err(internal)?,
            id: id.parse().map_err(internal)?,
        },
        decision: DecisionSummary {
            effect: Effect::Allow,
            rule_ids: Vec::new(),
            rev: 0,
        },
        outcome: Outcome::Success,
        reason: Reason::parse("allowed").map_err(internal)?,
        trace_id: None,
        span_id: None,
        service: "tutelad".parse().map_err(internal)?,
        request_id: None,
        ip: None,
        payload_digest: None,
        labels: Vec::new(),
        details: Some(tutela_contracts::audit::Details::new(details).map_err(internal)?),
    };
    draft.check().map_err(internal)?;
    Ok(draft)
}

fn details(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

/// `tutela keys list`.
///
/// # Errors
///
/// A database error.
pub async fn list(client: &mut Client, out: &mut dyn Write) -> Result<(), CliError> {
    let tx = client.transaction().await?;
    let set = tutela_store::signing_keys(&tx).await?;
    tx.commit().await?;
    let signing = set.signing(set.now).map(|k| k.kid.clone());
    for k in &set.keys {
        let role = if Some(&k.kid) == signing.as_ref() {
            "signs"
        } else if k.signs_from > set.now {
            "next"
        } else {
            "previous"
        };
        writeln!(out, "{}  {role}", k.kid)?;
    }
    for kid in &set.denied {
        writeln!(out, "{kid}  denied")?;
    }
    let tx = client.transaction().await?;
    let audit = tutela_store::audit_keys(&tx).await?;
    tx.commit().await?;
    for k in &audit {
        let role = if k.retired_at.is_some() {
            "retired"
        } else {
            "signs"
        };
        writeln!(out, "{}  audit {role} ({})", k.kid, k.origin)?;
    }
    Ok(())
}

/// `tutela keys rotate --audit`: the audit producer key that signs is
/// retired and the next one is made (ADR-0045). Add its public key to
/// attache's `ledger.producers` first: the retired key is kept, so records
/// it signed still verify.
///
/// # Errors
///
/// A database or vault error.
pub async fn rotate_audit(
    client: &mut Client,
    vault: &Vault,
    iss: &Issuer,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let tx = client.transaction().await?;
    let (next, retired) = tutela_store::rotate_audit_key(&tx, vault).await?;
    let record = deployment_record(
        iss,
        "audit_key",
        "rotate",
        &next,
        details(&[
            ("kid", Value::String(next.clone())),
            ("retired", retired.clone().into()),
        ]),
    )?;
    tutela_store::append_deployment_audit(&tx, &[record]).await?;
    let public = tutela_store::audit_keys(&tx)
        .await?
        .into_iter()
        .find(|k| k.kid == next)
        .map(|k| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &k.public_key))
        .unwrap_or_default();
    tx.commit().await?;
    writeln!(out, "audit key {next} signs from the next forwarding tick")?;
    writeln!(out, "public key for attache's ledger.producers: {public}")?;
    if let Some(r) = retired {
        writeln!(
            out,
            "the key {r} is retired and kept: records it signed still verify"
        )?;
    }
    Ok(())
}

/// `tutela keys rotate`: a next key. With one already waiting, nothing is
/// made and it is shown.
///
/// # Errors
///
/// A database or vault error.
pub async fn rotate(
    client: &mut Client,
    vault: &Vault,
    iss: &Issuer,
    jwks_cache: Duration,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let tx = client.transaction().await?;
    let r = tutela_store::rotate_signing_key(&tx, vault, rotation_times(jwks_cache)).await?;
    if r.made {
        let record = deployment_record(
            iss,
            "signing_key",
            "rotate",
            &r.next,
            details(&[
                ("next", Value::String(r.next.clone())),
                ("signs_from_ms", millis(r.signs_from).into()),
                (
                    "previous",
                    r.previous.as_ref().map(|(k, _)| k.clone()).into(),
                ),
                (
                    "retire_at_ms",
                    r.previous.as_ref().map(|(_, t)| millis(*t)).into(),
                ),
            ]),
        )?;
        tutela_store::append_deployment_audit(&tx, &[record]).await?;
    }
    tx.commit().await?;
    let wait = r
        .signs_from
        .duration_since(SystemTime::now())
        .map_or(0, |d| d.as_secs());
    if r.made {
        writeln!(out, "next key {} signs in {wait} s", r.next)?;
    } else {
        writeln!(
            out,
            "a next key is already waiting: {} signs in {wait} s",
            r.next
        )?;
    }
    if let Some((kid, at)) = &r.previous {
        let left = at
            .duration_since(SystemTime::now())
            .map_or(0, |d| d.as_secs());
        writeln!(out, "the key {kid} leaves the JWKS in {left} s")?;
    }
    Ok(())
}

/// `tutela keys deny <kid>`: refused at once, and a new key signs.
///
/// # Errors
///
/// A database or vault error, or an unknown `kid`.
pub async fn deny(
    client: &mut Client,
    vault: &Vault,
    iss: &Issuer,
    kid: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let tx = client.transaction().await?;
    let replacement = tutela_store::deny_signing_key(&tx, vault, kid).await?;
    let record = deployment_record(
        iss,
        "signing_key",
        "deny",
        kid,
        details(&[
            ("kid", Value::String(kid.to_owned())),
            ("replacement", replacement.clone().into()),
        ]),
    )?;
    tutela_store::append_deployment_audit(&tx, &[record]).await?;
    tx.commit().await?;
    writeln!(out, "denied {kid}")?;
    if let Some(r) = replacement {
        writeln!(out, "{r} signs now")?;
    }
    Ok(())
}

/// `tutela keys rewrap`.
///
/// # Errors
///
/// A database or vault error.
pub async fn rewrap(
    client: &mut Client,
    vault: &Vault,
    iss: &Issuer,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let tx = client.transaction().await?;
    let n = tutela_store::rewrap_signing_keys(&tx, vault).await?
        + tutela_store::rewrap_audit_keys(&tx, vault).await?;
    let record = deployment_record(
        iss,
        "signing_key",
        "rewrap",
        "all",
        details(&[("rewrapped", n.into())]),
    )?;
    tutela_store::append_deployment_audit(&tx, &[record]).await?;
    tx.commit().await?;
    writeln!(out, "re-wrapped {n} key(s) under the current master key")?;
    Ok(())
}
