//! The applied manifest of each app, and model changes (library mode).
//!
//! In library mode the model is the product's `tutela.resources.toml`
//! (ARCHITECTURE.md, library mode). The store keeps the applied text and
//! its digest; [`publish_manifest`] replaces it and, in the same
//! transaction, bumps every tenant's revision and records the change in
//! each tenant's `model_revision` (PERMISSION-MODEL.md 15, 16). A tenant
//! that published its own model through `tutelad` keeps it (ADR-0026).

use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use tutela_contracts::tenant::{TenantId, TenantKey};
use tutela_pdp::model::{AppName, Class};

use crate::{DbResult as _, StoreError, set_tenant, to_rev};

/// The applied manifest of an app.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoredManifest {
    /// The manifest text.
    pub source: String,
    /// SHA-256 of the text, lowercase hex.
    pub digest: String,
    /// 1 for the first apply, then one more per apply.
    pub version: i64,
}

/// A model change to publish.
#[derive(Clone, Debug)]
pub struct Publish<'a> {
    /// The app whose manifest changes.
    pub app: &'a AppName,
    /// The new manifest text. The caller has compiled it.
    pub source: &'a str,
    /// The version the caller compared against: `None` when the app had no
    /// manifest. If another apply came first, the publish is refused.
    pub expected: Option<i64>,
    /// The class of the diff.
    pub class: Class,
    /// The diff as text, one change per line.
    pub diff: &'a str,
    /// Who applied it (for the record).
    pub author: Option<&'a str>,
    /// The approval key ids for a widening change.
    pub approvers: &'a [String],
}

/// SHA-256 of a manifest text, lowercase hex.
#[must_use]
pub fn digest(source: &str) -> String {
    Sha256::digest(source.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The applied manifest of `app`, if any.
///
/// # Errors
///
/// A database error.
pub async fn manifest(
    tx: &Transaction<'_>,
    app: &AppName,
) -> Result<Option<StoredManifest>, StoreError> {
    let row = tx
        .query_opt(
            "SELECT source, digest, version FROM tutela.app_manifest WHERE app = $1",
            &[&app.as_str()],
        )
        .await
        .db()?;
    row.map(|r| {
        Ok(StoredManifest {
            source: r.try_get(0).db()?,
            digest: r.try_get(1).db()?,
            version: r.try_get(2).db()?,
        })
    })
    .transpose()
}

/// The one applied manifest of this schema, if any. A schema holds one app
/// (ADR-0014 item 7): assignments name role keys without an app, so a second
/// app would mean something else by the same key. That is an error, not a
/// choice between the two.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) when two apps have a manifest,
/// or a database error.
pub async fn applied_manifest(tx: &Transaction<'_>) -> Result<Option<StoredManifest>, StoreError> {
    let rows = tx
        .query(
            "SELECT source, digest, version FROM tutela.app_manifest LIMIT 2",
            &[],
        )
        .await
        .db()?;
    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Ok(None)
        } else {
            Err(StoreError::invalid("this schema holds more than one app"))
        };
    };
    Ok(Some(StoredManifest {
        source: row.try_get(0).db()?,
        digest: row.try_get(1).db()?,
        version: row.try_get(2).db()?,
    }))
}

/// Publishes a manifest: replaces the app's manifest, then, in the same
/// transaction, bumps every tenant's revision and records the change for
/// each one. Returns each tenant with its new revision.
///
/// The caller compiles the new text, compares it with the stored one and
/// decides whether the change may go in (a widening change needs an
/// approval token). This function only stores the result.
///
/// # Errors
///
/// [`Exists`](crate::StoreErrorKind::Exists) if the stored version is not
/// `expected` (another apply came first),
/// [`Corrupt`](crate::StoreErrorKind::Corrupt) for a bad tenant row, or a
/// database error.
pub async fn publish_manifest(
    tx: &Transaction<'_>,
    p: &Publish<'_>,
) -> Result<Vec<(TenantKey, u64)>, StoreError> {
    let app = p.app.as_str();
    // Serialize applies of one app.
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended('tutela.apply:' || $1, 0))",
        &[&app],
    )
    .await
    .db()?;
    let current: Option<i64> = tx
        .query_opt(
            "SELECT version FROM tutela.app_manifest WHERE app = $1",
            &[&app],
        )
        .await
        .db()?
        .map(|r| r.try_get(0))
        .transpose()
        .db()?;
    if current != p.expected {
        return Err(StoreError::exists("a newer manifest; compare again"));
    }
    let digest = digest(p.source);
    let version = current.unwrap_or(0).saturating_add(1);
    tx.execute(
        "INSERT INTO tutela.app_manifest (app, source, digest, version, applied_by) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (app) DO UPDATE SET source = excluded.source, \
         digest = excluded.digest, version = excluded.version, applied_at = now(), \
         applied_by = excluded.applied_by",
        &[&app, &p.source, &digest, &version, &p.author],
    )
    .await
    .db()?;
    let tenants = tx
        .query(
            "SELECT tenant_id, iss FROM tutela.tenant ORDER BY tenant_id",
            &[],
        )
        .await
        .db()?;
    let mut out = Vec::with_capacity(tenants.len());
    for t in tenants {
        let tid: TenantId = t
            .try_get::<_, &str>(0)
            .db()?
            .parse()
            .map_err(|_| StoreError::corrupt("tenant id"))?;
        let iss = t
            .try_get::<_, &str>(1)
            .db()?
            .parse()
            .map_err(|_| StoreError::corrupt("issuer"))?;
        set_tenant(tx, &tid).await?;
        // A tenant that published its own model keeps it (ADR-0026): the
        // revision moves, the model does not.
        let head: Option<(i64, String)> = tx
            .query_opt(
                "SELECT version, origin FROM tutela.model_revision WHERE tenant_id = $1 \
                 ORDER BY version DESC LIMIT 1",
                &[&tid.to_string()],
            )
            .await
            .db()?
            .map(|r| Ok((r.try_get(0).db()?, r.try_get(1).db()?)))
            .transpose()
            .map_err(|e: StoreError| e)?;
        let rev: i64 = tx
            .query_opt(
                "UPDATE tutela.tenant_rev SET rev = rev + 1 WHERE tenant_id = $1 RETURNING rev",
                &[&tid.to_string()],
            )
            .await
            .db()?
            .ok_or(StoreError::corrupt("tenant revision row"))?
            .try_get(0)
            .db()?;
        if head.as_ref().is_none_or(|(_, origin)| origin != "tenant") {
            let number = head.map_or(1, |(v, _)| v.saturating_add(1));
            tx.execute(
                "INSERT INTO tutela.model_revision (tenant_id, rev, parent_rev, app, author, \
                 approvers, diff, class, state, published_at, bundle_digest, version, source) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'published', now(), $9, $10, $11)",
                &[
                    &tid.to_string(),
                    &rev,
                    &(rev - 1),
                    &app,
                    &p.author,
                    &p.approvers,
                    &p.diff,
                    &class_text(p.class),
                    &digest,
                    &number,
                    &p.source,
                ],
            )
            .await
            .db()?;
        }
        out.push((TenantKey::new(iss, tid), to_rev(rev)?));
    }
    // A manifest is the one write that spans tenants. Leave none entered.
    tx.execute("SELECT set_config('tutela.tenant_id', '', true)", &[])
        .await
        .db()?;
    Ok(out)
}

/// The stored class: `narrowing`, `neutral` or `widening` (PERMISSION-MODEL.md 18).
pub(crate) const fn class_text(c: Class) -> &'static str {
    match c {
        Class::Narrowing => "narrowing",
        Class::Neutral => "neutral",
        Class::Widening => "widening",
    }
}
