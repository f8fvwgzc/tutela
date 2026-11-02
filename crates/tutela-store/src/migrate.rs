//! Embedded, numbered migrations (ADR-0014).
//!
//! Each migration runs once, in its own transaction, under an advisory lock,
//! and is recorded in `tutela.schema_migration`. A database that has a
//! migration this build does not know is refused: an older binary never
//! writes to a newer schema.

use tokio_postgres::Client;

use crate::{DbResult as _, StoreError};

/// The migrations, in order. Released migrations never change.
const MIGRATIONS: &[(i32, &str, &str)] = &[
    (1, "init", include_str!("../migrations/0001_init.sql")),
    (
        2,
        "approver_key",
        include_str!("../migrations/0002_approver_key.sql"),
    ),
    (
        3,
        "assignment_expiry",
        include_str!("../migrations/0003_assignment_expiry.sql"),
    ),
    (
        4,
        "model_versions",
        include_str!("../migrations/0004_model_versions.sql"),
    ),
    (
        5,
        "two_person",
        include_str!("../migrations/0005_two_person.sql"),
    ),
    (
        6,
        "signing_keys",
        include_str!("../migrations/0006_signing_keys.sql"),
    ),
    (
        7,
        "principals",
        include_str!("../migrations/0007_principals.sql"),
    ),
    (
        8,
        "audit_log",
        include_str!("../migrations/0008_audit_log.sql"),
    ),
    (9, "events", include_str!("../migrations/0009_events.sql")),
    (
        10,
        "webhooks",
        include_str!("../migrations/0010_webhooks.sql"),
    ),
    (
        11,
        "audit_forward",
        include_str!("../migrations/0011_audit_forward.sql"),
    ),
    (
        12,
        "lifecycle",
        include_str!("../migrations/0012_lifecycle.sql"),
    ),
];

/// One lock id for every migrator of this schema (`pg_advisory_xact_lock`).
const LOCK_ID: i64 = 0x7475_7465_6c61_0001;

/// Applies every migration the database does not have yet. Returns the
/// versions applied now (empty when the schema is current).
///
/// Run it with a role that may create the schema and its tables (the
/// owner), not with the product's runtime role (PERMISSION-MODEL.md 16.2).
///
/// # Errors
///
/// [`Database`](crate::StoreErrorKind::Database) if a migration fails (nothing
/// of it stays), and [`SchemaTooNew`](crate::StoreErrorKind::SchemaTooNew) if
/// the database has a migration this build does not know.
pub async fn migrate(client: &mut Client) -> Result<Vec<i32>, StoreError> {
    let tx = client.transaction().await.db()?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&LOCK_ID])
        .await
        .db()?;
    tx.batch_execute(
        "CREATE SCHEMA IF NOT EXISTS tutela;
         CREATE TABLE IF NOT EXISTS tutela.schema_migration (
             version    integer PRIMARY KEY,
             name       text NOT NULL,
             applied_at timestamptz NOT NULL DEFAULT now()
         );",
    )
    .await
    .db()?;
    let have: Vec<i32> = tx
        .query("SELECT version FROM tutela.schema_migration", &[])
        .await
        .db()?
        .iter()
        .map(|r| r.get(0))
        .collect();
    if let Some(&v) = have
        .iter()
        .find(|v| !MIGRATIONS.iter().any(|(m, _, _)| m == *v))
    {
        return Err(StoreError::schema_too_new(v));
    }
    let mut applied = Vec::new();
    for &(version, name, sql) in MIGRATIONS {
        if have.contains(&version) {
            continue;
        }
        tx.batch_execute(sql).await.db()?;
        tx.execute(
            "INSERT INTO tutela.schema_migration (version, name) VALUES ($1, $2)",
            &[&version, &name],
        )
        .await
        .db()?;
        applied.push(version);
    }
    tx.commit().await.db()?;
    Ok(applied)
}

/// The newest migration in the database, or 0 if none has run. A role that
/// is not the owner can read this once it has its grants.
///
/// # Errors
///
/// A database error, for example when the schema does not exist.
pub async fn applied(client: &Client) -> Result<i32, StoreError> {
    client
        .query_one(
            "SELECT coalesce(max(version), 0) FROM tutela.schema_migration",
            &[],
        )
        .await
        .db()?
        .try_get(0)
        .db()
}

/// The newest migration this build knows.
#[must_use]
pub fn latest() -> i32 {
    MIGRATIONS.last().map_or(0, |&(v, _, _)| v)
}
