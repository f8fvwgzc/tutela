//! Embedded, numbered migrations (ADR-0014).
//!
//! Each migration runs once, in its own transaction, under an advisory lock,
//! and is recorded in `tutela.schema_migration`. A database that has a
//! migration this build does not know is refused: an older binary never
//! writes to a newer schema.

use tokio_postgres::Client;

use crate::StoreError;

/// The migrations, in order. Released migrations never change.
const MIGRATIONS: &[(i32, &str, &str)] =
    &[(1, "init", include_str!("../migrations/0001_init.sql"))];

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
/// [`StoreError::Db`] if a migration fails (nothing of it stays), and
/// [`StoreError::SchemaTooNew`] if the database has a migration this build
/// does not know.
pub async fn migrate(client: &mut Client) -> Result<Vec<i32>, StoreError> {
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&LOCK_ID])
        .await?;
    tx.batch_execute(
        "CREATE SCHEMA IF NOT EXISTS tutela;
         CREATE TABLE IF NOT EXISTS tutela.schema_migration (
             version    integer PRIMARY KEY,
             name       text NOT NULL,
             applied_at timestamptz NOT NULL DEFAULT now()
         );",
    )
    .await?;
    let have: Vec<i32> = tx
        .query("SELECT version FROM tutela.schema_migration", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    if let Some(&v) = have
        .iter()
        .find(|v| !MIGRATIONS.iter().any(|(m, _, _)| m == *v))
    {
        return Err(StoreError::SchemaTooNew(v));
    }
    let mut applied = Vec::new();
    for &(version, name, sql) in MIGRATIONS {
        if have.contains(&version) {
            continue;
        }
        tx.batch_execute(sql).await?;
        tx.execute(
            "INSERT INTO tutela.schema_migration (version, name) VALUES ($1, $2)",
            &[&version, &name],
        )
        .await?;
        applied.push(version);
    }
    tx.commit().await?;
    Ok(applied)
}

/// The newest migration this build knows.
#[must_use]
pub fn latest() -> i32 {
    MIGRATIONS.last().map_or(0, |&(v, _, _)| v)
}
