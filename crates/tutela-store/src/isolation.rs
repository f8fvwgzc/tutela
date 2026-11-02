//! The database side of tenant isolation (THREAT-MODEL.md TM-14): the grants
//! of a runtime role, and a check that the role and the schema really
//! isolate tenants.
//!
//! Row-level security stops a code bug only when the role cannot bypass it.
//! A superuser, a `BYPASSRLS` role and a table's owner without `FORCE` all
//! see every tenant, and nothing in a query shows it. So this is checked
//! against the catalogs, not assumed.

use tokio_postgres::Client;

use crate::{DbResult as _, StoreError};

/// Tables with no tenant data that a runtime role may read. The tenant
/// directory is needed to enter a tenant, the applied manifest for the
/// model, the migration table for the readiness check, and the approver keys
/// to check an approval token. It writes none of them: a tenant's own model
/// is tenant data (ADR-0026), so no call of the service reaches the app's
/// manifest.
const READ_ONLY: [&str; 4] = ["tenant", "app_manifest", "schema_migration", "approver_key"];

/// Tables with no tenant data that a runtime role may read, add to and
/// update, never delete from: the service's own signing keys (ADR-0030).
/// A trigger keeps a key's identity and its denial.
const KEPT: [&str; 1] = ["signing_key"];

/// Tables with tenant data where a runtime role gets less than read and
/// write: the audit log is append-only (ADR-0034), and its head only moves
/// forward. A trigger refuses the rest for every role as well.
const LIMITED: [(&str, &str); 2] = [
    ("audit_record", "SELECT, INSERT"),
    ("audit_head", "SELECT, INSERT, UPDATE"),
];

/// A plain role name: it goes into `GRANT`, which takes no parameters.
fn plain_role(role: &str) -> bool {
    !role.is_empty()
        && role.len() <= 63
        && role
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && role
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Gives a runtime role what it needs and no more: read and write on every
/// table with row-level security, read on the tenant directory, the applied
/// manifest, the migration table and the approver keys, read, add and update
/// on the signing keys, and nothing else. It owns nothing and cannot create
/// anything.
///
/// Run it as the owner, after [`migrate`](crate::migrate), in the same
/// deploy step: a new tenant table gets its grant from the catalog here. It
/// may run again at any time.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a role name that is not
/// plain, or for the role that is running this (it owns the tables), or a
/// database error, for example an unknown role.
pub async fn grant_service(client: &mut Client, role: &str) -> Result<(), StoreError> {
    if !plain_role(role) {
        return Err(StoreError::invalid(
            "a role name is at most 63 characters of a-z, 0-9 and `_`",
        ));
    }
    let tx = client.transaction().await.db()?;
    let me: String = tx
        .query_one("SELECT current_user::text", &[])
        .await
        .db()?
        .try_get(0)
        .db()?;
    if me == role {
        return Err(StoreError::invalid(
            "the runtime role must not be the role that owns the tables",
        ));
    }
    tx.batch_execute(&format!("GRANT USAGE ON SCHEMA tutela TO {role}"))
        .await
        .db()?;
    let tables = tx
        .query(
            "SELECT c.relname::text FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'tutela' AND c.relkind = 'r' AND c.relrowsecurity \
             AND c.relforcerowsecurity AND EXISTS \
             (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)",
            &[],
        )
        .await
        .db()?;
    for t in tables {
        let table: &str = t.try_get(0).db()?;
        let privileges = LIMITED
            .iter()
            .find(|(name, _)| *name == table)
            .map_or("SELECT, INSERT, UPDATE, DELETE", |(_, p)| *p);
        tx.batch_execute(&format!(
            "REVOKE ALL ON tutela.\"{table}\" FROM {role}; \
             GRANT {privileges} ON tutela.\"{table}\" TO {role}"
        ))
        .await
        .db()?;
    }
    for table in READ_ONLY {
        tx.batch_execute(&format!("GRANT SELECT ON tutela.{table} TO {role}"))
            .await
            .db()?;
    }
    for table in KEPT {
        tx.batch_execute(&format!(
            "GRANT SELECT, INSERT, UPDATE ON tutela.{table} TO {role}"
        ))
        .await
        .db()?;
    }
    tx.commit().await.db()
}

/// Checks, on this connection, that the current role and the schema isolate
/// tenants:
///
/// - the role is not a superuser and has no `BYPASSRLS`;
/// - it owns nothing in the schema, is not a member of an owner, and cannot
///   create objects there;
/// - every table with a `tenant_id` column, except the tenant directory, has
///   row-level security, `FORCE` and a policy;
/// - the schema has no `SECURITY DEFINER` function and no owner-rights view;
/// - the role may not change or remove an audit record, and the triggers
///   that refuse it for every role are enabled (ADR-0034).
///
/// `tutelad` refuses to serve when this fails. A product in library mode can
/// call it at start-up too.
///
/// # Errors
///
/// [`Isolation`](crate::StoreErrorKind::Isolation), naming the first rule
/// that fails, or a database error.
pub async fn check_isolation(client: &Client) -> Result<(), StoreError> {
    let role = client
        .query_one(
            "SELECT r.rolsuper, r.rolbypassrls, \
             EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                     WHERE n.nspname = 'tutela' AND pg_has_role(current_user, c.relowner, 'MEMBER')), \
             has_schema_privilege(current_user, 'tutela', 'CREATE') \
             FROM pg_roles r WHERE r.rolname = current_user",
            &[],
        )
        .await
        .db()?;
    if role.try_get::<_, bool>(0).db()? {
        return Err(StoreError::isolation("the role is a superuser"));
    }
    if role.try_get::<_, bool>(1).db()? {
        return Err(StoreError::isolation("the role has BYPASSRLS"));
    }
    if role.try_get::<_, bool>(2).db()? {
        return Err(StoreError::isolation("the role owns a table in the schema"));
    }
    if role.try_get::<_, bool>(3).db()? {
        return Err(StoreError::isolation(
            "the role may create objects in the schema",
        ));
    }
    let schema = client
        .query_one(
            "SELECT \
             EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                     JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' \
                     WHERE n.nspname = 'tutela' AND c.relkind IN ('r', 'p') \
                     AND c.relname <> 'tenant' \
                     AND NOT (c.relrowsecurity AND c.relforcerowsecurity \
                              AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid))), \
             EXISTS (SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid = f.pronamespace \
                     WHERE n.nspname = 'tutela' AND f.prosecdef), \
             EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                     WHERE n.nspname = 'tutela' AND c.relkind IN ('v', 'm') \
                     AND NOT coalesce(c.reloptions @> ARRAY['security_invoker=true'], false))",
            &[],
        )
        .await
        .db()?;
    if schema.try_get::<_, bool>(0).db()? {
        return Err(StoreError::isolation(
            "a tenant table has no forced row-level security",
        ));
    }
    if schema.try_get::<_, bool>(1).db()? {
        return Err(StoreError::isolation(
            "the schema has a SECURITY DEFINER function",
        ));
    }
    if schema.try_get::<_, bool>(2).db()? {
        return Err(StoreError::isolation("the schema has an owner-rights view"));
    }
    let audit = client
        .query_one(
            "SELECT CASE WHEN to_regclass('tutela.audit_record') IS NULL THEN 0 \
             WHEN has_table_privilege(current_user, 'tutela.audit_record', 'UPDATE') \
               OR has_table_privilege(current_user, 'tutela.audit_record', 'DELETE') \
               OR has_table_privilege(current_user, 'tutela.audit_record', 'TRUNCATE') \
               OR has_table_privilege(current_user, 'tutela.audit_head', 'DELETE') \
               OR has_table_privilege(current_user, 'tutela.audit_head', 'TRUNCATE') THEN 1 \
             WHEN (SELECT count(*) FROM pg_trigger \
                   WHERE tgrelid IN (to_regclass('tutela.audit_record'), to_regclass('tutela.audit_head')) \
                   AND tgname IN ('audit_record_kept', 'audit_record_not_truncated', \
                                  'audit_head_forward', 'audit_head_not_truncated') \
                   AND tgenabled IN ('O', 'A')) <> 4 THEN 2 \
             ELSE 0 END",
            &[],
        )
        .await
        .db()?;
    match audit.try_get::<_, i32>(0).db()? {
        0 => Ok(()),
        1 => Err(StoreError::isolation("the role may change the audit log")),
        _ => Err(StoreError::isolation(
            "the audit log's append-only triggers are not enabled",
        )),
    }
}
