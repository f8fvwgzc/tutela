//! The operator's side of a tenant's lifecycle (ADR-0041): `tutelad tenant
//! create` and `tutelad tenant restore`, which run as the owner role, and
//! the purge, which runs on the expiry sweep's timer.
//!
//! **Who makes a tenant.** A tenant is above every tenant's roles (TM-08),
//! so no route of the API makes one: the operator does, with the owner's
//! credentials, as for `tutelad migrate`. The first org and its first owners
//! are made with it, because every admin call needs keys at every org.
//! Part 4's Helm bootstrap job and CLI call [`create_tenant`].

use tutela_contracts::audit::{Actor, AuditDraft};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::{Issuer, OrgId, TenantId, TenantKey};
use tutela_pdp::model::RoleKey;
use tutela_pdp::{PathEntry, Subject};
use tutela_store::OutboxEvent;
use tutela_store::tokio_postgres::Client;

use crate::audit::{BuildError, Record, system};

/// The role the first owners get at the first org: the seeded Owner
/// (MANIFEST.md 5.1), every admin key there.
pub const OWNER_ROLE: &str = "owner";

/// A tenant to make.
#[derive(Clone, Debug, Default)]
pub struct NewTenant {
    /// Its display name.
    pub name: Option<String>,
    /// The name of its first org.
    pub org_name: Option<String>,
    /// Principals made owners of the first org: a person (`user:`) or a
    /// service account (`sa:`).
    pub admins: Vec<Principal>,
    /// People made owners of the first org by their upstream `(iss, sub)`,
    /// found or made as token exchange does (ADR-0031).
    pub upstream_admins: Vec<(Issuer, String)>,
}

/// A tenant just made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Created {
    /// The tenant key, under `TUTELA_ISSUER`.
    pub key: TenantKey,
    /// Its first org.
    pub org: OrgId,
    /// Its first owners, in the order given.
    pub owners: Vec<Principal>,
    /// The revision after the owners were assigned.
    pub rev: u64,
}

/// A record about a tenant by `tutelad` itself.
pub(crate) fn system_record(
    tenant: &TenantKey,
    action: &str,
    resource: (&str, &str),
    rev: u64,
) -> Result<Record, BuildError> {
    Ok(Record::new(tenant, Actor::new(system()?), action, resource).allowed(rev))
}

/// The record of `action` on tenant `of` in the deployment's own chain
/// (ADR-0034 item 10), whose tenant key names `own`: a tenant's lifecycle
/// is above any one tenant, and the deployment's chain is forwarded after
/// the tenant's own stops.
///
/// # Errors
///
/// A record that cannot be built: a bug.
pub fn deployment_record(
    own: &Issuer,
    action: &str,
    of: &TenantKey,
    actor: Actor,
) -> Result<Record, BuildError> {
    let tid = tutela_store::audit::deployment_tenant()
        .map_err(|_| BuildError::new("deployment tenant"))?;
    let tenant = of.tid.to_string();
    Ok(Record::new(
        &TenantKey::new(own.clone(), tid),
        actor,
        action,
        ("tutela_tenant", &tenant),
    )
    .allowed(0)
    .detail("tid", tenant.clone())
    .detail("tenant_iss", of.iss.to_string()))
}

pub(crate) fn drafts(records: Vec<Record>) -> Result<Vec<AuditDraft>, BuildError> {
    records.into_iter().map(Record::build).collect()
}

/// Makes a tenant under `own` (`TUTELA_ISSUER`), with its first org and its
/// first owners, on `owner`, a connection of the **owner** role. The tenant's
/// chain records the creation and each owner; so does the deployment's.
///
/// # Errors
///
/// No owner given, a bad name, a principal that is not a person or a
/// service account, or a database error. Nothing is made then.
pub async fn create_tenant(
    owner: &mut Client,
    own: &Issuer,
    new: &NewTenant,
) -> anyhow::Result<Created> {
    create(owner, own, None, new).await
}

/// As [`create_tenant`], with the tenant id `tid` the operator chose: the
/// Helm bootstrap job names the tenant in the trust file before it makes it
/// (ADR-0056). An id in the directory already, in any state, is refused.
///
/// # Errors
///
/// As [`create_tenant`], and an id that is in use.
pub async fn create_tenant_with_id(
    owner: &mut Client,
    own: &Issuer,
    tid: TenantId,
    new: &NewTenant,
) -> anyhow::Result<Created> {
    create(owner, own, Some(tid), new).await
}

async fn create(
    owner: &mut Client,
    own: &Issuer,
    tid: Option<TenantId>,
    new: &NewTenant,
) -> anyhow::Result<Created> {
    anyhow::ensure!(
        !new.admins.is_empty() || !new.upstream_admins.is_empty(),
        "a tenant needs at least one owner (--admin or --admin-upstream)"
    );
    for a in &new.admins {
        anyhow::ensure!(
            matches!(
                a.kind(),
                PrincipalKind::User | PrincipalKind::ServiceAccount
            ),
            "an owner is a user or a service account"
        );
    }
    let role = RoleKey::parse(OWNER_ROLE)?;
    let tx = owner.transaction().await?;
    let key = match tid {
        Some(tid) => {
            anyhow::ensure!(
                tutela_store::directory_entry(&tx, &tid).await?.is_none(),
                "the tenant id is in use"
            );
            tutela_store::create_tenant_with_id(&tx, own, tid).await?
        }
        None => tutela_store::create_tenant(&tx, own).await?,
    };
    if new.name.is_some() {
        tutela_store::set_tenant_name(&tx, &key, new.name.as_deref()).await?;
    }
    let (org, _) = tutela_store::add_org(&tx, &key).await?;
    if new.org_name.is_some() {
        tutela_store::set_org_name(&tx, &key, &org, new.org_name.as_deref()).await?;
    }
    let mut owners = new.admins.clone();
    for (iss, sub) in &new.upstream_admins {
        let (state, _) = tutela_store::provision_user(&tx, &key, iss, sub).await?;
        owners.push(state.principal);
    }
    let at = PathEntry::org(&org).map_err(|_| anyhow::anyhow!("the new org is not a scope"))?;
    let mut rev = 0;
    for o in &owners {
        let (_, r) =
            tutela_store::assign(&tx, &key, &Subject::Principal(o.clone()), &role, &at, None)
                .await?;
        rev = r;
    }
    tutela_store::emit(&tx, &key, OutboxEvent::OrgCreated { org }).await?;
    let tid = key.tid.to_string();
    let mut records = vec![
        system_record(&key, "tutela_tenant:create", ("tutela_tenant", &tid), rev)?
            .detail("by", "operator"),
        system_record(
            &key,
            "tutela_org:create",
            ("tutela_org", &org.to_string()),
            rev,
        )?
        .org(org),
    ];
    for o in &owners {
        records.push(
            system_record(
                &key,
                "tutela_org:owner",
                ("tutela_org", &org.to_string()),
                rev,
            )?
            .org(org)
            .detail("principal", o.to_string())
            .detail("role", OWNER_ROLE),
        );
    }
    tutela_store::append_audit(&tx, &key, &drafts(records)?).await?;
    tx.commit().await?;
    let tx = owner.transaction().await?;
    let record = deployment_record(own, "tutela_tenant:create", &key, Actor::new(system()?))?
        .detail("by", "operator");
    tutela_store::append_deployment_audit(&tx, &drafts(vec![record])?).await?;
    tx.commit().await?;
    Ok(Created {
        key,
        org,
        owners,
        rev,
    })
}

/// Undoes a tenant's soft delete before its purge, on `owner`, a connection
/// of the owner role. Recorded in the tenant's chain and the deployment's.
///
/// # Errors
///
/// A tenant that is not soft-deleted, or already purged, or a database
/// error.
pub async fn restore_tenant(
    owner: &mut Client,
    own: &Issuer,
    key: &TenantKey,
) -> anyhow::Result<()> {
    let tx = owner.transaction().await?;
    anyhow::ensure!(
        tutela_store::restore_tenant(&tx, key).await?,
        "no such soft-deleted tenant, or it is purged already"
    );
    let rev = tutela_store::rev(&tx, key).await?;
    let tid = key.tid.to_string();
    let record = system_record(key, "tutela_tenant:restore", ("tutela_tenant", &tid), rev)?
        .detail("by", "operator");
    tutela_store::append_audit(&tx, key, &drafts(vec![record])?).await?;
    tx.commit().await?;
    let tx = owner.transaction().await?;
    let record = deployment_record(own, "tutela_tenant:restore", key, Actor::new(system()?))?
        .detail("by", "operator");
    tutela_store::append_deployment_audit(&tx, &drafts(vec![record])?).await?;
    tx.commit().await?;
    Ok(())
}

/// Makes an app of tenant `key` for the bootstrap (ADR-0044 item 1), on
/// `owner`, a connection of the **owner** role: its service account and its
/// first client secret, which is returned once and stored only as its hash
/// with the pepper of `secrets`. The tenant must be under `own`: `tutelad`
/// issues tokens for its own tenants only. The tenant's chain and the
/// deployment's record it.
///
/// # Errors
///
/// A tenant that is not under `own` or not in the directory, a bad name,
/// or a database error. Nothing is made then.
pub async fn create_app(
    owner: &mut Client,
    own: &Issuer,
    key: &TenantKey,
    name: &str,
    secrets: &crate::config::Secrets,
) -> anyhow::Result<(tutela_store::AppInfo, zeroize::Zeroizing<String>)> {
    anyhow::ensure!(
        key.iss == *own,
        "an app belongs to a tenant under TUTELA_ISSUER"
    );
    let (pepper, version) = secrets.pepper();
    let (secret, hash) = crate::apps::new_secret(pepper, version)?;
    let tx = owner.transaction().await?;
    let app = tutela_store::create_app(&tx, key, name, "operator", &hash).await?;
    let rev = tutela_store::rev(&tx, key).await?;
    let record = system_record(key, "tutela_app:create", ("tutela_app", &app.id), rev)?
        .detail("by", "operator")
        .detail("app", app.id.clone())
        .detail("principal", app.principal.to_string())
        .detail("key_id", hash.key_id.clone())
        .detail("prefix", format!("tut_sk_{}", hash.prefix));
    tutela_store::append_audit(&tx, key, &drafts(vec![record])?).await?;
    tx.commit().await?;
    let tx = owner.transaction().await?;
    let record = deployment_record(own, "tutela_app:create", key, Actor::new(system()?))?
        .detail("by", "operator")
        .detail("app", app.id.clone());
    tutela_store::append_deployment_audit(&tx, &drafts(vec![record])?).await?;
    tx.commit().await?;
    Ok((app, secret))
}

/// The records of a tenant's purge, in its own chain, by `tutelad`.
///
/// # Errors
///
/// A record that cannot be built: a bug.
pub(crate) fn purge_records(key: &TenantKey) -> Result<Vec<AuditDraft>, BuildError> {
    let tid = key.tid.to_string();
    drafts(vec![system_record(
        key,
        "tutela_tenant:purge",
        ("tutela_tenant", &tid),
        0,
    )?])
}

/// The record of an org's purge, in its tenant's chain, by `tutelad`.
///
/// # Errors
///
/// A record that cannot be built: a bug.
pub(crate) fn org_purge_records(
    key: &TenantKey,
    org: &OrgId,
    rev: u64,
) -> Result<Vec<AuditDraft>, BuildError> {
    drafts(vec![
        system_record(
            key,
            "tutela_org:purge",
            ("tutela_org", &org.to_string()),
            rev,
        )?
        .org(*org),
    ])
}

/// A connection of the owner role from `url` (`TUTELA_OWNER_DATABASE_URL`),
/// with the TLS rule of every database connection (ADR-0018 item 10).
///
/// # Errors
///
/// A bad URL, a failed TLS setup, or no connection. The text never holds
/// the URL.
pub async fn connect_owner(url: &str) -> anyhow::Result<Client> {
    use anyhow::Context as _;
    let (pg, transport) = tutela_store::database_config(url).map_err(|e| {
        anyhow::anyhow!(
            e.detail()
                .unwrap_or("TUTELA_OWNER_DATABASE_URL is not valid")
        )
    })?;
    let client = match transport {
        tutela_store::Transport::Local => {
            let (client, conn) = pg
                .connect(tutela_store::tokio_postgres::NoTls)
                .await
                .context("connecting as the owner")?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
        }
        tutela_store::Transport::Tls => {
            let tls = tutela_safenet::tls_client_config().context("setting up database TLS")?;
            let (client, conn) = pg
                .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
                .await
                .context("connecting as the owner")?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
        }
    };
    Ok(client)
}
