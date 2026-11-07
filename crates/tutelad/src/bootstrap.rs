//! `tutelad bootstrap`: what the Helm chart's bootstrap job does before the
//! service starts (ADR-0056), as the owner role, from a plan the chart
//! writes from its values.
//!
//! 1. Applies the migrations, as `tutelad migrate` does.
//! 2. Makes the tenant with the id the plan names (the trust file names it
//!    before it exists) and its first owners, unless it is there already.
//! 3. Makes each product's app, unless an enabled app of that name is there,
//!    and writes its client secret to the product's Kubernetes Secret.
//! 4. Gives each app's service account its roles, unless it has an
//!    assignment at that scope already: a role the tenant's owner changed
//!    later is kept.
//! 5. Registers each webhook for its product's app and writes its secret to
//!    a Kubernetes Secret, unless a webhook at that URL is there already.
//!
//! **Idempotent.** It runs again on every upgrade and changes nothing that
//! is there. A secret is shown once (ADR-0044, ADR-0036), so when the app or
//! webhook is there but its Secret is gone (or names another app), the job
//! rotates it, with the usual one-hour overlap, and writes the new one.
//! Every change is recorded in the tenant's audit chain, by `tutelad`, as
//! the operator.
//!
//! The job prints one JSON line per step, never a secret.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use serde::Deserialize;
use tutela_contracts::audit::Actor;
use tutela_contracts::events::EventType;
use tutela_contracts::keys::{ResourceId, ResourceType};
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{Issuer, OrgId, TenantId, TenantKey};
use tutela_pdp::model::RoleKey;
use tutela_pdp::{PathEntry, Subject};
use tutela_store::tokio_postgres::Client;

use crate::audit::Record;
use crate::config::Secrets;
use crate::lifecycle::{self, NewTenant, drafts, system_record};

pub mod kube;

/// How long an old secret keeps working after the job rotates it because
/// its Secret was gone: the default overlap of a rotation (ADR-0044 item 8).
pub const ROTATE_OVERLAP: Duration = Duration::from_secs(3600);

/// What the job makes, from the chart's values.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// The tenant.
    pub tenant: TenantPlan,
    /// The products' apps.
    #[serde(default)]
    pub apps: Vec<AppPlan>,
    /// The products' webhooks.
    #[serde(default)]
    pub webhooks: Vec<WebhookPlan>,
    /// The Console's URL, printed at the end when set.
    #[serde(default)]
    pub console_url: Option<String>,
}

/// The tenant of the deployment.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlan {
    /// Its id, `ten_<uuidv7>`: the trust file's `tenants` names it.
    pub id: String,
    /// Its display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Its first org's display name.
    #[serde(default)]
    pub org_name: Option<String>,
    /// The first owners by their upstream account, `<iss>=<sub>`.
    #[serde(default)]
    pub admin_upstream: Vec<String>,
    /// The first owners by principal, `user:usr_…` or `sa:sa_…`.
    #[serde(default)]
    pub admins: Vec<String>,
}

/// A product's app.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPlan {
    /// The app's name, unique in the plan.
    pub name: String,
    /// The Kubernetes Secret its credentials go to.
    pub secret: String,
    /// The roles its service account gets.
    #[serde(default)]
    pub roles: Vec<RolePlan>,
}

/// A role for an app's service account.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolePlan {
    /// The role key, for example `owner`.
    pub role: String,
    /// `org` for the tenant's first org, or `<type>:<id>`.
    #[serde(default = "first_org")]
    pub scope: String,
}

fn first_org() -> String {
    "org".to_owned()
}

/// A product's webhook.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookPlan {
    /// The app of the plan it is registered for.
    pub app: String,
    /// The endpoint: a public https URL (CONTRACTS.md 8.5).
    pub url: String,
    /// The event types; empty: every type.
    #[serde(default)]
    pub types: Vec<String>,
    /// The Kubernetes Secret its signing secret goes to.
    pub secret: String,
}

impl Plan {
    /// Reads and checks a plan.
    ///
    /// # Errors
    ///
    /// JSON that is not a plan, a bad tenant id, Secret name, app name,
    /// role, scope or event type, or a webhook for an app the plan lacks.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let plan: Self = serde_json::from_str(text).context("the plan is not valid")?;
        plan.check()?;
        Ok(plan)
    }

    fn check(&self) -> anyhow::Result<()> {
        self.tenant
            .id
            .parse::<TenantId>()
            .map_err(|_| anyhow::anyhow!("tenant.id is not a tenant id (ten_<uuidv7>)"))?;
        let mut names = std::collections::BTreeSet::new();
        let mut secrets = std::collections::BTreeSet::new();
        for a in &self.apps {
            anyhow::ensure!(names.insert(a.name.as_str()), "two apps are named alike");
            anyhow::ensure!(
                secret_name(&a.secret),
                "an app's secret is not a Secret name"
            );
            anyhow::ensure!(
                secrets.insert(a.secret.as_str()),
                "two secrets share a name"
            );
            for r in &a.roles {
                RoleKey::parse(&r.role).map_err(|_| anyhow::anyhow!("a role is not a role key"))?;
                scope_of(&r.scope, None)?;
            }
        }
        for w in &self.webhooks {
            anyhow::ensure!(
                names.contains(w.app.as_str()),
                "a webhook names an app the plan does not make"
            );
            anyhow::ensure!(
                secret_name(&w.secret),
                "a webhook's secret is not a Secret name"
            );
            anyhow::ensure!(
                secrets.insert(w.secret.as_str()),
                "two secrets share a name"
            );
            for t in &w.types {
                EventType::parse(t).map_err(|_| anyhow::anyhow!("a type is not an event type"))?;
            }
        }
        Ok(())
    }
}

/// A Kubernetes object name (RFC 1123 subdomain), so it is safe in a path.
#[must_use]
pub fn secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric())
}

/// The scope `text` names: `org` (the tenant's first org, `org` given) or
/// `<type>:<id>`.
fn scope_of(text: &str, org: Option<&OrgId>) -> anyhow::Result<PathEntry> {
    if text == "org" {
        return match org {
            Some(o) => PathEntry::org(o).map_err(|_| anyhow::anyhow!("the org is not a scope")),
            // Checking the plan: the org comes later.
            None => Ok(PathEntry::new(
                ResourceType::ORG,
                ResourceId::parse("org").map_err(|_| anyhow::anyhow!("org"))?,
            )),
        };
    }
    let (kind, id) = text
        .split_once(':')
        .context("a scope is `org` or `<type>:<id>`")?;
    Ok(PathEntry::new(
        ResourceType::parse(kind).map_err(|_| anyhow::anyhow!("a scope's type is not a type"))?,
        ResourceId::parse(id).map_err(|_| anyhow::anyhow!("a scope's id is not an id"))?,
    ))
}

/// Where the job writes secrets.
#[derive(Debug)]
pub enum Sink {
    /// Kubernetes Secrets in the job's namespace, through the API server.
    Kubernetes(kube::Kube),
    /// One JSON file per secret in a directory, mode 0600: for a deployment
    /// without Kubernetes, and for tests.
    Dir(PathBuf),
}

impl Sink {
    async fn get(&self, name: &str) -> anyhow::Result<Option<BTreeMap<String, String>>> {
        match self {
            Self::Kubernetes(k) => k.get_secret(name).await,
            Self::Dir(dir) => match std::fs::read(dir.join(format!("{name}.json"))) {
                Ok(bytes) => Ok(Some(
                    serde_json::from_slice(&bytes).context("a secret file is not JSON")?,
                )),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e).context("reading a secret file"),
            },
        }
    }

    async fn put(&self, name: &str, data: &BTreeMap<String, String>) -> anyhow::Result<()> {
        match self {
            Self::Kubernetes(k) => k.put_secret(name, data).await,
            Self::Dir(dir) => {
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt as _;
                let path = dir.join(format!("{name}.json"));
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)
                    .context("writing a secret file")?;
                f.write_all(&serde_json::to_vec(data)?)
                    .context("writing a secret file")?;
                Ok(())
            }
        }
    }
}

/// What the job needs besides the plan; the binary reads it from the
/// environment.
#[derive(Debug)]
pub struct Env {
    /// `TUTELA_OWNER_DATABASE_URL`.
    pub owner_url: String,
    /// `TUTELA_SERVICE_ROLE`.
    pub service_role: String,
    /// `TUTELA_ISSUER`.
    pub own: Issuer,
    /// `TUTELA_MASTER_KEY`, `TUTELA_KEY_PEPPER` and their versions.
    pub secrets: Secrets,
    /// The webhook URL check (`tutela-safenet`): loopback is allowed only in
    /// dev mode.
    pub policy: tutela_safenet::Policy,
}

/// One step's outcome, printed as a JSON line.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Step {
    /// `migrate`, `tenant`, `app`, `role`, `webhook` or `console`.
    pub step: &'static str,
    /// `made`, `kept`, `rotated`, `given`, `left` (a different role is there)
    /// or `done`.
    pub outcome: &'static str,
    /// What it is about: a tenant, app, role or webhook id, never a secret.
    pub about: String,
}

impl Step {
    fn new(step: &'static str, outcome: &'static str, about: impl Into<String>) -> Self {
        Self {
            step,
            outcome,
            about: about.into(),
        }
    }
}

/// Runs the plan. Returns every step, in order, as it went.
///
/// # Errors
///
/// A failed migration, a tenant id under another issuer or soft-deleted, a
/// refused webhook URL, a Secret that cannot be read or written, or a
/// database error. Steps done before stay done; the next run goes on from
/// there.
pub async fn run(plan: &Plan, env: &Env, sink: &Sink) -> anyhow::Result<Vec<Step>> {
    let mut steps = Vec::new();
    let vars = [
        ("TUTELA_OWNER_DATABASE_URL", env.owner_url.clone()),
        ("TUTELA_SERVICE_ROLE", env.service_role.clone()),
    ];
    crate::server::migrate(|name| {
        vars.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    })
    .await?;
    steps.push(Step::new(
        "migrate",
        "done",
        tutela_store::latest_migration().to_string(),
    ));
    let mut owner = lifecycle::connect_owner(&env.owner_url).await?;

    let (key, org, made) = tenant(&mut owner, env, &plan.tenant).await?;
    steps.push(Step::new(
        "tenant",
        if made { "made" } else { "kept" },
        key.tid.to_string(),
    ));

    let mut principals = BTreeMap::new();
    for a in &plan.apps {
        let (principal, step) = app(&mut owner, env, &key, a, sink).await?;
        steps.push(step);
        for r in &a.roles {
            steps.push(role(&mut owner, &key, &org, &principal, a, r).await?);
        }
        principals.insert(a.name.as_str(), principal);
    }

    if !plan.webhooks.is_empty() {
        let client = tutela_safenet::Client::new(env.policy.clone())
            .context("setting up the webhook URL check")?;
        let vault = env.secrets.vault()?;
        for w in &plan.webhooks {
            let by = principals
                .get(w.app.as_str())
                .context("a webhook names an app the plan does not make")?;
            steps.push(webhook(&mut owner, &key, &vault, &client, by, w, sink).await?);
        }
    }

    if let Some(url) = &plan.console_url {
        steps.push(Step::new("console", "done", url.clone()));
    }
    Ok(steps)
}

/// The tenant: made with its first owners, or kept. Returns its key, its
/// first org and whether it was made.
async fn tenant(
    owner: &mut Client,
    env: &Env,
    t: &TenantPlan,
) -> anyhow::Result<(TenantKey, OrgId, bool)> {
    let tid: TenantId =
        t.id.parse()
            .map_err(|_| anyhow::anyhow!("tenant.id is not a tenant id"))?;
    let tx = owner.transaction().await?;
    let entry = tutela_store::directory_entry(&tx, &tid).await?;
    tx.commit().await?;
    let key = TenantKey::new(env.own.clone(), tid);
    let made = match entry {
        None => {
            let new = NewTenant {
                name: t.name.clone(),
                org_name: t.org_name.clone(),
                admins: t
                    .admins
                    .iter()
                    .map(|a| a.parse())
                    .collect::<Result<_, _>>()
                    .map_err(|_| anyhow::anyhow!("tenant.admins holds a bad principal"))?,
                upstream_admins: t
                    .admin_upstream
                    .iter()
                    .map(|u| {
                        let (iss, sub) = u.split_once('=')?;
                        Some((iss.parse().ok()?, sub.to_owned()))
                    })
                    .collect::<Option<_>>()
                    .context("tenant.admin_upstream is <iss>=<sub>")?,
            };
            lifecycle::create_tenant_with_id(owner, &env.own, tid, &new).await?;
            true
        }
        Some(e) => {
            anyhow::ensure!(
                e.iss == env.own.as_str(),
                "the tenant id is in use under another issuer than TUTELA_ISSUER"
            );
            anyhow::ensure!(
                e.purged_at.is_none(),
                "the tenant is purged; its id is never used again"
            );
            anyhow::ensure!(
                e.deleted_at.is_none(),
                "the tenant is soft-deleted: restore it with `tutelad tenant restore`, \
                 or name another tenant"
            );
            false
        }
    };
    let tx = owner.transaction().await?;
    let org = tutela_store::orgs(&tx, &key)
        .await?
        .into_iter()
        .filter(|o| o.deleted_at.is_none())
        .min_by_key(|o| o.created_at)
        .map(|o| o.org)
        .context("the tenant has no live org")?;
    tx.commit().await?;
    Ok((key, org, made))
}

/// The credentials a product reads from its app's Secret.
fn app_secret(
    env: &Env,
    key: &TenantKey,
    app: &tutela_store::AppInfo,
    secret: &str,
) -> BTreeMap<String, String> {
    let iss = env.own.as_str().trim_end_matches('/');
    BTreeMap::from([
        ("client_id".to_owned(), app.id.clone()),
        ("client_secret".to_owned(), secret.to_owned()),
        ("principal".to_owned(), app.principal.to_string()),
        ("tenant".to_owned(), key.tid.to_string()),
        ("issuer".to_owned(), env.own.as_str().to_owned()),
        ("token_url".to_owned(), format!("{iss}/oauth2/token")),
    ])
}

/// An app: made, kept, or rotated when its Secret is gone. Returns its
/// service account.
async fn app(
    owner: &mut Client,
    env: &Env,
    key: &TenantKey,
    a: &AppPlan,
    sink: &Sink,
) -> anyhow::Result<(Principal, Step)> {
    let tx = owner.transaction().await?;
    let found = tutela_store::apps(&tx, key)
        .await?
        .into_iter()
        .find(|x| x.name == a.name && x.disabled_at.is_none());
    tx.commit().await?;
    let Some(found) = found else {
        let (made, secret) =
            lifecycle::create_app(owner, &env.own, key, &a.name, &env.secrets).await?;
        sink.put(&a.secret, &app_secret(env, key, &made, &secret))
            .await?;
        return Ok((made.principal.clone(), Step::new("app", "made", made.id)));
    };
    let stored = sink.get(&a.secret).await?;
    if stored
        .as_ref()
        .and_then(|d| d.get("client_id"))
        .is_some_and(|id| *id == found.id)
    {
        return Ok((found.principal.clone(), Step::new("app", "kept", found.id)));
    }
    // There, but its secret is not where the product reads it: shown once,
    // so a new one, with the usual overlap for whoever still holds the old.
    let (pepper, version) = env.secrets.pepper();
    let (secret, hash) = crate::apps::new_secret(pepper, version)?;
    let tx = owner.transaction().await?;
    tutela_store::rotate_app_secret(
        &tx,
        key,
        &found.id,
        &hash,
        SystemTime::now() + ROTATE_OVERLAP,
        "operator",
    )
    .await?;
    let rev = tutela_store::rev(&tx, key).await?;
    let record = system_record(key, "tutela_app:rotate", ("tutela_app", &found.id), rev)?
        .detail("by", "operator")
        .detail("app", found.id.clone())
        .detail("key_id", hash.key_id.clone())
        .detail("prefix", format!("tut_sk_{}", hash.prefix))
        .detail("overlap_secs", ROTATE_OVERLAP.as_secs());
    tutela_store::append_audit(&tx, key, &drafts(vec![record])?).await?;
    tx.commit().await?;
    sink.put(&a.secret, &app_secret(env, key, &found, &secret))
        .await?;
    Ok((
        found.principal.clone(),
        Step::new("app", "rotated", found.id),
    ))
}

/// A role of an app's service account: given, kept, or left when the
/// tenant's owner put another role there.
async fn role(
    owner: &mut Client,
    key: &TenantKey,
    org: &OrgId,
    principal: &Principal,
    a: &AppPlan,
    r: &RolePlan,
) -> anyhow::Result<Step> {
    let role = RoleKey::parse(&r.role).map_err(|_| anyhow::anyhow!("a role is not a role key"))?;
    let at = scope_of(&r.scope, Some(org))?;
    let subject = Subject::Principal(principal.clone());
    let about = format!("{}:{}@{}", a.name, role, r.scope);
    let tx = owner.transaction().await?;
    let there = tutela_store::assignments(
        &tx,
        key,
        &tutela_store::AssignmentQuery {
            subject: Some(&subject),
            scope: Some(&at),
            after: None,
            limit: None,
        },
    )
    .await?;
    if let Some(a) = there.first() {
        tx.commit().await?;
        return Ok(if a.role == role {
            Step::new("role", "kept", about)
        } else {
            Step::new("role", "left", about)
        });
    }
    let (rule, rev) = tutela_store::assign(&tx, key, &subject, &role, &at, None).await?;
    let rule = rule.to_string();
    let mut record = system_record(
        key,
        "tutela_assignment:create",
        ("tutela_assignment", &rule),
        rev,
    )?
    .detail("by", "operator")
    .detail("assignment", rule.clone())
    .detail("principal", principal.to_string())
    .detail("role", role.to_string())
    .detail("scope", format!("{}:{}", at.type_name, at.id));
    if let Some(o) = at.org_id() {
        record = record.org(o);
    }
    tutela_store::append_audit(&tx, key, &drafts(vec![record])?).await?;
    tx.commit().await?;
    Ok(Step::new("role", "given", about))
}

/// A webhook: registered for its app, kept, or rotated when its Secret is
/// gone.
async fn webhook(
    owner: &mut Client,
    key: &TenantKey,
    vault: &tutela_vault::Vault<tutela_vault::LocalKms>,
    client: &tutela_safenet::Client,
    by: &Principal,
    w: &WebhookPlan,
    sink: &Sink,
) -> anyhow::Result<Step> {
    let tx = owner.transaction().await?;
    let found = tutela_store::webhooks::webhooks(&tx, key)
        .await?
        .into_iter()
        .find(|x| x.url == w.url && !x.disabled);
    tx.commit().await?;
    let data = |id: &str, secret: &str| {
        BTreeMap::from([
            ("webhook_id".to_owned(), id.to_owned()),
            ("secret".to_owned(), secret.to_owned()),
            ("url".to_owned(), w.url.clone()),
        ])
    };
    if let Some(found) = found {
        let stored = sink.get(&w.secret).await?;
        if stored
            .as_ref()
            .and_then(|d| d.get("webhook_id"))
            .is_some_and(|id| *id == found.id)
        {
            return Ok(Step::new("webhook", "kept", found.id));
        }
        let tx = owner.transaction().await?;
        let secret = tutela_store::webhooks::rotate_webhook_secret(
            &tx,
            key,
            vault,
            &found.id,
            ROTATE_OVERLAP,
        )
        .await?;
        let rev = tutela_store::rev(&tx, key).await?;
        let record = system_record(
            key,
            "tutela_webhook:rotate",
            ("tutela_webhook", &found.id),
            rev,
        )?
        .detail("by", "operator")
        .detail("webhook", found.id.clone())
        .detail("overlap_secs", ROTATE_OVERLAP.as_secs());
        tutela_store::append_audit(&tx, key, &drafts(vec![record])?).await?;
        tx.commit().await?;
        sink.put(&w.secret, &data(&found.id, secret.expose()))
            .await?;
        return Ok(Step::new("webhook", "rotated", found.id));
    }
    client
        .check(&w.url)
        .await
        .map_err(|_| anyhow::anyhow!("a webhook URL is refused: it must be a public https URL"))?;
    let types = w
        .types
        .iter()
        .map(|t| EventType::parse(t))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("a type is not an event type"))?;
    let tx = owner.transaction().await?;
    let (id, secret) =
        tutela_store::webhooks::register_webhook(&tx, key, vault, &w.url, &types, by).await?;
    let rev = tutela_store::rev(&tx, key).await?;
    let names: Vec<String> = types.iter().map(ToString::to_string).collect();
    let record = Record::new(
        key,
        Actor::new(by.clone()),
        "tutela_webhook:register",
        ("tutela_webhook", &id),
    )
    .allowed(rev)
    .detail("by", "operator")
    .detail("webhook", id.clone())
    .detail("types", names);
    tutela_store::append_audit(&tx, key, &drafts(vec![record])?).await?;
    tx.commit().await?;
    sink.put(&w.secret, &data(&id, secret.expose())).await?;
    Ok(Step::new("webhook", "made", id))
}
