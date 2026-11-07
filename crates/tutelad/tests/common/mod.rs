//! What the `tutelad` tests share: a real Postgres, a signing key and a
//! running service.
//!
//! `TUTELA_TEST_DATABASE_URL` names a server and a role that may create
//! roles and databases. Each test makes its own database, owned by a role
//! that is not a superuser, and connects the service as a second role that
//! owns nothing. With the variable unset, a test says so and passes, except
//! when `TUTELA_REQUIRE_DATABASE=1` (CI sets it).
#![allow(dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tutela_sdk::{Alg, CacheRules, Clock, IssuerConfig, JwksSource, Verifier, VerifierConfig};
use tutela_store::tokio_postgres::{self, Client, NoTls};
use tutelad::api::AppState;
use tutelad::config::{Config, TrustFile};
use tutelad::db::Db;
use tutelad::telemetry::Metrics;

pub const ISS: &str = "https://auth.example.test";
/// `tutelad`'s own issuer in the tests.
pub const OWN_ISS: &str = "https://tutela.example.test";
/// Test values only.
pub const MASTER_KEY: &str = "6d61737465722d6b65792d666f722d74657374732d6f6e6c792d303030303031";
pub const PEPPER: &str = "7065707065722d666f722d74657374732d6f6e6c792d30303030303030303031";
pub const USER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081";
pub const OWNER: &str = "tutela_test_owner";
pub const OWNER_PASSWORD: &str = "tutela_test_owner";
pub const SERVICE: &str = "tutela_test_service";
pub const SERVICE_PASSWORD: &str = "tutela_test_service";

fn base_url() -> Option<String> {
    match std::env::var("TUTELA_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            assert!(
                std::env::var("TUTELA_REQUIRE_DATABASE").as_deref() != Ok("1"),
                "TUTELA_REQUIRE_DATABASE=1 but TUTELA_TEST_DATABASE_URL is not set"
            );
            eprintln!("skipped: set TUTELA_TEST_DATABASE_URL to run the tutelad tests");
            None
        }
    }
}

pub async fn connect(url: &str) -> Client {
    let (client, conn) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

/// A key=value connection string with `dbname`, `user` and `password`
/// replaced.
pub fn with(url: &str, db: &str, user: &str, password: &str) -> String {
    let mut parts: Vec<String> = url
        .split_whitespace()
        .filter(|p| {
            !p.starts_with("dbname=") && !p.starts_with("user=") && !p.starts_with("password=")
        })
        .map(str::to_owned)
        .collect();
    parts.push(format!("dbname={db}"));
    parts.push(format!("user={user}"));
    parts.push(format!("password={password}"));
    parts.join(" ")
}

/// A test database. Dropped by [`TestDb::finish`] when the test passes.
pub struct TestDb {
    /// A superuser, on the server's first database.
    pub admin: Client,
    /// The base URL.
    pub base: String,
    /// The database's name.
    pub name: String,
    /// The owner role: migrations and seed data.
    pub owner: Client,
    /// `TUTELA_DATABASE_URL` for the service: a role that owns nothing.
    pub service_url: String,
    /// The owner's URL.
    pub owner_url: String,
}

async fn make_role(admin: &Client, role: &str, password: &str) {
    let exists = admin
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&role])
        .await
        .unwrap()
        .is_some();
    if !exists {
        // Two tests may race to make the role; one of them wins.
        let _ = admin
            .batch_execute(&format!(
                "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}'"
            ))
            .await;
    }
}

/// A database with the schema and the service role's grants.
pub async fn migrated() -> Option<TestDb> {
    let mut d = db().await?;
    tutela_store::migrate(&mut d.owner).await.unwrap();
    tutela_store::grant_service(&mut d.owner, SERVICE)
        .await
        .unwrap();
    Some(d)
}

/// A new tenant of [`ISS`].
pub async fn tenant(owner: &mut Client) -> tutela_contracts::tenant::TenantKey {
    tenant_of(owner, ISS).await
}

/// A new tenant of `iss`.
pub async fn tenant_of(owner: &mut Client, iss: &str) -> tutela_contracts::tenant::TenantKey {
    let tx = owner.transaction().await.unwrap();
    let t = tutela_store::create_tenant(&tx, &iss.parse().unwrap())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    t
}

/// A new database with no schema.
pub async fn db() -> Option<TestDb> {
    let base = base_url()?;
    let admin = connect(&base).await;
    make_role(&admin, OWNER, OWNER_PASSWORD).await;
    make_role(&admin, SERVICE, SERVICE_PASSWORD).await;
    let name = format!("tutela_test_{}", uuid::Uuid::now_v7().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {name} OWNER {OWNER}"))
        .await
        .unwrap();
    let owner_url = with(&base, &name, OWNER, OWNER_PASSWORD);
    let service_url = with(&base, &name, SERVICE, SERVICE_PASSWORD);
    let owner = connect(&owner_url).await;
    Some(TestDb {
        admin,
        base,
        name,
        owner,
        service_url,
        owner_url,
    })
}

impl TestDb {
    /// A superuser connection to this database.
    pub async fn superuser(&self) -> Client {
        let parts: Vec<String> = self
            .base
            .split_whitespace()
            .filter(|p| !p.starts_with("dbname="))
            .map(str::to_owned)
            .chain([format!("dbname={}", self.name)])
            .collect();
        connect(&parts.join(" ")).await
    }

    pub async fn finish(self) {
        drop(self.owner);
        self.admin
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}

/// One ES256 issuer.
pub struct Issuer {
    key: EcdsaKeyPair,
}

impl Issuer {
    pub fn new() -> Self {
        Self {
            key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap(),
        }
    }

    fn xy(&self) -> (String, String) {
        let p = self.key.public_key().as_ref();
        (B64.encode(&p[1..33]), B64.encode(&p[33..65]))
    }

    /// The RFC 7638 thumbprint.
    pub fn kid(&self) -> String {
        let (x, y) = self.xy();
        let json = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        B64.encode(digest(&SHA256, json.as_bytes()))
    }

    pub fn jwks(&self) -> Vec<u8> {
        let (x, y) = self.xy();
        json!({"keys": [{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": self.kid(), "use": "sig"}]})
            .to_string()
            .into_bytes()
    }

    pub fn sign(&self, iss: &str, tid: &str, aud: &str, now: u64) -> String {
        let claims = json!({
            "iss": iss, "sub": USER, "aud": aud, "azp": "crm-web",
            "exp": now + 300, "iat": now, "nbf": now,
            "jti": uuid::Uuid::now_v7().to_string(),
            "sid": "ses_0193a1b2-c3d4-7123-8456-789abcdef012",
            "tid": tid, "epoch": 0, "rev": 0, "amr": ["pwd"]
        });
        self.sign_claims(&claims)
    }

    pub fn sign_claims(&self, claims: &Value) -> String {
        self.sign_typed("at+jwt", claims)
    }

    /// A token with header `typ`.
    pub fn sign_typed(&self, typ: &str, claims: &Value) -> String {
        let header = json!({"typ": typ, "alg": "ES256", "kid": self.kid()});
        let msg = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = self.key.sign(&SystemRandom::new(), msg.as_bytes()).unwrap();
        format!("{msg}.{}", B64.encode(sig.as_ref()))
    }
}

/// The issuer's JWKS, without a network.
struct Keys(Vec<u8>);

impl JwksSource for Keys {
    fn fetch(
        &self,
        _url: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send>> {
        let body = self.0.clone();
        Box::pin(async move { Some(body) })
    }
}

struct Now;

impl Clock for Now {
    fn now(&self) -> u64 {
        now()
    }
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A trust file naming `tenants` for [`ISS`].
pub fn trust(tenants: &[String]) -> TrustFile {
    let list = tenants
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(", ");
    TrustFile::parse(
        &format!(
            "[[issuer]]\niss = \"{ISS}\"\njwks_uri = \"{ISS}/jwks\"\nalgs = [\"ES256\"]\n\
             tenants = [{list}]\n"
        ),
        false,
    )
    .unwrap()
}

/// A config on free ports.
pub fn config(database_url: &str, trust: TrustFile) -> Config {
    Config {
        database_url: database_url.to_owned(),
        listen: "127.0.0.1:0".parse().unwrap(),
        ops_listen: "127.0.0.1:0".parse().unwrap(),
        audience: "tutela-authz".parse().unwrap(),
        trust,
        dev_mode: false,
        log: "info".to_owned(),
        pool_size: 4,
        request_timeout: Duration::from_secs(5),
        shutdown_drain: Duration::ZERO,
        shutdown_timeout: Duration::from_secs(5),
        expiry_sweep: Duration::from_secs(3600),
        limits: tutelad::cache::Limits::default(),
        impact_work: tutela_pdp::MAX_IMPACT_WORK,
        issuer: OWN_ISS.parse().unwrap(),
        secrets: secrets(),
        jwks_cache: Duration::from_secs(300),
        key_refresh: Duration::from_secs(10),
        token_ttl: Duration::from_secs(300),
        admin_acr: vec![STEP_UP.to_owned()],
        delegated_ttl: Duration::from_secs(90),
        // Tests that deliver webhooks run the relay themselves.
        webhook_poll: Duration::ZERO,
        event_retention: Duration::from_secs(7 * 24 * 3600),
        streams: tutelad::stream::StreamSettings {
            poll: Duration::from_millis(100),
            ..tutelad::stream::StreamSettings::default()
        },
        bundle_ttl: Duration::from_secs(300),
        purge_grace: Duration::from_secs(30 * 24 * 3600),
        audit_verify: Duration::ZERO,
        ledger: None,
        console: None,
        cors: tutelad::cors::Cors::default(),
    }
}

/// The `acr` the tests' deployment counts as step-up MFA.
pub const STEP_UP: &str = "mfa";

/// The test master key and pepper.
pub fn secrets() -> tutelad::config::Secrets {
    tutelad::config::Secrets::from_values(Some(MASTER_KEY), None, Some(PEPPER), None).unwrap()
}

/// The vault of [`MASTER_KEY`], for the store's key calls.
pub fn vault() -> tutela_vault::Vault {
    secrets().vault().unwrap()
}

/// The state, with the issuer's keys in memory. Delegated tokens are on, as
/// in production (ADR-0033).
pub fn state(config: &Config, issuer: &Issuer) -> AppState {
    state_with(config, issuer, true)
}

/// [`state`], with delegated (`agent+jwt`) tokens on or off.
pub fn state_with(config: &Config, issuer: &Issuer, delegation: bool) -> AppState {
    state_with_jwks(config, Arc::new(Keys(issuer.jwks())), delegation)
}

/// [`state_with`], with the other issuers' JWKS from `other`: for example
/// `config.jwks_source()`, which fetches them over HTTP as production does.
pub fn state_with_jwks(config: &Config, other: Arc<dyn JwksSource>, delegation: bool) -> AppState {
    let vc: VerifierConfig = config.verifier_config();
    let vc = VerifierConfig {
        issuers: vc
            .issuers
            .into_iter()
            .map(|i| IssuerConfig {
                algs: if i.external { i.algs } else { vec![Alg::Es256] },
                ..i
            })
            .collect(),
        cache: CacheRules::default(),
        delegation,
        delegation_aware: delegation,
        ..vc
    };
    let db = Db::connect(&config.database_url, config.pool_size).unwrap();
    let metrics = Arc::new(Metrics::new());
    let keys = Arc::new(config.key_ring().unwrap());
    let events_keys = Arc::clone(&keys);
    let clock: Arc<dyn Clock> = Arc::new(Now);
    AppState {
        verifier: Arc::new(Verifier::with(
            vc,
            Arc::new(tutelad::keys::OwnJwks::new(
                Arc::clone(&keys),
                Arc::clone(&other),
            )),
            Arc::clone(&clock),
        )),
        audiences: Arc::new(tutelad::exchange::Audiences::new(
            config, &keys, &other, &clock,
        )),
        revocations: Arc::new(tutelad::revocation::Revocations::new(
            db.clone(),
            config.limits,
        )),
        keys,
        cache: Arc::new(tutelad::cache::TenantCache::new(
            db.clone(),
            config.limits,
            Arc::clone(&metrics),
        )),
        events: Arc::new(tutelad::stream::Hub::new(
            db.clone(),
            Arc::clone(&events_keys),
            config.streams,
        )),
        db,
        metrics,
        bundle_ttl: config.bundle_ttl,
        purge_grace: config.purge_grace,
        own: config.issuer.clone(),
        vault: Arc::new(config.secrets.vault().unwrap()),
        safenet: Arc::new(
            tutela_safenet::Client::new(if config.dev_mode {
                tutela_safenet::Policy::new().dev_loopback()
            } else {
                tutela_safenet::Policy::new()
            })
            .unwrap(),
        ),
        stopping: Arc::new(AtomicBool::new(false)),
        dev_mode: config.dev_mode,
        impact_work: config.impact_work,
        pepper: Arc::new(tutelad::apps::Pepper::of(&config.secrets)),
    }
}

/// A running service.
pub struct Running {
    pub api: SocketAddr,
    pub ops: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Running {
    pub fn api_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.api)
    }

    pub fn ops_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.ops)
    }

    /// Asks it to stop, and waits.
    pub async fn stop(self) -> anyhow::Result<()> {
        let _ = self.stop.send(());
        self.task.await.unwrap()
    }
}

pub async fn start(config: &Config, state: AppState) -> Running {
    let server = tutelad::Server::bind(config, state).await.unwrap();
    let (api, ops) = (server.api_addr().unwrap(), server.ops_addr().unwrap());
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(server.serve(async move {
        let _ = stopped.await;
    }));
    Running {
        api,
        ops,
        stop,
        task,
    }
}

// ---------- A seeded world, for the check API ----------

pub const SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7090";
pub const STRANGER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7082";
pub const B_USER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7083";
pub const AGENT: &str = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";
pub const AUD: &str = "tutela-authz";

pub const MANIFEST: &str = r#"
version = 1
[app]
name = "crm"

[types.project]
parent = "org"
container = true

[types.invoice]
parent = "project"
[types.invoice.fields]
status = { sensitivity = "internal" }
amount = { sensitivity = "confidential", type = "integer" }
[types.invoice.actions]
approve = { needs = "write" }

[roles.reader]
grants = { project = "read", invoice = "read" }

[roles.approver]
grants = { project = "write", invoice = "write", "invoice.amount" = "read", "invoice:approve" = true }

[ui."invoices.approve_button"]
actions     = ["invoice:approve"]
routes      = ["POST /api/invoices/{id}/approve"]
when_denied = "disable"
reason      = "Only approvers can approve."

[ui."invoices.delete_button"]
actions     = ["invoice:delete"]
routes      = ["DELETE /api/invoices/{id}"]
when_denied = "hide"

[ui."invoices.amount_cell"]
fields      = ["invoice.amount"]
routes      = ["PATCH /api/invoices/{id}"]
when_denied = "readonly"

[ui."invoices.status_cell"]
fields      = ["invoice.status"]
routes      = ["PATCH /api/invoices/{id}"]
when_denied = "hide"

[ui."projects.settings"]
actions     = ["project:write"]
routes      = ["PATCH /api/projects/{id}"]
when_denied = "hide"
"#;

/// Compiles `source` and publishes it as a new manifest of the one app.
pub async fn publish(owner: &mut Client, source: &str, expected: Option<i64>) {
    use tutela_pdp::model::{Class, Model};
    let model = Model::from_toml(source).unwrap();
    let tx = owner.transaction().await.unwrap();
    tutela_store::publish_manifest(
        &tx,
        &tutela_store::Publish {
            app: model.app(),
            source,
            expected,
            class: Class::Neutral,
            diff: "",
            author: None,
            approvers: &[],
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// One tenant's seed: an org, a project, and an invoice under the project,
/// with `user` holding `role` on the project.
pub struct Seed {
    pub key: tutela_contracts::tenant::TenantKey,
    pub tid: String,
    pub org: tutela_pdp::PathEntry,
    pub project: tutela_pdp::PathEntry,
    pub assignment: tutela_contracts::decision::RuleId,
}

fn scope(kind: &str, id: &str) -> tutela_pdp::PathEntry {
    tutela_pdp::PathEntry::new(kind.parse().unwrap(), id.parse().unwrap())
}

pub async fn seed(owner: &mut Client, user: &str, role: &str) -> Seed {
    seed_of(owner, ISS, user, role).await
}

/// [`seed`], for a tenant of `iss`.
pub async fn seed_of(owner: &mut Client, iss: &str, user: &str, role: &str) -> Seed {
    use tutela_pdp::Subject;
    let key = tenant_of(owner, iss).await;
    let tx = owner.transaction().await.unwrap();
    let (org, _) = tutela_store::add_org(&tx, &key).await.unwrap();
    let org = tutela_pdp::PathEntry::org(&org).unwrap();
    let project = scope("project", "p-1");
    tutela_store::put_scope(&tx, &key, &project, std::slice::from_ref(&org), false)
        .await
        .unwrap();
    let (assignment, _) = tutela_store::assign(
        &tx,
        &key,
        &Subject::Principal(user.parse().unwrap()),
        &tutela_pdp::model::RoleKey::parse(role).unwrap(),
        &project,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    Seed {
        tid: key.tid.to_string(),
        key,
        org,
        project,
        assignment,
    }
}

/// Removes an assignment and returns the new revision.
pub async fn revoke(owner: &mut Client, s: &Seed, id: &tutela_contracts::decision::RuleId) -> u64 {
    let tx = owner.transaction().await.unwrap();
    let rev = tutela_store::unassign(&tx, &s.key, id).await.unwrap();
    tx.commit().await.unwrap();
    rev
}

/// A database with the manifest, tenant A (USER is a reader) and tenant B
/// (B_USER is an approver), and a running service that trusts both.
pub struct World {
    pub d: TestDb,
    pub issuer: Issuer,
    pub a: Seed,
    pub b: Seed,
    pub s: Running,
    pub config: Config,
}

pub async fn world() -> Option<World> {
    world_with(|_| {}).await
}

pub async fn world_with(tune: impl FnOnce(&mut Config)) -> Option<World> {
    let mut d = migrated().await?;
    publish(&mut d.owner, MANIFEST, None).await;
    let a = seed(&mut d.owner, USER, "reader").await;
    let b = seed(&mut d.owner, B_USER, "approver").await;
    let issuer = Issuer::new();
    let mut cfg = config(&d.service_url, trust(&[a.tid.clone(), b.tid.clone()]));
    tune(&mut cfg);
    let s = start(&cfg, state(&cfg, &issuer)).await;
    Some(World {
        d,
        issuer,
        a,
        b,
        s,
        config: cfg,
    })
}

impl World {
    pub async fn finish(self) {
        self.s.stop().await.unwrap();
        self.d.finish().await;
    }

    /// POSTs `body` to `path` with `token`.
    pub async fn post(&self, path: &str, token: &str, body: &Value) -> reqwest::Response {
        http()
            .post(self.s.api_url(path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .unwrap()
    }
}

impl Issuer {
    /// A token of `sub` in tenant `tid`, carrying `rev`.
    pub fn token(&self, sub: &str, tid: &str, rev: u64) -> String {
        self.token_of(ISS, sub, tid, rev)
    }

    /// [`Issuer::token`], from issuer `iss`.
    pub fn token_of(&self, iss: &str, sub: &str, tid: &str, rev: u64) -> String {
        let now = now();
        let mut claims = json!({
            "iss": iss, "sub": sub, "aud": AUD, "azp": "crm-web",
            "exp": now + 300, "iat": now, "nbf": now,
            "jti": uuid::Uuid::now_v7().to_string(),
            "tid": tid, "epoch": 0, "rev": rev,
        });
        if sub.starts_with("user:") {
            claims["sid"] = json!("ses_0193a1b2-c3d4-7123-8456-789abcdef012");
            claims["amr"] = json!(["pwd"]);
        }
        self.sign_claims(&claims)
    }
}

impl Issuer {
    /// A delegated token: `sub` acting through `agent`.
    pub fn delegated(&self, sub: &str, agent: &str, tid: &str) -> String {
        let now = now();
        self.sign_typed(
            "agent+jwt",
            &json!({
                "iss": ISS, "sub": sub, "aud": AUD, "azp": "crm-web",
                "exp": now + 100, "iat": now, "nbf": now,
                "jti": uuid::Uuid::now_v7().to_string(),
                "tid": tid, "epoch": 0, "rev": 0,
                "act": {"sub": agent}, "cap": {}, "run_id": "run-1",
            }),
        )
    }

    /// An admin token (`aud=tutela-admin`) of `sub` with `acr`, issued
    /// `age` seconds ago and living `life` seconds.
    pub fn admin_token(&self, sub: &str, tid: &str, acr: &str, age: u64, life: u64) -> String {
        self.admin_token_at(sub, tid, acr, age, life, 0)
    }

    /// [`Issuer::admin_token`] carrying `rev`.
    pub fn admin_token_at(
        &self,
        sub: &str,
        tid: &str,
        acr: &str,
        age: u64,
        life: u64,
        rev: u64,
    ) -> String {
        let iat = now() - age;
        let mut claims = json!({
            "iss": ISS, "sub": sub, "aud": "tutela-admin", "azp": "tutela-console",
            "exp": iat + life, "iat": iat, "nbf": iat,
            "jti": uuid::Uuid::now_v7().to_string(),
            "tid": tid, "epoch": 0, "rev": rev, "acr": acr,
        });
        if sub.starts_with("user:") {
            claims["sid"] = json!("ses_0193a1b2-c3d4-7123-8456-789abcdef012");
            claims["amr"] = json!(["pwd", "otp"]);
        }
        self.sign_claims(&claims)
    }

    /// What the Console or a pipeline sends to the admin routes (ADR-0032):
    /// a person's admin token after step-up, a service's own token.
    pub fn console(&self, sub: &str, tid: &str, rev: u64) -> String {
        if sub.starts_with("user:") {
            self.admin_token_at(sub, tid, STEP_UP, 0, 300, rev)
        } else {
            self.token(sub, tid, rev)
        }
    }

    /// A person's admin token from another session.
    pub fn second_console_session(&self, sub: &str, tid: &str) -> String {
        let now = now();
        self.sign_claims(&json!({
            "iss": ISS, "sub": sub, "aud": "tutela-admin", "azp": "tutela-console",
            "exp": now + 300, "iat": now, "nbf": now,
            "jti": uuid::Uuid::now_v7().to_string(),
            "sid": "ses_0193a1b2-c3d4-7123-8456-000000000002",
            "amr": ["pwd", "otp"], "acr": STEP_UP,
            "tid": tid, "epoch": 0, "rev": 0,
        }))
    }

    /// A token of `sub` from another session.
    pub fn second_session(&self, sub: &str, tid: &str) -> String {
        let now = now();
        self.sign_claims(&json!({
            "iss": ISS, "sub": sub, "aud": AUD, "azp": "crm-web",
            "exp": now + 300, "iat": now, "nbf": now,
            "jti": uuid::Uuid::now_v7().to_string(),
            "sid": "ses_0193a1b2-c3d4-7123-8456-000000000002",
            "amr": ["pwd", "otp"],
            "tid": tid, "epoch": 0, "rev": 0,
        }))
    }
}

/// An evaluation of `action` on invoice `inv-1` under `s`'s project.
pub fn ask(subject: &str, action: &str, s: &Seed) -> Value {
    json!({
        "subject": {"type": subject.split(':').next().unwrap(), "id": subject},
        "action": {"name": action},
        "resource": {"type": "invoice", "id": "inv-1", "properties": {"path": path(s), "attrs": {}}},
    })
}

/// The invoice's path: the project, then the org.
pub fn path(s: &Seed) -> Value {
    json!([
        {"type": s.project.type_name.to_string(), "id": s.project.id.to_string()},
        {"type": "org", "id": s.org.id.to_string()},
    ])
}

// ---------- The audit log (ADR-0034) ----------

/// Every audit record of `key`, as JSON, after checking that the chain holds.
pub async fn audit_of(owner: &mut Client, key: &tutela_contracts::tenant::TenantKey) -> Vec<Value> {
    let tx = owner.transaction().await.unwrap();
    let report = tutela_store::verify_audit_chain(&tx, key).await.unwrap();
    assert!(report.is_intact(), "{report:?}");
    let rows = tutela_store::audit_records(&tx, key, 0, 1000)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(rows.len() as u64, report.head);
    rows.iter()
        .map(|r| serde_json::from_str(&r.body).unwrap())
        .collect()
}

/// The records of `key` whose `action` is `action`.
pub async fn audited(
    owner: &mut Client,
    key: &tutela_contracts::tenant::TenantKey,
    action: &str,
) -> Vec<Value> {
    audit_of(owner, key)
        .await
        .into_iter()
        .filter(|r| r["action"] == action)
        .collect()
}

// ---------- The outbox (ADR-0035) ----------

/// Every event of `key` in the outbox, oldest first.
pub async fn events_of(
    owner: &mut Client,
    key: &tutela_contracts::tenant::TenantKey,
) -> Vec<tutela_store::StoredEvent> {
    let tx = owner.transaction().await.unwrap();
    let e = tutela_store::events_after(&tx, key, 0, 1000).await.unwrap();
    tx.commit().await.unwrap();
    e
}

/// A product's verifier: it trusts the test issuer for tenants A and B with
/// the service's audience, as a product that feeds it from `tutelad`'s
/// events would.
pub fn product_verifier(w: &World) -> Verifier {
    let vc = config(&w.d.service_url, trust(&[w.a.tid.clone(), w.b.tid.clone()])).verifier_config();
    let vc = VerifierConfig {
        issuers: vc
            .issuers
            .into_iter()
            .map(|i| IssuerConfig {
                algs: vec![Alg::Es256],
                ..i
            })
            .collect(),
        cache: CacheRules::default(),
        ..vc
    };
    Verifier::with(vc, Arc::new(Keys(w.issuer.jwks())), Arc::new(Now))
}
