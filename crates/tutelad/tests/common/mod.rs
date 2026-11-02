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
    let tx = owner.transaction().await.unwrap();
    let t = tutela_store::create_tenant(&tx, &ISS.parse().unwrap())
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
        let header = json!({"typ": "at+jwt", "alg": "ES256", "kid": self.kid()});
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
    }
}

/// The state, with the issuer's keys in memory.
pub fn state(config: &Config, issuer: &Issuer) -> AppState {
    let vc: VerifierConfig = config.trust.verifier_config(config.audience.clone());
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
    AppState {
        verifier: Arc::new(Verifier::with(
            vc,
            Arc::new(Keys(issuer.jwks())),
            Arc::new(Now),
        )),
        db: Db::connect(&config.database_url, config.pool_size).unwrap(),
        metrics: Arc::new(Metrics::new()),
        stopping: Arc::new(AtomicBool::new(false)),
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
