//! The service gate's high-availability checks, with two real `tutelad`
//! processes on one Postgres: how long a revoked role lives on the other
//! replica, what a cut database does, and that an expiry and a stale limit
//! fail closed. Nothing here is in-process: these are the shipped binary
//! and real sockets.
#![cfg(test)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use common::{Issuer, SA, Seed, TestDb, USER, ask, http, publish};
use reqwest::StatusCode;
use serde_json::Value;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;

/// The documented delay of a revocation in normal running, with
/// `TUTELA_REVISION_CHECK_MS=1000` (the default): the check interval, plus
/// the read and the load. PERMISSION-MODEL.md 16.1 states this number. Change
/// the two together.
const DOCUMENTED_DELAY: Duration = Duration::from_millis(1500);

const EVAL: &str = "/access/v1/evaluation";

/// The issuer's JWKS, served for real: a process cannot share memory with
/// the test.
struct Jwks {
    iss: String,
    task: JoinHandle<()>,
}

impl Jwks {
    async fn serve(issuer: &Issuer) -> Self {
        let body = issuer.jwks();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let iss = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { iss, task }
    }
}

impl Drop for Jwks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A TCP proxy in front of Postgres. `cut` ends every connection and
/// refuses new ones, which is what a replica sees in a database outage or a
/// network split. Postgres itself keeps running, for the rest of the test.
struct Proxy {
    addr: SocketAddr,
    cut: Arc<AtomicBool>,
    open: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: JoinHandle<()>,
}

impl Proxy {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cut = Arc::new(AtomicBool::new(false));
        let open: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let (c, o) = (Arc::clone(&cut), Arc::clone(&open));
        let accept = tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                if c.load(Ordering::SeqCst) {
                    continue;
                }
                let task = tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(target).await {
                        let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                o.lock().await.push(task);
            }
        });
        Self {
            addr,
            cut,
            open,
            accept,
        }
    }

    async fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
        for task in self.open.lock().await.drain(..) {
            task.abort();
        }
    }

    fn restore(&self) {
        self.cut.store(false, Ordering::SeqCst);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// The address of the server in a key=value connection string.
fn server(url: &str) -> SocketAddr {
    let field = |key: &str| {
        url.split_whitespace()
            .find_map(|p| p.strip_prefix(key))
            .unwrap()
            .to_owned()
    };
    format!("{}:{}", field("host="), field("port="))
        .parse()
        .unwrap()
}

/// `url` with its `host` and `port` replaced.
fn through(url: &str, addr: SocketAddr) -> String {
    let mut parts: Vec<String> = url
        .split_whitespace()
        .filter(|p| !p.starts_with("host=") && !p.starts_with("port="))
        .map(str::to_owned)
        .collect();
    parts.push(format!("host={}", addr.ip()));
    parts.push(format!("port={}", addr.port()));
    parts.join(" ")
}

/// One real `tutelad`.
struct Replica {
    child: tokio::process::Child,
    api: SocketAddr,
    ops: SocketAddr,
    /// Read all the time: a pipe nobody reads fills up, and the replica then
    /// stops at its next log line.
    log: JoinHandle<String>,
}

impl Replica {
    async fn start(
        tag: &str,
        trust: &std::path::Path,
        database_url: &str,
        env: &[(&str, &str)],
    ) -> Self {
        let free = || {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
        };
        let (api, ops) = (free(), free());
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_tutelad"));
        cmd.env_clear()
            .env("TUTELA_DATABASE_URL", database_url)
            .env("TUTELA_TRUST_FILE", trust)
            .env("TUTELA_LISTEN", api.to_string())
            .env("TUTELA_OPS_LISTEN", ops.to_string())
            .env("TUTELA_SHUTDOWN_DRAIN_SECS", "0")
            .env("TUTELA_DEV_MODE", "1")
            .env("TUTELA_ISSUER", common::OWN_ISS)
            .env("TUTELA_MASTER_KEY", common::MASTER_KEY)
            .env("TUTELA_KEY_PEPPER", common::PEPPER)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let log = tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;
            let mut text = String::new();
            let _ = stdout.read_to_string(&mut text).await;
            text
        });
        let c = http();
        let url = format!("http://{ops}/healthz");
        for _ in 0..200 {
            if c.get(&url).send().await.is_ok() {
                return Self {
                    child,
                    api,
                    ops,
                    log,
                };
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("replica {tag} did not start");
    }

    async fn ask(&self, token: &str, body: &Value) -> (StatusCode, Value) {
        let r = http()
            .post(format!("http://{}{EVAL}", self.api))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// `Some(true|false)` for a decision, `None` for no decision.
    async fn decision(&self, token: &str, body: &Value) -> Option<bool> {
        let (status, v) = self.ask(token, body).await;
        (status == StatusCode::OK).then(|| v["decision"].as_bool().unwrap())
    }

    async fn ready(&self) -> StatusCode {
        http()
            .get(format!("http://{}/readyz", self.ops))
            .send()
            .await
            .unwrap()
            .status()
    }

    async fn metrics(&self) -> String {
        http()
            .get(format!("http://{}/metrics", self.ops))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    }

    /// Stops it with SIGTERM and returns its log.
    async fn stop(mut self) -> String {
        let pid = self.child.id().unwrap().to_string();
        tokio::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .await
            .unwrap();
        let status = tokio::time::timeout(Duration::from_secs(15), self.child.wait())
            .await
            .expect("the replica did not stop")
            .unwrap();
        assert_eq!(status.code(), Some(0));
        self.log.await.unwrap()
    }
}

/// A tenant, an issuer the replicas can reach, and a trust file.
struct Cluster {
    d: TestDb,
    issuer: Issuer,
    jwks: Jwks,
    a: Seed,
    trust: std::path::PathBuf,
    /// Writes as the service role: what a replica's write path uses.
    writer: tutela_store::tokio_postgres::Client,
}

impl Cluster {
    async fn new() -> Option<Self> {
        let mut d = common::migrated().await?;
        publish(&mut d.owner, common::MANIFEST, None).await;
        let issuer = Issuer::new();
        let jwks = Jwks::serve(&issuer).await;
        // The tenant belongs to this run's issuer.
        let a = common::seed_of(&mut d.owner, &jwks.iss, USER, "reader").await;
        let trust = std::env::temp_dir().join(format!("tutelad-ha-{}.toml", a.tid));
        std::fs::write(
            &trust,
            format!(
                "[[issuer]]\niss = \"{iss}\"\njwks_uri = \"{iss}/jwks\"\nalgs = [\"ES256\"]\n\
                 tenants = [\"{tid}\"]\n",
                iss = jwks.iss,
                tid = a.tid
            ),
        )
        .unwrap();
        let writer = common::connect(&d.service_url).await;
        Some(Self {
            d,
            issuer,
            jwks,
            a,
            trust,
            writer,
        })
    }

    fn token(&self, sub: &str) -> String {
        self.issuer.token_of(&self.jwks.iss, sub, &self.a.tid, 0)
    }

    /// A role for `user` on the project, through the store, as the service
    /// role.
    async fn grant(&mut self, user: &str, role: &str) -> tutela_contracts::decision::RuleId {
        let tx = self.writer.transaction().await.unwrap();
        let (id, _) = tutela_store::assign(
            &tx,
            &self.a.key,
            &Subject::Principal(user.parse().unwrap()),
            &RoleKey::parse(role).unwrap(),
            &self.a.project,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        id
    }

    async fn revoke(&mut self, id: &tutela_contracts::decision::RuleId) {
        let tx = self.writer.transaction().await.unwrap();
        tutela_store::unassign(&tx, &self.a.key, id).await.unwrap();
        tx.commit().await.unwrap();
    }

    async fn finish(self) {
        std::fs::remove_file(&self.trust).unwrap();
        drop(self.writer);
        self.d.finish().await;
    }
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() - 1) * p / 100]
}

/// The gate's check: revoke a role through the store, and measure how long
/// the other replica keeps answering allow, under steady traffic. Each
/// round starts at a different point of the check interval. The test fails
/// if the worst round is over the documented delay.
#[tokio::test]
async fn ha_a_revoked_role_stops_on_every_replica_within_the_documented_delay() {
    const ROUNDS: usize = 20;
    let Some(mut c) = Cluster::new().await else {
        return;
    };
    let one = Replica::start("one", &c.trust, &c.d.service_url, &[]).await;
    let two = Replica::start("two", &c.trust, &c.d.service_url, &[]).await;
    let token = c.token(SA);
    let subject = common::STRANGER;
    let body = ask(subject, "invoice:read", &c.a);

    let mut delays = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        let id = c.grant(subject, "reader").await;
        // Both replicas have seen the grant.
        let started = Instant::now();
        loop {
            let a = one.decision(&token, &body).await;
            let b = two.decision(&token, &body).await;
            if a == Some(true) && b == Some(true) {
                break;
            }
            assert!(
                started.elapsed() < DOCUMENTED_DELAY * 2,
                "round {round}: the grant did not arrive"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Keep asking, as a busy tenant does, up to a different point of
        // the interval each round. A replica nobody asks checks at the next
        // request, so an idle gap would measure almost no delay at all.
        let replica = if round % 2 == 0 { &two } else { &one };
        let phase = u64::try_from(round).unwrap() * 41 % 1000;
        let until = Instant::now() + Duration::from_millis(phase);
        while Instant::now() < until {
            assert_eq!(replica.decision(&token, &body).await, Some(true));
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        c.revoke(&id).await;
        let revoked = Instant::now();
        // The clock stops when the replica says deny.
        loop {
            match replica.decision(&token, &body).await {
                Some(false) => break,
                Some(true) => {}
                None => panic!("round {round}: no decision"),
            }
            assert!(
                revoked.elapsed() < Duration::from_secs(10),
                "round {round}: the revoked role never stopped"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        delays.push(revoked.elapsed());
    }
    delays.sort();
    let (p50, p95, max) = (
        percentile(&delays, 50),
        percentile(&delays, 95),
        percentile(&delays, 100),
    );
    eprintln!("revocation delay over {ROUNDS} rounds: p50 {p50:?}, p95 {p95:?}, max {max:?}");
    assert!(
        max <= DOCUMENTED_DELAY,
        "the worst round took {max:?}, over the documented {DOCUMENTED_DELAY:?}"
    );
    one.stop().await;
    two.stop().await;
    c.finish().await;
}

/// One expiry with two sweeping replicas makes one revision, and both
/// serve after it.
#[tokio::test]
async fn ha_two_replicas_share_a_sweep_and_one_stays_when_the_other_goes() {
    let Some(mut c) = Cluster::new().await else {
        return;
    };
    let env = [("TUTELA_EXPIRY_SWEEP_SECS", "1")];
    let one = Replica::start("one", &c.trust, &c.d.service_url, &env).await;
    let two = Replica::start("two", &c.trust, &c.d.service_url, &env).await;
    assert_eq!(one.ready().await, StatusCode::OK);
    assert_eq!(two.ready().await, StatusCode::OK);

    let before = rev(&mut c).await;
    {
        let tx = c.writer.transaction().await.unwrap();
        tutela_store::assign_until(
            &tx,
            &c.a.key,
            &Subject::Principal(common::STRANGER.parse().unwrap()),
            &RoleKey::parse("reader").unwrap(),
            &c.a.project,
            None,
            SystemTime::now() + Duration::from_millis(300),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // Long enough for several sweeps on each replica.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert_eq!(
        rev(&mut c).await,
        before + 2,
        "the assignment and one sweep, however many replicas swept"
    );

    let token = c.token(SA);
    let body = ask(USER, "invoice:read", &c.a);
    assert_eq!(one.decision(&token, &body).await, Some(true));
    assert_eq!(two.decision(&token, &body).await, Some(true));
    one.stop().await;
    assert_eq!(two.decision(&token, &body).await, Some(true));
    two.stop().await;
    c.finish().await;
}

async fn rev(c: &mut Cluster) -> u64 {
    let tx = c.writer.transaction().await.unwrap();
    let rev = tutela_store::rev(&tx, &c.a.key).await.unwrap();
    tx.commit().await.unwrap();
    rev
}

/// A database outage from the replica's side, with short limits. What is in
/// hand serves until the limit of each class, in the documented order, and
/// then nothing is an allow. A role revoked during the split takes effect
/// at the limit at the latest. When the database is back, so is the truth.
#[tokio::test]
async fn ha_a_lost_database_fails_closed_at_each_age_limit_and_recovers() {
    let Some(mut c) = Cluster::new().await else {
        return;
    };
    let proxy = Proxy::start(server(&c.d.service_url)).await;
    let url = through(&c.d.service_url, proxy.addr);
    let env = [
        ("TUTELA_REVISION_CHECK_MS", "200"),
        ("TUTELA_MAX_AGE_READ_SECS", "4"),
        ("TUTELA_MAX_AGE_WRITE_SECS", "2"),
    ];
    let replica = Replica::start("cut", &c.trust, &url, &env).await;
    let approver = common::STRANGER;
    let assignment = c.grant(approver, "approver").await;

    let token = c.token(SA);
    let read = ask(approver, "invoice:read", &c.a);
    let write = ask(approver, "invoice:approve", &c.a);
    let admin = ask(approver, "invoice:manage_access", &c.a);
    assert_eq!(replica.decision(&token, &read).await, Some(true));
    assert_eq!(replica.decision(&token, &write).await, Some(true));
    assert_eq!(replica.decision(&token, &admin).await, Some(false));
    assert_eq!(replica.ready().await, StatusCode::OK);

    proxy.cut().await;
    // The role is revoked behind the split. This replica cannot know.
    c.revoke(&assignment).await;
    let cut = Instant::now();
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(replica.ready().await, StatusCode::SERVICE_UNAVAILABLE);
    let health = http()
        .get(format!("http://{}/healthz", replica.ops))
        .send()
        .await
        .unwrap();
    assert_eq!(
        health.status(),
        StatusCode::OK,
        "liveness needs no database"
    );

    // Admin actions are never answered from data that cannot be checked.
    let (status, p) = replica.ask(&token, &admin).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{p}");
    assert_eq!(p["type"], "urn:tutela:problem:expired");
    assert_eq!(replica.decision(&token, &read).await, Some(true));
    assert_eq!(replica.decision(&token, &write).await, Some(true));

    // Past the write limit: reads go on, writes stop.
    tokio::time::sleep(Duration::from_millis(2300).saturating_sub(cut.elapsed())).await;
    assert_eq!(replica.decision(&token, &read).await, Some(true));
    assert_eq!(replica.decision(&token, &write).await, None);

    // Past the read limit: nothing. Poll for a while: not one allow.
    tokio::time::sleep(Duration::from_millis(4300).saturating_sub(cut.elapsed())).await;
    let until = Instant::now() + Duration::from_millis(1500);
    let mut answers = 0;
    while Instant::now() < until {
        let (status, body) = replica.ask(&token, &read).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["type"], "urn:tutela:problem:expired");
        answers += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(answers > 5);
    let metrics = replica.metrics().await;
    assert!(
        metrics.contains(r#"tutelad_decisions_total{operation="evaluation",outcome="error"}"#),
        "{metrics}"
    );
    assert!(metrics.contains(r#"tutelad_revision_checks_total{result="failed"}"#));

    // Back: the first answer is the truth, the revoked role.
    proxy.restore();
    let back = Instant::now();
    let answer = loop {
        if let Some(d) = replica.decision(&token, &read).await {
            break d;
        }
        assert!(
            back.elapsed() < Duration::from_secs(10),
            "it did not recover"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(!answer, "the role was revoked during the split");
    replica.stop().await;
    c.finish().await;
}

/// A tenant the replica has never seen, with no database: no data is an
/// error, never an allow. The same at a fresh start.
#[tokio::test]
async fn ha_no_data_and_no_database_is_a_503() {
    let Some(c) = Cluster::new().await else {
        return;
    };
    let proxy = Proxy::start(server(&c.d.service_url)).await;
    proxy.cut().await;
    let url = through(&c.d.service_url, proxy.addr);
    let replica = Replica::start("empty", &c.trust, &url, &[]).await;
    let token = c.token(SA);
    let (status, body) = replica.ask(&token, &ask(USER, "invoice:read", &c.a)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["type"], "urn:tutela:problem:no_data");
    replica.stop().await;
    c.finish().await;
}

/// An assignment reaches its expiry during an outage, well inside the age
/// limit. The replica cannot reload, and it knows the view stopped being
/// true: no allow from that moment, for anyone in the tenant.
#[tokio::test]
async fn ha_an_expiry_during_an_outage_ends_the_data_and_nothing_is_allowed() {
    let Some(mut c) = Cluster::new().await else {
        return;
    };
    let proxy = Proxy::start(server(&c.d.service_url)).await;
    let url = through(&c.d.service_url, proxy.addr);
    let env = [
        ("TUTELA_REVISION_CHECK_MS", "200"),
        ("TUTELA_MAX_AGE_READ_SECS", "60"),
    ];
    let replica = Replica::start("expiry", &c.trust, &url, &env).await;
    let expires = SystemTime::now() + Duration::from_millis(1500);
    {
        let tx = c.writer.transaction().await.unwrap();
        tutela_store::assign_until(
            &tx,
            &c.a.key,
            &Subject::Principal(common::STRANGER.parse().unwrap()),
            &RoleKey::parse("reader").unwrap(),
            &c.a.project,
            None,
            expires,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let token = c.token(SA);
    let temporary = ask(common::STRANGER, "invoice:read", &c.a);
    let permanent = ask(USER, "invoice:read", &c.a);
    assert_eq!(replica.decision(&token, &temporary).await, Some(true));
    proxy.cut().await;
    assert_eq!(replica.decision(&token, &temporary).await, Some(true));

    tokio::time::sleep(
        expires
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            + Duration::from_millis(100),
    )
    .await;
    assert_eq!(replica.decision(&token, &temporary).await, None);
    // The whole view: any principal, or the data could be used past a truth
    // it no longer holds.
    assert_eq!(replica.decision(&token, &permanent).await, None);
    replica.stop().await;
    c.finish().await;
}

/// The shipped binary's log, at the default level, through allows, denies,
/// a batch and a failure: no token, no subject and no resource.
#[tokio::test]
async fn tm17_the_log_holds_no_token_subject_or_resource() {
    let Some(c) = Cluster::new().await else {
        return;
    };
    let replica = Replica::start("log", &c.trust, &c.d.service_url, &[]).await;
    let token = c.token(SA);
    let body = ask(USER, "invoice:read", &c.a);
    assert_eq!(replica.decision(&token, &body).await, Some(true));
    let denied = ask(common::STRANGER, "invoice:write", &c.a);
    assert_eq!(replica.decision(&token, &denied).await, Some(false));
    let mut bad = body.clone();
    bad["context"] = serde_json::json!({"at_least_revision": 99_999});
    assert_eq!(replica.decision(&token, &bad).await, None);
    let log = replica.stop().await;
    assert!(log.contains("request served"), "{log}");
    // The tenant may be there: an id, and it says whose request it was.
    assert!(
        log.lines()
            .filter(|l| l.contains("request served"))
            .all(|l| l.contains(&format!("\"tid\":\"{}\"", c.a.tid))),
        "a request's log line must name its tenant:\n{log}"
    );
    for secret in [token.as_str(), USER, common::STRANGER, "inv-1", "p-1"] {
        assert!(!log.contains(secret), "{secret} reached the log:\n{log}");
    }
    c.finish().await;
}
