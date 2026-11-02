//! `tutela apply` end to end against a real Postgres. Same setup as
//! `tutela-store`'s tests: `TUTELA_TEST_DATABASE_URL`, one database per
//! test, owned by a role that is not a superuser.

use tutela_pdp::model::{AppName, Class};
use tutela_store::tokio_postgres::{Client, NoTls};

use crate::apply::{self, Options, Outcome};
use crate::approval::{self, Approval, NO_MANIFEST};
use crate::init::starter;

const OWNER: &str = "tutela_test_owner";
const OWNER_PASSWORD: &str = "tutela_test_owner";
const NOW: u64 = 2_000_000_000;

struct Db {
    admin: Client,
    name: String,
    client: Client,
}

async fn connect(url: &str) -> Client {
    let (client, conn) = tutela_store::tokio_postgres::connect(url, NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

async fn db() -> Option<Db> {
    let base = match std::env::var("TUTELA_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            assert!(
                std::env::var("TUTELA_REQUIRE_DATABASE").as_deref() != Ok("1"),
                "TUTELA_REQUIRE_DATABASE=1 but TUTELA_TEST_DATABASE_URL is not set"
            );
            eprintln!("skipped: set TUTELA_TEST_DATABASE_URL to run the tutela apply tests");
            return None;
        }
    };
    let admin = connect(&base).await;
    if admin
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&OWNER])
        .await
        .unwrap()
        .is_none()
    {
        let _ = admin
            .batch_execute(&format!(
                "CREATE ROLE {OWNER} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{OWNER_PASSWORD}'"
            ))
            .await;
    }
    let name = format!("tutela_test_{}", uuid_like());
    admin
        .batch_execute(&format!("CREATE DATABASE {name} OWNER {OWNER}"))
        .await
        .unwrap();
    let mut parts: Vec<String> = base
        .split_whitespace()
        .filter(|p| {
            !p.starts_with("dbname=") && !p.starts_with("user=") && !p.starts_with("password=")
        })
        .map(str::to_owned)
        .collect();
    parts.extend([
        format!("dbname={name}"),
        format!("user={OWNER}"),
        format!("password={OWNER_PASSWORD}"),
    ]);
    let mut client = connect(&parts.join(" ")).await;
    tutela_store::migrate(&mut client).await.unwrap();
    // Two tenants, so a publish bumps more than one.
    let iss = "https://idp.example.test".parse().unwrap();
    for _ in 0..2 {
        let tx = client.transaction().await.unwrap();
        tutela_store::create_tenant(&tx, &iss).await.unwrap();
        tx.commit().await.unwrap();
    }
    Some(Db {
        admin,
        name,
        client,
    })
}

/// A unique name part: the clock, the process id and a counter (tests in
/// one process run in parallel and may read the same clock value).
fn uuid_like() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{t:x}_{}_{n}", std::process::id())
}

impl Db {
    async fn finish(self) {
        drop(self.client);
        self.admin
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }

    async fn apply(&mut self, source: &str, token: Option<&str>) -> (Outcome, String) {
        let mut out = Vec::new();
        let o = apply::apply(
            &mut self.client,
            &Options {
                source,
                approval: token,
                author: Some("test"),
                dry_run: false,
                now: NOW,
            },
            &mut out,
        )
        .await
        .unwrap();
        (o, String::from_utf8(out).unwrap())
    }

    async fn stored_version(&mut self) -> Option<i64> {
        let tx = self.client.transaction().await.unwrap();
        let app = AppName::parse("crm").unwrap();
        tutela_store::manifest(&tx, &app)
            .await
            .unwrap()
            .map(|m| m.version)
    }
}

/// A registered approver: its key and id.
async fn approver(db: &mut Db) -> (ed25519_dalek::SigningKey, String) {
    let key = approval::generate().unwrap();
    let mut out = Vec::new();
    let id = crate::approvers_add(
        &mut db.client,
        "Dana",
        &approval::public_key_text(&key.verifying_key()),
        &mut out,
    )
    .await
    .unwrap();
    (key, id)
}

fn token(key: &ed25519_dalek::SigningKey, kid: &str, from: &str, to: &str) -> String {
    approval::mint(
        key,
        &Approval {
            app: "crm".into(),
            from: from.into(),
            to: to.into(),
            kid: kid.into(),
            iat: NOW - 10,
            exp: NOW + 3_600,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn a_first_apply_is_widening_and_needs_an_approval() {
    let Some(mut db) = db().await else { return };
    let v1 = starter("crm");
    let to = tutela_store::digest(&v1);
    // No token: refused, nothing written, and the approve command is shown.
    let (o, text) = db.apply(&v1, None).await;
    assert_eq!(o, Outcome::Refused);
    assert!(
        text.contains(&format!("tutela approve --app crm --from none --to {to}")),
        "{text}"
    );
    assert!(text.contains("WIDENING"), "{text}");
    assert_eq!(db.stored_version().await, None);
    // A token from an unknown key: refused.
    let stranger = approval::generate().unwrap();
    let sid = tutela_store::approver_id(&stranger.verifying_key().to_bytes());
    let (o, text) = db
        .apply(&v1, Some(&token(&stranger, &sid, NO_MANIFEST, &to)))
        .await;
    assert_eq!(o, Outcome::Refused);
    assert!(text.contains("unknown approver key"), "{text}");
    // A registered key: applied, every tenant bumped.
    let (key, kid) = approver(&mut db).await;
    let (o, text) = db
        .apply(&v1, Some(&token(&key, &kid, NO_MANIFEST, &to)))
        .await;
    assert_eq!(
        o,
        Outcome::Applied {
            class: Class::Widening,
            version: 1,
            tenants: 2
        },
        "{text}"
    );
    // The same manifest again: nothing to do.
    assert_eq!(db.apply(&v1, None).await.0, Outcome::NoChange);
    db.finish().await;
}

#[tokio::test]
async fn narrowing_goes_in_without_a_token_and_widening_never_does() {
    let Some(mut db) = db().await else { return };
    let v1 = starter("crm");
    let d1 = tutela_store::digest(&v1);
    let (key, kid) = approver(&mut db).await;
    db.apply(&v1, Some(&token(&key, &kid, NO_MANIFEST, &d1)))
        .await;
    // Narrowing: the editor loses `task:close`.
    let v2 = v1.replace(
        r#"grants = { project = "read", task = "write", "task:close" = true }"#,
        r#"grants = { project = "read", task = "write" }"#,
    );
    assert_ne!(v1, v2);
    let (o, text) = db.apply(&v2, None).await;
    assert!(
        matches!(
            o,
            Outcome::Applied {
                class: Class::Narrowing,
                version: 2,
                ..
            }
        ),
        "{text}"
    );
    // Widening back: refused without a token...
    let d2 = tutela_store::digest(&v2);
    assert_eq!(db.apply(&v1, None).await.0, Outcome::Refused);
    // ...with a token for another change (the first apply's)...
    let (o, text) = db
        .apply(&v1, Some(&token(&key, &kid, NO_MANIFEST, &d1)))
        .await;
    assert_eq!(o, Outcome::Refused);
    assert!(text.contains("different change"), "{text}");
    // ...and with a revoked key.
    let t = token(&key, &kid, &d2, &d1);
    crate::approvers_revoke(&mut db.client, &kid, &mut Vec::new())
        .await
        .unwrap();
    let (o, text) = db.apply(&v1, Some(&t)).await;
    assert_eq!(o, Outcome::Refused);
    assert!(text.contains("revoked"), "{text}");
    assert_eq!(db.stored_version().await, Some(2));
    // Another approver's token for exactly this change goes in.
    let (key2, kid2) = approver(&mut db).await;
    let (o, _) = db.apply(&v1, Some(&token(&key2, &kid2, &d2, &d1))).await;
    assert!(matches!(
        o,
        Outcome::Applied {
            class: Class::Widening,
            version: 3,
            ..
        }
    ));
    db.finish().await;
}

#[tokio::test]
async fn a_dry_run_writes_nothing_and_a_broken_manifest_is_an_error() {
    let Some(mut db) = db().await else { return };
    let mut out = Vec::new();
    let o = apply::apply(
        &mut db.client,
        &Options {
            source: &starter("crm"),
            approval: None,
            author: None,
            dry_run: true,
            now: NOW,
        },
        &mut out,
    )
    .await
    .unwrap();
    assert_eq!(o, Outcome::DryRun(Class::Widening));
    assert_eq!(db.stored_version().await, None);
    let broken = apply::apply(
        &mut db.client,
        &Options {
            source: "version = 1\n[app]\nname = \"crm\"\nunknown = true\n",
            approval: None,
            author: None,
            dry_run: false,
            now: NOW,
        },
        &mut Vec::new(),
    )
    .await;
    assert!(matches!(broken, Err(crate::CliError::Compile)));
    db.finish().await;
}

/// `tokio_postgres::Error` keeps the server's message in `source()`, so the
/// report must walk the chain to show it. It shows once on either path.
#[tokio::test]
async fn a_database_error_shows_the_server_message_once() {
    let Some(db) = db().await else { return };
    let failed = || db.client.batch_execute("SELECT * FROM no_such_table");
    let want = "database error: db error: ERROR: relation \"no_such_table\" does not exist";
    let direct = crate::CliError::from(failed().await.unwrap_err());
    assert_eq!(direct.report(), want);
    let stored = crate::CliError::from(tutela_store::StoreError::from(failed().await.unwrap_err()));
    assert_eq!(stored.report(), want);
    db.finish().await;
}
