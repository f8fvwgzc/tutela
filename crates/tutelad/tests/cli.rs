//! The `tutela` CLI against a real `tutelad` on a real Postgres (ADR-0045):
//! `tutela apply` with the impact report, approvals and two-person
//! publish; `tutela apps`; `tutela keys`. The pipeline authenticates as an
//! app, as texc-symphony will (MIGRATION-0.2.md).
#![cfg(test)]

mod common;

use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_cli::service::{Applied, ApplyOptions, Service, apply};
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutelad::config::TrustFile;

use common::{
    AUD, Issuer, MANIFEST, OWN_ISS, Running, TestDb, config, http, migrated, now, publish, start,
    state,
};

const KC: &str = "https://kc.example.test/realms/acme";

struct C {
    d: TestDb,
    s: Running,
    issuer: Issuer,
    a: tutela_contracts::tenant::TenantKey,
    /// The pipeline's app: its client id and secret.
    app: (String, String),
}

async fn c() -> Option<C> {
    let mut d = migrated().await?;
    publish(&mut d.owner, MANIFEST, None).await;
    let own: tutela_contracts::tenant::Issuer = OWN_ISS.parse().unwrap();
    let made = tutelad::lifecycle::create_tenant(
        &mut d.owner,
        &own,
        &tutelad::lifecycle::NewTenant {
            upstream_admins: vec![(KC.parse().unwrap(), "owner".to_owned())],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let a = made.key.clone();
    // The pipeline: an app whose service account owns the org.
    let (app, secret) =
        tutelad::lifecycle::create_app(&mut d.owner, &own, &a, "pipeline", &common::secrets())
            .await
            .unwrap();
    let tx = d.owner.transaction().await.unwrap();
    tutela_store::assign(
        &tx,
        &a,
        &Subject::Principal(app.principal.clone()),
        &RoleKey::parse("owner").unwrap(),
        &tutela_pdp::PathEntry::org(&made.org).unwrap(),
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let file = format!(
        "[[issuer]]\niss = \"{KC}\"\njwks_uri = \"{KC}/certs\"\nalgs = [\"ES256\"]\n\
         tenants = [\"{}\"]\nexternal = true\nallow_typ_jwt = true\n",
        a.tid
    );
    let issuer = Issuer::new();
    let cfg = config(&d.service_url, TrustFile::parse(&file, false).unwrap());
    let s = start(&cfg, state(&cfg, &issuer)).await;
    Some(C {
        d,
        s,
        issuer,
        a,
        app: (app.id, secret.to_string()),
    })
}

impl C {
    async fn pipeline_token(&self) -> String {
        let (id, secret) = &self.app;
        let r = http()
            .post(self.s.api_url("/oauth2/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "authorization",
                format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
            )
            .body("grant_type=client_credentials")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let v: Value = r.json().await.unwrap();
        v["access_token"].as_str().unwrap().to_owned()
    }

    /// The owner's admin token, after a step-up sign-in.
    async fn owner_admin(&self) -> String {
        let now = now();
        let subject = self.issuer.sign_typed(
            "JWT",
            &json!({"exp": now + 300, "iat": now, "jti": uuid::Uuid::now_v7().to_string(),
                    "iss": KC, "aud": AUD, "sub": "owner", "azp": "console", "acr": common::STEP_UP}),
        );
        let r = http()
            .post(self.s.api_url("/oauth2/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                serde_urlencoded::to_string([
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    ("subject_token", subject.as_str()),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:access_token",
                    ),
                    ("audience", "tutela-admin"),
                ])
                .unwrap(),
            )
            .send()
            .await
            .unwrap();
        let v: Value = r.json().await.unwrap();
        v["access_token"].as_str().unwrap().to_owned()
    }

    fn url(&self) -> String {
        self.s.api_url("")
    }

    async fn finish(self) {
        self.s.stop().await.unwrap();
        self.d.finish().await;
    }
}

/// A manifest whose `reader` also writes invoices: a widening change.
fn widened() -> String {
    MANIFEST.replace(
        "grants = { project = \"read\", invoice = \"read\" }",
        "grants = { project = \"read\", invoice = \"write\" }",
    )
}

/// A manifest whose `reader` no longer reads invoices: a narrowing change.
fn added() -> String {
    MANIFEST.replace(
        "grants = { project = \"read\", invoice = \"read\" }",
        "grants = { project = \"read\" }",
    )
}

async fn run(
    svc: &Service,
    source: &str,
    approval: Option<&str>,
    dry_run: bool,
) -> (Applied, String) {
    let mut out = Vec::new();
    let r = apply(
        svc,
        &ApplyOptions {
            source,
            approval,
            dry_run,
        },
        &mut out,
    )
    .await
    .unwrap();
    (r, String::from_utf8(out).unwrap())
}

async fn active_version(c: &C, token: &str) -> i64 {
    let r = http()
        .get(c.s.api_url("/v1/models"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    v["active"]["version"].as_i64().unwrap_or(0)
}

#[tokio::test]
async fn tm08_tutela_apply_shows_the_impact_and_refuses_a_widening_change_without_a_token() {
    let Some(mut c) = c().await else { return };
    let token = c.pipeline_token().await;
    let svc = Service::new(&c.url(), &token).unwrap();
    // The tenant follows the app's manifest: the same text changes nothing.
    let (r, out) = run(&svc, MANIFEST, None, false).await;
    assert_eq!(r, Applied::Unchanged, "{out}");
    // A narrowing change: the diff, the report, a publish at the version
    // shown.
    let (r, out) = run(&svc, &added(), None, true).await;
    assert_eq!(r, Applied::Shown, "{out}");
    assert!(out.contains("class:   narrowing"), "{out}");
    assert!(out.contains("lose"), "the report says who loses: {out}");
    let v0 = active_version(&c, &token).await;
    let (r, out) = run(&svc, &added(), None, true).await;
    assert_eq!(r, Applied::Shown, "{out}");
    assert_eq!(
        active_version(&c, &token).await,
        v0,
        "a dry run writes nothing"
    );
    let (r, out) = run(&svc, &added(), None, false).await;
    assert_eq!(r, Applied::Published, "{out}");
    let v1 = active_version(&c, &token).await;
    assert!(v1 > v0, "{v0} -> {v1}");
    // A widening change: the report names who gains, and without a token
    // the CLI refuses before it sends a publish.
    let (r, out) = run(&svc, &widened(), None, false).await;
    assert_eq!(r, Applied::Refused, "{out}");
    assert!(out.contains("class:   widening"), "{out}");
    assert!(out.contains("tutela approve --app crm"), "{out}");
    assert!(out.contains(&format!("--tenant {}", c.a.tid)), "{out}");
    assert_eq!(active_version(&c, &token).await, v1);
    let refused = common::audited(&mut c.d.owner, &c.a, "tutela_model:publish").await;
    assert!(
        refused.iter().all(|r| r["outcome"] == "success"),
        "no publish was even asked for: {refused:?}"
    );
    // A token for another change, or another tenant, is refused by the
    // service; one for this change and tenant publishes it.
    let key = tutela_cli::approval::generate().unwrap();
    let tx = c.d.owner.transaction().await.unwrap();
    tutela_store::add_approver(&tx, "release manager", &key.verifying_key().to_bytes())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let digest = |s: &str| tutela_store::digest(s);
    let mint = |from: &str, to: &str, tid: Option<String>| {
        let iat = now();
        tutela_cli::approval::mint(
            &key,
            &tutela_cli::approval::Approval {
                app: "crm".into(),
                from: from.into(),
                to: to.into(),
                kid: tutela_store::approver_id(&key.verifying_key().to_bytes()),
                iat,
                exp: iat + 600,
                tid,
            },
        )
        .unwrap()
    };
    let tid = Some(c.a.tid.to_string());
    let wrong = mint(&digest(MANIFEST), &digest(&widened()), tid.clone());
    let (r, out) = run(&svc, &widened(), Some(&wrong), false).await;
    assert_eq!(r, Applied::Refused, "a token for another change: {out}");
    let good = mint(&digest(&added()), &digest(&widened()), tid);
    let (r, out) = run(&svc, &widened(), Some(&good), false).await;
    assert_eq!(r, Applied::Published, "{out}");
    let v2 = active_version(&c, &token).await;
    assert!(v2 > v1, "{v1} -> {v2}");
    // Two-person publish on: the CLI makes a proposal instead.
    let r = http()
        .put(c.s.api_url("/v1/models/settings"))
        .bearer_auth(&token)
        .json(&json!({"two_person": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let (r, out) = run(&svc, MANIFEST, None, false).await;
    assert_eq!(r, Applied::Proposed, "{out}");
    assert_eq!(
        active_version(&c, &token).await,
        v2,
        "a proposal publishes nothing"
    );
    // A service that is not the tenant's admin gets the service's refusal.
    let bad = Service::new(
        &c.url(),
        &c.issuer.token(common::SA, &c.a.tid.to_string(), 0),
    )
    .unwrap();
    let mut out = Vec::new();
    let e = apply(
        &bad,
        &ApplyOptions {
            source: &added(),
            approval: None,
            dry_run: false,
        },
        &mut out,
    )
    .await
    .unwrap_err();
    assert!(matches!(e, tutela_cli::CliError::Service(_)), "{e:?}");
    c.finish().await;
}

#[tokio::test]
async fn tutela_apps_prints_a_secret_once_and_tutela_keys_rotates_through_the_key_store() {
    let Some(mut c) = c().await else { return };
    let admin = c.owner_admin().await;
    let svc = Service::new(&c.url(), &admin).unwrap();
    let mut out = Vec::new();
    tutela_cli::service::apps_create(&svc, "reports", &mut out)
        .await
        .unwrap();
    let text = String::from_utf8(out).unwrap();
    let secret = text
        .lines()
        .find_map(|l| l.strip_prefix("client_secret: "))
        .unwrap()
        .trim()
        .to_owned();
    assert!(secret.starts_with("tut_sk_"), "{text}");
    let mut out = Vec::new();
    tutela_cli::service::apps_list(&svc, &mut out)
        .await
        .unwrap();
    let list = String::from_utf8(out).unwrap();
    assert!(
        list.contains("reports") && !list.contains(&secret[16..]),
        "{list}"
    );
    let id = text
        .lines()
        .find_map(|l| l.strip_prefix("client_id:"))
        .unwrap()
        .trim()
        .to_owned();
    let mut out = Vec::new();
    tutela_cli::service::apps_rotate(&svc, &id, Some(0), &mut out)
        .await
        .unwrap();
    let rotated = String::from_utf8(out).unwrap();
    assert!(
        !rotated.contains(&secret[16..]),
        "a new secret, not the old one"
    );
    assert!(
        tutela_cli::service::Service::new("http://example.test", "t").is_err(),
        "https only"
    );
    assert!(
        tutela_cli::service::Service::new(&c.url(), " ").is_err(),
        "a token is required"
    );

    // `tutela keys` through the key store, as the service role.
    let mut db = common::connect(&c.d.service_url).await;
    let vault = common::vault();
    let own: tutela_contracts::tenant::Issuer = OWN_ISS.parse().unwrap();
    let before = SystemTime::now();
    let mut out = Vec::new();
    tutela_cli::keys::rotate(&mut db, &vault, &own, Duration::from_secs(300), &mut out)
        .await
        .unwrap();
    let tx = db.transaction().await.unwrap();
    let set = tutela_store::signing_keys(&tx).await.unwrap();
    tx.commit().await.unwrap();
    let next = set
        .keys
        .iter()
        .find(|k| k.signs_from > set.now)
        .expect("a next key");
    assert!(
        next.signs_from >= before + Duration::from_secs(590),
        "published twice the cache time before it signs"
    );
    let signing = set.signing(set.now).unwrap().kid.clone();
    let mut out = Vec::new();
    tutela_cli::keys::deny(&mut db, &vault, &own, &signing, &mut out)
        .await
        .unwrap();
    let tx = db.transaction().await.unwrap();
    let set = tutela_store::signing_keys(&tx).await.unwrap();
    tx.commit().await.unwrap();
    assert!(set.denied.contains(&signing));
    assert_ne!(set.signing(set.now).unwrap().kid, signing);
    let mut out = Vec::new();
    tutela_cli::keys::rewrap(&mut db, &vault, &own, &mut out)
        .await
        .unwrap();
    // The audit producer key (ADR-0045): rotated twice, both old ones kept.
    for _ in 0..2 {
        let mut out = Vec::new();
        tutela_cli::keys::rotate_audit(&mut db, &vault, &own, &mut out)
            .await
            .unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("public key for attache")
        );
    }
    let tx = db.transaction().await.unwrap();
    let audit = tutela_store::audit_keys(&tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit.iter().filter(|k| k.retired_at.is_none()).count(), 1);
    let mut out = Vec::new();
    tutela_cli::keys::list(&mut db, &mut out).await.unwrap();
    let listed = String::from_utf8(out).unwrap();
    assert!(
        listed.contains("audit retired") && listed.contains("audit signs"),
        "{listed}"
    );
    // Each is in the deployment's chain, which still verifies.
    let tx = c.d.owner.transaction().await.unwrap();
    let report = tutela_store::verify_deployment_audit_chain(&tx)
        .await
        .unwrap();
    assert!(report.is_intact(), "{report:?}");
    let rows = tutela_store::deployment_audit_records(&tx, 0, 1000)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let actions: Vec<String> = rows
        .iter()
        .map(|r| {
            serde_json::from_str::<Value>(&r.body).unwrap()["action"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    for a in [
        "tutela_signing_key:rotate",
        "tutela_signing_key:deny",
        "tutela_signing_key:rewrap",
        "tutela_audit_key:rotate",
    ] {
        assert!(actions.iter().any(|x| x == a), "{a} in {actions:?}");
    }
    c.finish().await;
}
