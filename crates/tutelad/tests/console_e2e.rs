//! The Phase B exit check in a real browser (part 4b2, ADR-0053): sign-in,
//! the UI permission map and runtime role editing, end to end.
//!
//! This test makes the world: a tenant under `tutelad`'s own issuer, the
//! test OpenID provider (`tutela-test-idp`, shaped like Keycloak 26) as its
//! realm, an owner and a second person, and a real `tutelad` on a real
//! Postgres that serves the built Console (`console/dist`) and fetches the
//! realm's JWKS over HTTP. Then it runs the Playwright check
//! `console/e2e/exit-check.spec.ts` in Chromium, and checks the audit
//! chain afterwards.
//!
//! With `TUTELA_E2E_KEYCLOAK_FIXTURE` set, the realm is a real Keycloak 26
//! instead (#87, ADR-0057): `scripts/keycloak-check.mjs` (`make keycloak`)
//! starts it, makes the realm with the Console's client from the Helm chart
//! and runs this test, and the people sign in at Keycloak's own login and
//! OTP pages. Everything else is the same check.
//!
//! It needs node, pnpm, the built Console and Playwright's Chromium, so it
//! runs only with `TUTELA_CONSOLE_E2E=1` (`make js-e2e`, part of `make`).
//! With it set, a missing database fails under `TUTELA_REQUIRE_DATABASE=1`,
//! as every database test does, and a missing browser fails the check.
#![cfg(test)]

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use serde_json::json;
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutela_store::tokio_postgres::Client;
use tutela_test_idp::{Person, Settings};
use tutelad::config::TrustFile;

use common::{OWN_ISS, Seed, now};

/// The roles of the check: an auditor holds `read_audit` at the org and
/// nothing to change; the owner edits `reader`.
fn manifest() -> String {
    format!(
        "{}\n{}",
        common::MANIFEST,
        r#"
[roles.auditor]
grants = { project = "read", invoice = "read", "org:read_audit" = true }
"#
    )
}

/// The realm the Console signs in at.
enum Realm {
    /// The test provider shaped like Keycloak 26 (ADR-0051).
    TestIdp(tutela_test_idp::Running),
    /// A real Keycloak (#87).
    Keycloak(common::keycloak::Kc),
}

impl Realm {
    fn issuer(&self) -> String {
        match self {
            Self::TestIdp(idp) => idp.issuer().to_owned(),
            Self::Keycloak(kc) => kc.f["realm"]["issuer"].as_str().unwrap().to_owned(),
        }
    }

    fn jwks_uri(&self) -> String {
        match self {
            Self::TestIdp(idp) => idp.jwks_uri(),
            Self::Keycloak(_) => format!("{}/protocol/openid-connect/certs", self.issuer()),
        }
    }

    /// The realm's subject of a person of the check, and how they sign in
    /// at Keycloak's form (the test provider's form picks them by name).
    fn person(&self, who: &str, test_idp_sub: &str) -> (String, serde_json::Value) {
        match self {
            Self::TestIdp(_) => (test_idp_sub.to_owned(), serde_json::Value::Null),
            Self::Keycloak(kc) => {
                let p = kc.person(who);
                (
                    p["sub"].as_str().unwrap().to_owned(),
                    json!({
                        "username": p["username"], "password": p["password"], "totp": p["totp"],
                    }),
                )
            }
        }
    }

    async fn stop(self) {
        if let Self::TestIdp(idp) = self {
            idp.stop().await;
        }
    }
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

async fn person(owner: &mut Client, s: &Seed, iss: &str, sub: &str) -> String {
    let tx = owner.transaction().await.unwrap();
    let (p, _) = tutela_store::provision_user(&tx, &s.key, &iss.parse().unwrap(), sub)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    p.principal.to_string()
}

async fn assign(owner: &mut Client, s: &Seed, who: &str, role: &str) {
    let tx = owner.transaction().await.unwrap();
    tutela_store::assign(
        &tx,
        &s.key,
        &Subject::Principal(who.parse().unwrap()),
        &RoleKey::parse(role).unwrap(),
        &s.org,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// An admin token of `tutelad` for `sub`, issued `age` seconds ago and
/// lasting `life` seconds: what an exchange would have given then.
fn admin_token(keys: &tutelad::keys::KeyRing, sub: &str, tid: &str, age: u64, life: u64) -> String {
    let iat = now() - age;
    keys.sign_jwt(
        "at+jwt",
        &json!({
            "iss": OWN_ISS, "sub": sub, "aud": "tutela-admin", "azp": "tutela-console",
            "exp": iat + life, "iat": iat, "nbf": iat,
            "jti": uuid::Uuid::now_v7().to_string(),
            "sid": format!("ses_{}", uuid::Uuid::now_v7()),
            "tid": tid, "epoch": 0, "rev": 1, "amr": ["ext"], "acr": common::STEP_UP,
        }),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_console_passes_the_exit_check_in_a_real_browser() {
    if std::env::var("TUTELA_CONSOLE_E2E").as_deref() != Ok("1") {
        eprintln!("skipped: `make js-e2e` runs the Console's exit check in a browser");
        return;
    }
    let Some(mut d) = common::migrated().await else {
        return;
    };
    let dist = repo().join("console/dist");
    assert!(
        dist.join("index.html").is_file(),
        "the Console is not built: run `make js-build` first"
    );
    common::publish(&mut d.owner, &manifest(), None).await;
    let s = common::seed_of(&mut d.owner, OWN_ISS, common::USER, "reader").await;

    // tutelad's address first: the realm must know the Console's callback.
    // The listener is kept and handed to the server, never given up (#147).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = listener.local_addr().unwrap();
    let url = format!("http://{api}");
    let idp = if let Some(f) = common::keycloak::fixture("TUTELA_E2E_KEYCLOAK_FIXTURE") {
        let kc = common::keycloak::Kc::new(f);
        kc.allow_console(&url).await;
        Realm::Keycloak(kc)
    } else {
        let mut idp = Settings::new("tutela-authz");
        idp.redirect_uris = vec![format!("{url}/console/callback")];
        idp.post_logout_redirect_uris = vec![format!("{url}/console/")];
        idp.people = vec![
            Person::new("kc-owner", "Olivia Owner"),
            Person::new("kc-member", "Max Member"),
        ];
        Realm::TestIdp(tutela_test_idp::start(idp).await.unwrap())
    };
    let realm = idp.issuer();
    let (owner_sub, owner_login) = idp.person("owner", "kc-owner");
    let (member_sub, member_login) = idp.person("member", "kc-member");

    // The owner owns the org; the second person only views it, through a
    // group, so the owner can still give them a role of their own there.
    let owner = person(&mut d.owner, &s, &realm, &owner_sub).await;
    let member = person(&mut d.owner, &s, &realm, &member_sub).await;
    assign(&mut d.owner, &s, &owner, "owner").await;
    {
        let staff = tutela_pdp::model::GroupKey::parse("staff").unwrap();
        let tx = d.owner.transaction().await.unwrap();
        tutela_store::create_group(&tx, &s.key, &s.org.org_id().unwrap(), &staff, "Staff")
            .await
            .unwrap();
        tutela_store::add_member(
            &tx,
            &s.key,
            &staff,
            &tutela_pdp::Member::Principal(member.parse().unwrap()),
            None,
        )
        .await
        .unwrap();
        tutela_store::assign(
            &tx,
            &s.key,
            &Subject::Group(staff),
            &RoleKey::parse("viewer").unwrap(),
            &s.org,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let trust = TrustFile::parse(
        &format!(
            "[[issuer]]\niss = \"{realm}\"\njwks_uri = \"{}\"\nalgs = [\"RS256\"]\n\
             tenants = [\"{}\"]\nexternal = true\nallow_typ_jwt = true\n",
            idp.jwks_uri(),
            s.tid
        ),
        true,
    )
    .unwrap();
    let mut cfg = common::config(&d.service_url, trust);
    cfg.dev_mode = true;
    cfg.console = Some(
        tutelad::console::ConsoleConfig::from_values(
            dist.to_str().unwrap(),
            Some(&realm),
            Some("tutela-console"),
            &cfg.admin_acr,
            cfg.audience.as_str(),
            &[realm.parse().unwrap()],
        )
        .unwrap(),
    );
    // The realm's JWKS over HTTP, through tutela-safenet, as in production.
    let jwks: Arc<dyn tutela_sdk::JwksSource> = Arc::new(cfg.jwks_source().unwrap());
    let state = common::state_with_jwks(&cfg, jwks, true);
    let keys = Arc::clone(&state.keys);
    let service = common::start_on(&cfg, state, listener).await;

    let fixture = json!({
        "url": url,
        "realm": realm,
        "provider": if matches!(idp, Realm::Keycloak(_)) { "keycloak" } else { "test-idp" },
        "org": s.org.id.to_string(),
        "owner": { "principal": owner, "name": "Olivia Owner", "login": owner_login },
        "member": { "principal": member, "name": "Max Member", "login": member_login },
        // Six minutes old: expired a minute ago; and one whose life is
        // above the 300 s limit of tutela-admin. A fresh one as control.
        "stale_admin": [
            admin_token(&keys, &owner, &s.tid, 360, 300),
            admin_token(&keys, &owner, &s.tid, 360, 420),
        ],
        "fresh_admin": admin_token(&keys, &owner, &s.tid, 0, 120),
        "shots": std::env::var("TUTELA_E2E_SHOTS").unwrap_or_default(),
    });
    let path = std::env::temp_dir().join(format!("tutela-e2e-{}.json", uuid::Uuid::now_v7()));
    std::fs::write(&path, fixture.to_string()).unwrap();

    let console = repo().join("console");
    let out = tokio::task::spawn_blocking(move || {
        Command::new("pnpm")
            .args(["exec", "playwright", "test", "--reporter=list"])
            .current_dir(console)
            .env("TUTELA_E2E_FIXTURE", &path)
            .output()
            .map(|o| (o, path))
    })
    .await
    .unwrap();
    let (out, path) = out.expect("pnpm runs: make js-install first");
    let _ = std::fs::remove_file(path);
    println!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "the Console's exit check failed");

    // What the people did in the browser is in the tenant's audit chain,
    // with the person behind the session as the actor.
    for action in [
        "tutela_assignment:create",
        "tutela_assignment:delete",
        "tutela_model:publish",
    ] {
        let records = common::audited(&mut d.owner, &s.key, action).await;
        assert!(
            records
                .iter()
                .any(|r| r["outcome"] == "success" && r["actor"]["id"] == owner.as_str()),
            "{action}: {records:?}"
        );
    }

    service.stop().await.unwrap();
    idp.stop().await;
    d.finish().await;
}
