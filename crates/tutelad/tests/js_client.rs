//! `@f8fvwgzc/tutela-js` against a real `tutelad` on a real Postgres (part
//! 4b1). This test makes the world: two tenants under `tutelad`'s own
//! issuer, each with a Keycloak-shaped realm in the trust file, people with
//! roles, and upstream tokens signed by a local signer (as `exchange.rs`
//! does). It writes them to a fixture file, then runs the JavaScript test
//! `sdk/js/test-integration/tutelad.it.ts` with vitest against the service.
//!
//! It needs node and pnpm, so it runs only with `TUTELA_JS_INTEGRATION=1`
//! (`make js-it`, part of `make`); plain `cargo test` says it is skipped.
//! With it set, a missing database fails under `TUTELA_REQUIRE_DATABASE=1`,
//! as every database test does.
#![cfg(test)]

mod common;

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutela_store::tokio_postgres::Client;
use tutelad::config::TrustFile;

use common::{AUD, Issuer, OWN_ISS, STEP_UP, STRANGER, Seed, now};

/// A Keycloak realm that signs people in for tenant A.
const KC_A: &str = "https://kc.example.test/realms/acme";
/// A realm for tenant B.
const KC_B: &str = "https://kc.example.test/realms/beta";

/// The test manifest, with a role that may manage access at a project while
/// it only reads there (as `admin_bindings.rs` has it).
fn manifest() -> String {
    format!(
        "{}\n{}",
        common::MANIFEST,
        r#"
[roles.keeper]
grants = { project = "read", invoice = "read", "project:manage_access" = true }
"#
    )
}

/// A person of `iss` with upstream subject `sub`, made in the tenant as
/// token exchange would make it.
async fn person(owner: &mut Client, s: &Seed, iss: &str, sub: &str) -> String {
    let tx = owner.transaction().await.unwrap();
    let (p, _) = tutela_store::provision_user(&tx, &s.key, &iss.parse().unwrap(), sub)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    p.principal.to_string()
}

async fn assign(
    owner: &mut Client,
    s: &Seed,
    who: &str,
    role: &str,
    at: &tutela_pdp::PathEntry,
) -> String {
    let tx = owner.transaction().await.unwrap();
    let (id, _) = tutela_store::assign(
        &tx,
        &s.key,
        &Subject::Principal(who.parse().unwrap()),
        &RoleKey::parse(role).unwrap(),
        at,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id.to_string()
}

/// An access token of realm `iss` for upstream subject `sub`, shaped as
/// Keycloak's, with `acr` (the step-up value, or a plain "1").
fn kc(issuer: &Issuer, iss: &str, sub: &str, acr: &str) -> String {
    let now = now();
    issuer.sign_typed(
        "JWT",
        &json!({
            "exp": now + 300, "iat": now, "auth_time": now - 5,
            "jti": uuid::Uuid::now_v7().to_string(),
            "iss": iss, "aud": AUD, "sub": sub, "typ": "Bearer",
            "azp": "tutela-console", "sid": uuid::Uuid::now_v7().to_string(), "acr": acr,
            "scope": "openid email profile",
        }),
    )
}

fn tokens(issuer: &Issuer, iss: &str, sub: &str, acr: &str) -> Vec<String> {
    (0..4).map(|_| kc(issuer, iss, sub, acr)).collect()
}

fn scope(e: &tutela_pdp::PathEntry) -> Value {
    json!({"type": e.type_name.to_string(), "id": e.id.to_string()})
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tutela_js_against_a_real_tutelad() {
    if std::env::var("TUTELA_JS_INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipped: `make js-it` runs the JavaScript client against tutelad");
        return;
    }
    let Some(mut d) = common::migrated().await else {
        return;
    };
    common::publish(&mut d.owner, &manifest(), None).await;
    let a = common::seed_of(&mut d.owner, OWN_ISS, common::USER, "reader").await;
    let b = common::seed_of(&mut d.owner, OWN_ISS, common::B_USER, "approver").await;

    // Tenant A: an owner at the org, a keeper and a reader at project p-1.
    let owner = person(&mut d.owner, &a, KC_A, "kc-owner").await;
    let keeper = person(&mut d.owner, &a, KC_A, "kc-keeper").await;
    let reader = person(&mut d.owner, &a, KC_A, "kc-reader").await;
    let org_a = a.org.clone();
    let p1 = a.project.clone();
    assign(&mut d.owner, &a, &owner, "owner", &org_a).await;
    assign(&mut d.owner, &a, &keeper, "keeper", &p1).await;
    assign(&mut d.owner, &a, &reader, "reader", &p1).await;

    // Tenant B: its owner, and a project only B has, with an assignment.
    let b_owner = person(&mut d.owner, &b, KC_B, "kc-b-owner").await;
    let org_b = b.org.clone();
    assign(&mut d.owner, &b, &b_owner, "owner", &org_b).await;
    let pb = tutela_pdp::PathEntry::new("project".parse().unwrap(), "p-b".parse().unwrap());
    {
        let tx = d.owner.transaction().await.unwrap();
        tutela_store::put_scope(&tx, &b.key, &pb, std::slice::from_ref(&org_b), false)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let b_assignment = assign(&mut d.owner, &b, common::B_USER, "reader", &pb).await;

    let ext = |iss: &str, tid: &str| {
        format!(
            "[[issuer]]\niss = \"{iss}\"\njwks_uri = \"{iss}/protocol/openid-connect/certs\"\n\
             algs = [\"ES256\"]\ntenants = [\"{tid}\"]\nexternal = true\nallow_typ_jwt = true\n"
        )
    };
    let trust = TrustFile::parse(
        &format!("{}{}", ext(KC_A, &a.tid), ext(KC_B, &b.tid)),
        false,
    )
    .unwrap();
    let issuer = Issuer::new();
    let cfg = common::config(&d.service_url, trust);
    let s = common::start(&cfg, common::state(&cfg, &issuer)).await;

    let fixture = json!({
        "url": s.api_url(""),
        "newcomer": STRANGER,
        "a": {
            "tid": a.tid, "org": scope(&org_a), "project": scope(&p1),
            "owner": owner, "keeper": keeper, "reader": reader,
        },
        "b": {
            "tid": b.tid, "org": scope(&org_b), "project": scope(&pb),
            "assignment": b_assignment,
        },
        "upstream": {
            "owner": tokens(&issuer, KC_A, "kc-owner", STEP_UP),
            "owner_without_step_up": tokens(&issuer, KC_A, "kc-owner", "1"),
            "keeper": tokens(&issuer, KC_A, "kc-keeper", STEP_UP),
            "reader": tokens(&issuer, KC_A, "kc-reader", STEP_UP),
            "b_owner": tokens(&issuer, KC_B, "kc-b-owner", STEP_UP),
            "replay": tokens(&issuer, KC_A, "kc-owner", STEP_UP),
        },
    });
    let path = std::env::temp_dir().join(format!("tutela-js-it-{}.json", uuid::Uuid::now_v7()));
    std::fs::write(&path, fixture.to_string()).unwrap();

    let sdk = repo().join("sdk/js");
    let out = tokio::task::spawn_blocking(move || {
        Command::new("pnpm")
            .args([
                "exec",
                "vitest",
                "run",
                "--config",
                "vitest.integration.config.ts",
            ])
            .current_dir(sdk)
            .env("TUTELA_JS_FIXTURE", &path)
            .output()
            .map(|o| (o, path))
    })
    .await
    .unwrap();
    let (out, path) = out.expect("pnpm runs: make js-install first");
    let _ = std::fs::remove_file(path);
    println!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "the JavaScript integration test failed"
    );

    // What the client did is in tenant A's audit chain, with who asked:
    // the person behind the browser session, never a service.
    let made = common::audited(&mut d.owner, &a.key, "tutela_assignment:create").await;
    assert!(
        made.iter()
            .any(|r| r["outcome"] == "success" && r["actor"]["id"] == owner.as_str()),
        "{made:?}"
    );
    assert!(
        made.iter()
            .any(|r| r["outcome"] == "denied" && r["actor"]["id"] == keeper.as_str()),
        "{made:?}"
    );
    // Tenant B's assignment is untouched.
    let tx = d.owner.transaction().await.unwrap();
    let bundle = tutela_store::load(&tx, &b.key).await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        bundle
            .data
            .bindings
            .iter()
            .any(|x| x.id.as_str() == b_assignment),
        "tenant B's assignment is still there"
    );

    s.stop().await.unwrap();
    d.finish().await;
}
