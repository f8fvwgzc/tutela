//! The Helm chart's bootstrap job (ADR-0056): `tutelad bootstrap`'s plan
//! against a real Postgres, from an empty database, run again, with its
//! Secrets gone, and with an owner's later change. Secrets go to a directory
//! here; the Kubernetes calls are tested in `bootstrap::kube`.
#![cfg(test)]

mod common;

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_pdp::model::RoleKey;
use tutela_pdp::{PathEntry, Subject};
use tutelad::bootstrap::{Env, Plan, Sink, Step, run};
use tutelad::config::TrustFile;

use common::{OWN_ISS, SERVICE, TestDb, config, http, start, state};

const KC: &str = "https://kc.example.test/realms/acme";
const TID: &str = "ten_01a1b4a2-5f7f-7123-8000-1d2e3f405162";

fn plan(hook: &str) -> Plan {
    Plan::parse(
        &json!({
            "tenant": {
                "id": TID,
                "name": "Acme",
                "org_name": "Head office",
                "admin_upstream": [format!("{KC}=olivia")],
            },
            "apps": [
                {"name": "crm", "secret": "crm-tutela", "roles": [{"role": "owner", "scope": "org"}]},
                {"name": "billing", "secret": "billing-tutela"},
            ],
            "webhooks": [
                {"app": "crm", "url": hook, "types": ["tutela.permissions.changed.v1"],
                 "secret": "crm-tutela-webhook"},
            ],
            "console_url": "https://tutela.example.test/console/",
        })
        .to_string(),
    )
    .unwrap()
}

fn env(d: &TestDb) -> Env {
    Env {
        owner_url: d.owner_url.clone(),
        service_role: SERVICE.to_owned(),
        own: OWN_ISS.parse().unwrap(),
        secrets: common::secrets(),
        policy: tutela_safenet::Policy::new().dev_loopback(),
    }
}

fn outcomes(steps: &[Step]) -> Vec<(&'static str, &'static str)> {
    steps.iter().map(|s| (s.step, s.outcome)).collect()
}

fn read(dir: &Path, name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join(format!("{name}.json"))).unwrap()).unwrap()
}

/// A token of the app's service account by `client_credentials`.
async fn client_token(api: &str, id: &str, secret: &str) -> (StatusCode, Value) {
    let r = http()
        .post(format!("{api}/oauth2/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "authorization",
            format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
        )
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(Value::Null))
}

fn claims(token: &str) -> Value {
    let p = token.split('.').nth(1).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p)
            .unwrap(),
    )
    .unwrap()
}

/// Apps, webhooks and audit records of the tenant: the tables are under
/// forced row-level security, so the count enters it.
async fn counts(d: &mut TestDb) -> (usize, usize, usize) {
    let key = key();
    let tx = d.owner.transaction().await.unwrap();
    let apps = tutela_store::apps(&tx, &key).await.unwrap().len();
    let hooks = tutela_store::webhooks::webhooks(&tx, &key)
        .await
        .unwrap()
        .len();
    let records = tutela_store::audit_records(&tx, &key, 0, 1000)
        .await
        .unwrap()
        .len();
    tx.commit().await.unwrap();
    (apps, hooks, records)
}

fn key() -> tutela_contracts::tenant::TenantKey {
    tutela_contracts::tenant::TenantKey::new(OWN_ISS.parse().unwrap(), TID.parse().unwrap())
}

#[tokio::test]
async fn the_job_makes_the_tenant_apps_roles_and_webhooks_once_and_heals_a_lost_secret() {
    // An empty database: the job migrates it.
    let Some(mut d) = common::db().await else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("tutela-bootstrap-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let sink = Sink::Dir(dir.clone());
    let hook = "http://127.0.0.1:9/hook";
    let env = env(&d);

    let first = run(&plan(hook), &env, &sink).await.unwrap();
    assert_eq!(
        outcomes(&first),
        [
            ("migrate", "done"),
            ("tenant", "made"),
            ("app", "made"),
            ("role", "given"),
            ("app", "made"),
            ("webhook", "made"),
            ("console", "done"),
        ]
    );
    assert_eq!(first[1].about, TID);
    // No step names a secret.
    let crm = read(&dir, "crm-tutela");
    let secret = crm["client_secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("tut_sk_"));
    let printed = serde_json::to_string(&first).unwrap();
    assert!(!printed.contains(&secret));
    assert_eq!(crm["tenant"], TID);
    assert_eq!(crm["issuer"], OWN_ISS);
    assert_eq!(crm["token_url"], format!("{OWN_ISS}/oauth2/token"));
    let hook_secret = read(&dir, "crm-tutela-webhook");
    assert!(
        hook_secret["secret"]
            .as_str()
            .unwrap()
            .starts_with("whsec_")
    );
    assert!(!printed.contains(hook_secret["secret"].as_str().unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.join("crm-tutela.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The app's secret works at the real token endpoint, for its tenant.
    let trust = TrustFile::parse(
        &format!(
            "[[issuer]]\niss = \"{KC}\"\njwks_uri = \"{KC}/certs\"\nalgs = [\"RS256\"]\n\
             tenants = [\"{TID}\"]\nexternal = true\nallow_typ_jwt = true\n"
        ),
        false,
    )
    .unwrap();
    let cfg = config(&d.service_url, trust);
    let s = start(&cfg, state(&cfg, &common::Issuer::new())).await;
    let api = format!("http://{}", s.api);
    let cid = crm["client_id"].as_str().unwrap().to_owned();
    let (status, v) = client_token(&api, &cid, &secret).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let c = claims(v["access_token"].as_str().unwrap());
    assert_eq!(c["tid"], TID);
    assert_eq!(c["sub"], crm["principal"]);
    assert_eq!(c["azp"], cid.as_str());

    // The first owner by upstream account and the app's service account
    // are owners of the first org; the tenant has its name.
    let key =
        tutela_contracts::tenant::TenantKey::new(OWN_ISS.parse().unwrap(), TID.parse().unwrap());
    let tx = d.owner.transaction().await.unwrap();
    let info = tutela_store::tenant_info(&tx, &key).await.unwrap();
    assert_eq!(info.name.as_deref(), Some("Acme"));
    let orgs = tutela_store::orgs(&tx, &key).await.unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].name.as_deref(), Some("Head office"));
    let at = PathEntry::org(&orgs[0].org).unwrap();
    let owners = tutela_store::assignments(
        &tx,
        &key,
        &tutela_store::AssignmentQuery {
            subject: None,
            scope: Some(&at),
            after: None,
            limit: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(owners.len(), 2);
    assert!(owners.iter().all(|a| a.role.as_str() == "owner"));
    let sa = Subject::Principal(crm["principal"].as_str().unwrap().parse().unwrap());
    assert!(owners.iter().any(|a| a.subject == sa));

    // Again, as on every upgrade: nothing new, nothing rotated.
    let files = |names: &[&str]| -> Vec<Vec<u8>> {
        names
            .iter()
            .map(|n| std::fs::read(dir.join(format!("{n}.json"))).unwrap())
            .collect()
    };
    let names = ["crm-tutela", "billing-tutela", "crm-tutela-webhook"];
    let before = files(&names);
    let (apps, hooks, records) = counts(&mut d).await;
    assert_eq!((apps, hooks), (2, 1));
    let again = run(&plan(hook), &env, &sink).await.unwrap();
    assert_eq!(
        outcomes(&again),
        [
            ("migrate", "done"),
            ("tenant", "kept"),
            ("app", "kept"),
            ("role", "kept"),
            ("app", "kept"),
            ("webhook", "kept"),
            ("console", "done"),
        ]
    );
    assert_eq!(files(&names), before);
    assert_eq!(counts(&mut d).await, (apps, hooks, records));
    let tx = d.owner.transaction().await.unwrap();
    let tenants: i64 = tx
        .query_one("SELECT count(*) FROM tutela.tenant", &[])
        .await
        .unwrap()
        .get(0);
    tx.commit().await.unwrap();
    assert_eq!(tenants, 1);

    // A Secret gone: the job rotates (a secret is shown once) and writes the
    // new one; the client id stays, and the new secret works.
    std::fs::remove_file(dir.join("crm-tutela.json")).unwrap();
    std::fs::remove_file(dir.join("crm-tutela-webhook.json")).unwrap();
    let healed = run(&plan(hook), &env, &sink).await.unwrap();
    assert_eq!(
        outcomes(&healed)[2..6],
        [
            ("app", "rotated"),
            ("role", "kept"),
            ("app", "kept"),
            ("webhook", "rotated")
        ]
    );
    let crm2 = read(&dir, "crm-tutela");
    assert_eq!(crm2["client_id"], cid.as_str());
    let secret2 = crm2["client_secret"].as_str().unwrap();
    assert_ne!(secret2, secret);
    let (status, _) = client_token(&api, &cid, secret2).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        read(&dir, "crm-tutela-webhook")["webhook_id"],
        hook_secret["webhook_id"]
    );
    assert_eq!(counts(&mut d).await.0, 2);

    // The tenant's owner gives the app another role there: the job leaves it.
    let tx = d.owner.transaction().await.unwrap();
    let mine = owners.iter().find(|a| a.subject == sa).unwrap();
    tutela_store::unassign(&tx, &key, &mine.id).await.unwrap();
    tutela_store::assign(
        &tx,
        &key,
        &sa,
        &RoleKey::parse("viewer").unwrap(),
        &at,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let left = run(&plan(hook), &env, &sink).await.unwrap();
    assert_eq!(left[3].step, "role");
    assert_eq!(left[3].outcome, "left");

    // Every change was recorded in the tenant's chain, by the operator.
    let tx = d.owner.transaction().await.unwrap();
    let chain = tutela_store::audit_records(&tx, &key, 0, 1000)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let actions: Vec<String> = chain
        .iter()
        .map(|r| serde_json::from_str::<Value>(&r.body).unwrap()["action"].to_string())
        .map(|a| a.trim_matches('"').to_owned())
        .collect();
    for a in [
        "tutela_tenant:create",
        "tutela_app:create",
        "tutela_assignment:create",
        "tutela_webhook:register",
        "tutela_app:rotate",
        "tutela_webhook:rotate",
    ] {
        assert!(actions.iter().any(|x| x == a), "{a} is not recorded");
    }

    s.stop().await.unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    d.finish().await;
}

#[tokio::test]
async fn the_job_refuses_a_bad_plan_and_a_soft_deleted_tenant() {
    let good = |f: &dyn Fn(&mut Value)| {
        let mut v = json!({
            "tenant": {"id": TID, "admins": ["sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7090"]},
            "apps": [{"name": "crm", "secret": "crm-tutela"}],
            "webhooks": [{"app": "crm", "url": "https://crm.example.test/hook", "secret": "crm-hook"}],
        });
        f(&mut v);
        Plan::parse(&v.to_string())
    };
    assert!(good(&|_| {}).is_ok());
    for (why, bad) in [
        (
            "tenant id",
            &(|v: &mut Value| v["tenant"]["id"] = json!("ten_nope")) as &dyn Fn(&mut Value),
        ),
        ("secret name", &|v: &mut Value| {
            v["apps"][0]["secret"] = json!("../etc")
        }),
        ("upper case", &|v: &mut Value| {
            v["apps"][0]["secret"] = json!("Crm")
        }),
        ("unknown app", &|v: &mut Value| {
            v["webhooks"][0]["app"] = json!("billing")
        }),
        ("shared secret", &|v: &mut Value| {
            v["webhooks"][0]["secret"] = json!("crm-tutela")
        }),
        ("event type", &|v: &mut Value| {
            v["webhooks"][0]["types"] = json!(["nope"])
        }),
        ("role", &|v: &mut Value| {
            v["apps"][0]["roles"] = json!([{"role": "No Role"}])
        }),
        ("scope", &|v: &mut Value| {
            v["apps"][0]["roles"] = json!([{"role": "owner", "scope": "nope"}])
        }),
        ("unknown field", &|v: &mut Value| {
            v["apps"][0]["secrets"] = json!("x")
        }),
    ] {
        assert!(good(bad).is_err(), "{why}");
    }

    let Some(mut d) = common::migrated().await else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("tutela-bootstrap-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let sink = Sink::Dir(dir.clone());
    let p = Plan::parse(
        &json!({"tenant": {"id": TID, "admins": ["sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7090"]}})
            .to_string(),
    )
    .unwrap();
    let env = env(&d);
    run(&p, &env, &sink).await.unwrap();
    let key =
        tutela_contracts::tenant::TenantKey::new(OWN_ISS.parse().unwrap(), TID.parse().unwrap());
    let tx = d.owner.transaction().await.unwrap();
    tutela_store::delete_tenant(&tx, &key, std::time::Duration::from_secs(3600))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let e = run(&p, &env, &sink).await.unwrap_err();
    assert!(format!("{e:#}").contains("soft-deleted"), "{e:#}");

    // A tenant id under another issuer is not taken over.
    let other = Env {
        own: "https://other.example.test".parse().unwrap(),
        ..env
    };
    let e = run(&p, &other, &sink).await.unwrap_err();
    assert!(format!("{e:#}").contains("another issuer"), "{e:#}");
    std::fs::remove_dir_all(&dir).unwrap();
    d.finish().await;
}

/// `tutelad tenant new-id` gives the chart's `tenant.id`: a fresh tenant id
/// each time, with no database and no setting.
#[tokio::test]
async fn new_id_prints_a_fresh_tenant_id() {
    let run = || async {
        let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_tutelad"))
            .env_clear()
            .args(["tenant", "new-id"])
            .output()
            .await
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    let (a, b) = (run().await, run().await);
    assert_ne!(a, b);
    for id in [a, b] {
        id.parse::<tutela_contracts::tenant::TenantId>().unwrap();
        assert!(Plan::parse(&json!({"tenant": {"id": id}}).to_string()).is_ok());
    }
}
