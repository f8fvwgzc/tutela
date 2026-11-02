//! Model versions over the API, through the real auth layer on a real
//! Postgres (CONTRACTS.md 7.10, ADR-0026).
#![cfg(test)]

mod common;

use common::{AGENT, MANIFEST, SA, Seed, USER, World, http, now, world};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutela_store::approval::{self, Approval};
use tutela_store::tokio_postgres::Client;

const ADMIN: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b1";
const ADMIN_SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b2";

/// The same model with the reader's level on invoices changed.
fn with_reader(level: &str) -> String {
    MANIFEST.replace(
        "grants = { project = \"read\", invoice = \"read\" }",
        &format!("grants = {{ project = \"read\", invoice = \"{level}\" }}"),
    )
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

async fn admins(w: &mut World) {
    for s in [&w.a, &w.b] {
        assign(&mut w.d.owner, s, ADMIN, "owner").await;
        assign(&mut w.d.owner, s, ADMIN_SA, "owner").await;
    }
}

async fn approver(owner: &mut Client) -> (SigningKey, String) {
    let key = SigningKey::from_bytes(&[9; 32]);
    let pk = key.verifying_key().to_bytes();
    let tx = owner.transaction().await.unwrap();
    let kid = tutela_store::add_approver(&tx, "dana", &pk).await.unwrap();
    tx.commit().await.unwrap();
    (key, kid)
}

fn token_for(key: &SigningKey, kid: &str, from: &str, to: &str, tid: &str, secs: u64) -> String {
    approval::mint(
        key,
        &Approval {
            app: "crm".into(),
            from: from.into(),
            to: to.into(),
            kid: kid.into(),
            iat: now() - 10,
            exp: now() + secs,
            tid: Some(tid.into()),
        },
    )
    .unwrap()
}

async fn get(w: &World, path: &str, token: &str) -> reqwest::Response {
    http()
        .get(w.s.api_url(path))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

async fn active(w: &World, s: &Seed) -> Value {
    let t = w.issuer.token(ADMIN, &s.tid, 0);
    let v: Value = get(w, "/v1/models", &t).await.json().await.unwrap();
    v["active"].clone()
}

async fn publish(w: &World, s: &Seed, body: &Value) -> reqwest::Response {
    let t = w.issuer.token(ADMIN, &s.tid, 0);
    w.post("/v1/models/publish", &t, body).await
}

fn problem(v: &Value) -> &str {
    v["type"]
        .as_str()
        .unwrap()
        .strip_prefix("urn:tutela:problem:")
        .unwrap()
}

/// May the seed's user write an invoice, at this revision or later?
async fn can_write(w: &World, s: &Seed, user: &str, rev: u64) -> bool {
    let mut q = common::ask(user, "invoice:write", s);
    q["context"] = json!({"at_least_revision": rev});
    let t = w.issuer.token(SA, &s.tid, 0);
    let v: Value = w
        .post("/access/v1/evaluation", &t, &q)
        .await
        .json()
        .await
        .unwrap();
    v["decision"].as_bool().unwrap()
}

#[tokio::test]
async fn tm08_a_widening_publish_is_refused_without_an_approval_token() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let (key, kid) = approver(&mut w.d.owner).await;
    let head = active(&w, &w.a).await;
    let expected = head["version"].as_i64().unwrap();
    let from = head["digest"].as_str().unwrap().to_owned();
    let source = with_reader("write");
    let to = tutela_store::digest(&source);
    let tid = w.a.tid.clone();
    let body = |approval: Option<String>| json!({"source": source, "expected_version": expected, "approval": approval});

    let res = publish(&w, &w.a, &body(None)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let v: Value = res.json().await.unwrap();
    assert_eq!(problem(&v), "approval_required", "{v}");
    assert!(!can_write(&w, &w.a, USER, 0).await);
    assert_eq!(active(&w, &w.a).await, head);

    // Each of these approves something else.
    let bad = [
        "tutela-approval-v1.e30.AAAA".to_owned(),
        token_for(&key, &kid, &from, "b", &tid, 600),
        token_for(&key, &kid, "a", &to, &tid, 600),
        token_for(&key, &kid, &from, &to, &w.b.tid, 600),
        token_for(&key, &kid, &from, &to, &tid, 0),
        token_for(
            &SigningKey::from_bytes(&[8; 32]),
            &kid,
            &from,
            &to,
            &tid,
            600,
        ),
    ];
    for t in bad {
        let res = publish(&w, &w.a, &body(Some(t.clone()))).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{t}");
    }
    assert_eq!(active(&w, &w.a).await, head);

    // A token with no tenant is for the app's manifest, not for one tenant.
    let open = approval::mint(
        &key,
        &Approval {
            app: "crm".into(),
            from: from.clone(),
            to: to.clone(),
            kid: kid.clone(),
            iat: now() - 10,
            exp: now() + 600,
            tid: None,
        },
    )
    .unwrap();
    let res = publish(&w, &w.a, &body(Some(open))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // A revoked key approves nothing, also tokens it signed before.
    let late = SigningKey::from_bytes(&[10; 32]);
    let tx = w.d.owner.transaction().await.unwrap();
    let late_pk = late.verifying_key().to_bytes();
    let late_kid = tutela_store::add_approver(&tx, "ex", &late_pk)
        .await
        .unwrap();
    tutela_store::revoke_approver(&tx, &late_kid).await.unwrap();
    tx.commit().await.unwrap();
    let revoked = token_for(&late, &late_kid, &from, &to, &tid, 600);
    let res = publish(&w, &w.a, &body(Some(revoked))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let good = token_for(&key, &kid, &from, &to, &tid, 600);
    let res = publish(&w, &w.a, &body(Some(good.clone()))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["class"], "widening");
    // Version 1 is the manifest the tenant ran on until now.
    assert_eq!(v["version"], 2);
    assert!(can_write(&w, &w.a, USER, v["rev"].as_u64().unwrap()).await);

    let t = w.issuer.token(ADMIN, &tid, 0);
    let base: Value = get(&w, "/v1/models/1", &t).await.json().await.unwrap();
    assert_eq!(base["source"], MANIFEST);
    assert_eq!(base["origin"], "app");
    let one: Value = get(&w, "/v1/models/2", &t).await.json().await.unwrap();
    assert_eq!(one["source"], source);
    assert_eq!(one["approvers"], json!([kid]));
    assert_eq!(one["author"], ADMIN);
    assert_eq!(one["origin"], "tenant");
    w.finish().await;
}

#[tokio::test]
async fn tm05_a_publish_changes_its_own_tenant_only() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let (a0, b0) = (active(&w, &w.a).await, active(&w, &w.b).await);
    // Narrowing, so no token: the approver of tenant B loses write.
    let source = MANIFEST.replace(
        "grants = { project = \"write\", invoice = \"write\", ",
        "grants = { project = \"write\", invoice = \"read\", ",
    );
    let body = json!({"source": source, "expected_version": b0["version"]});
    assert!(can_write(&w, &w.b, common::B_USER, 0).await);
    let res = publish(&w, &w.b, &body).await;
    assert_eq!(res.status(), StatusCode::OK, "{:?}", res.text().await);
    assert_eq!(active(&w, &w.a).await, a0);
    let b1 = active(&w, &w.b).await;
    assert_eq!(b1["own"], true);
    assert_ne!(b1["digest"], b0["digest"]);
    assert_eq!(b1["version"], 2);

    let rev = {
        let t = w.issuer.token(ADMIN, &w.b.tid, 0);
        let v: Value = get(&w, "/v1/models", &t).await.json().await.unwrap();
        v["versions"][0]["rev"].as_u64().unwrap()
    };
    assert!(!can_write(&w, &w.b, common::B_USER, rev).await);

    // Tenant A's token sees nothing of B's version, and B's history is B's.
    let t = w.issuer.token(ADMIN, &w.a.tid, 0);
    let v = b1["version"].as_i64().unwrap();
    let res = get(&w, &format!("/v1/models/{v}"), &t).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let list: Value = get(&w, "/v1/models", &t).await.json().await.unwrap();
    assert!(
        list["versions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["origin"] == "app")
    );
    w.finish().await;
}

#[tokio::test]
async fn tm08_a_rollback_is_a_new_version_and_passes_the_same_checks() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let (key, kid) = approver(&mut w.d.owner).await;
    let v1 = active(&w, &w.a).await;
    // Narrow first: the reader loses read on invoices. The manifest the
    // tenant ran on becomes version 1.
    let narrow = with_reader("none");
    let body = json!({"source": narrow, "expected_version": v1["version"]});
    let res = publish(&w, &w.a, &body).await;
    assert_eq!(res.status(), StatusCode::OK);
    let digest = tutela_store::digest(&narrow);
    let first = 1;

    // Going back widens, so it needs a token like any other widening change.
    let restore = |approval: Option<String>| json!({"restore": first, "expected_version": first + 1, "approval": approval});
    let res = publish(&w, &w.a, &restore(None)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let token = token_for(
        &key,
        &kid,
        &digest,
        v1["digest"].as_str().unwrap(),
        &w.a.tid,
        600,
    );
    let res = publish(&w, &w.a, &restore(Some(token))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["version"], first + 2);
    assert_eq!(v["restores"], first);

    let now = active(&w, &w.a).await;
    assert_eq!(now["digest"], v1["digest"]);
    assert_eq!(now["own"], true);
    // Nothing was rewritten.
    let t = w.issuer.token(ADMIN, &w.a.tid, 0);
    let list: Value = get(&w, "/v1/models", &t).await.json().await.unwrap();
    let numbers: Vec<i64> = list["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_i64().unwrap())
        .collect();
    assert_eq!(numbers, vec![first + 2, first + 1, first]);
    assert_eq!(list["versions"][0]["restores"], first);
    assert_eq!(list["versions"][1]["digest"], digest);

    // A version that does not exist cannot be restored.
    let res = publish(
        &w,
        &w.a,
        &json!({"restore": 99, "expected_version": first + 2}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    w.finish().await;
}

#[tokio::test]
async fn who_may_look_at_or_change_a_model() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let tid = w.a.tid.clone();
    let head = active(&w, &w.a).await;
    let body = json!({"source": with_reader("none"), "expected_version": head["version"]});
    // A plain member of the tenant, its product service, and an agent.
    for sub in [USER, SA, AGENT] {
        let t = w.issuer.token(sub, &tid, 0);
        assert_eq!(
            get(&w, "/v1/models", &t).await.status(),
            StatusCode::FORBIDDEN,
            "{sub}"
        );
        assert_eq!(
            get(&w, "/v1/models/1", &t).await.status(),
            StatusCode::FORBIDDEN,
            "{sub}"
        );
        assert_eq!(
            w.post("/v1/models/publish", &t, &body).await.status(),
            StatusCode::FORBIDDEN,
            "{sub}"
        );
    }
    // An admin of tenant B is no one in tenant A: its token is for tenant B.
    let t = w.issuer.token(common::B_USER, &tid, 0);
    assert_eq!(
        w.post("/v1/models/publish", &t, &body).await.status(),
        StatusCode::FORBIDDEN
    );
    // No token.
    let res = http().get(w.s.api_url("/v1/models")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // A service holding the keys may: `tutela apply` in a pipeline.
    let t = w.issuer.token(ADMIN_SA, &tid, 0);
    assert_eq!(get(&w, "/v1/models", &t).await.status(), StatusCode::OK);
    let res = w.post("/v1/models/publish", &t, &body).await;
    assert_eq!(res.status(), StatusCode::OK);
    w.finish().await;
}

#[tokio::test]
async fn an_org_admin_of_part_of_a_tenant_does_not_change_the_whole_of_it() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::add_org(&tx, &w.a.key).await.unwrap();
    tx.commit().await.unwrap();
    // A new org in tenant A, with no admin yet. A new token asks past the
    // lease with its revision.
    let t = w.issuer.token(ADMIN, &w.a.tid, 1_000);
    let res = get(&w, "/v1/models", &t).await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let t = w.issuer.token(ADMIN, &w.a.tid, 0);
    assert_eq!(
        get(&w, "/v1/models", &t).await.status(),
        StatusCode::FORBIDDEN
    );
    w.finish().await;
}

#[tokio::test]
async fn a_publish_compares_against_what_is_there() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let head = active(&w, &w.a).await;
    let v = head["version"].as_i64().unwrap();
    let t = w.issuer.token(ADMIN, &w.a.tid, 0);
    let ask = |body: Value| {
        let (w, t) = (&w, t.clone());
        async move {
            let res = w.post("/v1/models/publish", &t, &body).await;
            let status = res.status();
            (status, res.json::<Value>().await.unwrap())
        }
    };
    let narrow = with_reader("none");
    let (s, b) = ask(json!({"source": narrow, "expected_version": v + 5})).await;
    assert_eq!((s, problem(&b)), (StatusCode::CONFLICT, "version_conflict"));
    let (s, b) = ask(json!({"source": MANIFEST, "expected_version": v})).await;
    assert_eq!((s, problem(&b)), (StatusCode::CONFLICT, "no_change"));
    let (s, b) = ask(json!({"source": "not toml", "expected_version": v})).await;
    assert_eq!(
        (s, problem(&b)),
        (StatusCode::BAD_REQUEST, "invalid_manifest")
    );
    let other = MANIFEST.replace("name = \"crm\"", "name = \"other\"");
    let (s, b) = ask(json!({"source": other, "expected_version": v})).await;
    assert_eq!((s, problem(&b)), (StatusCode::BAD_REQUEST, "app_mismatch"));
    let (s, b) = ask(json!({"source": narrow})).await;
    assert_eq!(
        (s, problem(&b)),
        (StatusCode::BAD_REQUEST, "invalid_request")
    );
    let (s, _) = ask(json!({"source": narrow, "restore": 1, "expected_version": v})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Two publishes from one version: one wins, and the other compares again.
    let a = with_reader("none");
    let b = MANIFEST.replace(
        "[roles.reader]\ngrants = { project = \"read\", invoice = \"read\" }",
        "[roles.reader]\ngrants = { project = \"none\", invoice = \"read\" }",
    );
    let (ra, rb) = tokio::join!(
        ask(json!({"source": a, "expected_version": v})),
        ask(json!({"source": b, "expected_version": v})),
    );
    let mut got = [ra.0.as_u16(), rb.0.as_u16()];
    got.sort_unstable();
    assert_eq!(got, [200, 409], "{ra:?} {rb:?}");

    let m = reqwest::get(w.s.ops_url("/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for line in [
        "tutelad_model_operations_total{operation=\"publish\",outcome=\"ok\"} 1",
        "tutelad_model_operations_total{operation=\"publish\",outcome=\"invalid\"}",
        "tutelad_model_operations_total{operation=\"publish\",outcome=\"conflict\"}",
    ] {
        assert!(m.contains(line), "{line}");
    }
    w.finish().await;
}

#[tokio::test]
async fn tm14_the_service_role_writes_no_manifest_and_no_approver_key() {
    let Some(w) = world().await else { return };
    let service = common::connect(&w.d.service_url).await;
    for sql in [
        "UPDATE tutela.app_manifest SET version = version + 1",
        "INSERT INTO tutela.approver_key (id, name, public_key) VALUES ('apk_0', 'x', '\\x00')",
    ] {
        let e = service.batch_execute(sql).await.unwrap_err();
        assert_eq!(e.code().map(|c| c.code()), Some("42501"), "{sql}");
    }
    assert!(
        service
            .query("SELECT id FROM tutela.approver_key", &[])
            .await
            .is_ok()
    );
    w.finish().await;
}

async fn dry_run(w: &World, s: &Seed, sub: &str, source: &str) -> reqwest::Response {
    let t = w.issuer.token(sub, &s.tid, 0);
    w.post("/v1/models/impact", &t, &json!({"source": source}))
        .await
}

#[tokio::test]
async fn the_impact_report_says_who_gains_from_the_tenants_own_data() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    // Tenant B's approver is also a reader there. It is in B's report only.
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::assign(
        &tx,
        &w.b.key,
        &Subject::Principal(common::B_USER.parse().unwrap()),
        &RoleKey::parse("reader").unwrap(),
        &w.b.org,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let head = active(&w, &w.a).await;
    let source = with_reader("write");
    let res = dry_run(&w, &w.a, ADMIN, &source).await;
    assert_eq!(res.status(), StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["class"], "widening");
    assert_eq!(v["version"], head["version"]);
    assert_eq!(v["from"], head["digest"]);
    assert_eq!(v["to"], tutela_store::digest(&source));
    let impact = &v["impact"];
    assert_eq!(impact["complete"], true);
    assert_eq!(impact["no_impact"], false);
    assert_eq!(
        impact["summary"],
        json!([
            "1 user gains write on invoice in 1 scope",
            "1 user gains write on invoice.status in 1 scope",
        ]),
        "{impact}"
    );
    assert_eq!(impact["lines"][0]["examples"], json!([USER]));
    assert_eq!(impact["lines"][0]["count"], 1);
    // Nothing changed: the live answer is the old one, at every revision.
    assert!(!can_write(&w, &w.a, USER, 0).await);
    assert_eq!(active(&w, &w.a).await, head);

    let v: Value = dry_run(&w, &w.b, ADMIN, &source)
        .await
        .json()
        .await
        .unwrap();
    let names = v["impact"]["lines"][0]["examples"].clone();
    assert_eq!(names, json!([common::B_USER]), "{v}");

    // A change nobody holds has no impact, and says so.
    let spare = format!("{MANIFEST}\n[roles.spare]\ngrants = {{ invoice = \"full\" }}\n");
    let v: Value = dry_run(&w, &w.a, ADMIN, &spare).await.json().await.unwrap();
    assert_eq!(v["impact"]["no_impact"], true, "{v}");
    assert_eq!(v["class"], "widening");

    // It reveals other people's access: a plain member, a product service
    // and an agent may not ask.
    for sub in [USER, SA, AGENT] {
        let res = dry_run(&w, &w.a, sub, &source).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{sub}");
    }
    w.finish().await;
}

#[tokio::test]
async fn an_impact_report_that_stops_early_says_so_and_is_kept_with_the_version() {
    let Some(mut w) = common::world_with(|c| c.impact_work = 1).await else {
        return;
    };
    admins(&mut w).await;
    let head = active(&w, &w.a).await;
    let narrow = with_reader("none");
    let v: Value = dry_run(&w, &w.a, ADMIN, &narrow)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["impact"]["complete"], false, "{v}");
    assert_eq!(v["impact"]["no_impact"], false);

    let res = publish(
        &w,
        &w.a,
        &json!({"source": narrow, "expected_version": head["version"]}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let out: Value = res.json().await.unwrap();
    assert_eq!(out["impact"]["complete"], false);
    let t = w.issuer.token(ADMIN, &w.a.tid, 0);
    let kept: Value = get(&w, &format!("/v1/models/{}", out["version"]), &t)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(kept["impact"], out["impact"]);
    w.finish().await;
}
