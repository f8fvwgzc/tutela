//! The local hash-chained audit log through the real service, the real auth
//! layer and a real Postgres (ADR-0034, CONTRACTS.md 9.4, THREAT-MODEL.md
//! TM-20).
#![cfg(test)]

mod common;

use std::time::Duration;

use common::{MANIFEST, SA, STRANGER, Seed, USER, World, ask, audit_of, audited, world};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutela_store::tokio_postgres::Client;

const ADMIN: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70d1";
const ADMIN_SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70d2";

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
        let s = Seed {
            key: s.key.clone(),
            tid: s.tid.clone(),
            org: s.org.clone(),
            project: s.project.clone(),
            assignment: s.assignment.clone(),
        };
        assign(&mut w.d.owner, &s, ADMIN, "owner").await;
        assign(&mut w.d.owner, &s, ADMIN_SA, "owner").await;
    }
}

fn with_reader(level: &str) -> String {
    MANIFEST.replace(
        "grants = { project = \"read\", invoice = \"read\" }",
        &format!("grants = {{ project = \"read\", invoice = \"{level}\" }}"),
    )
}

async fn call(
    w: &World,
    method: &str,
    path: &str,
    asker: &str,
    s: &Seed,
    body: &Value,
) -> (StatusCode, Value) {
    let t = w.issuer.console(asker, &s.tid, 0);
    let req = if method == "PUT" {
        common::http().put(w.s.api_url(path))
    } else {
        common::http().post(w.s.api_url(path))
    };
    let res = req.bearer_auth(t).json(body).send().await.unwrap();
    let status = res.status();
    (status, res.json().await.unwrap_or(Value::Null))
}

fn problem(v: &Value) -> &str {
    v["type"]
        .as_str()
        .and_then(|t| t.strip_prefix("urn:tutela:problem:"))
        .unwrap_or("")
}

/// A publish, its refusals, an impact report, the two-person setting, a
/// proposal and its approval each leave their record, with what the notes
/// ask for; the other tenant's log has none of them.
#[tokio::test]
async fn tm20_model_operations_leave_their_records() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let a = Seed {
        key: w.a.key.clone(),
        tid: w.a.tid.clone(),
        org: w.a.org.clone(),
        project: w.a.project.clone(),
        assignment: w.a.assignment.clone(),
    };
    // An impact report reads other people's access: who asked is kept.
    let (status, v) = call(
        &w,
        "POST",
        "/v1/models/impact",
        ADMIN,
        &a,
        &json!({"source": with_reader("none")}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // A narrowing publish needs no approval.
    let active: Value = common::http()
        .get(w.s.api_url("/v1/models"))
        .bearer_auth(w.issuer.console(ADMIN, &a.tid, 0))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let base = active["active"]["version"].as_i64().unwrap();
    let (status, v) = call(
        &w,
        "POST",
        "/v1/models/publish",
        ADMIN,
        &a,
        &json!({"source": with_reader("none"), "expected_version": base}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (version, rev) = (v["version"].as_i64().unwrap(), v["rev"].as_u64().unwrap());
    // A widening one without its token is refused, and that is recorded.
    let (status, v) = call(
        &w,
        "POST",
        "/v1/models/publish",
        ADMIN_SA,
        &a,
        &json!({"source": MANIFEST, "expected_version": version}),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "approval_required"),
        "{v}"
    );

    let impact = audited(&mut w.d.owner, &a.key, "tutela_model:impact").await;
    assert_eq!(impact.len(), 1);
    assert_eq!(impact[0]["actor"]["id"], ADMIN);
    assert_eq!(impact[0]["details"]["class"], "narrowing");
    let publishes = audited(&mut w.d.owner, &a.key, "tutela_model:publish").await;
    assert_eq!(publishes.len(), 2, "{publishes:?}");
    let ok = &publishes[0];
    assert_eq!(ok["outcome"], "success");
    assert_eq!(ok["details"]["version"], version);
    assert_eq!(ok["details"]["rev"], rev);
    assert_eq!(ok["decision"]["rev"], rev);
    assert_eq!(ok["details"]["author"], ADMIN);
    assert_eq!(ok["details"]["class"], "narrowing");
    assert_eq!(ok["details"]["approvers"], json!([]));
    assert_eq!(ok["details"]["impact_digest"].as_str().unwrap().len(), 64);
    let refused = &publishes[1];
    assert_eq!(refused["outcome"], "denied");
    assert_eq!(refused["reason"], "approval_required");
    assert_eq!(refused["actor"]["id"], ADMIN_SA);

    // Two-person publish: on, a proposal, another person approves.
    let (status, v) = call(
        &w,
        "PUT",
        "/v1/models/settings",
        ADMIN,
        &a,
        &json!({"two_person": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // While it is on, a direct publish is refused, and nothing of it stays
    // but its refusal: the store's transaction rolled back.
    let (status, v) = call(&w, "POST", "/v1/models/publish", ADMIN, &a, &json!({"source": format!("{}\n# direct\n", with_reader("none")), "expected_version": version})).await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "two_person_required"),
        "{v}"
    );
    let (status, v) = call(&w, "POST", "/v1/models/proposals", ADMIN, &a, &json!({"source": format!("{}\n# proposal\n", with_reader("none")), "expected_version": version})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let pid = v["id"].as_str().unwrap().to_owned();
    let (status, v) = call(
        &w,
        "POST",
        &format!("/v1/models/proposals/{pid}/approve"),
        ADMIN,
        &a,
        &json!({}),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "same_person"),
        "{v}"
    );
    let (status, v) = call(
        &w,
        "POST",
        &format!("/v1/models/proposals/{pid}/approve"),
        ADMIN_SA,
        &a,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let v2 = v["version"].as_i64().unwrap();
    // A proposal that is not open any more cannot be rejected: no record
    // of a rejection that did not happen.
    let (status, v) = call(
        &w,
        "POST",
        &format!("/v1/models/proposals/{pid}/reject"),
        ADMIN,
        &a,
        &json!({}),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::CONFLICT, "not_open"),
        "{v}"
    );
    // Off takes two: asked, then agreed.
    call(
        &w,
        "PUT",
        "/v1/models/settings",
        ADMIN,
        &a,
        &json!({"two_person": false}),
    )
    .await;
    call(
        &w,
        "PUT",
        "/v1/models/settings",
        ADMIN_SA,
        &a,
        &json!({"two_person": false}),
    )
    .await;

    let all = audit_of(&mut w.d.owner, &a.key).await;
    let settings: Vec<&Value> = all
        .iter()
        .filter(|r| r["action"] == "tutela_setting:write")
        .collect();
    let states: Vec<&str> = settings
        .iter()
        .map(|r| r["details"]["two_person"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["on", "off_asked", "off"]);
    let proposal: Vec<&Value> = all
        .iter()
        .filter(|r| r["resource"]["type"] == "tutela_proposal")
        .collect();
    let steps: Vec<(&str, &str)> = proposal
        .iter()
        .map(|r| {
            (
                r["action"].as_str().unwrap(),
                r["outcome"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        steps,
        [
            ("tutela_proposal:propose", "success"),
            ("tutela_proposal:approve", "denied"),
            ("tutela_proposal:approve", "success"),
        ]
    );
    let published: Vec<&Value> = all
        .iter()
        .filter(|r| r["action"] == "tutela_model:publish" && r["outcome"] == "success")
        .collect();
    assert_eq!(published.len(), 2);
    let approved = published[1];
    assert_eq!(approved["details"]["version"], v2);
    assert_eq!(approved["details"]["author"], ADMIN);
    assert_eq!(approved["details"]["proposal"], pid.as_str());
    assert_eq!(
        approved["details"]["approvers"],
        json!([{"principal": ADMIN_SA}])
    );
    let two_person: Vec<&Value> = all
        .iter()
        .filter(|r| r["action"] == "tutela_model:publish" && r["reason"] == "two_person_required")
        .collect();
    assert_eq!(two_person.len(), 1);
    // The refused direct publish made no version: the approved one is next.
    assert_eq!(v2, version + 1);
    // The other tenant's log has none of this.
    assert!(audit_of(&mut w.d.owner, &w.b.key).await.is_empty());
    w.finish().await;
}

/// Explain and simulate record who asked about whom; a refused ask read
/// nothing and leaves nothing.
#[tokio::test]
async fn tm20_explain_and_simulate_record_who_asked_about_whom() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let a = Seed {
        key: w.a.key.clone(),
        tid: w.a.tid.clone(),
        org: w.a.org.clone(),
        project: w.a.project.clone(),
        assignment: w.a.assignment.clone(),
    };
    let q = ask(USER, "invoice:read", &a);
    let (status, v) = call(&w, "POST", "/v1/authz/explain", ADMIN, &a, &q).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let mut sim = q.clone();
    sim["candidate"] = json!({"source": with_reader("none")});
    let (status, v) = call(&w, "POST", "/v1/authz/simulate", ADMIN_SA, &a, &sim).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, _) = call(&w, "POST", "/v1/authz/explain", STRANGER, &a, &q).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let explained = audited(&mut w.d.owner, &a.key, "tutela_access:explain").await;
    assert_eq!(explained.len(), 1);
    assert_eq!(explained[0]["actor"]["id"], ADMIN);
    assert_eq!(explained[0]["resource"]["id"], USER);
    assert_eq!(explained[0]["details"]["subject"], USER);
    assert_eq!(explained[0]["details"]["action"], "invoice:read");
    assert_eq!(explained[0]["details"]["answer"], "allow");
    let simulated = audited(&mut w.d.owner, &a.key, "tutela_access:simulate").await;
    assert_eq!(simulated.len(), 1);
    assert_eq!(simulated[0]["actor"]["id"], ADMIN_SA);
    assert_eq!(simulated[0]["details"]["answer"], "deny");
    assert!(audit_of(&mut w.d.owner, &w.b.key).await.is_empty());
    w.finish().await;
}

/// A write check records a deny with the denied fields; an allowed write
/// with no move records nothing.
#[tokio::test]
async fn tm20_a_write_check_deny_is_recorded_with_its_fields() {
    let Some(mut w) = world().await else { return };
    let body = |subject: &str, s: &Seed| {
        json!({
            "subject": {"type": "user", "id": subject},
            "resource": {"type": "invoice", "id": "inv-1", "properties": {
                "path": common::path(s), "attrs": {}
            }},
            "new_attrs": {"status": "done", "amount": 5},
        })
    };
    // The reader of A may not write.
    let t = w.issuer.token(USER, &w.a.tid, 0);
    let res = w.post("/v1/authz/write-check", &t, &body(USER, &w.a)).await;
    assert_eq!(res.status(), StatusCode::OK);
    // The approver of B may write `status` and read `amount` only: still a
    // deny, of one field.
    let tb = w.issuer.token(common::B_USER, &w.b.tid, 0);
    let res = w
        .post("/v1/authz/write-check", &tb, &body(common::B_USER, &w.b))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let a = audit_of(&mut w.d.owner, &w.a.key).await;
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0]["action"], "invoice:write");
    assert_eq!(a[0]["resource"], json!({"type": "invoice", "id": "inv-1"}));
    assert_eq!(a[0]["outcome"], "denied");
    assert_eq!(
        a[0]["details"]["denied_fields"],
        json!(["amount", "status"])
    );
    assert_eq!(a[0]["details"]["subject"], USER);
    let b = audit_of(&mut w.d.owner, &w.b.key).await;
    assert_eq!(b.len(), 1, "{b:?}");
    assert_eq!(b[0]["details"]["denied_fields"], json!(["amount"]));
    w.finish().await;
}

/// The service's own role may add records and read them, never change or
/// remove one; readiness refuses a role that could, or a schema whose
/// append-only triggers are off.
#[tokio::test]
async fn tm20_the_service_role_cannot_change_or_delete_a_record() {
    let Some(mut w) = world().await else { return };
    let t = w.issuer.token(USER, &w.a.tid, 0);
    let mut q = json!({
        "subject": {"type": "user", "id": USER},
        "resource": {"type": "invoice", "id": "inv-1", "properties": {"path": common::path(&w.a), "attrs": {}}},
        "new_attrs": {"status": "done"},
    });
    w.post("/v1/authz/write-check", &t, &q).await;
    q["new_attrs"] = json!({"amount": 1});
    w.post("/v1/authz/write-check", &t, &q).await;
    assert_eq!(audit_of(&mut w.d.owner, &w.a.key).await.len(), 2);

    let mut service = common::connect(&w.d.service_url).await;
    for sql in [
        "UPDATE tutela.audit_record SET body = body WHERE seq = 1",
        "DELETE FROM tutela.audit_record WHERE seq = 2",
        "TRUNCATE tutela.audit_record",
        "DELETE FROM tutela.audit_head",
        "UPDATE tutela.audit_head SET seq = 0",
    ] {
        let tx = service.transaction().await.unwrap();
        tutela_store::enter(&tx, &w.a.key).await.unwrap();
        let e = tx.batch_execute(sql).await.unwrap_err();
        let code = e.code().map(|c| c.code().to_owned());
        assert!(
            matches!(code.as_deref(), Some("42501" | "23000")),
            "{sql}: {e}"
        );
    }
    let records = audit_of(&mut w.d.owner, &w.a.key).await;
    assert_eq!(records.len(), 2);
    assert!(tutela_store::check_isolation(&service).await.is_ok());

    // A grant that lets the role change the log fails readiness.
    w.d.owner
        .batch_execute(&format!(
            "GRANT UPDATE ON tutela.audit_record TO {}",
            common::SERVICE
        ))
        .await
        .unwrap();
    let e = tutela_store::check_isolation(&service).await.unwrap_err();
    assert_eq!(e.detail(), Some("the role may change the audit log"));
    // grant_service puts it right again.
    tutela_store::grant_service(&mut w.d.owner, common::SERVICE)
        .await
        .unwrap();
    assert!(tutela_store::check_isolation(&service).await.is_ok());
    // A trigger switched off by the owner fails readiness too.
    w.d.owner
        .batch_execute("ALTER TABLE tutela.audit_record DISABLE TRIGGER audit_record_kept")
        .await
        .unwrap();
    let e = tutela_store::check_isolation(&service).await.unwrap_err();
    assert_eq!(
        e.detail(),
        Some("the audit log's append-only triggers are not enabled")
    );
    drop(service);
    w.d.owner
        .batch_execute("ALTER TABLE tutela.audit_record ENABLE TRIGGER audit_record_kept")
        .await
        .unwrap();
    let _ = SA;
    w.finish().await;
}

/// The expiry sweep removes an assignment and records it, by `tutelad`
/// itself, in the same transaction as the revision it bumps.
#[tokio::test]
async fn tm20_the_expiry_sweep_records_what_it_removed() {
    let Some(mut w) = world().await else { return };
    let tx = w.d.owner.transaction().await.unwrap();
    let (rule, _) = tutela_store::assign_until(
        &tx,
        &w.a.key,
        &Subject::Principal(common::STRANGER.parse().unwrap()),
        &RoleKey::parse("reader").unwrap(),
        &w.a.project,
        None,
        std::time::SystemTime::now() + Duration::from_millis(200),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let st = common::state(&w.config, &w.issuer);
    let sweep = tutelad::expiry::sweep(&st.db, &st.metrics).await.unwrap();
    assert_eq!(sweep.expired, 1);
    let recs = audited(&mut w.d.owner, &w.a.key, "tutela_assignment:expire").await;
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0]["actor"]["id"], tutelad::audit::SYSTEM);
    assert_eq!(recs[0]["resource"]["id"], rule.as_str());
    assert_eq!(recs[0]["details"]["subject"], common::STRANGER);
    assert_eq!(recs[0]["details"]["role"], "reader");
    let tx = w.d.owner.transaction().await.unwrap();
    let rev = tutela_store::rev(&tx, &w.a.key).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(recs[0]["decision"]["rev"], rev);
    w.finish().await;
}

/// A token that names `tutelad` itself is refused on the API: no caller
/// may act as the actor of the service's own records.
#[tokio::test]
async fn no_token_may_speak_as_the_service_itself() {
    let Some(w) = world().await else { return };
    let t = w.issuer.token(tutelad::audit::SYSTEM, &w.a.tid, 0);
    let res = common::http()
        .get(w.s.api_url("/v1/whoami"))
        .bearer_auth(t)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    w.finish().await;
}
