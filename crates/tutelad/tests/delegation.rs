//! Delegated agent tokens (RFC 8693 with `act`, `typ: agent+jwt`) from
//! token exchange, through the real service, the real auth layer and a real
//! Postgres (ADR-0033, CONTRACTS.md 4.5, 4.8, THREAT-MODEL.md TM-02, TM-03).
#![cfg(test)]

mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_contracts::principal::{Principal, WorkloadId};
use tutelad::api::AppState;
use tutelad::config::TrustFile;

use common::{
    AUD, ISS, Issuer, MANIFEST, OWN_ISS, Running, Seed, TestDb, ask, config, http, migrated, now,
    publish, seed_of, start, state,
};

/// The realm that logs people in for tenant A.
const KC: &str = "https://kc.example.test/realms/acme";
/// attache's workload issuer for tenant A: JWT-SVIDs.
const EMBASSY: &str = "https://embassy.prod.attache.example.test";
const TRUST_DOMAIN: &str = "prod.attache.example.test";

fn agent(n: u32) -> Principal {
    format!("agent:agt_0193a1b2-c3d4-7b33-9c44-{n:012x}")
        .parse()
        .unwrap()
}

struct D {
    d: TestDb,
    st: AppState,
    s: Running,
    issuer: Issuer,
    /// Tenant A, under the own issuer.
    a: Seed,
    /// Tenant B, under the own issuer.
    b: Seed,
}

async fn d() -> Option<D> {
    let mut d = migrated().await?;
    publish(&mut d.owner, MANIFEST, None).await;
    let a = seed_of(&mut d.owner, OWN_ISS, common::USER, "reader").await;
    let b = seed_of(&mut d.owner, OWN_ISS, common::B_USER, "reader").await;
    let file = format!(
        "[[issuer]]\niss = \"{ISS}\"\njwks_uri = \"{ISS}/jwks\"\nalgs = [\"ES256\"]\n\
         tenants = [\"{a}\"]\n\
         [[issuer]]\niss = \"{KC}\"\njwks_uri = \"{KC}/certs\"\nalgs = [\"ES256\"]\n\
         tenants = [\"{a}\"]\nexternal = true\nallow_typ_jwt = true\n\
         [[issuer]]\niss = \"{EMBASSY}\"\njwks_uri = \"{EMBASSY}/keys\"\nalgs = [\"ES256\"]\n\
         tenants = [\"{a}\"]\nexternal = true\nallow_typ_jwt = true\nworkloads = true\n\
         [[audience]]\nname = \"symphony\"\ndelegation_aware = true\n\
         [[audience]]\nname = \"crm-api\"\n",
        a = a.tid,
    );
    let issuer = Issuer::new();
    let cfg = config(&d.service_url, TrustFile::parse(&file, false).unwrap());
    let st = state(&cfg, &issuer);
    let s = start(&cfg, st.clone()).await;
    let mut w = D {
        d,
        st,
        s,
        issuer,
        a,
        b,
    };
    for n in 1..=6 {
        let key = w.a.key.clone();
        w.store(async |tx| {
            tutela_store::register_agent(tx, &key, &agent(n), None)
                .await
                .unwrap()
        })
        .await;
    }
    Some(w)
}

fn claims(token: &str) -> (Value, Value) {
    let mut parts = token.split('.');
    let h = parts.next().unwrap();
    let p = parts.next().unwrap();
    (
        serde_json::from_slice(&B64.decode(h).unwrap()).unwrap(),
        serde_json::from_slice(&B64.decode(p).unwrap()).unwrap(),
    )
}

fn sub(token: &str) -> String {
    claims(token).1["sub"].as_str().unwrap().to_owned()
}

/// The chain of a delegated token, the current actor first.
fn chain(token: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut next = claims(token).1.get("act").cloned();
    while let Some(a) = next {
        out.push(a["sub"].as_str().unwrap().to_owned());
        next = a.get("act").cloned();
    }
    out
}

const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

impl D {
    async fn store<T>(
        &mut self,
        f: impl AsyncFnOnce(&tutela_store::tokio_postgres::Transaction<'_>) -> T,
    ) -> T {
        let tx = self.d.owner.transaction().await.unwrap();
        let out = f(&tx).await;
        tx.commit().await.unwrap();
        out
    }

    async fn form(&self, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
        let r = http()
            .post(self.s.api_url("/oauth2/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(pairs).unwrap())
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap())
    }

    /// A person's Tutela token: a realm token of `who`, exchanged.
    async fn person(&self, who: &str) -> String {
        let now = now();
        let kc = self.issuer.sign_typed(
            "JWT",
            &json!({
                "iss": KC, "sub": who, "aud": AUD, "azp": "chat-web",
                "exp": now + 300, "iat": now,
                "jti": uuid::Uuid::now_v7().to_string(), "acr": "1",
            }),
        );
        let (status, body) = self
            .form(&[
                ("grant_type", GRANT),
                ("subject_token", &kc),
                ("subject_token_type", ACCESS),
                ("audience", AUD),
            ])
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    /// An agent's own token, from the Tutela-format issuer of the trust file
    /// (attache, here), for tenant `tid`.
    fn agent_token(&self, a: &Principal, tid: &str) -> String {
        self.agent_token_at(a, tid, 0)
    }

    /// [`D::agent_token`] at `epoch`.
    fn agent_token_at(&self, a: &Principal, tid: &str, epoch: u64) -> String {
        let now = now();
        self.issuer.sign_claims(&json!({
            "iss": ISS, "sub": a.to_string(), "aud": AUD, "azp": "attache-sidecar",
            "exp": now + 300, "iat": now, "nbf": now,
            "jti": uuid::Uuid::now_v7().to_string(),
            "tid": tid, "epoch": epoch, "rev": 0,
        }))
    }

    /// A JWT-SVID of attache's embassy for the workload `w`.
    fn svid(&self, w: &str) -> String {
        let now = now();
        self.issuer.sign_typed(
            "JWT",
            &json!({"iss": EMBASSY, "sub": w, "aud": AUD, "exp": now + 300, "iat": now,
                    "jti": uuid::Uuid::now_v7().to_string()}),
        )
    }

    async fn delegate_with(
        &self,
        subject: &str,
        actor: Option<&str>,
        audience: &str,
        extra: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut pairs = vec![
            ("grant_type", GRANT),
            ("subject_token", subject),
            ("subject_token_type", ACCESS),
            ("audience", audience),
        ];
        if let Some(actor) = actor {
            pairs.extend([("actor_token", actor), ("actor_token_type", JWT)]);
        }
        pairs.extend_from_slice(extra);
        self.form(&pairs).await
    }

    /// A delegated token of `subject` acted for by `actor`, for `audience`.
    async fn delegate(&self, subject: &str, actor: &str, audience: &str) -> String {
        let (status, body) = self
            .delegate_with(
                subject,
                Some(actor),
                audience,
                &[("run_id", "run-1"), ("cap", r#"{"snapshot":"opaque"}"#)],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn refused(&self, subject: &str, actor: Option<&str>, audience: &str) -> String {
        let (status, body) = self
            .delegate_with(subject, actor, audience, &[("run_id", "run-1")])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        body["error"].as_str().unwrap().to_owned()
    }

    async fn get(&self, path: &str, token: &str) -> StatusCode {
        http()
            .get(self.s.api_url(path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
    }

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        let r = http()
            .post(self.s.api_url(path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn assign(&mut self, who: &str, role: &str) -> u64 {
        let (a, project) = (self.a.key.clone(), self.a.project.clone());
        let who: Principal = who.parse().unwrap();
        self.store(async |tx| {
            tutela_store::assign(
                tx,
                &a,
                &tutela_pdp::Subject::Principal(who),
                &tutela_pdp::model::RoleKey::parse(role).unwrap(),
                &project,
                None,
            )
            .await
            .unwrap()
            .1
        })
        .await
    }

    /// May the delegated token's person, acted for by its chain, read the
    /// invoice, at revision `rev` or later?
    async fn may_read(&self, token: &str, rev: u64) -> bool {
        let c = claims(token).1;
        let mut q = ask(c["sub"].as_str().unwrap(), "invoice:read", &self.a);
        // The subject carries the token's whole chain, as its `act` claim.
        q["subject"]["properties"] = json!({"act": c["act"]});
        q["context"] = json!({"at_least_revision": rev});
        let (status, body) = self.post("/access/v1/evaluation", token, &q).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["decision"].as_bool().unwrap()
    }

    async fn until_refused(&self, token: &str) {
        let start = std::time::Instant::now();
        while self.get("/v1/whoami", token).await != StatusCode::UNAUTHORIZED {
            assert!(
                start.elapsed() < Duration::from_millis(2500),
                "the revoked token still works"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn finish(self) {
        self.s.stop().await.unwrap();
        self.d.finish().await;
    }
}

/// TM-02: a delegated token is issued only for an audience registered
/// `delegation_aware`, never as an admin token; it carries the person, the
/// agent, the opaque `cap` and the run, and lives 60 to 120 s.
#[tokio::test]
async fn tm02_a_delegated_token_is_only_for_a_delegation_aware_audience() {
    let Some(w) = d().await else { return };
    let person = w.person("kc-alice").await;
    let actor = w.agent_token(&agent(1), &w.a.tid);
    assert_eq!(
        w.refused(&person, Some(&actor), "crm-api").await,
        "invalid_target"
    );
    assert_eq!(
        w.refused(&person, Some(&actor), "tutela-admin").await,
        "invalid_target"
    );
    let t = w.delegate(&person, &actor, "symphony").await;
    let (h, c) = claims(&t);
    assert_eq!(h["typ"], "agent+jwt");
    assert_eq!(c["iss"], OWN_ISS);
    assert_eq!(c["sub"], sub(&person));
    assert_eq!(c["aud"], "symphony");
    assert_eq!(chain(&t), vec![agent(1).to_string()]);
    assert_eq!(c["cap"], json!({"snapshot": "opaque"}));
    assert_eq!(c["run_id"], "run-1");
    assert_eq!(c["tid"], w.a.tid);
    assert_eq!(c["epoch"], 0);
    let life = c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap();
    assert!((60..=120).contains(&life), "{life}");
    // The service's own audience takes delegated tokens: the check API
    // evaluates the chain.
    let own = w.delegate(&person, &actor, AUD).await;
    assert_eq!(w.get("/v1/whoami", &own).await, StatusCode::OK);
    // A run is required, and `cap` is at most 4096 bytes of a JSON object.
    let (status, body) = w
        .delegate_with(&person, Some(&actor), "symphony", &[])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
    let big = format!(r#"{{"x":"{}"}}"#, "a".repeat(5000));
    for cap in [big.as_str(), "[1,2]", "not json"] {
        let (status, body) = w
            .delegate_with(
                &person,
                Some(&actor),
                "symphony",
                &[("run_id", "r"), ("cap", cap)],
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
    }
    w.finish().await;
}

/// TM-03, the overlap: a delegated token never decides more than the person
/// AND the agent each hold.
#[tokio::test]
async fn tm03_a_delegated_token_never_grants_more_than_person_and_agent() {
    let Some(mut w) = d().await else { return };
    let person = w.person("kc-alice").await;
    let me = sub(&person);
    let t = w
        .delegate(&person, &w.agent_token(&agent(1), &w.a.tid), AUD)
        .await;
    // Nobody holds anything.
    assert!(!w.may_read(&t, 0).await);
    // The person reads; the agent does not: no.
    let rev = w.assign(&me, "reader").await;
    assert!(!w.may_read(&t, rev).await);
    // The agent reads too: yes.
    let rev = w.assign(&agent(1).to_string(), "reader").await;
    assert!(w.may_read(&t, rev).await);
    // The agent alone, with a person who holds nothing: no.
    let other = w.person("kc-bob").await;
    let t2 = w
        .delegate(&other, &w.agent_token(&agent(1), &w.a.tid), AUD)
        .await;
    assert!(!w.may_read(&t2, rev).await);
    // The token cannot ask about the person alone, or drop its agent.
    let (status, _) = w
        .post("/access/v1/evaluation", &t, &ask(&me, "invoice:read", &w.a))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    w.finish().await;
}

/// TM-02: the chain holds at most four actors; a fifth fails. Each link is
/// an agent registered in the tenant.
#[tokio::test]
async fn tm02_a_chain_past_four_actors_fails() {
    let Some(w) = d().await else { return };
    let mut t = w.person("kc-alice").await;
    for n in 1..=4 {
        t = w
            .delegate(&t, &w.agent_token(&agent(n), &w.a.tid), AUD)
            .await;
        assert_eq!(chain(&t).len(), n as usize);
        assert_eq!(chain(&t)[0], agent(n).to_string(), "the newest actor first");
        assert_eq!(w.get("/v1/whoami", &t).await, StatusCode::OK);
    }
    assert_eq!(
        w.refused(&t, Some(&w.agent_token(&agent(5), &w.a.tid)), AUD)
            .await,
        "invalid_grant"
    );
    w.finish().await;
}

/// TM-02: disabling the agent, or the person, stops their delegated tokens
/// on the API and at the next exchange. An agent that is not registered in
/// the person's tenant never acts.
#[tokio::test]
async fn tm02_a_disabled_agent_or_person_revokes_the_delegated_token() {
    let Some(mut w) = d().await else { return };
    let person = w.person("kc-alice").await;
    let actor = w.agent_token(&agent(1), &w.a.tid);
    let t = w.delegate(&person, &actor, AUD).await;
    assert_eq!(w.get("/v1/whoami", &t).await, StatusCode::OK);
    let key = w.a.key.clone();
    w.store(async |tx| {
        tutela_store::set_disabled(tx, &key, &agent(1), true)
            .await
            .unwrap()
    })
    .await;
    w.until_refused(&t).await;
    assert_eq!(w.refused(&person, Some(&actor), AUD).await, "invalid_grant");
    // Its token for another hop is refused as well.
    assert_eq!(w.refused(&t, None, "symphony").await, "invalid_grant");
    w.store(async |tx| {
        tutela_store::set_disabled(tx, &key, &agent(1), false)
            .await
            .unwrap()
    })
    .await;
    // Enabled again, its old token stays dead: the epoch was raised.
    assert_eq!(w.refused(&person, Some(&actor), AUD).await, "invalid_grant");
    let t2 = w
        .delegate(&person, &w.agent_token_at(&agent(1), &w.a.tid, 1), AUD)
        .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(w.get("/v1/whoami", &t2).await, StatusCode::OK);
    // The person disabled: every delegated token of theirs stops.
    let me: Principal = sub(&person).parse().unwrap();
    w.store(async |tx| {
        tutela_store::set_disabled(tx, &key, &me, true)
            .await
            .unwrap()
    })
    .await;
    w.until_refused(&t2).await;
    assert_eq!(
        w.refused(&person, Some(&w.agent_token(&agent(2), &w.a.tid)), AUD)
            .await,
        "invalid_grant"
    );

    // Not registered, registered in tenant B only, or a token for tenant B.
    let p2 = w.person("kc-carol").await;
    let unknown: Principal = "agent:agt_0193a1b2-c3d4-7b33-9c44-0000000000ff"
        .parse()
        .unwrap();
    assert_eq!(
        w.refused(&p2, Some(&w.agent_token(&unknown, &w.a.tid)), AUD)
            .await,
        "invalid_grant"
    );
    let b = w.b.key.clone();
    let b_agent: Principal = "agent:agt_0193a1b2-c3d4-7b33-9c44-0000000000bb"
        .parse()
        .unwrap();
    w.store(async |tx| {
        tutela_store::register_agent(tx, &b, &b_agent, None)
            .await
            .unwrap()
    })
    .await;
    assert_eq!(
        w.refused(&p2, Some(&w.agent_token(&b_agent, &w.a.tid)), AUD)
            .await,
        "invalid_grant"
    );
    let for_b = w.st.keys.sign_jwt(
        "at+jwt",
        &json!({
            "iss": OWN_ISS, "sub": b_agent.to_string(), "aud": AUD, "azp": "attache-sidecar",
            "exp": now() + 300, "iat": now(), "nbf": now(),
            "jti": uuid::Uuid::now_v7().to_string(), "tid": w.b.tid, "epoch": 0, "rev": 0,
        }),
    );
    assert_eq!(
        w.refused(&p2, Some(&for_b.unwrap()), AUD).await,
        "invalid_grant"
    );
    // An agent registered in both tenants, with its token for tenant B, does
    // not act for a person of tenant A: the token's tenant decides.
    let both = agent(3);
    let b2 = w.b.key.clone();
    w.store(async |tx| {
        tutela_store::register_agent(tx, &b2, &both, None)
            .await
            .unwrap()
    })
    .await;
    let both_for_b =
        w.st.keys
            .sign_jwt(
                "at+jwt",
                &json!({
                    "iss": OWN_ISS, "sub": both.to_string(), "aud": AUD, "azp": "attache-sidecar",
                    "exp": now() + 300, "iat": now(), "nbf": now(),
                    "jti": uuid::Uuid::now_v7().to_string(), "tid": w.b.tid, "epoch": 0, "rev": 0,
                }),
            )
            .unwrap();
    assert_eq!(
        w.refused(&p2, Some(&both_for_b), AUD).await,
        "invalid_grant"
    );
    // The same agent's token for tenant A acts.
    w.delegate(&p2, &w.agent_token(&both, &w.a.tid), AUD).await;
    // A person never acts as an agent.
    assert_eq!(w.refused(&p2, Some(&person), AUD).await, "invalid_grant");
    w.finish().await;
}

/// A delegated principal never holds an admin key: it cannot read or publish
/// a model, nor approve a proposal, even when the person may.
#[tokio::test]
async fn a_delegated_principal_cannot_call_the_model_routes_or_approve() {
    let Some(mut w) = d().await else { return };
    let person = w.person("kc-alice").await;
    let me = sub(&person);
    let (a, org) = (w.a.key.clone(), w.a.org.clone());
    let who: Principal = me.parse().unwrap();
    w.store(async |tx| {
        tutela_store::assign(
            tx,
            &a,
            &tutela_pdp::Subject::Principal(who),
            &tutela_pdp::model::RoleKey::parse("owner").unwrap(),
            &org,
            None,
        )
        .await
        .unwrap()
    })
    .await;
    let t = w
        .delegate(&person, &w.agent_token(&agent(1), &w.a.tid), AUD)
        .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(w.get("/v1/models", &t).await, StatusCode::FORBIDDEN);
    let (status, _) = w
        .post("/v1/models/proposals/x/approve", &t, &json!({}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = w
        .post("/v1/authz/explain", &t, &ask(&me, "invoice:read", &w.a))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Nor an admin token through a delegated token.
    assert_eq!(w.refused(&t, None, "tutela-admin").await, "invalid_target");
    w.finish().await;
}

/// A workload agent acts through a JWT-SVID of attache's embassy, on
/// attache's path `/ns/<namespace>/svc/<service>`. An SVID is never a person,
/// and a workload nobody registered never acts.
#[tokio::test]
async fn a_workload_agent_acts_through_its_spiffe_id() {
    let Some(mut w) = d().await else { return };
    let spiffe = format!("spiffe://{TRUST_DOMAIN}/ns/shop/svc/orders");
    let workload = WorkloadId::parse(&spiffe).unwrap();
    let key = w.a.key.clone();
    let bot: Principal = "agent:agt_0193a1b2-c3d4-7b33-9c44-0000000000a1"
        .parse()
        .unwrap();
    let (b2, wl) = (bot.clone(), workload.clone());
    w.store(async |tx| {
        tutela_store::register_agent(tx, &key, &b2, Some(&wl))
            .await
            .unwrap()
    })
    .await;
    let person = w.person("kc-alice").await;
    let t = w.delegate(&person, &w.svid(&spiffe), "symphony").await;
    assert_eq!(chain(&t), vec![bot.to_string()]);
    // A workload nobody registered, and a path that is not attache's.
    let other = format!("spiffe://{TRUST_DOMAIN}/ns/shop/svc/billing");
    assert_eq!(
        w.refused(&person, Some(&w.svid(&other)), "symphony").await,
        "invalid_grant"
    );
    let sa_path = format!("spiffe://{TRUST_DOMAIN}/sa/orders");
    assert_eq!(
        w.refused(&person, Some(&w.svid(&sa_path)), "symphony")
            .await,
        "invalid_grant"
    );
    // An SVID is never the person.
    assert_eq!(
        w.refused(
            &w.svid(&spiffe),
            Some(&w.agent_token(&agent(1), &w.a.tid)),
            "symphony"
        )
        .await,
        "invalid_grant"
    );
    w.finish().await;
}

/// The next hop: a service exchanges the delegated token it received for one
/// of another delegation-aware audience. The chain, the run and `cap` stay,
/// and the new token never outlives the old one. A service that is not
/// delegation-aware gets nothing.
#[tokio::test]
async fn a_delegated_token_is_exchanged_per_hop_and_never_longer() {
    let Some(w) = d().await else { return };
    let person = w.person("kc-alice").await;
    let t = w
        .delegate(&person, &w.agent_token(&agent(1), &w.a.tid), "symphony")
        .await;
    let (status, body) = w
        .delegate_with(&t, None, AUD, &[("node_id", "step-2")])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let next = body["access_token"].as_str().unwrap();
    let (c0, c1) = (claims(&t).1, claims(next).1);
    assert_eq!(claims(next).0["typ"], "agent+jwt");
    assert_eq!(c1["aud"], AUD);
    assert_eq!(c1["act"], c0["act"]);
    assert_eq!(c1["cap"], c0["cap"]);
    assert_eq!(c1["run_id"], c0["run_id"]);
    assert_eq!(c1["node_id"], "step-2");
    assert!(c1["exp"].as_u64() <= c0["exp"].as_u64());
    assert_eq!(w.refused(&t, None, "crm-api").await, "invalid_target");
    w.finish().await;
}

/// Every delegated token issued has its audit.v1 record (ADR-0034): the
/// person, the whole `act` chain, the audience, `run_id`, `node_id` and the
/// `jti`; a refusal records its reason and the person.
#[tokio::test]
async fn tm20_a_delegated_token_is_recorded_with_its_whole_chain() {
    let Some(mut w) = d().await else { return };
    let person = w.person("kc-alice").await;
    let one = w
        .delegate(&person, &w.agent_token(&agent(1), &w.a.tid), AUD)
        .await;
    let (status, body) = w
        .delegate_with(
            &one,
            Some(&w.agent_token(&agent(2), &w.a.tid)),
            "symphony",
            &[("node_id", "step-2")],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let two = body["access_token"].as_str().unwrap().to_owned();
    // An agent of no tenant here: refused, with its reason.
    assert_eq!(
        w.refused(&person, Some(&w.agent_token(&agent(9), &w.a.tid)), AUD)
            .await,
        "invalid_grant"
    );
    let key = w.a.key.clone();
    let recs = common::audited(&mut w.d.owner, &key, "tutela_token:issue").await;
    let delegated: Vec<&Value> = recs
        .iter()
        .filter(|r| r["details"]["kind"] == "delegated")
        .collect();
    assert_eq!(delegated.len(), 3, "{recs:?}");
    let (c2, me) = (claims(&two).1, sub(&person));
    let last = delegated[1];
    assert_eq!(last["outcome"], "success");
    assert_eq!(last["actor"]["kind"], "agent");
    assert_eq!(last["actor"]["id"], agent(2).to_string());
    assert_eq!(last["actor"]["on_behalf_of"], me.as_str());
    assert_eq!(last["details"]["principal"], me.as_str());
    assert_eq!(
        last["details"]["act"],
        json!([agent(2).to_string(), agent(1).to_string()])
    );
    assert_eq!(last["details"]["aud"], "symphony");
    assert_eq!(last["details"]["run_id"], "run-1");
    assert_eq!(last["details"]["node_id"], "step-2");
    assert_eq!(last["details"]["jti"], c2["jti"]);
    let refused = delegated[2];
    assert_eq!(refused["outcome"], "denied");
    assert_eq!(refused["reason"], "actor_unknown");
    assert_eq!(refused["details"]["principal"], me.as_str());
    let text = serde_json::to_string(&recs).unwrap();
    assert!(!text.contains(&one) && !text.contains(&two) && !text.contains("opaque"));
    w.finish().await;
}
