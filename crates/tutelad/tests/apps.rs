//! Apps and client authentication at the token endpoint (ADR-0044,
//! CONTRACTS.md 4.9 and 7.13.8), through the real service, the real auth
//! layer and a real Postgres. People sign in at a Keycloak-shaped local
//! signer and exchange its tokens, as the Console will.
#![cfg(test)]

mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tonic::Code;
use tutelad::admin::grpc::pb;
use tutelad::admin::grpc::pb::admin_client::AdminClient;
use tutelad::config::TrustFile;

use common::{
    AUD, Issuer, MANIFEST, OWN_ISS, PEPPER, Running, TestDb, config, http, migrated, now, publish,
    start, state,
};

const KC: &str = "https://kc.example.test/realms/acme";
const KC_B: &str = "https://kc.example.test/realms/beta";
const GRANT_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";

struct T {
    d: TestDb,
    s: Running,
    issuer: Issuer,
    a: tutela_contracts::tenant::TenantKey,
}

async fn t() -> Option<T> {
    let mut d = migrated().await?;
    publish(&mut d.owner, MANIFEST, None).await;
    let own: tutela_contracts::tenant::Issuer = OWN_ISS.parse().unwrap();
    let make = |realm: &str| tutelad::lifecycle::NewTenant {
        name: None,
        org_name: None,
        admins: Vec::new(),
        upstream_admins: vec![(realm.parse().unwrap(), "owner".to_owned())],
    };
    let a = tutelad::lifecycle::create_tenant(&mut d.owner, &own, &make(KC))
        .await
        .unwrap()
        .key;
    let b = tutelad::lifecycle::create_tenant(&mut d.owner, &own, &make(KC_B))
        .await
        .unwrap()
        .key;
    let ext = |iss: &str, tid: &str| {
        format!(
            "[[issuer]]\niss = \"{iss}\"\njwks_uri = \"{iss}/certs\"\n\
             algs = [\"ES256\"]\ntenants = [\"{tid}\"]\nexternal = true\nallow_typ_jwt = true\n"
        )
    };
    let file = format!(
        "{}{}[[audience]]\nname = \"crm-api\"\n",
        ext(KC, &a.tid.to_string()),
        ext(KC_B, &b.tid.to_string())
    );
    let issuer = Issuer::new();
    let cfg = config(&d.service_url, TrustFile::parse(&file, false).unwrap());
    let s = start(&cfg, state(&cfg, &issuer)).await;
    Some(T { d, s, issuer, a })
}

impl T {
    /// A Keycloak token of `realm` for `sub`, with `acr`.
    fn kc(&self, realm: &str, sub: &str, acr: &str) -> String {
        let now = now();
        self.issuer.sign_typed(
            "JWT",
            &json!({
                "exp": now + 300, "iat": now, "jti": uuid::Uuid::now_v7().to_string(),
                "iss": realm, "aud": AUD, "sub": sub, "azp": "crm-web", "acr": acr,
            }),
        )
    }

    async fn token(
        &self,
        pairs: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> (StatusCode, Value, reqwest::header::HeaderMap) {
        let mut r = http()
            .post(self.s.api_url("/oauth2/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(pairs).unwrap());
        if let Some((id, secret)) = basic {
            r = r.header(
                "authorization",
                format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
            );
        }
        let r = r.send().await.unwrap();
        let status = r.status();
        let headers = r.headers().clone();
        (status, r.json().await.unwrap(), headers)
    }

    /// An access token or an admin token of the person `sub` of `realm`.
    async fn person(&self, realm: &str, sub: &str, audience: &str) -> String {
        let acr = if audience == "tutela-admin" {
            common::STEP_UP
        } else {
            "1"
        };
        let subject = self.kc(realm, sub, acr);
        let (status, v, _) = self
            .token(
                &[
                    ("grant_type", GRANT_EXCHANGE),
                    ("subject_token", &subject),
                    ("subject_token_type", ACCESS),
                    ("audience", audience),
                ],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{v}");
        v["access_token"].as_str().unwrap().to_owned()
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut r = http()
            .request(method, self.s.api_url(path))
            .bearer_auth(token);
        if let Some(b) = body {
            r = r.json(b);
        }
        let res = r.send().await.unwrap();
        let status = res.status();
        let text = res.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// A new app of the tenant `admin` owns: its client id and secret.
    async fn app(&self, admin: &str, name: &str) -> (String, String, String) {
        let (status, v) = self
            .call(
                reqwest::Method::POST,
                "/v1/admin/apps",
                admin,
                Some(&json!({"name": name})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{v}");
        (
            v["app"]["client_id"].as_str().unwrap().to_owned(),
            v["client_secret"].as_str().unwrap().to_owned(),
            v["app"]["principal"].as_str().unwrap().to_owned(),
        )
    }

    async fn client_token(&self, id: &str, secret: &str) -> (StatusCode, Value) {
        let (status, v, _) = self
            .token(&[("grant_type", "client_credentials")], Some((id, secret)))
            .await;
        (status, v)
    }

    async fn whoami(&self, token: &str) -> (StatusCode, Value) {
        self.call(reqwest::Method::GET, "/v1/whoami", token, None)
            .await
    }

    async fn finish(self) {
        self.s.stop().await.unwrap();
        self.d.finish().await;
    }
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

async fn grpc(t: &T) -> AdminClient<tonic::transport::Channel> {
    let channel = tonic::transport::Endpoint::from_shared(t.s.api_url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    AdminClient::new(channel)
}

fn with_token<M>(token: &str, msg: M) -> tonic::Request<M> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

#[tokio::test]
async fn tm09_an_app_is_made_by_the_tenants_owner_and_its_secret_is_shown_once_and_stored_hashed() {
    let Some(mut t) = t().await else { return };
    let admin = t.person(KC, "owner", "tutela-admin").await;
    let (id, secret, sa) = t.app(&admin, "crm backend").await;
    assert!(id.starts_with("app_"), "{id}");
    assert!(sa.starts_with("sa:sa_"), "{sa}");
    assert!(
        tutela_contracts::apikey::ApiKey::parse(&secret).is_ok(),
        "an API key of CONTRACTS.md 5"
    );
    assert!(secret.starts_with("tut_sk_"));
    // The list never shows a secret.
    let (status, v) = t
        .call(reqwest::Method::GET, "/v1/admin/apps", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["apps"][0]["client_id"], id.as_str());
    assert!(!v.to_string().contains(&secret[15..]), "{v}");
    // Stored as SHA-256(pepper || key) only: never the secret, in no table.
    let su = t.d.superuser().await;
    let row = su
        .query_one(
            "SELECT hash, prefix, pepper_version FROM tutela.app_secret",
            &[],
        )
        .await
        .unwrap();
    let hash: String = row.get(0);
    let pepper = hex(PEPPER);
    assert_eq!(hash, tutelad::apps::hash(&pepper, &secret));
    assert_eq!(row.get::<_, String>(1), secret[7..15]);
    assert_eq!(row.get::<_, i32>(2), 1);
    let dump: String = su
        .query_one(
            "SELECT string_agg(t::text, ' ') FROM (SELECT * FROM tutela.app_secret) t",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!dump.contains(&secret[16..]), "the secret part is stored");
    // Nor in the audit log.
    let records = common::audit_of(&mut t.d.owner, &t.a).await;
    assert!(
        !serde_json::to_string(&records)
            .unwrap()
            .contains(&secret[16..])
    );
    let made = records
        .iter()
        .find(|r| r["action"] == "tutela_app:create")
        .unwrap();
    assert_eq!(made["details"]["prefix"], &secret[..15]);

    // Nobody less than the tenant's owner may make or see an app.
    let nobody = t.person(KC, "nobody", "tutela-admin").await;
    let plain = t.person(KC, "owner", AUD).await;
    let (_, sa_token) = t.client_token(&id, &secret).await;
    let service = sa_token["access_token"].as_str().unwrap().to_owned();
    let mut g = grpc(&t).await;
    for (what, token) in [
        ("a person with no key", &nobody),
        ("the owner's plain token", &plain),
        ("an app with no role", &service),
    ] {
        let (status, v) = t
            .call(
                reqwest::Method::POST,
                "/v1/admin/apps",
                token,
                Some(&json!({"name": "x"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {v}");
        let (status, _) = t
            .call(reqwest::Method::GET, "/v1/admin/apps", token, None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}");
        let (status, _) = t
            .call(
                reqwest::Method::POST,
                &format!("/v1/admin/apps/{id}/rotate"),
                token,
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}");
        let (status, _) = t
            .call(
                reqwest::Method::POST,
                &format!("/v1/admin/apps/{id}/disable"),
                token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}");
        let e = g
            .create_app(with_token(token, pb::CreateAppRequest { name: "x".into() }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::PermissionDenied, "{what}");
        let e = g
            .list_apps(with_token(token, pb::ListAppsRequest {}))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::PermissionDenied, "{what}");
    }
    // Over gRPC the owner makes one too, its secret in the answer once.
    let r = g
        .create_app(with_token(
            &admin,
            pb::CreateAppRequest {
                name: "worker".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let v: Value = serde_json::from_str(&r.result_json).unwrap();
    assert!(v["client_secret"].as_str().unwrap().starts_with("tut_sk_"));
    // Tenant B's owner reaches none of A's apps.
    let b_admin = t.person(KC_B, "owner", "tutela-admin").await;
    let (status, _) = t
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{id}/rotate"),
            &b_admin,
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = t
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{id}/disable"),
            &b_admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, v) = t
        .call(reqwest::Method::GET, "/v1/admin/apps", &b_admin, None)
        .await;
    assert_eq!(v["apps"], json!([]), "{v}");
    let e = g
        .rotate_app_secret(with_token(
            &b_admin,
            pb::RotateAppSecretRequest {
                id: id.clone(),
                overlap_secs: None,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    t.finish().await;
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn tm09_client_credentials_give_the_apps_service_account_a_token_of_its_tenant() {
    let Some(mut t) = t().await else { return };
    let admin = t.person(KC, "owner", "tutela-admin").await;
    let (id, secret, sa) = t.app(&admin, "crm backend").await;
    // HTTP Basic.
    let (status, v) = t.client_token(&id, &secret).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let token = v["access_token"].as_str().unwrap().to_owned();
    let c = claims(&token);
    assert_eq!(c["sub"], sa.as_str());
    assert_eq!(c["azp"], id.as_str());
    assert_eq!(c["aud"], AUD);
    assert_eq!(c["tid"], t.a.tid.to_string());
    assert_eq!(c["iss"], OWN_ISS);
    assert!(c.get("sid").is_none() && c.get("amr").is_none(), "{c}");
    let (status, v) = t.whoami(&token).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["sub"], sa.as_str());
    // The form, and another registered audience.
    let (status, v, _) = t
        .token(
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &id),
                ("client_secret", &secret),
                ("audience", "crm-api"),
            ],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        claims(v["access_token"].as_str().unwrap())["aud"],
        "crm-api"
    );
    // Never an admin token, never an unknown audience.
    for aud in ["tutela-admin", "nobody-api"] {
        let (status, v, _) = t
            .token(
                &[("grant_type", "client_credentials"), ("audience", aud)],
                Some((&id, &secret)),
            )
            .await;
        assert_eq!(
            (status, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_target")),
            "{aud}: {v}"
        );
    }
    // Every bad credential is the same 401 invalid_client.
    let (other, other_secret, _) = t.app(&admin, "other").await;
    let b_admin = t.person(KC_B, "owner", "tutela-admin").await;
    let (b_id, b_secret, _) = t.app(&b_admin, "beta backend").await;
    let mut wrong = secret.clone();
    wrong.replace_range(20..21, if &secret[20..21] == "A" { "B" } else { "A" });
    for (what, cid, cs) in [
        ("a wrong secret", id.as_str(), wrong.as_str()),
        ("another app's secret", id.as_str(), other_secret.as_str()),
        (
            "an app of another tenant's secret",
            id.as_str(),
            b_secret.as_str(),
        ),
        (
            "another tenant's client with this secret",
            b_id.as_str(),
            secret.as_str(),
        ),
        (
            "an unknown client",
            "app_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7000",
            secret.as_str(),
        ),
        ("not a client id", "crm-web", secret.as_str()),
        ("not a key", id.as_str(), "hunter2"),
    ] {
        let (status, v, headers) = t
            .token(&[("grant_type", "client_credentials")], Some((cid, cs)))
            .await;
        assert_eq!(
            (status, v["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("invalid_client")),
            "{what}: {v}"
        );
        assert_eq!(
            v["error_description"], "the client could not be authenticated",
            "{what}"
        );
        assert!(headers.contains_key("www-authenticate"), "{what}");
    }
    let (status, v, _) = t.token(&[("grant_type", "client_credentials")], None).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_client")),
        "{v}"
    );
    let (status, v, _) = t
        .token(
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &id),
                ("client_secret", &secret),
            ],
            Some((&id, &secret)),
        )
        .await;
    assert_eq!(
        (status, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request")),
        "two methods: {v}"
    );
    let _ = other;
    // Issued tokens are recorded with the app; the secret is never written.
    let records = common::audit_of(&mut t.d.owner, &t.a).await;
    let issued: Vec<&Value> = records
        .iter()
        .filter(|r| r["action"] == "tutela_token:issue" && r["details"]["kind"] == "client")
        .collect();
    assert!(
        issued
            .iter()
            .any(|r| r["outcome"] == "success" && r["details"]["app"] == id.as_str()),
        "{issued:?}"
    );
    assert!(
        !serde_json::to_string(&records)
            .unwrap()
            .contains(&secret[16..])
    );
    t.finish().await;
}

#[tokio::test]
async fn a_secret_rotates_with_an_overlap_and_a_disabled_app_stops_at_once() {
    let Some(mut t) = t().await else { return };
    let admin = t.person(KC, "owner", "tutela-admin").await;
    let (id, first, sa) = t.app(&admin, "crm backend").await;
    let (status, v) = t
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{id}/rotate"),
            &admin,
            Some(&json!({"overlap_secs": 60})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let second = v["client_secret"].as_str().unwrap().to_owned();
    assert_ne!(first, second);
    // Both work during the overlap.
    for s in [&first, &second] {
        assert_eq!(t.client_token(&id, s).await.0, StatusCode::OK);
    }
    // A rotation with no overlap ends both old ones at once.
    let (status, v) = t
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{id}/rotate"),
            &admin,
            Some(&json!({"overlap_secs": 0})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let third = v["client_secret"].as_str().unwrap().to_owned();
    for s in [&first, &second] {
        assert_eq!(t.client_token(&id, s).await.0, StatusCode::UNAUTHORIZED);
    }
    let (status, v) = t.client_token(&id, &third).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let token = v["access_token"].as_str().unwrap().to_owned();
    let (status, _) = t
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{id}/rotate"),
            &admin,
            Some(&json!({"overlap_secs": 604_801})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Disabled: no secret works, and the token it holds stops on the API.
    let (status, v) = t
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{id}/disable"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["disabled_at"].is_string());
    assert_eq!(
        t.client_token(&id, &third).await.0,
        StatusCode::UNAUTHORIZED
    );
    let start = std::time::Instant::now();
    while t.whoami(&token).await.0 != StatusCode::UNAUTHORIZED {
        assert!(
            start.elapsed() < Duration::from_millis(2500),
            "the disabled app's token still works"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, _) = t
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{id}/disable"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let events = common::events_of(&mut t.d.owner, &t.a).await;
    assert!(
        events
            .iter()
            .any(|e| e.event_type.to_string() == "tutela.principal.disabled.v1"),
        "{events:?}"
    );
    let records = common::audit_of(&mut t.d.owner, &t.a).await;
    for action in ["tutela_app:rotate", "tutela_app:disable"] {
        assert!(
            records
                .iter()
                .any(|r| r["action"] == action && r["outcome"] == "success"),
            "{action}"
        );
    }
    let _ = sa;
    t.finish().await;
}

#[tokio::test]
async fn tm09_an_exchange_binds_azp_to_the_client_that_authenticated() {
    let Some(t) = t().await else { return };
    let admin = t.person(KC, "owner", "tutela-admin").await;
    let (x, x_secret, _) = t.app(&admin, "x").await;
    let (y, y_secret, _) = t.app(&admin, "y").await;
    let b_admin = t.person(KC_B, "owner", "tutela-admin").await;
    let (bx, bx_secret, _) = t.app(&b_admin, "bx").await;
    let exchange = |subject: String, audience: &'static str| {
        vec![
            ("grant_type".to_owned(), GRANT_EXCHANGE.to_owned()),
            ("subject_token".to_owned(), subject),
            ("subject_token_type".to_owned(), ACCESS.to_owned()),
            ("audience".to_owned(), audience.to_owned()),
        ]
    };
    let pairs = |v: &Vec<(String, String)>| {
        v.iter()
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect::<Vec<_>>()
    };
    let ask = |v: Vec<(String, String)>, basic: Option<(String, String)>| {
        let t = &t;
        async move {
            let refs: Vec<(&str, &str)> = v.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
            let basic = basic.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
            let (s, v, _) = t.token(&refs, basic).await;
            (s, v)
        }
    };
    // A person's sign-in, exchanged by app X: the token's azp is X.
    let (status, v) = ask(
        exchange(t.kc(KC, "alice", "1"), AUD),
        Some((x.clone(), x_secret.clone())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let alice_x = v["access_token"].as_str().unwrap().to_owned();
    assert_eq!(claims(&alice_x)["azp"], x.as_str());
    // A public client (the Console in a browser) authenticates nothing: the
    // azp stays the sign-in's.
    let (status, v) = ask(exchange(t.kc(KC, "alice", "1"), AUD), None).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        claims(v["access_token"].as_str().unwrap())["azp"],
        "crm-web"
    );
    // X's token, exchanged again: only by X.
    let again = exchange(alice_x.clone(), "crm-api");
    let (status, v) = ask(pairs(&again), Some((x.clone(), x_secret.clone()))).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        claims(v["access_token"].as_str().unwrap())["azp"],
        x.as_str()
    );
    let (status, v) = ask(pairs(&again), Some((y.clone(), y_secret.clone()))).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "another app: {v}"
    );
    let (status, v) = ask(pairs(&again), None).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_client")),
        "no client: {v}"
    );
    // An app may not claim to be a public client either.
    let mut with_id = pairs(&again);
    with_id.push(("client_id".to_owned(), x.clone()));
    let (status, v) = ask(with_id, None).await;
    assert_eq!(
        (status, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_client")),
        "{v}"
    );
    // A client of another tenant exchanges nothing of this one.
    let (status, v) = ask(
        exchange(t.kc(KC, "alice", "1"), AUD),
        Some((bx.clone(), bx_secret.clone())),
    )
    .await;
    assert_eq!(
        (status, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "{v}"
    );
    // The app's own token, exchanged for another audience, by the app.
    let (_, v) = t.client_token(&x, &x_secret).await;
    let own = v["access_token"].as_str().unwrap().to_owned();
    let (status, v) = ask(
        exchange(own.clone(), "crm-api"),
        Some((x.clone(), x_secret.clone())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, _) = ask(exchange(own, "crm-api"), Some((y, y_secret))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The metadata names the methods.
    let m: Value = http()
        .get(t.s.api_url("/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        m["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == "client_credentials"),
        "{m}"
    );
    assert!(
        m["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == "client_secret_basic"),
        "{m}"
    );
    t.finish().await;
}

#[tokio::test]
async fn the_operator_makes_an_app_for_the_bootstrap() {
    let Some(mut t) = t().await else { return };
    let own: tutela_contracts::tenant::Issuer = OWN_ISS.parse().unwrap();
    let secrets = common::secrets();
    let (app, secret) =
        tutelad::lifecycle::create_app(&mut t.d.owner, &own, &t.a, "bootstrap", &secrets)
            .await
            .unwrap();
    let (status, v) = t.client_token(&app.id, &secret).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let records = common::audit_of(&mut t.d.owner, &t.a).await;
    let made = records
        .iter()
        .find(|r| r["action"] == "tutela_app:create")
        .unwrap();
    assert_eq!(made["actor"]["id"], tutelad::audit::SYSTEM);
    // A tenant that is not the deployment's own is refused.
    let foreign = common::tenant_of(&mut t.d.owner, common::ISS).await;
    assert!(
        tutelad::lifecycle::create_app(&mut t.d.owner, &own, &foreign, "x", &secrets)
            .await
            .is_err()
    );
    t.finish().await;
}
