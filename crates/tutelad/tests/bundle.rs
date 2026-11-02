//! Signed bundles through the real service, the real auth layer and a real
//! Postgres, verified and used offline by a product's PDP (ADR-0024,
//! ADR-0038, THREAT-MODEL.md TM-13 and TM-15). This is the "bundle expiry"
//! check of the service gate.
#![cfg(test)]

mod common;

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_contracts::keys::ActionKey;
use tutela_contracts::tenant::TrustList;
use tutela_pdp::model::RoleKey;
use tutela_pdp::{Attrs, CheckRequest, PdpError, ResourceRef, Subject};
use tutela_sdk::bundle::{BundleError, OfflineError, OfflinePdp};
use tutela_sdk::{Alg, CacheRules, Clock, IssuerConfig, JwksSource, Verifier, VerifierConfig};

use common::{AGENT, OWN_ISS, SA, Seed, USER, World, world, world_with};

const ADMIN_SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70a9";

async fn owner(
    w: &mut World,
    s_key: &tutela_contracts::tenant::TenantKey,
    org: &tutela_pdp::PathEntry,
    who: &str,
) {
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::assign(
        &tx,
        s_key,
        &Subject::Principal(who.parse().unwrap()),
        &RoleKey::parse("owner").unwrap(),
        org,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn admins(w: &mut World) {
    let (a, ao) = (w.a.key.clone(), w.a.org.clone());
    let (b, bo) = (w.b.key.clone(), w.b.org.clone());
    owner(w, &a, &ao, ADMIN_SA).await;
    owner(w, &b, &bo, ADMIN_SA).await;
}

async fn pull(w: &World, token: &str) -> (StatusCode, String) {
    let res = common::http()
        .get(w.s.api_url("/v1/authz/bundle"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = res.status();
    if status == StatusCode::OK {
        assert_eq!(res.headers()["content-type"], "application/jwt");
        assert_eq!(res.headers()["cache-control"], "no-store");
    }
    (status, res.text().await.unwrap())
}

fn claims(jws: &str) -> Value {
    use base64::Engine as _;
    let p = jws.split('.').nth(1).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p)
            .unwrap(),
    )
    .unwrap()
}

/// A clock a test moves.
struct TestClock(AtomicU64);

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The running service's own JWKS, fetched from it, as a product fetches it.
struct ServerJwks(String);

impl JwksSource for ServerJwks {
    fn fetch(
        &self,
        _url: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send>> {
        let url = self.0.clone();
        Box::pin(async move {
            let r = reqwest::get(url).await.ok()?;
            Some(r.bytes().await.ok()?.to_vec())
        })
    }
}

/// A product's verifier that trusts `tutelad`'s own issuer for tenant `s`,
/// with the service's JWKS, and the clock `clock`.
fn product(w: &World, s: &Seed, clock: Arc<TestClock>) -> Verifier {
    let iss: tutela_contracts::tenant::Issuer = OWN_ISS.parse().unwrap();
    Verifier::with(
        VerifierConfig {
            audience: "crm-api".parse().unwrap(),
            trust: TrustList::new().with(iss.clone(), s.key.tid).unwrap(),
            issuers: vec![IssuerConfig {
                jwks_uri: tutelad::keys::jwks_url(&iss),
                iss,
                algs: vec![Alg::Es256],
                external: false,
                allow_typ_jwt: false,
            }],
            delegation: false,
            delegation_aware: false,
            denied_kids: std::collections::HashSet::new(),
            cache: CacheRules::default(),
        },
        Arc::new(ServerJwks(w.s.api_url("/.well-known/jwks.json"))),
        clock,
    )
}

fn clock() -> Arc<TestClock> {
    Arc::new(TestClock(AtomicU64::new(common::now())))
}

/// May USER read the invoice under A's project, offline?
fn read_invoice(pdp: &OfflinePdp, s: &Seed) -> Result<bool, PdpError> {
    pdp.check(&CheckRequest {
        tenant: s.key.clone(),
        subject: USER.parse().unwrap(),
        actors: Vec::new(),
        action: ActionKey::parse("invoice:read").unwrap(),
        resource: ResourceRef {
            type_name: "invoice".parse().unwrap(),
            id: "inv-1".parse().unwrap(),
            path: vec![s.project.clone(), s.org.clone()],
            attrs: Attrs::new(),
        },
        fields: Some(Vec::new()),
        at_least_revision: None,
    })
    .map(|d| d.is_allowed())
}

/// Who may pull a whole tenant: a service holding `read_audit` at every org
/// of its tenant. Nobody else, and never another tenant's data. Every pull
/// is in the audit log.
#[tokio::test]
async fn tm13_only_a_service_with_read_audit_everywhere_pulls_a_bundle() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let (status, jws) = pull(&w, &w.issuer.token(ADMIN_SA, &w.a.tid, 0)).await;
    assert_eq!(status, StatusCode::OK, "{jws}");
    let c = claims(&jws);
    assert_eq!(c["iss"], OWN_ISS);
    assert_eq!(c["tid"], w.a.tid.as_str());
    assert_eq!(c["tenant_iss"], common::ISS);
    assert_eq!(c["format"], 1);
    for denied in [
        w.issuer.token(SA, &w.a.tid, 0),
        w.issuer.token(USER, &w.a.tid, 0),
        w.issuer.token(AGENT, &w.a.tid, 0),
        w.issuer.delegated(USER, AGENT, &w.a.tid),
    ] {
        let (status, _) = pull(&w, &denied).await;
        assert!(
            matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
            "{status}"
        );
    }
    let admin = w
        .issuer
        .admin_token(USER, &w.a.tid, common::STEP_UP, 0, 300);
    assert_eq!(pull(&w, &admin).await.0, StatusCode::UNAUTHORIZED);
    let res = common::http()
        .get(w.s.api_url("/v1/authz/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // B's service gets B's bundle, with nothing of A.
    let (status, b) = pull(&w, &w.issuer.token(ADMIN_SA, &w.b.tid, 0)).await;
    assert_eq!(status, StatusCode::OK);
    let text = claims(&b).to_string();
    assert!(text.contains(w.b.tid.as_str()));
    assert!(!text.contains(w.a.tid.as_str()) && !text.contains(&w.a.org.id.to_string()));
    // Each pull is recorded, by who pulled it.
    let pulls = common::audited(&mut w.d.owner, &w.a.key, "tutela_bundle:pull").await;
    assert_eq!(pulls.len(), 1);
    assert_eq!(pulls[0]["actor"]["id"], ADMIN_SA);
    assert_eq!(pulls[0]["details"]["jti"], c["jti"]);
    w.finish().await;
}

/// The service gate's bundle expiry: a bundle verifies against the same
/// JWKS as a token, but is never a token; a PDP answers from it with
/// `tutelad` gone, until `exp`, and never after.
#[tokio::test]
async fn tm13_a_pdp_answers_offline_from_a_bundle_until_it_expires() {
    let Some(mut w) = world_with(|c| c.bundle_ttl = Duration::from_secs(60)).await else {
        return;
    };
    admins(&mut w).await;
    let a = Seed {
        key: w.a.key.clone(),
        tid: w.a.tid.clone(),
        org: w.a.org.clone(),
        project: w.a.project.clone(),
        assignment: w.a.assignment.clone(),
    };
    let token = w.issuer.token(ADMIN_SA, &w.a.tid, 0);
    let (_, jws) = pull(&w, &token).await;
    let c = claims(&jws);
    let exp = c["exp"].as_u64().unwrap();
    assert!(exp <= common::now() + 60 && exp > common::now());
    let t = clock();
    let product = product(&w, &a, Arc::clone(&t));
    let verified = product.verify_bundle(&jws).await.unwrap();
    // A bundle is no token, and a token no bundle.
    assert!(product.verify(&jws).await.is_err());
    assert_eq!(
        product.verify_bundle(&token).await.unwrap_err(),
        BundleError::Malformed
    );
    let mut pdp = OfflinePdp::new(t.clone());
    pdp.load(verified).unwrap();
    assert_eq!(read_invoice(&pdp, &a), Ok(true));
    // `tutelad` stops: the PDP still answers from its bundle.
    let World { d, s, .. } = w;
    s.stop().await.unwrap();
    assert_eq!(read_invoice(&pdp, &a), Ok(true));
    // At `exp`, no answer at all: never an allow from an expired bundle.
    t.0.store(exp, Ordering::SeqCst);
    assert_eq!(read_invoice(&pdp, &a), Err(PdpError::ExpiredBundle));
    // An expired bundle is refused when it is read again.
    assert_eq!(
        product.verify_bundle(&jws).await.unwrap_err(),
        BundleError::Expired
    );
    // Much later, still no answer; and with `tutelad` gone its keys cannot
    // be fetched again, so the bundle fails its signature: closed either way.
    t.0.store(exp + 3600, Ordering::SeqCst);
    assert_eq!(read_invoice(&pdp, &a), Err(PdpError::ExpiredBundle));
    assert!(product.verify_bundle(&jws).await.is_err());
    d.finish().await;
}

/// `exp` is never later than the first assignment in the bundle that
/// expires: a bundle never outlives a grant.
#[tokio::test]
async fn tm13_a_bundle_never_outlives_an_expiring_assignment() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let tx = w.d.owner.transaction().await.unwrap();
    let until = std::time::SystemTime::now() + Duration::from_secs(20);
    tutela_store::assign_until(
        &tx,
        &w.a.key,
        &Subject::Principal(common::STRANGER.parse().unwrap()),
        &RoleKey::parse("reader").unwrap(),
        &w.a.project,
        None,
        until,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (status, jws) = pull(&w, &w.issuer.token(ADMIN_SA, &w.a.tid, 0)).await;
    assert_eq!(status, StatusCode::OK);
    let exp = claims(&jws)["exp"].as_u64().unwrap();
    let until = until
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        exp <= until,
        "the bundle lasts to {exp}, past the grant's {until}"
    );
    assert!(exp + 30 > until, "the bundle ends far too soon");
    w.finish().await;
}

/// TM-15 and TM-13: a bundle signed with a denied `kid` is refused, as soon
/// as the deny-list reaches the product (SSE `denied_kids`); an older
/// bundle than the one loaded, a changed one, another tenant's, and a newer
/// format are refused.
#[tokio::test]
async fn tm15_a_denied_kid_an_older_a_changed_and_a_newer_bundle_are_refused() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let a = Seed {
        key: w.a.key.clone(),
        tid: w.a.tid.clone(),
        org: w.a.org.clone(),
        project: w.a.project.clone(),
        assignment: w.a.assignment.clone(),
    };
    let token = w.issuer.token(ADMIN_SA, &w.a.tid, 0);
    let (_, first) = pull(&w, &token).await;
    common::revoke(&mut w.d.owner, &a, &a.assignment).await;
    let (_, second) = pull(&w, &token).await;
    assert!(claims(&second)["rev"].as_u64() > claims(&first)["rev"].as_u64());
    let t = clock();
    let product = product(&w, &a, Arc::clone(&t));
    let mut pdp = OfflinePdp::new(t.clone());
    pdp.load(product.verify_bundle(&second).await.unwrap())
        .unwrap();
    // The revoked reader reads nothing in the newer bundle.
    assert_eq!(read_invoice(&pdp, &a), Ok(false));
    // An older bundle replayed: refused, the newer one stays.
    let older = product.verify_bundle(&first).await.unwrap();
    assert_eq!(pdp.load(older), Err(OfflineError::Older));
    assert_eq!(read_invoice(&pdp, &a), Ok(false));
    // A changed payload: the signature fails.
    let mut parts: Vec<String> = second.split('.').map(str::to_owned).collect();
    let mut c = claims(&second);
    c["exp"] = json!(c["exp"].as_u64().unwrap() + 86_400);
    use base64::Engine as _;
    parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(c.to_string());
    assert_eq!(
        product.verify_bundle(&parts.join(".")).await.unwrap_err(),
        BundleError::Signature
    );
    // B's bundle is not A's: a product that trusts tutelad for A only
    // refuses it, and a PDP of A refuses to load it.
    let (_, b) = pull(&w, &w.issuer.token(ADMIN_SA, &w.b.tid, 0)).await;
    assert_eq!(
        product.verify_bundle(&b).await.unwrap_err(),
        BundleError::Untrusted
    );
    // The deny-list reaches the product: the bundle's `kid` is refused.
    let kid = {
        use base64::Engine as _;
        let h: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(second.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        h["kid"].as_str().unwrap().to_owned()
    };
    let n = tutela_sdk::events::apply_denied_kids(
        &product,
        &json!({"iss": OWN_ISS, "jwks_uri": tutelad::keys::jwks_url(&OWN_ISS.parse().unwrap()), "kids": [kid]}),
    )
    .await;
    assert_eq!(n, Some(1));
    assert_eq!(
        product.verify_bundle(&second).await.unwrap_err(),
        BundleError::Signature
    );
    // A newer format than this build reads, signed by a trusted issuer.
    let test_issuer = common::product_verifier(&w);
    let now = common::now();
    let newer = w.issuer.sign_typed(
        "tutela-bundle+jwt",
        &json!({"iss": common::ISS, "tid": w.a.tid, "tenant_iss": common::ISS, "rev": 1,
                "iat": now, "exp": now + 60, "jti": "x", "format": 2}),
    );
    assert_eq!(
        test_issuer.verify_bundle(&newer).await.unwrap_err(),
        BundleError::Unsupported
    );
    w.finish().await;
}
