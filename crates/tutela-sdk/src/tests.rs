//! Verifier tests: every step of CONTRACTS.md 4.2, algorithm confusion,
//! the JWKS rules of TM-15, delegation and external issuers.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RSA_PKCS1_SHA256,
    RsaKeyPair,
};
use serde_json::{Value, json};

use super::jwks::Key;
use super::*;

const ISS: &str = "https://auth.example.test";
const EXT: &str = "https://kc.example.test/realms/crm";
const TID: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";
const EXT_TID: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c";
const USER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081";
const AGENT: &str = "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102";
const NOW: u64 = 1_800_000_000;

/// A signing key of one algorithm and its public JWK.
enum Signer {
    Es(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
    Rs(RsaKeyPair),
}

impl Signer {
    fn new(alg: Alg) -> Self {
        match alg {
            Alg::Es256 => {
                Self::Es(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap())
            }
            Alg::EdDsa => Self::Ed(Ed25519KeyPair::generate().unwrap()),
            Alg::Rs256 => Self::Rs(RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap()),
        }
    }

    const fn alg(&self) -> Alg {
        match self {
            Self::Es(_) => Alg::Es256,
            Self::Ed(_) => Alg::EdDsa,
            Self::Rs(_) => Alg::Rs256,
        }
    }

    fn key(&self) -> Key {
        match self {
            Self::Es(k) => {
                let p = k.public_key().as_ref().to_vec();
                Key::P256 {
                    x: B64.encode(&p[1..33]),
                    y: B64.encode(&p[33..65]),
                    point: p,
                }
            }
            Self::Ed(k) => {
                let x = k.public_key().as_ref().to_vec();
                Key::Ed25519 {
                    x_b64: B64.encode(&x),
                    x,
                }
            }
            Self::Rs(k) => {
                let pk = k.public_key();
                let n = pk.modulus().big_endian_without_leading_zero().to_vec();
                let e = pk.exponent().big_endian_without_leading_zero().to_vec();
                Key::Rsa {
                    n_b64: B64.encode(&n),
                    e_b64: B64.encode(&e),
                    n,
                    e,
                }
            }
        }
    }

    fn kid(&self) -> String {
        self.key().thumbprint()
    }

    fn jwk(&self, kid: &str) -> Value {
        match self.key() {
            Key::P256 { x, y, .. } => {
                json!({"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "use": "sig"})
            }
            Key::Ed25519 { x_b64, .. } => {
                json!({"kty": "OKP", "crv": "Ed25519", "x": x_b64, "kid": kid})
            }
            Key::Rsa { n_b64, e_b64, .. } => {
                json!({"kty": "RSA", "n": n_b64, "e": e_b64, "kid": kid, "alg": "RS256"})
            }
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match self {
            Self::Es(k) => k.sign(&rng, msg).unwrap().as_ref().to_vec(),
            Self::Ed(k) => k.sign(msg).as_ref().to_vec(),
            Self::Rs(k) => {
                let mut sig = vec![0; k.public_modulus_len()];
                k.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig).unwrap();
                sig
            }
        }
    }

    /// A compact JWS over `header` and `claims`.
    fn token(&self, header: &Value, claims: &Value) -> String {
        let h = B64.encode(serde_json::to_vec(header).unwrap());
        let p = B64.encode(serde_json::to_vec(claims).unwrap());
        let signed = format!("{h}.{p}");
        format!("{signed}.{}", B64.encode(self.sign(signed.as_bytes())))
    }

    fn header(&self, typ: &str) -> Value {
        json!({"typ": typ, "alg": self.alg().as_str(), "kid": self.kid()})
    }
}

/// An in-memory JWKS source that counts its fetches and can be broken.
struct Memory {
    body: Mutex<Option<Vec<u8>>>,
    fetches: AtomicUsize,
}

impl Memory {
    fn new(keys: &[Value]) -> Arc<Self> {
        let m = Arc::new(Self {
            body: Mutex::new(None),
            fetches: AtomicUsize::new(0),
        });
        m.set(keys);
        m
    }
    fn set(&self, keys: &[Value]) {
        *self.body.lock().unwrap() = Some(serde_json::to_vec(&json!({"keys": keys})).unwrap());
    }
    fn break_it(&self) {
        *self.body.lock().unwrap() = None;
    }
    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

impl JwksSource for Memory {
    fn fetch(
        &self,
        _url: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send>> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let body = self.body.lock().unwrap().clone();
        Box::pin(async move { body })
    }
}

struct Fake(AtomicU64);
impl Clock for Fake {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn config(algs: Vec<Alg>) -> VerifierConfig {
    VerifierConfig {
        audience: "svc".parse().unwrap(),
        trust: TrustList::new()
            .with(ISS.parse().unwrap(), TID.parse().unwrap())
            .unwrap()
            .with(EXT.parse().unwrap(), EXT_TID.parse().unwrap())
            .unwrap(),
        issuers: vec![
            IssuerConfig {
                iss: ISS.parse().unwrap(),
                jwks_uri: format!("{ISS}/.well-known/jwks.json"),
                algs: algs.clone(),
                external: false,
                allow_typ_jwt: false,
            },
            IssuerConfig {
                iss: EXT.parse().unwrap(),
                jwks_uri: format!("{EXT}/protocol/openid-connect/certs"),
                algs,
                external: true,
                allow_typ_jwt: true,
            },
        ],
        delegation: false,
        delegation_aware: false,
        denied_kids: HashSet::new(),
        cache: CacheRules::default(),
    }
}

fn verifier(cfg: VerifierConfig, src: &Arc<Memory>) -> (Verifier, Arc<Fake>) {
    let clock = Arc::new(Fake(AtomicU64::new(NOW)));
    let v = Verifier::with(
        cfg,
        Arc::clone(src) as Arc<dyn JwksSource>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    (v, clock)
}

fn claims() -> Value {
    json!({
        "iss": ISS, "sub": USER, "aud": "svc", "azp": "crm-web",
        "exp": NOW + 300, "iat": NOW, "nbf": NOW,
        "jti": "0193a1b2-c3d4-7e99-8f00-a1b2c3d4e5f6",
        "sid": "ses_0193a1b2-c3d4-7123-8456-789abcdef012",
        "tid": TID, "epoch": 3, "rev": 42, "amr": ["pwd"]
    })
}

fn delegated() -> Value {
    json!({
        "iss": ISS, "sub": USER, "act": {"sub": AGENT},
        "cap": {"snapshot": "opaque"}, "run_id": "run-1", "aud": "svc", "azp": "attache",
        "exp": NOW + 90, "iat": NOW, "nbf": NOW,
        "jti": "0193a1b2-c3d4-7e99-8f00-a1b2c3d4e5f7",
        "tid": TID, "epoch": 3, "rev": 42
    })
}

fn with(mut v: Value, k: &str, val: Value) -> Value {
    v[k] = val;
    v
}

async fn step(v: &Verifier, token: &str) -> Option<Step> {
    v.verify(token).await.err().map(|e| e.step())
}

#[tokio::test]
async fn every_algorithm_verifies_with_its_own_key() {
    for alg in [Alg::Es256, Alg::Rs256, Alg::EdDsa] {
        let s = Signer::new(alg);
        let src = Memory::new(&[s.jwk(&s.kid())]);
        let (v, _) = verifier(config(vec![alg]), &src);
        let id = v
            .verify(&s.token(&s.header("at+jwt"), &claims()))
            .await
            .unwrap();
        assert_eq!(
            id.tenant(),
            TenantKey::new(ISS.parse().unwrap(), TID.parse().unwrap())
        );
        assert!(matches!(id, Identity::Access(_)), "{alg:?}");
        // `application/at+jwt`, any case, is the same type.
        let h = with(s.header("at+jwt"), "typ", json!("Application/AT+JWT"));
        assert!(v.verify(&s.token(&h, &claims())).await.is_ok());
    }
}

#[tokio::test]
async fn bad_headers_and_algorithm_confusion_are_refused() {
    let s = Signer::new(Alg::Es256);
    let src = Memory::new(&[s.jwk(&s.kid())]);
    let (v, _) = verifier(config(vec![Alg::Es256]), &src);
    let c = claims();
    let base = s.header("at+jwt");
    for bad in [
        with(base.clone(), "typ", json!("JWT")),
        with(base.clone(), "typ", json!("id+jwt")),
        with(base.clone(), "alg", json!("none")),
        with(base.clone(), "alg", json!("HS256")),
        with(base.clone(), "alg", json!("RS256")),
        with(base.clone(), "kid", json!("")),
        with(base.clone(), "jku", json!("https://evil.example/jwks")),
        with(base.clone(), "jwk", json!({})),
        with(base.clone(), "x5u", json!("https://evil.example/c")),
        with(base.clone(), "x5c", json!([])),
        with(base.clone(), "crit", json!(["exp"])),
        json!({"alg": "ES256", "kid": s.kid()}),
    ] {
        assert_eq!(
            step(&v, &s.token(&bad, &c)).await,
            Some(Step::Header),
            "{bad}"
        );
    }
    // An Ed25519 key under the ES256 key's kid: a key of another type never
    // verifies.
    let ed = Signer::new(Alg::EdDsa);
    let mixed = Memory::new(&[ed.jwk(&s.kid())]);
    let mut cfg = config(vec![Alg::Es256, Alg::EdDsa]);
    cfg.issuers[0].external = false;
    let (v2, _) = verifier(cfg, &mixed);
    let t = s.token(&s.header("at+jwt"), &c);
    assert!(matches!(
        step(&v2, &t).await,
        Some(Step::Key | Step::Signature)
    ));
    // Not a JWS at all.
    for junk in ["", "a.b", "a.b.c.d", "!!!.???.###"] {
        assert_eq!(step(&v, junk).await, Some(Step::Header), "{junk}");
    }
    assert_eq!(step(&v, &"a".repeat(9000)).await, Some(Step::Size));
}

#[tokio::test]
async fn tm01_signatures_audiences_and_claims_are_checked_in_order() {
    let s = Signer::new(Alg::Es256);
    let other = Signer::new(Alg::Es256);
    let src = Memory::new(&[s.jwk(&s.kid())]);
    let (v, _) = verifier(config(vec![Alg::Es256]), &src);
    // Another key's signature under our kid.
    let forged = other.token(&s.header("at+jwt"), &claims());
    assert_eq!(step(&v, &forged).await, Some(Step::Signature));
    // A payload changed after signing.
    let good = s.token(&s.header("at+jwt"), &claims());
    let mut parts: Vec<&str> = good.split('.').collect();
    let changed = B64.encode(serde_json::to_vec(&with(claims(), "rev", json!(43))).unwrap());
    parts[1] = &changed;
    assert_eq!(step(&v, &parts.join(".")).await, Some(Step::Signature));
    // Unknown issuer.
    let t = s.token(
        &s.header("at+jwt"),
        &with(claims(), "iss", json!("https://other.example")),
    );
    assert_eq!(step(&v, &t).await, Some(Step::Issuer));
    // Claims (5 to 8).
    for bad in [
        with(claims(), "aud", json!("other")),
        with(claims(), "aud", json!(["svc", "other"])),
        with(claims(), "exp", json!(NOW - 61)),
        with(claims(), "exp", json!(NOW + 601)),
        with(claims(), "iat", json!(NOW + 61)),
        with(
            claims(),
            "tid",
            json!("ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2d"),
        ),
        with(claims(), "sub", json!("workload:spiffe://example.test/x")),
        with(claims(), "act", json!({"sub": AGENT})),
        with(claims(), "amr", json!([])),
    ] {
        assert_eq!(
            step(&v, &s.token(&s.header("at+jwt"), &bad)).await,
            Some(Step::Claims),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn tm15_the_kid_deny_list_and_the_refetch_limit_hold() {
    let old = Signer::new(Alg::Es256);
    let new = Signer::new(Alg::Es256);
    let src = Memory::new(&[old.jwk(&old.kid())]);
    let (v, clock) = verifier(config(vec![Alg::Es256]), &src);
    let t_old = old.token(&old.header("at+jwt"), &claims());
    assert!(v.verify(&t_old).await.is_ok());
    assert_eq!(src.fetches(), 1);
    // An unknown kid right after a fetch: no refetch within 30 s.
    let t_new = new.token(&new.header("at+jwt"), &claims());
    assert_eq!(step(&v, &t_new).await, Some(Step::Key));
    assert_eq!(src.fetches(), 1);
    // After 30 s: one refetch (the key is not published yet), then refused;
    // a second try at once does not fetch again.
    clock.0.store(NOW + 31, Ordering::SeqCst);
    assert_eq!(step(&v, &t_new).await, Some(Step::Key));
    assert_eq!(step(&v, &t_new).await, Some(Step::Key));
    assert_eq!(src.fetches(), 2);
    // Published, and the interval passed again: rotation works.
    src.set(&[old.jwk(&old.kid()), new.jwk(&new.kid())]);
    clock.0.store(NOW + 62, Ordering::SeqCst);
    assert!(v.verify(&t_new).await.is_ok());
    assert_eq!(src.fetches(), 3);
    // An emergency deny-list refuses at once, even though the key is cached.
    v.deny_kid(&old.kid());
    assert_eq!(step(&v, &t_old).await, Some(Step::Key));
    assert!(v.verify(&t_new).await.is_ok());
}

#[tokio::test]
async fn tm15_a_broken_jwks_endpoint_fails_closed_after_the_stale_limit() {
    let s = Signer::new(Alg::Es256);
    let src = Memory::new(&[s.jwk(&s.kid())]);
    let (v, clock) = verifier(config(vec![Alg::Es256]), &src);
    let token = |at: u64| {
        s.token(
            &s.header("at+jwt"),
            &with(
                with(with(claims(), "iat", json!(at)), "nbf", json!(at)),
                "exp",
                json!(at + 300),
            ),
        )
    };
    assert!(v.verify(&token(NOW)).await.is_ok());
    src.break_it();
    // After the TTL the refresh fails; the cached key is still used.
    clock.0.store(NOW + 400, Ordering::SeqCst);
    assert!(v.verify(&token(NOW + 400)).await.is_ok());
    // Past the stale limit (1 hour) nothing verifies.
    clock.0.store(NOW + 3_700, Ordering::SeqCst);
    assert_eq!(step(&v, &token(NOW + 3_700)).await, Some(Step::Key));
}

#[tokio::test]
async fn tutela_keys_are_named_by_their_thumbprint() {
    let s = Signer::new(Alg::Es256);
    let src = Memory::new(&[s.jwk("my-own-kid")]);
    let (v, _) = verifier(config(vec![Alg::Es256]), &src);
    let h = with(s.header("at+jwt"), "kid", json!("my-own-kid"));
    assert_eq!(step(&v, &s.token(&h, &claims())).await, Some(Step::Key));
}

#[tokio::test]
async fn epochs_and_disabled_principals() {
    let s = Signer::new(Alg::Es256);
    let src = Memory::new(&[s.jwk(&s.kid())]);
    let (v, _) = verifier(config(vec![Alg::Es256]), &src);
    let t = s.token(&s.header("at+jwt"), &claims());
    let user: Principal = USER.parse().unwrap();
    v.epochs().note(&user, 3);
    assert!(v.verify(&t).await.is_ok());
    v.epochs().note(&user, 4);
    v.epochs().note(&user, 2);
    assert_eq!(step(&v, &t).await, Some(Step::Epoch));
    let fresh = s.token(&s.header("at+jwt"), &with(claims(), "epoch", json!(4)));
    assert!(v.verify(&fresh).await.is_ok());
    v.epochs().set_disabled(&user, true);
    assert_eq!(step(&v, &fresh).await, Some(Step::Epoch));
}

#[tokio::test]
async fn tm02_delegated_tokens_need_delegation_on_and_every_actor_allowed() {
    let s = Signer::new(Alg::Es256);
    let src = Memory::new(&[s.jwk(&s.kid())]);
    let t = s.token(&s.header("agent+jwt"), &delegated());
    // Off by default.
    let (v, _) = verifier(config(vec![Alg::Es256]), &src);
    assert_eq!(step(&v, &t).await, Some(Step::Delegation));
    // On, but our audience is not delegation-aware.
    let mut cfg = config(vec![Alg::Es256]);
    cfg.delegation = true;
    let (v, _) = verifier(cfg.clone(), &src);
    assert_eq!(step(&v, &t).await, Some(Step::Delegation));
    cfg.delegation_aware = true;
    let (v, _) = verifier(cfg, &src);
    assert!(matches!(
        v.verify(&t).await.unwrap(),
        Identity::Delegated(_)
    ));
    // A delegated token sent as an access token, and the reverse.
    let as_access = s.token(&s.header("at+jwt"), &delegated());
    assert_eq!(step(&v, &as_access).await, Some(Step::Claims));
    // A lifetime over 120 s.
    let long = s.token(
        &s.header("agent+jwt"),
        &with(delegated(), "exp", json!(NOW + 121)),
    );
    assert_eq!(step(&v, &long).await, Some(Step::Claims));
    // A disabled actor.
    v.epochs().set_disabled(&AGENT.parse().unwrap(), true);
    assert_eq!(step(&v, &t).await, Some(Step::Delegation));
    v.epochs().set_disabled(&AGENT.parse().unwrap(), false);
    // `cnf` must match the client certificate.
    let cert = [7u8; 32];
    let bound = s.token(
        &s.header("agent+jwt"),
        &with(delegated(), "cnf", json!({"x5t#S256": B64.encode(cert)})),
    );
    assert_eq!(step(&v, &bound).await, Some(Step::Delegation));
    let ctx = Context {
        client_cert_sha256: Some(&cert),
    };
    assert!(v.verify_with(&bound, ctx).await.is_ok());
    let other = Context {
        client_cert_sha256: Some(&[8u8; 32]),
    };
    assert!(v.verify_with(&bound, other).await.is_err());
}

#[tokio::test]
async fn external_issuers_get_their_tenant_from_the_trust_list() {
    let s = Signer::new(Alg::Rs256);
    let src = Memory::new(&[s.jwk("kc-key-1")]);
    let (v, _) = verifier(config(vec![Alg::Rs256]), &src);
    let h = json!({"typ": "JWT", "alg": "RS256", "kid": "kc-key-1"});
    let kc = json!({
        "iss": EXT, "sub": "f:6a1b:alice", "aud": "svc", "azp": "crm-web",
        "exp": NOW + 300, "iat": NOW, "tid": TID, "email": "alice@example.test"
    });
    let Identity::External(t) = v.verify(&s.token(&h, &kc)).await.unwrap() else {
        panic!("not external");
    };
    // `tid` in the token is ignored: the trust list decides.
    assert_eq!(t.tenant.tid.to_string(), EXT_TID);
    assert_eq!(t.sub, "f:6a1b:alice");
    for bad in [
        with(kc.clone(), "aud", json!(["svc", "account"])),
        with(kc.clone(), "exp", json!(NOW + 601)),
        with(kc.clone(), "exp", json!(NOW - 61)),
        with(kc.clone(), "sub", json!("")),
    ] {
        assert_eq!(
            step(&v, &s.token(&h, &bad)).await,
            Some(Step::Claims),
            "{bad}"
        );
    }
    // An external issuer never sends delegated tokens.
    let d = json!({"typ": "agent+jwt", "alg": "RS256", "kid": "kc-key-1"});
    assert_eq!(step(&v, &s.token(&d, &kc)).await, Some(Step::Header));
}

#[tokio::test]
async fn tm18_the_jwks_is_fetched_through_safenet() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let s = Signer::new(Alg::EdDsa);
    let body = serde_json::to_vec(&json!({"keys": [s.jwk(&s.kid())]})).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            });
        }
    });
    let mut cfg = config(vec![Alg::EdDsa]);
    cfg.issuers[0].jwks_uri = format!("http://127.0.0.1:{port}/jwks");
    let dev = SafenetSource::new(tutela_safenet::Policy::new().dev_loopback()).unwrap();
    let v = Verifier::with(
        cfg.clone(),
        Arc::new(dev),
        Arc::new(Fake(AtomicU64::new(NOW))),
    );
    assert!(
        v.verify(&s.token(&s.header("at+jwt"), &claims()))
            .await
            .is_ok()
    );
    // Production rules refuse the same URL: no key, so the token fails.
    let prod = SafenetSource::new(tutela_safenet::Policy::new()).unwrap();
    let v = Verifier::with(cfg, Arc::new(prod), Arc::new(Fake(AtomicU64::new(NOW))));
    assert_eq!(
        step(&v, &s.token(&s.header("at+jwt"), &claims())).await,
        Some(Step::Key)
    );
}
