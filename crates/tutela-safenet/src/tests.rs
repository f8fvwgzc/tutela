//! TM-18 tests: the URL check, the resolver, and requests to a local server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::*;

/// A resolver with fixed answers. Each name has a list of answers; each
/// lookup takes the next one (the last one repeats).
struct Fake {
    answers: HashMap<String, Vec<Vec<IpAddr>>>,
    calls: Mutex<HashMap<String, usize>>,
    total: AtomicUsize,
}

impl Fake {
    fn new(answers: &[(&str, &[&[&str]])]) -> Arc<Self> {
        Arc::new(Self {
            answers: answers
                .iter()
                .map(|(h, seq)| {
                    let seq = seq
                        .iter()
                        .map(|a| a.iter().map(|s| s.parse().unwrap()).collect())
                        .collect();
                    ((*h).to_owned(), seq)
                })
                .collect(),
            calls: Mutex::new(HashMap::new()),
            total: AtomicUsize::new(0),
        })
    }
}

impl Lookup for Fake {
    fn lookup(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> {
        self.total.fetch_add(1, Ordering::SeqCst);
        let n = {
            let mut calls = self.calls.lock().unwrap();
            let n = calls.entry(host.clone()).or_insert(0);
            *n += 1;
            *n - 1
        };
        let answer = self
            .answers
            .get(&host)
            .and_then(|seq| seq.get(n).or_else(|| seq.last()).cloned());
        Box::pin(async move {
            answer.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"))
        })
    }
}

async fn resolve(lookup: Arc<Fake>, policy: Policy, host: &str) -> Result<Vec<IpAddr>, String> {
    Guard::checked(lookup, Arc::new(policy), host.to_owned())
        .await
        .map_err(|e| e.to_string())
}

#[test]
fn tm18_bad_urls_are_refused_before_any_request() {
    let p = Policy::new();
    for bad in [
        "http://169.254.169.254/",
        "https://169.254.169.254/latest/meta-data/",
        "https://2130706433/",
        "https://0x7f.1/",
        "https://017700000001/",
        "https://127.1/",
        "https://[::ffff:127.0.0.1]/",
        "https://[::1]/",
        "https://[fd00:ec2::254]/",
        "https://10.0.0.5/",
        "https://100.100.100.200/",
        "https://localhost/",
        "https://admin.localhost./",
        "https://user:pw@example.com/",
        "http://example.com/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "not a url",
        "https:///",
    ] {
        assert!(check_url(bad, &p).is_err(), "{bad}");
    }
    for ok in [
        "https://example.com/.well-known/jwks.json",
        "https://8.8.8.8/",
        "https://[2606:4700:4700::1111]/",
    ] {
        assert!(check_url(ok, &p).is_ok(), "{ok}");
    }
    // Errors never repeat the credentials.
    let e = check_url("https://alice:hunter2@example.com/", &p).unwrap_err();
    assert!(!e.to_string().contains("hunter2"));
}

#[test]
fn dev_mode_allows_loopback_only_and_the_allow_list_is_exact() {
    let dev = Policy::new().dev_loopback();
    for ok in [
        "http://localhost:8080/",
        "http://127.0.0.1:9/",
        "http://[::1]/",
        "https://localhost/",
    ] {
        assert!(check_url(ok, &dev).is_ok(), "{ok}");
    }
    for bad in [
        "http://example.com/",
        "http://10.0.0.5/",
        "https://169.254.169.254/",
    ] {
        assert!(check_url(bad, &dev).is_err(), "{bad}");
    }
    let kc = Policy::new()
        .allow_private_host("kc.internal")
        .unwrap()
        .allow_private_host("10.0.0.7")
        .unwrap();
    assert!(check_url("https://10.0.0.7/realms/a", &kc).is_ok());
    assert!(check_url("https://10.0.0.8/", &kc).is_err());
    assert!(
        check_url("http://10.0.0.7/", &kc).is_err(),
        "https is still required"
    );
    assert!(Policy::new().allow_private_host("").is_err());
    assert!(Policy::new().allow_private_host("a b").is_err());
}

#[tokio::test]
async fn tm18_the_resolver_checks_every_address_once_per_connection() {
    let fake = Fake::new(&[
        ("public.test", &[&["93.184.216.34"]]),
        ("private.test", &[&["10.0.0.1"]]),
        ("mixed.test", &[&["93.184.216.34", "127.0.0.1"]]),
        ("rebind.test", &[&["93.184.216.34"], &["169.254.169.254"]]),
        ("kc.internal", &[&["10.0.0.7"]]),
        ("localhost", &[&["93.184.216.34"]]),
    ]);
    let p = Policy::new;
    assert!(resolve(Arc::clone(&fake), p(), "public.test").await.is_ok());
    assert!(
        resolve(Arc::clone(&fake), p(), "private.test")
            .await
            .is_err()
    );
    // One bad address refuses the whole name.
    assert!(resolve(Arc::clone(&fake), p(), "mixed.test").await.is_err());
    assert!(
        resolve(Arc::clone(&fake), p(), "nowhere.test")
            .await
            .is_err()
    );
    // A name that changes its answer: each connection resolves once and is
    // checked; the rebound answer is refused.
    assert!(resolve(Arc::clone(&fake), p(), "rebind.test").await.is_ok());
    assert!(
        resolve(Arc::clone(&fake), p(), "rebind.test")
            .await
            .is_err()
    );
    // The allow-list opens one named host, nothing else.
    let kc = p().allow_private_host("kc.internal").unwrap();
    assert!(
        resolve(Arc::clone(&fake), kc.clone(), "kc.internal")
            .await
            .is_ok()
    );
    assert!(
        resolve(Arc::clone(&fake), kc, "private.test")
            .await
            .is_err()
    );
    // `localhost` stays on this machine even in dev mode.
    assert!(
        resolve(Arc::clone(&fake), p().dev_loopback(), "localhost")
            .await
            .is_err()
    );
}

/// A one-shot HTTP server on 127.0.0.1 that answers with `reply` (or waits
/// `delay` first). Returns its port.
async fn serve(reply: Vec<u8>, delay: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let reply = reply.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                tokio::time::sleep(delay).await;
                let _ = sock.write_all(&reply).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

fn http(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

fn dev_client(policy: Policy) -> Client {
    Client::new(policy.dev_loopback()).unwrap()
}

#[tokio::test]
async fn a_redirect_is_returned_never_followed() {
    let port = serve(
        http(
            "302 Found",
            "location: http://169.254.169.254/latest/\r\n",
            b"",
        ),
        Duration::ZERO,
    )
    .await;
    let r = dev_client(Policy::new())
        .get(&format!("http://127.0.0.1:{port}/"))
        .await
        .unwrap();
    assert_eq!(r.status, 302);
    assert_eq!(r.header("location"), Some("http://169.254.169.254/latest/"));
    assert!(!r.is_success());
}

#[tokio::test]
async fn bodies_have_a_size_limit() {
    let big = vec![b'x'; 4096];
    let port = serve(http("200 OK", "", &big), Duration::ZERO).await;
    let url = format!("http://127.0.0.1:{port}/");
    let e = dev_client(Policy::new().max_body(1024))
        .get(&url)
        .await
        .unwrap_err();
    assert!(matches!(e, SafenetError::TooLarge { limit: 1024 }), "{e}");
    let r = dev_client(Policy::new().max_body(8192))
        .get(&url)
        .await
        .unwrap();
    assert_eq!((r.status, r.body.len()), (200, 4096));
    // Without a content-length the limit holds while reading.
    let mut chunked = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".to_vec();
    chunked.extend_from_slice(&big);
    let port = serve(chunked, Duration::ZERO).await;
    let e = dev_client(Policy::new().max_body(1024))
        .get(&format!("http://127.0.0.1:{port}/"))
        .await
        .unwrap_err();
    assert!(matches!(e, SafenetError::TooLarge { .. }), "{e}");
}

#[tokio::test]
async fn slow_servers_time_out() {
    let port = serve(http("200 OK", "", b"late"), Duration::from_secs(5)).await;
    let e = dev_client(Policy::new().timeout(Duration::from_millis(300)))
        .get(&format!("http://127.0.0.1:{port}/"))
        .await
        .unwrap_err();
    assert!(matches!(e, SafenetError::Timeout), "{e}");
}

#[tokio::test]
async fn production_refuses_the_local_server_and_names_through_the_resolver() {
    let port = serve(http("200 OK", "", b"secret"), Duration::ZERO).await;
    let prod = Client::new(Policy::new()).unwrap();
    for url in [
        format!("http://127.0.0.1:{port}/"),
        format!("https://127.0.0.1:{port}/"),
        format!("https://localhost:{port}/"),
    ] {
        assert!(prod.get(&url).await.is_err(), "{url}");
    }
    // A public-looking name that resolves to this machine is refused in the
    // resolver, before any connection.
    let fake = Fake::new(&[("api.test", &[&["127.0.0.1"]])]);
    let c = Client::with_lookup(Policy::new(), Arc::clone(&fake) as Arc<dyn Lookup>).unwrap();
    let e = c
        .get(&format!("https://api.test:{port}/"))
        .await
        .unwrap_err();
    assert!(matches!(e, SafenetError::NotPublic { .. }), "{e}");
    assert_eq!(fake.total.load(Ordering::SeqCst), 1);
}

#[test]
fn the_tls_config_builds_on_aws_lc_rs() {
    let c = tls_client_config().unwrap();
    assert!(c.crypto_provider().cipher_suites.iter().all(|s| {
        let name = format!("{:?}", s.suite());
        name.contains("AES") || name.contains("CHACHA20")
    }));
}

#[tokio::test]
async fn callers_cannot_set_reserved_headers() {
    let c = dev_client(Policy::new());
    for h in [
        "Host",
        "content-length",
        "baggage",
        "proxy-authorization",
        "bad header",
    ] {
        let e = c
            .post(
                "http://127.0.0.1:9/",
                "application/json",
                vec![],
                &[(h, "x")],
            )
            .await
            .unwrap_err();
        assert!(matches!(e, SafenetError::Header(_)), "{h}: {e}");
    }
}
