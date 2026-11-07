//! The few calls of the Kubernetes API the bootstrap job makes: read a
//! Secret, and make or replace one, in the job's own namespace, with the
//! job's service account token (ADR-0056).
//!
//! In a pod, [`Kube::in_cluster`] reads the API server's address from
//! `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`, and the token,
//! the namespace and the cluster's CA from the service account's files. The
//! API server is reached over https with that CA only, never through a
//! proxy. The chart's Role lets the job's account `get`, `create` and
//! `update` Secrets in its namespace, nothing else.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Where a pod's service account files are.
pub const ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// The label every Secret the job writes carries.
pub const MANAGED_BY: (&str, &str) = ("app.kubernetes.io/managed-by", "tutelad-bootstrap");

/// A client of one namespace's Secrets.
pub struct Kube {
    http: reqwest::Client,
    base: String,
    token: Zeroizing<String>,
    namespace: String,
}

impl std::fmt::Debug for Kube {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kube")
            .field("base", &self.base)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl Kube {
    /// The client of a pod: the API server from the environment, the token,
    /// namespace and CA from the files in `dir` ([`ACCOUNT_DIR`]).
    ///
    /// # Errors
    ///
    /// Not in a pod (no `KUBERNETES_SERVICE_HOST`), a file that cannot be
    /// read, or a CA that is not PEM.
    pub fn in_cluster(dir: &Path) -> anyhow::Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .context("KUBERNETES_SERVICE_HOST is not set: not in a Kubernetes pod")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_owned());
        // An IPv6 address goes in brackets.
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .with_context(|| format!("reading the service account's {name}"))
        };
        let token = Zeroizing::new(read("token")?.trim().to_owned());
        let namespace = read("namespace")?.trim().to_owned();
        let ca = std::fs::read(dir.join("ca.crt")).context("reading the cluster's CA")?;
        Self::new(
            &format!("https://{host}:{port}"),
            token,
            Some(&ca),
            namespace,
        )
    }

    /// A client of `base` (the API server) for `namespace`, with `token`,
    /// trusting only `ca` (PEM) when it is given.
    ///
    /// # Errors
    ///
    /// A CA that is not PEM, a namespace that is not a Kubernetes name, or
    /// an HTTP client that cannot be set up.
    pub fn new(
        base: &str,
        token: Zeroizing<String>,
        ca: Option<&[u8]>,
        namespace: String,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            super::secret_name(&namespace),
            "the namespace is not a Kubernetes name"
        );
        let mut b = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30));
        if let Some(ca) = ca {
            let certs =
                reqwest::Certificate::from_pem_bundle(ca).context("the cluster's CA is not PEM")?;
            anyhow::ensure!(!certs.is_empty(), "the cluster's CA holds no certificate");
            b = b.tls_certs_only(certs);
        }
        Ok(Self {
            http: b.build().context("setting up the Kubernetes client")?,
            base: base.trim_end_matches('/').to_owned(),
            token,
            namespace,
        })
    }

    fn url(&self, name: Option<&str>) -> String {
        let all = format!("{}/api/v1/namespaces/{}/secrets", self.base, self.namespace);
        match name {
            Some(n) => format!("{all}/{n}"),
            None => all,
        }
    }

    /// The data of Secret `name`, decoded, or `None` when there is none.
    ///
    /// # Errors
    ///
    /// A name that is not a Kubernetes name, a refused or failed call, or a
    /// Secret whose data is not base64 text.
    pub async fn get_secret(&self, name: &str) -> anyhow::Result<Option<BTreeMap<String, String>>> {
        anyhow::ensure!(super::secret_name(name), "not a Secret name");
        let r = self
            .http
            .get(self.url(Some(name)))
            .bearer_auth(self.token.as_str())
            .send()
            .await
            .context("asking the Kubernetes API for a Secret")?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        anyhow::ensure!(
            r.status().is_success(),
            "the Kubernetes API answered {} for a Secret",
            r.status()
        );
        let v: Value = r.json().await.context("a Secret that is not JSON")?;
        let mut out = BTreeMap::new();
        if let Some(data) = v.get("data").and_then(Value::as_object) {
            for (k, val) in data {
                let text = val.as_str().context("a Secret's value is not text")?;
                let bytes = B64.decode(text).context("a Secret's value is not base64")?;
                out.insert(
                    k.clone(),
                    String::from_utf8(bytes).context("a Secret's value is not UTF-8")?,
                );
            }
        }
        Ok(Some(out))
    }

    /// Makes Secret `name` with `data`, or replaces the one there.
    ///
    /// # Errors
    ///
    /// A name that is not a Kubernetes name, or a refused or failed call.
    pub async fn put_secret(
        &self,
        name: &str,
        data: &BTreeMap<String, String>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(super::secret_name(name), "not a Secret name");
        let encoded: serde_json::Map<String, Value> = data
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(B64.encode(v))))
            .collect();
        let body = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "type": "Opaque",
            "metadata": {
                "name": name,
                "namespace": self.namespace,
                "labels": { MANAGED_BY.0: MANAGED_BY.1 },
            },
            "data": encoded,
        });
        let r = self
            .http
            .post(self.url(None))
            .bearer_auth(self.token.as_str())
            .json(&body)
            .send()
            .await
            .context("making a Secret")?;
        if r.status() == reqwest::StatusCode::CONFLICT {
            let r = self
                .http
                .put(self.url(Some(name)))
                .bearer_auth(self.token.as_str())
                .json(&body)
                .send()
                .await
                .context("replacing a Secret")?;
            anyhow::ensure!(
                r.status().is_success(),
                "the Kubernetes API answered {} replacing a Secret",
                r.status()
            );
            return Ok(());
        }
        anyhow::ensure!(
            r.status().is_success(),
            "the Kubernetes API answered {} making a Secret",
            r.status()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Json;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::get;

    use super::*;

    type Store = Arc<Mutex<(BTreeMap<String, Value>, Vec<String>)>>;

    fn authorized(h: &HeaderMap) -> bool {
        h.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer the-token")
    }

    /// A fake API server: the Secrets of namespace `ns`, and a log of calls.
    async fn fake() -> (String, Store) {
        let store: Store = Arc::default();
        let app = axum::Router::new()
            .route(
                "/api/v1/namespaces/ns/secrets",
                axum::routing::post(
                    |State(s): State<Store>, h: HeaderMap, Json(body): Json<Value>| async move {
                        if !authorized(&h) {
                            return StatusCode::UNAUTHORIZED;
                        }
                        let name = body["metadata"]["name"].as_str().unwrap().to_owned();
                        let mut s = s.lock().unwrap();
                        s.1.push(format!("POST {name}"));
                        if s.0.contains_key(&name) {
                            return StatusCode::CONFLICT;
                        }
                        s.0.insert(name, body);
                        StatusCode::CREATED
                    },
                ),
            )
            .route(
                "/api/v1/namespaces/ns/secrets/{name}",
                get(
                    |State(s): State<Store>, h: HeaderMap, Path(name): Path<String>| async move {
                        if !authorized(&h) {
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                        let mut s = s.lock().unwrap();
                        s.1.push(format!("GET {name}"));
                        s.0.get(&name)
                            .cloned()
                            .map(Json)
                            .ok_or(StatusCode::NOT_FOUND)
                    },
                )
                .put(
                    |State(s): State<Store>,
                     h: HeaderMap,
                     Path(name): Path<String>,
                     Json(body): Json<Value>| async move {
                        if !authorized(&h) {
                            return StatusCode::UNAUTHORIZED;
                        }
                        let mut s = s.lock().unwrap();
                        s.1.push(format!("PUT {name}"));
                        s.0.insert(name, body);
                        StatusCode::OK
                    },
                ),
            )
            .with_state(Arc::clone(&store));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        (base, store)
    }

    #[tokio::test]
    async fn secrets_are_read_made_and_replaced_with_the_token() {
        let (base, store) = fake().await;
        let k = Kube::new(&base, Zeroizing::new("the-token".into()), None, "ns".into()).unwrap();
        assert_eq!(k.get_secret("crm-tutela").await.unwrap(), None);
        let data = BTreeMap::from([("client_id".to_owned(), "app_1".to_owned())]);
        k.put_secret("crm-tutela", &data).await.unwrap();
        assert_eq!(k.get_secret("crm-tutela").await.unwrap(), Some(data));
        {
            let s = store.lock().unwrap();
            let body = &s.0["crm-tutela"];
            assert_eq!(body["kind"], "Secret");
            assert_eq!(body["metadata"]["namespace"], "ns");
            assert_eq!(body["metadata"]["labels"][MANAGED_BY.0], MANAGED_BY.1);
            // Base64 on the wire, as the API wants it.
            assert_eq!(body["data"]["client_id"], B64.encode("app_1"));
        }
        // There already: replaced.
        let next = BTreeMap::from([("client_id".to_owned(), "app_2".to_owned())]);
        k.put_secret("crm-tutela", &next).await.unwrap();
        assert_eq!(k.get_secret("crm-tutela").await.unwrap(), Some(next));
        assert_eq!(
            store.lock().unwrap().1,
            [
                "GET crm-tutela",
                "POST crm-tutela",
                "GET crm-tutela",
                "POST crm-tutela",
                "PUT crm-tutela",
                "GET crm-tutela"
            ]
        );
    }

    #[tokio::test]
    async fn a_bad_name_is_never_sent_and_a_refusal_is_an_error() {
        let (base, store) = fake().await;
        let k = Kube::new(&base, Zeroizing::new("the-token".into()), None, "ns".into()).unwrap();
        let data = BTreeMap::new();
        for bad in ["../../nodes", "Crm", "a/b", "", "-a"] {
            assert!(k.get_secret(bad).await.is_err(), "{bad}");
            assert!(k.put_secret(bad, &data).await.is_err(), "{bad}");
        }
        assert!(store.lock().unwrap().1.is_empty());
        assert!(Kube::new(&base, Zeroizing::new("t".into()), None, "../ns".into()).is_err());
        let wrong = Kube::new(&base, Zeroizing::new("other".into()), None, "ns".into()).unwrap();
        assert!(wrong.get_secret("crm-tutela").await.is_err());
        assert!(wrong.put_secret("crm-tutela", &data).await.is_err());
        assert!(
            Kube::new(
                &base,
                Zeroizing::new("t".into()),
                Some(b"not pem"),
                "ns".into()
            )
            .is_err()
        );
    }
}
