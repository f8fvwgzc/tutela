//! The Tutela Console: its static files, served on the API port under
//! `/console/` (ADR-0050).
//!
//! The files are the built Console (`console/dist`), read once at start from
//! `TUTELA_CONSOLE_DIR` into memory. A request is answered from that list by
//! its exact path, never by joining a path to the directory, so no request
//! can reach another file. Paths under `/console/` need no token: the page
//! must load before the person has signed in. Every answer carries a strict
//! Content-Security-Policy, `nosniff` and `Referrer-Policy: no-referrer`.
//!
//! `GET /console/config.json` tells the page where people sign in: the
//! realm (an external issuer of the trust file) and the Console's client id,
//! from `tutelad`'s configuration, never from the person.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, bail, ensure};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::Response;
use tutela_contracts::tenant::Issuer;

/// The prefix every Console path starts with.
pub const PREFIX: &str = "/console";
/// The Console's settings, as JSON.
pub const CONFIG_PATH: &str = "/console/config.json";
/// The most files the directory may hold.
const MAX_FILES: usize = 2048;
/// The most bytes all files together may hold.
const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// The deepest a file may be below the directory.
const MAX_DEPTH: usize = 8;
/// Vite puts content-hashed files here: they never change under one name.
const IMMUTABLE_DIR: &str = "assets/";

/// `TUTELA_CONSOLE_DIR`, `TUTELA_CONSOLE_ISSUER` and
/// `TUTELA_CONSOLE_CLIENT_ID`.
#[derive(Clone, Debug)]
pub struct ConsoleConfig {
    /// The built Console.
    pub dir: PathBuf,
    /// The realm people sign in at: an external issuer of the trust file.
    pub issuer: Issuer,
    /// The Console's client id at that realm: a public client.
    pub client_id: String,
    /// The `acr` the Console asks for at sign-in: the first value of
    /// `TUTELA_ADMIN_ACR`.
    pub step_up_acr: String,
    /// `TUTELA_AUDIENCE`: the audience the realm's tokens must have.
    pub audience: String,
}

impl ConsoleConfig {
    /// Checks the settings against the rest of the configuration.
    ///
    /// # Errors
    ///
    /// A missing issuer or client id, an issuer that is not an external
    /// issuer of the trust file, a bad client id, or no `TUTELA_ADMIN_ACR`.
    pub fn from_values(
        dir: &str,
        issuer: Option<&str>,
        client_id: Option<&str>,
        admin_acr: &[String],
        audience: &str,
        external: &[Issuer],
    ) -> anyhow::Result<Self> {
        let issuer: Issuer = issuer
            .context("TUTELA_CONSOLE_ISSUER is required with TUTELA_CONSOLE_DIR")?
            .parse()
            .context("TUTELA_CONSOLE_ISSUER is not a valid issuer")?;
        ensure!(
            external.contains(&issuer),
            "TUTELA_CONSOLE_ISSUER must be an external issuer of the trust file: people sign in \
             there, and tutelad exchanges its tokens"
        );
        let client_id =
            client_id.context("TUTELA_CONSOLE_CLIENT_ID is required with TUTELA_CONSOLE_DIR")?;
        ensure!(
            !client_id.is_empty()
                && client_id.len() <= 128
                && client_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(&b)),
            "TUTELA_CONSOLE_CLIENT_ID must be 1 to 128 letters, digits, '-', '.', '_' or ':'"
        );
        let step_up_acr = admin_acr.first().cloned().context(
            "the Console needs TUTELA_ADMIN_ACR: without it no admin token is ever issued",
        )?;
        Ok(Self {
            dir: PathBuf::from(dir),
            issuer,
            client_id: client_id.to_owned(),
            step_up_acr,
            audience: audience.to_owned(),
        })
    }
}

/// One file of the Console, in memory.
#[derive(Debug)]
struct File {
    body: Bytes,
    content_type: &'static str,
    immutable: bool,
}

/// The loaded Console.
#[derive(Debug)]
pub struct Console {
    /// By path below the directory, `/`-separated, e.g. `assets/app-1f2e.js`.
    files: HashMap<String, File>,
    config_json: Bytes,
    csp: HeaderValue,
}

impl Console {
    /// Reads every file of `config.dir` into memory.
    ///
    /// # Errors
    ///
    /// The directory cannot be read, has no `index.html`, or holds too many
    /// files or bytes.
    pub fn load(config: &ConsoleConfig) -> anyhow::Result<Self> {
        let mut files = HashMap::new();
        let mut total = 0;
        walk(&config.dir, "", 0, &mut files, &mut total)
            .with_context(|| format!("reading TUTELA_CONSOLE_DIR {}", config.dir.display()))?;
        ensure!(
            files.contains_key("index.html"),
            "TUTELA_CONSOLE_DIR {} has no index.html: build the Console first (`make js`)",
            config.dir.display()
        );
        let config_json = serde_json::json!({
            "issuer": config.issuer.as_str(),
            "client_id": config.client_id,
            "step_up_acr": config.step_up_acr,
            "audience": config.audience,
        })
        .to_string();
        let csp = csp(&config.issuer)?;
        Ok(Self {
            files,
            config_json: Bytes::from(config_json),
            csp,
        })
    }

    /// The number of files served.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether no file is served (never, once loaded: `index.html` is there).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The router of every path under [`PREFIX`].
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(serve).with_state(self)
    }

    fn headers(&self, h: &mut HeaderMap) {
        h.insert(header::CONTENT_SECURITY_POLICY, self.csp.clone());
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        h.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        h.insert(
            "cross-origin-opener-policy",
            HeaderValue::from_static("same-origin"),
        );
        h.insert(
            "cross-origin-resource-policy",
            HeaderValue::from_static("same-origin"),
        );
    }

    fn answer(
        &self,
        status: StatusCode,
        content_type: &'static str,
        cache: &'static str,
        body: Body,
    ) -> Response {
        let mut res = Response::new(body);
        *res.status_mut() = status;
        let h = res.headers_mut();
        self.headers(h);
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        res
    }

    fn file(&self, name: &str) -> Option<Response> {
        let f = self.files.get(name)?;
        let cache = if f.immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        Some(self.answer(
            StatusCode::OK,
            f.content_type,
            cache,
            Body::from(f.body.clone()),
        ))
    }

    fn not_found(&self) -> Response {
        self.answer(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "no-cache",
            Body::from("not found"),
        )
    }
}

/// Whether `path` belongs to the Console: `/console` and everything below.
#[must_use]
pub fn owns(path: &str) -> bool {
    path == PREFIX
        || path
            .strip_prefix(PREFIX)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// A page of the Console's own router: one to six segments of lower-case
/// letters, digits, `-` and `_`, with no dot. It gets `index.html`; the
/// page's script shows the page. A file path (with a dot), an encoded or
/// odd character, `..` or an empty segment is never a page.
fn is_page(rest: &str) -> bool {
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let mut n = 0;
    for seg in rest.split('/') {
        n += 1;
        let ok = (1..=64).contains(&seg.len())
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !ok || n > 6 {
            return false;
        }
    }
    n >= 1
}

async fn serve(State(console): State<Arc<Console>>, method: Method, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        let mut res = console.answer(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            "no-cache",
            Body::from("method not allowed"),
        );
        res.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return res;
    }
    let path = uri.path();
    if path == PREFIX {
        let mut res = console.answer(
            StatusCode::PERMANENT_REDIRECT,
            "text/plain; charset=utf-8",
            "no-cache",
            Body::empty(),
        );
        res.headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static("/console/"));
        return res;
    }
    if path == CONFIG_PATH {
        return console.answer(
            StatusCode::OK,
            "application/json",
            "no-store",
            Body::from(console.config_json.clone()),
        );
    }
    let Some(rest) = path.strip_prefix("/console/") else {
        return console.not_found();
    };
    if rest.is_empty() {
        return console
            .file("index.html")
            .unwrap_or_else(|| console.not_found());
    }
    if let Some(res) = console.file(rest) {
        return res;
    }
    if is_page(rest) {
        return console
            .file("index.html")
            .unwrap_or_else(|| console.not_found());
    }
    console.not_found()
}

/// The Content-Security-Policy: everything from this origin only, and the
/// realm's origin for the sign-in calls (discovery and the token endpoint).
fn csp(issuer: &Issuer) -> anyhow::Result<HeaderValue> {
    let origin = origin(issuer.as_str())?;
    HeaderValue::from_str(&format!(
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; \
         font-src 'self'; connect-src 'self' {origin}; object-src 'none'; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ))
    .context("TUTELA_CONSOLE_ISSUER cannot be put in a Content-Security-Policy")
}

/// `scheme://host[:port]` of a URL.
fn origin(url: &str) -> anyhow::Result<String> {
    let (scheme, rest) = url
        .split_once("://")
        .context("TUTELA_CONSOLE_ISSUER is not a URL")?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    ensure!(
        (scheme == "https" || scheme == "http")
            && !host.is_empty()
            && !host.contains('@')
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b)),
        "TUTELA_CONSOLE_ISSUER has no plain origin"
    );
    Ok(format!("{scheme}://{host}"))
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Whether a file name may be served: visible ASCII without `\`, `%` or a
/// leading dot (no hidden files).
fn servable(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~@+".contains(&b))
}

fn walk(
    dir: &Path,
    prefix: &str,
    depth: usize,
    files: &mut HashMap<String, File>,
    total: &mut u64,
) -> anyhow::Result<()> {
    ensure!(depth <= MAX_DEPTH, "more than {MAX_DEPTH} directories deep");
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            tracing::warn!("a Console file name is not UTF-8; it is not served");
            continue;
        };
        if !servable(&name) {
            tracing::warn!(name, "a Console file name is not served");
            continue;
        }
        // `symlink_metadata`: a link is never followed out of the directory.
        let meta = std::fs::symlink_metadata(entry.path())?;
        let path = format!("{prefix}{name}");
        if meta.is_dir() {
            walk(&entry.path(), &format!("{path}/"), depth + 1, files, total)?;
        } else if meta.is_file() {
            ensure!(files.len() < MAX_FILES, "more than {MAX_FILES} files");
            *total += meta.len();
            if *total > MAX_BYTES {
                bail!("more than {MAX_BYTES} bytes");
            }
            let body = std::fs::read(entry.path())?;
            files.insert(
                path.clone(),
                File {
                    body: Bytes::from(body),
                    content_type: content_type(&name),
                    immutable: path.starts_with(IMMUTABLE_DIR),
                },
            );
        } else {
            tracing::warn!(
                path,
                "a Console entry that is not a plain file is not served"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt as _;

    const KC: &str = "https://kc.example.test/realms/acme";

    fn config(dir: &Path) -> ConsoleConfig {
        ConsoleConfig::from_values(
            dir.to_str().unwrap(),
            Some(KC),
            Some("tutela-console"),
            &["mfa".to_owned()],
            "tutela-authz",
            &[KC.parse().unwrap()],
        )
        .unwrap()
    }

    fn built() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tutela-console-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(
            dir.join("index.html"),
            "<!doctype html><title>Console</title>",
        )
        .unwrap();
        std::fs::write(dir.join("assets/app-1f2e3d.js"), "console.log(1)").unwrap();
        std::fs::write(dir.join("assets/app-1f2e3d.css"), "body{}").unwrap();
        std::fs::write(dir.join("favicon.svg"), "<svg/>").unwrap();
        std::fs::write(dir.join(".env"), "SECRET=1").unwrap();
        dir
    }

    async fn get(router: &Router, uri: &str) -> Response {
        router
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body(res: Response) -> String {
        let b = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(b.to_vec()).unwrap()
    }

    fn router(dir: &Path) -> Router {
        Arc::new(Console::load(&config(dir)).unwrap()).router()
    }

    #[tokio::test]
    async fn every_answer_has_the_security_headers() {
        let dir = built();
        let r = router(&dir);
        for uri in [
            "/console/",
            "/console",
            "/console/config.json",
            "/console/scopes",
            "/console/assets/app-1f2e3d.js",
            "/console/nothing.js",
        ] {
            let res = get(&r, uri).await;
            let h = res.headers();
            let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
            assert!(csp.contains("default-src 'self'"), "{uri}: {csp}");
            assert!(csp.contains("script-src 'self';"), "{uri}: {csp}");
            assert!(csp.contains("style-src 'self';"), "{uri}: {csp}");
            assert!(
                csp.contains("connect-src 'self' https://kc.example.test;"),
                "{csp}"
            );
            assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
            assert!(csp.contains("base-uri 'none'"), "{csp}");
            assert!(!csp.contains("unsafe"), "{csp}");
            assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{uri}");
            assert_eq!(h[header::REFERRER_POLICY], "no-referrer", "{uri}");
            assert_eq!(h[header::X_FRAME_OPTIONS], "DENY", "{uri}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn files_pages_and_the_config() {
        let dir = built();
        let r = router(&dir);
        let res = get(&r, "/console/").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-cache");
        assert!(body(res).await.contains("<title>Console</title>"));

        let res = get(&r, "/console/assets/app-1f2e3d.js").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            res.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(body(res).await, "console.log(1)");

        // Pages of the Console's own router get index.html.
        for page in [
            "/console/scopes",
            "/console/roles/",
            "/console/model/history",
            "/console/callback",
        ] {
            let res = get(&r, page).await;
            assert_eq!(res.status(), StatusCode::OK, "{page}");
            assert!(body(res).await.contains("<title>Console</title>"), "{page}");
        }

        let res = get(&r, "/console").await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(res.headers()[header::LOCATION], "/console/");

        let res = get(&r, "/console/config.json").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
        let v: serde_json::Value = serde_json::from_str(&body(res).await).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "issuer": KC, "client_id": "tutela-console",
                "step_up_acr": "mfa", "audience": "tutela-authz",
            })
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_missing_file_or_a_traversal_is_not_found() {
        let dir = built();
        // A file next to the directory, which no path may reach.
        let secret = dir.with_extension("secret");
        std::fs::write(&secret, "SECRET").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, dir.join("assets/link.js")).unwrap();
        let r = router(&dir);
        for uri in [
            "/console/assets/missing.js",
            "/console/.env",
            "/console/../Cargo.toml",
            "/console/assets/../../secret",
            "/console/..%2f..%2fCargo.toml",
            "/console/%2e%2e/%2e%2e/etc/passwd",
            "/console/assets/..%5c..%5csecret",
            "/console//index.html",
            "/console/assets/link.js",
            "/console/Scopes",
            "/console/a/b/c/d/e/f/g",
        ] {
            let res = get(&r, uri).await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(res.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
            assert!(!body(res).await.contains("SECRET"), "{uri}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_file(secret).unwrap();
    }

    #[tokio::test]
    async fn only_get_and_head() {
        let dir = built();
        let r = router(&dir);
        let res = r
            .clone()
            .oneshot(Request::post("/console/").body(Body::from("x")).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(res.headers()[header::ALLOW], "GET, HEAD");
        let res = r
            .oneshot(Request::head("/console/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_refuses_a_directory_without_index_html() {
        let dir = std::env::temp_dir().join(format!("tutela-console-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let e = Console::load(&config(&dir)).unwrap_err();
        assert!(format!("{e:#}").contains("has no index.html"), "{e:#}");
        std::fs::remove_dir_all(&dir).unwrap();
        let e = Console::load(&config(&dir)).unwrap_err();
        assert!(
            format!("{e:#}").contains("reading TUTELA_CONSOLE_DIR"),
            "{e:#}"
        );
    }

    #[test]
    fn the_settings_are_checked() {
        let ext: Vec<Issuer> = vec![KC.parse().unwrap()];
        let acr = vec!["mfa".to_owned()];
        let ok = |iss: Option<&str>, id: Option<&str>, acr: &[String]| {
            ConsoleConfig::from_values("/x", iss, id, acr, "tutela-authz", &ext)
        };
        assert!(ok(Some(KC), Some("tutela-console"), &acr).is_ok());
        let e = ok(None, Some("c"), &acr).unwrap_err();
        assert!(
            e.to_string().contains("TUTELA_CONSOLE_ISSUER is required"),
            "{e}"
        );
        let e = ok(Some("https://other.example.test/realms/x"), Some("c"), &acr).unwrap_err();
        assert!(
            e.to_string().contains("external issuer of the trust file"),
            "{e}"
        );
        let e = ok(Some(KC), None, &acr).unwrap_err();
        assert!(
            e.to_string()
                .contains("TUTELA_CONSOLE_CLIENT_ID is required"),
            "{e}"
        );
        let e = ok(Some(KC), Some("a b"), &acr).unwrap_err();
        assert!(
            e.to_string().contains("TUTELA_CONSOLE_CLIENT_ID must be"),
            "{e}"
        );
        let e = ok(Some(KC), Some("c"), &[]).unwrap_err();
        assert!(e.to_string().contains("TUTELA_ADMIN_ACR"), "{e}");
    }

    #[test]
    fn origins_and_pages() {
        assert_eq!(origin(KC).unwrap(), "https://kc.example.test");
        assert_eq!(
            origin("http://127.0.0.1:18555/realms/t").unwrap(),
            "http://127.0.0.1:18555"
        );
        assert!(origin("https://user@kc.example.test/x").is_err());
        assert!(owns("/console") && owns("/console/") && owns("/console/x"));
        assert!(!owns("/consoles") && !owns("/v1/console") && !owns("/"));
        assert!(is_page("scopes") && is_page("scopes/") && is_page("model/history"));
        assert!(!is_page("") && !is_page("a.js") && !is_page("A") && !is_page("a//b"));
        assert!(!is_page("..") && !is_page("a/../b") && !is_page("%2e"));
    }
}
