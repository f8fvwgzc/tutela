//! The CLI against `tutelad` (Phase B, ADR-0045): `tutela apply` with the
//! impact report, approvals and two-person publish, and `tutela apps`.
//!
//! The service is `TUTELA_URL` (or `--server`); the caller's token is
//! `TUTELA_TOKEN` (or `--token`): a pipeline's service token (`tutela-authz`)
//! or a person's admin token after step-up (ADR-0032). `https` is required,
//! except on a loopback host. A refusal of the service is printed as its
//! problem code and detail; a token is never printed.

use std::io::Write;
use std::time::Duration;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::CliError;

/// How long one call may take.
const TIMEOUT: Duration = Duration::from_secs(60);

/// `tutelad`'s API, as one caller.
pub struct Service {
    base: String,
    token: Zeroizing<String>,
    http: reqwest::Client,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

/// A refusal of the service: its status and its problem code.
#[derive(Debug)]
pub struct Refused {
    /// The HTTP status.
    pub status: u16,
    /// The problem's code (`urn:tutela:problem:<code>`).
    pub code: String,
    /// The problem's detail or title.
    pub detail: String,
}

fn loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl Service {
    /// The service at `url`, called with `token`.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] for a URL that is not `https` (or `http` on a
    /// loopback host), or an empty token.
    pub fn new(url: &str, token: &str) -> Result<Self, CliError> {
        let bad = || CliError::Usage("--server is an https URL (http only on localhost)".into());
        let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
        let name = if host.starts_with('[') {
            host.split_once(']')
                .map_or(host, |(h, _)| h)
                .trim_start_matches('[')
        } else {
            host.split(':').next().unwrap_or_default()
        };
        match scheme {
            "https" => {}
            "http" if loopback(name) => {}
            _ => return Err(bad()),
        }
        if rest.contains('@') {
            return Err(CliError::Usage("--server holds no credentials".into()));
        }
        if token.trim().is_empty() {
            return Err(CliError::Usage(
                "a token is required: --token or TUTELA_TOKEN".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| CliError::Usage("the HTTP client could not start".into()))?;
        Ok(Self {
            base: url.trim_end_matches('/').to_owned(),
            token: Zeroizing::new(token.trim().to_owned()),
            http,
        })
    }

    /// Calls `path` and answers its JSON, or the service's refusal.
    ///
    /// # Errors
    ///
    /// [`CliError::Service`] when the service refused, [`CliError::Network`]
    /// when it could not be reached.
    pub async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        let mut r = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(self.token.as_str());
        if let Some(b) = body {
            r = r.json(b);
        }
        let res = r
            .send()
            .await
            .map_err(|_| CliError::Network(format!("{} could not be reached", self.base)))?;
        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|_| CliError::Network("the answer could not be read".into()))?;
        let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(json);
        }
        let code = json["type"]
            .as_str()
            .and_then(|t| t.strip_prefix("urn:tutela:problem:"))
            .unwrap_or(if status.as_u16() == 401 {
                "invalid_token"
            } else {
                "error"
            })
            .to_owned();
        let detail = json["detail"]
            .as_str()
            .or_else(|| json["title"].as_str())
            .unwrap_or("no detail")
            .to_owned();
        Err(CliError::Service(Refused {
            status: status.as_u16(),
            code,
            detail,
        }))
    }
}

/// How `apply` against `tutelad` ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// A new version is active.
    Published,
    /// A proposal waits for a second person (two-person publish).
    Proposed,
    /// Nothing to do: the model is the same.
    Unchanged,
    /// Shown only (`--dry-run`).
    Shown,
    /// A widening change without an approval token: nothing written.
    Refused,
}

/// What `apply` sends.
pub struct ApplyOptions<'a> {
    /// The manifest's text.
    pub source: &'a str,
    /// An approval token from `tutela approve --tenant <tid>`.
    pub approval: Option<&'a str>,
    /// Show the diff and the report only.
    pub dry_run: bool,
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// `tutela apply --server`: the diff and the impact report from
/// `POST /v1/models/impact`, then a publish with `expected_version` and the
/// approval token, or a proposal when the tenant has two-person publish on.
/// A widening change without a token is refused here, before anything is
/// sent, and the service refuses it too.
///
/// # Errors
///
/// A [`CliError`]: the manifest does not compile, or the service refused
/// for another reason than a missing approval.
pub async fn apply(
    svc: &Service,
    o: &ApplyOptions<'_>,
    out: &mut dyn Write,
) -> Result<Applied, CliError> {
    let model = crate::check(o.source, &mut std::io::sink())?;
    let me = svc.call(reqwest::Method::GET, "/v1/whoami", None).await?;
    let change = svc
        .call(
            reqwest::Method::POST,
            "/v1/models/impact",
            Some(&json!({"source": o.source})),
        )
        .await?;
    let (from, to, class) = (s(&change["from"]), s(&change["to"]), s(&change["class"]));
    writeln!(out, "tenant:  {}", s(&me["tid"]))?;
    writeln!(out, "version: {} -> new", change["version"])?;
    writeln!(out, "from:    {from}")?;
    writeln!(out, "to:      {to}")?;
    writeln!(out, "class:   {class}")?;
    if from == to {
        writeln!(out, "no change")?;
        return Ok(Applied::Unchanged);
    }
    let diff = s(&change["diff"]);
    if !diff.is_empty() {
        writeln!(out, "diff:")?;
        for line in diff.lines() {
            writeln!(out, "  {line}")?;
        }
    }
    let impact = &change["impact"];
    writeln!(out, "impact:")?;
    let summary = impact["summary"].as_array().cloned().unwrap_or_default();
    if summary.is_empty() {
        writeln!(out, "  nobody gains or loses anything")?;
    }
    for line in &summary {
        writeln!(out, "  {}", s(line))?;
    }
    if impact["complete"] == Value::Bool(false) {
        writeln!(
            out,
            "  (the report stopped at its bound: there may be more)"
        )?;
    }
    let widening = class == "widening";
    if widening && o.approval.is_none() {
        writeln!(
            out,
            "refused: this change widens access and needs an approval token."
        )?;
        writeln!(
            out,
            "ask an approver to run: tutela approve --app {} --from {from} --to {to} --tenant {} --key <their key file>",
            model.app(),
            s(&me["tid"])
        )?;
        return Ok(Applied::Refused);
    }
    if o.dry_run {
        writeln!(out, "dry run: nothing written")?;
        return Ok(Applied::Shown);
    }
    let settings = svc
        .call(reqwest::Method::GET, "/v1/models/settings", None)
        .await?;
    let body = json!({
        "source": o.source,
        "expected_version": change["version"],
        "approval": o.approval,
    });
    if settings["two_person"] == Value::Bool(true) {
        let p = svc
            .call(reqwest::Method::POST, "/v1/models/proposals", Some(&body))
            .await?;
        writeln!(out, "proposed: {} (two-person publish is on)", s(&p["id"]))?;
        writeln!(
            out,
            "a second person approves it: POST /v1/models/proposals/{}/approve",
            s(&p["id"])
        )?;
        return Ok(Applied::Proposed);
    }
    match svc
        .call(reqwest::Method::POST, "/v1/models/publish", Some(&body))
        .await
    {
        Ok(p) => {
            writeln!(
                out,
                "published: version {} at revision {}",
                p["version"], p["rev"]
            )?;
            Ok(Applied::Published)
        }
        Err(CliError::Service(r)) if r.code == "approval_required" => {
            writeln!(out, "refused by the service: {}", r.detail)?;
            Ok(Applied::Refused)
        }
        Err(e) => Err(e),
    }
}

/// `tutela apps create`: a new app; its client secret is printed this once.
///
/// # Errors
///
/// A [`CliError`].
pub async fn apps_create(svc: &Service, name: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let v = svc
        .call(
            reqwest::Method::POST,
            "/v1/admin/apps",
            Some(&json!({"name": name})),
        )
        .await?;
    print_secret(&v, out)
}

/// `tutela apps rotate`: a new client secret, printed this once.
///
/// # Errors
///
/// A [`CliError`].
pub async fn apps_rotate(
    svc: &Service,
    id: &str,
    overlap_secs: Option<u64>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let v = svc
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{}/rotate", path_part(id)?),
            Some(&json!({"overlap_secs": overlap_secs})),
        )
        .await?;
    print_secret(&v, out)
}

fn print_secret(v: &Value, out: &mut dyn Write) -> Result<(), CliError> {
    writeln!(out, "client_id:     {}", s(&v["app"]["client_id"]))?;
    writeln!(out, "principal:     {}", s(&v["app"]["principal"]))?;
    writeln!(out, "client_secret: {}", s(&v["client_secret"]))?;
    writeln!(
        out,
        "the secret is shown this once: keep it in your secret store now"
    )?;
    Ok(())
}

/// `tutela apps list`.
///
/// # Errors
///
/// A [`CliError`].
pub async fn apps_list(svc: &Service, out: &mut dyn Write) -> Result<(), CliError> {
    let v = svc
        .call(reqwest::Method::GET, "/v1/admin/apps", None)
        .await?;
    for a in v["apps"].as_array().into_iter().flatten() {
        let state = if a["disabled_at"].is_string() {
            "disabled"
        } else {
            "enabled"
        };
        writeln!(
            out,
            "{}  {}  {}  {state}",
            s(&a["client_id"]),
            s(&a["principal"]),
            s(&a["name"])
        )?;
    }
    Ok(())
}

/// `tutela apps disable`.
///
/// # Errors
///
/// A [`CliError`].
pub async fn apps_disable(svc: &Service, id: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let v = svc
        .call(
            reqwest::Method::POST,
            &format!("/v1/admin/apps/{}/disable", path_part(id)?),
            None,
        )
        .await?;
    writeln!(out, "disabled: {}", s(&v["client_id"]))?;
    Ok(())
}

/// A client id as a URL path segment: `app_` and a UUID's characters only.
fn path_part(id: &str) -> Result<&str, CliError> {
    if id.starts_with("app_")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Ok(id)
    } else {
        Err(CliError::Usage(format!(
            "`{id}` is not a client id (app_<uuidv7>)"
        )))
    }
}
