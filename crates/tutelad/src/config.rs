//! Configuration: `TUTELA_*` variables and the trust file.
//!
//! Secrets stay out of `Debug`: the database URL holds a password.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::cache::Limits;
use crate::keys::{KeyRing, OwnJwks};
use anyhow::{Context as _, anyhow, bail, ensure};
use serde::Deserialize;
use tutela_contracts::claims::{
    Audience, MAX_ACCESS_TOKEN_LIFETIME_SECS, MAX_DELEGATED_TOKEN_LIFETIME_SECS,
};
use tutela_contracts::tenant::{Issuer, TenantId, TrustList};
use tutela_sdk::{
    Alg, CacheRules, Clock, IssuerConfig, JwksSource, SafenetSource, SystemClock, Verifier,
    VerifierConfig,
};
use tutela_vault::{LocalKms, Vault};
use zeroize::Zeroizing;

/// The planned audience of the check API (CONTRACTS.md 7.1).
pub const DEFAULT_AUDIENCE: &str = "tutela-authz";

/// Everything `tutelad` reads at start-up.
#[derive(Clone)]
pub struct Config {
    /// `TUTELA_DATABASE_URL`: a non-owner role (THREAT-MODEL.md TM-14).
    pub database_url: String,
    /// `TUTELA_LISTEN`: the API port. Every request needs a token.
    pub listen: SocketAddr,
    /// `TUTELA_OPS_LISTEN`: health, readiness and metrics. Keep it out of
    /// the public load balancer.
    pub ops_listen: SocketAddr,
    /// `TUTELA_AUDIENCE`: the `aud` this service accepts.
    pub audience: Audience,
    /// `TUTELA_TRUST_FILE`: the issuers, read and checked.
    pub trust: TrustFile,
    /// `TUTELA_DEV_MODE=1`: `http` issuers and JWKS on loopback.
    pub dev_mode: bool,
    /// `TUTELA_LOG`: the log filter.
    pub log: String,
    /// `TUTELA_DB_POOL_SIZE`: the most connections per replica.
    pub pool_size: usize,
    /// `TUTELA_REQUEST_TIMEOUT_SECS`: the longest a request may run.
    pub request_timeout: Duration,
    /// `TUTELA_SHUTDOWN_DRAIN_SECS`: how long readiness fails before the
    /// listeners stop, so a load balancer can move away.
    pub shutdown_drain: Duration,
    /// `TUTELA_SHUTDOWN_TIMEOUT_SECS`: how long running requests may finish.
    pub shutdown_timeout: Duration,
    /// `TUTELA_EXPIRY_SWEEP_SECS`: how often expired assignments are removed
    /// and the revision bumped. This is the worst case for a cache that does
    /// not honour `next_expiry` (ADR-0020).
    pub expiry_sweep: Duration,
    /// `TUTELA_REVISION_CHECK_MS`, `TUTELA_MAX_AGE_READ_SECS` and
    /// `TUTELA_MAX_AGE_WRITE_SECS`: how current an answer must be.
    pub limits: Limits,
    /// `TUTELA_IMPACT_MAX_WORK`: the most steps one impact report takes
    /// (ADR-0027). A report that reaches it says it is not complete.
    pub impact_work: usize,
    /// `TUTELA_ISSUER`: this service's own issuer, the `iss` of every token
    /// it signs (ADR-0030). Its tokens are trusted for every tenant of the
    /// directory under it.
    pub issuer: Issuer,
    /// `TUTELA_MASTER_KEY` and `TUTELA_KEY_PEPPER`: required, never made up
    /// (THREAT-MODEL.md TM-22).
    pub secrets: Secrets,
    /// `TUTELA_JWKS_CACHE_SECS`: how long a verifier may keep the JWKS. A
    /// rotation publishes the next key twice this long before it signs.
    pub jwks_cache: Duration,
    /// `TUTELA_KEY_REFRESH_SECS`: how often a replica reads the signing keys
    /// again, so a rotation or a denial elsewhere reaches it.
    pub key_refresh: Duration,
    /// `TUTELA_TOKEN_TTL_SECS`: the life of an access token from token
    /// exchange, at most 600 s (CONTRACTS.md 4.2). It never outlives the
    /// token it was exchanged for.
    pub token_ttl: Duration,
    /// `TUTELA_ADMIN_ACR`: the `acr` values that count as step-up MFA for an
    /// admin token (CONTRACTS.md 4.4, ADR-0032), comma-separated. Empty:
    /// no admin token is issued or accepted for a person.
    pub admin_acr: Vec<String>,
    /// `TUTELA_DELEGATED_TTL_SECS`: the life of a delegated token, 60 to
    /// 120 s (CONTRACTS.md 4.5). It never outlives the person's token or the
    /// agent's.
    pub delegated_ttl: Duration,
    /// `TUTELA_WEBHOOK_POLL_MS`: how often a replica delivers events to
    /// webhooks (ADR-0036). `0` turns delivery off on this replica.
    pub webhook_poll: Duration,
    /// `TUTELA_EVENT_RETENTION_SECS`: how long events and ended webhook
    /// deliveries are kept, at least two days (retries last 24 hours). An SSE
    /// client that resumes from an older event gets `reset`.
    pub event_retention: Duration,
    /// `TUTELA_EVENTS_POLL_MS`, `TUTELA_SSE_MAX_STREAMS`,
    /// `TUTELA_SSE_MAX_SECS` and `TUTELA_SSE_BUFFER`: how `GET /v1/events`
    /// streams behave (ADR-0037).
    pub streams: crate::stream::StreamSettings,
    /// `TUTELA_BUNDLE_TTL_SECS`: the longest a signed bundle lasts, 1 to
    /// 3600 s (ADR-0038). A bundle ends sooner at the first assignment in
    /// it that expires.
    pub bundle_ttl: Duration,
    /// `TUTELA_PURGE_GRACE_SECS`: how long a soft-deleted tenant or org
    /// keeps its data before the purge (ADR-0041), at least one hour;
    /// default 30 days.
    pub purge_grace: Duration,
    /// `TUTELA_AUDIT_VERIFY_SECS`: how often every audit chain is walked
    /// and a broken link reported (ADR-0034); default one hour, `0` off.
    pub audit_verify: Duration,
    /// `TUTELA_LEDGER_URL`, `TUTELA_LEDGER_TOKEN` and `TUTELA_AUDIT_KEY`:
    /// forwarding of audit records to attache's evidence ledger (ADR-0039).
    /// `None`: off.
    pub ledger: Option<crate::ledger::LedgerConfig>,
}

/// The secrets `tutelad` needs at start-up. `Debug` shows none of them.
#[derive(Clone)]
pub struct Secrets {
    master: Zeroizing<String>,
    master_previous: Option<Zeroizing<String>>,
    pepper: Zeroizing<Vec<u8>>,
    pepper_version: u32,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("pepper_version", &self.pepper_version)
            .finish_non_exhaustive()
    }
}

impl Secrets {
    /// From the values of `TUTELA_MASTER_KEY`, `TUTELA_MASTER_KEY_PREVIOUS`,
    /// `TUTELA_KEY_PEPPER` and `TUTELA_KEY_PEPPER_VERSION`.
    ///
    /// # Errors
    ///
    /// A missing master key or pepper, a master key that is not 32 bytes, a
    /// pepper under 32 bytes, a pepper that is the master key (CONTRACTS.md
    /// 5.4: it is never derived from it), or a bad version. The text names
    /// the variable, never its value.
    pub fn from_values(
        master: Option<&str>,
        master_previous: Option<&str>,
        pepper: Option<&str>,
        pepper_version: Option<&str>,
    ) -> anyhow::Result<Self> {
        fn present(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|v| !v.is_empty())
        }
        // The vault's own checks, so the two never disagree.
        LocalKms::from_values(master, master_previous).map_err(|e| anyhow!("{e}"))?;
        let master = present(master).context("TUTELA_MASTER_KEY is not set")?;
        let pepper_text =
            present(pepper).context("TUTELA_KEY_PEPPER is not set; Tutela never makes one up")?;
        let pepper = decode_secret(pepper_text)
            .filter(|p| p.len() >= 32)
            .context("TUTELA_KEY_PEPPER must be at least 32 random bytes, as base64 or hex")?;
        ensure!(
            decode_secret(master).is_none_or(|m| *m != *pepper),
            "TUTELA_KEY_PEPPER must not be the master key: it is separate and never derived \
             from it (CONTRACTS.md 5.4)"
        );
        let pepper_version = match present(pepper_version) {
            None => 1,
            Some(v) => v
                .parse::<u32>()
                .ok()
                .filter(|v| *v >= 1)
                .context("TUTELA_KEY_PEPPER_VERSION must be a whole number from 1")?,
        };
        Ok(Self {
            master: Zeroizing::new(master.to_owned()),
            master_previous: present(master_previous).map(|p| Zeroizing::new(p.to_owned())),
            pepper,
            pepper_version,
        })
    }

    /// The vault over the master key.
    ///
    /// # Errors
    ///
    /// Never for values that [`Secrets::from_values`] accepted.
    pub fn vault(&self) -> anyhow::Result<Vault> {
        LocalKms::from_values(
            Some(self.master.as_str()),
            self.master_previous.as_ref().map(|p| p.as_str()),
        )
        .map(Vault::new)
        .map_err(|e| anyhow!("{e}"))
    }

    /// The API-key pepper and its version (CONTRACTS.md 5.4). API keys come
    /// with part 4; the pepper is required now so a deployment never runs
    /// without one (TM-22).
    #[must_use]
    pub fn pepper(&self) -> (&[u8], u32) {
        (&self.pepper, self.pepper_version)
    }
}

/// Bytes from hex (an even number of digits) or base64 (standard or
/// URL-safe, with or without padding).
fn decode_secret(v: &str) -> Option<Zeroizing<Vec<u8>>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    if v.len().is_multiple_of(2) && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (0..v.len() / 2)
            .map(|i| {
                v.get(2 * i..2 * i + 2)
                    .and_then(|d| u8::from_str_radix(d, 16).ok())
            })
            .collect::<Option<Vec<u8>>>()
            .map(Zeroizing::new);
    }
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .into_iter()
        .find_map(|engine| engine.decode(v).ok())
        .map(Zeroizing::new)
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("ops_listen", &self.ops_listen)
            .field("audience", &self.audience)
            .field("dev_mode", &self.dev_mode)
            .field("log", &self.log)
            .field("pool_size", &self.pool_size)
            .field("limits", &self.limits)
            .field("issuer", &self.issuer)
            .field("secrets", &self.secrets)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// From the process environment.
    ///
    /// # Errors
    ///
    /// A missing or bad variable, or a bad trust file. The text never holds
    /// a value of `TUTELA_DATABASE_URL`.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// From any source of variables.
    ///
    /// # Errors
    ///
    /// As [`Config::from_env`].
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let get = |name: &str| var(name).filter(|v| !v.is_empty());
        let need = |name: &str| get(name).with_context(|| format!("{name} is not set"));
        let dev_mode = match get("TUTELA_DEV_MODE").as_deref() {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => bail!("TUTELA_DEV_MODE must be 0 or 1"),
        };
        let audience = get("TUTELA_AUDIENCE").unwrap_or_else(|| DEFAULT_AUDIENCE.to_owned());
        let trust_path = PathBuf::from(need("TUTELA_TRUST_FILE")?);
        let expiry_sweep = seconds(&get, "TUTELA_EXPIRY_SWEEP_SECS", "30")?;
        ensure!(
            !expiry_sweep.is_zero(),
            "TUTELA_EXPIRY_SWEEP_SECS must be at least 1"
        );
        let limits = Limits {
            check_every: Duration::from_millis(parsed(&get, "TUTELA_REVISION_CHECK_MS", "1000")?),
            max_age_read: seconds(&get, "TUTELA_MAX_AGE_READ_SECS", "60")?,
            max_age_write: seconds(&get, "TUTELA_MAX_AGE_WRITE_SECS", "10")?,
        };
        ensure!(
            limits.check_every <= limits.max_age_write,
            "TUTELA_REVISION_CHECK_MS must not be above TUTELA_MAX_AGE_WRITE_SECS"
        );
        ensure!(
            limits.max_age_write <= limits.max_age_read,
            "writes fail closed sooner than reads: TUTELA_MAX_AGE_WRITE_SECS must not be above \
             TUTELA_MAX_AGE_READ_SECS"
        );
        let impact_work = parsed(
            &get,
            "TUTELA_IMPACT_MAX_WORK",
            &tutela_pdp::MAX_IMPACT_WORK.to_string(),
        )?;
        ensure!(
            impact_work >= 1,
            "TUTELA_IMPACT_MAX_WORK must be at least 1"
        );
        let secrets = Secrets::from_values(
            var("TUTELA_MASTER_KEY").as_deref(),
            var("TUTELA_MASTER_KEY_PREVIOUS").as_deref(),
            var("TUTELA_KEY_PEPPER").as_deref(),
            var("TUTELA_KEY_PEPPER_VERSION").as_deref(),
        )?;
        let trust = TrustFile::read(&trust_path, dev_mode)?;
        let issuer = own_issuer(&need("TUTELA_ISSUER")?, dev_mode, &trust)?;
        let audience: Audience = audience.parse().context("TUTELA_AUDIENCE is not valid")?;
        ensure!(
            audience != Audience::TUTELA_ADMIN,
            "TUTELA_AUDIENCE must not be tutela-admin, which has its own rules"
        );
        ensure!(
            !trust.audience.iter().any(|a| a.name == audience),
            "the trust file names TUTELA_AUDIENCE as an [[audience]]; it is always served"
        );
        let jwks_cache = seconds(&get, "TUTELA_JWKS_CACHE_SECS", "300")?;
        ensure!(
            !jwks_cache.is_zero(),
            "TUTELA_JWKS_CACHE_SECS must be at least 1"
        );
        let token_ttl = seconds(&get, "TUTELA_TOKEN_TTL_SECS", "300")?;
        ensure!(
            (60..=MAX_ACCESS_TOKEN_LIFETIME_SECS).contains(&token_ttl.as_secs()),
            "TUTELA_TOKEN_TTL_SECS must be from 60 to 600"
        );
        let admin_acr: Vec<String> = get("TUTELA_ADMIN_ACR")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .collect();
        ensure!(
            admin_acr
                .iter()
                .all(|v| v.len() <= 64 && v.bytes().all(|b| b.is_ascii_graphic())),
            "TUTELA_ADMIN_ACR is a comma-separated list of acr values"
        );
        let delegated_ttl = seconds(&get, "TUTELA_DELEGATED_TTL_SECS", "90")?;
        ensure!(
            (60..=MAX_DELEGATED_TOKEN_LIFETIME_SECS).contains(&delegated_ttl.as_secs()),
            "TUTELA_DELEGATED_TTL_SECS must be from 60 to 120"
        );
        let key_refresh = seconds(&get, "TUTELA_KEY_REFRESH_SECS", "10")?;
        ensure!(
            !key_refresh.is_zero() && key_refresh <= jwks_cache,
            "TUTELA_KEY_REFRESH_SECS must be from 1 to TUTELA_JWKS_CACHE_SECS"
        );
        let webhook_poll = Duration::from_millis(parsed(&get, "TUTELA_WEBHOOK_POLL_MS", "1000")?);
        let event_retention = seconds(&get, "TUTELA_EVENT_RETENTION_SECS", "604800")?;
        let ledger = match get("TUTELA_LEDGER_URL").filter(|v| !v.is_empty()) {
            None => None,
            Some(url) => {
                let token = get("TUTELA_LEDGER_TOKEN")
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        anyhow!("TUTELA_LEDGER_TOKEN is required with TUTELA_LEDGER_URL")
                    })?;
                let key = get("TUTELA_AUDIT_KEY")
                    .and_then(|k| {
                        use base64::Engine as _;
                        base64::engine::general_purpose::STANDARD
                            .decode(k.trim())
                            .ok()
                    })
                    .filter(|k| k.len() == 32)
                    .ok_or_else(|| {
                        anyhow!(
                            "TUTELA_AUDIT_KEY must be 32 bytes in base64 with TUTELA_LEDGER_URL"
                        )
                    })?;
                Some(crate::ledger::LedgerConfig {
                    url,
                    token: Zeroizing::new(token),
                    key: Zeroizing::new(key),
                })
            }
        };
        let bundle_ttl = seconds(&get, "TUTELA_BUNDLE_TTL_SECS", "300")?;
        ensure!(
            (1..=3600).contains(&bundle_ttl.as_secs()),
            "TUTELA_BUNDLE_TTL_SECS must be from 1 to 3600"
        );
        let purge_grace = seconds(&get, "TUTELA_PURGE_GRACE_SECS", "2592000")?;
        ensure!(
            purge_grace >= Duration::from_secs(3600),
            "TUTELA_PURGE_GRACE_SECS must be at least 3600 (one hour)"
        );
        let audit_verify = seconds(&get, "TUTELA_AUDIT_VERIFY_SECS", "3600")?;
        let streams = crate::stream::StreamSettings {
            poll: Duration::from_millis(parsed(&get, "TUTELA_EVENTS_POLL_MS", "500")?),
            max_streams: parsed(&get, "TUTELA_SSE_MAX_STREAMS", "1000")?,
            max_age: seconds(&get, "TUTELA_SSE_MAX_SECS", "900")?,
            buffer: parsed(&get, "TUTELA_SSE_BUFFER", "256")?,
            ..crate::stream::StreamSettings::default()
        };
        ensure!(
            !streams.poll.is_zero() && !streams.max_age.is_zero() && streams.buffer > 0,
            "TUTELA_EVENTS_POLL_MS, TUTELA_SSE_MAX_SECS and TUTELA_SSE_BUFFER must be at least 1"
        );
        ensure!(
            event_retention >= Duration::from_secs(2 * 24 * 3600),
            "TUTELA_EVENT_RETENTION_SECS must be at least 172800 (two days)"
        );
        Ok(Self {
            database_url: need("TUTELA_DATABASE_URL")?,
            listen: parsed(&get, "TUTELA_LISTEN", "0.0.0.0:8080")?,
            ops_listen: parsed(&get, "TUTELA_OPS_LISTEN", "0.0.0.0:9090")?,
            audience,
            trust,
            dev_mode,
            log: get("TUTELA_LOG").unwrap_or_else(|| "info".to_owned()),
            pool_size: parsed(&get, "TUTELA_DB_POOL_SIZE", "16")?,
            request_timeout: seconds(&get, "TUTELA_REQUEST_TIMEOUT_SECS", "30")?,
            shutdown_drain: seconds(&get, "TUTELA_SHUTDOWN_DRAIN_SECS", "5")?,
            shutdown_timeout: seconds(&get, "TUTELA_SHUTDOWN_TIMEOUT_SECS", "30")?,
            expiry_sweep,
            limits,
            impact_work,
            issuer,
            secrets,
            jwks_cache,
            key_refresh,
            token_ttl,
            admin_acr,
            delegated_ttl,
            webhook_poll,
            event_retention,
            streams,
            bundle_ttl,
            purge_grace,
            audit_verify,
            ledger,
        })
    }

    /// The verifier's settings: the trust file's issuers, and this service's
    /// own issuer, trusted for every tenant of its directory (each request's
    /// tenant is checked against the directory when it enters it).
    #[must_use]
    pub fn verifier_config(&self) -> VerifierConfig {
        let mut config = self.trust.verifier_config(self.audience.clone());
        // `own_issuer` refused an issuer of the trust file, and a dev-only
        // issuer outside dev mode, so this cannot fail.
        if config.trust.insert_directory(self.issuer.clone()).is_err() {
            tracing::error!("the own issuer could not be trusted");
        }
        config.issuers.push(IssuerConfig {
            iss: self.issuer.clone(),
            jwks_uri: crate::keys::jwks_url(&self.issuer),
            algs: vec![Alg::Es256],
            external: false,
            allow_typ_jwt: false,
        });
        config
    }

    /// The token verifier: this service's own keys from `ring`, every other
    /// issuer's JWKS through `tutela-safenet` under this config's rules.
    ///
    /// # Errors
    ///
    /// When the JWKS client cannot be set up.
    pub fn verifier(&self, ring: Arc<KeyRing>) -> anyhow::Result<Verifier> {
        Ok(self.verifier_with(ring, Arc::new(self.jwks_source()?), Arc::new(SystemClock)))
    }

    /// Where other issuers' JWKS come from: `tutela-safenet`, under this
    /// config's rules.
    ///
    /// # Errors
    ///
    /// When the JWKS client cannot be set up.
    pub fn jwks_source(&self) -> anyhow::Result<SafenetSource> {
        let mut policy = tutela_safenet::Policy::new();
        if self.dev_mode {
            policy = policy.dev_loopback();
        }
        for host in &self.trust.private_hosts {
            policy = policy
                .allow_private_host(host)
                .with_context(|| format!("private host {host:?} in the trust file"))?;
        }
        SafenetSource::new(policy).context("setting up the JWKS client")
    }

    /// The token verifier with another JWKS source for the other issuers,
    /// and another clock: for tests.
    #[must_use]
    pub fn verifier_with(
        &self,
        ring: Arc<KeyRing>,
        other: Arc<dyn JwksSource>,
        clock: Arc<dyn Clock>,
    ) -> Verifier {
        Verifier::with(
            self.verifier_config(),
            Arc::new(OwnJwks::new(ring, other)),
            clock,
        )
    }

    /// The signing keys, not loaded yet.
    ///
    /// # Errors
    ///
    /// Never for a config that [`Config::from_vars`] accepted.
    pub fn key_ring(&self) -> anyhow::Result<KeyRing> {
        Ok(KeyRing::new(
            self.issuer.clone(),
            self.secrets.vault()?,
            self.jwks_cache,
        ))
    }
}

/// `TUTELA_ISSUER`, checked: a valid issuer, `http` only on loopback in dev
/// mode, and not an issuer of the trust file, whose tenants are fixed.
fn own_issuer(text: &str, dev_mode: bool, trust: &TrustFile) -> anyhow::Result<Issuer> {
    let iss: Issuer = text
        .parse()
        .context("TUTELA_ISSUER is not a valid issuer")?;
    ensure!(
        dev_mode || !iss.is_dev_only(),
        "TUTELA_ISSUER may be http only on loopback in dev mode"
    );
    ensure!(
        !trust.issuer.iter().any(|e| e.iss == iss),
        "TUTELA_ISSUER must not be an issuer of the trust file"
    );
    Ok(iss)
}

fn parsed<T: FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: &str,
) -> anyhow::Result<T> {
    get(name)
        .unwrap_or_else(|| default.to_owned())
        .parse()
        .map_err(|_| anyhow!("{name} is not valid"))
}

fn seconds(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: &str,
) -> anyhow::Result<Duration> {
    parsed(get, name, default).map(Duration::from_secs)
}

/// One issuer in the trust file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerEntry {
    /// The exact `iss`.
    pub iss: Issuer,
    /// Its JWKS document.
    pub jwks_uri: String,
    /// The algorithms it may use (`ES256`, `RS256`, `EdDSA`).
    pub algs: Vec<String>,
    /// The tenants it may speak for.
    pub tenants: Vec<TenantId>,
    /// An external issuer such as Keycloak (CONTRACTS.md 4.6).
    #[serde(default)]
    pub external: bool,
    /// For an external issuer: accept `typ: JWT` as well as `at+jwt`.
    #[serde(default)]
    pub allow_typ_jwt: bool,
    /// For an external issuer: it names workloads, not people. attache's
    /// embassy, whose JWT-SVIDs name a SPIFFE id on the path
    /// `/ns/<namespace>/svc/<service>`. Its tokens only ever stand for a
    /// registered agent as the actor of a delegated token (ADR-0033).
    #[serde(default)]
    pub workloads: bool,
}

/// An audience `tutelad` issues tokens for: a service that verifies them.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceEntry {
    /// The `aud` (CONTRACTS.md 4.2).
    pub name: Audience,
    /// It accepts delegated (`agent+jwt`) tokens (CONTRACTS.md 4.5).
    #[serde(default)]
    pub delegation_aware: bool,
}

/// The trust file: which issuers `tutelad` accepts, and for which tenants
/// (CONTRACTS.md 1.6), and the audiences it issues tokens for. A tenant
/// comes only from a token that this list allows.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustFile {
    /// Host names the JWKS fetch may reach on a private network, for example
    /// an internal Keycloak.
    #[serde(default)]
    pub private_hosts: Vec<String>,
    /// The issuers.
    #[serde(default)]
    pub issuer: Vec<IssuerEntry>,
    /// The audiences token exchange issues for, besides the service's own.
    #[serde(default)]
    pub audience: Vec<AudienceEntry>,
    #[serde(skip)]
    trust: TrustList,
    #[serde(skip)]
    issuers: Vec<IssuerConfig>,
}

impl TrustFile {
    /// Reads and checks a trust file.
    ///
    /// # Errors
    ///
    /// When it cannot be read, or fails [`TrustFile::parse`].
    pub fn read(path: &Path, dev_mode: bool) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the trust file {}", path.display()))?;
        Self::parse(&text, dev_mode)
            .with_context(|| format!("checking the trust file {}", path.display()))
    }

    /// Parses and checks a trust file's text. An empty list is refused: a
    /// service that accepts no issuer can only be a mistake.
    ///
    /// # Errors
    ///
    /// A syntax error, an unknown key, an issuer with no tenant, an unknown
    /// algorithm, an external issuer with more than one tenant, or an `http`
    /// issuer outside dev mode.
    pub fn parse(text: &str, dev_mode: bool) -> anyhow::Result<Self> {
        let mut file: Self = toml::from_str(text).context("parsing the TOML")?;
        ensure!(!file.issuer.is_empty(), "the file names no issuer");
        file.trust = if dev_mode {
            TrustList::dev_mode()
        } else {
            TrustList::new()
        };
        let mut names = HashSet::new();
        for a in &file.audience {
            ensure!(
                a.name != Audience::TUTELA_ADMIN,
                "the audience tutela-admin is the service's own, with its own rules"
            );
            ensure!(
                names.insert(a.name.clone()),
                "the audience {} is named twice",
                a.name
            );
        }
        file.issuers = Vec::with_capacity(file.issuer.len());
        for entry in &file.issuer {
            let iss = entry.iss.as_str();
            ensure!(!entry.tenants.is_empty(), "issuer {iss} names no tenant");
            ensure!(!entry.algs.is_empty(), "issuer {iss} names no algorithm");
            ensure!(
                !entry.external || entry.tenants.len() == 1,
                "the external issuer {iss} must name exactly one tenant (CONTRACTS.md 1.6)"
            );
            ensure!(
                entry.external || !entry.allow_typ_jwt,
                "allow_typ_jwt is only for an external issuer ({iss})"
            );
            ensure!(
                entry.external || !entry.workloads,
                "workloads is only for an external issuer ({iss})"
            );
            for tenant in &entry.tenants {
                file.trust
                    .insert(entry.iss.clone(), *tenant)
                    .with_context(|| format!("issuer {iss}"))?;
            }
            let algs = entry
                .algs
                .iter()
                .map(|a| Alg::parse(a).with_context(|| format!("issuer {iss}: algorithm {a:?}")))
                .collect::<anyhow::Result<Vec<_>>>()?;
            file.issuers.push(IssuerConfig {
                iss: entry.iss.clone(),
                jwks_uri: entry.jwks_uri.clone(),
                algs,
                external: entry.external,
                allow_typ_jwt: entry.allow_typ_jwt,
            });
        }
        Ok(file)
    }

    /// The verifier settings for `audience`, the service's own. Delegated
    /// tokens are on, and the audience is `delegation_aware`: the check API
    /// evaluates the whole `act` chain (ADR-0033).
    #[must_use]
    pub fn verifier_config(&self, audience: Audience) -> VerifierConfig {
        VerifierConfig {
            audience,
            trust: self.trust.clone(),
            issuers: self.issuers.clone(),
            delegation: true,
            delegation_aware: true,
            denied_kids: HashSet::new(),
            cache: CacheRules::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TID: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b";
    const MASTER: &str = "6d61737465722d6b65792d666f722d74657374732d6f6e6c792d303030303031";
    const PEPPER: &str = "7065707065722d666f722d74657374732d6f6e6c792d30303030303030303031";
    const OWN: &str = "https://tutela.example.test";

    /// The variables every start needs besides the ones a test names.
    fn required(name: &str) -> Option<String> {
        match name {
            "TUTELA_ISSUER" => Some(OWN.to_owned()),
            "TUTELA_MASTER_KEY" => Some(MASTER.to_owned()),
            "TUTELA_KEY_PEPPER" => Some(PEPPER.to_owned()),
            _ => None,
        }
    }

    fn file(iss: &str, extra: &str) -> String {
        format!(
            "[[issuer]]\niss = \"{iss}\"\njwks_uri = \"{iss}/jwks\"\nalgs = [\"ES256\"]\n\
             tenants = [\"{TID}\"]\n{extra}"
        )
    }

    fn with_limits(check_ms: &str, read: &str, write: &str) -> anyhow::Result<Config> {
        let path =
            std::env::temp_dir().join(format!("tutelad-limits-{}.toml", uuid::Uuid::now_v7()));
        std::fs::write(&path, file("https://auth.example.test", "")).unwrap();
        let trust = path.display().to_string();
        let config = Config::from_vars(|name| match name {
            "TUTELA_DATABASE_URL" => Some("host=127.0.0.1".to_owned()),
            "TUTELA_TRUST_FILE" => Some(trust.clone()),
            "TUTELA_REVISION_CHECK_MS" => Some(check_ms.to_owned()),
            "TUTELA_MAX_AGE_READ_SECS" => Some(read.to_owned()),
            "TUTELA_MAX_AGE_WRITE_SECS" => Some(write.to_owned()),
            other => required(other),
        });
        std::fs::remove_file(&path).unwrap();
        config
    }

    #[test]
    fn writes_must_fail_closed_no_later_than_reads() {
        let c = with_limits("1000", "60", "10").unwrap();
        assert_eq!(c.limits, Limits::default());
        assert!(with_limits("0", "60", "10").is_ok());
        assert!(with_limits("1000", "5", "10").is_err(), "write above read");
        assert!(with_limits("20000", "60", "10").is_err(), "check above age");
        assert!(with_limits("soon", "60", "10").is_err());
    }

    #[test]
    fn a_good_trust_file_gives_the_verifier_its_issuers() {
        let t = TrustFile::parse(&file("https://auth.example.test", ""), false).unwrap();
        let c = t.verifier_config("tutela-authz".parse().unwrap());
        assert_eq!(c.issuers.len(), 1);
        assert_eq!(c.issuers[0].algs, [Alg::Es256]);
        assert!(
            c.delegation && c.delegation_aware,
            "delegated tokens are on"
        );
    }

    #[test]
    fn bad_trust_files_are_refused() {
        let two = "[[issuer]]\niss = \"https://a.example.test\"\njwks_uri = \"https://a.example.test/j\"\n\
                   algs = [\"ES256\"]\nexternal = true\ntenants = [\"ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b\", \
                   \"ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c\"]\n";
        for (text, why) in [
            (String::new(), "names no issuer"),
            (file("https://a.example.test", "typo = 1\n"), "parsing"),
            (file("http://127.0.0.1:8000", ""), "issuer"),
            (two.to_owned(), "exactly one tenant"),
            (
                file("https://a.example.test", "allow_typ_jwt = true\n"),
                "only for an external issuer",
            ),
            (
                file("https://a.example.test", "workloads = true\n"),
                "workloads is only for an external issuer",
            ),
            (
                file("https://a.example.test", "").replace("ES256", "HS256"),
                "algorithm",
            ),
        ] {
            let e = format!("{:#}", TrustFile::parse(&text, false).unwrap_err());
            assert!(e.contains(why), "{e}");
        }
        // Dev mode allows a loopback issuer.
        TrustFile::parse(&file("http://127.0.0.1:8000", ""), true).unwrap();
        // Audiences: named once, never tutela-admin.
        let base = file("https://a.example.test", "");
        for (extra, why) in [
            ("[[audience]]\nname = \"tutela-admin\"\n", "tutela-admin"),
            (
                "[[audience]]\nname = \"crm\"\n[[audience]]\nname = \"crm\"\n",
                "named twice",
            ),
            ("[[audience]]\nname = \"Crm\"\n", "parsing"),
        ] {
            let e = format!(
                "{:#}",
                TrustFile::parse(&format!("{base}{extra}"), false).unwrap_err()
            );
            assert!(e.contains(why), "{e}");
        }
        let ok = TrustFile::parse(
            &format!("{base}[[audience]]\nname = \"crm\"\ndelegation_aware = true\n"),
            false,
        )
        .unwrap();
        assert!(ok.audience[0].delegation_aware);
    }

    fn vars(pairs: &[(&'static str, String)]) -> impl Fn(&str) -> Option<String> {
        let pairs = pairs.to_vec();
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .or_else(|| required(name))
        }
    }

    /// TM-22: a missing or weak secret stops the start-up, and says which
    /// variable, never its value.
    #[test]
    fn tm22_missing_secrets_stop_the_start_up() {
        let path = trust_on_disk("secrets");
        let base = [
            ("TUTELA_DATABASE_URL", "host=db".to_owned()),
            ("TUTELA_TRUST_FILE", path.display().to_string()),
        ];
        let run = |extra: &[(&'static str, &str)]| {
            let extra: Vec<(&str, String)> =
                extra.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
            let all: Vec<(&'static str, String)> =
                base.iter().cloned().chain(extra.iter().cloned()).collect();
            let blank = extra.clone();
            Config::from_vars(move |name| {
                if let Some((_, v)) = blank.iter().find(|(k, _)| *k == name) {
                    return Some(v.clone()).filter(|v| v != "<unset>");
                }
                vars(&all)(name)
            })
            .map(|_| ())
            .map_err(|e| format!("{e:#}"))
        };
        assert!(run(&[]).is_ok());
        for (name, value, why) in [
            (
                "TUTELA_MASTER_KEY",
                "<unset>",
                "TUTELA_MASTER_KEY is not set",
            ),
            ("TUTELA_MASTER_KEY", "", "TUTELA_MASTER_KEY is not set"),
            (
                "TUTELA_MASTER_KEY",
                "short",
                "TUTELA_MASTER_KEY must be 32 bytes",
            ),
            (
                "TUTELA_KEY_PEPPER",
                "<unset>",
                "TUTELA_KEY_PEPPER is not set",
            ),
            ("TUTELA_KEY_PEPPER", "abcd", "at least 32 random bytes"),
            ("TUTELA_KEY_PEPPER", MASTER, "must not be the master key"),
            (
                "TUTELA_KEY_PEPPER_VERSION",
                "0",
                "TUTELA_KEY_PEPPER_VERSION",
            ),
            ("TUTELA_ISSUER", "<unset>", "TUTELA_ISSUER is not set"),
            (
                "TUTELA_ISSUER",
                "http://127.0.0.1:9",
                "only on loopback in dev mode",
            ),
            (
                "TUTELA_ISSUER",
                "https://auth.example.test",
                "an issuer of the trust file",
            ),
            ("TUTELA_KEY_REFRESH_SECS", "0", "TUTELA_KEY_REFRESH_SECS"),
        ] {
            let e = run(&[(name, value)]).unwrap_err();
            assert!(e.contains(why), "{name}={value:?}: {e}");
            assert!(!e.contains(PEPPER) && !e.contains(MASTER), "{e}");
        }
        let good = Config::from_vars(vars(&base)).unwrap();
        let shown = format!("{good:?}");
        assert!(
            !shown.contains(MASTER) && !shown.contains(PEPPER),
            "{shown}"
        );
        assert_eq!(good.secrets.pepper().1, 1);
        assert_eq!(good.secrets.pepper().0.len(), 32);
        assert!(good.ledger.is_none(), "forwarding is off unless configured");
        // Forwarding to the ledger needs its token and the producer key; the
        // error names the variable, never a value, and Debug shows neither.
        let url = (
            "TUTELA_LEDGER_URL",
            "https://embassy.example.test/api/v1/ledger/append",
        );
        let token = ("TUTELA_LEDGER_TOKEN", "att_secret-token-for-tests-only");
        let key = (
            "TUTELA_AUDIT_KEY",
            "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=",
        );
        for (extra, why) in [
            (vec![url, key], "TUTELA_LEDGER_TOKEN is required"),
            (vec![url, token], "TUTELA_AUDIT_KEY must be 32 bytes"),
            (
                vec![url, token, ("TUTELA_AUDIT_KEY", "c2hvcnQ=")],
                "TUTELA_AUDIT_KEY must be 32 bytes",
            ),
        ] {
            let e = run(&extra).unwrap_err();
            assert!(e.contains(why), "{e}");
            assert!(!e.contains(token.1), "{e}");
        }
        assert!(run(&[url, token, key]).is_ok());
        std::fs::remove_file(path).unwrap();
    }

    fn trust_on_disk(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tutelad-trust-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, file("https://auth.example.test", "")).unwrap();
        path
    }

    /// The example file parses, so it stays true.
    #[test]
    fn the_deploy_files_stay_true() {
        let env = include_str!("../../../deploy/tutelad.env");
        for line in ["RUST_BACKTRACE=1", "RUST_LIB_BACKTRACE=0"] {
            assert!(env.lines().any(|l| l == line), "{line}");
        }
        let compose = include_str!("../../../deploy/compose.yaml");
        assert!(compose.contains("- tutelad.env"));
        TrustFile::parse(include_str!("../../../deploy/trust.example.toml"), false).unwrap();
    }

    #[test]
    fn variables_have_safe_defaults_and_secrets_stay_out_of_debug_and_errors() {
        let path = trust_on_disk("defaults");
        let good = [
            ("TUTELA_DATABASE_URL", "host=db password=hunter2".to_owned()),
            ("TUTELA_TRUST_FILE", path.display().to_string()),
        ];
        let c = Config::from_vars(vars(&good)).unwrap();
        assert_eq!(c.listen.port(), 8080);
        assert_eq!(c.ops_listen.port(), 9090);
        assert_eq!(c.audience.as_str(), DEFAULT_AUDIENCE);
        assert!(!c.dev_mode);
        assert!(!format!("{c:?}").contains("hunter2"));
        // No step-up value by default: no admin token for a person.
        assert!(c.admin_acr.is_empty());
        let mut acr = good.to_vec();
        acr.push(("TUTELA_ADMIN_ACR", " mfa, gold ,".to_owned()));
        assert_eq!(
            Config::from_vars(vars(&acr)).unwrap().admin_acr,
            ["mfa", "gold"]
        );
        let mut bad_acr = good.to_vec();
        bad_acr.push(("TUTELA_ADMIN_ACR", "m f a".to_owned()));
        assert!(Config::from_vars(vars(&bad_acr)).is_err());
        // A delegated token lives 60 to 120 s (CONTRACTS.md 4.5).
        assert_eq!(c.delegated_ttl.as_secs(), 90);
        for (ttl, ok) in [("59", false), ("60", true), ("120", true), ("121", false)] {
            let mut v = good.to_vec();
            v.push(("TUTELA_DELEGATED_TTL_SECS", ttl.to_owned()));
            assert_eq!(Config::from_vars(vars(&v)).is_ok(), ok, "{ttl}");
        }

        let e = Config::from_vars(vars(&good[1..])).unwrap_err();
        assert_eq!(e.to_string(), "TUTELA_DATABASE_URL is not set");
        let mut bad = good.to_vec();
        bad.push(("TUTELA_LISTEN", "nonsense".to_owned()));
        let e = Config::from_vars(vars(&bad)).unwrap_err();
        assert_eq!(e.to_string(), "TUTELA_LISTEN is not valid");
        std::fs::remove_file(path).unwrap();
    }
}
