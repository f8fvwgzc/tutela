//! Signed bundles: a tenant's data and its active model, signed by
//! `tutelad`, for checks in a product's own process with no network
//! (ADR-0024, ADR-0038, THREAT-MODEL.md TM-13).
//!
//! A bundle is a JWS: header `typ: tutela-bundle+jwt`, signed by `tutelad`'s
//! own issuer with the key its JWKS names. [`Verifier::verify_bundle`]
//! checks it the way a token is checked (the issuer and the tenant on the
//! trust list, the signature against the same JWKS, a `kid` on the
//! deny-list refused), then its own rules: the format, and `exp`, with no
//! clock skew. An [`OfflinePdp`] loads verified bundles: it refuses a lower
//! revision than it has, and stops answering at `exp`, also when `tutelad`
//! is gone.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use tutela_contracts::decision::Decision;
use tutela_contracts::tenant::{Issuer, TenantId, TenantKey};
use tutela_pdp::model::Model;
use tutela_pdp::{CheckRequest, PathEntry, Pdp, PdpError, ScopePathError, ScopePaths, TenantData};

use crate::Verifier;

/// The `typ` of a bundle. Never an access token's: a bundle is not a
/// credential, and no token verifier accepts it, nor this one a token.
pub const BUNDLE_TYP: &str = "tutela-bundle+jwt";

/// The bundle format this build reads.
pub const BUNDLE_FORMAT: u32 = 1;

/// The largest bundle this reads: 32 MiB.
pub const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;

/// Why a bundle was refused. The text never holds the bundle.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// Not a JWS of the bundle type, too large, or claims that do not parse.
    #[error("not a bundle")]
    Malformed,
    /// The issuer, or the (issuer, tenant) pair, is not on the trust list.
    #[error("the bundle's issuer or tenant is not trusted")]
    Untrusted,
    /// The key is unknown, on the deny-list, or the signature does not
    /// verify.
    #[error("the bundle's signature does not verify")]
    Signature,
    /// `exp` has passed.
    #[error("the bundle has expired")]
    Expired,
    /// A newer format than this build reads.
    #[error("the bundle needs a newer reader")]
    Unsupported,
    /// The model does not compile, or is not the digest it claims.
    #[error("the bundle's model does not compile or does not match its digest")]
    Model,
}

/// The model of a bundle.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleModel {
    /// The SHA-256 of `source`, hex.
    pub digest: String,
    /// The model's text (`tutela.resources.toml`).
    pub source: String,
}

/// One registered scope and its ancestors, nearest first.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundlePath {
    /// The scope.
    pub scope: PathEntry,
    /// Its ancestors, nearest first; the last is the org.
    pub ancestors: Vec<PathEntry>,
}

/// The claims of a bundle.
#[derive(Clone, Debug, Deserialize)]
pub struct BundleClaims {
    /// `tutelad`'s own issuer, the signer. The trust list must let it speak
    /// for `tid`.
    pub iss: Issuer,
    /// The tenant.
    pub tid: TenantId,
    /// The issuer of the tenant key `(tenant_iss, tid)` the data is kept
    /// under: the `iss` of the tenant's own tokens.
    pub tenant_iss: Issuer,
    /// The tenant revision it was read at.
    pub rev: u64,
    /// When it was made, NumericDate.
    pub iat: u64,
    /// When it stops being used, NumericDate: never later than the first
    /// assignment in it that expires.
    pub exp: u64,
    /// Its id.
    pub jti: String,
    /// The format, [`BUNDLE_FORMAT`].
    pub format: u32,
    /// The tenant's active model.
    pub model: BundleModel,
    /// The tenant's data.
    pub data: TenantData,
    /// The registered scope paths.
    pub paths: Vec<BundlePath>,
}

#[derive(Deserialize)]
struct FormatOnly {
    format: Option<u32>,
}

impl Verifier {
    /// Verifies a bundle: its header, issuer, tenant, signature and `kid`
    /// as for a token of a Tutela-format issuer, then its format and `exp`
    /// against this verifier's clock, with no skew.
    ///
    /// # Errors
    ///
    /// A [`BundleError`].
    pub async fn verify_bundle(&self, bundle: &str) -> Result<BundleClaims, BundleError> {
        if bundle.len() > MAX_BUNDLE_BYTES {
            return Err(BundleError::Malformed);
        }
        let mut parts = bundle.split('.');
        let (Some(h64), Some(p64), Some(s64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(BundleError::Malformed);
        };
        let header: crate::Header = B64
            .decode(h64)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(BundleError::Malformed)?;
        let typ_ok = header
            .typ
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case(BUNDLE_TYP));
        if !typ_ok
            || header
                .rest
                .keys()
                .any(|k| crate::FORBIDDEN_HEADERS.contains(&k.as_str()))
        {
            return Err(BundleError::Malformed);
        }
        let alg = header
            .alg
            .as_deref()
            .and_then(crate::Alg::parse)
            .ok_or(BundleError::Malformed)?;
        let kid = header
            .kid
            .filter(|k| !k.is_empty() && k.len() <= 256)
            .ok_or(BundleError::Malformed)?;
        let payload = B64.decode(p64).map_err(|_| BundleError::Malformed)?;
        let iss: crate::IssOnly =
            serde_json::from_slice(&payload).map_err(|_| BundleError::Malformed)?;
        // Only a Tutela-format issuer signs bundles: an external one (an
        // IdP) never speaks for a tenant's data.
        let issuer = self
            .issuers
            .get(&iss.iss)
            .filter(|i| !i.external)
            .ok_or(BundleError::Untrusted)?;
        if !issuer.algs.contains(&alg) {
            return Err(BundleError::Signature);
        }
        if self.denied.read().map_or(true, |d| d.contains(&kid)) {
            return Err(BundleError::Signature);
        }
        let now = self.clock.now();
        let key = self
            .keys
            .key(&issuer.jwks_uri, &kid, now)
            .await
            .filter(|k| k.thumbprint() == kid)
            .ok_or(BundleError::Signature)?;
        let signature = B64.decode(s64).map_err(|_| BundleError::Signature)?;
        let signed = bundle
            .get(..h64.len() + 1 + p64.len())
            .ok_or(BundleError::Signature)?;
        if !key.verify(alg, signed.as_bytes(), &signature) {
            return Err(BundleError::Signature);
        }
        // The format first: a newer one may not parse as this one.
        let f: FormatOnly = serde_json::from_slice(&payload).map_err(|_| BundleError::Malformed)?;
        match f.format {
            Some(BUNDLE_FORMAT) => {}
            Some(v) if v > BUNDLE_FORMAT => return Err(BundleError::Unsupported),
            _ => return Err(BundleError::Malformed),
        }
        let claims: BundleClaims =
            serde_json::from_slice(&payload).map_err(|_| BundleError::Malformed)?;
        if !self.config.trust.allows(&claims.iss, &claims.tid) {
            return Err(BundleError::Untrusted);
        }
        if now >= claims.exp {
            return Err(BundleError::Expired);
        }
        Ok(claims)
    }
}

/// The scope paths of a bundle, for `list_filter`.
#[derive(Clone, Debug)]
pub struct BundlePaths {
    tenant: TenantKey,
    paths: HashMap<PathEntry, Vec<PathEntry>>,
}

impl ScopePaths for BundlePaths {
    fn ancestors(
        &self,
        tenant: &TenantKey,
        scope: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError> {
        if *tenant != self.tenant {
            return Err(ScopePathError::NotFound);
        }
        self.paths
            .get(scope)
            .cloned()
            .ok_or(ScopePathError::NotFound)
    }

    fn below(
        &self,
        tenant: &TenantKey,
        scopes: &[PathEntry],
    ) -> Option<Result<Vec<PathEntry>, ScopePathError>> {
        if *tenant != self.tenant {
            return Some(Err(ScopePathError::NotFound));
        }
        let scopes: HashSet<&PathEntry> = scopes.iter().collect();
        Some(Ok(self
            .paths
            .iter()
            .filter(|(_, path)| path.iter().any(|a| scopes.contains(a)))
            .map(|(s, _)| s.clone())
            .collect()))
    }
}

/// A PDP fed by verified bundles of one tenant, with no network: it refuses
/// a bundle older than the one it has, and stops answering at the bundle's
/// `exp` (TM-13, TM-23).
pub struct OfflinePdp {
    pdp: Pdp,
    tenant: Option<TenantKey>,
    rev: Option<u64>,
    exp: u64,
    paths: Option<Arc<BundlePaths>>,
    clock: Arc<dyn crate::Clock>,
}

impl std::fmt::Debug for OfflinePdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflinePdp")
            .field("tenant", &self.tenant)
            .field("rev", &self.rev)
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
}

impl OfflinePdp {
    /// An empty PDP that reads time from `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn crate::Clock>) -> Self {
        Self {
            pdp: Pdp::new(),
            tenant: None,
            rev: None,
            exp: 0,
            paths: None,
            clock,
        }
    }

    /// Loads a verified bundle. Its model is compiled and must be the
    /// digest it names, and its data goes through [`Pdp::load`]'s checks.
    ///
    /// # Errors
    ///
    /// [`OfflineError::Older`] for a lower revision than the one loaded,
    /// [`OfflineError::Tenant`] for another tenant's bundle,
    /// [`OfflineError::Expired`] past its `exp`, and [`OfflineError::Load`]
    /// for a model or data that do not load.
    pub fn load(&mut self, b: BundleClaims) -> Result<(), OfflineError> {
        let tenant = TenantKey::new(b.tenant_iss.clone(), b.tid);
        if self.tenant.as_ref().is_some_and(|t| *t != tenant) {
            return Err(OfflineError::Tenant);
        }
        if self.rev.is_some_and(|r| b.rev < r) {
            return Err(OfflineError::Older);
        }
        if self.clock.now() >= b.exp {
            return Err(OfflineError::Expired);
        }
        let digest = sha256_hex(b.model.source.as_bytes());
        if digest != b.model.digest {
            return Err(OfflineError::Load);
        }
        let model = Model::from_toml(&b.model.source).map_err(|_| OfflineError::Load)?;
        let mut pdp = Pdp::new();
        pdp.load(tenant.clone(), b.rev, Arc::new(model), b.data)
            .map_err(|_| OfflineError::Load)?;
        self.paths = Some(Arc::new(BundlePaths {
            tenant: tenant.clone(),
            paths: b
                .paths
                .into_iter()
                .map(|p| (p.scope, p.ancestors))
                .collect(),
        }));
        self.pdp = pdp;
        self.tenant = Some(tenant);
        self.rev = Some(b.rev);
        self.exp = b.exp;
        Ok(())
    }

    /// The revision loaded.
    #[must_use]
    pub const fn rev(&self) -> Option<u64> {
        self.rev
    }

    /// `check` on the loaded bundle, while it lasts.
    ///
    /// # Errors
    ///
    /// [`PdpError::ExpiredBundle`] at and after `exp`,
    /// [`PdpError::NoBundle`] before the first load, or the evaluator's
    /// error. Never an allow from an expired bundle.
    pub fn check(&self, req: &CheckRequest) -> Result<Decision, PdpError> {
        if self.rev.is_none() {
            return Err(PdpError::NoBundle);
        }
        if self.clock.now() >= self.exp {
            return Err(PdpError::ExpiredBundle);
        }
        self.pdp.check(req)
    }

    /// The scope paths of the loaded bundle, for `list_filter`.
    #[must_use]
    pub fn paths(&self) -> Option<Arc<BundlePaths>> {
        self.paths.clone()
    }
}

/// Why [`OfflinePdp::load`] refused a bundle.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OfflineError {
    /// A lower revision than the one loaded: a replay of an older bundle.
    #[error("the bundle is older than the one loaded")]
    Older,
    /// Another tenant's bundle.
    #[error("the bundle is of another tenant")]
    Tenant,
    /// Its `exp` has passed.
    #[error("the bundle has expired")]
    Expired,
    /// The model or the data do not load.
    #[error("the bundle does not load")]
    Load,
}

fn sha256_hex(b: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b)
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}
