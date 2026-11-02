//! How a request gets its tenant: from the verified token, and from nowhere
//! else (THREAT-MODEL.md TM-14).
//!
//! [`Tenant`] has a private field and one constructor, [`Tenant::of`], which
//! takes the [`Identity`] that `AuthLayer` verified. It does not deserialize
//! and it has no `From`, so a header, a query or a body cannot become one,
//! and [`crate::db::Conn::begin`] takes nothing else.
//!
//! ```compile_fail
//! use tutela_contracts::tenant::TenantKey;
//! fn from_a_header(key: TenantKey) -> tutelad::tenant::Tenant {
//!     tutelad::tenant::Tenant(key)
//! }
//! ```

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use tutela_contracts::tenant::{Issuer, TenantKey};
use tutela_sdk::{ExternalToken, Identity};

use crate::api::{Problem, invalid_token};

/// The tenant of a verified token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant(TenantKey);

impl Tenant {
    /// The tenant of a verified identity. It also names the tenant in the
    /// request's log span (ADR-0018 item 8), so every route does, over HTTP
    /// and gRPC.
    #[must_use]
    pub fn of(identity: &Identity) -> Self {
        let tenant = Self(identity.tenant());
        tracing::Span::current().record("tid", tracing::field::display(tenant.key().tid));
        tenant
    }

    /// The tenant a verified token of an external issuer speaks for, under
    /// this service's own issuer `own`: the one tenant the trust file maps
    /// that issuer to (CONTRACTS.md 1.6). Token exchange only (ADR-0031). It
    /// still comes from the verified token and the trust list, never from
    /// the request, and the directory checks it when it is entered.
    pub(crate) fn exchanged(own: &Issuer, token: &ExternalToken) -> Self {
        let tenant = Self(TenantKey::new(own.clone(), token.tenant.tid));
        tracing::Span::current().record("tid", tracing::field::display(tenant.key().tid));
        tenant
    }

    /// The tenant of an app, from the app directory, at the token endpoint
    /// only (ADR-0044): it is entered to read the app's secret, and nothing
    /// is issued unless that secret matches. It never comes from a request.
    pub(crate) fn of_app(key: TenantKey) -> Self {
        let tenant = Self(key);
        tracing::Span::current().record("tid", tracing::field::display(tenant.key().tid));
        tenant
    }

    /// The tenant key.
    #[must_use]
    pub const fn key(&self) -> &TenantKey {
        &self.0
    }
}

/// A handler takes a [`Tenant`] argument. A request with no verified
/// identity never reaches it.
impl<S: Send + Sync> FromRequestParts<S> for Tenant {
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Problem> {
        parts
            .extensions
            .get::<Identity>()
            .map(Self::of)
            .ok_or_else(invalid_token)
    }
}
