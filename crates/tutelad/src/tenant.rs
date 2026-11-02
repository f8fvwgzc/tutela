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
use tutela_contracts::tenant::TenantKey;
use tutela_sdk::Identity;

use crate::api::{Problem, invalid_token};

/// The tenant of a verified token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant(TenantKey);

impl Tenant {
    /// The tenant of a verified identity.
    #[must_use]
    pub fn of(identity: &Identity) -> Self {
        Self(identity.tenant())
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
        let tenant = parts
            .extensions
            .get::<Identity>()
            .map(Self::of)
            .ok_or_else(invalid_token)?;
        tracing::Span::current().record("tid", tracing::field::display(tenant.key().tid));
        Ok(tenant)
    }
}
