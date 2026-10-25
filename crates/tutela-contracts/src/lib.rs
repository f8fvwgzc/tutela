//! Wire contracts shared by every Tutela package and every consumer.
//!
//! This crate implements [`docs/CONTRACTS.md`]: the exact text and JSON forms
//! that every Tutela crate, the `tutelad` service, the SDKs and every product
//! use. It is pure: no I/O, no async, no crypto. Parsers never repair input:
//! a value that breaks a rule is rejected (CONTRACTS.md section 0).
//!
//! | Module | CONTRACTS.md | What |
//! |---|---|---|
//! | [`id`] | 1.1, 1.2 | UUIDv7 text, session ids |
//! | [`principal`] | 1.3, 1.4 | principal strings, SPIFFE workload ids |
//! | [`tenant`] | 1.5, 1.6 | tenant and org ids, issuers, the tenant key, the trust list |
//! | [`keys`] | 2 | names, field, feature, action, permission and UI keys |
//! | [`level`] | 3 | the four levels |
//! | [`claims`] | 4 | access-token and delegated-token claims and their checks |
//! | [`apikey`] | 5 | API key parsing and the display prefix |
//! | [`decision`] | 6.1 to 6.3 | the Decision object, reason codes, obligations |
//! | [`events`] | 8.1 to 8.3 | the CloudEvents envelope, event types, event data |
//! | [`audit`] | 9 | the audit.v1 record |
//! | [`timestamp`] | 0 | JSON times |
//! | [`encoding`] | 0, 4, 9 | base64url values, the JSON integer range |
//!
//! Planned, not here yet: the `Pdp` API (Phase A, `tutela-pdp`), signature
//! and header checks of tokens (Phase A, `tutela-sdk`), the remote check API
//! and protos (Phase B), producer signatures and sequence numbers of audit
//! records (Phase B).
//!
//! [`docs/CONTRACTS.md`]: https://github.com/f8fvwgzc/tutela/blob/main/docs/CONTRACTS.md

#[macro_use]
mod macros;

mod text;

pub mod apikey;
pub mod audit;
pub mod claims;
pub mod decision;
pub mod encoding;
pub mod events;
pub mod id;
pub mod keys;
pub mod level;
pub mod principal;
pub mod tenant;
pub mod timestamp;

#[cfg(test)]
mod test_support;

/// A field that has one fixed value (for example `specversion` = `"1.0"` or
/// `schema` = `"audit.v1"`) had another value.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("expected the value `{expected}`")]
pub struct FixedValueError {
    /// The only valid value.
    pub expected: &'static str,
}
