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

/// `error` and its sources on one line, joined by `: `.
///
/// An error's own text leaves its source out, so a plain `{e}` drops the
/// reason. `{e:#}` does not help either: it walks the chain of an
/// `anyhow::Error`, and a `thiserror` type ignores it. Use this wherever an
/// error from a Tutela crate is printed for a person.
///
/// ```
/// use tutela_contracts::{error_chain, keys::FieldKey};
///
/// let e = FieldKey::parse("project.Name").unwrap_err();
/// assert_eq!(e.to_string(), "invalid name");
/// assert!(error_chain(&e).starts_with("invalid name: "));
/// ```
#[must_use]
pub fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let texts: Vec<String> = std::iter::successors(Some(error), |e| e.source())
        .map(ToString::to_string)
        .collect();
    texts.join(": ")
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::decision::Reason;
    use crate::error_chain;
    use crate::events::{EventSource, EventType};
    use crate::keys::FieldKey;
    use crate::principal::Principal;
    use crate::tenant::TenantId;

    const NAME: &str = "a name must start with a lowercase letter a-z";
    const UUID: &str = "a UUIDv7 must be exactly 36 characters";

    /// Each error says only its own part. The reason sits in `source()`, and
    /// the chain still reads as one sentence.
    #[test]
    fn display_leaves_the_source_to_the_chain() {
        let check = |e: &(dyn Error + 'static), own: &str, whole: &str| {
            assert_eq!(e.to_string(), own);
            assert!(e.source().is_some(), "{own}");
            assert_eq!(error_chain(e), whole);
        };
        check(
            &FieldKey::parse("project.Name").unwrap_err(),
            "invalid name",
            &format!("invalid name: {NAME}"),
        );
        check(
            &Reason::parse("Bad").unwrap_err(),
            "invalid reason code",
            &format!("invalid reason code: {NAME}"),
        );
        check(
            &EventType::parse("tutela.Bad.created.v1").unwrap_err(),
            "invalid entity or verb in the event type",
            &format!("invalid entity or verb in the event type: {NAME}"),
        );
        check(
            &EventSource::parse("tutela://tutela.example.com/ten_1").unwrap_err(),
            "invalid tenant id in the event source",
            &format!("invalid tenant id in the event source: invalid UUIDv7 in the id: {UUID}"),
        );
        check(
            &"ten_1".parse::<TenantId>().unwrap_err(),
            "invalid UUIDv7 in the id",
            &format!("invalid UUIDv7 in the id: {UUID}"),
        );
        check(
            &"user:usr_1".parse::<Principal>().unwrap_err(),
            "invalid principal id",
            &format!("invalid principal id: invalid UUIDv7 in the id: {UUID}"),
        );
        check(
            &"workload:http://x".parse::<Principal>().unwrap_err(),
            "invalid workload SPIFFE ID",
            "invalid workload SPIFFE ID: a SPIFFE ID must start with `spiffe://`",
        );
    }

    /// A value that fails to deserialize still says why.
    #[test]
    fn a_serde_error_keeps_the_reason() {
        let err = serde_json::from_str::<Principal>("\"user:usr_1\"").unwrap_err();
        let want = format!("invalid principal id: invalid UUIDv7 in the id: {UUID}");
        assert!(err.to_string().contains(&want), "{err}");
    }
}
