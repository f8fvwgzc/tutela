//! Feeding a [`Verifier`] from Tutela's events (CONTRACTS.md 4.2 step 9,
//! 8.3, 8.6; ADR-0037).
//!
//! A product that listens to `GET /v1/events` of its `tutelad` (or to its
//! webhooks) hands each message to these functions:
//!
//! - [`apply_event`] for a CloudEvent: `tutela.session.revoked.v1`,
//!   `tutela.principal.disabled.v1` and `tutela.principal.enabled.v1` move
//!   the verifier's [`EpochBook`](crate::EpochBook), so a revoked session or
//!   a disabled principal is refused at once instead of when its token
//!   expires. Any other type is ignored here.
//! - [`apply_denied_kids`] for a `denied_kids` message: each `kid` goes on
//!   the deny-list at once, and the issuer's cached JWKS is forgotten, so
//!   the next token fetches it again (TM-15).
//!
//! Only call them with messages from the `tutelad` the product trusts, over
//! its own authenticated connection: they lower what the verifier accepts,
//! never raise it, except `principal.enabled`, which ends a disabling.

use serde::Deserialize;
use tutela_contracts::principal::Principal;

use crate::Verifier;

/// What a message did to the verifier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Applied {
    /// A principal's newest epoch was noted.
    Epoch,
    /// A principal was marked disabled.
    Disabled,
    /// A principal was marked enabled again.
    Enabled,
    /// Nothing: a type this does not act on, or a message that does not
    /// parse.
    Ignored,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    event_type: String,
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    principal: Principal,
    epoch: u64,
}

/// Applies one event (the CloudEvent JSON) to `verifier`'s epoch book.
#[must_use]
pub fn apply_event(verifier: &Verifier, event: &serde_json::Value) -> Applied {
    let Ok(e) = Envelope::deserialize(event) else {
        return Applied::Ignored;
    };
    let book = verifier.epochs();
    match e.event_type.as_str() {
        "tutela.session.revoked.v1" => {
            book.note(&e.data.principal, e.data.epoch);
            Applied::Epoch
        }
        "tutela.principal.disabled.v1" => {
            book.note(&e.data.principal, e.data.epoch);
            book.set_disabled(&e.data.principal, true);
            Applied::Disabled
        }
        "tutela.principal.enabled.v1" => {
            book.note(&e.data.principal, e.data.epoch);
            book.set_disabled(&e.data.principal, false);
            Applied::Enabled
        }
        _ => Applied::Ignored,
    }
}

#[derive(Deserialize)]
struct DeniedKids {
    jwks_uri: String,
    kids: Vec<String>,
}

/// Applies a `denied_kids` message (`{"iss", "jwks_uri", "kids"}`): every
/// `kid` is refused from now on, and the cached JWKS at `jwks_uri` is
/// forgotten. Returns how many `kid`s it holds, or `None` for a message
/// that does not parse.
pub async fn apply_denied_kids(verifier: &Verifier, message: &serde_json::Value) -> Option<usize> {
    let m = DeniedKids::deserialize(message).ok()?;
    for kid in &m.kids {
        verifier.deny_kid(kid);
    }
    verifier.forget_jwks(&m.jwks_uri).await;
    Some(m.kids.len())
}
