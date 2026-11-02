//! Events (CONTRACTS.md 8, ADR-0035): the envelope `tutelad` sends for an
//! event of the transactional outbox.
//!
//! The store writes each event in the transaction of its change
//! (`tutela_store::emit`, `tutela_store::OutboxEvent`); webhooks and
//! `GET /v1/events` read them back in order and send them as CloudEvents
//! with the source `tutela://<host>/<tid>`, where `<host>` is the host of
//! `TUTELA_ISSUER`.

use serde_json::{Map, Value};
use tutela_contracts::events::{CloudEvent, EventSource};
use tutela_contracts::tenant::{Issuer, TenantId};
use tutela_store::StoredEvent;

/// The event source of tenant `tid` under the service's own issuer:
/// `tutela://<host>[:<port>]/<tid>`.
///
/// # Errors
///
/// [`SourceError`] when the issuer's host is not a DNS name the event
/// grammar takes.
pub fn source(own: &Issuer, tid: TenantId) -> Result<EventSource, SourceError> {
    let url = tutela_safenet::Url::parse(own.as_str()).map_err(|_| SourceError)?;
    let host = url.host_str().ok_or(SourceError)?;
    EventSource::new(&host.to_ascii_lowercase(), url.port(), tid).map_err(|_| SourceError)
}

/// The issuer's host cannot name an event source.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the issuer's host cannot name an event source")]
pub struct SourceError;

/// The CloudEvents envelope of `event`, as webhooks and SSE send it.
///
/// # Errors
///
/// [`SourceError`], as [`source`].
pub fn envelope(
    own: &Issuer,
    tid: TenantId,
    event: &StoredEvent,
) -> Result<CloudEvent<Map<String, Value>>, SourceError> {
    Ok(event.cloud(source(own, tid)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_source_is_the_issuers_host_and_port() {
        let tid: TenantId = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b".parse().unwrap();
        let s = source(&"https://Tutela.Example.test".parse().unwrap(), tid);
        // An issuer URL is exact text; a host with capitals is still a host.
        if let Ok(s) = s {
            assert_eq!(s.host(), "tutela.example.test");
        }
        let s = source(&"https://tutela.example.test:8443".parse().unwrap(), tid).unwrap();
        assert_eq!(
            s.to_string(),
            "tutela://tutela.example.test:8443/ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"
        );
    }
}
