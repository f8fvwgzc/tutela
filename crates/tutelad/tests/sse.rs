//! `GET /v1/events` through the real service, the real auth layer and a
//! real Postgres (ADR-0037, CONTRACTS.md 8.6).
#![cfg(test)]

mod common;

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tutela_store::OutboxEvent;

use common::{AGENT, ISS, SA, USER, World, world, world_with};

/// One SSE message.
#[derive(Clone, Debug)]
struct Msg {
    id: Option<String>,
    event: String,
    data: Value,
}

/// An open stream, read a chunk at a time.
struct Stream {
    res: reqwest::Response,
    buf: String,
}

impl Stream {
    /// The next message, skipping keep-alive comments; `None` when the
    /// stream ended or nothing came in `wait`.
    async fn next(&mut self, wait: Duration) -> Option<Msg> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            while let Some(i) = self.buf.find("\n\n") {
                let block: String = self.buf.drain(..i + 2).collect();
                let mut m = Msg {
                    id: None,
                    event: "message".to_owned(),
                    data: Value::Null,
                };
                let mut any = false;
                for line in block.lines() {
                    if let Some(v) = line.strip_prefix("id:") {
                        m.id = Some(v.trim().to_owned());
                        any = true;
                    } else if let Some(v) = line.strip_prefix("event:") {
                        m.event = v.trim().to_owned();
                        any = true;
                    } else if let Some(v) = line.strip_prefix("data:") {
                        m.data = serde_json::from_str(v.trim()).unwrap();
                        any = true;
                    }
                }
                if any {
                    return Some(m);
                }
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, self.res.chunk()).await {
                Ok(Ok(Some(b))) => self.buf.push_str(std::str::from_utf8(&b).unwrap()),
                _ => return None,
            }
        }
    }

    /// The next message that is an event of the outbox.
    async fn event(&mut self, wait: Duration) -> Option<Msg> {
        loop {
            let m = self.next(wait).await?;
            if m.id.is_some() {
                return Some(m);
            }
        }
    }
}

async fn open(
    w: &World,
    token: &str,
    last: Option<&str>,
    query: &str,
) -> Result<Stream, (StatusCode, Value)> {
    let mut req = common::http()
        .get(w.s.api_url(&format!("/v1/events{query}")))
        .bearer_auth(token);
    if let Some(l) = last {
        req = req.header("last-event-id", l);
    }
    let res = req.send().await.unwrap();
    if res.status() != StatusCode::OK {
        let status = res.status();
        return Err((status, res.json().await.unwrap_or(Value::Null)));
    }
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    Ok(Stream {
        res,
        buf: String::new(),
    })
}

async fn emit(w: &mut World, key: &tutela_contracts::tenant::TenantKey, e: OutboxEvent) {
    let tx = w.d.owner.transaction().await.unwrap();
    tutela_store::emit(&tx, key, e).await.unwrap();
    tx.commit().await.unwrap();
}

const WAIT: Duration = Duration::from_secs(5);

/// A service gets its tenant's deny-list and revision first, then each new
/// event as it commits, and resumes after `Last-Event-ID` with nothing lost.
#[tokio::test]
async fn a_service_follows_its_tenants_events_and_resumes_after_its_last_id() {
    let Some(mut w) = world().await else { return };
    let t = w.issuer.token(SA, &w.a.tid, 0);
    let mut s = open(&w, &t, None, "").await.unwrap();
    let first = s.next(WAIT).await.unwrap();
    assert_eq!(first.event, "denied_kids");
    assert_eq!(first.data["iss"], common::OWN_ISS);
    let rev = s.next(WAIT).await.unwrap();
    assert_eq!(rev.event, "rev");
    let a = w.a.key.clone();
    emit(&mut w, &a, OutboxEvent::ModelPublished { rev: 41 }).await;
    let m = s.event(WAIT).await.unwrap();
    assert_eq!(m.event, "tutela.model.published.v1");
    assert_eq!(m.data["data"]["rev"], 41);
    assert_eq!(m.data["id"], m.id.clone().unwrap().as_str());
    assert_eq!(m.data["tenantid"], w.a.tid.as_str());
    let seen = m.id.unwrap();
    drop(s);
    // While nobody listens, two more; a resumed stream gets both, in order.
    emit(&mut w, &a, OutboxEvent::ModelPublished { rev: 42 }).await;
    emit(&mut w, &a, OutboxEvent::PermissionsChanged { rev: 43 }).await;
    let mut again = open(&w, &t, Some(&seen), "").await.unwrap();
    let revs: Vec<Value> = [
        again.event(WAIT).await.unwrap(),
        again.event(WAIT).await.unwrap(),
    ]
    .iter()
    .map(|m| m.data["data"]["rev"].clone())
    .collect();
    assert_eq!(revs, [json!(42), json!(43)]);
    // `types` filters.
    let mut only = open(&w, &t, Some(&seen), "?types=tutela.permissions.changed.v1")
        .await
        .unwrap();
    let m = only.event(WAIT).await.unwrap();
    assert_eq!(m.data["data"]["rev"], 43);
    w.finish().await;
}

/// An id the tenant does not have (pruned, or another tenant's) gets
/// `reset` first: the client reloads.
#[tokio::test]
async fn an_unknown_last_event_id_gets_reset() {
    let Some(mut w) = world().await else { return };
    let b = w.b.key.clone();
    emit(&mut w, &b, OutboxEvent::ModelPublished { rev: 7 }).await;
    let theirs = common::events_of(&mut w.d.owner, &b)
        .await
        .pop()
        .unwrap()
        .id
        .to_string();
    let t = w.issuer.token(SA, &w.a.tid, 0);
    for last in [
        theirs.as_str(),
        "0193a1b2-c3d5-7000-8000-0000000000e1",
        "not-an-id",
    ] {
        let mut s = open(&w, &t, Some(last), "").await.unwrap();
        assert_eq!(s.next(WAIT).await.unwrap().event, "reset", "{last}");
    }
    w.finish().await;
}

/// Only a service of the tenant listens: a person, an agent, a delegated
/// token, no token and an admin token are refused, and a stream never
/// shows another tenant's event.
#[tokio::test]
async fn denied_principals_get_no_stream_and_a_stream_shows_one_tenant() {
    let Some(mut w) = world().await else { return };
    for token in [
        w.issuer.token(USER, &w.a.tid, 0),
        w.issuer.token(AGENT, &w.a.tid, 0),
        w.issuer.delegated(USER, AGENT, &w.a.tid),
    ] {
        let (status, _) = open(&w, &token, None, "").await.err().unwrap();
        assert!(
            matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
            "{status}"
        );
    }
    let res = common::http()
        .get(w.s.api_url("/v1/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let admin = w
        .issuer
        .admin_token(USER, &w.a.tid, common::STEP_UP, 0, 300);
    let (status, _) = open(&w, &admin, None, "").await.err().unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = open(&w, &w.issuer.token(SA, &w.a.tid, 0), None, "?types=nope")
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A's service listens first, so A's tenant has a feed on this replica;
    // B's service listens next. A's events never reach B's stream.
    let mut a_stream = open(&w, &w.issuer.token(SA, &w.a.tid, 0), None, "")
        .await
        .unwrap();
    let mut b = open(&w, &w.issuer.token(SA, &w.b.tid, 0), None, "")
        .await
        .unwrap();
    let a = w.a.key.clone();
    let bk = w.b.key.clone();
    emit(&mut w, &a, OutboxEvent::ModelPublished { rev: 1 }).await;
    emit(&mut w, &bk, OutboxEvent::ModelPublished { rev: 2 }).await;
    let m = b.event(WAIT).await.unwrap();
    assert_eq!(m.data["tenantid"], w.b.tid.as_str());
    assert_eq!(m.data["data"]["rev"], 2);
    let m = a_stream.event(WAIT).await.unwrap();
    assert_eq!(m.data["tenantid"], w.a.tid.as_str());
    let _ = ISS;
    w.finish().await;
}

/// TM-15 and TM-13: a denied `kid` and a new revision are pushed; fed to a
/// product's verifier, the deny-list refuses that key at once and a
/// revoked session's old token at once.
#[tokio::test]
async fn tm15_a_denied_kid_and_a_revocation_reach_a_products_verifier() {
    // A denial elsewhere reaches this replica within its key refresh.
    let Some(mut w) = world_with(|c| c.key_refresh = Duration::from_secs(1)).await else {
        return;
    };
    let st = common::state(&w.config, &w.issuer);
    st.keys.refresh(&st.db).await.unwrap();
    let t = w.issuer.token(SA, &w.a.tid, 0);
    let mut s = open(&w, &t, None, "").await.unwrap();
    let kids = s.next(WAIT).await.unwrap();
    assert_eq!(kids.data["kids"], json!([]));
    s.next(WAIT).await.unwrap();
    // A product's verifier, trusting the test issuer for tenant A.
    let product = common::product_verifier(&w);
    let old = w.issuer.token(USER, &w.a.tid, 0);
    assert!(product.verify(&old).await.is_ok());
    // A revocation: the stream carries the event, the verifier applies it.
    let a = w.a.key.clone();
    let tx = w.d.owner.transaction().await.unwrap();
    let epoch = tutela_store::revoke_sessions(&tx, &a, &USER.parse().unwrap())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut saw_rev = false;
    let revoked = loop {
        let m = s.next(WAIT).await.expect("the revocation was not pushed");
        if m.event == "rev" {
            saw_rev = true;
        }
        if m.event == "tutela.session.revoked.v1" {
            break m;
        }
    };
    assert_eq!(revoked.data["data"]["epoch"], epoch);
    assert_eq!(
        tutela_sdk::events::apply_event(&product, &revoked.data),
        tutela_sdk::events::Applied::Epoch
    );
    assert!(
        product.verify(&old).await.is_err(),
        "an old epoch still verifies"
    );
    // The revision moved too, and was pushed (now or with the event).
    if !saw_rev {
        let m = s.next(WAIT).await.unwrap();
        assert_eq!(m.event, "rev");
    }
    // A denied key of the service's own issuer is pushed within a poll.
    let kid = st.keys.published()[0].clone();
    st.keys.deny(&st.db, &kid).await.unwrap();
    let denied = loop {
        let m = s.next(WAIT).await.expect("the deny-list was not pushed");
        if m.event == "denied_kids" {
            break m;
        }
    };
    assert!(
        denied.data["kids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == &json!(kid))
    );
    let n = tutela_sdk::events::apply_denied_kids(&product, &denied.data).await;
    assert_eq!(n, Some(1));
    w.finish().await;
}

/// A slow client cannot hold memory: past its buffer it gets `reset` and
/// the stream ends. A replica holds a bounded number of streams, each
/// for a bounded time.
#[tokio::test]
async fn a_slow_client_is_reset_and_streams_are_bounded() {
    let Some(mut w) = world_with(|c| {
        c.streams.max_streams = 2;
        c.streams.max_age = Duration::from_secs(2);
        c.streams.buffer = 4;
    })
    .await
    else {
        return;
    };
    let t = w.issuer.token(SA, &w.a.tid, 0);
    let mut slow = open(&w, &t, None, "").await.unwrap();
    slow.next(WAIT).await.unwrap();
    slow.next(WAIT).await.unwrap();
    let _second = open(&w, &t, None, "").await.unwrap();
    let (status, v) = open(&w, &t, None, "").await.err().unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    // Twenty events in one transaction reach the feed in one read: more
    // than the buffer, so the stream is told to reset and ends.
    let a = w.a.key.clone();
    let tx = w.d.owner.transaction().await.unwrap();
    for rev in 0..20 {
        tutela_store::emit(&tx, &a, OutboxEvent::ModelPublished { rev })
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let mut got = Vec::new();
    while let Some(m) = slow.next(WAIT).await {
        got.push(m.event);
    }
    assert_eq!(got.last().map(String::as_str), Some("reset"), "{got:?}");
    assert!(got.len() < 20, "{got:?}");
    // A stream ends at its age limit.
    let mut short = open(&w, &t, None, "").await.unwrap();
    let start = std::time::Instant::now();
    while short.next(Duration::from_secs(5)).await.is_some() {}
    assert!(start.elapsed() < Duration::from_secs(4));
    w.finish().await;
}
