//! `GET /v1/events`: a tenant's events as Server-Sent Events (CONTRACTS.md
//! 8.6, ADR-0037).
//!
//! **Who may listen.** A service (`sa`, `key`) of the tenant, with a token
//! of the service's own audience: a stream shows every principal of the
//! tenant that was revoked or disabled, and every model and revision
//! change, as `search/subject` does (ADR-0022 item 6). A person, an agent, a
//! delegated or an external token gets 403. A browser listens through its
//! product's backend.
//!
//! **What comes.** First `event: denied_kids` (the service's own `kid`
//! deny-list, TM-15) and `event: rev` (the tenant's revision); then each
//! event of the tenant, `id:` its id, `event:` its type, `data:` the
//! CloudEvent on one line; `rev` again whenever the revision moves, and
//! `denied_kids` whenever the deny-list changes. A receiver drops its cached
//! JWKS on a new `denied_kids` (`Verifier::forget_jwks`), and stops waiting
//! for its lease on a new `rev`.
//!
//! **Resume.** `Last-Event-ID` names the last event seen; the stream goes on
//! after it. An id the tenant no longer has (pruned, or never its own) gets
//! `event: reset` first: reload the cache. A client that falls behind the
//! stream's buffer gets `reset` and the stream ends; it reconnects with its
//! `Last-Event-ID`.
//!
//! **Bounds.** At most `TUTELA_SSE_MAX_STREAMS` streams per replica (503
//! after), each for at most `TUTELA_SSE_MAX_SECS` and never past its token's
//! `exp`. A stream holds no database connection: one feed per tenant reads
//! the outbox every `TUTELA_EVENTS_POLL_MS` for all of its streams, and a
//! resumed stream reads its gap a page at a time. Each stream checks every
//! few seconds that its token's principal was not revoked.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::sync::broadcast;
use tutela_contracts::events::EventType;
use tutela_contracts::id::Uuid7;
use tutela_contracts::principal::PrincipalKind;
use tutela_contracts::tenant::{Issuer, TenantKey};
use tutela_sdk::Identity;
use tutela_store::StoredEvent;

use crate::api::{AppState, Problem};
use crate::db::Db;
use crate::keys::KeyRing;
use crate::tenant::Tenant;

/// How the event streams of a replica behave.
#[derive(Clone, Copy, Debug)]
pub struct StreamSettings {
    /// `TUTELA_EVENTS_POLL_MS`: how often a tenant's feed reads the outbox.
    pub poll: Duration,
    /// `TUTELA_SSE_MAX_STREAMS`: open streams per replica.
    pub max_streams: usize,
    /// `TUTELA_SSE_MAX_SECS`: the longest one stream lasts.
    pub max_age: Duration,
    /// Messages a feed keeps for a stream that is behind; past it the
    /// stream gets `reset` and ends.
    pub buffer: usize,
    /// How often a stream checks that its principal was not revoked.
    pub recheck: Duration,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            poll: Duration::from_millis(500),
            max_streams: 1000,
            max_age: Duration::from_secs(900),
            buffer: 256,
            recheck: Duration::from_secs(5),
        }
    }
}

/// One message of a tenant's feed.
#[derive(Clone, Debug)]
enum Msg {
    Event(Arc<StoredEvent>),
    Rev(u64),
    Denied(Arc<Vec<String>>),
}

/// The feeds of this replica, one per tenant with a stream open, and the
/// count of open streams.
#[derive(Debug)]
pub struct Hub {
    db: Db,
    keys: Arc<KeyRing>,
    settings: StreamSettings,
    open: Arc<AtomicUsize>,
    feeds: Mutex<HashMap<TenantKey, broadcast::Sender<Msg>>>,
    closed: tokio::sync::watch::Sender<bool>,
}

impl Hub {
    /// A hub over `db`, pushing `keys`' deny-list.
    #[must_use]
    pub fn new(db: Db, keys: Arc<KeyRing>, settings: StreamSettings) -> Self {
        Self {
            db,
            keys,
            settings,
            open: Arc::default(),
            feeds: Mutex::new(HashMap::new()),
            closed: tokio::sync::watch::Sender::new(false),
        }
    }

    /// Ends every stream of this replica, and refuses new ones: a shutdown
    /// starts with this, so clients reconnect to another replica with their
    /// `Last-Event-ID` while requests drain.
    pub fn close(&self) {
        self.closed.send_replace(true);
    }

    /// Streams open on this replica now.
    #[must_use]
    pub fn open_streams(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }

    /// A receiver of `tenant`'s feed, starting the feed at `start` (the
    /// outbox's number read just before) when it has none.
    fn subscribe(
        self: &Arc<Self>,
        tenant: &Tenant,
        start: u64,
    ) -> Result<broadcast::Receiver<Msg>, Problem> {
        let mut feeds = self
            .feeds
            .lock()
            .map_err(|_| Problem::stale("unavailable"))?;
        if let Some(tx) = feeds.get(tenant.key()) {
            return Ok(tx.subscribe());
        }
        let (tx, rx) = broadcast::channel(self.settings.buffer.max(1));
        feeds.insert(tenant.key().clone(), tx.clone());
        tokio::spawn(Arc::clone(self).feed(tenant.clone(), tx, start));
        Ok(rx)
    }

    /// Reads `tenant`'s outbox, revision and the deny-list for its streams,
    /// until none is left.
    async fn feed(self: Arc<Self>, tenant: Tenant, tx: broadcast::Sender<Msg>, start: u64) {
        let mut after = start;
        let mut rev: Option<u64> = None;
        let mut denied: Option<Vec<String>> = None;
        loop {
            {
                // Ends under the lock, so a new stream never joins a feed
                // that is about to stop.
                let Ok(mut feeds) = self.feeds.lock() else {
                    return;
                };
                if tx.receiver_count() == 0 {
                    feeds.remove(tenant.key());
                    return;
                }
            }
            let kids = self.keys.denied();
            if denied.as_ref() != Some(&kids) {
                let _ = tx.send(Msg::Denied(Arc::new(kids.clone())));
                denied = Some(kids);
            }
            match read(&self.db, &tenant, after).await {
                Ok((events, current)) => {
                    for e in events {
                        after = e.seq;
                        let _ = tx.send(Msg::Event(Arc::new(e)));
                    }
                    if rev != Some(current) {
                        let _ = tx.send(Msg::Rev(current));
                        rev = Some(current);
                    }
                }
                Err(e) => tracing::warn!(
                    tid = %tenant.key().tid,
                    error = %e,
                    "an event feed could not read the outbox"
                ),
            }
            tokio::time::sleep(self.settings.poll).await;
        }
    }
}

/// The events of `tenant` after `after`, and its revision.
async fn read(
    db: &Db,
    tenant: &Tenant,
    after: u64,
) -> Result<(Vec<StoredEvent>, u64), crate::db::DbError> {
    let mut conn = db.conn().await?;
    let tx = conn.begin(tenant).await?;
    let events = tutela_store::events_after(&tx, tenant.key(), after, 500).await?;
    let rev = tutela_store::rev(&tx, tenant.key()).await?;
    tx.commit().await?;
    Ok((events, rev))
}

/// `?types=` of `GET /v1/events`.
#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    types: Option<String>,
}

/// Counts an open stream, and uncounts it when dropped.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Where a stream is.
enum Phase {
    /// The first messages: `reset` when asked for, `denied_kids`, `rev`.
    Hello(Vec<Event>),
    /// Reading the gap after `Last-Event-ID` from the outbox.
    Replay,
    /// Following the feed.
    Live,
    /// Done.
    End,
}

struct Stream {
    state: AppState,
    id: Identity,
    tenant: Tenant,
    own: Issuer,
    types: Option<Vec<EventType>>,
    rx: broadcast::Receiver<Msg>,
    after: u64,
    phase: Phase,
    queue: std::collections::VecDeque<Event>,
    until: tokio::time::Instant,
    next_check: tokio::time::Instant,
    closed: tokio::sync::watch::Receiver<bool>,
    _slot: Slot,
}

fn message(own: &Issuer, tenant: &TenantKey, e: &StoredEvent) -> Option<Event> {
    let ce = crate::events::envelope(own, tenant.tid, e).ok()?;
    let data = serde_json::to_string(&ce).ok()?;
    Some(
        Event::default()
            .id(e.id.to_string())
            .event(e.event_type.as_str())
            .data(data),
    )
}

fn reset() -> Event {
    Event::default().event("reset").data("{}")
}

impl Stream {
    fn wanted(&self, e: &StoredEvent) -> bool {
        self.types
            .as_ref()
            .is_none_or(|t| t.contains(&e.event_type))
    }

    /// Takes `e` in order. Returns `false` for an event past a gap: the
    /// stream reads the gap from the outbox first (numbers have no gap, so
    /// a jump means this stream missed something).
    fn take(&mut self, e: &StoredEvent) -> bool {
        if e.seq <= self.after {
            return true;
        }
        if e.seq > self.after + 1 {
            return false;
        }
        self.after = e.seq;
        if self.wanted(e)
            && let Some(m) = message(&self.own, self.tenant.key(), e)
        {
            self.queue.push_back(m);
        }
        true
    }

    /// The next message, or `None` when the stream ends.
    async fn next(&mut self) -> Option<Event> {
        loop {
            if let Some(m) = self.queue.pop_front() {
                return Some(m);
            }
            if *self.closed.borrow() {
                return None;
            }
            match std::mem::replace(&mut self.phase, Phase::End) {
                Phase::Hello(first) => {
                    self.queue.extend(first);
                    self.phase = Phase::Replay;
                }
                Phase::Replay => {
                    let page = replay(&self.state.db, &self.tenant, self.after)
                        .await
                        .ok()?;
                    if page.is_empty() {
                        self.phase = Phase::Live;
                    } else {
                        for e in &page {
                            self.take(e);
                        }
                        self.phase = Phase::Replay;
                    }
                }
                Phase::Live => {
                    self.phase = Phase::Live;
                    let now = tokio::time::Instant::now();
                    if now >= self.until {
                        self.phase = Phase::End;
                        continue;
                    }
                    if now >= self.next_check {
                        if self.state.revocations.check(&self.id).await.is_err() {
                            self.phase = Phase::End;
                            continue;
                        }
                        self.next_check = now + self.state.events.settings.recheck;
                    }
                    let wake = self.until.min(self.next_check);
                    let (rx, closed) = (&mut self.rx, &mut self.closed);
                    let woke = tokio::select! {
                        got = rx.recv() => Some(got),
                        () = tokio::time::sleep_until(wake) => None,
                        _ = closed.wait_for(|c| *c) => {
                            self.phase = Phase::End;
                            None
                        }
                    };
                    match woke {
                        Some(Ok(Msg::Event(e))) => {
                            if !self.take(&e) {
                                self.phase = Phase::Replay;
                            }
                        }
                        Some(Ok(Msg::Rev(rev))) => self.queue.push_back(
                            Event::default()
                                .event("rev")
                                .data(format!("{{\"rev\":{rev}}}")),
                        ),
                        Some(Ok(Msg::Denied(kids))) => {
                            self.queue.push_back(denied(&self.own, &kids));
                        }
                        Some(Err(broadcast::error::RecvError::Lagged(_))) => {
                            self.queue.push_back(reset());
                            self.phase = Phase::End;
                        }
                        Some(Err(broadcast::error::RecvError::Closed)) => self.phase = Phase::End,
                        None => {}
                    }
                }
                Phase::End => return None,
            }
        }
    }
}

fn denied(own: &Issuer, kids: &[String]) -> Event {
    let data = serde_json::json!({
        "iss": own.as_str(),
        "jwks_uri": crate::keys::jwks_url(own),
        "kids": kids,
    });
    Event::default().event("denied_kids").data(data.to_string())
}

async fn replay(
    db: &Db,
    tenant: &Tenant,
    after: u64,
) -> Result<Vec<StoredEvent>, crate::db::DbError> {
    let mut conn = db.conn().await?;
    let tx = conn.begin(tenant).await?;
    let page = tutela_store::events_after(&tx, tenant.key(), after, 200).await?;
    tx.commit().await?;
    Ok(page)
}

/// `GET /v1/events`.
pub async fn events(
    State(state): State<AppState>,
    Extension(id): Extension<Identity>,
    Query(q): Query<StreamQuery>,
    headers: HeaderMap,
) -> Response {
    match open(state, id, q, &headers).await {
        Ok(r) => r,
        Err(p) => p.into_response(),
    }
}

async fn open(
    state: AppState,
    id: Identity,
    q: StreamQuery,
    headers: &HeaderMap,
) -> Result<Response, Problem> {
    // A service of the tenant, with a token of this service's audience.
    let exp = match &id {
        Identity::Access(c)
            if matches!(
                c.sub.kind(),
                PrincipalKind::ServiceAccount | PrincipalKind::Key
            ) =>
        {
            c.exp
        }
        _ => {
            state.metrics.count_stream("forbidden");
            return Err(Problem::forbidden());
        }
    };
    let tenant = Tenant::of(&id);
    let types = match q.types.as_deref() {
        None | Some("") => None,
        Some(list) => {
            let parsed: Result<Vec<EventType>, _> = list.split(',').map(EventType::parse).collect();
            match parsed {
                Ok(t) if t.len() <= 32 => Some(t),
                _ => {
                    state.metrics.count_stream("invalid");
                    return Err(Problem::invalid(
                        "invalid_request",
                        "`types` is a comma-separated list of at most 32 event types".to_owned(),
                    ));
                }
            }
        }
    };
    let hub = Arc::clone(&state.events);
    if *hub.closed.borrow() {
        state.metrics.count_stream("full");
        return Err(Problem::stale("stopping"));
    }
    if hub.open.fetch_add(1, Ordering::SeqCst) >= hub.settings.max_streams {
        hub.open.fetch_sub(1, Ordering::SeqCst);
        state.metrics.count_stream("full");
        return Err(Problem::stale("too_many_streams"));
    }
    let slot = Slot(Arc::clone(&hub.open));
    let last = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let (after, lost, rev, now) = {
        let mut conn = state.db.conn().await?;
        let tx = conn.begin(&tenant).await?;
        let now = tutela_store::events_now(&tx, tenant.key()).await?;
        let found = match last.map(Uuid7::parse) {
            Some(Ok(id)) => tutela_store::event_cursor(&tx, tenant.key(), &id).await?,
            _ => None,
        };
        let rev = tutela_store::rev(&tx, tenant.key()).await?;
        tx.commit().await?;
        match (last, found) {
            (None, _) => (now, false, rev, now),
            (Some(_), Some(seq)) => (seq, false, rev, now),
            (Some(_), None) => (now, true, rev, now),
        }
    };
    // The feed starts at `now` when it is new; the replay reads from the
    // outbox past whatever the feed sent before this stream joined.
    let rx = hub.subscribe(&tenant, now)?;
    let own = state.keys.iss().clone();
    let mut first = Vec::new();
    if lost {
        first.push(reset());
    }
    first.push(denied(&own, &state.keys.denied()));
    first.push(
        Event::default()
            .event("rev")
            .data(format!("{{\"rev\":{rev}}}")),
    );
    let left = Duration::from_secs(
        exp.saturating_sub(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        ),
    );
    let now = tokio::time::Instant::now();
    let settings = hub.settings;
    let stream = Stream {
        until: now + left.min(settings.max_age),
        next_check: now + settings.recheck,
        state: state.clone(),
        id,
        tenant,
        own,
        types,
        rx,
        after,
        phase: Phase::Hello(first),
        queue: std::collections::VecDeque::new(),
        closed: hub.closed.subscribe(),
        _slot: slot,
    };
    state.metrics.count_stream("opened");
    let body = futures_util::stream::unfold(stream, |mut s| async move {
        s.next().await.map(|m| (Ok::<_, Infallible>(m), s))
    });
    let mut res = Sse::new(body)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response();
    res.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(res)
}
