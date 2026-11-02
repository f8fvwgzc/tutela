//! The transactional outbox (CONTRACTS.md 8.5, ADR-0035).
//!
//! An event is written by [`emit`] in the transaction of the change it is
//! about, so there is no change without its event and no event without its
//! change: a rolled-back change emits nothing. Its id (a UUIDv7) is fixed
//! when it is written and never changes, so a receiver that gets it twice
//! drops the second copy (at least once, CONTRACTS.md 8.5).
//!
//! **Order without loss.** Each event gets the tenant's next number
//! (`seq`) from a counter on the tenant's revision row, which the writer
//! locks until it commits. So numbers are given in commit order with no
//! gap, a reader ([`events_after`]) that walks `seq` never skips an event
//! that commits late, and a rolled-back change uses no number. Emitting
//! serializes a tenant's writers as a write already does; a write that
//! bumps the revision holds that lock anyway.
//!
//! **Adding an event.** Add a variant to [`OutboxEvent`] (its type, subject
//! and data follow CONTRACTS.md 8.3), and call [`emit`] in the change's
//! transaction. The org lifecycle events of part 3c exist already:
//! `emit(tx, tenant, OutboxEvent::OrgCreated { org })` is all it takes.

use std::time::SystemTime;

use serde_json::{Map, Value, json};
use tokio_postgres::{Row, Transaction};
use tutela_contracts::events::{CloudEvent, EventSource, EventSubject, EventType};
use tutela_contracts::id::{SessionId, Uuid7};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::{OrgId, TenantId, TenantKey};
use tutela_contracts::timestamp::Timestamp;

use crate::{DbResult as _, StoreError, enter, uuid7};

/// The most events [`events_after`] returns at once.
pub const MAX_EVENT_PAGE: usize = 1000;

/// One event of CONTRACTS.md 8.3, as a change emits it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum OutboxEvent {
    /// `tutela.user.created.v1`: a person was made (just-in-time
    /// provisioning).
    UserCreated {
        /// The user principal.
        user: Principal,
    },
    /// `tutela.user.disabled.v1`, sent with `tutela.principal.disabled.v1`.
    UserDisabled {
        /// The user principal.
        user: Principal,
        /// Its new epoch.
        epoch: u64,
    },
    /// `tutela.user.deleted.v1` (part 3c).
    UserDeleted {
        /// The user principal.
        user: Principal,
    },
    /// `tutela.org.created.v1` (part 3c).
    OrgCreated {
        /// The org.
        org: OrgId,
    },
    /// `tutela.org.updated.v1` (part 3c).
    OrgUpdated {
        /// The org.
        org: OrgId,
    },
    /// `tutela.org.deleted.v1` (part 3c).
    OrgDeleted {
        /// The org.
        org: OrgId,
        /// When its data is purged.
        purge_after: Timestamp,
    },
    /// `tutela.session.revoked.v1`: a user's sessions were revoked.
    SessionRevoked {
        /// The user principal.
        principal: Principal,
        /// Its new epoch.
        epoch: u64,
        /// The one session, or `None` for all of them.
        sid: Option<SessionId>,
    },
    /// `tutela.principal.disabled.v1`.
    PrincipalDisabled {
        /// The principal, any kind.
        principal: Principal,
        /// Its new epoch.
        epoch: u64,
    },
    /// `tutela.principal.enabled.v1` (new in Phase B, additive): a disabled
    /// principal may act again, with tokens of `epoch` or later.
    PrincipalEnabled {
        /// The principal, any kind.
        principal: Principal,
        /// Its epoch: tokens of an older one stay refused.
        epoch: u64,
    },
    /// `tutela.model.published.v1`: a new model version.
    ModelPublished {
        /// The new tenant revision.
        rev: u64,
    },
    /// `tutela.permissions.changed.v1`: assignments, groups, field rules,
    /// boundary rules or scopes changed.
    PermissionsChanged {
        /// The new tenant revision.
        rev: u64,
    },
}

impl OutboxEvent {
    /// The event type.
    #[must_use]
    pub fn event_type(&self) -> EventType {
        match self {
            Self::UserCreated { .. } => EventType::USER_CREATED,
            Self::UserDisabled { .. } => EventType::USER_DISABLED,
            Self::UserDeleted { .. } => EventType::USER_DELETED,
            Self::OrgCreated { .. } => EventType::ORG_CREATED,
            Self::OrgUpdated { .. } => EventType::ORG_UPDATED,
            Self::OrgDeleted { .. } => EventType::ORG_DELETED,
            Self::SessionRevoked { .. } => EventType::SESSION_REVOKED,
            Self::PrincipalDisabled { .. } => EventType::PRINCIPAL_DISABLED,
            Self::PrincipalEnabled { .. } => EventType::PRINCIPAL_ENABLED,
            Self::ModelPublished { .. } => EventType::MODEL_PUBLISHED,
            Self::PermissionsChanged { .. } => EventType::PERMISSIONS_CHANGED,
        }
    }

    /// The subject, the org it is about, and the data (CONTRACTS.md 8.3).
    fn parts(&self, tid: &TenantId) -> (EventSubject, Option<OrgId>, Value) {
        match self {
            Self::UserCreated { user } | Self::UserDeleted { user } => {
                (user.into(), None, json!({ "user": user.to_string() }))
            }
            Self::UserDisabled { user, epoch } => (
                user.into(),
                None,
                json!({ "user": user.to_string(), "epoch": epoch }),
            ),
            Self::OrgCreated { org } | Self::OrgUpdated { org } => {
                ((*org).into(), Some(*org), json!({ "org": org.to_string() }))
            }
            Self::OrgDeleted { org, purge_after } => (
                (*org).into(),
                Some(*org),
                json!({ "org": org.to_string(), "purge_after": purge_after.to_string() }),
            ),
            Self::SessionRevoked {
                principal,
                epoch,
                sid,
            } => {
                let mut data = json!({ "principal": principal.to_string(), "epoch": epoch });
                if let (Some(sid), Value::Object(m)) = (sid, &mut data) {
                    m.insert("sid".to_owned(), Value::from(sid.to_string()));
                }
                (principal.into(), None, data)
            }
            Self::PrincipalDisabled { principal, epoch }
            | Self::PrincipalEnabled { principal, epoch } => (
                principal.into(),
                None,
                json!({ "principal": principal.to_string(), "epoch": epoch }),
            ),
            Self::ModelPublished { rev } | Self::PermissionsChanged { rev } => {
                ((*tid).into(), None, json!({ "rev": rev }))
            }
        }
    }
}

/// Where a reader is in a tenant's events: after the event with this
/// `seq`. `0` is before the first. Readers keep it and ask for what comes
/// after.
pub type Cursor = u64;

/// One stored event.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoredEvent {
    /// Its number in the tenant, from 1, in commit order with no gap: the
    /// place for the next [`events_after`].
    pub seq: Cursor,
    /// The event id, also the idempotency key.
    pub id: Uuid7,
    /// The type.
    pub event_type: EventType,
    /// The subject.
    pub subject: EventSubject,
    /// The org, when the event is about one.
    pub org: Option<OrgId>,
    /// The data object.
    pub data: Map<String, Value>,
    /// When the change happened.
    pub time: Timestamp,
}

impl StoredEvent {
    /// The CloudEvents envelope (CONTRACTS.md 8.1), from `source`.
    #[must_use]
    pub fn cloud(&self, source: EventSource) -> CloudEvent<Map<String, Value>> {
        let mut e = CloudEvent::new(
            self.id,
            source,
            self.event_type.clone(),
            self.subject.clone(),
            self.time,
            self.data.clone(),
        );
        e.orgid = self.org;
        e
    }
}

/// Writes `event` in the caller's transaction, the one of its change.
/// Returns its id.
///
/// # Errors
///
/// [`Invalid`](crate::StoreErrorKind::Invalid) for a `user` field that is not
/// a user, [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a
/// database error.
pub async fn emit(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    event: OutboxEvent,
) -> Result<Uuid7, StoreError> {
    enter(tx, tenant).await?;
    insert(tx, &tenant.tid, &event).await
}

/// [`emit`] in a transaction that has set the tenant already, without the
/// directory check: for the store's own writes.
pub(crate) async fn insert(
    tx: &Transaction<'_>,
    tid: &TenantId,
    event: &OutboxEvent,
) -> Result<Uuid7, StoreError> {
    let user_only = match event {
        OutboxEvent::UserCreated { user }
        | OutboxEvent::UserDeleted { user }
        | OutboxEvent::UserDisabled { user, .. } => Some(user),
        OutboxEvent::SessionRevoked { principal, .. } => Some(principal),
        _ => None,
    };
    if user_only.is_some_and(|p| p.kind() != PrincipalKind::User) {
        return Err(StoreError::invalid("this event is about a user principal"));
    }
    let id = uuid7()?;
    let (subject, org, data) = event.parts(tid);
    // The counter row stays locked until the transaction ends: numbers are
    // given in commit order.
    let seq: i64 = tx
        .query_opt(
            "UPDATE tutela.tenant_rev SET event_seq = event_seq + 1 WHERE tenant_id = $1 \
             RETURNING event_seq",
            &[&tid.to_string()],
        )
        .await
        .db()?
        .ok_or(StoreError::corrupt("tenant revision row"))?
        .try_get(0)
        .db()?;
    tx.execute(
        "INSERT INTO tutela.event (tenant_id, seq, id, type, subject, org_id, data) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            &tid.to_string(),
            &seq,
            &id.to_string(),
            &event.event_type().as_str(),
            &subject.as_str(),
            &org.map(|o| o.to_string()),
            &data.to_string(),
        ],
    )
    .await
    .db()?;
    Ok(id)
}

const COLUMNS: &str = "seq, id, type, subject, org_id, data, \
    (extract(epoch FROM time) * 1000)::bigint";

fn stored(r: &Row) -> Result<StoredEvent, StoreError> {
    let corrupt = |_| StoreError::corrupt("event");
    let seq: i64 = r.try_get(0).db()?;
    let id: String = r.try_get(1).db()?;
    let ty: String = r.try_get(2).db()?;
    let subject: String = r.try_get(3).db()?;
    let org: Option<String> = r.try_get(4).db()?;
    let data: String = r.try_get(5).db()?;
    let millis: i64 = r.try_get(6).db()?;
    let Value::Object(data) =
        serde_json::from_str(&data).map_err(|_| StoreError::corrupt("event"))?
    else {
        return Err(StoreError::corrupt("event"));
    };
    Ok(StoredEvent {
        seq: u64::try_from(seq).map_err(|_| StoreError::corrupt("event"))?,
        id: Uuid7::parse(&id).map_err(corrupt)?,
        event_type: EventType::parse(&ty).map_err(|_| StoreError::corrupt("event"))?,
        subject: EventSubject::parse(&subject).map_err(|_| StoreError::corrupt("event"))?,
        org: org
            .map(|o| o.parse())
            .transpose()
            .map_err(|_| StoreError::corrupt("event"))?,
        data,
        time: Timestamp::from_unix_millis(millis).map_err(|_| StoreError::corrupt("event"))?,
    })
}

/// Up to `limit` (at most [`MAX_EVENT_PAGE`]) events of `tenant` after
/// `after`, in `seq` order. An event of a transaction still running is
/// never skipped: no later number exists until it ends.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn events_after(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    after: Cursor,
    limit: usize,
) -> Result<Vec<StoredEvent>, StoreError> {
    enter(tx, tenant).await?;
    let limit = i64::try_from(limit.clamp(1, MAX_EVENT_PAGE))
        .map_err(|_| StoreError::invalid("a page size"))?;
    let after = i64::try_from(after).map_err(|_| StoreError::invalid("an event position"))?;
    let rows = tx
        .query(
            &format!(
                "SELECT {COLUMNS} FROM tutela.event WHERE tenant_id = $1 AND seq > $2 \
                 ORDER BY seq LIMIT $3"
            ),
            &[&tenant.tid.to_string(), &after, &limit],
        )
        .await
        .db()?;
    rows.iter().map(stored).collect()
}

/// The event with number `seq` of `tenant`, or `None` when it was pruned.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn event_at(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    seq: Cursor,
) -> Result<Option<StoredEvent>, StoreError> {
    enter(tx, tenant).await?;
    let seq = i64::try_from(seq).map_err(|_| StoreError::invalid("an event position"))?;
    tx.query_opt(
        &format!("SELECT {COLUMNS} FROM tutela.event WHERE tenant_id = $1 AND seq = $2"),
        &[&tenant.tid.to_string(), &seq],
    )
    .await
    .db()?
    .as_ref()
    .map(stored)
    .transpose()
}

/// The place of event `id` in `tenant`, to go on after it (an SSE
/// `Last-Event-ID`), or `None` when the tenant has no such event: it was
/// pruned, or it never was.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn event_cursor(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    id: &Uuid7,
) -> Result<Option<Cursor>, StoreError> {
    enter(tx, tenant).await?;
    tx.query_opt(
        "SELECT seq FROM tutela.event WHERE tenant_id = $1 AND id = $2",
        &[&tenant.tid.to_string(), &id.to_string()],
    )
    .await
    .db()?
    .map(|r| u64::try_from(r.try_get::<_, i64>(0).db()?).map_err(|_| StoreError::corrupt("event")))
    .transpose()
}

/// The place of "now" in `tenant`: the last number given. A new reader
/// starts here, and gets every event committed after this call.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn events_now(tx: &Transaction<'_>, tenant: &TenantKey) -> Result<Cursor, StoreError> {
    enter(tx, tenant).await?;
    let seq: i64 = tx
        .query_opt(
            "SELECT event_seq FROM tutela.tenant_rev WHERE tenant_id = $1",
            &[&tenant.tid.to_string()],
        )
        .await
        .db()?
        .ok_or(StoreError::corrupt("tenant revision row"))?
        .try_get(0)
        .db()?;
    u64::try_from(seq).map_err(|_| StoreError::corrupt("tenant revision row"))
}

/// Removes `tenant`'s events written before `before`. Returns how many.
///
/// # Errors
///
/// [`UnknownTenant`](crate::StoreErrorKind::UnknownTenant), or a database
/// error.
pub async fn prune_events(
    tx: &Transaction<'_>,
    tenant: &TenantKey,
    before: SystemTime,
) -> Result<u64, StoreError> {
    enter(tx, tenant).await?;
    tx.execute(
        "DELETE FROM tutela.event WHERE tenant_id = $1 AND time < $2",
        &[&tenant.tid.to_string(), &before],
    )
    .await
    .db()
}
