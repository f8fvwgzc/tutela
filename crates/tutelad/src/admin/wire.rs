//! The JSON of the admin routes (CONTRACTS.md 7.13). gRPC carries the same
//! fields (`tutela.admin.v1`).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tutela_store::PrincipalState;

/// `POST /v1/admin/agents`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterAgentBody {
    /// The SPIFFE id of the workload the agent runs as, on attache's path
    /// `/ns/<namespace>/svc/<service>`.
    pub workload: Option<String>,
}

/// A body that names one principal.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalBody {
    /// `user:usr_<uuidv7>` or `agent:agt_<uuidv7>`.
    pub principal: Option<String>,
}

/// `POST /v1/admin/principals/disabled`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetDisabledBody {
    /// The principal.
    pub principal: Option<String>,
    /// `true` disables it, `false` enables it again.
    pub disabled: Option<bool>,
}

/// One principal of the tenant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalOut {
    /// The principal.
    pub principal: String,
    /// Its epoch: a token with a lower one is refused.
    pub epoch: u64,
    /// `true` while it is disabled.
    pub disabled: bool,
    /// The workload an agent runs as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    /// The tenant revision after a change that bumped it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<u64>,
}

impl PrincipalOut {
    /// The answer for `s`, after a change to revision `rev`.
    #[must_use]
    pub fn of(s: &PrincipalState, rev: Option<u64>) -> Self {
        Self {
            principal: s.principal.to_string(),
            epoch: s.epoch,
            disabled: s.disabled,
            workload: s.workload.as_ref().map(ToString::to_string),
            rev,
        }
    }
}

/// The query of `GET /v1/admin/agents`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AgentsQuery {
    /// The `next_after` of the page before.
    pub after: Option<String>,
    /// How many. At most 1000; 100 when missing.
    pub limit: Option<usize>,
    /// Only the agent of this workload.
    pub workload: Option<String>,
}

/// A page of agents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentsOut {
    /// The agents, by principal.
    pub agents: Vec<PrincipalOut>,
    /// Where the next page starts; missing at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}

/// `PUT /v1/admin/boundaries`: the move and link rules of a scope, in the
/// words of PERMISSION-MODEL.md 9 and 10. A rule left out is not set.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryBody {
    /// The registered scope.
    pub scope: Option<ScopeRef>,
    /// `members`, `owners` or `none`.
    pub moves_out: Option<String>,
    /// `members`, `owners` or `none`.
    pub moves_in: Option<String>,
    /// `approve` or `block`.
    pub on_looser: Option<String>,
    /// `any`, `team` or `none`.
    pub links_from: Option<String>,
}

/// A scope: `{"type", "id"}`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeRef {
    /// The type.
    #[serde(rename = "type")]
    pub kind: String,
    /// The product's id.
    pub id: String,
}

/// A change that bumped the tenant revision.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevOut {
    /// The new revision: send it as `at_least_revision`.
    pub rev: u64,
}

/// `POST /v1/admin/resource-types`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceTypesBody {
    /// Type name to its definition, in the keys of MANIFEST.md 4.
    pub types: Option<Map<String, Value>>,
    /// The active version the caller compared against.
    pub expected_version: Option<i64>,
}

/// `PATCH /v1/admin/tenant` and the body of a new or renamed org.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameBody {
    /// The display name, 1 to 200 characters. Missing or `null` clears it.
    pub name: Option<String>,
}

/// A tenant, as its admin sees it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantOut {
    /// `ten_<uuidv7>`.
    pub tid: String,
    /// The issuer of its tenant key.
    pub iss: String,
    /// Its display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When it was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// After a soft delete: when its data is purged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purge_after: Option<String>,
}

/// One org of the tenant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgOut {
    /// `org_<uuidv7>`.
    pub org: String,
    /// Its display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When it was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// When it was soft-deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    /// When its data is purged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purge_after: Option<String>,
    /// When its data was purged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purged_at: Option<String>,
    /// The tenant revision after a change that bumped it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<u64>,
}

impl OrgOut {
    /// The answer for `o`, after a change to revision `rev`.
    #[must_use]
    pub fn of(o: &tutela_store::OrgInfo, rev: Option<u64>) -> Self {
        use crate::models::wire::time;
        Self {
            org: o.org.to_string(),
            name: o.name.clone(),
            created_at: time(o.created_at),
            deleted_at: o.deleted_at.and_then(time),
            purge_after: o.purge_after.and_then(time),
            purged_at: o.purged_at.and_then(time),
            rev,
        }
    }
}

/// The tenant's orgs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgsOut {
    /// Oldest first, the deleted ones too.
    pub orgs: Vec<OrgOut>,
}

/// `POST /v1/admin/webhooks`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterWebhookBody {
    /// The endpoint: `https`, a public address.
    pub url: Option<String>,
    /// The event types it gets; missing or empty: every type.
    pub types: Option<Vec<String>>,
}

/// `POST /v1/admin/webhooks/{id}/rotate`.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateBody {
    /// How long the old secret keeps signing; default 3600, at most 604800.
    pub overlap_secs: Option<u64>,
}

/// One webhook. Never its secret.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookOut {
    /// `whk_<uuidv7>`.
    pub id: String,
    /// The endpoint.
    pub url: String,
    /// The event types it gets; empty: every type.
    pub types: Vec<String>,
    /// `true` once it is disabled.
    pub disabled: bool,
    /// Who registered it.
    pub created_by: String,
}

/// A webhook and its new secret: the one answer that shows it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookSecretOut {
    /// The webhook.
    pub webhook: WebhookOut,
    /// `whsec_<base64 of 32 random bytes>`. Shown this once.
    pub secret: String,
}

/// The tenant's webhooks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhooksOut {
    /// Oldest first.
    pub webhooks: Vec<WebhookOut>,
}

/// The query of `GET /v1/admin/webhooks/{id}/deliveries`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DeliveriesQuery {
    /// `dead`: only the dead ones.
    pub state: Option<String>,
    /// The `next_after` of the page before.
    pub after: Option<u64>,
    /// How many. At most 1000; 100 when missing.
    pub limit: Option<usize>,
}

/// One delivery.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryOut {
    /// The webhook.
    pub webhook: String,
    /// The event's number in the tenant.
    pub seq: u64,
    /// `pending`, `delivered` or `dead`.
    pub state: String,
    /// Attempts made.
    pub attempts: u32,
    /// The last answer's status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_status: Option<u16>,
    /// The last error code (`status`, `timeout`, `not_public`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl DeliveryOut {
    /// The answer for a stored delivery.
    #[must_use]
    pub fn of(d: tutela_store::webhooks::Delivery) -> Self {
        Self {
            webhook: d.webhook_id,
            seq: d.seq,
            state: d.state,
            attempts: d.attempts,
            last_status: d.last_status,
            last_error: d.last_error,
        }
    }
}

/// A page of deliveries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveriesOut {
    /// By event number.
    pub deliveries: Vec<DeliveryOut>,
    /// Where the next page starts; missing at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after: Option<u64>,
}
