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

// ---------- Scopes, role assignments and groups (CONTRACTS.md 7.13.7) ----------

/// A field that may be missing, `null` or a value: `Some(None)` is `null`.
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// `POST /v1/admin/scopes`: registers a scope under its parent.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutScopeBody {
    /// The new scope.
    pub scope: Option<ScopeRef>,
    /// Its parent: an org of the tenant or a registered scope.
    pub parent: Option<ScopeRef>,
    /// `true`: it stops inheritance from above. Missing: what its type
    /// starts as (`starts` in the model).
    pub private: Option<bool>,
}

/// `POST /v1/admin/scopes/move`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveScopeBody {
    /// The registered scope to move.
    pub scope: Option<ScopeRef>,
    /// Its new parent: an org of the tenant or a registered scope.
    pub parent: Option<ScopeRef>,
    /// Who agreed to a move into a looser scope, in the product's own flow.
    /// A service only (CONTRACTS.md 7.8).
    pub approved_by: Option<Vec<String>>,
}

/// A body that names one scope.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBody {
    /// The registered scope.
    pub scope: Option<ScopeRef>,
}

/// `PUT /v1/admin/scopes/private`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateBody {
    /// The registered scope.
    pub scope: Option<ScopeRef>,
    /// `true` stops inheritance from above; `false` lets it in again.
    pub private: Option<bool>,
}

/// The query of `GET /v1/admin/scopes`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ScopesQuery {
    /// `type:id` of an org or a registered scope: the scopes below it.
    pub under: Option<String>,
    /// The `next_after` of the page before.
    pub after: Option<String>,
    /// How many. At most 1000; 100 when missing.
    pub limit: Option<usize>,
}

/// One registered scope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeOut {
    /// The scope.
    pub scope: ScopeRef,
    /// Its ancestors, nearest first, ending at its org.
    pub ancestors: Vec<ScopeRef>,
    /// `true` when it stops inheritance from above.
    pub private: bool,
    /// `members`, `owners` or `none`; missing: not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moves_out: Option<String>,
    /// `members`, `owners` or `none`; missing: not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moves_in: Option<String>,
    /// `approve` or `block`; missing: not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_looser: Option<String>,
    /// `any`, `team` or `none`; missing: not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links_from: Option<String>,
}

/// A page of scopes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopesOut {
    /// By `type:id`.
    pub scopes: Vec<ScopeOut>,
    /// Where the next page starts; missing at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}

/// A registered or moved scope and the new revision.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeChangeOut {
    /// The scope as it is now.
    pub scope: ScopeOut,
    /// The new revision: send it as `at_least_revision`.
    pub rev: u64,
}

/// `POST /v1/admin/assignments`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignBody {
    /// A principal, or `group:<key>`.
    pub subject: Option<String>,
    /// A role of the tenant's model.
    pub role: Option<String>,
    /// An org of the tenant or a registered scope.
    pub scope: Option<ScopeRef>,
    /// RFC 3339; missing: it does not end.
    pub expires_at: Option<String>,
}

/// `PATCH /v1/admin/assignments/{id}`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiryBody {
    /// RFC 3339, or `null` to make it permanent. Required.
    #[serde(default, deserialize_with = "present")]
    pub expires_at: Option<Option<String>>,
}

/// `POST /v1/admin/assignments/list`. A principal is personal data, so the
/// filter is a body, never a query (CONTRACTS.md 9.5).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentsQuery {
    /// Only at this scope.
    pub scope: Option<ScopeRef>,
    /// Only for this principal or `group:<key>`.
    pub subject: Option<String>,
    /// The `next_after` of the page before.
    pub after: Option<String>,
    /// How many. At most 1000; 100 when missing.
    pub limit: Option<usize>,
}

/// One role assignment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssignmentOut {
    /// `ra_<uuidv7>`.
    pub id: String,
    /// A principal, or `group:<key>`.
    pub subject: String,
    /// The role.
    pub role: String,
    /// Where it applies.
    pub scope: ScopeRef,
    /// Who granted it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    /// When it was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// When it ends; missing: never.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl AssignmentOut {
    /// The answer for a stored assignment.
    #[must_use]
    pub fn of(a: &tutela_store::Assignment) -> Self {
        use crate::models::wire::time;
        Self {
            id: a.id.to_string(),
            subject: match &a.subject {
                tutela_pdp::Subject::Principal(p) => p.to_string(),
                tutela_pdp::Subject::Group(g) => format!("group:{g}"),
            },
            role: a.role.to_string(),
            scope: ScopeRef {
                kind: a.scope.type_name.to_string(),
                id: a.scope.id.to_string(),
            },
            granted_by: a.granted_by.as_ref().map(ToString::to_string),
            created_at: time(a.created_at),
            expires_at: a.expires_at.and_then(time),
        }
    }
}

/// A page of assignments.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssignmentsOut {
    /// By id.
    pub assignments: Vec<AssignmentOut>,
    /// Where the next page starts; missing at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}

/// An assignment after a change, and the new revision.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssignmentChangeOut {
    /// The assignment as it is now; missing after a delete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment: Option<AssignmentOut>,
    /// The new revision: send it as `at_least_revision`.
    pub rev: u64,
}

/// `POST /v1/admin/groups`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupBody {
    /// The org it belongs to.
    pub org: Option<String>,
    /// Its key, unique in the tenant.
    pub key: Option<String>,
    /// Its display name, at most 256 characters.
    pub name: Option<String>,
}

/// The query of `GET /v1/admin/groups`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct GroupsQuery {
    /// Only the groups of this org.
    pub org: Option<String>,
    /// The `next_after` of the page before.
    pub after: Option<String>,
    /// How many. At most 1000; 100 when missing.
    pub limit: Option<usize>,
}

/// One group.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupOut {
    /// Its key.
    pub key: String,
    /// The org it belongs to.
    pub org: String,
    /// Its display name.
    pub name: String,
    /// When it was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// How many direct members it has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<u64>,
    /// The tenant revision after a change that bumped it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<u64>,
}

impl GroupOut {
    /// The answer for a stored group.
    #[must_use]
    pub fn of(g: &tutela_store::GroupInfo, members: Option<u64>, rev: Option<u64>) -> Self {
        Self {
            key: g.key.to_string(),
            org: g.org.to_string(),
            name: g.name.clone(),
            created_at: crate::models::wire::time(g.created_at),
            members,
            rev,
        }
    }
}

/// A page of groups.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupsOut {
    /// By key.
    pub groups: Vec<GroupOut>,
    /// Where the next page starts; missing at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}

/// `POST /v1/admin/groups/{key}/members` and `…/members/remove`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberBody {
    /// A principal, or `group:<key>`.
    pub member: Option<String>,
}

/// The query of `GET /v1/admin/groups/{key}/members`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct MembersQuery {
    /// The `next_after` of the page before.
    pub after: Option<String>,
    /// How many. At most 1000; 100 when missing.
    pub limit: Option<usize>,
}

/// A page of a group's direct members.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembersOut {
    /// Principals and `group:<key>`, by their text.
    pub members: Vec<String>,
    /// Where the next page starts; missing at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}

/// The query of `GET /v1/admin/roles`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RolesQuery {
    /// `type:id` of the org or registered scope the caller manages.
    pub scope: Option<String>,
}

/// One role of the tenant's active model: a row of the permission matrix.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleOut {
    /// Its key.
    pub key: String,
    /// Its display label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The seeded role it is (`owner`, `member`, ...), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seeded: Option<String>,
    /// The item level per type; a type not listed is `none`.
    pub levels: std::collections::BTreeMap<String, String>,
    /// Levels of single fields and features (`contract.budget`).
    pub field_levels: std::collections::BTreeMap<String, String>,
    /// Custom-action grants and admin keys (`contract:approve`,
    /// `org:manage_access`).
    pub grants: Vec<String>,
    /// Who may receive it: `user`, `sa`, `key`, `agent`, `workload`, `group`.
    pub assignable_to: Vec<String>,
}

/// One field of a type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldOut {
    /// Its name.
    pub name: String,
    /// `public`, `internal`, `confidential` or `secret`.
    pub sensitivity: String,
    /// Its display label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// One type of the tenant's active model: a column group of the matrix.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeOut {
    /// Its name.
    pub name: String,
    /// Its display label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The types that may be its parent.
    pub parents: Vec<String>,
    /// `true` when other resources may live inside it.
    pub container: bool,
    /// `true` when a new scope of it starts private.
    pub starts_private: bool,
    /// Its data fields.
    pub fields: Vec<FieldOut>,
    /// Its features (`@ai`).
    pub features: Vec<String>,
    /// Its custom actions.
    pub actions: Vec<String>,
}

/// The roles and types of the tenant's active model.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RolesOut {
    /// The active model version.
    pub version: i64,
    /// By key.
    pub roles: Vec<RoleOut>,
    /// By name.
    pub types: Vec<TypeOut>,
}

// ---------- Apps (CONTRACTS.md 7.13.8) ----------

/// One app. Never its secret.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppOut {
    /// Its client id, `app_<uuidv7>`.
    pub client_id: String,
    /// Its display name.
    pub name: String,
    /// Its service account, `sa:sa_<uuidv7>`.
    pub principal: String,
    /// Who made it.
    pub created_by: String,
    /// When it was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// When it was disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<String>,
}

/// An app and a new client secret: the one answer that shows it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppSecretOut {
    /// The app.
    pub app: AppOut,
    /// `tut_sk_<prefix>_<secret>` (CONTRACTS.md 5.1). Shown this once.
    pub client_secret: String,
}

/// The tenant's apps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppsOut {
    /// Oldest first.
    pub apps: Vec<AppOut>,
}
