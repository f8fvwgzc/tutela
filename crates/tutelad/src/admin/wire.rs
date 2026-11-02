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
