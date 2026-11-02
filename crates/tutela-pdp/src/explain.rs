//! Why a decision came out as it did (PERMISSION-MODEL.md 15.1, ADR-0028).
//!
//! An explanation is the decision of `check`, the walk of each principal in
//! it, and what each of its `rule_ids` is. It reveals the model and other
//! principals' assignments, so `tutelad` asks a stronger right than a check.

use std::collections::HashMap;

use serde::Serialize;
use tutela_contracts::decision::{Decision, RuleId};

use crate::api::{CheckRequest, PathEntry, PdpError};
use crate::data::Subject;
use crate::eval::{Walk, bindings_at, org_owner};
use crate::pdp::{Pdp, this_entry};

/// What one rule id of a decision is.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleExplained {
    /// A role assignment.
    Assignment {
        /// The id.
        id: RuleId,
        /// A principal string, or `group:<key>`.
        subject: String,
        /// The role.
        role: String,
        /// Where.
        scope: PathEntry,
    },
    /// A field rule at one scope.
    FieldRule {
        /// The id.
        id: RuleId,
        /// Where.
        scope: PathEntry,
        /// The field or feature.
        field: String,
        /// The role, or `None` for all roles.
        role: Option<String>,
        /// The cap.
        max: String,
    },
    /// A field rule of the model, at the org root.
    ModelFieldRule {
        /// The id.
        id: RuleId,
        /// The field or feature.
        field: String,
        /// The role, or `None` for all roles.
        role: Option<String>,
        /// The cap.
        max: String,
    },
    /// A condition of the model that was false.
    Condition {
        /// The id.
        id: RuleId,
        /// The role it narrows.
        role: String,
        /// The type.
        resource_type: String,
        /// The level it leaves.
        otherwise: String,
    },
    /// A boundary rule, or an id this build does not describe.
    Other {
        /// The id.
        id: RuleId,
    },
}

/// One node of a walk, nearest first.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct StepExplained {
    /// The node.
    pub scope: PathEntry,
    /// The assignments here that hold this principal. With some, the walk
    /// stops here.
    pub assignments: Vec<RuleId>,
    /// `true` for a private scope.
    pub private: bool,
}

/// The walk of one principal (PERMISSION-MODEL.md 7.1 step 3).
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct SideExplained {
    /// The person first, then each actor.
    pub principal: String,
    /// `assignment`, `no_role`, `private_scope` or `outside_ai_reach`.
    pub outcome: &'static str,
    /// `true` when the org Owner path decided.
    pub org_owner: bool,
    /// The nodes walked, until the one that decided.
    pub walk: Vec<StepExplained>,
}

/// A decision with its reasons.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Explanation {
    /// What `check` says.
    pub decision: Decision,
    /// Each principal's walk.
    pub sides: Vec<SideExplained>,
    /// What each of `decision.rule_ids` is, in its order.
    pub rules: Vec<RuleExplained>,
}

impl Pdp {
    /// `check`, with the walk of each principal and what each rule id is.
    ///
    /// # Errors
    ///
    /// As [`Pdp::check`].
    pub fn explain(&self, req: &CheckRequest) -> Result<Explanation, PdpError> {
        let decision = self.check(req)?;
        let b = self.bundle(&req.tenant, req.at_least_revision)?;
        let ctx = b.ctx();
        let this = this_entry(&req.resource)?;
        let walk = Walk::new(&b.index, &this, &req.resource.path);
        let mut sides = Vec::new();
        for p in core::iter::once(&req.subject).chain(&req.actors) {
            let mut side = SideExplained {
                principal: p.to_string(),
                outcome: "no_role",
                org_owner: false,
                walk: Vec::new(),
            };
            let owner = walk.org().and_then(|org| org_owner(ctx, org, p));
            if let (Some(bi), Some(org)) = (owner, walk.org()) {
                side.org_owner = true;
                side.outcome = "assignment";
                side.walk.push(StepExplained {
                    scope: org.clone(),
                    assignments: b
                        .index
                        .bindings
                        .get(bi)
                        .map(|x| x.id.clone())
                        .into_iter()
                        .collect(),
                    private: false,
                });
            } else {
                let last = walk.nodes.len().saturating_sub(1);
                for (i, (node, scope)) in walk.nodes.iter().zip(&walk.scopes).enumerate() {
                    let found: Vec<RuleId> = scope
                        .map(|s| bindings_at(&b.index, s, p))
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|bi| b.index.bindings.get(bi).map(|x| x.id.clone()))
                        .collect();
                    let private = scope.is_some_and(|s| s.private);
                    let stop = !found.is_empty() || private;
                    side.walk.push(StepExplained {
                        scope: (*node).clone(),
                        assignments: found.clone(),
                        private,
                    });
                    if !found.is_empty() {
                        let reach = p.kind() == tutela_contracts::principal::PrincipalKind::Agent
                            && i == last;
                        side.outcome = if reach {
                            "outside_ai_reach"
                        } else {
                            "assignment"
                        };
                    } else if private {
                        side.outcome = "private_scope";
                    }
                    if stop {
                        break;
                    }
                }
            }
            sides.push(side);
        }
        let by_id: HashMap<&RuleId, usize> = b
            .index
            .bindings
            .iter()
            .enumerate()
            .map(|(i, x)| (&x.id, i))
            .collect();
        let scope_rules: HashMap<&RuleId, usize> = b
            .index
            .field_rules
            .iter()
            .enumerate()
            .map(|(i, x)| (&x.id, i))
            .collect();
        let rules = decision
            .rule_ids
            .iter()
            .map(|id| {
                if let Some(x) = by_id.get(id).and_then(|&i| b.index.bindings.get(i)) {
                    return RuleExplained::Assignment {
                        id: id.clone(),
                        subject: match &x.subject {
                            Subject::Principal(p) => p.to_string(),
                            Subject::Group(g) => format!("group:{g}"),
                        },
                        role: x.role.to_string(),
                        scope: x.scope.clone(),
                    };
                }
                if let Some(r) = scope_rules
                    .get(id)
                    .and_then(|&i| b.index.field_rules.get(i))
                {
                    return RuleExplained::FieldRule {
                        id: id.clone(),
                        scope: r.scope.clone(),
                        field: r.field.to_string(),
                        role: r.role.as_ref().map(ToString::to_string),
                        max: r.max.to_string(),
                    };
                }
                let model_index = |prefix: &str| {
                    id.as_str()
                        .strip_prefix(prefix)
                        .and_then(|n| n.parse::<usize>().ok())
                };
                if let Some(r) =
                    model_index("model:field_rule:").and_then(|i| b.model.field_rules().get(i))
                {
                    return RuleExplained::ModelFieldRule {
                        id: id.clone(),
                        field: r.field.to_string(),
                        role: r.role.as_ref().map(ToString::to_string),
                        max: r.max.to_string(),
                    };
                }
                if let Some(c) =
                    model_index("model:condition:").and_then(|i| b.model.conditions().get(i))
                {
                    return RuleExplained::Condition {
                        id: id.clone(),
                        role: c.role.to_string(),
                        resource_type: c.resource_type.to_string(),
                        otherwise: c.otherwise.to_string(),
                    };
                }
                RuleExplained::Other { id: id.clone() }
            })
            .collect();
        Ok(Explanation {
            decision,
            sides,
            rules,
        })
    }
}
