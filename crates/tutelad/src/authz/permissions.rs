//! The UI permission map, `POST /v1/authz/permissions` (CONTRACTS.md 7.5).
//!
//! The map is a UI hint: every server route checks again. Its answers come
//! from `Pdp::check`, one decision per action, so it cannot say more than
//! `check` does.
//!
//! **The ETag.** Two loads at one revision can differ, because an assignment
//! can expire before the revision moves (ADR-0020). So the tag is not a
//! name for (revision, request). It hashes the whole answer as well as the
//! tenant, the revision, the model, the subject and the request, and the
//! answer is worked out on every call. That costs a few microseconds per
//! action and no database read, and a `304` can never hide a change, or one
//! principal's map stand in for another's.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use serde_json::json;
use tutela_contracts::decision::Decision;
use tutela_contracts::keys::{ActionKey, BuiltinAction, FieldKey, UiKey};
use tutela_pdp::CheckRequest;
use tutela_pdp::model::{UiComponent, WhenDenied};
use tutela_sdk::Identity;

use super::wire::{self, Invalid, PermissionsBody};
use super::{floor, may_ask, pdp_problem, view};
use crate::api::{AppState, Problem};
use crate::cache::{ActionClass, Snapshot};
use crate::telemetry::{Metrics, Outcome};
use crate::tenant::Tenant;

const OP: &str = "permissions";

/// The most names in `actions`, `fields` or `ui_keys`. A model has at most
/// 2,000 UI keys.
const MAX_NAMES: usize = 2_000;

/// One UI key's answer.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UiAnswer {
    /// `show`, `disable`, `hide` or `readonly`.
    pub mode: &'static str,
    /// A reason code that is safe to show (CONTRACTS.md 6.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The map.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PermissionMap {
    /// The revision that was used.
    pub rev: u64,
    /// By UI key.
    pub ui: BTreeMap<String, UiAnswer>,
    /// By action key.
    pub actions: BTreeMap<String, bool>,
    /// By field key: `none`, `read` or `write`.
    pub fields: BTreeMap<String, &'static str>,
}

/// The answer: the map and its tag, or only the tag when the caller has
/// the same map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permissions {
    /// The quoted ETag.
    pub etag: String,
    /// `None`: not modified.
    pub map: Option<PermissionMap>,
}

/// What a field's level is, from a read decision's mask.
fn field_level(
    read: &Decision,
    key: &FieldKey,
    ty: &tutela_contracts::keys::ResourceType,
) -> &'static str {
    if key.resource_type() != ty {
        "none"
    } else if read.field_mask.can_write(key.field()) {
        "write"
    } else if read.field_mask.can_read(key.field()) {
        "read"
    } else {
        "none"
    }
}

const fn denied_mode(w: WhenDenied) -> &'static str {
    match w {
        WhenDenied::Show => "show",
        WhenDenied::Disable => "disable",
        WhenDenied::Hide => "hide",
        WhenDenied::Readonly => "readonly",
    }
}

/// The checks of one map, each action once.
struct Asker<'a> {
    snapshot: &'a Snapshot,
    metrics: &'a Metrics,
    request: CheckRequest,
    seen: HashMap<ActionKey, Decision>,
}

impl Asker<'_> {
    fn decide(&mut self, action: &ActionKey) -> Result<&Decision, Problem> {
        if !self.seen.contains_key(action) {
            let mut req = self.request.clone();
            req.action = action.clone();
            let d = self.snapshot.pdp.check(&req).map_err(|e| pdp_problem(&e))?;
            let outcome = if d.is_allowed() {
                Outcome::Allow
            } else {
                Outcome::Deny
            };
            self.metrics.count_decision(OP, outcome);
            self.seen.insert(action.clone(), d);
        }
        self.seen
            .get(action)
            .ok_or_else(|| Problem::stale("unavailable"))
    }

    /// One UI key. A key about another type cannot be decided on this
    /// resource, so it counts as denied.
    fn ui(&mut self, c: &UiComponent, read: &Decision) -> Result<UiAnswer, Problem> {
        let ty = self.request.resource.type_name.clone();
        let mut refused = None;
        for action in &c.actions {
            if action.resource_type() != &ty {
                refused.get_or_insert_with(|| "not_allowed".to_owned());
                continue;
            }
            let d = self.decide(action)?;
            if !d.is_allowed() {
                refused.get_or_insert_with(|| d.reason.public_code().as_str().to_owned());
            }
        }
        let levels: BTreeSet<&str> = c.fields.iter().map(|f| field_level(read, f, &ty)).collect();
        if levels.contains("none") {
            refused.get_or_insert_with(|| read.reason.public_code().as_str().to_owned());
        }
        match refused {
            Some(reason) => {
                // `readonly` shows the value, and the value is not readable.
                let mode = match c.when_denied {
                    WhenDenied::Readonly if levels.contains("none") => "hide",
                    w => denied_mode(w),
                };
                Ok(UiAnswer {
                    mode,
                    reason: (mode == "disable").then_some(reason),
                })
            }
            None if levels.contains("read") => Ok(UiAnswer {
                mode: "readonly",
                reason: None,
            }),
            None => Ok(UiAnswer {
                mode: "show",
                reason: None,
            }),
        }
    }
}

fn too_many(n: usize) -> Result<(), Problem> {
    if n > MAX_NAMES {
        return Err(Problem::invalid(
            "too_many_items",
            format!("a list holds at most {MAX_NAMES} names"),
        ));
    }
    Ok(())
}

fn etag(parts: &serde_json::Value, rev: u64) -> String {
    let digest = tutela_store::digest(&parts.to_string());
    let short = digest.get(..16).unwrap_or(&digest);
    format!("\"r{rev}-{short}\"")
}

/// `true` if `header` names `tag`. `*` does not: it would answer 304 to a
/// caller who holds no map at all.
fn matches(header: Option<&str>, tag: &str) -> bool {
    header.is_some_and(|h| {
        h.split(',')
            .map(|t| t.trim().trim_start_matches("W/"))
            .any(|t| t == tag)
    })
}

/// `POST /v1/authz/permissions`.
///
/// # Errors
///
/// A [`Problem`]. An error is never a map.
pub async fn permissions(
    state: &AppState,
    id: &Identity,
    body: PermissionsBody,
    if_none_match: Option<&str>,
) -> Result<Permissions, Problem> {
    let names = body.ui_keys.as_ref().map_or(0, Vec::len);
    too_many(names)?;
    too_many(body.actions.as_ref().map_or(0, Vec::len))?;
    too_many(body.fields.as_ref().map_or(0, Vec::len))?;
    let (subject, actors) = wire::principal(
        body.subject
            .as_ref()
            .ok_or(Invalid("`subject` is missing"))?,
    )?;
    may_ask(id, &subject, &actors)?;
    let resource = wire::map_resource(
        body.resource
            .clone()
            .ok_or(Invalid("`resource` is missing"))?,
    )?;
    let ui_keys = body
        .ui_keys
        .as_deref()
        .map(|keys| {
            keys.iter()
                .map(|k| {
                    UiKey::parse(k).map_err(|_| Invalid("a name in `ui_keys` is not a UI key"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let actions = body
        .actions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|a| {
            ActionKey::parse(a).map_err(|_| Invalid("a name in `actions` is not an action key"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fields = body
        .fields
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|f| FieldKey::parse(f).map_err(|_| Invalid("a name in `fields` is not a field key")))
        .collect::<Result<Vec<_>, _>>()?;

    let need = floor(id, body.at_least_revision);
    let tenant = Tenant::of(id);
    let view = view(state, OP, &tenant, need).await?;
    // A UI hint: every route checks again, with its own class.
    let snapshot = view.for_class(ActionClass::Read).map_err(|e| {
        state.metrics.count_decision(OP, Outcome::Error);
        Problem::from(e)
    })?;

    let map = build(
        snapshot,
        &state.metrics,
        CheckRequest {
            tenant: tenant.key().clone(),
            subject: subject.clone(),
            actors: actors.clone(),
            action: ActionKey::builtin(resource.type_name.clone(), BuiltinAction::Read),
            resource,
            fields: None,
            at_least_revision: need,
        },
        ui_keys.as_deref(),
        &actions,
        &fields,
    )
    .inspect_err(|_| state.metrics.count_decision(OP, Outcome::Error))?;

    let tag = etag(
        &json!([
            tenant.key().iss.as_str(),
            tenant.key().tid.to_string(),
            snapshot.rev,
            snapshot.model_digest,
            subject.to_string(),
            actors.iter().map(ToString::to_string).collect::<Vec<_>>(),
            body.canonical(),
            map,
        ]),
        snapshot.rev,
    );
    if matches(if_none_match, &tag) {
        return Ok(Permissions {
            etag: tag,
            map: None,
        });
    }
    Ok(Permissions {
        etag: tag,
        map: Some(map),
    })
}

fn build(
    snapshot: &Snapshot,
    metrics: &Metrics,
    request: CheckRequest,
    ui_keys: Option<&[UiKey]>,
    actions: &[ActionKey],
    fields: &[FieldKey],
) -> Result<PermissionMap, Problem> {
    let ty = request.resource.type_name.clone();
    let read_key = request.action.clone();
    let mut asker = Asker {
        snapshot,
        metrics,
        request,
        seen: HashMap::new(),
    };
    let read = asker.decide(&read_key)?.clone();
    let declared = snapshot.model.ui();
    let mut ui = BTreeMap::new();
    match ui_keys {
        None => {
            for (key, component) in declared {
                ui.insert(key.to_string(), asker.ui(component, &read)?);
            }
        }
        Some(keys) => {
            for key in keys {
                let component = declared.get(key).ok_or_else(|| {
                    Problem::invalid("unknown_key", "a UI key is not in the model".to_owned())
                })?;
                ui.insert(key.to_string(), asker.ui(component, &read)?);
            }
        }
    }
    let mut out_actions = BTreeMap::new();
    for action in actions {
        out_actions.insert(action.to_string(), asker.decide(action)?.is_allowed());
    }
    let out_fields = fields
        .iter()
        .map(|f| (f.to_string(), field_level(&read, f, &ty)))
        .collect();
    Ok(PermissionMap {
        rev: snapshot.rev,
        ui,
        actions: out_actions,
        fields: out_fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_none_match_names_a_tag_and_a_star_names_none() {
        let tag = "\"r1-abc\"";
        assert!(matches(Some(tag), tag));
        assert!(matches(Some("W/\"r1-abc\""), tag));
        assert!(matches(Some("\"r0-000\", \"r1-abc\""), tag));
        assert!(!matches(Some("\"r2-abc\""), tag));
        assert!(!matches(Some("*"), tag));
        assert!(!matches(None, tag));
    }
}
