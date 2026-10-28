//! A reference evaluator for the property tests: an oracle for `check`.
//!
//! It is written from PERMISSION-MODEL.md §7.1 and the rules of ADR-0013,
//! straight over [`TenantData`] and the compiled model, with no code from
//! `eval.rs`, `filter.rs` or `pdp.rs` and none of their indexes. It reads the
//! model only through its plain data (roles, types, conditions, org-root
//! field rules). It is slow and simple on purpose.

use std::collections::BTreeSet;

use tutela_contracts::keys::{ActionKey, ActionRequirement, FieldKey, FieldName, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::{Principal, PrincipalKind};

use crate::model::{ADMIN_KEYS, GroupKey, Model, Role, RoleKey, SubjectKind, Template, Value};
use crate::{AttrValue, Attrs, Binding, CheckRequest, Member, PathEntry, Subject, TenantData};

/// What `check` must answer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Expected {
    pub allowed: bool,
    pub level: Level,
    pub read: BTreeSet<String>,
    pub write: BTreeSet<String>,
}

/// One deciding role of one principal, with its level after its own
/// conditions.
struct Deciding<'m> {
    key: &'m RoleKey,
    role: &'m Role,
    item: Level,
}

/// What one principal holds on the resource.
struct Holds<'m> {
    principal: Principal,
    /// `None`: no deciding role (no assignment, a private scope, or an agent
    /// assigned only at the org root). Roles that are gone or may not be
    /// given are left out: they give nothing.
    roles: Option<Vec<Deciding<'m>>>,
}

/// The expected answer, or `None` when `check` must return an error.
pub(crate) fn expected(model: &Model, data: &TenantData, req: &CheckRequest) -> Option<Expected> {
    let res = &req.resource;
    let ty = &res.type_name;
    if res.path.len() > 32 || req.action.resource_type() != ty {
        return None;
    }
    let def = model.types().get(ty);
    if def.is_none() && *ty != ResourceType::ORG {
        return None;
    }
    let this = PathEntry::new(ty.clone(), res.id.clone());
    let mut nodes = vec![this];
    nodes.extend(res.path.iter().cloned());
    let org = nodes.last()?.clone();
    let deny = Expected {
        allowed: false,
        level: Level::None,
        read: BTreeSet::new(),
        write: BTreeSet::new(),
    };
    // Step 2: the resource must be in the tenant.
    if !org.org_id().is_some_and(|o| data.orgs.contains(&o)) {
        return Some(deny);
    }
    let delegated = !req.actors.is_empty();
    let who: Vec<&Principal> = core::iter::once(&req.subject).chain(&req.actors).collect();
    let holds: Vec<Holds<'_>> = who
        .iter()
        .map(|p| holds(model, data, &nodes, &res.attrs, p))
        .collect();

    // Step 8 per principal, then the overlap (step 7).
    let allowed = holds
        .iter()
        .all(|h| allows(model, h, &req.action, delegated));
    let level = holds.iter().map(item_of).min().unwrap_or(Level::None);
    let manage = ActionKey::new(ty.clone(), "manage_access".parse().ok()?);
    let manage_all = holds.iter().all(|h| allows(model, h, &manage, delegated));
    let mut keys: Vec<(FieldKey, bool)> = Vec::new();
    if let Some(d) = def {
        for (f, fd) in &d.fields {
            keys.push((FieldKey::new(ty.clone(), f.clone()), fd.grants_access));
        }
        for f in &d.features {
            keys.push((FieldKey::new(ty.clone(), f.clone()), false));
        }
    }
    let mut out = Expected {
        allowed,
        level,
        read: BTreeSet::new(),
        write: BTreeSet::new(),
    };
    if level == Level::None {
        return Some(out);
    }
    for (k, grants_access) in keys {
        let l = holds
            .iter()
            .map(|h| field_of(model, data, &nodes, h, &k))
            .min()
            .unwrap_or(Level::None);
        if l >= Level::Read {
            out.read.insert(k.field().to_string());
        }
        if l >= Level::Write && (!grants_access || manage_all) {
            out.write.insert(k.field().to_string());
        }
    }
    Some(out)
}

/// `true` if principal `p` is in group `g`, directly or through groups.
fn member(data: &TenantData, p: &Principal, g: &GroupKey, seen: &mut BTreeSet<GroupKey>) -> bool {
    if !seen.insert(g.clone()) {
        return false;
    }
    let Some(group) = data.groups.iter().find(|x| x.key == *g) else {
        return false;
    };
    group.members.iter().any(|m| match m {
        Member::Principal(q) => q == p,
        Member::Group(h) => member(data, p, h, seen),
    })
}

fn in_group(data: &TenantData, p: &Principal, g: &GroupKey) -> bool {
    member(data, p, g, &mut BTreeSet::new())
}

/// The role a binding gives `p`, if the model has it and it may be given to
/// the binding's subject.
fn role_of<'m>(model: &'m Model, b: &Binding, p: &Principal) -> Option<(&'m RoleKey, &'m Role)> {
    let (k, r) = model.roles().get_key_value(&b.role)?;
    let kind = match b.subject {
        Subject::Group(_) => SubjectKind::Group,
        Subject::Principal(_) => SubjectKind::Principal(p.kind()),
    };
    r.assignable_to.contains(&kind).then_some((k, r))
}

/// Steps 3 and 4 for one principal.
fn holds<'m>(
    model: &'m Model,
    data: &TenantData,
    nodes: &[PathEntry],
    attrs: &Attrs,
    p: &Principal,
) -> Holds<'m> {
    let last = nodes.len() - 1;
    let direct_at = |node: &PathEntry| {
        data.bindings
            .iter()
            .find(|b| b.scope == *node && b.subject == Subject::Principal(p.clone()))
    };
    // The org Owner: a user with a direct `owner` assignment at the org root.
    let mut found: Option<(usize, Vec<&Binding>)> = None;
    if p.kind() == PrincipalKind::User
        && let Some(b) = direct_at(&nodes[last])
        && b.role.as_str() == "owner"
        && role_of(model, b, p).is_some()
    {
        found = Some((last, vec![b]));
    }
    if found.is_none() {
        for (i, node) in nodes.iter().enumerate() {
            if let Some(b) = direct_at(node) {
                found = Some((i, vec![b]));
                break;
            }
            let groups: Vec<&Binding> = data
                .bindings
                .iter()
                .filter(|b| b.scope == *node)
                .filter(|b| matches!(&b.subject, Subject::Group(g) if in_group(data, p, g)))
                .collect();
            if !groups.is_empty() {
                found = Some((i, groups));
                break;
            }
            if data.private_scopes.contains(node) {
                break;
            }
        }
    }
    let Some((at, bindings)) = found else {
        return Holds {
            principal: p.clone(),
            roles: None,
        };
    };
    if p.kind() == PrincipalKind::Agent && at == last {
        return Holds {
            principal: p.clone(),
            roles: None,
        };
    }
    let ty = &nodes[0].type_name;
    let roles = bindings
        .into_iter()
        .filter_map(|b| role_of(model, b, p))
        .map(|(key, role)| {
            let mut item = role.level(ty);
            for c in model.conditions() {
                if c.role == *key && c.resource_type == *ty && !condition(data, &c.when, attrs, p) {
                    item = item.min(c.otherwise);
                }
            }
            Deciding { key, role, item }
        })
        .collect();
    Holds {
        principal: p.clone(),
        roles: Some(roles),
    }
}

/// A condition: false as a whole when it names a group the tenant does not
/// have.
fn condition(data: &TenantData, t: &Template, attrs: &Attrs, p: &Principal) -> bool {
    fn groups(t: &Template, out: &mut Vec<GroupKey>) {
        match t {
            Template::InGroup { group } => out.push(group.clone()),
            Template::And(v) | Template::Or(v) => v.iter().for_each(|x| groups(x, out)),
            Template::Not(x) => groups(x, out),
            _ => {}
        }
    }
    let mut named = Vec::new();
    groups(t, &mut named);
    if named
        .iter()
        .any(|g| !data.groups.iter().any(|x| x.key == *g))
    {
        return false;
    }
    template(data, t, attrs, p)
}

fn template(data: &TenantData, t: &Template, attrs: &Attrs, p: &Principal) -> bool {
    let get = |f: &FieldName| attrs.get(f);
    let eq = |a: Option<&AttrValue>, v: &Value| match (a, v) {
        (Some(AttrValue::String(a)), Value::String(b)) => a == b,
        (Some(AttrValue::Integer(a)), Value::Integer(b)) => a == b,
        (Some(AttrValue::Boolean(a)), Value::Boolean(b)) => a == b,
        _ => false,
    };
    match t {
        Template::Eq { field, value } => eq(get(field), value),
        Template::In { field, values } => values.iter().any(|v| eq(get(field), v)),
        Template::Contains { field, value } => {
            matches!(get(field), Some(AttrValue::Strings(v)) if v.contains(value))
        }
        Template::IsPrincipal { field } => {
            matches!(get(field), Some(AttrValue::String(s)) if *s == p.to_string())
        }
        Template::InGroup { group } => in_group(data, p, group),
        Template::And(v) => v.iter().all(|x| template(data, x, attrs, p)),
        Template::Or(v) => v.iter().any(|x| template(data, x, attrs, p)),
        Template::Not(x) => !template(data, x, attrs, p),
    }
}

/// The item level of one principal: the highest of its deciding roles.
fn item_of(h: &Holds<'_>) -> Level {
    h.roles
        .as_ref()
        .and_then(|rs| rs.iter().map(|r| r.item).max())
        .unwrap_or(Level::None)
}

/// Step 8 for one principal.
fn allows(model: &Model, h: &Holds<'_>, action: &ActionKey, delegated: bool) -> bool {
    let Some(roles) = &h.roles else {
        return false;
    };
    let agent = h.principal.kind() == PrincipalKind::Agent;
    let name = action.action().as_str();
    match name {
        "read" => roles.iter().any(|r| r.item >= Level::Read),
        "write" => roles.iter().any(|r| r.item >= Level::Write),
        "delete" => roles.iter().any(|r| r.item >= Level::Full),
        _ if ADMIN_KEYS.contains(&name) => {
            !agent && !delegated && roles.iter().any(|r| r.role.grants.contains(action))
        }
        _ => {
            let Some(def) = model
                .types()
                .get(action.resource_type())
                .and_then(|t| t.actions.get(action.action()))
            else {
                return false;
            };
            let held = |r: &Deciding<'_>| r.role.grants.contains(action);
            match def.needs {
                ActionRequirement::OwnerOnly => {
                    !agent && !delegated && roles.iter().any(|r| r.item == Level::Full && held(r))
                }
                ActionRequirement::Level(l) => {
                    roles.iter().any(|r| r.item >= l && (!def.grant || held(r)))
                }
            }
        }
    }
}

/// Step 5 for one principal and one field or feature: the highest over its
/// deciding roles of min(the role's own level, the closest field rule).
fn field_of(
    model: &Model,
    data: &TenantData,
    nodes: &[PathEntry],
    h: &Holds<'_>,
    f: &FieldKey,
) -> Level {
    let Some(roles) = &h.roles else {
        return Level::None;
    };
    let def = model.types().get(f.resource_type());
    let feature = f.is_feature();
    let declared = def.is_some_and(|d| {
        if feature {
            d.features.contains(f.field())
        } else {
            d.fields.contains_key(f.field())
        }
    });
    roles
        .iter()
        .map(|r| {
            if !declared {
                return Level::None;
            }
            let set = r.role.field_levels.get(f).copied();
            let own = if feature {
                if r.item == Level::None {
                    Level::None
                } else {
                    set.unwrap_or(r.item)
                }
            } else {
                set.unwrap_or(r.item).min(r.item)
            };
            own.min(closest_rule(model, data, nodes, r.key, f))
        })
        .max()
        .unwrap_or(Level::None)
}

/// The closest field rule for one role: walk up from the item; at one scope
/// a rule for the role beats a rule for all roles; the model's rules sit at
/// the org root.
fn closest_rule(
    model: &Model,
    data: &TenantData,
    nodes: &[PathEntry],
    role: &RoleKey,
    f: &FieldKey,
) -> Level {
    for node in nodes {
        let here = |want: Option<&RoleKey>| {
            data.field_rules
                .iter()
                .find(|r| r.scope == *node && r.field == *f && r.role.as_ref() == want)
                .map(|r| r.max)
        };
        if let Some(l) = here(Some(role)).or_else(|| here(None)) {
            return l;
        }
    }
    let root = |want: Option<&RoleKey>| {
        model
            .field_rules()
            .iter()
            .find(|r| r.field == *f && r.role.as_ref() == want)
            .map(|r| r.max)
    };
    root(Some(role))
        .or_else(|| root(None))
        .unwrap_or(Level::Full)
}
