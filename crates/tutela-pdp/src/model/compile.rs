//! The model compiler: raw manifest -> checked [`Model`] (docs/MANIFEST.md).

use std::collections::{BTreeMap, BTreeSet};

use tutela_contracts::claims::Audience;
use tutela_contracts::keys::{
    ActionKey, ActionName, ActionRequirement, FieldKey, FieldName, ResourceType, UiKey,
};
use tutela_contracts::level::Level;
use tutela_contracts::principal::PrincipalKind;

use super::raw;
use super::{
    AiReach, AppName, Condition, CustomAction, FieldDef, FieldDisplay, FieldRule, FieldType,
    GroupKey, Issue, Issues, MANIFEST_VERSION, MAX_MANIFEST_BYTES, Method, Model, Role, RoleKey,
    Route, SeededRole, Sensitivity, Starts, SubjectKind, Template, TypeDef, UiComponent, Value,
    WhenDenied, is_admin_key,
};

const MAX_TYPES: usize = 512;
const MAX_FIELDS: usize = 256;
const MAX_ACTIONS: usize = 64;
const MAX_ROLES: usize = 512;
const MAX_FIELD_RULES: usize = 10_000;
const MAX_CONDITIONS: usize = 1_000;
const MAX_TEMPLATE_NODES: usize = 32;
const MAX_TEMPLATE_DEPTH: usize = 4;
const MAX_IN_VALUES: usize = 64;
const MAX_BRANCHES: usize = 16;
const MAX_UI_KEYS: usize = 2_000;
const MAX_ROUTES: usize = 16;
const MAX_LABEL: usize = 128;
const MAX_REASON: usize = 512;
const MAX_STRING_VALUE: usize = 256;
const MAX_NESTING: usize = 32;

struct Ctx {
    issues: Vec<Issue>,
}

impl Ctx {
    fn bad(&mut self, at: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            at: at.into(),
            message: message.into(),
        });
    }
}

fn level(s: &str) -> Option<Level> {
    Level::ALL.into_iter().find(|l| l.as_str() == s)
}

/// Display text: 1 to `max` characters, no control characters.
fn text_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
}

fn label(ctx: &mut Ctx, at: &str, l: Option<String>) -> Option<String> {
    if let Some(s) = &l {
        if !text_ok(s, MAX_LABEL) {
            ctx.bad(
                at,
                "a label is 1 to 128 characters with no control characters",
            );
        }
    }
    l
}

pub(super) fn compile(source: &str) -> Result<Model, Issues> {
    if source.len() > MAX_MANIFEST_BYTES {
        return Err(Issues(vec![Issue {
            at: String::new(),
            message: "the manifest is larger than 4 MiB".into(),
        }]));
    }
    if nesting(source) > MAX_NESTING {
        return Err(Issues(vec![Issue {
            at: String::new(),
            message: "tables and arrays nest more than 32 levels deep".into(),
        }]));
    }
    let raw: raw::Manifest = toml::from_str(source).map_err(|e| {
        Issues(vec![Issue {
            at: String::new(),
            message: e.message().to_owned() + &location(source, e.span()),
        }])
    })?;
    let mut ctx = Ctx { issues: Vec::new() };
    let model = build(&mut ctx, raw);
    if ctx.issues.is_empty() {
        Ok(model)
    } else {
        Err(Issues(ctx.issues))
    }
}

/// The deepest nesting of `{` and `[` outside strings and comments. Checked
/// before parsing, so hostile input cannot exhaust the stack.
fn nesting(source: &str) -> usize {
    let b = source.as_bytes();
    let (mut i, mut depth, mut max) = (0usize, 0usize, 0usize);
    while i < b.len() {
        match b[i] {
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            q @ (b'"' | b'\'') => {
                let triple = b.get(i..i + 3) == Some(&[q, q, q][..]);
                i += if triple { 3 } else { 1 };
                while i < b.len() {
                    if q == b'"' && b[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if b[i] == q && (!triple || b.get(i..i + 3) == Some(&[q, q, q][..])) {
                        i += if triple { 3 } else { 1 };
                        break;
                    }
                    if !triple && b[i] == b'\n' {
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            b'{' | b'[' => {
                depth += 1;
                max = max.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    max
}

fn location(source: &str, span: Option<core::ops::Range<usize>>) -> String {
    let Some(span) = span else {
        return String::new();
    };
    let before = source.get(..span.start).unwrap_or(source);
    let line = before.matches('\n').count() + 1;
    format!(" (line {line})")
}

fn build(ctx: &mut Ctx, raw: raw::Manifest) -> Model {
    if raw.version != MANIFEST_VERSION {
        ctx.bad("version", "the only manifest version is 1");
    }
    let app = AppName::parse(&raw.app.name).unwrap_or_else(|e| {
        ctx.bad("app.name", e.to_string());
        AppName(String::new())
    });
    let audience = raw.app.audience.as_deref().and_then(|a| {
        Audience::parse(a)
            .map_err(|e| ctx.bad("app.audience", e.to_string()))
            .ok()
    });
    let types = types(ctx, raw.types);
    let roles = roles(ctx, &types, raw.roles);
    let field_rules = field_rules(ctx, &types, &roles, raw.field_rules);
    let conditions = conditions(ctx, &types, &roles, raw.conditions);
    let ui = ui(ctx, &types, raw.ui);
    Model {
        app,
        audience,
        types,
        roles,
        field_rules,
        conditions,
        ui,
    }
}

// ---------- types ----------

fn types(ctx: &mut Ctx, raw: BTreeMap<String, raw::Type>) -> BTreeMap<ResourceType, TypeDef> {
    if raw.len() > MAX_TYPES {
        ctx.bad("types", "at most 512 types");
    }
    let mut out = BTreeMap::new();
    let mut parents_raw: BTreeMap<ResourceType, Vec<String>> = BTreeMap::new();
    for (name, t) in raw {
        let at = format!("types.{name}");
        let ty = match ResourceType::parse(&name) {
            Ok(ty) if ty.is_reserved() => {
                ctx.bad(&at, "`org` and names starting with `tutela_` are reserved");
                continue;
            }
            Ok(ty) => ty,
            Err(e) => {
                ctx.bad(&at, e.to_string());
                continue;
            }
        };
        if !t.container && (t.starts.is_some() || t.ai_reach.is_some()) {
            ctx.bad(&at, "`starts` and `ai_reach` are for containers only");
        }
        let starts = match t.starts.as_deref() {
            None | Some("open") => Starts::Open,
            Some("private") => Starts::Private,
            Some(_) => {
                ctx.bad(format!("{at}.starts"), "must be `open` or `private`");
                Starts::Open
            }
        };
        let ai_reach = match t.ai_reach.as_deref() {
            None | Some("project") => AiReach::Project,
            Some("team") => AiReach::Team,
            Some(_) => {
                ctx.bad(
                    format!("{at}.ai_reach"),
                    "must be `project` or `team`; nothing wider exists",
                );
                AiReach::Project
            }
        };
        let label = label(ctx, &format!("{at}.label"), t.label);
        let mut fields = BTreeMap::new();
        for (fname, f) in t.fields {
            let fat = format!("{at}.fields.{fname}");
            let Some(field) =
                parse_plain_name(ctx, &fat, &fname).and_then(|n| FieldName::parse(&n).ok())
            else {
                continue;
            };
            let sensitivity = Sensitivity::parse(&f.sensitivity).unwrap_or_else(|| {
                ctx.bad(
                    format!("{fat}.sensitivity"),
                    "must be `public`, `internal`, `confidential` or `secret`",
                );
                Sensitivity::Secret
            });
            let field_type = match f.field_type.as_deref() {
                None => FieldType::String,
                Some(s) => FieldType::parse(s).unwrap_or_else(|| {
                    ctx.bad(
                        format!("{fat}.type"),
                        "must be `string`, `integer`, `boolean`, `string_list` or `principal`",
                    );
                    FieldType::String
                }),
            };
            let label = label(ctx, &format!("{fat}.label"), f.label);
            fields.insert(
                field,
                FieldDef {
                    sensitivity,
                    field_type,
                    grants_access: f.grants_access,
                    label,
                },
            );
        }
        let mut features = BTreeSet::new();
        for f in t.features {
            let Some(feature) = parse_plain_name(ctx, &format!("{at}.features"), &f)
                .and_then(|n| FieldName::parse(&format!("@{n}")).ok())
            else {
                continue;
            };
            if !features.insert(feature) {
                ctx.bad(format!("{at}.features"), format!("`{f}` is listed twice"));
            }
        }
        if fields.len() + features.len() > MAX_FIELDS {
            ctx.bad(&at, "at most 256 fields and features per type");
        }
        let mut actions = BTreeMap::new();
        if t.actions.len() > MAX_ACTIONS {
            ctx.bad(
                format!("{at}.actions"),
                "at most 64 custom actions per type",
            );
        }
        for (aname, a) in t.actions {
            let aat = format!("{at}.actions.{aname}");
            let name = match ActionName::parse(&aname) {
                Ok(n) => n,
                Err(e) => {
                    ctx.bad(&aat, e.to_string());
                    continue;
                }
            };
            if name.builtin().is_some() || is_admin_key(&name) {
                ctx.bad(
                    &aat,
                    "built-in action names and admin keys cannot be declared",
                );
                continue;
            }
            let needs = match a.needs.as_str() {
                "owner" => ActionRequirement::OwnerOnly,
                s => match level(s) {
                    Some(l) if l > Level::None => ActionRequirement::Level(l),
                    _ => {
                        ctx.bad(
                            format!("{aat}.needs"),
                            "must be `read`, `write`, `full` or `owner`",
                        );
                        continue;
                    }
                },
            };
            let grant = a.grant.unwrap_or(true);
            if needs == ActionRequirement::OwnerOnly && !grant {
                ctx.bad(&aat, "an owner-only action always needs a grant");
            }
            actions.insert(name, CustomAction { needs, grant });
        }
        parents_raw.insert(ty.clone(), t.parent.into_vec());
        out.insert(
            ty,
            TypeDef {
                label,
                parents: BTreeSet::new(),
                container: t.container,
                starts,
                ai_reach,
                fields,
                features,
                actions,
            },
        );
    }
    // Parents: `org` or declared containers (a type may list itself).
    for (ty, parents) in parents_raw {
        let at = format!("types.{ty}.parent");
        if parents.is_empty() {
            ctx.bad(&at, "list at least one parent type");
        }
        let mut set = BTreeSet::new();
        for p in parents {
            let Ok(pt) = ResourceType::parse(&p) else {
                ctx.bad(&at, format!("`{p}` is not a type name"));
                continue;
            };
            if pt != ResourceType::ORG {
                match out.get(&pt) {
                    None => ctx.bad(&at, format!("`{p}` is not a declared type")),
                    Some(d) if !d.container => {
                        ctx.bad(&at, format!("`{p}` is not a container"));
                    }
                    Some(_) => {}
                }
            }
            set.insert(pt);
        }
        if let Some(d) = out.get_mut(&ty) {
            d.parents = set;
        }
    }
    // Every type must reach `org` through its parents.
    let mut reached: BTreeSet<ResourceType> = BTreeSet::new();
    loop {
        let before = reached.len();
        for (ty, d) in &out {
            if d.parents
                .iter()
                .any(|p| *p == ResourceType::ORG || reached.contains(p))
            {
                reached.insert(ty.clone());
            }
        }
        if reached.len() == before {
            break;
        }
    }
    for ty in out.keys() {
        if !reached.contains(ty) {
            ctx.bad(
                format!("types.{ty}.parent"),
                "the type never reaches `org` through its parents",
            );
        }
    }
    out
}

/// A plain name (no `@`) for a field or feature.
fn parse_plain_name(ctx: &mut Ctx, at: &str, s: &str) -> Option<String> {
    match tutela_contracts::keys::check_name(s) {
        Ok(()) => Some(s.to_owned()),
        Err(e) => {
            ctx.bad(at, format!("`{s}`: {e}"));
            None
        }
    }
}

// ---------- roles ----------

/// `true` if the key names a declared type (or `org`).
fn known_type(types: &BTreeMap<ResourceType, TypeDef>, t: &ResourceType) -> bool {
    *t == ResourceType::ORG || types.contains_key(t)
}

/// `true` if the field key names a declared field or feature.
fn known_field(types: &BTreeMap<ResourceType, TypeDef>, k: &FieldKey) -> bool {
    types.get(k.resource_type()).is_some_and(|d| {
        if k.is_feature() {
            d.features.contains(k.field())
        } else {
            d.fields.contains_key(k.field())
        }
    })
}

fn all_types(types: &BTreeMap<ResourceType, TypeDef>) -> impl Iterator<Item = ResourceType> + '_ {
    core::iter::once(ResourceType::ORG).chain(types.keys().cloned())
}

fn seeded(types: &BTreeMap<ResourceType, TypeDef>, role: SeededRole) -> Role {
    let level = match role {
        SeededRole::Owner | SeededRole::Member => Level::Full,
        SeededRole::Viewer | SeededRole::Guest | SeededRole::Agent => Level::Read,
    };
    let levels = all_types(types).map(|t| (t, level)).collect();
    let mut grants = BTreeSet::new();
    if role == SeededRole::Owner {
        for t in all_types(types) {
            for k in super::ADMIN_KEYS {
                if let Ok(a) = ActionName::parse(k) {
                    grants.insert(ActionKey::new(t.clone(), a));
                }
            }
            if let Some(d) = types.get(&t) {
                for a in d.actions.keys() {
                    grants.insert(ActionKey::new(t.clone(), a.clone()));
                }
            }
        }
    }
    let assignable_to = match role {
        SeededRole::Owner => SubjectKind::ALL
            .into_iter()
            .filter(|k| *k != SubjectKind::Principal(PrincipalKind::Agent))
            .collect(),
        SeededRole::Agent => [SubjectKind::Principal(PrincipalKind::Agent)].into(),
        _ => SubjectKind::ALL.into_iter().collect(),
    };
    Role {
        label: None,
        seeded: Some(role),
        levels,
        field_levels: BTreeMap::new(),
        grants,
        assignable_to,
    }
}

fn roles(
    ctx: &mut Ctx,
    types: &BTreeMap<ResourceType, TypeDef>,
    raw: BTreeMap<String, raw::Role>,
) -> BTreeMap<RoleKey, Role> {
    let mut out = BTreeMap::new();
    for s in SeededRole::ALL {
        out.insert(RoleKey(s.key().to_owned()), seeded(types, s));
    }
    for (name, r) in raw {
        let at = format!("roles.{name}");
        let key = match RoleKey::parse(&name) {
            Ok(k) => k,
            Err(e) => {
                ctx.bad(&at, e.to_string());
                continue;
            }
        };
        let seeded_as = SeededRole::from_key(&name);
        if seeded_as == Some(SeededRole::Owner) {
            ctx.bad(&at, "the seeded `owner` role cannot be declared or changed");
            continue;
        }
        let label = label(ctx, &format!("{at}.label"), r.label);
        let mut levels = BTreeMap::new();
        let mut field_levels = BTreeMap::new();
        let mut grants = BTreeSet::new();
        for (k, v) in r.grants {
            let gat = format!("{at}.grants.{k}");
            if k.contains(':') {
                let Ok(ak) = ActionKey::parse(&k) else {
                    ctx.bad(&gat, "not an action key `<type>:<action>`");
                    continue;
                };
                if !matches!(v, raw::GrantValue::Flag(true)) {
                    ctx.bad(&gat, "an action key takes `true`; leave it out to deny");
                    continue;
                }
                if !known_type(types, ak.resource_type()) {
                    ctx.bad(&gat, "not a declared type");
                } else if ak.as_builtin().is_some() && !is_admin_key(ak.action()) {
                    ctx.bad(
                        &gat,
                        "built-in actions come from levels and cannot be granted",
                    );
                } else if !is_admin_key(ak.action()) {
                    match types
                        .get(ak.resource_type())
                        .and_then(|d| d.actions.get(ak.action()))
                    {
                        None => ctx.bad(&gat, "not a declared custom action or admin key"),
                        Some(a) if !a.grant => {
                            ctx.bad(&gat, "this action needs no grant (`grant = false`)");
                        }
                        Some(_) => {
                            grants.insert(ak);
                        }
                    }
                } else {
                    grants.insert(ak);
                }
                continue;
            }
            let lvl = match v {
                raw::GrantValue::Level(s) => level(&s),
                raw::GrantValue::Flag(_) => None,
            };
            let Some(lvl) = lvl else {
                ctx.bad(&gat, "takes a level: `none`, `read`, `write` or `full`");
                continue;
            };
            if k.contains('.') {
                match FieldKey::parse(&k) {
                    Ok(fk) if known_field(types, &fk) => {
                        field_levels.insert(fk, lvl);
                    }
                    Ok(_) => ctx.bad(&gat, "not a declared field or feature"),
                    Err(e) => ctx.bad(&gat, e.to_string()),
                }
            } else {
                match ResourceType::parse(&k) {
                    Ok(t) if known_type(types, &t) => {
                        levels.insert(t, lvl);
                    }
                    Ok(_) => ctx.bad(&gat, "not a declared type"),
                    Err(e) => ctx.bad(&gat, e.to_string()),
                }
            }
        }
        for (fk, l) in &field_levels {
            let tl = levels
                .get(fk.resource_type())
                .copied()
                .unwrap_or(Level::None);
            if *l > tl {
                ctx.bad(
                    format!("{at}.grants.{fk}"),
                    format!(
                        "`{l}` is above the role's level for `{}` (`{tl}`)",
                        fk.resource_type()
                    ),
                );
            }
        }
        let owner_only = grants.iter().any(|g| {
            is_admin_key(g.action())
                || types
                    .get(g.resource_type())
                    .and_then(|d| d.actions.get(g.action()))
                    .is_some_and(|a| a.needs == ActionRequirement::OwnerOnly)
        });
        let agent = SubjectKind::Principal(PrincipalKind::Agent);
        let assignable_to: BTreeSet<SubjectKind> = match r.assignable_to {
            None if owner_only => SubjectKind::ALL
                .into_iter()
                .filter(|k| *k != agent)
                .collect(),
            None => SubjectKind::ALL.into_iter().collect(),
            Some(list) => {
                let mut set = BTreeSet::new();
                for s in list {
                    match SubjectKind::parse(&s) {
                        Some(k) => {
                            if !set.insert(k) {
                                ctx.bad(
                                    format!("{at}.assignable_to"),
                                    format!("`{s}` is listed twice"),
                                );
                            }
                        }
                        None => ctx.bad(
                            format!("{at}.assignable_to"),
                            format!("`{s}` is not one of user, sa, key, agent, workload, group"),
                        ),
                    }
                }
                if set.is_empty() {
                    ctx.bad(format!("{at}.assignable_to"), "list at least one kind");
                }
                set
            }
        };
        if owner_only && assignable_to.contains(&agent) {
            ctx.bad(
                format!("{at}.assignable_to"),
                "a role with an admin key or an owner-only action can never be assigned to an agent",
            );
        }
        out.insert(
            key,
            Role {
                label,
                seeded: seeded_as,
                levels,
                field_levels,
                grants,
                assignable_to,
            },
        );
    }
    if out.len() > MAX_ROLES {
        ctx.bad("roles", "at most 512 roles, seeded ones included");
    }
    out
}

// ---------- field rules ----------

fn field_rules(
    ctx: &mut Ctx,
    types: &BTreeMap<ResourceType, TypeDef>,
    roles: &BTreeMap<RoleKey, Role>,
    raw: Vec<raw::FieldRule>,
) -> Vec<FieldRule> {
    let mut out: BTreeMap<(FieldKey, Option<RoleKey>), FieldRule> = BTreeMap::new();
    // The Correction: confidential and secret fields start at None.
    for (t, d) in types {
        for (f, def) in &d.fields {
            if def.sensitivity.starts_hidden() {
                let field = FieldKey::new(t.clone(), f.clone());
                out.insert(
                    (field.clone(), None),
                    FieldRule {
                        field,
                        role: None,
                        max: Level::None,
                        display: FieldDisplay::Restricted,
                        implicit: true,
                    },
                );
            }
        }
    }
    if raw.len() > MAX_FIELD_RULES {
        ctx.bad("field_rules", "at most 10,000 field rules");
    }
    for (i, r) in raw.into_iter().enumerate() {
        let at = format!("field_rules[{i}]");
        let field = match FieldKey::parse(&r.field) {
            Ok(f) if known_field(types, &f) => f,
            Ok(_) => {
                ctx.bad(format!("{at}.field"), "not a declared field or feature");
                continue;
            }
            Err(e) => {
                ctx.bad(format!("{at}.field"), e.to_string());
                continue;
            }
        };
        let role = match r.role.as_deref().map(RoleKey::parse) {
            None => None,
            Some(Ok(k)) if roles.contains_key(&k) => Some(k),
            Some(_) => {
                ctx.bad(format!("{at}.role"), "not a role of this model");
                continue;
            }
        };
        let Some(max) = level(&r.max) else {
            ctx.bad(
                format!("{at}.max"),
                "takes a level: `none`, `read`, `write` or `full`",
            );
            continue;
        };
        let display = match r.display.as_deref() {
            None | Some("restricted") => FieldDisplay::Restricted,
            Some("remove") => FieldDisplay::Remove,
            Some(_) => {
                ctx.bad(format!("{at}.display"), "must be `restricted` or `remove`");
                continue;
            }
        };
        let k = (field.clone(), role.clone());
        if let Some(old) = out.get(&k) {
            if old.implicit {
                ctx.bad(
                    &at,
                    "a confidential or secret field already has an all-roles rule; add a rule for one role to open it",
                );
            } else {
                ctx.bad(&at, "a rule for this field and role is already declared");
            }
            continue;
        }
        out.insert(
            k,
            FieldRule {
                field,
                role,
                max,
                display,
                implicit: false,
            },
        );
    }
    out.into_values().collect()
}

// ---------- conditions ----------

fn conditions(
    ctx: &mut Ctx,
    types: &BTreeMap<ResourceType, TypeDef>,
    roles: &BTreeMap<RoleKey, Role>,
    raw: Vec<raw::Condition>,
) -> Vec<Condition> {
    if raw.len() > MAX_CONDITIONS {
        ctx.bad("conditions", "at most 1,000 conditions");
    }
    let mut out = Vec::new();
    for (i, c) in raw.into_iter().enumerate() {
        let at = format!("conditions[{i}]");
        let role = match RoleKey::parse(&c.role) {
            Ok(k) if k.as_str() == SeededRole::Owner.key() => {
                ctx.bad(
                    format!("{at}.role"),
                    "the `owner` role cannot have conditions",
                );
                continue;
            }
            Ok(k) if roles.contains_key(&k) => k,
            _ => {
                ctx.bad(format!("{at}.role"), "not a role of this model");
                continue;
            }
        };
        let (rt, def) = match ResourceType::parse(&c.resource_type) {
            Ok(t) => match types.get(&t) {
                Some(d) => (t, d),
                None => {
                    ctx.bad(format!("{at}.type"), "not a declared type");
                    continue;
                }
            },
            Err(e) => {
                ctx.bad(format!("{at}.type"), e.to_string());
                continue;
            }
        };
        let Some(otherwise) = level(&c.otherwise) else {
            ctx.bad(
                format!("{at}.else"),
                "takes a level: `none`, `read`, `write` or `full`",
            );
            continue;
        };
        let role_level = roles.get(&role).map_or(Level::None, |r| r.level(&rt));
        if otherwise > role_level {
            ctx.bad(
                format!("{at}.else"),
                format!("`{otherwise}` is above the role's level for `{rt}` (`{role_level}`); conditions only narrow"),
            );
        }
        let mut nodes = 0usize;
        let Some(when) = template(ctx, &format!("{at}.when"), def, c.when, 1, &mut nodes) else {
            continue;
        };
        if nodes > MAX_TEMPLATE_NODES {
            ctx.bad(format!("{at}.when"), "a template has at most 32 nodes");
        }
        out.push(Condition {
            role,
            resource_type: rt,
            when,
            otherwise,
        });
    }
    out
}

/// The declared data field a template reads. It must decide access.
fn template_field<'d>(
    ctx: &mut Ctx,
    at: &str,
    def: &'d TypeDef,
    name: &str,
) -> Option<(FieldName, &'d FieldDef)> {
    let Some((field, fd)) = def.fields.get_key_value(name) else {
        ctx.bad(
            at,
            format!("`{name}` is not a declared data field of the type"),
        );
        return None;
    };
    if !fd.grants_access {
        ctx.bad(
            at,
            format!("`{name}` is read by a condition, so it must have `grants_access = true`"),
        );
    }
    Some((field.clone(), fd))
}

fn value(ctx: &mut Ctx, at: &str, ft: FieldType, v: toml::Value) -> Option<Value> {
    match (ft, v) {
        (FieldType::String, toml::Value::String(s)) => {
            if text_ok(&s, MAX_STRING_VALUE) {
                Some(Value::String(s))
            } else {
                ctx.bad(
                    at,
                    "a string value is 1 to 256 characters with no control characters",
                );
                None
            }
        }
        (FieldType::Integer, toml::Value::Integer(i)) => Some(Value::Integer(i)),
        (FieldType::Boolean, toml::Value::Boolean(b)) => Some(Value::Boolean(b)),
        (FieldType::StringList | FieldType::Principal, _) => {
            ctx.bad(
                at,
                "this template does not work on this field type (use `contains` or `is_principal`)",
            );
            None
        }
        (_, _) => {
            ctx.bad(at, "the value's type does not match the field's type");
            None
        }
    }
}

fn template(
    ctx: &mut Ctx,
    at: &str,
    def: &TypeDef,
    t: raw::Template,
    depth: usize,
    nodes: &mut usize,
) -> Option<Template> {
    *nodes += 1;
    if depth > MAX_TEMPLATE_DEPTH {
        ctx.bad(at, "a template is at most 4 levels deep");
        return None;
    }
    match t {
        raw::Template::Eq(c) => {
            let (field, fd) = template_field(ctx, at, def, &c.field)?;
            let value = value(ctx, at, fd.field_type, c.value)?;
            Some(Template::Eq { field, value })
        }
        raw::Template::In(c) => {
            let (field, fd) = template_field(ctx, at, def, &c.field)?;
            if fd.field_type == FieldType::Boolean {
                ctx.bad(
                    at,
                    "`in` works on string and integer fields; use `eq` for a boolean",
                );
                return None;
            }
            if c.values.is_empty() || c.values.len() > MAX_IN_VALUES {
                ctx.bad(at, "`in` takes 1 to 64 values");
                return None;
            }
            let mut values = Vec::new();
            for v in c.values {
                values.push(value(ctx, at, fd.field_type, v)?);
            }
            Some(Template::In { field, values })
        }
        raw::Template::Contains(c) => {
            let (field, fd) = template_field(ctx, at, def, &c.field)?;
            if fd.field_type != FieldType::StringList {
                ctx.bad(at, "`contains` works on `string_list` fields only");
                return None;
            }
            match value(ctx, at, FieldType::String, c.value)? {
                Value::String(value) => Some(Template::Contains { field, value }),
                _ => None,
            }
        }
        raw::Template::IsPrincipal(name) => {
            let (field, fd) = template_field(ctx, at, def, &name)?;
            if fd.field_type != FieldType::Principal {
                ctx.bad(at, "`is_principal` works on `principal` fields only");
                return None;
            }
            Some(Template::IsPrincipal { field })
        }
        raw::Template::InGroup(name) => match GroupKey::parse(&name) {
            Ok(group) => Some(Template::InGroup { group }),
            Err(e) => {
                ctx.bad(at, format!("`{name}`: {e}"));
                None
            }
        },
        raw::Template::And(v) | raw::Template::Or(v) if !(2..=MAX_BRANCHES).contains(&v.len()) => {
            ctx.bad(at, "`and` and `or` take 2 to 16 templates");
            None
        }
        raw::Template::And(v) => branches(ctx, at, def, v, depth, nodes).map(Template::And),
        raw::Template::Or(v) => branches(ctx, at, def, v, depth, nodes).map(Template::Or),
        raw::Template::Not(t) => {
            template(ctx, at, def, *t, depth + 1, nodes).map(|t| Template::Not(Box::new(t)))
        }
    }
}

fn branches(
    ctx: &mut Ctx,
    at: &str,
    def: &TypeDef,
    v: Vec<raw::Template>,
    depth: usize,
    nodes: &mut usize,
) -> Option<Vec<Template>> {
    let mut out = Vec::new();
    let mut ok = true;
    for t in v {
        match template(ctx, at, def, t, depth + 1, nodes) {
            Some(t) => out.push(t),
            None => ok = false,
        }
    }
    ok.then_some(out)
}

// ---------- UI keys ----------

fn route(s: &str) -> Option<Route> {
    let (m, path) = s.split_once(' ')?;
    let method = match m {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "PATCH" => Method::Patch,
        "DELETE" => Method::Delete,
        _ => return None,
    };
    let ok_char = |c: char| c.is_ascii_graphic() && !matches!(c, '?' | '#');
    if !path.starts_with('/') || path.len() > 512 || !path.chars().all(ok_char) {
        return None;
    }
    // Placeholders: `{name}`, never nested or open.
    let mut open = false;
    for c in path.chars() {
        match (c, open) {
            ('{', false) => open = true,
            ('}', true) => open = false,
            ('{' | '}', _) => return None,
            _ => {}
        }
    }
    if open {
        return None;
    }
    Some(Route {
        method,
        path: path.to_owned(),
    })
}

fn ui(
    ctx: &mut Ctx,
    types: &BTreeMap<ResourceType, TypeDef>,
    raw: BTreeMap<String, raw::Ui>,
) -> BTreeMap<UiKey, UiComponent> {
    if raw.len() > MAX_UI_KEYS {
        ctx.bad("ui", "at most 2,000 UI keys");
    }
    let mut out = BTreeMap::new();
    for (name, u) in raw {
        let at = format!("ui.\"{name}\"");
        let key = match UiKey::parse(&name) {
            Ok(k) => k,
            Err(e) => {
                ctx.bad(&at, e.to_string());
                continue;
            }
        };
        let mut actions = BTreeSet::new();
        for a in u.actions {
            match ActionKey::parse(&a) {
                Ok(k) if action_exists(types, &k) => {
                    actions.insert(k);
                }
                _ => ctx.bad(
                    format!("{at}.actions"),
                    format!("`{a}` is not an action of a declared type"),
                ),
            }
        }
        let mut fields = BTreeSet::new();
        for f in u.fields {
            match FieldKey::parse(&f) {
                Ok(k) if known_field(types, &k) => {
                    fields.insert(k);
                }
                _ => ctx.bad(
                    format!("{at}.fields"),
                    format!("`{f}` is not a declared field or feature"),
                ),
            }
        }
        if actions.is_empty() && fields.is_empty() {
            ctx.bad(&at, "name at least one action or field");
        }
        if u.routes.is_empty() || u.routes.len() > MAX_ROUTES {
            ctx.bad(format!("{at}.routes"), "list 1 to 16 routes");
        }
        let mut routes = Vec::new();
        for r in u.routes {
            match route(&r) {
                Some(r) => routes.push(r),
                None => ctx.bad(
                    format!("{at}.routes"),
                    format!("`{r}` is not `METHOD /path` (GET, POST, PUT, PATCH or DELETE)"),
                ),
            }
        }
        let when_denied = match u.when_denied.as_str() {
            "show" => WhenDenied::Show,
            "disable" => WhenDenied::Disable,
            "hide" => WhenDenied::Hide,
            "readonly" => WhenDenied::Readonly,
            _ => {
                ctx.bad(
                    format!("{at}.when_denied"),
                    "must be `show`, `disable`, `hide` or `readonly`",
                );
                WhenDenied::Hide
            }
        };
        if let Some(r) = &u.reason {
            if !text_ok(r, MAX_REASON) {
                ctx.bad(
                    format!("{at}.reason"),
                    "1 to 512 characters with no control characters",
                );
            }
        }
        out.insert(
            key,
            UiComponent {
                actions,
                fields,
                routes,
                when_denied,
                reason: u.reason,
            },
        );
    }
    out
}

fn action_exists(types: &BTreeMap<ResourceType, TypeDef>, k: &ActionKey) -> bool {
    known_type(types, k.resource_type())
        && (k.as_builtin().is_some()
            || is_admin_key(k.action())
            || types
                .get(k.resource_type())
                .is_some_and(|d| d.actions.contains_key(k.action())))
}
