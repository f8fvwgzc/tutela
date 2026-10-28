//! Random models, tenants and rows for the property tests and the
//! differential `list_filter` ≡ `check` test.
//!
//! Every world has two tenants whose resource ids are the same strings, so a
//! leak across tenants shows up. Fields are often null, and conditions often
//! use `not`, so a `NULL` leak through `not` shows up (ADR-0011 F4).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;

use tutela_contracts::keys::{FieldKey, FieldName};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;

use crate::model::{GroupKey, Model, RoleKey};
use crate::tests_check::{agent, entry, org_id, rule, tenant, user};
use crate::{
    AttrValue, Attrs, Binding, FilterExpr, FilterValue, Group, ListFilter, Member, PathEntry,
    ResourceRef, ScopeFieldRule, ScopePathError, ScopePaths, Subject, TenantData,
};

/// SplitMix64: small, fast, and the same everywhere.
pub(crate) struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n.max(1) as u64)).unwrap()
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }

    pub fn level(&mut self) -> Level {
        *self.pick(&Level::ALL)
    }

    pub fn level_upto(&mut self, max: Level) -> Level {
        let v: Vec<Level> = Level::ALL.into_iter().filter(|l| *l <= max).collect();
        *self.pick(&v)
    }
}

/// Every data field a generated `doc` may have. `extra` comes and goes
/// with model changes.
pub(crate) const DATA_FIELDS: [&str; 8] = [
    "status", "prio", "flag", "labels", "owner_p", "title", "secret_f", "extra",
];
pub(crate) const GROUPS: [&str; 3] = ["g1", "g2", "g3"];
pub(crate) const BUILTIN_ACTIONS: [&str; 7] = [
    "doc:read",
    "doc:write",
    "doc:delete",
    "doc:manage_access",
    "doc:manage_fields",
    "doc:read_audit",
    "doc:approve_move",
];

/// A data field of `doc`.
#[derive(Clone, Debug)]
pub(crate) struct FieldSpec {
    pub name: &'static str,
    pub sensitivity: &'static str,
    pub ty: &'static str,
    pub grants_access: bool,
}

/// A custom action of `doc`.
#[derive(Clone, Debug)]
pub(crate) struct ActionSpec {
    pub name: &'static str,
    pub needs: &'static str,
    pub grant: bool,
}

/// A role, before it is rendered as TOML.
#[derive(Clone, Debug)]
pub(crate) struct RoleSpec {
    pub key: String,
    pub node: Level,
    pub doc: Level,
    pub fields: BTreeMap<&'static str, Level>,
    pub grants: BTreeSet<&'static str>,
    pub assignable: Option<Vec<&'static str>>,
}

/// A condition on `doc`.
#[derive(Clone, Debug)]
pub(crate) struct CondSpec {
    pub role: String,
    pub when: String,
    pub otherwise: Level,
}

/// An org-root field rule.
#[derive(Clone, Debug)]
pub(crate) struct RuleSpec {
    pub field: &'static str,
    pub role: Option<String>,
    pub max: Level,
}

/// A whole model, before it is rendered as TOML.
#[derive(Clone, Debug)]
pub(crate) struct ModelSpec {
    pub fields: Vec<FieldSpec>,
    /// Feature names with their `@`.
    pub features: Vec<&'static str>,
    pub actions: Vec<ActionSpec>,
    pub roles: Vec<RoleSpec>,
    pub conds: Vec<CondSpec>,
    pub rules: Vec<RuleSpec>,
}

fn template(rng: &mut Rng, depth: usize) -> String {
    let leaf = depth >= 3 || rng.chance(45);
    if leaf {
        // `not(eq)` is two levels; the template limit is four.
        let kinds = if depth >= 3 { 8 } else { 9 };
        return match rng.below(kinds) {
            0 => format!(
                "{{ eq = {{ field = \"status\", value = \"{}\" }} }}",
                rng.pick(&["open", "done", "x"])
            ),
            1 => format!(
                "{{ eq = {{ field = \"prio\", value = {} }} }}",
                rng.below(3)
            ),
            2 => format!(
                "{{ eq = {{ field = \"flag\", value = {} }} }}",
                rng.chance(50)
            ),
            3 => "{ in = { field = \"status\", values = [\"open\", \"x\"] } }".to_owned(),
            4 => "{ in = { field = \"prio\", values = [0, 2] } }".to_owned(),
            5 => format!(
                "{{ contains = {{ field = \"labels\", value = \"{}\" }} }}",
                rng.pick(&["a", "b", "c"])
            ),
            6 => "{ is_principal = \"owner_p\" }".to_owned(),
            7 => format!("{{ in_group = \"{}\" }}", rng.pick(&["g1", "g2", "nope"])),
            _ => format!(
                "{{ not = {{ eq = {{ field = \"status\", value = \"{}\" }} }} }}",
                rng.pick(&["open", "done"])
            ),
        };
    }
    match rng.below(4) {
        0 | 1 => format!("{{ not = {} }}", template(rng, depth + 1)),
        2 => format!(
            "{{ and = [{}, {}] }}",
            template(rng, depth + 1),
            template(rng, depth + 1)
        ),
        _ => format!(
            "{{ or = [{}, {}] }}",
            template(rng, depth + 1),
            template(rng, depth + 1)
        ),
    }
}

const ADMIN_GRANTS: [&str; 4] = [
    "doc:seal",
    "doc:manage_access",
    "doc:manage_fields",
    "doc:read_audit",
];

impl ModelSpec {
    pub fn generate(rng: &mut Rng) -> Self {
        let field = |name, sensitivity, ty, grants_access| FieldSpec {
            name,
            sensitivity,
            ty,
            grants_access,
        };
        let mut fields = vec![
            field("status", "internal", "string", true),
            field("prio", "internal", "integer", true),
            field("flag", "public", "boolean", true),
            field("labels", "internal", "string_list", true),
            field("owner_p", "internal", "principal", true),
            field("title", "public", "string", false),
            field("secret_f", "secret", "string", false),
        ];
        if rng.chance(50) {
            fields.push(field("extra", "internal", "string", rng.chance(30)));
        }
        let mut features = vec!["@ai", "@chat"];
        if rng.chance(50) {
            features.push("@files");
        }
        let action = |name, needs, grant| ActionSpec { name, needs, grant };
        let mut actions = vec![
            action("approve", "write", true),
            action("export", "read", false),
            action("publish", "full", true),
            action("seal", "owner", true),
        ];
        if rng.chance(50) {
            actions.push(action("extra_act", "read", true));
        }
        let mut spec = Self {
            fields,
            features,
            actions,
            roles: Vec::new(),
            conds: Vec::new(),
            rules: Vec::new(),
        };
        let n = 1 + rng.below(5);
        for i in 0..n {
            let r = spec.role(rng, format!("r{i}"));
            spec.roles.push(r);
        }
        if rng.chance(60) {
            // The blueprint's agent: writes the docs it owns.
            let mut a = spec.role(rng, "agent".to_owned());
            a.grants.retain(|g| !ADMIN_GRANTS.contains(g));
            a.assignable = None;
            spec.roles.push(a);
        }
        for _ in 0..rng.below(5) {
            let r = rng.pick(&spec.roles).clone();
            if r.doc == Level::None {
                continue;
            }
            spec.conds.push(CondSpec {
                role: r.key.clone(),
                when: template(rng, 0),
                otherwise: rng.level_upto(r.doc),
            });
        }
        if let Some(doc) = spec.roles.iter().find(|r| r.key == "agent").map(|r| r.doc)
            && doc > Level::None
            && rng.chance(70)
        {
            spec.conds.push(CondSpec {
                role: "agent".to_owned(),
                when: "{ is_principal = \"owner_p\" }".to_owned(),
                otherwise: rng.level_upto(doc.min(Level::Read)),
            });
        }
        let mut seen = BTreeSet::new();
        for _ in 0..rng.below(4) {
            let field = *rng.pick(&["title", "status", "secret_f", "@ai", "labels"]);
            let role = if field == "secret_f" || rng.chance(50) {
                let mut keys: Vec<String> = spec.roles.iter().map(|r| r.key.clone()).collect();
                keys.extend(["member", "viewer"].map(str::to_owned));
                Some(rng.pick(&keys).clone())
            } else {
                None
            };
            if seen.insert((field, role.clone())) {
                spec.rules.push(RuleSpec {
                    field,
                    role,
                    max: rng.level(),
                });
            }
        }
        spec
    }

    fn has_field(&self, f: &str) -> bool {
        self.fields.iter().any(|x| x.name == f) || self.features.contains(&f)
    }

    fn role(&self, rng: &mut Rng, key: String) -> RoleSpec {
        let doc = rng.level();
        let mut fields = BTreeMap::new();
        for f in &self.fields {
            if rng.chance(25) {
                fields.insert(f.name, rng.level_upto(doc));
            }
        }
        if doc >= Level::Read {
            for &f in &self.features {
                if rng.chance(30) {
                    fields.insert(f, rng.level());
                }
            }
        }
        let mut grants = BTreeSet::new();
        for a in &self.actions {
            if a.grant && a.needs != "owner" && rng.chance(50) {
                grants.insert(match a.name {
                    "approve" => "doc:approve",
                    "publish" => "doc:publish",
                    _ => "doc:extra_act",
                });
            }
        }
        let admin = rng.chance(20);
        if admin {
            grants.insert(*rng.pick(&ADMIN_GRANTS));
        }
        let assignable = if admin {
            None
        } else {
            match rng.below(4) {
                0 => None,
                1 => Some(vec!["user", "group"]),
                2 => Some(vec!["agent", "user"]),
                _ => Some(vec!["user", "agent", "group", "sa"]),
            }
        };
        RoleSpec {
            key,
            node: rng.level(),
            doc,
            fields,
            grants,
            assignable,
        }
    }

    pub fn render(&self) -> String {
        let mut s = String::from(
            "version = 1\n[app]\nname = \"gen\"\n\n\
             [types.node]\nparent = [\"org\", \"node\"]\ncontainer = true\n\n\
             [types.box]\nparent = [\"org\", \"node\"]\n\n",
        );
        let feats: Vec<String> = self
            .features
            .iter()
            .map(|f| format!("\"{}\"", f.trim_start_matches('@')))
            .collect();
        let _ = write!(
            s,
            "[types.doc]\nparent = [\"node\", \"doc\"]\ncontainer = true\nfeatures = [{}]\n\n[types.doc.fields]\n",
            feats.join(", ")
        );
        for f in &self.fields {
            let _ = writeln!(
                s,
                "{} = {{ sensitivity = \"{}\", type = \"{}\", grants_access = {} }}",
                f.name, f.sensitivity, f.ty, f.grants_access
            );
        }
        s.push_str("\n[types.doc.actions]\n");
        for a in &self.actions {
            let _ = writeln!(
                s,
                "{} = {{ needs = \"{}\", grant = {} }}",
                a.name, a.needs, a.grant
            );
        }
        for r in &self.roles {
            let mut g = vec![
                format!("node = \"{}\"", r.node),
                format!("doc = \"{}\"", r.doc),
            ];
            for (f, l) in &r.fields {
                g.push(format!("\"doc.{f}\" = \"{l}\""));
            }
            for k in &r.grants {
                g.push(format!("\"{k}\" = true"));
            }
            let _ = write!(s, "\n[roles.{}]\ngrants = {{ {} }}\n", r.key, g.join(", "));
            if let Some(a) = &r.assignable {
                let list: Vec<String> = a.iter().map(|k| format!("\"{k}\"")).collect();
                let _ = writeln!(s, "assignable_to = [{}]", list.join(", "));
            }
        }
        for c in &self.conds {
            let _ = write!(
                s,
                "\n[[conditions]]\nrole = \"{}\"\ntype = \"doc\"\nwhen = {}\nelse = \"{}\"\n",
                c.role, c.when, c.otherwise
            );
        }
        for r in &self.rules {
            let _ = write!(
                s,
                "\n[[field_rules]]\nfield = \"doc.{}\"\nmax = \"{}\"\n",
                r.field, r.max
            );
            if let Some(role) = &r.role {
                let _ = writeln!(s, "role = \"{role}\"");
            }
        }
        s
    }

    /// Removes a field or feature and everything that names it.
    fn drop_field(&mut self, f: &str) {
        self.fields.retain(|x| x.name != f);
        self.features.retain(|x| *x != f);
        for r in &mut self.roles {
            r.fields.remove(f);
        }
        self.rules.retain(|r| r.field != f);
    }

    /// One random change. The result may not compile, or may widen; the
    /// caller checks both.
    #[allow(clippy::too_many_lines)]
    pub fn mutate(&self, rng: &mut Rng) -> Self {
        let mut m = self.clone();
        let ri = rng.below(m.roles.len());
        match rng.below(17) {
            0 => m.roles[ri].doc = rng.level(),
            1 => m.roles[ri].node = rng.level(),
            2 => {
                let f = rng.pick(&m.fields).name;
                let max = m.roles[ri].doc;
                m.roles[ri].fields.insert(f, rng.level_upto(max));
            }
            3 => {
                let g = *rng.pick(&["doc:approve", "doc:publish"]);
                if !m.roles[ri].grants.remove(g) {
                    m.roles[ri].grants.insert(g);
                }
            }
            4 if !m.conds.is_empty() => {
                let i = rng.below(m.conds.len());
                m.conds.remove(i);
            }
            5 => {
                let r = m.roles[ri].clone();
                if r.doc > Level::None {
                    m.conds.push(CondSpec {
                        role: r.key,
                        when: template(rng, 0),
                        otherwise: rng.level_upto(r.doc),
                    });
                }
            }
            6 if !m.rules.is_empty() => {
                let i = rng.below(m.rules.len());
                m.rules[i].max = rng.level();
            }
            7 if !m.rules.is_empty() => {
                let i = rng.below(m.rules.len());
                m.rules.remove(i);
            }
            8 => {
                let key = m.roles[ri].key.clone();
                m.roles.remove(ri);
                m.conds.retain(|c| c.role != key);
                m.rules.retain(|r| r.role.as_ref() != Some(&key));
            }
            9 => {
                let a = rng.below(m.actions.len());
                if m.actions[a].needs != "owner" {
                    m.actions[a].needs = rng.pick(&["read", "write", "full"]);
                }
            }
            10 => {
                m.roles[ri].assignable = match rng.below(3) {
                    0 => Some(vec!["user"]),
                    1 => Some(vec!["agent"]),
                    _ => Some(vec!["user", "agent", "group", "sa"]),
                };
                if m.roles[ri].grants.iter().any(|g| ADMIN_GRANTS.contains(g)) {
                    m.roles[ri].assignable = None;
                }
            }
            11 => {
                // A field's sensitivity. A field that conditions read may not
                // become confidential: that change does not compile.
                let i = rng.below(m.fields.len());
                m.fields[i].sensitivity =
                    rng.pick(&["public", "internal", "confidential", "secret"]);
            }
            12 => {
                // An action's grant flag. With `grant = false`, no role may
                // hold the grant.
                let i = rng.below(m.actions.len());
                if m.actions[i].needs != "owner" {
                    m.actions[i].grant = !m.actions[i].grant;
                    if !m.actions[i].grant {
                        let key = format!("doc:{}", m.actions[i].name);
                        for r in &mut m.roles {
                            r.grants.retain(|g| *g != key);
                        }
                    }
                }
            }
            13 => {
                // A feature level. It may be above the type level, but the
                // type level must be at least Read.
                let f = *rng.pick(&m.features);
                if m.roles[ri].doc >= Level::Read {
                    m.roles[ri].fields.insert(f, rng.level());
                } else {
                    m.roles[ri].fields.remove(f);
                }
            }
            14 => {
                if m.has_field("extra") {
                    m.drop_field("extra");
                } else {
                    m.fields.push(FieldSpec {
                        name: "extra",
                        sensitivity: rng.pick(&["internal", "confidential"]),
                        ty: "string",
                        grants_access: rng.chance(50),
                    });
                }
            }
            15 => {
                if m.actions.iter().any(|a| a.name == "extra_act") {
                    m.actions.retain(|a| a.name != "extra_act");
                    for r in &mut m.roles {
                        r.grants.remove("doc:extra_act");
                    }
                } else {
                    m.actions.push(ActionSpec {
                        name: "extra_act",
                        needs: rng.pick(&["read", "write"]),
                        grant: rng.chance(50),
                    });
                }
            }
            _ => {
                if m.has_field("@files") {
                    m.drop_field("@files");
                } else {
                    m.features.push("@files");
                }
            }
        }
        m
    }

    /// Every action the model declares on `doc`, built-in and custom.
    pub fn actions(&self) -> Vec<String> {
        BUILTIN_ACTIONS
            .iter()
            .map(|a| (*a).to_owned())
            .chain(self.actions.iter().map(|a| format!("doc:{}", a.name)))
            .collect()
    }

    /// A value of the right type for each declared data field.
    pub fn sample_value(&self, f: &str) -> Option<AttrValue> {
        let spec = self.fields.iter().find(|x| x.name == f)?;
        Some(match spec.ty {
            "integer" => AttrValue::Integer(1),
            "boolean" => AttrValue::Boolean(true),
            "string_list" => AttrValue::Strings(vec!["a".into()]),
            "principal" => AttrValue::String(user(1).to_string()),
            _ => AttrValue::String("v".into()),
        })
    }
}

/// One node or row of a tenant's tree.
#[derive(Clone, Debug)]
pub(crate) struct Node {
    pub entry: PathEntry,
    /// Ancestors, nearest first; the last is the org.
    pub path: Vec<PathEntry>,
    pub attrs: Attrs,
}

impl Node {
    pub fn resource(&self) -> ResourceRef {
        ResourceRef {
            type_name: self.entry.type_name.clone(),
            id: self.entry.id.clone(),
            path: self.path.clone(),
            attrs: self.attrs.clone(),
        }
    }
}

/// One tenant: its key, data and tree.
pub(crate) struct Tenant {
    pub key: TenantKey,
    pub data: TenantData,
    /// Every node and row, the org excluded.
    pub nodes: Vec<Node>,
}

impl Tenant {
    pub fn rows(&self) -> impl Iterator<Item = &Node> {
        self.nodes
            .iter()
            .filter(|n| n.entry.type_name.as_str() == "doc")
    }
}

/// The principals of every world.
pub(crate) fn principals() -> Vec<Principal> {
    vec![
        user(1),
        user(2),
        user(3),
        user(4),
        agent(1),
        agent(2),
        "sa:sa_0193a1b2-c3d4-7c55-ad66-000000000001"
            .parse()
            .unwrap(),
    ]
}

/// A tenant's tree and data. `n` makes the org id and tenant key; the
/// resource ids are the same in every tenant.
///
/// Some scopes are of type `box`, which is not a container: rows stored
/// below them stand for paths that were stored before the type stopped
/// being a container (a neutral manifest change). Some rows reuse the id of
/// a scope of another type. A few rows have 33 ancestors, one more than
/// `check` accepts; they are never scopes.
#[allow(clippy::too_many_lines)]
pub(crate) fn tenant_world(rng: &mut Rng, n: u32, roles: &[String]) -> Tenant {
    let key = tenant(n);
    let org = PathEntry::org(&org_id(n)).unwrap();
    let mut nodes: Vec<Node> = Vec::new();
    let node_count = 3 + rng.below(12);
    let deep = rng.chance(20);
    for i in 0..node_count {
        let parent = if i == 0 || rng.chance(20) {
            None
        } else if deep {
            Some(i - 1)
        } else {
            Some(rng.below(i))
        };
        let path = parent.map_or_else(|| vec![org.clone()], |p| path_below(&nodes[p]));
        let t = if !deep && rng.chance(15) {
            "box"
        } else {
            "node"
        };
        nodes.push(Node {
            entry: entry(t, &format!("n{i}")),
            path,
            attrs: Attrs::new(),
        });
    }
    if deep {
        // A chain to the depth limit: rows at path length 32, and below
        // them rows with 33 ancestors.
        while nodes.last().is_some_and(|n| n.path.len() < 31) {
            let i = nodes.len();
            let path = path_below(&nodes[i - 1]);
            nodes.push(Node {
                entry: entry("node", &format!("n{i}")),
                path,
                attrs: Attrs::new(),
            });
        }
    }
    let ps = principals();
    let row_count = 8 + rng.below(30);
    let first_row = nodes.len();
    let mut doc_ids = BTreeSet::new();
    for i in 0..row_count {
        let made = nodes.len() - first_row;
        let parent = if made > 0 && rng.chance(25) {
            // Below a row; in a deep world often below the deepest one.
            if deep && rng.chance(50) {
                nodes.len() - 1
            } else {
                first_row + rng.below(made)
            }
        } else if deep && rng.chance(30) {
            first_row - 1
        } else {
            rng.below(first_row)
        };
        let path = path_below(&nodes[parent]);
        if path.len() > crate::MAX_PATH + 1 {
            continue;
        }
        // Sometimes the id of a scope of another type.
        let reuse = format!("n{}", rng.below(first_row));
        let id = if rng.chance(10) && doc_ids.insert(reuse.clone()) {
            reuse
        } else {
            let own = format!("d{i}");
            doc_ids.insert(own.clone());
            own
        };
        nodes.push(Node {
            entry: entry("doc", &id),
            path,
            attrs: attrs(rng, &ps),
        });
    }
    // Scopes: every node `check` accepts, so up to 32 ancestors. Rows below
    // a scope with 32 ancestors have 33 and match no filter.
    let scope_nodes: Vec<&Node> = nodes
        .iter()
        .filter(|n| n.path.len() <= crate::MAX_PATH)
        .collect();

    let groups = vec![
        Group {
            key: GroupKey::parse("g1").unwrap(),
            members: members(rng, &ps, Some("g2")),
        },
        Group {
            key: GroupKey::parse("g2").unwrap(),
            members: members(rng, &ps, None),
        },
        Group {
            key: GroupKey::parse("g3").unwrap(),
            members: members(rng, &ps, Some("g1")),
        },
    ];
    let mut scopes: Vec<PathEntry> = vec![org.clone()];
    scopes.extend(scope_nodes.iter().map(|n| n.entry.clone()));
    let mut role_keys: Vec<String> = roles.to_vec();
    role_keys.extend(["owner", "member", "viewer", "guest", "agent", "ghost"].map(str::to_owned));
    let mut bindings = Vec::new();
    let mut taken = BTreeSet::new();
    for i in 0..rng.below(14) {
        let subject = if rng.chance(30) {
            Subject::Group(GroupKey::parse(rng.pick(&GROUPS)).unwrap())
        } else {
            Subject::Principal(rng.pick(&ps).clone())
        };
        let scope = if rng.chance(15) {
            org.clone()
        } else {
            rng.pick(&scopes).clone()
        };
        if !taken.insert((subject.clone(), scope.clone())) {
            continue;
        }
        let tag = if matches!(subject, Subject::Group(_)) {
            "g"
        } else {
            "p"
        };
        bindings.push(Binding {
            id: rule(&format!("ra_{tag}{i}")),
            subject,
            role: RoleKey::parse(rng.pick(&role_keys)).unwrap(),
            scope,
        });
    }
    let private_scopes = scope_nodes
        .iter()
        .filter(|_| rng.chance(25))
        .map(|n| n.entry.clone())
        .collect();
    let mut field_rules = Vec::new();
    let mut rule_keys = BTreeSet::new();
    for i in 0..rng.below(5) {
        let scope = rng.pick(&scope_nodes).entry.clone();
        let field = *rng.pick(&["title", "status", "secret_f", "@ai", "extra"]);
        let role = rng
            .chance(60)
            .then(|| RoleKey::parse(rng.pick(&role_keys)).unwrap());
        if !rule_keys.insert((scope.clone(), field, role.clone())) {
            continue;
        }
        field_rules.push(ScopeFieldRule {
            id: rule(&format!("fr_{i}")),
            scope,
            field: FieldKey::parse(&format!("doc.{field}")).unwrap(),
            role,
            max: rng.level(),
        });
    }
    Tenant {
        key,
        data: TenantData {
            orgs: [org_id(n)].into(),
            bindings,
            groups,
            private_scopes,
            field_rules,
        },
        nodes,
    }
}

fn path_below(parent: &Node) -> Vec<PathEntry> {
    core::iter::once(parent.entry.clone())
        .chain(parent.path.iter().cloned())
        .collect()
}

fn members(rng: &mut Rng, ps: &[Principal], nested: Option<&str>) -> Vec<Member> {
    let mut m: Vec<Member> = ps
        .iter()
        .filter(|_| rng.chance(30))
        .map(|p| Member::Principal(p.clone()))
        .collect();
    if let Some(g) = nested
        && rng.chance(50)
    {
        m.push(Member::Group(GroupKey::parse(g).unwrap()));
    }
    m
}

/// Field values: each one null (missing) four times in ten.
fn attrs(rng: &mut Rng, ps: &[Principal]) -> Attrs {
    let mut a = Attrs::new();
    let mut put = |rng: &mut Rng, f: &str, v: AttrValue| {
        if !rng.chance(40) {
            a.insert(FieldName::parse(f).unwrap(), v);
        }
    };
    let status = (*rng.pick(&["open", "done", "x"])).to_owned();
    put(rng, "status", AttrValue::String(status));
    let prio = i64::try_from(rng.below(3)).unwrap();
    put(rng, "prio", AttrValue::Integer(prio));
    let flag = rng.chance(50);
    put(rng, "flag", AttrValue::Boolean(flag));
    let labels: Vec<String> = ["a", "b", "c"]
        .iter()
        .filter(|_| rng.chance(40))
        .map(|s| (*s).to_owned())
        .collect();
    put(rng, "labels", AttrValue::Strings(labels));
    let owner = rng.pick(ps).to_string();
    put(rng, "owner_p", AttrValue::String(owner));
    a
}

/// A world: one model, two tenants with the same resource ids.
pub(crate) struct World {
    pub spec: ModelSpec,
    pub model: Arc<Model>,
    pub tenants: Vec<Tenant>,
}

pub(crate) fn world(seed: u64) -> World {
    let mut rng = Rng::new(seed);
    let spec = ModelSpec::generate(&mut rng);
    let model = Arc::new(Model::from_toml(&spec.render()).unwrap_or_else(|e| {
        panic!(
            "the generated manifest must compile: {e}\n{}",
            spec.render()
        )
    }));
    let roles: Vec<String> = spec.roles.iter().map(|r| r.key.clone()).collect();
    let mut tenants = vec![
        tenant_world(&mut rng, 1, &roles),
        tenant_world(&mut rng, 2, &roles),
    ];
    // Sometimes g3 also holds g2, so g2 can sit in two groups (g1 and g3).
    // Drawn after everything else, so the rest of each world is unchanged.
    for t in &mut tenants {
        if rng.chance(50)
            && let Some(g3) = t.data.groups.iter_mut().find(|g| g.key.as_str() == "g3")
        {
            g3.members.push(Member::Group(GroupKey::parse("g2").unwrap()));
        }
    }
    World {
        spec,
        model,
        tenants,
    }
}

/// A scope-path provider over the worlds' trees, keyed by (tenant, type, id).
#[derive(Default)]
pub(crate) struct Paths {
    pub map: HashMap<(TenantKey, PathEntry), Vec<PathEntry>>,
    /// Scopes to fail on, to test provider misses.
    pub missing: BTreeSet<PathEntry>,
    /// Every scope asked for.
    pub asked: std::cell::RefCell<BTreeSet<PathEntry>>,
}

impl Paths {
    pub fn of(tenants: &[Tenant]) -> Self {
        let mut map = HashMap::new();
        for t in tenants {
            for n in &t.nodes {
                map.insert((t.key.clone(), n.entry.clone()), n.path.clone());
            }
        }
        Self {
            map,
            ..Self::default()
        }
    }
}

impl ScopePaths for Paths {
    fn ancestors(
        &self,
        tenant: &TenantKey,
        scope: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError> {
        self.asked.borrow_mut().insert(scope.clone());
        if self.missing.contains(scope) {
            return Err(ScopePathError::NotFound);
        }
        self.map
            .get(&(tenant.clone(), scope.clone()))
            .cloned()
            .ok_or(ScopePathError::NotFound)
    }
}

// ---------- The filter on one row, as an SDK would read it ----------

/// `true` if the row passes the filter (CONTRACTS.md 6.6), written from the
/// contract text and apart from the evaluator.
pub(crate) fn row_matches(f: &ListFilter, row: &Node) -> bool {
    let positive =
        f.ids_in.contains(&row.entry.id) || row.path.iter().any(|a| f.container_in.contains(a));
    row.path.len() <= crate::MAX_PATH
        && positive
        && f.condition.as_ref().is_none_or(|c| expr_holds(c, row))
}

fn value_eq(a: Option<&AttrValue>, v: &FilterValue) -> bool {
    match (a, v) {
        (Some(AttrValue::String(a)), FilterValue::String(b)) => a == b,
        (Some(AttrValue::Integer(a)), FilterValue::Integer(b)) => a == b,
        (Some(AttrValue::Boolean(a)), FilterValue::Boolean(b)) => a == b,
        _ => false,
    }
}

fn is_null(a: Option<&AttrValue>) -> bool {
    matches!(a, None | Some(AttrValue::Null))
}

fn expr_holds(e: &FilterExpr, row: &Node) -> bool {
    match e {
        FilterExpr::True => true,
        FilterExpr::False => false,
        FilterExpr::And { args } => args.iter().all(|x| expr_holds(x, row)),
        FilterExpr::Or { args } => args.iter().any(|x| expr_holds(x, row)),
        FilterExpr::Not { arg } => !expr_holds(arg, row),
        FilterExpr::Eq { attr, value } => value_eq(row.attrs.get(attr), value),
        FilterExpr::Ne { attr, value } => {
            let a = row.attrs.get(attr);
            !is_null(a) && !value_eq(a, value)
        }
        FilterExpr::In { attr, values } => values.iter().any(|v| value_eq(row.attrs.get(attr), v)),
        FilterExpr::Contains { attr, value } => {
            matches!(row.attrs.get(attr), Some(AttrValue::Strings(v)) if v.contains(value))
        }
        FilterExpr::IsNull { attr } => is_null(row.attrs.get(attr)),
        FilterExpr::IdIn { ids } => ids.contains(&row.entry.id),
        FilterExpr::Under { scopes } => row.path.iter().any(|a| scopes.contains(a)),
    }
}

/// `true` if the condition holds a `not` over a comparison: the case where
/// a `NULL` could leak.
pub(crate) fn has_not_over_comparison(e: &FilterExpr) -> bool {
    match e {
        FilterExpr::Not { arg } => {
            matches!(
                **arg,
                FilterExpr::Eq { .. } | FilterExpr::In { .. } | FilterExpr::Contains { .. }
            ) || has_not_over_comparison(arg)
        }
        FilterExpr::And { args } | FilterExpr::Or { args } => {
            args.iter().any(has_not_over_comparison)
        }
        _ => false,
    }
}
