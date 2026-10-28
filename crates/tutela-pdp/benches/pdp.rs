//! Latency of the evaluator at the library-gate size: `check` (mixed,
//! allowed only, allowed delegated calls), `write_check` and `list_filter`.
//!
//! The tenant has the sizes of the week-1 spike (SPIKE-WEEK1.md 4.1, the
//! model the library gate names): 200 types, 100 roles, 5,000 field rules,
//! 10,000 role assignments, 10,000 users and 100 agents, 500 groups nested
//! 8 deep, 20,000 scopes (10% private) and 200,000 items with paths up to
//! 32. The gate: `check` p99 under 1 ms in process (ROADMAP Phase A). The
//! run fails (exit code 1) when a `check` workload is above it.
//!
//! Run with `cargo bench -p tutela-pdp`, on a quiet machine: no other build
//! at the same time.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt::Write as _;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use tutela_contracts::decision::Effect;
use tutela_contracts::keys::{ActionKey, FieldKey, FieldName, ResourceId, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{Issuer, OrgId, TenantKey};
use tutela_pdp::model::{GroupKey, Model, RoleKey};
use tutela_pdp::{
    AttrValue, Attrs, Binding, CheckRequest, Group, ListFilterRequest, Member, PathEntry, Pdp,
    ResourceRef, ScopeFieldRule, ScopePathError, ScopePaths, Subject, TenantData,
    WriteCheckRequest,
};

type Res<T> = Result<T, Box<dyn Error>>;

const USERS: usize = 10_000;
const AGENTS: usize = 100;
const GROUPS: usize = 500;
const GROUP_LEVELS: usize = 8;
const DEPTS: usize = 100;
const SCOPES: usize = 20_000;
const ITEMS: usize = 200_000;
const USER_BINDINGS: usize = 8_000;
const ROOT_BINDINGS: usize = 300;
const GROUP_BINDINGS: usize = 1_500;
const AGENT_BINDINGS: usize = 500;
const ROLES: usize = 95;
const FILLER_TYPES: usize = 196;
const ROOT_RULES: usize = 1_000;
const SCOPE_RULES: usize = 4_000;
const CONDITIONS: usize = 200;
const CHECKS: usize = 200_000;
const LISTS: usize = 500;
/// The library gate: `check` p99 under 1 ms, in microseconds.
const GATE_P99_US: f64 = 1_000.0;

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n.max(1) as u64)).unwrap_or(0)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// 20 fields: 3 public, 14 internal, 2 confidential, 1 secret.
const FIELDS: [(&str, &str); 20] = [
    ("status", "internal"),
    ("prio", "internal"),
    ("owner_p", "internal"),
    ("labels", "internal"),
    ("title", "public"),
    ("code", "public"),
    ("kind", "public"),
    ("summary", "internal"),
    ("notes", "internal"),
    ("due", "internal"),
    ("region", "internal"),
    ("team", "internal"),
    ("phase", "internal"),
    ("score", "internal"),
    ("tags2", "internal"),
    ("source", "internal"),
    ("link", "internal"),
    ("cost", "confidential"),
    ("budget", "confidential"),
    ("salary", "secret"),
];

fn field_line(name: &str, sensitivity: &str) -> String {
    let ty = match name {
        "prio" => ", type = \"integer\", grants_access = true",
        "owner_p" => ", type = \"principal\", grants_access = true",
        "labels" => ", type = \"string_list\", grants_access = true",
        "status" => ", grants_access = true",
        _ => "",
    };
    format!("{name} = {{ sensitivity = \"{sensitivity}\"{ty} }}\n")
}

fn manifest(rng: &mut Rng) -> String {
    let mut s = String::from(
        "version = 1\n[app]\nname = \"bench\"\n\n\
         [types.dept]\nparent = \"org\"\ncontainer = true\n\n\
         [types.proj]\nparent = [\"dept\", \"proj\"]\ncontainer = true\n\n\
         [types.item]\nparent = \"proj\"\nfeatures = [\"ai\", \"chat\", \"files\"]\n\n\
         [types.item.fields]\n",
    );
    for (f, sens) in FIELDS {
        s.push_str(&field_line(f, sens));
    }
    s.push_str(
        "\n[types.item.actions]\napprove = { needs = \"write\" }\nexport = { needs = \"read\" }\n",
    );
    for t in 0..FILLER_TYPES {
        let _ = write!(
            s,
            "\n[types.filler{t}]\nparent = \"org\"\n\n[types.filler{t}.fields]\nf = {{ sensitivity = \"internal\" }}\n"
        );
    }
    let levels = [Level::Read, Level::Write, Level::Full, Level::Read];
    let mut role_item = Vec::new();
    for r in 0..ROLES {
        let item = levels[rng.below(levels.len())];
        role_item.push(item);
        let mut g = vec![
            format!("dept = \"{}\"", levels[rng.below(4)]),
            format!("proj = \"{}\"", levels[rng.below(4)]),
            format!("item = \"{item}\""),
        ];
        for t in 0..FILLER_TYPES {
            g.push(format!("filler{t} = \"{}\"", levels[rng.below(4)]));
        }
        for (f, _) in FIELDS {
            if rng.chance(10) {
                g.push(format!("\"item.{f}\" = \"read\""));
            }
        }
        if rng.chance(40) {
            g.push("\"item.@ai\" = \"write\"".to_owned());
        }
        for a in ["approve", "export"] {
            if rng.chance(30) {
                g.push(format!("\"item:{a}\" = true"));
            }
        }
        let _ = write!(
            s,
            "\n[roles.r{r}]\ngrants = {{ {} }}\nassignable_to = [\"user\", \"group\"]\n",
            g.join(", ")
        );
    }
    for c in 0..CONDITIONS {
        let r = c % ROLES;
        let when = match rng.below(4) {
            0 => "{ eq = { field = \"status\", value = \"open\" } }",
            1 => "{ is_principal = \"owner_p\" }",
            2 => "{ not = { contains = { field = \"labels\", value = \"locked\" } } }",
            _ => "{ in = { field = \"prio\", values = [1, 2] } }",
        };
        let _ = write!(
            s,
            "\n[[conditions]]\nrole = \"r{r}\"\ntype = \"item\"\nwhen = {when}\nelse = \"read\"\n"
        );
    }
    let mut taken = BTreeSet::new();
    while taken.len() < ROOT_RULES {
        let r = rng.below(ROLES);
        let (f, _) = FIELDS[rng.below(FIELDS.len())];
        if taken.insert((r, f)) {
            let _ = write!(
                s,
                "\n[[field_rules]]\nfield = \"item.{f}\"\nrole = \"r{r}\"\nmax = \"{}\"\n",
                levels[rng.below(4)]
            );
        }
    }
    s.push_str(
        "\n[roles.agent]\ngrants = { proj = \"read\", item = \"write\" }\n\n\
         [[conditions]]\nrole = \"agent\"\ntype = \"item\"\nwhen = { is_principal = \"owner_p\" }\nelse = \"read\"\n",
    );
    s
}

fn user(n: usize) -> Res<Principal> {
    Ok(format!("user:usr_0193a1b2-c3d4-7a11-8b22-{n:012x}").parse()?)
}

fn agent(n: usize) -> Res<Principal> {
    Ok(format!("agent:agt_0193a1b2-c3d4-7b33-9c44-{n:012x}").parse()?)
}

fn entry(t: &str, id: &str) -> Res<PathEntry> {
    Ok(PathEntry::new(
        ResourceType::parse(t)?,
        ResourceId::parse(id)?,
    ))
}

fn rule(s: &str) -> Res<tutela_contracts::decision::RuleId> {
    Ok(tutela_contracts::decision::RuleId::parse(s)?)
}

/// The product's tree, as a scope-path provider.
struct Tree {
    tenant: TenantKey,
    paths: HashMap<PathEntry, Vec<PathEntry>>,
}

impl ScopePaths for Tree {
    fn ancestors(&self, t: &TenantKey, s: &PathEntry) -> Result<Vec<PathEntry>, ScopePathError> {
        if *t != self.tenant {
            return Err(ScopePathError::NotFound);
        }
        self.paths.get(s).cloned().ok_or(ScopePathError::NotFound)
    }
}

/// An item, kept small: its parent scope and its field values.
struct Item {
    parent: usize,
    attrs: Attrs,
}

struct World {
    pdp: Pdp,
    tree: Tree,
    scopes: Vec<PathEntry>,
    items: Vec<Item>,
    item_type: ResourceType,
    /// Items below each project scope.
    by_scope: HashMap<usize, Vec<usize>>,
    /// (agent, the users bound with it, its scope).
    agent_teams: Vec<(Principal, Vec<Principal>, usize)>,
}

impl World {
    fn resource(&self, i: usize) -> Res<ResourceRef> {
        let item = self.items.get(i).ok_or("no such item")?;
        let parent = self.scopes.get(item.parent).ok_or("no such scope")?;
        let mut path = vec![parent.clone()];
        path.extend(self.tree.paths.get(parent).cloned().unwrap_or_default());
        Ok(ResourceRef {
            type_name: self.item_type.clone(),
            id: ResourceId::parse(&format!("i{i}"))?,
            path,
            attrs: item.attrs.clone(),
        })
    }

    fn check(
        &self,
        subject: Principal,
        actors: Vec<Principal>,
        act: &str,
        i: usize,
    ) -> Res<CheckRequest> {
        Ok(CheckRequest {
            tenant: self.tree.tenant.clone(),
            subject,
            actors,
            action: ActionKey::parse(act)?,
            resource: self.resource(i)?,
            fields: None,
            at_least_revision: None,
        })
    }
}

#[allow(clippy::too_many_lines)]
fn build() -> Res<World> {
    let mut rng = Rng(0x7475_7465_6c61);
    let started = Instant::now();
    let model = Arc::new(Model::from_toml(&manifest(&mut rng))?);
    let org_id: OrgId = "org_0193a1b2-c3d4-7f00-9a00-000000000001".parse()?;
    let org = PathEntry::org(&org_id)?;
    let tenant = TenantKey::new(
        Issuer::parse("https://auth.bench.test")?,
        "ten_0193a1b2-c3d4-7e5f-8a6b-000000000001".parse()?,
    );

    // 20,000 scopes: departments, then projects in chains up to depth 31.
    let mut paths: HashMap<PathEntry, Vec<PathEntry>> = HashMap::new();
    let mut scopes: Vec<PathEntry> = Vec::with_capacity(SCOPES);
    for d in 0..DEPTS {
        let e = entry("dept", &format!("d{d}"))?;
        paths.insert(e.clone(), vec![org.clone()]);
        scopes.push(e);
    }
    while scopes.len() < SCOPES {
        let p = scopes.len();
        let e = entry("proj", &format!("p{p}"))?;
        let parent = if rng.chance(70) { p - 1 } else { rng.below(p) };
        let parent = if paths.get(&scopes[parent]).is_some_and(|v| v.len() < 30) {
            parent
        } else {
            rng.below(DEPTS)
        };
        let mut path = vec![scopes[parent].clone()];
        path.extend(paths.get(&scopes[parent]).cloned().unwrap_or_default());
        paths.insert(e.clone(), path);
        scopes.push(e);
    }
    let projects: Vec<usize> = (DEPTS..SCOPES).collect();

    // 200,000 items below projects.
    let mut items = Vec::with_capacity(ITEMS);
    let mut by_scope: HashMap<usize, Vec<usize>> = HashMap::new();
    let status = FieldName::parse("status")?;
    let owner_p = FieldName::parse("owner_p")?;
    let labels = FieldName::parse("labels")?;
    let prio = FieldName::parse("prio")?;
    for i in 0..ITEMS {
        let parent = projects[rng.below(projects.len())];
        let mut attrs = Attrs::new();
        if rng.chance(70) {
            let s = if rng.chance(50) { "open" } else { "done" };
            attrs.insert(status.clone(), AttrValue::String(s.to_owned()));
        }
        if rng.chance(60) {
            let owner = if rng.chance(50) {
                agent(rng.below(AGENTS))?
            } else {
                user(rng.below(USERS))?
            };
            attrs.insert(owner_p.clone(), AttrValue::String(owner.to_string()));
        }
        if rng.chance(50) {
            let l = if rng.chance(20) {
                vec!["locked".to_owned()]
            } else {
                vec![]
            };
            attrs.insert(labels.clone(), AttrValue::Strings(l));
        }
        if rng.chance(50) {
            attrs.insert(
                prio.clone(),
                AttrValue::Integer(i64::try_from(rng.below(3))?),
            );
        }
        // The fields that decide access are always sent, `null` if unset.
        for f in [&status, &owner_p, &labels, &prio] {
            attrs.entry(f.clone()).or_insert(AttrValue::Null);
        }
        by_scope.entry(parent).or_default().push(i);
        items.push(Item { parent, attrs });
    }

    // 500 groups in 8 levels; each group below the top is in 1-2 groups of
    // the level above. Users in 1-3 groups; one big group holds them all.
    let mut groups: Vec<Group> = (0..GROUPS)
        .map(|g| -> Res<Group> {
            Ok(Group {
                key: GroupKey::parse(&format!("g{g}"))?,
                members: Vec::new(),
            })
        })
        .collect::<Res<_>>()?;
    let per_level = GROUPS / GROUP_LEVELS;
    for g in per_level..GROUPS - 1 {
        let level = g / per_level;
        let above = (level - 1) * per_level;
        for _ in 0..1 + rng.below(2) {
            let parent = above + rng.below(per_level);
            let child = groups[g].key.clone();
            groups[parent].members.push(Member::Group(child));
        }
    }
    let big = GROUPS - 1;
    for u in 0..USERS {
        let p = user(u)?;
        groups[big].members.push(Member::Principal(p.clone()));
        for _ in 0..1 + rng.below(3) {
            let g = rng.below(GROUPS - 1);
            groups[g].members.push(Member::Principal(p.clone()));
        }
    }

    // 10,000 role assignments.
    let roles: Vec<String> = (0..ROLES).map(|r| format!("r{r}")).collect();
    let mut bindings = Vec::new();
    let mut taken = BTreeSet::new();
    let mut push = |subject: Subject, role: &str, scope: PathEntry, id: String| -> Res<()> {
        if taken.insert((subject.clone(), scope.clone())) {
            bindings.push(Binding {
                id: rule(&id)?,
                subject,
                role: RoleKey::parse(role)?,
                scope,
            });
        }
        Ok(())
    };
    for i in 0..ROOT_BINDINGS {
        let r = &roles[rng.below(ROLES)];
        push(
            Subject::Principal(user(rng.below(USERS))?),
            r,
            org.clone(),
            format!("ra_root_{i}"),
        )?;
    }
    for i in 0..USER_BINDINGS - ROOT_BINDINGS {
        let r = &roles[rng.below(ROLES)];
        let scope = scopes[rng.below(SCOPES)].clone();
        push(
            Subject::Principal(user(rng.below(USERS))?),
            r,
            scope,
            format!("ra_u_{i}"),
        )?;
    }
    for i in 0..GROUP_BINDINGS {
        let r = &roles[rng.below(ROLES)];
        let scope = scopes[rng.below(SCOPES)].clone();
        let g = groups[rng.below(GROUPS)].key.clone();
        push(Subject::Group(g), r, scope, format!("ra_g_{i}"))?;
    }
    let mut agent_teams = Vec::new();
    for i in 0..AGENT_BINDINGS {
        let a = i % AGENTS;
        let ag = agent(a)?;
        let s = projects[rng.below(projects.len())];
        let scope = scopes[s].clone();
        push(
            Subject::Principal(ag.clone()),
            "agent",
            scope.clone(),
            format!("ra_a_{i}"),
        )?;
        if i < AGENTS {
            let mut team = Vec::new();
            for k in 0..3 {
                let u = user(rng.below(USERS))?;
                push(
                    Subject::Principal(u.clone()),
                    "member",
                    scope.clone(),
                    format!("ra_t_{i}_{k}"),
                )?;
                team.push(u);
            }
            agent_teams.push((ag, team, s));
        }
    }

    let private_scopes = (0..SCOPES / 10)
        .map(|_| scopes[DEPTS + rng.below(SCOPES - DEPTS)].clone())
        .collect();
    let mut field_rules = Vec::new();
    let mut rule_keys = BTreeSet::new();
    while field_rules.len() < SCOPE_RULES {
        let scope = scopes[rng.below(SCOPES)].clone();
        let (f, _) = FIELDS[rng.below(FIELDS.len())];
        let role = rng.chance(70).then(|| roles[rng.below(ROLES)].clone());
        if !rule_keys.insert((scope.clone(), f, role.clone())) {
            continue;
        }
        field_rules.push(ScopeFieldRule {
            id: rule(&format!("fr_{}", field_rules.len()))?,
            scope,
            field: FieldKey::parse(&format!("item.{f}"))?,
            role: role.map(|r| RoleKey::parse(&r)).transpose()?,
            max: [Level::None, Level::Read, Level::Write][rng.below(3)],
        });
    }
    let data = TenantData {
        orgs: [org_id].into(),
        bindings,
        groups,
        private_scopes,
        field_rules,
    };
    let mut pdp = Pdp::new();
    pdp.load(tenant.clone(), 1, model, data)?;
    println!("built and loaded the tenant in {:.2?}", started.elapsed());
    Ok(World {
        pdp,
        tree: Tree { tenant, paths },
        scopes,
        items,
        item_type: ResourceType::parse("item")?,
        by_scope,
        agent_teams,
    })
}

/// Prints one line and returns the p99 in microseconds.
fn report(name: &str, mut ns: Vec<u128>, allowed: Option<usize>) -> f64 {
    ns.sort_unstable();
    let at = |q: f64| {
        let i = ((ns.len() as f64) * q) as usize;
        ns.get(i.min(ns.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0) as f64
            / 1000.0
    };
    let allowed = allowed.map_or_else(
        || "     -".to_owned(),
        |a| format!("{:>5.1}%", 100.0 * a as f64 / ns.len().max(1) as f64),
    );
    println!(
        "{name:<28} n={:>7} allowed={allowed}  p50={:>8.1}us  p99={:>8.1}us  p99.9={:>8.1}us  max={:>9.1}us",
        ns.len(),
        at(0.50),
        at(0.99),
        at(0.999),
        ns.last().copied().unwrap_or(0) as f64 / 1000.0,
    );
    at(0.99)
}

/// Times `check` on requests made by `next` (made outside the timed part).
fn time_checks(
    w: &World,
    name: &str,
    n: usize,
    mut next: impl FnMut(usize) -> Res<CheckRequest>,
) -> Res<f64> {
    let mut ns = Vec::with_capacity(n);
    let mut allowed = 0;
    for k in 0..n {
        let r = next(k)?;
        let t = Instant::now();
        let d = black_box(w.pdp.check(black_box(&r)))?;
        ns.push(t.elapsed().as_nanos());
        if d.is_allowed() {
            allowed += 1;
        }
    }
    Ok(report(name, ns, Some(allowed)))
}

#[allow(clippy::too_many_lines)]
fn main() -> Res<()> {
    let w = build()?;
    let mut rng = Rng(42);
    let actions = ["item:read", "item:write", "item:approve", "item:export"];
    let mut p99s = Vec::new();

    // W1: random users, items and actions (mostly denies).
    let mut picks = Vec::with_capacity(CHECKS);
    for _ in 0..CHECKS {
        picks.push((rng.below(USERS), rng.below(ITEMS), rng.below(4)));
    }
    p99s.push(time_checks(&w, "check, mixed", CHECKS, |k| {
        let (u, i, a) = picks[k];
        w.check(user(u)?, vec![], actions[a], i)
    })?);

    // W2: allowed calls only: users bound near the items they ask for.
    let mut allowed = Vec::new();
    let mut tries = 0;
    while allowed.len() < 20_000 && tries < 2_000_000 {
        tries += 1;
        let (u, a) = (rng.below(USERS), rng.below(4));
        let i = rng.below(ITEMS);
        let r = w.check(user(u)?, vec![], actions[a], i)?;
        if w.pdp.check(&r)?.is_allowed() {
            allowed.push((u, i, a));
        }
    }
    if allowed.is_empty() {
        return Err("no allowed calls found".into());
    }
    p99s.push(time_checks(&w, "check, allowed only", CHECKS, |k| {
        let (u, i, a) = allowed[k % allowed.len()];
        w.check(user(u)?, vec![], actions[a], i)
    })?);

    // W3: allowed delegated calls: a user and an agent bound at the same
    // project, on items below it.
    let mut delegated = Vec::new();
    for (t, (ag, team, s)) in w.agent_teams.iter().enumerate() {
        for (m, u) in team.iter().enumerate() {
            for &i in w.by_scope.get(s).into_iter().flatten() {
                for (a, act) in actions.iter().enumerate().take(2) {
                    let r = w.check(u.clone(), vec![ag.clone()], act, i)?;
                    if w.pdp.check(&r)?.is_allowed() {
                        delegated.push((t, m, i, a));
                    }
                }
            }
        }
    }
    if delegated.is_empty() {
        return Err("no allowed delegated calls found".into());
    }
    p99s.push(time_checks(&w, "check, delegated allowed", CHECKS, |k| {
        let (t, m, i, a) = delegated[k % delegated.len()];
        let (ag, team, _) = &w.agent_teams[t];
        w.check(team[m].clone(), vec![ag.clone()], actions[a], i)
    })?);

    // write_check of two fields on allowed delegated writes.
    let writes: Vec<_> = delegated.iter().filter(|d| d.3 == 1).collect();
    let mut ns = Vec::new();
    let mut ok = 0;
    let notes = FieldName::parse("notes")?;
    let title = FieldName::parse("title")?;
    for k in 0..CHECKS.min(writes.len() * 10) {
        let &(t, m, i, _) = writes[k % writes.len()];
        let (ag, team, _) = &w.agent_teams[t];
        let mut new_attrs = Attrs::new();
        new_attrs.insert(notes.clone(), AttrValue::String("n".into()));
        new_attrs.insert(title.clone(), AttrValue::String("t".into()));
        let r = WriteCheckRequest {
            tenant: w.tree.tenant.clone(),
            subject: team[m].clone(),
            actors: vec![ag.clone()],
            resource: w.resource(i)?,
            new_attrs,
            new_path: None,
            at_least_revision: None,
        };
        let t0 = Instant::now();
        let d = black_box(w.pdp.write_check(black_box(&r)))?;
        ns.push(t0.elapsed().as_nanos());
        if d.effect == Effect::Allow {
            ok += 1;
        }
    }
    report("write_check, delegated", ns, Some(ok));

    // W4: list filters for random users, and users with their agent.
    let mut largest = (0, 0, 0);
    let mut times: BTreeMap<&str, Vec<u128>> = BTreeMap::new();
    for k in 0..LISTS {
        let (subject, actors, name) = if k % 2 == 0 {
            (user(rng.below(USERS))?, vec![], "list_filter")
        } else {
            let (ag, team, _) = &w.agent_teams[rng.below(w.agent_teams.len())];
            (team[0].clone(), vec![ag.clone()], "list_filter, delegated")
        };
        let req = ListFilterRequest {
            tenant: w.tree.tenant.clone(),
            subject,
            actors,
            action: ActionKey::parse(actions[k % 2])?,
            at_least_revision: None,
        };
        let t0 = Instant::now();
        let f = black_box(w.pdp.list_filter(black_box(&req), &w.tree))?;
        times.entry(name).or_default().push(t0.elapsed().as_nanos());
        let s = f.size();
        largest = (
            largest.0.max(s.nodes),
            largest.1.max(s.depth),
            largest.2.max(s.entries),
        );
    }
    for (name, ns) in times {
        report(name, ns, None);
    }
    println!(
        "largest list filter seen: {} condition nodes, depth {}, {} entries (each the max over all filters)",
        largest.0, largest.1, largest.2
    );

    let worst = p99s.iter().copied().fold(0.0_f64, f64::max);
    if worst >= GATE_P99_US {
        return Err(
            format!("check p99 {worst:.1} us is not under the gate of {GATE_P99_US} us").into(),
        );
    }
    println!("gate: check p99 {worst:.1} us < {GATE_P99_US} us: pass");
    Ok(())
}
