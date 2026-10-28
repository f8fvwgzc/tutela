//! Latency of the evaluator on a large generated tenant: `check` (mixed,
//! allowed only, allowed delegated calls), `write_check` and `list_filter`.
//!
//! Run with `cargo bench -p tutela-pdp`. It prints p50, p99, p99.9 and the
//! slowest call per workload, and the largest list filter it saw. The
//! library gate asks for `check` p99 under 1 ms in process (ROADMAP Phase A).
//! Run it on a quiet machine: no other build at the same time.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt::Write as _;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

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

const USERS: u32 = 5_000;
const AGENTS: u32 = 50;
const GROUPS: usize = 200;
const DEPTS: usize = 100;
const PROJECTS: usize = 2_000;
const ITEMS: usize = 20_000;
const BINDINGS: usize = 10_000;
const PRIVATE: usize = 300;
const SCOPE_RULES: usize = 500;
const ROLES: usize = 60;
const FILLER_TYPES: usize = 40;
const CHECKS: usize = 200_000;
const LISTS: usize = 2_000;

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

fn level_name(l: Level) -> &'static str {
    l.as_str()
}

const FIELDS: [&str; 12] = [
    "status", "prio", "owner_p", "labels", "title", "summary", "notes", "due", "cost", "budget",
    "region", "tags2",
];

fn manifest(rng: &mut Rng) -> String {
    let mut s = String::from(
        "version = 1\n[app]\nname = \"bench\"\n\n\
         [types.dept]\nparent = \"org\"\ncontainer = true\n\n\
         [types.proj]\nparent = [\"dept\", \"proj\"]\ncontainer = true\n\n\
         [types.item]\nparent = \"proj\"\nfeatures = [\"ai\", \"chat\", \"files\"]\n\n\
         [types.item.fields]\n\
         status  = { sensitivity = \"internal\", grants_access = true }\n\
         prio    = { sensitivity = \"internal\", type = \"integer\", grants_access = true }\n\
         owner_p = { sensitivity = \"internal\", type = \"principal\", grants_access = true }\n\
         labels  = { sensitivity = \"internal\", type = \"string_list\", grants_access = true }\n\
         title   = { sensitivity = \"public\" }\n\
         summary = { sensitivity = \"internal\" }\n\
         notes   = { sensitivity = \"internal\" }\n\
         due     = { sensitivity = \"internal\" }\n\
         cost    = { sensitivity = \"confidential\", type = \"integer\" }\n\
         budget  = { sensitivity = \"confidential\", type = \"integer\" }\n\
         region  = { sensitivity = \"internal\" }\n\
         tags2   = { sensitivity = \"internal\" }\n\n\
         [types.item.actions]\napprove = { needs = \"write\" }\nexport = { needs = \"read\", grant = false }\n",
    );
    for t in 0..FILLER_TYPES {
        let _ = write!(
            s,
            "\n[types.filler{t}]\nparent = \"org\"\n\n[types.filler{t}.fields]\nf = {{ sensitivity = \"internal\" }}\n"
        );
    }
    let levels = [Level::Read, Level::Write, Level::Full, Level::Read];
    for r in 0..ROLES {
        let item = levels[rng.below(levels.len())];
        let mut g = vec![
            format!("dept = \"{}\"", level_name(levels[rng.below(4)])),
            format!("proj = \"{}\"", level_name(levels[rng.below(4)])),
            format!("item = \"{}\"", level_name(item)),
        ];
        for t in 0..FILLER_TYPES {
            if rng.chance(30) {
                g.push(format!("filler{t} = \"read\""));
            }
        }
        for f in FIELDS {
            if rng.chance(20) {
                g.push(format!("\"item.{f}\" = \"read\""));
            }
        }
        if rng.chance(40) {
            g.push("\"item.@ai\" = \"write\"".to_owned());
        }
        if rng.chance(30) {
            g.push("\"item:approve\" = true".to_owned());
        }
        let _ = write!(
            s,
            "\n[roles.r{r}]\ngrants = {{ {} }}\nassignable_to = [\"user\", \"group\"]\n",
            g.join(", ")
        );
        if rng.chance(30) {
            let when = match rng.below(3) {
                0 => "{ eq = { field = \"status\", value = \"open\" } }",
                1 => "{ is_principal = \"owner_p\" }",
                _ => "{ not = { contains = { field = \"labels\", value = \"locked\" } } }",
            };
            let _ = write!(
                s,
                "\n[[conditions]]\nrole = \"r{r}\"\ntype = \"item\"\nwhen = {when}\nelse = \"read\"\n"
            );
        }
        if rng.chance(20) {
            let _ = write!(
                s,
                "\n[[field_rules]]\nfield = \"item.budget\"\nrole = \"r{r}\"\nmax = \"read\"\n"
            );
        }
    }
    s.push_str(
        "\n[roles.agent]\ngrants = { proj = \"read\", item = \"write\" }\n\n\
         [[conditions]]\nrole = \"agent\"\ntype = \"item\"\nwhen = { is_principal = \"owner_p\" }\nelse = \"read\"\n",
    );
    s
}

fn user(n: u32) -> Res<Principal> {
    Ok(format!("user:usr_0193a1b2-c3d4-7a11-8b22-{n:012x}").parse()?)
}

fn agent(n: u32) -> Res<Principal> {
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

struct World {
    pdp: Pdp,
    tree: Tree,
    items: Vec<ResourceRef>,
    /// Items below each project.
    by_proj: HashMap<PathEntry, Vec<usize>>,
    /// (agent, the users bound with it, its project).
    agent_teams: Vec<(Principal, Vec<Principal>, PathEntry)>,
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

    // The tree: departments, projects (some in deep chains), items.
    let mut paths: HashMap<PathEntry, Vec<PathEntry>> = HashMap::new();
    let mut depts = Vec::new();
    for d in 0..DEPTS {
        let e = entry("dept", &format!("d{d}"))?;
        paths.insert(e.clone(), vec![org.clone()]);
        depts.push(e);
    }
    let mut projects: Vec<PathEntry> = Vec::new();
    for p in 0..PROJECTS {
        let e = entry("proj", &format!("p{p}"))?;
        let parent = if p > 0 && rng.chance(60) {
            // Deep chains: the previous project, up to path length 30.
            let prev = &projects[if rng.chance(70) { p - 1 } else { rng.below(p) }];
            if paths.get(prev).is_some_and(|v| v.len() < 30) {
                prev.clone()
            } else {
                depts[rng.below(DEPTS)].clone()
            }
        } else {
            depts[rng.below(DEPTS)].clone()
        };
        let mut path = vec![parent.clone()];
        path.extend(paths.get(&parent).cloned().unwrap_or_default());
        paths.insert(e.clone(), path);
        projects.push(e);
    }
    let mut items = Vec::new();
    let mut by_proj: HashMap<PathEntry, Vec<usize>> = HashMap::new();
    for i in 0..ITEMS {
        let parent = projects[rng.below(PROJECTS)].clone();
        let mut path = vec![parent.clone()];
        path.extend(paths.get(&parent).cloned().unwrap_or_default());
        let mut attrs = Attrs::new();
        if rng.chance(70) {
            let s = if rng.chance(50) { "open" } else { "done" };
            attrs.insert(FieldName::parse("status")?, AttrValue::String(s.to_owned()));
        }
        if rng.chance(60) {
            let owner = if rng.chance(50) {
                agent(u32::try_from(rng.below(AGENTS as usize))?)?
            } else {
                user(u32::try_from(rng.below(USERS as usize))?)?
            };
            attrs.insert(
                FieldName::parse("owner_p")?,
                AttrValue::String(owner.to_string()),
            );
        }
        if rng.chance(50) {
            let l = if rng.chance(20) {
                vec!["locked".to_owned()]
            } else {
                vec![]
            };
            attrs.insert(FieldName::parse("labels")?, AttrValue::Strings(l));
        }
        by_proj.entry(parent).or_default().push(i);
        items.push(ResourceRef {
            type_name: ResourceType::parse("item")?,
            id: ResourceId::parse(&format!("i{i}"))?,
            path,
            attrs,
        });
    }

    // Groups nested 6 deep, users in them.
    let mut groups: Vec<Group> = (0..GROUPS)
        .map(|g| -> Res<Group> {
            Ok(Group {
                key: GroupKey::parse(&format!("g{g}"))?,
                members: Vec::new(),
            })
        })
        .collect::<Res<_>>()?;
    for g in 1..GROUPS {
        if g % 6 != 0 {
            let child = groups[g].key.clone();
            groups[g - 1].members.push(Member::Group(child));
        }
    }
    for u in 0..USERS {
        let g = rng.below(GROUPS);
        groups[g].members.push(Member::Principal(user(u)?));
    }

    // Bindings: users and groups at random scopes, agents with teams.
    let roles: Vec<String> = (0..ROLES).map(|r| format!("r{r}")).collect();
    let mut bindings = Vec::new();
    let mut taken = BTreeSet::new();
    let mut scopes: Vec<PathEntry> = depts.clone();
    scopes.extend(projects.iter().cloned());
    for i in 0..BINDINGS {
        let subject = if rng.chance(20) {
            Subject::Group(groups[rng.below(GROUPS)].key.clone())
        } else {
            Subject::Principal(user(u32::try_from(rng.below(USERS as usize))?)?)
        };
        let scope = if rng.chance(1) {
            org.clone()
        } else {
            scopes[rng.below(scopes.len())].clone()
        };
        if !taken.insert((subject.clone(), scope.clone())) {
            continue;
        }
        bindings.push(Binding {
            id: rule(&format!("ra_{i}"))?,
            subject,
            role: RoleKey::parse(&roles[rng.below(ROLES)])?,
            scope,
        });
    }
    let mut agent_teams = Vec::new();
    for a in 0..AGENTS {
        let ag = agent(a)?;
        let proj = projects[rng.below(PROJECTS)].clone();
        let mut team = Vec::new();
        for k in 0..3 {
            let u = user(u32::try_from(rng.below(USERS as usize))?)?;
            if taken.insert((Subject::Principal(u.clone()), proj.clone())) {
                bindings.push(Binding {
                    id: rule(&format!("ra_team_{a}_{k}"))?,
                    subject: Subject::Principal(u.clone()),
                    role: RoleKey::parse("member")?,
                    scope: proj.clone(),
                });
                team.push(u);
            }
        }
        bindings.push(Binding {
            id: rule(&format!("ra_agent_{a}"))?,
            subject: Subject::Principal(ag.clone()),
            role: RoleKey::parse("agent")?,
            scope: proj.clone(),
        });
        agent_teams.push((ag, team, proj));
    }
    let private_scopes = (0..PRIVATE)
        .map(|_| projects[rng.below(PROJECTS)].clone())
        .collect();
    let field_rules = (0..SCOPE_RULES)
        .map(|i| -> Res<ScopeFieldRule> {
            Ok(ScopeFieldRule {
                id: rule(&format!("fr_{i}"))?,
                scope: projects[i % PROJECTS].clone(),
                field: FieldKey::parse(&format!("item.{}", FIELDS[i % FIELDS.len()]))?,
                role: Some(RoleKey::parse(&roles[i % ROLES])?),
                max: Level::Read,
            })
        })
        .collect::<Res<_>>()?;
    let data = TenantData {
        orgs: [org_id].into(),
        bindings,
        groups,
        private_scopes,
        field_rules,
    };
    let mut pdp = Pdp::new();
    pdp.load(tenant.clone(), 1, model, data)?;
    println!("built the tenant in {:.2?}", started.elapsed());
    Ok(World {
        pdp,
        tree: Tree { tenant, paths },
        items,
        by_proj,
        agent_teams,
    })
}

fn report(name: &str, mut ns: Vec<u128>, allowed: Option<usize>) {
    ns.sort_unstable();
    let at = |q: f64| {
        let i = ((ns.len() as f64) * q) as usize;
        ns.get(i.min(ns.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0)
    };
    let allowed = allowed.map_or_else(
        || "     -".to_owned(),
        |a| format!("{:>5.1}%", 100.0 * a as f64 / ns.len().max(1) as f64),
    );
    println!(
        "{name:<28} n={:>7} allowed={allowed}  p50={:>7.1}us  p99={:>7.1}us  p99.9={:>7.1}us  max={:>8.1}us",
        ns.len(),
        at(0.50) as f64 / 1000.0,
        at(0.99) as f64 / 1000.0,
        at(0.999) as f64 / 1000.0,
        ns.last().copied().unwrap_or(0) as f64 / 1000.0,
    );
}

fn check_req(
    w: &World,
    subject: Principal,
    actors: Vec<Principal>,
    act: &str,
    item: usize,
) -> Res<CheckRequest> {
    let resource = w.items.get(item).cloned().ok_or("no such item")?;
    Ok(CheckRequest {
        tenant: w.tree.tenant.clone(),
        subject,
        actors,
        action: ActionKey::parse(act)?,
        resource,
        fields: None,
        at_least_revision: None,
    })
}

fn time_checks(w: &World, name: &str, reqs: &[CheckRequest]) -> Res<()> {
    let mut ns = Vec::with_capacity(reqs.len());
    let mut allowed = 0;
    for r in reqs {
        let t = Instant::now();
        let d = black_box(w.pdp.check(black_box(r)))?;
        ns.push(t.elapsed().as_nanos());
        if d.is_allowed() {
            allowed += 1;
        }
    }
    report(name, ns, Some(allowed));
    Ok(())
}

fn main() -> Res<()> {
    let w = build()?;
    let mut rng = Rng(42);
    let actions = ["item:read", "item:write", "item:approve", "item:export"];

    // W1: random users, random items, random actions (mostly denies).
    let mut mixed = Vec::with_capacity(CHECKS);
    for _ in 0..CHECKS {
        let u = user(u32::try_from(rng.below(USERS as usize))?)?;
        mixed.push(check_req(
            &w,
            u,
            vec![],
            actions[rng.below(4)],
            rng.below(ITEMS),
        )?);
    }
    time_checks(&w, "check, mixed", &mixed)?;

    // W2: allowed calls only.
    let allowed: Vec<CheckRequest> = mixed
        .into_iter()
        .filter(|r| w.pdp.check(r).is_ok_and(|d| d.is_allowed()))
        .collect();
    let mut many = Vec::with_capacity(CHECKS);
    while many.len() < CHECKS && !allowed.is_empty() {
        many.extend(allowed.iter().take(CHECKS - many.len()).cloned());
    }
    time_checks(&w, "check, allowed only", &many)?;

    // W3: allowed delegated calls: a user and an agent bound at the same
    // project, on items below it.
    let mut delegated = Vec::new();
    for (ag, team, proj) in &w.agent_teams {
        for u in team {
            for &i in w.by_proj.get(proj).into_iter().flatten() {
                for act in ["item:read", "item:write"] {
                    let r = check_req(&w, u.clone(), vec![ag.clone()], act, i)?;
                    if w.pdp.check(&r).is_ok_and(|d| d.is_allowed()) {
                        delegated.push(r);
                    }
                }
            }
        }
    }
    let base = delegated.clone();
    while delegated.len() < CHECKS && !base.is_empty() {
        delegated.extend(base.iter().take(CHECKS - delegated.len()).cloned());
    }
    time_checks(&w, "check, delegated allowed", &delegated)?;

    // write_check of two fields on allowed delegated writes.
    let mut writes = Vec::new();
    for r in base
        .iter()
        .filter(|r| r.action.action().as_str() == "write")
    {
        let mut new_attrs = Attrs::new();
        new_attrs.insert(FieldName::parse("notes")?, AttrValue::String("n".into()));
        new_attrs.insert(FieldName::parse("title")?, AttrValue::String("t".into()));
        writes.push(WriteCheckRequest {
            tenant: r.tenant.clone(),
            subject: r.subject.clone(),
            actors: r.actors.clone(),
            resource: r.resource.clone(),
            new_attrs,
            new_path: None,
            at_least_revision: None,
        });
    }
    let mut ns = Vec::new();
    let mut ok = 0;
    for _ in 0..(CHECKS / writes.len().max(1)).max(1) {
        for r in &writes {
            let t = Instant::now();
            let d = black_box(w.pdp.write_check(black_box(r)))?;
            ns.push(t.elapsed().as_nanos());
            if d.effect == tutela_contracts::decision::Effect::Allow {
                ok += 1;
            }
        }
    }
    report("write_check, delegated", ns, Some(ok));

    // W4: list filters for random users, and for users with their agent.
    let mut largest = (0, 0, 0);
    let mut sizes: BTreeMap<&str, Vec<u128>> = BTreeMap::new();
    for k in 0..LISTS {
        let (subject, actors, name) = if k % 2 == 0 {
            (
                user(u32::try_from(rng.below(USERS as usize))?)?,
                vec![],
                "list_filter",
            )
        } else {
            let (ag, team, _) = &w.agent_teams[rng.below(w.agent_teams.len())];
            let u = team.first().cloned().unwrap_or(user(0)?);
            (u, vec![ag.clone()], "list_filter, delegated")
        };
        let req = ListFilterRequest {
            tenant: w.tree.tenant.clone(),
            subject,
            actors,
            action: ActionKey::parse(actions[k % 2])?,
            at_least_revision: None,
        };
        let t = Instant::now();
        let f = black_box(w.pdp.list_filter(black_box(&req), &w.tree))?;
        sizes.entry(name).or_default().push(t.elapsed().as_nanos());
        let s = f.size();
        largest = (
            largest.0.max(s.nodes),
            largest.1.max(s.depth),
            largest.2.max(s.entries),
        );
    }
    for (name, ns) in sizes {
        report(name, ns, None);
    }
    println!(
        "largest list filter seen: {} condition nodes, depth {}, {} entries (each the max over all filters)",
        largest.0, largest.1, largest.2
    );
    Ok(())
}
