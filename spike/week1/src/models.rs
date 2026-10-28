//! Model generators: the fixed big model (docs/SPIKE-WEEK1.md §4.1) and the
//! random models (§6.1). Deterministic per seed. THROWAWAY.

use crate::model::*;
use crate::rng::Rng;
use crate::tree::{Tree, NO_PARENT};
use rustc_hash::FxHashSet;

pub struct World {
    pub model: Model,
    pub tree: Tree,
    pub users: u32,
    pub agents: u32,
    pub container_types: Vec<TypeId>,
    pub leaf_types: Vec<TypeId>,
    /// Per group: its nesting level (0 = top).
    pub group_level: Vec<u8>,
    pub group_parents: Vec<Vec<u32>>,
    pub user_direct_groups: Vec<Vec<u32>>,
    /// Kept for the Postgres load.
    pub assignments: Vec<(u32, Subject, NodeId, RoleId)>,
    pub private: Vec<NodeId>,
}

fn rand_level(rng: &mut Rng, w: [u32; 4]) -> Level {
    let total: u32 = w.iter().sum();
    let mut x = rng.below(total as u64) as u32;
    for (i, wi) in w.iter().enumerate() {
        if x < *wi {
            return Level::ALL[i];
        }
        x -= wi;
    }
    Level::Full
}

fn rand_attrs(rng: &mut Rng, users: u32, agents: u32, null_p: f64) -> Attrs {
    Attrs {
        assignee: if rng.chance(null_p * 2.0) {
            None
        } else if rng.chance(0.2) {
            Some(Principal::Agent(rng.below(agents as u64) as u32))
        } else {
            Some(Principal::User(rng.below(users as u64) as u32))
        },
        status: if rng.chance(null_p) { None } else { Some(rng.below(3) as u8) },
        labels: if rng.chance(null_p) { None } else { Some(rng.below(16) as u8) },
        priority: if rng.chance(null_p) { None } else { Some(rng.below(6) as i64) },
        flag: if rng.chance(null_p) { None } else { Some(rng.chance(0.5)) },
    }
}

fn rand_tpl(rng: &mut Rng, groups: u32, depth: u32) -> Tpl {
    let k = if depth >= 2 { rng.below(7) } else { rng.below(10) };
    match k {
        0 => Tpl::StatusEq(rng.below(3) as u8),
        1 => Tpl::StatusIn(vec![rng.below(3) as u8, rng.below(3) as u8]),
        2 => Tpl::PriorityEq(rng.below(6) as i64),
        3 => Tpl::FlagEq(rng.chance(0.5)),
        4 => Tpl::LabelsContain(rng.below(4) as u8),
        5 => Tpl::AssigneeIsPrincipal,
        6 => {
            if groups == 0 {
                Tpl::AssigneeIsPrincipal
            } else {
                Tpl::InGroup(rng.below(groups as u64) as u32)
            }
        }
        7 => Tpl::And(vec![rand_tpl(rng, groups, depth + 1), rand_tpl(rng, groups, depth + 1)]),
        8 => Tpl::Or(vec![rand_tpl(rng, groups, depth + 1), rand_tpl(rng, groups, depth + 1)]),
        _ => Tpl::Not(Box::new(rand_tpl(rng, groups, depth + 1))),
    }
}

fn field_names(n_fields: usize) -> Vec<String> {
    let mut v = vec!["@ai".to_string(), "@chat".to_string(), "@files".to_string()];
    for i in 0..n_fields {
        v.push(format!("f{i:02}"));
    }
    v
}

/// Groups in `levels` levels; each group below the top is in 1 or 2 groups
/// of the level above.
fn rand_groups(rng: &mut Rng, sizes: &[u32]) -> (Vec<Vec<u32>>, Vec<u8>) {
    let mut parents = Vec::new();
    let mut level = Vec::new();
    let mut prev: Vec<u32> = Vec::new();
    for (l, &n) in sizes.iter().enumerate() {
        let mut cur = Vec::new();
        for _ in 0..n {
            let g = parents.len() as u32;
            let mut ps = Vec::new();
            if !prev.is_empty() {
                ps.push(rng.pick(&prev));
                if rng.chance(0.5) {
                    let q = rng.pick(&prev);
                    if !ps.contains(&q) {
                        ps.push(q);
                    }
                }
            }
            parents.push(ps);
            level.push(l as u8);
            cur.push(g);
        }
        prev = cur;
    }
    (parents, level)
}

/// The fixed model of docs/SPIKE-WEEK1.md §4.1.
pub fn big(seed: u64) -> World {
    let mut rng = Rng::new(seed);
    let users = 10_000u32;
    let agents = 100u32;
    let n_fields = 20usize;

    // Types: 0 = org, 1..=62 containers (tier = (t-1)/2 + 1), 63..=199 leaves.
    let mut types = vec![TypeDef { name: "org".into(), fields: field_names(n_fields) }];
    let container_types: Vec<TypeId> = (1..=62).collect();
    let leaf_types: Vec<TypeId> = (63..200).collect();
    for t in 1..200u16 {
        types.push(TypeDef { name: format!("t{t:03}"), fields: field_names(n_fields) });
    }
    let nf = types[0].fields.len(); // 23: 3 features first, then f00..f19
    // Field index k: features 0..3, fields 3..23. Sensitivity of field i
    // (0-based among the 20): 0..3 public, 3..17 internal, 17..19
    // confidential, 19 secret.
    let confidential: Vec<u16> = (3 + 17..3 + 20).map(|k| k as u16).collect();

    // Tree: org, 20,000 containers at depth 1..=31 (even per depth), 200,000
    // items with path length 1..=32.
    let mut tree = Tree::new();
    let org = tree.add(NO_PARENT, 0, rand_attrs(&mut rng, users, agents, 0.1));
    let mut by_depth: Vec<Vec<NodeId>> = vec![vec![org]];
    let per_depth = 20_000 / 31;
    for d in 1..=31usize {
        let count = if d == 31 { 20_000 - per_depth * 30 } else { per_depth };
        let mut cur = Vec::with_capacity(count);
        for _ in 0..count {
            let parent = rng.pick(&by_depth[d - 1]);
            let ty = (2 * (d - 1) + 1 + rng.below(2) as usize) as TypeId;
            cur.push(tree.add(parent, ty, rand_attrs(&mut rng, users, agents, 0.1)));
        }
        by_depth.push(cur);
    }
    let containers: Vec<NodeId> = by_depth[1..].iter().flatten().copied().collect();
    for _ in 0..200_000 {
        let len = rng.range(1, 32) as usize;
        let parent = rng.pick(&by_depth[len - 1]);
        let ty = rng.pick(&leaf_types);
        tree.add(parent, ty, rand_attrs(&mut rng, users, agents, 0.1));
    }
    let items: Vec<NodeId> = (containers.len() as u32 + 1..tree.len() as u32).collect();
    let private: Vec<NodeId> = containers.iter().copied().filter(|_| rng.chance(0.1)).collect();

    // Roles: 0 = Owner.
    let mut roles = Vec::new();
    for r in 0..100 {
        let mut type_level = Vec::new();
        let mut field_level = Vec::new();
        let mut grants = Vec::new();
        for _ in 0..types.len() {
            if r == 0 {
                type_level.push(Level::Full);
                field_level.push(vec![None; nf]);
                grants.push(0b11);
                continue;
            }
            let tl = rand_level(&mut rng, [20, 35, 30, 15]);
            type_level.push(tl);
            field_level.push(
                (0..nf)
                    .map(|_| if rng.chance(0.1) { Some(rand_level(&mut rng, [1, 1, 1, 1]).min(tl)) } else { None })
                    .collect(),
            );
            let mut g = 0u8;
            if rng.chance(0.3) {
                g |= 1;
            }
            if rng.chance(0.3) {
                g |= 2;
            }
            grants.push(g);
        }
        roles.push(Role { type_level, field_level, grants });
    }

    // Field rules: 600 org-root "all roles -> None" + 4,400 random.
    let mut rules = Vec::new();
    for t in 0..200u16 {
        for &f in &confidential {
            rules.push(FieldRule { id: rules.len() as u32, scope: org, ty: t, field: f, role: None, max: Level::None });
        }
    }
    let mut seen = FxHashSet::default();
    while rules.len() < 5_000 {
        let scope = rng.pick(&containers);
        let ty = if rng.chance(0.8) { rng.pick(&leaf_types) } else { rng.pick(&container_types) };
        let field = rng.below(nf as u64) as u16;
        let role = if rng.chance(0.5) { None } else { Some(rng.below(100) as RoleId) };
        if !seen.insert((scope, ty, field, role)) {
            continue;
        }
        rules.push(FieldRule { id: rules.len() as u32, scope, ty, field, role, max: rand_level(&mut rng, [1, 1, 1, 1]) });
    }

    // Groups: 500 in 8 levels; group 0 (top level) is "everyone".
    let (group_parents, group_level) = rand_groups(&mut rng, &[10, 70, 70, 70, 70, 70, 70, 70]);
    let deepest: Vec<u32> = (0..500u32).filter(|&g| group_level[g as usize] == 7).collect();
    let mut user_direct_groups = Vec::new();
    for _ in 0..users {
        let mut gs = vec![0u32];
        for _ in 0..rng.range(1, 3) {
            let g = if rng.chance(0.7) { rng.pick(&deepest) } else { rng.below(500) as u32 };
            if !gs.contains(&g) {
                gs.push(g);
            }
        }
        user_direct_groups.push(gs);
    }

    // 10,000 bindings.
    let mut assignments = Vec::new();
    let mut taken = FxHashSet::default();
    let mut add = |rng: &mut Rng, assignments: &mut Vec<(u32, Subject, NodeId, RoleId)>, s: Subject, n: NodeId, r: RoleId| {
        if taken.insert((s, n)) {
            assignments.push((assignments.len() as u32, s, n, r));
            let _ = rng;
            true
        } else {
            false
        }
    };
    let mut i = 0;
    while i < 300 {
        let u = Subject::User(rng.below(users as u64) as u32);
        let role = if i < 10 { OWNER } else { rng.range(1, 99) as RoleId };
        if add(&mut rng, &mut assignments, u, org, role) {
            i += 1;
        }
    }
    let node = |rng: &mut Rng| if rng.chance(0.9) { rng.pick(&containers) } else { rng.pick(&items) };
    let mut i = 0;
    while i < 7_700 {
        let s = Subject::User(rng.below(users as u64) as u32);
        let n = node(&mut rng);
        let role = if rng.chance(0.05) { OWNER } else { rng.range(1, 99) as RoleId };
        if add(&mut rng, &mut assignments, s, n, role) {
            i += 1;
        }
    }
    let mut i = 0;
    while i < 1_500 {
        let s = Subject::Group(rng.below(500) as u32);
        let n = node(&mut rng);
        let role = if rng.chance(0.05) { OWNER } else { rng.range(1, 99) as RoleId };
        if add(&mut rng, &mut assignments, s, n, role) {
            i += 1;
        }
    }
    let mut i = 0;
    while i < 500 {
        let s = Subject::Agent(rng.below(agents as u64) as u32);
        let n = node(&mut rng);
        let role = rng.range(1, 99) as RoleId;
        if add(&mut rng, &mut assignments, s, n, role) {
            i += 1;
        }
    }

    // 200 conditions.
    let mut conds = Vec::new();
    for id in 0..200u32 {
        let scope = if rng.chance(0.1) { org } else { rng.pick(&containers) };
        let ty = if rng.chance(0.8) { rng.pick(&leaf_types) } else { rng.pick(&container_types) };
        conds.push(Condition {
            id,
            role: rng.range(1, 99) as RoleId,
            ty,
            scope,
            tpl: rand_tpl(&mut rng, 500, 0),
            lif: rand_level(&mut rng, [2, 1, 1, 0]),
        });
    }

    finish(tree, types, roles, assignments, group_parents, group_level, user_direct_groups, private, rules, conds, org, users, agents, container_types, leaf_types)
}

#[allow(clippy::too_many_arguments)]
fn finish(
    tree: Tree,
    types: Vec<TypeDef>,
    roles: Vec<Role>,
    assignments: Vec<(u32, Subject, NodeId, RoleId)>,
    group_parents: Vec<Vec<u32>>,
    group_level: Vec<u8>,
    user_direct_groups: Vec<Vec<u32>>,
    private: Vec<NodeId>,
    rules: Vec<FieldRule>,
    conds: Vec<Condition>,
    org: NodeId,
    users: u32,
    agents: u32,
    container_types: Vec<TypeId>,
    leaf_types: Vec<TypeId>,
) -> World {
    let model = Model::compile(ModelInput {
        types,
        roles,
        assignments: assignments.iter().map(|&(id, subject, scope, role)| Assignment { id, subject, scope, role }).collect(),
        group_parents: group_parents.clone(),
        user_groups: user_direct_groups.clone(),
        private: private.clone(),
        rules,
        conds,
        org,
    });
    World {
        model,
        tree,
        users,
        agents,
        container_types,
        leaf_types,
        group_level,
        group_parents,
        user_direct_groups,
        assignments,
        private,
    }
}

/// One random model of docs/SPIKE-WEEK1.md §6.1.
pub fn random(seed: u64) -> World {
    let mut rng = Rng::new(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
    let users = 30u32;
    let agents = 5u32;
    let k = rng.range(2, 6) as u16;
    let container_types: Vec<TypeId> = (1..=k).collect();
    let leaf: TypeId = k + 1;
    let mut types = vec![TypeDef { name: "org".into(), fields: field_names(2) }];
    for t in 1..=leaf {
        types.push(TypeDef { name: format!("t{t}"), fields: field_names(2) });
    }
    let nf = types[0].fields.len();
    let null_p = [0.0, 0.1, 0.3][rng.below(3) as usize];

    let mut tree = Tree::new();
    let org = tree.add(NO_PARENT, 0, rand_attrs(&mut rng, users, agents, null_p));
    let n_c = rng.range(1_000, 5_000) as usize;
    let mut containers: Vec<NodeId> = Vec::new();
    // One chain to depth 31.
    let mut p = org;
    for _ in 0..31 {
        p = tree.add(p, rng.pick(&container_types), rand_attrs(&mut rng, users, agents, null_p));
        containers.push(p);
    }
    while containers.len() < n_c {
        let mut parent = if rng.chance(0.1) { org } else { rng.pick(&containers) };
        while parent != org && tree_depth(&tree, parent) >= 31 {
            parent = tree.parent[parent as usize];
        }
        let c = tree.add(parent, rng.pick(&container_types), rand_attrs(&mut rng, users, agents, null_p));
        containers.push(c);
    }
    let mut parents_for_rows = containers.clone();
    parents_for_rows.push(org);
    let first_row = tree.len() as NodeId;
    for _ in 0..100_000 {
        let parent = rng.pick(&parents_for_rows);
        tree.add(parent, leaf, rand_attrs(&mut rng, users, agents, null_p));
    }
    let rows: Vec<NodeId> = (first_row..tree.len() as NodeId).collect();
    let priv_p = rng.range(0, 40) as f64 / 100.0;
    let private: Vec<NodeId> = containers.iter().copied().filter(|_| rng.chance(priv_p)).collect();

    let n_roles = rng.range(3, 12) as usize;
    let mut roles = Vec::new();
    for r in 0..n_roles {
        let mut type_level = Vec::new();
        let mut field_level = Vec::new();
        let mut grants = Vec::new();
        for _ in 0..types.len() {
            if r == 0 {
                type_level.push(Level::Full);
                grants.push(0b11);
            } else {
                type_level.push(rand_level(&mut rng, [1, 2, 2, 1]));
                grants.push(rng.below(4) as u8);
            }
            field_level.push(vec![None; nf]);
        }
        roles.push(Role { type_level, field_level, grants });
    }

    let n_groups = rng.range(0, 40) as u32;
    let (group_parents, group_level) = if n_groups == 0 {
        (Vec::new(), Vec::new())
    } else {
        let levels = rng.range(1, 8).min(n_groups as u64) as u32;
        let mut sizes = vec![n_groups / levels; levels as usize];
        sizes[0] += n_groups % levels;
        rand_groups(&mut rng, &sizes)
    };
    let user_direct_groups: Vec<Vec<u32>> = (0..users)
        .map(|_| {
            let mut gs = Vec::new();
            if n_groups > 0 {
                for _ in 0..rng.below(4) {
                    let g = rng.below(n_groups as u64) as u32;
                    if !gs.contains(&g) {
                        gs.push(g);
                    }
                }
            }
            gs
        })
        .collect();

    let m = rng.range(100, 3_000) as usize;
    let mut assignments: Vec<(u32, Subject, NodeId, RoleId)> = Vec::new();
    let mut taken = FxHashSet::default();
    if rng.chance(0.3) {
        let u = Subject::User(rng.below(users as u64) as u32);
        taken.insert((u, org));
        assignments.push((0, u, org, OWNER));
    }
    let mut tries = 0;
    while assignments.len() < m && tries < m * 10 {
        tries += 1;
        let x = rng.below(100);
        let s = if x < 60 || n_groups == 0 && x < 85 {
            Subject::User(rng.below(users as u64) as u32)
        } else if x < 85 {
            Subject::Group(rng.below(n_groups as u64) as u32)
        } else {
            Subject::Agent(rng.below(agents as u64) as u32)
        };
        let y = rng.below(100);
        let n = if y < 3 {
            org
        } else if y < 85 {
            rng.pick(&containers)
        } else {
            rng.pick(&rows)
        };
        let mut role = rng.below(n_roles as u64) as RoleId;
        if matches!(s, Subject::Agent(_)) && role == OWNER {
            role = 1;
        }
        if taken.insert((s, n)) {
            assignments.push((assignments.len() as u32, s, n, role));
        }
    }

    let q = rng.range(0, 30) as u32;
    let mut conds = Vec::new();
    for id in 0..q {
        let y = rng.below(100);
        let scope = if y < 20 {
            org
        } else if y < 95 {
            rng.pick(&containers)
        } else {
            rng.pick(&rows)
        };
        let ty = if rng.chance(0.6) { leaf } else { rng.pick(&container_types) };
        conds.push(Condition {
            id,
            role: rng.below(n_roles as u64) as RoleId,
            ty,
            scope,
            tpl: rand_tpl(&mut rng, n_groups, 0),
            lif: rand_level(&mut rng, [2, 1, 1, 0]),
        });
    }

    finish(
        tree,
        types,
        roles,
        assignments,
        group_parents,
        group_level,
        user_direct_groups,
        private,
        Vec::new(),
        conds,
        org,
        users,
        agents,
        container_types,
        vec![leaf],
    )
}

fn tree_depth(tree: &Tree, n: NodeId) -> usize {
    tree.depth(n)
}
