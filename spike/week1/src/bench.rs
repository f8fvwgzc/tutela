//! Question 1: `check` latency (docs/SPIKE-WEEK1.md §4). THROWAWAY.

use crate::eval::{CheckRequest, ResourceRef};
use crate::models;
use crate::model::*;
use crate::pg::stats;
use crate::rng::Rng;
use crate::tree::ScopePaths;
use std::hint::black_box;
use std::time::Instant;

const WARMUP: usize = 100_000;
const MEASURED: usize = 1_000_000;

pub fn run(seed: u64) {
    let t = Instant::now();
    let w = models::big(seed);
    println!("model: generated and compiled in {:.1}s", t.elapsed().as_secs_f64());
    let m = &w.model;
    println!(
        "model: types={} roles={} field_rules={} bindings={} conditions={} users={} agents={} groups={} nodes={} private={}",
        m.types.len(),
        m.roles.len(),
        m.rules.len(),
        w.assignments.len(),
        m.conds.len(),
        w.users,
        w.agents,
        w.group_parents.len(),
        w.tree.len(),
        w.private.len()
    );
    let max_groups = m.user_groups.iter().map(Vec::len).max().unwrap_or(0);
    let avg_groups = m.user_groups.iter().map(Vec::len).sum::<usize>() as f64 / m.user_groups.len() as f64;
    let everyone = w.user_direct_groups.iter().filter(|g| g.contains(&0)).count();
    println!(
        "groups: levels={} transitive groups per user avg={avg_groups:.1} max={max_groups}; direct members of group 0 = {everyone}",
        w.group_level.iter().max().map_or(0, |l| l + 1)
    );

    let mut users: Vec<u32> = w
        .assignments
        .iter()
        .filter_map(|a| if let Subject::User(u) = a.1 { Some(u) } else { None })
        .collect();
    users.sort_unstable();
    users.dedup();
    let mut agents: Vec<u32> = w
        .assignments
        .iter()
        .filter_map(|a| if let Subject::Agent(x) = a.1 { Some(x) } else { None })
        .collect();
    agents.sort_unstable();
    agents.dedup();
    let all: Vec<NodeId> = (1..w.tree.len() as NodeId).collect();
    let deep: Vec<NodeId> = all.iter().copied().filter(|&n| w.tree.depth(n) == 32).collect();
    let max_depth = all.iter().map(|&n| w.tree.depth(n)).max().unwrap_or(0);
    println!(
        "workload inputs: users with a binding={} agents with a binding={} resources={} deep(32)={} max path={max_depth}",
        users.len(),
        agents.len(),
        all.len(),
        deep.len()
    );

    // Info only, added after the gated run (not in docs/SPIKE-WEEK1.md): W4
    // uses the users bound at the org root, so most calls are allowed and
    // build a full field mask. Every workload also reports allowed calls alone.
    let org_users: Vec<u32> = w
        .assignments
        .iter()
        .filter_map(|a| match a.1 {
            Subject::User(u) if a.2 == m.org => Some(u),
            _ => None,
        })
        .collect();
    for (name, pool, delegated, who) in [
        ("W1 mixed", &all, false, &users),
        ("W2 deep", &deep, false, &users),
        ("W3 delegated", &all, true, &users),
        ("W4 org-root users (info)", &all, false, &org_users),
    ] {
        let mut rng = Rng::new(seed ^ name.len() as u64 ^ 0xC0FFEE);
        let samples: Vec<(Principal, Option<Principal>, NodeId, Action)> = (0..WARMUP + MEASURED)
            .map(|_| {
                let p = Principal::User(rng.pick(who));
                let a = if delegated { Some(Principal::Agent(rng.pick(&agents))) } else { None };
                (p, a, rng.pick(pool), rng.pick(&Action::ALL))
            })
            .collect();
        let mut ns = Vec::with_capacity(MEASURED);
        let mut ns_allowed = Vec::new();
        let mut allowed = 0usize;
        let mut fields_read = 0usize;
        let t_all = Instant::now();
        for (i, &(p, a, n, action)) in samples.iter().enumerate() {
            let actors_buf = [a.unwrap_or(p)];
            let actors: &[Principal] = if a.is_some() { &actors_buf } else { &[] };
            let req = CheckRequest {
                subject: p,
                actors,
                action,
                resource: ResourceRef {
                    id: n,
                    ty: w.tree.ty(n),
                    path: w.tree.ancestors(n),
                    attrs: &w.tree.attrs[n as usize],
                },
                fields: None,
            };
            let t = Instant::now();
            let d = m.check(&req);
            let e = t.elapsed();
            let d = black_box(d);
            if i >= WARMUP {
                ns.push(e.as_nanos() as u64);
                if let Ok(d) = d {
                    if d.allow {
                        allowed += 1;
                        ns_allowed.push(e.as_nanos() as u64);
                    }
                    fields_read += d.read.len();
                }
            }
        }
        println!(
            "{name}: {}  (allowed {:.1}%, avg readable fields {:.1}, wall {:.1}s)",
            stats(ns),
            allowed as f64 * 100.0 / MEASURED as f64,
            fields_read as f64 / MEASURED as f64,
            t_all.elapsed().as_secs_f64()
        );
        println!("{name}, allowed calls only (info): {}", stats(ns_allowed));
    }

    // Information only: one list_filter call on this model.
    let mut rng = Rng::new(seed ^ 0xF117);
    let mut ns = Vec::new();
    let mut sizes = (0usize, 0usize, 0usize);
    for i in 0..1_100 {
        let p = Principal::User(rng.pick(&users));
        let ty = rng.pick(&w.leaf_types);
        let t = Instant::now();
        let f = m.list_filter(p, &[], ty, Action::Read, &w.tree);
        let e = t.elapsed();
        if i >= 100 {
            ns.push(e.as_nanos() as u64);
            let (nodes, _) = f.condition.as_ref().map_or((0, 0), |c| c.size());
            sizes.0 = sizes.0.max(nodes);
            sizes.1 = sizes.1.max(f.container_in.len());
            sizes.2 = sizes.2.max(f.ids_in.len());
        }
        black_box(f);
    }
    println!(
        "list_filter (info): {}  max AST nodes={} max container_in={} max ids_in={}",
        stats(ns),
        sizes.0,
        sizes.1,
        sizes.2
    );
}
