//! Question 3: list_filter == check on 100k rows (docs/SPIKE-WEEK1.md §6).
//! THROWAWAY.

use crate::eval::{CheckRequest, ResourceRef, Why};
use crate::filter::{to_sql, Ancestors, ListFilter, Param, Prepared, Row};
use crate::models::{self, World};
use crate::model::*;
use crate::pg::{array, boxed, opt, refs, stats};
use crate::rng::Rng;
use crate::tree::ScopePaths;
use postgres::Client;
use std::io::Write;
use std::time::Instant;

#[derive(Default, Clone, Debug)]
pub struct Coverage {
    pub checks: u64,
    pub allowed: u64,
    pub path32: u64,
    pub private_in_private_rows: u64,
    pub private_stop: u64,
    pub closer_lower: u64,
    pub via_group: u64,
    pub direct_over_group: u64,
    pub cond_true: u64,
    pub cond_false: u64,
    pub cond_with_null_attr: u64,
    pub row_itself: u64,
    pub overlap_deny: u64,
    pub org_owner: u64,
    pub filters: u64,
    pub alternation: u64,
    pub max_ast_nodes: usize,
    pub max_ast_depth: usize,
    pub max_ids_in: usize,
    pub max_container_in: usize,
}

impl Coverage {
    fn add(&mut self, o: &Coverage) {
        self.checks += o.checks;
        self.allowed += o.allowed;
        self.path32 += o.path32;
        self.private_in_private_rows += o.private_in_private_rows;
        self.private_stop += o.private_stop;
        self.closer_lower += o.closer_lower;
        self.via_group += o.via_group;
        self.direct_over_group += o.direct_over_group;
        self.cond_true += o.cond_true;
        self.cond_false += o.cond_false;
        self.cond_with_null_attr += o.cond_with_null_attr;
        self.row_itself += o.row_itself;
        self.overlap_deny += o.overlap_deny;
        self.org_owner += o.org_owner;
        self.filters += o.filters;
        self.alternation += o.alternation;
        self.max_ast_nodes = self.max_ast_nodes.max(o.max_ast_nodes);
        self.max_ast_depth = self.max_ast_depth.max(o.max_ast_depth);
        self.max_ids_in = self.max_ids_in.max(o.max_ids_in);
        self.max_container_in = self.max_container_in.max(o.max_container_in);
    }
}

struct Task {
    subject: Principal,
    actors: Vec<Principal>,
    ty: TypeId,
    action: Action,
}

struct Done {
    filter: ListFilter,
    expected: Vec<NodeId>,
    ast_mismatch: Vec<NodeId>,
    cov: Coverage,
}

fn load(c: &mut Client, seeds: &[u64]) -> Result<(), Box<dyn std::error::Error>> {
    c.batch_execute(
        "CREATE EXTENSION IF NOT EXISTS btree_gin;
         DROP TABLE IF EXISTS item, item_ancestor;
         CREATE TABLE item (tenant_id bigint NOT NULL, id bigint NOT NULL, type bigint NOT NULL, parent_id bigint,
             ancestors bigint[] NOT NULL, assignee text, status text, labels text[], priority bigint, flag boolean,
             PRIMARY KEY (tenant_id, id));
         CREATE TABLE item_ancestor (tenant_id bigint NOT NULL, item_id bigint NOT NULL, ancestor_id bigint NOT NULL,
             PRIMARY KEY (tenant_id, item_id, ancestor_id));",
    )?;
    for &seed in seeds {
        let t = Instant::now();
        let w = models::random(seed);
        let mut wr = c.copy_in(
            "COPY item (tenant_id, id, type, parent_id, ancestors, assignee, status, labels, priority, flag) FROM STDIN",
        )?;
        for n in 0..w.tree.len() as u32 {
            let a = &w.tree.attrs[n as usize];
            let p = w.tree.parent[n as usize];
            let labels = a.labels.map(|m| array(LABELS.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|x| x.1)));
            writeln!(
                wr,
                "{seed}\t{n}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                w.tree.ty(n),
                if p == u32::MAX { "\\N".into() } else { p.to_string() },
                array(w.tree.ancestors(n)),
                opt(a.assignee.map(|p| p.text())),
                opt(a.status.map(|s| STATUS[s as usize])),
                opt(labels),
                opt(a.priority),
                opt(a.flag.map(|b| if b { "t" } else { "f" })),
            )?;
        }
        wr.finish()?;
        if seed == 1 {
            let mut wr = c.copy_in("COPY item_ancestor (tenant_id, item_id, ancestor_id) FROM STDIN")?;
            for n in 0..w.tree.len() as u32 {
                for a in w.tree.ancestors(n) {
                    writeln!(wr, "{seed}\t{n}\t{a}")?;
                }
            }
            wr.finish()?;
        }
        println!("loaded seed {seed}: {} rows in {:.1}s", w.tree.len(), t.elapsed().as_secs_f64());
    }
    let t = Instant::now();
    c.batch_execute(
        "CREATE INDEX item_anc ON item USING gin (tenant_id, ancestors);
         CREATE INDEX item_type ON item (tenant_id, type);
         CREATE INDEX item_anc_rev ON item_ancestor (tenant_id, ancestor_id, item_id);",
    )?;
    c.batch_execute("VACUUM ANALYZE item")?;
    c.batch_execute("VACUUM ANALYZE item_ancestor")?;
    println!("indexes in {:.1}s", t.elapsed().as_secs_f64());
    Ok(())
}

fn subjects(w: &World, rng: &mut Rng) -> Vec<(Principal, Vec<Principal>)> {
    let mut users: Vec<u32> = (0..w.users).collect();
    for i in (1..users.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        users.swap(i, j);
    }
    // Put an org Owner first, if there is one.
    if let Some(&(_, Subject::User(u), _, OWNER)) = w.assignments.iter().find(|a| a.2 == w.model.org && a.3 == OWNER) {
        users.retain(|&x| x != u);
        users.insert(0, u);
    }
    let mut out: Vec<(Principal, Vec<Principal>)> = users[..16].iter().map(|&u| (Principal::User(u), vec![])).collect();
    for _ in 0..4 {
        let u = rng.below(w.users as u64) as u32;
        let a = rng.below(w.agents as u64) as u32;
        out.push((Principal::User(u), vec![Principal::Agent(a)]));
    }
    out
}

fn run_task(w: &World, rows: &[NodeId], t: &Task) -> Done {
    let m = &w.model;
    let mut cov = Coverage::default();
    let filter = m.list_filter(t.subject, &t.actors, t.ty, t.action, &w.tree);
    let prepared = Prepared::new(&filter);
    cov.filters = 1;
    if let Some(c) = &filter.condition {
        let (n, d) = c.size();
        cov.max_ast_nodes = n;
        cov.max_ast_depth = d;
    }
    cov.max_ids_in = filter.ids_in.len();
    cov.max_container_in = filter.container_in.len();
    let mut expected = Vec::new();
    let mut ast_mismatch = Vec::new();
    let private: rustc_hash::FxHashSet<NodeId> = w.private.iter().copied().collect();
    for &n in rows {
        let path = w.tree.ancestors(n);
        let attrs = &w.tree.attrs[n as usize];
        let res = ResourceRef { id: n, ty: t.ty, path, attrs };
        let req = CheckRequest { subject: t.subject, actors: &t.actors, action: t.action, resource: res, fields: Some(&[]) };
        let allow = match m.check(&req) {
            Ok(d) => {
                if d.reason == "delegation_overlap" {
                    cov.overlap_deny += 1;
                }
                d.allow
            }
            Err(_) => false,
        };
        cov.checks += 1;
        if allow {
            cov.allowed += 1;
            expected.push(n);
        }
        let got = prepared.matches(&Row { id: n, anc: path, attrs });
        if got != allow {
            ast_mismatch.push(n);
        }
        // Coverage (person side, read only).
        if t.action == Action::Read && t.actors.is_empty() {
            if path.len() == 32 {
                cov.path32 += 1;
            }
            if path.iter().filter(|a| private.contains(a)).count() >= 2 {
                cov.private_in_private_rows += 1;
            }
            let res = ResourceRef { id: n, ty: t.ty, path, attrs };
            if let Ok(wk) = m.walk(&res) {
                let r = m.resolve(t.subject, t.ty, attrs, &wk);
                match r.why {
                    Why::PrivateScope => cov.private_stop += 1,
                    Why::Found => {
                        if r.org_owner {
                            cov.org_owner += 1;
                        }
                        if r.via_group {
                            cov.via_group += 1;
                        }
                        if r.beat_group {
                            cov.direct_over_group += 1;
                        }
                        if r.scope == n {
                            cov.row_itself += 1;
                        }
                        if r.conds_true > 0 {
                            cov.cond_true += 1;
                        }
                        if !r.fired.is_empty() {
                            cov.cond_false += 1;
                        }
                        if (r.conds_true > 0 || !r.fired.is_empty()) && attrs.has_null() {
                            cov.cond_with_null_attr += 1;
                        }
                        if let (false, Some(role)) = (r.org_owner, r.role) {
                            let lvl = m.roles[role as usize].type_level[t.ty as usize];
                            let i = (0..wk.n).find(|&i| wk.ids[i] == r.scope).unwrap_or(0);
                            let higher_above = (i + 1..wk.n).any(|j| {
                                wk.data[j].and_then(|nd| m.role_at(nd, t.subject, t.ty)).is_some_and(|pk| {
                                    m.roles[pk.role as usize].type_level[t.ty as usize] > lvl
                                })
                            });
                            if higher_above {
                                cov.closer_lower += 1;
                            }
                            // An assigned scope inside a private scope (no role)
                            // inside another assigned scope.
                            let stop = (i + 1..wk.n).find(|&j| {
                                wk.data[j].is_some_and(|nd| nd.private && m.role_at(nd, t.subject, t.ty).is_none())
                            });
                            if let Some(j) = stop {
                                if (j + 1..wk.n).any(|k| wk.data[k].and_then(|nd| m.role_at(nd, t.subject, t.ty)).is_some()) {
                                    cov.alternation += 1;
                                }
                            }
                        }
                    }
                    Why::NoRole => {}
                }
            }
        }
    }
    Done { filter, expected, ast_mismatch, cov }
}

pub fn run(mut client: Option<&mut Client>, seeds: &[u64], threads: usize) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(c) = client.as_deref_mut() {
        load(c, seeds)?;
    }
    let mut total = Coverage::default();
    let mut ast_bad = 0u64;
    let mut sql_bad = 0u64;
    let mut count_bad = 0u64;
    let mut sql_rows_bad = 0u64;
    let mut closure_bad = 0u64;
    let mut sql_ns = Vec::new();
    let mut closure_ns = Vec::new();
    let mut array_ns_seed1 = Vec::new();
    let mut examples: Vec<String> = Vec::new();
    for &seed in seeds {
        let t0 = Instant::now();
        let w = models::random(seed);
        let mut rng = Rng::new(seed ^ 0x5B5B);
        let subs = subjects(&w, &mut rng);
        let mut tasks = Vec::new();
        let leaf = w.leaf_types[0];
        for (s, actors) in &subs {
            for a in [Action::Read, Action::Write, Action::Delete, Action::Approve] {
                tasks.push(Task { subject: *s, actors: actors.clone(), ty: leaf, action: a });
            }
            for &ct in &w.container_types {
                for a in [Action::Read, Action::Write] {
                    tasks.push(Task { subject: *s, actors: actors.clone(), ty: ct, action: a });
                }
            }
        }
        let mut rows_by_type: rustc_hash::FxHashMap<TypeId, Vec<NodeId>> = Default::default();
        for n in 0..w.tree.len() as NodeId {
            rows_by_type.entry(w.tree.ty(n)).or_default().push(n);
        }
        let empty = Vec::new();
        let chunks: Vec<Vec<(usize, &Task)>> = {
            let mut c: Vec<Vec<(usize, &Task)>> = (0..threads).map(|_| Vec::new()).collect();
            for (i, t) in tasks.iter().enumerate() {
                c[i % threads].push((i, t));
            }
            c
        };
        let mut done: Vec<(usize, Done)> = std::thread::scope(|sc| {
            let hs: Vec<_> = chunks
                .iter()
                .map(|chunk| {
                    let w = &w;
                    let rows_by_type = &rows_by_type;
                    let empty = &empty;
                    sc.spawn(move || {
                        chunk
                            .iter()
                            .map(|&(i, t)| (i, run_task(w, rows_by_type.get(&t.ty).unwrap_or(empty), t)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
        });
        done.sort_by_key(|d| d.0);
        let mut seed_cov = Coverage::default();
        let mut seed_ast_bad = 0u64;
        for (_, d) in &done {
            seed_cov.add(&d.cov);
            seed_ast_bad += d.ast_mismatch.len() as u64;
            if !d.ast_mismatch.is_empty() && examples.len() < 10 {
                examples.push(format!("seed {seed} AST mismatch rows {:?}", &d.ast_mismatch[..d.ast_mismatch.len().min(5)]));
            }
        }
        let mut seed_sql_bad = 0u64;
        if let Some(c) = client.as_deref_mut() {
            for (i, d) in &done {
                let task = &tasks[*i];
                for anc in [Ancestors::Array, Ancestors::Closure] {
                    if anc == Ancestors::Closure && seed != 1 {
                        continue;
                    }
                    let mut params = vec![Param::I64(seed as i64), Param::I64(task.ty as i64)];
                    let wh = to_sql(&d.filter, anc, &mut params);
                    let b = boxed(&params);
                    let r = refs(&b);
                    let q = format!("SELECT i.id FROM item i WHERE i.tenant_id = $1 AND i.type = $2 AND {wh}");
                    let t = Instant::now();
                    let rows = c.query(q.as_str(), &r)?;
                    let e = t.elapsed().as_nanos() as u64;
                    if let Some(ms) = std::env::var("SPIKE_SLOW_MS").ok().and_then(|v| v.parse::<u64>().ok()) {
                        if e > ms * 1_000_000 {
                            let mut inl = q.clone();
                            for (k, p) in params.iter().enumerate().rev() {
                                let lit = match p {
                                    Param::I64s(v) => format!("'{{{}}}'::bigint[]", v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),
                                    Param::Str(x) => format!("'{x}'"),
                                    Param::Strs(v) => format!("'{{{}}}'::text[]", v.join(",")),
                                    Param::I64(x) => x.to_string(),
                                    Param::Bool(b) => b.to_string(),
                                };
                                inl = inl.replace(&format!("${}", k + 1), &lit);
                            }
                            eprintln!("SLOW {}ms rows={} ids_in={} container_in={}\n{inl};", e / 1_000_000, rows.len(), d.filter.ids_in.len(), d.filter.container_in.len());
                        }
                    }
                    let mut got: Vec<NodeId> = rows.iter().map(|r| r.get::<_, i64>(0) as NodeId).collect();
                    got.sort_unstable();
                    let same = got == d.expected;
                    let row_diff = if same { 0 } else { sym_diff(&got, &d.expected) };
                    match anc {
                        Ancestors::Array => {
                            sql_ns.push(e);
                            if seed == 1 {
                                array_ns_seed1.push(e);
                            }
                            if !same {
                                seed_sql_bad += 1;
                                sql_rows_bad += row_diff;
                                if examples.len() < 10 {
                                    examples.push(format!(
                                        "seed {seed} task {i} SQL mismatch: got {} rows, check allows {}",
                                        got.len(),
                                        d.expected.len()
                                    ));
                                }
                            }
                            if i % 10 == 0 {
                                let cq = format!("SELECT count(*) FROM item i WHERE i.tenant_id = $1 AND i.type = $2 AND {wh}");
                                let n: i64 = c.query_one(cq.as_str(), &r)?.get(0);
                                if n as usize != d.expected.len() {
                                    count_bad += 1;
                                }
                            }
                        }
                        Ancestors::Closure => {
                            closure_ns.push(e);
                            if !same {
                                closure_bad += 1;
                            }
                        }
                    }
                }
            }
        }
        println!(
            "seed {seed}: containers+rows={} private={} assignments={} conditions={} groups={} tasks={} checks={} allowed={:.1}% AST mismatches={} SQL mismatched filters={} ({:.1}s)",
            w.tree.len(),
            w.private.len(),
            w.assignments.len(),
            w.model.conds.len(),
            w.group_parents.len(),
            tasks.len(),
            seed_cov.checks,
            seed_cov.allowed as f64 * 100.0 / seed_cov.checks.max(1) as f64,
            seed_ast_bad,
            seed_sql_bad,
            t0.elapsed().as_secs_f64()
        );
        ast_bad += seed_ast_bad;
        sql_bad += seed_sql_bad;
        total.add(&seed_cov);
    }
    println!("filter form: {:?}", crate::eval::form());
    println!("coverage: {total:#?}");
    for e in &examples {
        println!("example: {e}");
    }
    if !sql_ns.is_empty() {
        println!("SQL list query, array column, all seeds (info): {}", stats(sql_ns));
        println!("SQL list query, array column, seed 1 (info): {}", stats(array_ns_seed1));
        println!("SQL list query, closure table, seed 1 (info): {}  mismatched filters={closure_bad}", stats(closure_ns));
    }
    println!(
        "RESULT: row-level AST mismatches={ast_bad} SQL mismatched filters={sql_bad} SQL row mismatches={sql_rows_bad} count mismatches={count_bad} closure-variant mismatched filters={closure_bad}"
    );
    Ok(ast_bad == 0 && sql_bad == 0 && count_bad == 0 && closure_bad == 0)
}

/// Size of the symmetric difference of two sorted lists.
fn sym_diff(a: &[NodeId], b: &[NodeId]) -> u64 {
    let (mut i, mut j, mut n) = (0, 0, 0u64);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => {
                n += 1;
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                n += 1;
                j += 1;
            }
        }
    }
    n + (a.len() - i) as u64 + (b.len() - j) as u64
}
