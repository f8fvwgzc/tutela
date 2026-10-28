//! Question 2: closure latency in Postgres (docs/SPIKE-WEEK1.md §5).
//! THROWAWAY.

use crate::models;
use crate::model::Subject;
use crate::pg::{array, stats};
use crate::rng::Rng;
use crate::tree::ScopePaths;
use postgres::Client;
use std::io::Write;
use std::time::Instant;

const T: i64 = 1000;
const WARMUP: usize = 1_000;
const MEASURED: usize = 10_000;

pub fn run(c: &mut Client, seed: u64) -> Result<(), Box<dyn std::error::Error>> {
    let w = models::big(seed);
    let t = Instant::now();
    c.batch_execute(
        "DROP TABLE IF EXISTS group_member, group_closure, node, role_assignment;
         CREATE TABLE group_member (tenant_id bigint NOT NULL, group_id bigint NOT NULL, member_kind smallint NOT NULL,
             member_id bigint NOT NULL, PRIMARY KEY (tenant_id, group_id, member_kind, member_id));
         CREATE TABLE group_closure (tenant_id bigint NOT NULL, member_kind smallint NOT NULL, member_id bigint NOT NULL,
             group_id bigint NOT NULL, PRIMARY KEY (tenant_id, member_kind, member_id, group_id));
         CREATE TABLE node (tenant_id bigint NOT NULL, id bigint NOT NULL, parent_id bigint, type bigint NOT NULL,
             ancestors bigint[] NOT NULL, PRIMARY KEY (tenant_id, id));
         CREATE TABLE role_assignment (tenant_id bigint NOT NULL, id bigint NOT NULL, subject_kind smallint NOT NULL,
             subject_id bigint NOT NULL, scope_id bigint NOT NULL, role_id bigint NOT NULL, PRIMARY KEY (tenant_id, id));",
    )?;
    {
        let mut wr = c.copy_in("COPY node (tenant_id, id, parent_id, type, ancestors) FROM STDIN")?;
        for n in 0..w.tree.len() as u32 {
            let p = w.tree.parent[n as usize];
            let p = if p == u32::MAX { "\\N".to_string() } else { p.to_string() };
            writeln!(wr, "{T}\t{n}\t{p}\t{}\t{}", w.tree.ty(n), array(w.tree.ancestors(n)))?;
        }
        wr.finish()?;
    }
    let mut closure_rows = 0usize;
    {
        let mut wr = c.copy_in("COPY group_member (tenant_id, group_id, member_kind, member_id) FROM STDIN")?;
        for (g, ps) in w.group_parents.iter().enumerate() {
            for p in ps {
                writeln!(wr, "{T}\t{p}\t1\t{g}")?;
            }
        }
        for (u, gs) in w.user_direct_groups.iter().enumerate() {
            for g in gs {
                writeln!(wr, "{T}\t{g}\t0\t{u}")?;
            }
        }
        wr.finish()?;
        let mut wr = c.copy_in("COPY group_closure (tenant_id, member_kind, member_id, group_id) FROM STDIN")?;
        for (u, gs) in w.model.user_groups.iter().enumerate() {
            for g in gs {
                writeln!(wr, "{T}\t0\t{u}\t{g}")?;
                closure_rows += 1;
            }
        }
        for (g, gs) in w.model.group_ancestors.iter().enumerate() {
            for a in gs {
                writeln!(wr, "{T}\t1\t{g}\t{a}")?;
                closure_rows += 1;
            }
        }
        wr.finish()?;
        let mut wr =
            c.copy_in("COPY role_assignment (tenant_id, id, subject_kind, subject_id, scope_id, role_id) FROM STDIN")?;
        for &(id, s, n, r) in &w.assignments {
            let (k, x) = match s {
                Subject::User(u) => (0, u),
                Subject::Group(g) => (1, g),
                Subject::Agent(a) => (2, a),
            };
            writeln!(wr, "{T}\t{id}\t{k}\t{x}\t{n}\t{r}")?;
        }
        wr.finish()?;
    }
    c.batch_execute(
        "CREATE INDEX ON group_member (tenant_id, member_kind, member_id);
         CREATE INDEX ON group_closure (tenant_id, group_id);
         CREATE INDEX ON node (tenant_id, parent_id);
         CREATE INDEX ON role_assignment (tenant_id, subject_kind, subject_id);",
    )?;
    c.batch_execute("VACUUM ANALYZE group_member, group_closure, node, role_assignment")?;
    println!(
        "loaded in {:.1}s: nodes={} group_member rows={} group_closure rows={} role_assignment rows={}",
        t.elapsed().as_secs_f64(),
        w.tree.len(),
        w.group_parents.iter().map(Vec::len).sum::<usize>() + w.user_direct_groups.iter().map(Vec::len).sum::<usize>(),
        closure_rows,
        w.assignments.len()
    );

    let deep: Vec<i64> = (1..w.tree.len() as u32).filter(|&n| w.tree.depth(n) == 32).map(i64::from).collect();
    let mut rng = Rng::new(seed ^ 0xC105);

    let g1 = c.prepare(
        "WITH RECURSIVE g(group_id) AS (
           SELECT group_id FROM group_member WHERE tenant_id = $1 AND member_kind = 0 AND member_id = $2
           UNION
           SELECT gm.group_id FROM group_member gm JOIN g ON gm.tenant_id = $1 AND gm.member_kind = 1 AND gm.member_id = g.group_id)
         SELECT group_id FROM g",
    )?;
    let g2 = c.prepare("SELECT group_id FROM group_closure WHERE tenant_id = $1 AND member_kind = 0 AND member_id = $2")?;
    let p1 = c.prepare(
        "WITH RECURSIVE p(id, parent_id, n) AS (
           SELECT id, parent_id, 0 FROM node WHERE tenant_id = $1 AND id = $2
           UNION ALL
           SELECT x.id, x.parent_id, p.n + 1 FROM node x JOIN p ON x.tenant_id = $1 AND x.id = p.parent_id WHERE p.n < 40)
         SELECT id FROM p WHERE n > 0 ORDER BY n",
    )?;
    let p2 = c.prepare("SELECT ancestors FROM node WHERE tenant_id = $1 AND id = $2")?;
    let a1 = c.prepare(
        "SELECT scope_id, role_id FROM role_assignment WHERE tenant_id = $1 AND (
           (subject_kind = 0 AND subject_id = $2) OR
           (subject_kind = 1 AND subject_id IN (SELECT group_id FROM group_closure
              WHERE tenant_id = $1 AND member_kind = 0 AND member_id = $2)))",
    )?;
    let g3 = c.prepare(
        "WITH RECURSIVE m(kind, id) AS (
           SELECT member_kind, member_id FROM group_member WHERE tenant_id = $1 AND group_id = $2
           UNION
           SELECT gm.member_kind, gm.member_id FROM group_member gm JOIN m ON m.kind = 1 AND gm.tenant_id = $1 AND gm.group_id = m.id)
         SELECT count(*) FROM m WHERE kind = 0",
    )?;

    let users = w.users as u64;
    let mut rows_seen = [0usize; 4];
    let mut run = |name: &str, c: &mut Client, f: &mut dyn FnMut(&mut Client, &mut Rng) -> Result<usize, postgres::Error>| -> Result<(), postgres::Error> {
        let mut ns = Vec::with_capacity(MEASURED);
        let mut rows = 0usize;
        for i in 0..WARMUP + MEASURED {
            let t = Instant::now();
            let r = f(c, &mut rng)?;
            let e = t.elapsed();
            if i >= WARMUP {
                ns.push(e.as_nanos() as u64);
                rows += r;
            }
        }
        println!("{name}: {}  (avg rows {:.1})", stats(ns), rows as f64 / MEASURED as f64);
        Ok(())
    };
    run("G1 groups of a user, recursive CTE", c, &mut |c, rng| {
        Ok(c.query(&g1, &[&T, &(rng.below(users) as i64)])?.len())
    })?;
    run("P1 path at depth 32, recursive CTE", c, &mut |c, rng| {
        let rows = c.query(&p1, &[&T, &rng.pick(&deep)])?;
        Ok(rows.len())
    })?;
    run("G2 groups of a user, closure table", c, &mut |c, rng| {
        Ok(c.query(&g2, &[&T, &(rng.below(users) as i64)])?.len())
    })?;
    run("P2 path at depth 32, ancestors column", c, &mut |c, rng| {
        let rows = c.query(&p2, &[&T, &rng.pick(&deep)])?;
        let a: Vec<i64> = rows.first().map(|r| r.get(0)).unwrap_or_default();
        Ok(a.len())
    })?;
    run("A1 assignments for a user (info)", c, &mut |c, rng| {
        Ok(c.query(&a1, &[&T, &(rng.below(users) as i64)])?.len())
    })?;
    let top: Vec<i64> = (0..w.group_level.len()).filter(|&g| w.group_level[g] == 0).map(|g| g as i64).collect();
    run("G3 members of a top group, recursive CTE (info)", c, &mut |c, rng| {
        let n: i64 = c.query_one(&g3, &[&T, &rng.pick(&top)])?.get(0);
        Ok(n as usize)
    })?;
    // W1: add group A into group B one level up, and update the closure.
    let mut pairs = Vec::new();
    for (a, ps) in w.group_parents.iter().enumerate() {
        let la = w.group_level[a];
        if la == 0 {
            continue;
        }
        for b in 0..w.group_level.len() {
            if w.group_level[b] == la - 1 && !ps.contains(&(b as u32)) {
                pairs.push((a as i64, b as i64));
                break;
            }
        }
    }
    let mut inserted = 0u64;
    run("W1 add group to group + closure update, rolled back (info)", c, &mut |c, rng| {
        let (a, b) = rng.pick(&pairs);
        let mut tx = c.transaction()?;
        tx.execute("INSERT INTO group_member VALUES ($1, $2, 1, $3)", &[&T, &b, &a])?;
        let n = tx.execute(
            "INSERT INTO group_closure (tenant_id, member_kind, member_id, group_id)
             SELECT $1, d.k, d.id, u.g FROM
               (SELECT 1::smallint AS k, $2::bigint AS id
                UNION ALL SELECT member_kind, member_id FROM group_closure WHERE tenant_id = $1 AND group_id = $2) d
             CROSS JOIN
               (SELECT $3::bigint AS g
                UNION ALL SELECT group_id FROM group_closure WHERE tenant_id = $1 AND member_kind = 1 AND member_id = $3) u
             ON CONFLICT DO NOTHING",
            &[&T, &a, &b],
        )?;
        inserted += n;
        tx.rollback()?;
        Ok(n as usize)
    })?;
    let _ = &mut rows_seen;
    Ok(())
}
