//! The group and path closure benchmark of the Service gate (ROADMAP.md,
//! ADR-0020): `tutela-store`'s public calls on a real Postgres, as a role
//! that owns nothing, through forced row-level security.
//!
//! Run it on a quiet machine, with a role that may create roles and
//! databases:
//!
//! ```text
//! TUTELA_BENCH_DATABASE_URL="host=127.0.0.1 port=5432 user=postgres dbname=postgres" \
//!   cargo bench -p tutela-store --bench closure
//! ```
//!
//! Shape: the spike's closure world (ADR-0011) in each of 20 tenants, in the
//! same tables: 10,000 users, 500 groups in 8 levels, one group that holds
//! every user, a chain of 32 nested groups, 20,000 registered scopes with
//! paths of 1 to 32, and 10,000 assignments. So row-level security has work
//! to do, and a query that forgets a tenant column shows.
//!
//! Each run is a real request: a new transaction, `enter`, the call,
//! `COMMIT`. The tenant and the input are random. `call` is the store call
//! alone; `tx` is the whole transaction. Statements are not prepared ahead,
//! because the store does not prepare them.
//!
//! The gate: `tx` p99 under 5 ms for **G**, **G32** and **P**, the threshold
//! fixed before the spike. The binary exits 1 if it is not met. The rest is
//! information. **B**, the path closure going down, walks the tenant's
//! `scope_path` rows: see ADR-0020.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use tokio_postgres::{Client, NoTls};
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::GroupKey;
use tutela_pdp::{Member, PathEntry};

type Error = Box<dyn std::error::Error>;

const TENANTS: usize = 20;
const USERS: usize = 10_000;
const LEVELS: [usize; 8] = [10, 70, 70, 70, 70, 70, 70, 70];
const GROUPS: usize = 500;
const CHAIN: usize = 32;
const SCOPES: usize = 20_000;
const MAX_DEPTH: usize = 32;
const ASSIGNMENTS: usize = 10_000;
const WARMUP: usize = 1_000;
const MEASURED: usize = 10_000;
/// The whole-tenant calls are slow by design, so they run fewer times.
const SLOW_WARMUP: usize = 20;
const SLOW_MEASURED: usize = 200;
const GATE_MS: f64 = 5.0;

const OWNER: &str = "tutela_bench_owner";
const SERVICE: &str = "tutela_bench_service";
const PASSWORD: &str = "tutela_bench";
const ISS: &str = "https://auth.bench.test";

/// A small deterministic generator (xorshift).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap_or(0)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

fn tid(t: usize) -> String {
    format!("ten_0193a1b2-c3d4-7e5f-8a6b-{t:012x}")
}

fn org_id(t: usize) -> String {
    format!("org_0193a1b2-c3d4-7e5f-8a6b-{t:012x}")
}

fn user_id(u: usize) -> String {
    format!("usr_0193a1b2-c3d4-7a11-8b22-{u:012x}")
}

fn user(u: usize) -> Result<Principal, Error> {
    Ok(format!("user:{}", user_id(u)).parse()?)
}

fn group_key(g: usize) -> String {
    format!("g{g}")
}

fn chain_key(c: usize) -> String {
    format!("chain{c}")
}

fn scope(s: usize) -> Result<PathEntry, Error> {
    Ok(PathEntry::new("scope".parse()?, format!("s{s}").parse()?))
}

fn connect_url(base: &str, db: &str, user: &str) -> String {
    let mut parts: Vec<String> = base
        .split_whitespace()
        .filter(|p| {
            !p.starts_with("dbname=") && !p.starts_with("user=") && !p.starts_with("password=")
        })
        .map(str::to_owned)
        .collect();
    parts.push(format!("dbname={db}"));
    parts.push(format!("user={user}"));
    parts.push(format!("password={PASSWORD}"));
    parts.join(" ")
}

async fn connect(url: &str) -> Result<Client, Error> {
    let (client, conn) = tokio_postgres::connect(url, NoTls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

/// One or two distinct picks below `limit`.
fn parents(rng: &mut Rng, limit: usize) -> Vec<usize> {
    let first = rng.below(limit);
    let mut out = vec![first];
    if rng.chance(50) {
        let second = rng.below(limit);
        if second != first {
            out.push(second);
        }
    }
    out
}

/// The rows of one tenant, as bound arrays.
#[derive(Default)]
struct Rows {
    group_ids: Vec<String>,
    group_keys: Vec<String>,
    member_groups: Vec<String>,
    member_kinds: Vec<&'static str>,
    member_ids: Vec<String>,
    scope_ids: Vec<String>,
    scope_paths: Vec<String>,
    ra_ids: Vec<String>,
    ra_kinds: Vec<&'static str>,
    ra_subjects: Vec<String>,
    ra_scope_kinds: Vec<&'static str>,
    ra_scope_ids: Vec<String>,
}

/// One tenant's world. `scope_paths` holds a Postgres array literal.
fn world(t: usize) -> Rows {
    let mut rng = Rng(0x7475_7465_6c61 ^ ((t as u64 + 1) * 0x9e37_79b9));
    let mut r = Rows::default();
    let gid = |g: usize| format!("grp_{g}");

    // Groups in levels: each one below the top sits in 1 or 2 groups of the
    // level above.
    let mut starts = Vec::with_capacity(LEVELS.len());
    let mut next = 0;
    for size in LEVELS {
        starts.push(next);
        next += size;
    }
    for (level, (&start, &size)) in starts.iter().zip(&LEVELS).enumerate() {
        for g in start..start + size {
            r.group_ids.push(gid(g));
            r.group_keys.push(group_key(g));
            if level > 0 {
                let above = starts[level - 1];
                for p in parents(&mut rng, LEVELS[level - 1]) {
                    r.member_groups.push(gid(above + p));
                    r.member_kinds.push("group");
                    r.member_ids.push(gid(g));
                }
            }
        }
    }
    let deepest = starts[LEVELS.len() - 1];

    // Each user is in group 0 ("everyone") and 1 to 3 others, mostly deep.
    for u in 0..USERS {
        let mut mine = vec![0];
        for _ in 0..=rng.below(3) {
            let g = if rng.chance(70) {
                deepest + rng.below(LEVELS[LEVELS.len() - 1])
            } else {
                rng.below(GROUPS)
            };
            if !mine.contains(&g) {
                mine.push(g);
            }
        }
        for g in mine {
            r.member_groups.push(gid(g));
            r.member_kinds.push("user");
            r.member_ids.push(user_id(u));
        }
    }

    // A chain of 32 nested groups, with user 0 at the bottom.
    for c in 0..CHAIN {
        r.group_ids.push(format!("grp_chain_{c}"));
        r.group_keys.push(chain_key(c));
        if c > 0 {
            r.member_groups.push(format!("grp_chain_{}", c - 1));
            r.member_kinds.push("group");
            r.member_ids.push(format!("grp_chain_{c}"));
        }
    }
    r.member_groups.push(format!("grp_chain_{}", CHAIN - 1));
    r.member_kinds.push("user");
    r.member_ids.push(user_id(0));

    // Scopes, even across depths 1 to 32, each under a random scope one
    // level up. A scope's number rises with its depth.
    let org = format!("org:{}", org_id(t));
    let per_depth = SCOPES / MAX_DEPTH;
    let mut paths: Vec<String> = Vec::with_capacity(SCOPES);
    let mut level_start = 0;
    let mut level_len = 0;
    for depth in 1..=MAX_DEPTH {
        let start = paths.len();
        let count = if depth == MAX_DEPTH {
            SCOPES - start
        } else {
            per_depth
        };
        for s in start..start + count {
            let path = if depth == 1 {
                org.clone()
            } else {
                let parent = level_start + rng.below(level_len);
                format!("scope:s{parent},{}", paths[parent])
            };
            paths.push(path);
            r.scope_ids.push(format!("s{s}"));
        }
        level_start = start;
        level_len = count;
    }
    r.scope_paths = paths.iter().map(|p| format!("{{{p}}}")).collect();

    // Assignments: unique per (subject, scope).
    let mut taken = HashSet::with_capacity(ASSIGNMENTS);
    while r.ra_ids.len() < ASSIGNMENTS {
        let n = r.ra_ids.len();
        let group = n % 8 == 0;
        let (kind, subject) = if group {
            ("group", gid(rng.below(GROUPS)))
        } else {
            ("user", user_id(rng.below(USERS)))
        };
        let (scope_kind, scope_id) = if n % 32 == 0 {
            ("org", org_id(t))
        } else {
            ("scope", format!("s{}", rng.below(SCOPES)))
        };
        if taken.insert((kind, subject.clone(), scope_kind, scope_id.clone())) {
            r.ra_ids
                .push(format!("ra_0193a1b2-c3d4-7a11-8b22-{n:012x}"));
            r.ra_kinds.push(kind);
            r.ra_subjects.push(subject);
            r.ra_scope_kinds.push(scope_kind);
            r.ra_scope_ids.push(scope_id);
        }
    }
    r
}

/// Loads one tenant, as a superuser, so row-level security stays out of the
/// way of the load.
async fn load_tenant(c: &Client, t: usize) -> Result<(), Error> {
    let r = world(t);
    let tenant = tid(t);
    c.execute(
        "INSERT INTO tutela.tenant (tenant_id, iss) VALUES ($1, $2)",
        &[&tenant, &ISS],
    )
    .await?;
    c.execute(
        "INSERT INTO tutela.tenant_rev (tenant_id, rev) VALUES ($1, 1)",
        &[&tenant],
    )
    .await?;
    c.execute(
        "INSERT INTO tutela.org (tenant_id, org_id) VALUES ($1, $2)",
        &[&tenant, &org_id(t)],
    )
    .await?;
    c.execute(
        "INSERT INTO tutela.\"group\" (tenant_id, id, org_id, key) \
         SELECT $1, i, $2, k FROM unnest($3::text[], $4::text[]) AS u(i, k)",
        &[&tenant, &org_id(t), &r.group_ids, &r.group_keys],
    )
    .await?;
    c.execute(
        "INSERT INTO tutela.group_member (tenant_id, group_id, member_kind, member_id) \
         SELECT DISTINCT $1, g, k, m FROM unnest($2::text[], $3::text[], $4::text[]) AS u(g, k, m)",
        &[&tenant, &r.member_groups, &r.member_kinds, &r.member_ids],
    )
    .await?;
    c.execute(
        "INSERT INTO tutela.scope_path (tenant_id, scope_kind, scope_id, ancestors) \
         SELECT $1, 'scope', s, p::text[] FROM unnest($2::text[], $3::text[]) AS u(s, p)",
        &[&tenant, &r.scope_ids, &r.scope_paths],
    )
    .await?;
    c.execute(
        "INSERT INTO tutela.role_assignment (tenant_id, id, principal_kind, principal_id, \
         scope_kind, scope_id, role_id, rev) \
         SELECT $1, i, k, s, sk, si, 'reader', 1 \
         FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) \
         AS u(i, k, s, sk, si)",
        &[
            &tenant,
            &r.ra_ids,
            &r.ra_kinds,
            &r.ra_subjects,
            &r.ra_scope_kinds,
            &r.ra_scope_ids,
        ],
    )
    .await?;
    Ok(())
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let last = sorted.len().saturating_sub(1);
    let at = ((last as f64) * p).round() as usize;
    sorted.get(at).copied().unwrap_or_default()
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000_000.0
}

/// Prints a line; returns the p99 in ms.
fn report(name: &str, label: &str, samples: &mut [Duration], rows: Option<f64>) -> f64 {
    samples.sort_unstable();
    let p99 = percentile(samples, 0.99);
    let extra = rows.map_or_else(String::new, |r| format!("  (avg rows {r:.1})"));
    println!(
        "{name} {label}: n={} p50={:.1}us p90={:.1}us p99={:.1}us p99.9={:.1}us max={:.1}us{extra}",
        samples.len(),
        us(percentile(samples, 0.5)),
        us(percentile(samples, 0.9)),
        us(p99),
        us(percentile(samples, 0.999)),
        us(samples.last().copied().unwrap_or_default()),
    );
    p99.as_secs_f64() * 1_000.0
}

/// Runs `$body` in a transaction per run, on a random tenant. It evaluates
/// to the p99 of the whole transaction, in ms.
macro_rules! measure {
    ($name:expr, $client:expr, $tenants:expr, $rng:expr, $warmup:expr, $runs:expr,
     |$tx:ident, $tenant:ident| $body:expr) => {{
        let mut calls = Vec::with_capacity($runs);
        let mut txs = Vec::with_capacity($runs);
        let mut rows = 0usize;
        for i in 0..$warmup + $runs {
            let $tenant = &$tenants[$rng.below(TENANTS)];
            let started = Instant::now();
            let $tx = $client.transaction().await?;
            tutela_store::enter(&$tx, $tenant).await?;
            let call = Instant::now();
            let n: usize = $body;
            let call = call.elapsed();
            $tx.commit().await?;
            let total = started.elapsed();
            if i >= $warmup {
                calls.push(call);
                txs.push(total);
                rows += n;
            }
        }
        let avg = rows as f64 / $runs as f64;
        report($name, "call", &mut calls, Some(avg));
        report($name, "tx  ", &mut txs, None)
    }};
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let Ok(base) = std::env::var("TUTELA_BENCH_DATABASE_URL") else {
        eprintln!("set TUTELA_BENCH_DATABASE_URL to run this benchmark");
        return Ok(());
    };
    let admin = connect(&base).await?;
    let version: String = admin.query_one("SHOW server_version", &[]).await?.get(0);
    println!("postgres {version}");
    for role in [OWNER, SERVICE] {
        admin
            .batch_execute(&format!(
                "DROP ROLE IF EXISTS {role}; \
                 CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{PASSWORD}';"
            ))
            .await?;
    }
    let name = format!("tutela_bench_{}", std::process::id());
    admin
        .batch_execute(&format!("CREATE DATABASE {name} OWNER {OWNER}"))
        .await?;
    let result = bench(&base, &name).await;
    admin
        .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .await?;
    admin
        .batch_execute(&format!("DROP ROLE {OWNER}; DROP ROLE {SERVICE};"))
        .await?;
    if !result? {
        eprintln!("gate: FAIL (p99 at or over {GATE_MS} ms)");
        std::process::exit(1);
    }
    println!("gate: PASS (G, G32 and P tx p99 < {GATE_MS} ms)");
    Ok(())
}

async fn bench(base: &str, name: &str) -> Result<bool, Error> {
    let mut owner = connect(&connect_url(base, name, OWNER)).await?;
    tutela_store::migrate(&mut owner).await?;
    tutela_store::grant_service(&mut owner, SERVICE).await?;
    drop(owner);

    // A superuser on the bench database: the base URL with its dbname.
    let mut parts: Vec<String> = base
        .split_whitespace()
        .filter(|p| !p.starts_with("dbname="))
        .map(str::to_owned)
        .collect();
    parts.push(format!("dbname={name}"));
    let root = connect(&parts.join(" ")).await?;
    let setup = Instant::now();
    for t in 0..TENANTS {
        load_tenant(&root, t).await?;
    }
    root.batch_execute("VACUUM ANALYZE").await?;
    let counts = root
        .query_one(
            "SELECT (SELECT count(*) FROM tutela.group_member), \
             (SELECT count(*) FROM tutela.scope_path), \
             (SELECT count(*) FROM tutela.role_assignment)",
            &[],
        )
        .await?;
    println!(
        "setup: {TENANTS} tenants, {} group_member, {} scope_path, {} role_assignment rows in {:.1} s",
        counts.get::<_, i64>(0),
        counts.get::<_, i64>(1),
        counts.get::<_, i64>(2),
        setup.elapsed().as_secs_f64()
    );
    drop(root);

    let mut client = connect(&connect_url(base, name, SERVICE)).await?;
    tutela_store::check_isolation(&client).await?;
    let iss: tutela_contracts::tenant::Issuer = ISS.parse()?;
    let tenants: Vec<TenantKey> = (0..TENANTS)
        .map(|t| Ok(TenantKey::new(iss.clone(), tid(t).parse()?)))
        .collect::<Result<_, Error>>()?;
    let mut rng = Rng(0x0063_6c6f_7375_7265);
    let deep: Vec<usize> = (SCOPES - SCOPES / MAX_DEPTH..SCOPES).collect();
    let top = GroupKey::parse(&group_key(0))?;
    let bottom = GroupKey::parse(&chain_key(CHAIN - 1))?;
    let joining = GroupKey::parse(&group_key(GROUPS - 1))?;

    let g = measure!(
        "G groups of a user",
        client,
        tenants,
        rng,
        WARMUP,
        MEASURED,
        |tx, t| tutela_store::groups_of(&tx, t, &user(1 + rng.below(USERS - 1))?)
            .await?
            .len()
    );
    let g32 = measure!(
        "G32 groups of a user at the bottom of 32 levels",
        client,
        tenants,
        rng,
        WARMUP,
        MEASURED,
        |tx, t| tutela_store::groups_of(&tx, t, &user(0)?).await?.len()
    );
    let p = measure!(
        "P path of a scope at depth 32",
        client,
        tenants,
        rng,
        WARMUP,
        MEASURED,
        |tx, t| {
            let s = scope(deep[rng.below(deep.len())])?;
            tutela_store::ancestors(&tx, t, &s)
                .await?
                .map_or(0, |a| a.len())
        }
    );
    measure!(
        "A assignments that apply to a user (info)",
        client,
        tenants,
        rng,
        WARMUP,
        MEASURED,
        |tx, t| tutela_store::assignments_for(&tx, t, &user(rng.below(USERS))?)
            .await?
            .len()
    );
    measure!(
        "B scopes below a scope at depth 16 (info)",
        client,
        tenants,
        rng,
        WARMUP,
        MEASURED,
        |tx, t| {
            let s = scope(15 * (SCOPES / MAX_DEPTH) + rng.below(SCOPES / MAX_DEPTH))?;
            tutela_store::scopes_below(&tx, t, &s).await?.len()
        }
    );
    measure!(
        "M members of the group of everyone (info)",
        client,
        tenants,
        rng,
        SLOW_WARMUP,
        SLOW_MEASURED,
        |tx, t| tutela_store::members_of(&tx, t, &top).await?.len()
    );
    measure!(
        "M32 members at the end of the chain (info)",
        client,
        tenants,
        rng,
        WARMUP,
        MEASURED,
        |tx, t| tutela_store::members_of(&tx, t, &bottom).await?.len()
    );
    measure!(
        "L a whole tenant loaded (info)",
        client,
        tenants,
        rng,
        SLOW_WARMUP,
        SLOW_MEASURED,
        |tx, t| tutela_store::load(&tx, t).await?.data.bindings.len()
    );
    // The write's whole cost: the revision bump, the insert and the load
    // checks over the whole tenant. Each run removes what it added.
    measure!(
        "W a checked membership write and its removal (info)",
        client,
        tenants,
        rng,
        SLOW_WARMUP,
        SLOW_MEASURED,
        |tx, t| {
            let m = Member::Principal(user(USERS + 1)?);
            tutela_store::add_member(&tx, t, &joining, &m, None).await?;
            tutela_store::remove_member(&tx, t, &joining, &m).await?;
            1
        }
    );
    Ok(g < GATE_MS && g32 < GATE_MS && p < GATE_MS)
}
