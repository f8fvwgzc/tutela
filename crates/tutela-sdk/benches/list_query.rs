//! The list-query benchmark of the library gate (ROADMAP item 6, ADR-0011
//! F2, issue #22): `tutela_sdk::sql` against Postgres, at the `list_filter`
//! limits of CONTRACTS.md 6.6.
//!
//! Run on a quiet machine, with a database a role may create tables in:
//!
//! ```text
//! TUTELA_BENCH_DATABASE_URL="host=127.0.0.1 port=5432 user=... dbname=..." \
//!   cargo bench -p tutela-sdk --bench list_query
//! ```
//!
//! Shape: 20 tenants × 100,000 rows (10 departments × 100 projects × 100
//! rows each), `ancestors text[]` with a GIN index over the tenant and the
//! ancestors (`btree_gin`). Two workloads, 200 queries each, every query
//! `count(*)` with a 5 s statement timeout:
//! - **limits**: at the CONTRACTS.md 6.6 limits, taken from `tutela-pdp`'s
//!   constants: every `container_in` entry, a condition of
//!   `MAX_FILTER_NODES / 4` terms (under + not eq), and `ids_in` filling the
//!   total entries (see [`limits`]);
//! - **typical**: 5 `container_in` scopes and 3 condition terms.
//!
//! The gate: p99 under 100 ms for **limits**. The binary exits 1 if it is
//! not met.

use std::collections::HashMap;
use std::time::Instant;

use tokio_postgres::NoTls;
use tutela_contracts::keys::{FieldName, ResourceId, ResourceType};
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::{FilterExpr, FilterValue, ListFilter, PathEntry};
use tutela_sdk::sql::{self, Columns};

type Error = Box<dyn std::error::Error>;

const TENANTS: usize = 20;
const DEPTS: usize = 10;
const PROJECTS: usize = 100;
const ROWS: usize = 100;
const QUERIES: usize = 200;

/// A small deterministic generator (xorshift).
struct Rng(u64);
impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % (n as u64)).unwrap_or(0)
    }
}

fn tid(t: usize) -> String {
    format!("ten_0193a1b2-c3d4-7e5f-8a6b-{t:012x}")
}

fn tenant(t: usize) -> Result<TenantKey, Error> {
    Ok(TenantKey::new(
        "https://auth.bench.test".parse()?,
        tid(t).parse()?,
    ))
}

fn entry(ty: &str, id: &str) -> Result<PathEntry, Error> {
    Ok(PathEntry::new(
        ty.parse::<ResourceType>()?,
        id.parse::<ResourceId>()?,
    ))
}

fn project(rng: &mut Rng) -> Result<PathEntry, Error> {
    entry(
        "project",
        &format!("p{}-{}", rng.below(DEPTS), rng.below(PROJECTS)),
    )
}

fn not_eq(rng: &mut Rng) -> Result<FilterExpr, Error> {
    Ok(FilterExpr::Not {
        arg: Box::new(FilterExpr::Eq {
            attr: FieldName::parse("status")?,
            value: FilterValue::String(format!("s{}", rng.below(5))),
        }),
    })
}

/// The sizes at the limits of `tutela-pdp` (CONTRACTS.md 6.6): every
/// `container_in` entry, a condition of `terms` terms (4 nodes each: and,
/// under, not, eq), and `ids_in` filling the total entries. Overridden by
/// `TUTELA_BENCH_LIMITS=container_in,ids_in,terms` to try other limits.
fn limits() -> (usize, usize, usize) {
    if let Ok(v) = std::env::var("TUTELA_BENCH_LIMITS") {
        let n: Vec<usize> = v.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        if let [a, b, c] = n[..] {
            return (a, b, c);
        }
    }
    let terms = tutela_pdp::MAX_FILTER_NODES / 4;
    let scopes = tutela_pdp::MAX_CONTAINER_IN;
    let ids = tutela_pdp::MAX_FILTER_ENTRIES
        .saturating_sub(scopes + terms)
        .min(tutela_pdp::MAX_IDS_IN);
    (scopes, ids, terms)
}

fn filter(rng: &mut Rng, at_limits: bool) -> Result<ListFilter, Error> {
    let t = rng.below(TENANTS);
    let (scopes, ids, terms) = if at_limits { limits() } else { (5, 0, 3) };
    let mut container_in = Vec::with_capacity(scopes);
    for i in 0..scopes {
        // Real projects first, then ids that exist in no tenant (a filter at
        // the limit names more scopes than one tenant has).
        container_in.push(if i < 1_000.min(scopes) {
            project(rng)?
        } else {
            entry("project", &format!("gone-{i}"))?
        });
    }
    let ids_in = (0..ids)
        .map(|i| format!("r{}-{}-{}", rng.below(DEPTS), rng.below(PROJECTS), i % ROWS).parse())
        .collect::<Result<Vec<ResourceId>, _>>()?;
    let mut args = Vec::with_capacity(terms);
    for _ in 0..terms {
        args.push(FilterExpr::And {
            args: vec![
                FilterExpr::Under {
                    scopes: vec![project(rng)?],
                },
                not_eq(rng)?,
            ],
        });
    }
    Ok(ListFilter {
        tenant: tenant(t)?,
        type_name: "item".parse()?,
        rev: 1,
        ids_in,
        container_in,
        condition: Some(FilterExpr::Or { args }),
    })
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    let i = ((sorted.len() as f64) * p).ceil() as usize;
    sorted.get(i.saturating_sub(1)).copied().unwrap_or(f64::NAN)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let url =
        std::env::var("TUTELA_BENCH_DATABASE_URL").map_err(|_| "set TUTELA_BENCH_DATABASE_URL")?;
    let (mut client, conn) = tokio_postgres::connect(&url, NoTls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let version: String = client.query_one("SHOW server_version", &[]).await?.get(0);
    println!("postgres {version}");

    let setup = Instant::now();
    client
        .batch_execute(
            "DROP TABLE IF EXISTS bench_item;
             CREATE EXTENSION IF NOT EXISTS btree_gin;
             CREATE UNLOGGED TABLE bench_item (
                 tenant_iss text NOT NULL, tenant_tid text NOT NULL, id text NOT NULL,
                 ancestors text[] NOT NULL, status text, owner text);",
        )
        .await?;
    for t in 0..TENANTS {
        client
            .execute(
                "INSERT INTO bench_item
                 SELECT 'https://auth.bench.test', $1, 'r' || d || '-' || p || '-' || r,
                        ARRAY['project:p' || d || '-' || p, 'department:d' || d, 'org:' || $2],
                        CASE WHEN r % 7 = 0 THEN NULL ELSE 's' || (r % 5) END,
                        'user:u' || (r % 50)
                 FROM generate_series(0, $3::int - 1) d, generate_series(0, $4::int - 1) p,
                      generate_series(0, $5::int - 1) r",
                &[
                    &tid(t),
                    &format!("org_{t}"),
                    &i32::try_from(DEPTS)?,
                    &i32::try_from(PROJECTS)?,
                    &i32::try_from(ROWS)?,
                ],
            )
            .await?;
    }
    client
        .batch_execute(
            "CREATE INDEX bench_item_anc ON bench_item USING gin (tenant_tid, ancestors);
             CREATE INDEX bench_item_id ON bench_item (tenant_tid, id);
             ANALYZE bench_item;",
        )
        .await?;
    println!(
        "setup: {} rows in {:.1} s",
        TENANTS * DEPTS * PROJECTS * ROWS,
        setup.elapsed().as_secs_f64()
    );

    let cols = Columns {
        table: "bench_item".into(),
        tenant_iss: "tenant_iss".into(),
        tenant_tid: "tenant_tid".into(),
        id: "id".into(),
        ancestors: "ancestors".into(),
        fields: HashMap::from([
            (FieldName::parse("status")?, "status".into()),
            (FieldName::parse("owner")?, "owner".into()),
        ]),
    };
    let mut rng = Rng(0x7475_7465_6c61);
    let mut gate_ok = true;
    for (name, at_limits) in [("typical", false), ("limits", true)] {
        let mut ms = Vec::with_capacity(QUERIES);
        let mut timeouts = 0usize;
        let mut rows = 0i64;
        for _ in 0..QUERIES {
            let f = filter(&mut rng, at_limits)?;
            let tx = client.transaction().await?;
            let start = Instant::now();
            match sql::count(&tx, &f, &cols, 5_000).await {
                Ok(n) => rows += n,
                Err(_) => timeouts += 1,
            }
            ms.push(start.elapsed().as_secs_f64() * 1_000.0);
            tx.rollback().await?;
        }
        ms.sort_by(f64::total_cmp);
        let p99 = pct(&ms, 0.99);
        println!(
            "{name:8} p50 {:8.2} ms  p99 {:8.2} ms  max {:8.2} ms  timeouts {timeouts}  avg rows {}",
            pct(&ms, 0.50),
            p99,
            ms.last().copied().unwrap_or(f64::NAN),
            rows / i64::try_from(QUERIES)?
        );
        if at_limits && (p99 >= 100.0 || timeouts > 0) {
            gate_ok = false;
        }
    }
    client.batch_execute("DROP TABLE bench_item;").await?;
    if gate_ok {
        println!("gate: PASS (limits p99 < 100 ms, no timeouts)");
        Ok(())
    } else {
        println!("gate: FAIL (limits p99 >= 100 ms or a timeout)");
        std::process::exit(1);
    }
}
