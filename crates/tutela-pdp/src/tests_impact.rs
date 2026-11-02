//! The impact report (PERMISSION-MODEL.md 15.1 step 3, ADR-0027).
//!
//! The property test asks `check` under both models, for every principal on
//! every row, and looks for each real change in the report. So the report
//! cannot miss a change by reading the same code wrong twice: `check` knows
//! the field values, and the report does not.

use std::sync::Arc;

use proptest::prelude::*;
use tutela_contracts::decision::Decision;
use tutela_contracts::principal::Principal;

use crate::impact::{Change, ImpactReport, MAX_IMPACT_WORK, model_impact};
use crate::model::Model;
use crate::testgen::{Node, Paths, Rng, Tenant, World, principals, world};
use crate::tests_check::{binding, direct, entry, org_id, tenant, user};
use crate::tests_moves::with_more_bindings;
use crate::tests_props::{check_req, pdp_of};
use crate::{PathEntry, Pdp, ScopePathError, ScopePaths, TenantData};

fn holds(r: &ImpactReport, change: Change, key: &str, p: &Principal) -> bool {
    let p = p.to_string();
    r.lines
        .iter()
        .any(|l| l.change == change && l.key == key && l.principals.contains(&p))
}

/// Every action `check` was asked, in both models.
fn actions(w: &World, spec: &crate::testgen::ModelSpec) -> Vec<String> {
    let mut a = w.spec.actions();
    a.extend(spec.actions());
    a.sort();
    a.dedup();
    a
}

fn decide(pdp: &Pdp, t: &Tenant, p: &Principal, action: &str, row: &Node) -> Option<Decision> {
    pdp.check(&check_req(t, p, &[], action, row)).ok()
}

/// Every difference between the two answers on one row must be in the report.
fn compare_row(
    r: &ImpactReport,
    (before, after): (&Pdp, &Pdp),
    t: &Tenant,
    p: &Principal,
    row: &Node,
    all: &[String],
    stats: &mut Stats,
) {
    for a in all {
        let (Some(d0), Some(d1)) = (decide(before, t, p, a, row), decide(after, t, p, a, row))
        else {
            continue;
        };
        let ctx = || format!("{p} {a} on {}: {d0:?} -> {d1:?}\n{r:?}", row.entry);
        if d1.level > d0.level {
            assert!(holds(r, Change::Gain, "doc", p), "{}", ctx());
            stats.gains += 1;
        }
        if d1.level < d0.level {
            assert!(holds(r, Change::Lose, "doc", p), "{}", ctx());
            stats.losses += 1;
        }
        let name = a.split_once(':').map_or("", |(_, n)| n);
        let built_in = matches!(name, "read" | "write" | "delete");
        if !built_in && d1.is_allowed() != d0.is_allowed() {
            let change = if d1.is_allowed() {
                Change::Gain
            } else {
                Change::Lose
            };
            assert!(holds(r, change, a, p), "{}", ctx());
            stats.actions += 1;
        }
        for f in d1.field_mask.read() {
            if !d0.field_mask.read().contains(f) {
                assert!(holds(r, Change::Gain, &format!("doc.{f}"), p), "{}", ctx());
                stats.fields += 1;
            }
        }
        for f in d0.field_mask.read() {
            if !d1.field_mask.read().contains(f) {
                assert!(holds(r, Change::Lose, &format!("doc.{f}"), p), "{}", ctx());
                stats.fields += 1;
            }
        }
    }
}

#[derive(Default, Debug)]
struct Stats {
    reports: usize,
    gains: usize,
    losses: usize,
    actions: usize,
    fields: usize,
    conditional: usize,
    empty: usize,
}

fn report_holds_every_change(seed: u64, stats: &mut Stats) {
    let mut w = world(seed);
    let mut rng = Rng::new(seed ^ 0x696d_7061);
    with_more_bindings(&mut rng, &mut w);
    let spec = w.spec.mutate(&mut rng);
    let Ok(next) = Model::from_toml(&spec.render()) else {
        return;
    };
    let next = Arc::new(next);
    let paths = Paths::of(&w.tenants);
    let all = actions(&w, &spec);
    for t in &w.tenants {
        let before = pdp_of(&w.model, &[t]);
        let after = pdp_of(&next, &[t]);
        let r = model_impact(&before, &after, &t.key, &paths, MAX_IMPACT_WORK).unwrap();
        assert!(r.complete, "seed {seed}");
        stats.reports += 1;
        stats.empty += usize::from(r.lines.is_empty());
        stats.conditional += r.lines.iter().filter(|l| l.conditional).count();
        // Reading it again gives the same answer, line for line.
        assert_eq!(
            r,
            model_impact(&before, &after, &t.key, &paths, MAX_IMPACT_WORK).unwrap()
        );
        for p in principals() {
            for row in t.rows() {
                compare_row(&r, (&before, &after), t, &p, row, &all, stats);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn tm08_the_impact_report_holds_every_change(seed in any::<u64>()) {
        report_holds_every_change(seed, &mut Stats::default());
    }

    /// A report that stops early never reads as "no impact", at any bound.
    #[test]
    fn a_report_that_stops_early_never_says_no_impact(seed in any::<u64>(), limit in 0usize..200) {
        let w = world(seed);
        let mut rng = Rng::new(seed);
        let spec = w.spec.mutate(&mut rng);
        if let Ok(next) = Model::from_toml(&spec.render()) {
            let next = Arc::new(next);
            let paths = Paths::of(&w.tenants);
            for t in &w.tenants {
                let (before, after) = (pdp_of(&w.model, &[t]), pdp_of(&next, &[t]));
                let full = model_impact(&before, &after, &t.key, &paths, MAX_IMPACT_WORK).unwrap();
                let cut = model_impact(&before, &after, &t.key, &paths, limit).unwrap();
                if cut.complete {
                    prop_assert_eq!(&cut, &full);
                } else {
                    prop_assert!(!cut.no_impact());
                    for l in &cut.lines {
                        prop_assert!(full.lines.iter().any(|f| f.key == l.key && f.change == l.change));
                    }
                }
            }
        }
    }
}

#[test]
fn tm08_the_impact_test_compares_enough() {
    let mut s = Stats::default();
    for seed in 1..=120 {
        report_holds_every_change(seed, &mut s);
    }
    assert!(s.reports > 150, "{s:?}");
    assert!(s.gains > 100, "{s:?}");
    assert!(s.losses > 100, "{s:?}");
    assert!(s.actions > 20, "{s:?}");
    assert!(s.fields > 100, "{s:?}");
    assert!(s.conditional > 5, "{s:?}");
}

const OLD: &str = r#"
version = 1
[app]
name = "imp"

[types.project]
parent = "org"
container = true

[types.contract]
parent = "project"

[types.contract.fields]
title = { sensitivity = "internal" }
budget = { sensitivity = "confidential" }

[roles.staff]
grants = { project = "read", contract = "read" }
"#;

struct NoPaths;

impl ScopePaths for NoPaths {
    fn ancestors(
        &self,
        _: &tutela_contracts::tenant::TenantKey,
        _: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError> {
        Err(ScopePathError::NotFound)
    }
}

#[test]
fn it_reads_as_the_roadmap_says() {
    let org = PathEntry::org(&org_id(1)).unwrap();
    let p1 = entry("project", "p1");
    let p2 = entry("project", "p2");
    let data = TenantData {
        orgs: [org_id(1)].into(),
        bindings: vec![
            binding("ra_1", direct(&user(1)), "staff", p1.clone()),
            binding("ra_2", direct(&user(2)), "staff", p2.clone()),
            binding("ra_3", direct(&user(3)), "viewer", p2.clone()),
        ],
        ..TenantData::default()
    };
    let load = |source: &str| {
        let mut pdp = Pdp::new();
        let model = Arc::new(Model::from_toml(source).unwrap());
        pdp.load(tenant(1), 1, model, data.clone()).unwrap();
        pdp
    };
    let paths = Paths {
        map: [
            ((tenant(1), p1.clone()), vec![org.clone()]),
            ((tenant(1), p2.clone()), vec![org.clone()]),
        ]
        .into_iter()
        .collect(),
        ..Paths::default()
    };
    let new = OLD.replace(
        "grants = { project = \"read\", contract = \"read\" }",
        "grants = { project = \"read\", contract = \"write\" }",
    ) + "\n[[field_rules]]\nfield = \"contract.budget\"\nrole = \"staff\"\nmax = \"read\"\n";
    let r = model_impact(&load(OLD), &load(&new), &tenant(1), &paths, 10_000).unwrap();
    assert_eq!(
        r.summary(),
        vec![
            "2 users gain write on contract in 2 scopes",
            "2 users gain read on contract.budget in 2 scopes",
            "2 users gain write on contract.title in 2 scopes",
        ]
    );
    assert!(!r.no_impact());
    // The viewer keeps what it had, so it is in no line.
    assert!(
        r.lines
            .iter()
            .all(|l| !l.principals.contains(&user(3).to_string()))
    );

    // A change that nobody holds has no impact, and says so.
    let unused = OLD.to_owned() + "\n[roles.spare]\ngrants = { contract = \"full\" }\n";
    let r = model_impact(&load(OLD), &load(&unused), &tenant(1), &paths, 10_000).unwrap();
    assert!(r.no_impact(), "{r:?}");

    // The evaluators did not change, and a text change gives no line.
    let same = OLD.replace("name = \"imp\"", "name = \"imp\"\n");
    let r = model_impact(&load(OLD), &load(&same), &tenant(1), &NoPaths, 0).unwrap();
    assert!(r.no_impact(), "no difference needs no work: {r:?}");

    // A scope that cannot be placed fails closed.
    assert!(model_impact(&load(OLD), &load(&new), &tenant(1), &NoPaths, 10_000).is_err());
}
