//! Diffs between models (docs/MANIFEST.md section 10): worked cases from
//! PERMISSION-MODEL.md section 17 and property tests for "no widening".

use crate::model::{Class, DiffError, Model, diff};
use proptest::prelude::*;

fn model(src: &str) -> Model {
    Model::from_toml(src).unwrap()
}

/// A small contract tracker; `{extra}` is spliced in at the end.
fn tracker(budget: &str, extra: &str) -> String {
    format!(
        r#"
version = 1
[app]
name = "contracts"

[types.matter]
parent    = "org"
container = true

[types.contract]
parent = "matter"

[types.contract.fields]
title    = {{ sensitivity = "internal" }}
assignee = {{ sensitivity = "internal", type = "principal", grants_access = true }}
budget   = {{ sensitivity = "{budget}", type = "integer" }}

[types.contract.actions]
approve = {{ needs = "write" }}

[roles.reviewer]
grants = {{ matter = "read", contract = "write", "contract.title" = "read", "contract:approve" = true }}
{extra}
"#
    )
}

fn classes(old: &str, new: &str) -> (Class, Vec<String>) {
    let d = diff(&model(old), &model(new)).unwrap();
    (
        d.class(),
        d.changes().iter().map(ToString::to_string).collect(),
    )
}

#[test]
fn the_same_model_has_no_changes() {
    let m = model(&tracker("confidential", ""));
    let d = diff(&m, &m).unwrap();
    assert!(d.changes().is_empty());
    assert_eq!(d.class(), Class::Neutral);
}

#[test]
fn lowering_sensitivity_is_widening() {
    // PERMISSION-MODEL.md 17.8: budget confidential -> internal.
    let (c, lines) = classes(&tracker("confidential", ""), &tracker("internal", ""));
    assert_eq!(c, Class::Widening, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("contract.budget") && l.contains("sensitivity"))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("role `member` on `contract.budget` at the org root: none -> full"))
    );
    // And back is narrowing.
    let (c, _) = classes(&tracker("internal", ""), &tracker("confidential", ""));
    assert_eq!(c, Class::Narrowing);
}

#[test]
fn opening_a_hidden_field_for_one_role_is_widening() {
    // PERMISSION-MODEL.md 17.7: a role-specific rule loosens the all-roles
    // rule at the same scope.
    let rule =
        "[[field_rules]]\nfield = \"contract.budget\"\nrole = \"reviewer\"\nmax = \"read\"\n";
    let (c, lines) = classes(&tracker("confidential", ""), &tracker("confidential", rule));
    assert_eq!(c, Class::Widening);
    assert!(
        lines
            .iter()
            .any(|l| l
                .contains("role `reviewer` on `contract.budget` at the org root: none -> read"))
    );
}

#[test]
fn levels_grants_and_conditions() {
    let base = tracker("confidential", "");
    let raised = base.replace(
        "contract = \"write\", \"contract.title\"",
        "contract = \"full\", \"contract.title\"",
    );
    assert_eq!(classes(&base, &raised).0, Class::Widening);
    assert_eq!(classes(&raised, &base).0, Class::Narrowing);

    let no_grant = base.replace(", \"contract:approve\" = true", "");
    let (c, lines) = classes(&base, &no_grant);
    assert_eq!(c, Class::Narrowing, "{lines:?}");
    // Dropping the grant requirement lets every Write role approve.
    let open = no_grant.replace(
        "approve = { needs = \"write\" }",
        "approve = { needs = \"write\", grant = false }",
    );
    let (c, lines) = classes(&no_grant, &open);
    assert_eq!(c, Class::Widening);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("role `member` on `contract:approve`") && l.contains("now allowed"))
    );

    let cond = "[[conditions]]\nrole = \"reviewer\"\ntype = \"contract\"\nwhen = { is_principal = \"assignee\" }\nelse = \"read\"\n";
    assert_eq!(
        classes(&base, &tracker("confidential", cond)).0,
        Class::Narrowing
    );
    assert_eq!(
        classes(&tracker("confidential", cond), &base).0,
        Class::Widening
    );
    let changed = cond.replace("else = \"read\"", "else = \"none\"");
    // A changed condition is remove + add, so it counts as widening.
    assert_eq!(
        classes(
            &tracker("confidential", cond),
            &tracker("confidential", &changed)
        )
        .0,
        Class::Widening
    );
}

#[test]
fn new_things() {
    let base = tracker("confidential", "");
    // A new internal field is readable by every role with Read: widening.
    let field = base.replace(
        "title    = {",
        "notes = { sensitivity = \"internal\" }\ntitle    = {",
    );
    let (c, lines) = classes(&base, &field);
    assert_eq!(c, Class::Widening, "{lines:?}");
    // A new secret field is hidden at the org root, but a per-scope rule in
    // tutela-store (for example one left from before it was removed) could
    // open it, so it is widening too.
    let secret = base.replace(
        "title    = {",
        "notes = { sensitivity = \"secret\" }\ntitle    = {",
    );
    let (c, lines) = classes(&base, &secret);
    assert_eq!(c, Class::Widening, "{lines:?}");
    assert!(
        lines.iter().all(|l| !l.contains("notes` at the org root")),
        "{lines:?}"
    );
    // A new type and a new role are compared against a baseline where
    // nobody has anything: whoever gets access on them is widening.
    let more = tracker(
        "confidential",
        "[types.memo]\nparent = \"matter\"\n[roles.auditor]\ngrants = { contract = \"read\" }\n",
    );
    let (c, lines) = classes(&base, &more);
    assert_eq!(c, Class::Widening, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("role `member` on `memo`: none -> full"))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("role `auditor` on `contract`: none -> read"))
    );
    // A new role that gives nothing is neutral.
    let empty = tracker("confidential", "[roles.nobody]\n");
    assert_eq!(classes(&base, &empty).0, Class::Neutral);
    // Removing them again: narrowing.
    assert_eq!(classes(&more, &base).0, Class::Narrowing);
}

/// Review 1a: removing a type is narrowing, so it needs no token. Adding it
/// back with a weaker field must not be neutral.
#[test]
fn a_re_added_type_is_compared_against_nothing() {
    let rev_a = tracker("confidential", "");
    let rev_b = rev_a
        .replace("[types.contract]\nparent = \"matter\"\n", "")
        .replace(
            "[types.contract.fields]\ntitle    = { sensitivity = \"internal\" }\nassignee = { sensitivity = \"internal\", type = \"principal\", grants_access = true }\nbudget   = { sensitivity = \"confidential\", type = \"integer\" }\n\n[types.contract.actions]\napprove = { needs = \"write\" }\n",
            "",
        )
        .replace(
            "grants = { matter = \"read\", contract = \"write\", \"contract.title\" = \"read\", \"contract:approve\" = true }",
            "grants = { matter = \"read\" }",
        );
    assert_eq!(classes(&rev_a, &rev_b).0, Class::Narrowing);
    let rev_c = tracker("internal", "");
    let (c, lines) = classes(&rev_b, &rev_c);
    assert_eq!(c, Class::Widening, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("role `viewer` on `contract`: none -> read"))
    );
}

/// Review 1b: a confidential field is `none` at the org root for everyone,
/// but a per-scope rule can open it. Raising the role's own level is then
/// widening, even though the org-root level stays `none`.
#[test]
fn a_raised_level_under_a_root_cap_is_widening() {
    let base = tracker("confidential", "").replace(
        "\"contract.title\" = \"read\"",
        "\"contract.title\" = \"read\", \"contract.budget\" = \"read\"",
    );
    let raised = base.replace(
        "\"contract.budget\" = \"read\"",
        "\"contract.budget\" = \"write\"",
    );
    let (c, lines) = classes(&base, &raised);
    assert_eq!(c, Class::Widening, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("role `reviewer` on `contract.budget`"))
    );
    // Dropping the entry falls back to the type level (write): widening too.
    let dropped = base.replace(", \"contract.budget\" = \"read\"", "");
    assert_eq!(classes(&base, &dropped).0, Class::Widening);
}

/// Review 1c: conditions decide who sits at which level, so a lower `needs`
/// and an explicit feature level are widening even when the role's full
/// level hides them.
#[test]
fn lower_needs_and_feature_levels_are_widening() {
    let base = tracker("confidential", "");
    let read = base.replace(
        "approve = { needs = \"write\" }",
        "approve = { needs = \"read\" }",
    );
    let (c, lines) = classes(&base, &read);
    assert_eq!(c, Class::Widening, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("action `contract:approve` needs: write -> read"))
    );
    assert_eq!(classes(&read, &base).0, Class::Narrowing);
    let owner = base.replace(
        "approve = { needs = \"write\" }",
        "approve = { needs = \"owner\" }",
    );
    assert_eq!(classes(&owner, &base).0, Class::Widening);

    let ai = base.replace(
        "[types.contract]\nparent = \"matter\"\n",
        "[types.contract]\nparent = \"matter\"\nfeatures = [\"ai\"]\n",
    );
    let explicit = ai.replace(
        "\"contract.title\" = \"read\"",
        "\"contract.title\" = \"read\", \"contract.@ai\" = \"write\"",
    );
    let (c, lines) = classes(&ai, &explicit);
    assert_eq!(c, Class::Widening, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("on `contract.@ai` (item level read): read -> write"))
    );
}

#[test]
fn field_rule_and_ui_changes_get_lines() {
    let rule = |max: &str, display: &str| {
        tracker(
            "confidential",
            &format!(
                "[[field_rules]]\nfield = \"contract.title\"\nmax = \"{max}\"\ndisplay = \"{display}\"\n"
            ),
        )
    };
    let (c, lines) = classes(&rule("read", "restricted"), &rule("read", "remove"));
    assert_eq!(c, Class::Neutral);
    assert!(lines.iter().any(|l| l.contains("display changed")));
    assert_eq!(
        classes(&rule("read", "remove"), &rule("write", "remove")).0,
        Class::Widening
    );
    assert_eq!(
        classes(&rule("read", "remove"), &tracker("confidential", "")).0,
        Class::Widening
    );

    let ui = |actions: &str, routes: &str| {
        tracker(
            "confidential",
            &format!(
                "[ui.\"c.approve\"]\nactions = [{actions}]\nroutes = [{routes}]\nwhen_denied = \"hide\"\n"
            ),
        )
    };
    let full = ui(
        "\"contract:approve\", \"contract:write\"",
        "\"POST /a\", \"POST /b\"",
    );
    assert_eq!(
        classes(
            &full,
            &ui("\"contract:approve\"", "\"POST /a\", \"POST /b\"")
        )
        .0,
        Class::Widening
    );
    assert_eq!(
        classes(
            &full,
            &ui("\"contract:approve\", \"contract:write\"", "\"POST /a\"")
        )
        .0,
        Class::Widening
    );
    assert_eq!(
        classes(&full, &tracker("confidential", "")).0,
        Class::Widening
    );
    assert_eq!(
        classes(&tracker("confidential", ""), &full).0,
        Class::Neutral
    );
}

#[test]
fn boundaries_and_assignment() {
    let base = tracker("confidential", "");
    let private = base.replace(
        "container = true",
        "container = true\nstarts = \"private\"\nai_reach = \"project\"",
    );
    let team = base.replace("container = true", "container = true\nai_reach = \"team\"");
    assert_eq!(classes(&private, &base).0, Class::Widening);
    assert_eq!(classes(&base, &private).0, Class::Narrowing);
    assert_eq!(classes(&base, &team).0, Class::Widening);
    let to_agents = base.replace(
        "\"contract:approve\" = true }",
        "\"contract:approve\" = true }\nassignable_to = [\"user\"]",
    );
    assert_eq!(classes(&to_agents, &base).0, Class::Widening);
    let no_guard = base.replace(
        "type = \"principal\", grants_access = true",
        "type = \"principal\"",
    );
    assert_eq!(classes(&base, &no_guard).0, Class::Widening);
}

#[test]
fn other_apps_cannot_be_compared() {
    let a = model(&tracker("confidential", ""));
    let b = model(&tracker("confidential", "").replace("name = \"contracts\"", "name = \"crm\""));
    assert!(matches!(diff(&a, &b), Err(DiffError::AppMismatch { .. })));
}

// ---------- property tests ----------

const LEVELS: [&str; 4] = ["none", "read", "write", "full"];

/// A model with `types.len()` types and one role per entry of `roles`; each
/// role gives a level index per type and per field.
fn render(roles: &[Vec<(usize, usize)>], rules: &[(usize, usize)]) -> String {
    let mut s = String::from("version = 1\n[app]\nname = \"p\"\n");
    for t in 0..3 {
        s.push_str(&format!(
            "[types.t{t}]\nparent = \"org\"\ncontainer = true\n[types.t{t}.fields]\na = {{ sensitivity = \"internal\" }}\nb = {{ sensitivity = \"confidential\" }}\n"
        ));
    }
    for (i, r) in roles.iter().enumerate() {
        let mut grants = Vec::new();
        for (t, &(tl, fl)) in r.iter().enumerate() {
            grants.push(format!("t{t} = \"{}\"", LEVELS[tl]));
            grants.push(format!("\"t{t}.a\" = \"{}\"", LEVELS[fl.min(tl)]));
        }
        s.push_str(&format!(
            "[roles.r{i}]\ngrants = {{ {} }}\n",
            grants.join(", ")
        ));
    }
    for (i, &(t, max)) in rules.iter().enumerate() {
        s.push_str(&format!(
            "[[field_rules]]\nfield = \"t{t}.b\"\nrole = \"r{i}\"\nmax = \"{}\"\n",
            LEVELS[max]
        ));
    }
    s
}

fn levels() -> impl Strategy<Value = Vec<Vec<(usize, usize)>>> {
    prop::collection::vec(prop::collection::vec((0..4usize, 0..4usize), 3), 1..4)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Lowering levels and caps never counts as widening.
    #[test]
    fn lowering_is_never_widening(
        roles in levels(),
        cuts in prop::collection::vec((0..4usize, 0..4usize), 9),
        rule_max in prop::collection::vec(0..4usize, 3),
        rule_cut in prop::collection::vec(0..4usize, 3),
    ) {
        let rules: Vec<(usize, usize)> = (0..roles.len()).map(|i| (i % 3, rule_max[i])).collect();
        let lowered: Vec<Vec<(usize, usize)>> = roles.iter().enumerate().map(|(i, r)| {
            r.iter().enumerate().map(|(t, &(tl, fl))| {
                let (a, b) = cuts[(i * 3 + t) % cuts.len()];
                (tl.saturating_sub(a), fl.saturating_sub(b))
            }).collect()
        }).collect();
        let lowered_rules: Vec<(usize, usize)> = rules.iter().enumerate()
            .map(|(i, &(t, m))| (t, m.saturating_sub(rule_cut[i]))).collect();
        let old = Model::from_toml(&render(&roles, &rules)).unwrap();
        let new = Model::from_toml(&render(&lowered, &lowered_rules)).unwrap();
        let d = diff(&old, &new).unwrap();
        prop_assert!(!d.is_widening(), "{:?}", d.changes());
    }

    /// Raising one role's level on one type is always widening, and the
    /// reverse diff is never widening.
    #[test]
    fn raising_is_always_widening(roles in levels(), who in 0..4usize, t in 0..3usize) {
        let who = who % roles.len();
        prop_assume!(roles[who][t].0 < 3);
        let mut raised = roles.clone();
        raised[who][t].0 += 1;
        let old = Model::from_toml(&render(&roles, &[])).unwrap();
        let new = Model::from_toml(&render(&raised, &[])).unwrap();
        prop_assert!(diff(&old, &new).unwrap().is_widening());
        prop_assert!(!diff(&new, &old).unwrap().is_widening());
    }

    /// A diff of a model with itself is empty.
    #[test]
    fn a_model_equals_itself(roles in levels()) {
        let m = Model::from_toml(&render(&roles, &[])).unwrap();
        prop_assert!(diff(&m, &m).unwrap().changes().is_empty());
    }
}

/// Owner-only means Full on the item and the grant, everywhere. So making
/// an action owner-only is narrowing, and a reviewer narrowed by a condition
/// can no longer approve (re-review must-fix 1).
#[test]
fn owner_only_needs_full_and_the_grant() {
    let cond = "[[conditions]]\nrole = \"reviewer\"\ntype = \"contract\"\nwhen = { is_principal = \"assignee\" }\nelse = \"read\"\n";
    let base = tracker("confidential", cond);
    let owner = base.replace(
        "approve = { needs = \"write\" }",
        "approve = { needs = \"owner\" }",
    );
    let (c, lines) = classes(&base, &owner);
    assert_eq!(c, Class::Narrowing, "{lines:?}");
    assert_eq!(classes(&owner, &base).0, Class::Widening);
    let m = model(&owner);
    let approve = tutela_contracts::keys::ActionKey::parse("contract:approve").unwrap();
    let reviewer = crate::model::RoleKey::parse("reviewer").unwrap();
    // Write and the grant are not enough.
    assert!(!m.allows_custom(&reviewer, &approve));
    // The seeded owner has Full and every grant.
    assert!(m.allows_custom(&crate::model::RoleKey::parse("owner").unwrap(), &approve));
    // A role with Full but no grant may not.
    assert!(!m.allows_custom(&crate::model::RoleKey::parse("member").unwrap(), &approve));
}

#[test]
fn undeclared_fields_are_none() {
    let m = model(&tracker("confidential", ""));
    let reviewer = crate::model::RoleKey::parse("reviewer").unwrap();
    for k in ["contract.nope", "contract.@ai", "nope.title"] {
        let k = tutela_contracts::keys::FieldKey::parse(k).unwrap();
        assert_eq!(
            m.effective_field_level(&reviewer, &k, tutela_contracts::level::Level::Full),
            tutela_contracts::level::Level::None
        );
    }
}

/// Removing a rule for one role falls back to the all-roles rule. For a
/// hidden field that is `none`, so the removal is a revocation (narrowing),
/// not widening.
#[test]
fn a_removed_role_rule_is_judged_by_the_cap_that_replaces_it() {
    let with = tracker(
        "confidential",
        "[[field_rules]]\nfield = \"contract.budget\"\nrole = \"reviewer\"\nmax = \"read\"\n",
    );
    let without = tracker("confidential", "");
    let (c, lines) = classes(&with, &without);
    assert_eq!(c, Class::Narrowing, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("removed (max read -> none)")),
        "{lines:?}"
    );
}

#[test]
fn diff_lines_are_capped_but_the_class_is_exact() {
    let small = "version = 1\n[app]\nname = \"p\"\n".to_string();
    let mut big = small.clone();
    for t in 0..200 {
        big.push_str(&format!(
            "[types.t{t}]\nparent = \"org\"\n[types.t{t}.fields]\n"
        ));
        for f in 0..20 {
            big.push_str(&format!("f{f} = {{ sensitivity = \"internal\" }}\n"));
        }
    }
    let d = diff(&model(&small), &model(&big)).unwrap();
    assert_eq!(d.changes().len(), crate::model::MAX_DIFF_LINES);
    assert!(d.omitted() > 0);
    assert_eq!(d.class(), Class::Widening);
    // Widening lines come first.
    assert_eq!(d.changes()[0].class, Class::Widening);
}

/// Two conditions with the same `else` are still two lines, so omitted()
/// counts unique lines.
#[test]
fn conditions_with_the_same_else_are_separate_lines() {
    let two = "[[conditions]]\nrole = \"reviewer\"\ntype = \"contract\"\nwhen = { is_principal = \"assignee\" }\nelse = \"read\"\n[[conditions]]\nrole = \"reviewer\"\ntype = \"contract\"\nwhen = { not = { is_principal = \"assignee\" } }\nelse = \"read\"\n";
    let d = diff(
        &model(&tracker("confidential", "")),
        &model(&tracker("confidential", two)),
    )
    .unwrap();
    assert_eq!(d.omitted(), 0);
    let added = d
        .changes()
        .iter()
        .filter(|c| c.what.contains("was added"))
        .count();
    assert_eq!(added, 2, "{:?}", d.changes());
}
