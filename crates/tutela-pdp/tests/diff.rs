//! Diffs between models (docs/MANIFEST.md section 10): worked cases from
//! PERMISSION-MODEL.md section 17 and property tests for "no widening".

use proptest::prelude::*;
use tutela_pdp::model::{Class, DiffError, Model, diff};

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
        d.changes.iter().map(ToString::to_string).collect(),
    )
}

#[test]
fn the_same_model_has_no_changes() {
    let m = model(&tracker("confidential", ""));
    let d = diff(&m, &m).unwrap();
    assert!(d.changes.is_empty());
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
            .any(|l| l.contains("role `member` on `contract.budget`: none -> full"))
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
            .any(|l| l.contains("role `reviewer` on `contract.budget`: none -> read"))
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
    let open = base.replace(
        "approve = { needs = \"write\" }",
        "approve = { needs = \"write\", grant = false }",
    );
    let (c, lines) = classes(&no_grant, &open);
    assert_eq!(c, Class::Widening);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("role `member` on `contract:approve`: now allowed"))
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
    // A new secret field starts hidden: neutral.
    let secret = base.replace(
        "title    = {",
        "notes = { sensitivity = \"secret\" }\ntitle    = {",
    );
    assert_eq!(classes(&base, &secret).0, Class::Neutral);
    // A new type and a new role: neutral.
    let more = tracker(
        "confidential",
        "[types.memo]\nparent = \"matter\"\n[roles.auditor]\ngrants = { contract = \"read\" }\n",
    );
    let (c, lines) = classes(&base, &more);
    assert_eq!(c, Class::Neutral, "{lines:?}");
    // Removing them again: narrowing.
    assert_eq!(classes(&more, &base).0, Class::Narrowing);
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
        prop_assert!(!d.is_widening(), "{:?}", d.changes);
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
        prop_assert!(diff(&m, &m).unwrap().changes.is_empty());
    }
}
