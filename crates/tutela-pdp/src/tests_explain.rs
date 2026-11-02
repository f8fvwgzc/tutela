//! Explain on the worked example (PERMISSION-MODEL.md 17).

use crate::RuleExplained;
use crate::tests_check::{
    CLAUSE, JAE, MINA, agent, board, c204, delegated, kestrel, path_of, req, sup, user,
};

#[test]
fn an_explanation_is_the_decision_and_its_reasons() {
    let pdp = kestrel();
    let r = req(&user(MINA), "contract:read", c204());
    let e = pdp.explain(&r).unwrap();
    // The decision is check's, field for field.
    assert_eq!(e.decision, pdp.check(&r).unwrap());
    let side = &e.sides[0];
    assert_eq!(side.outcome, "assignment");
    assert!(!side.org_owner);
    // C-204, then the matter where Mina is a legal reviewer: the walk stops.
    assert_eq!(side.walk.len(), 2);
    assert_eq!(side.walk[1].scope, sup());
    assert!(side.walk[1].private);
    assert_eq!(side.walk[1].assignments.len(), 1);
    // Every rule id is described, in the decision's order.
    assert_eq!(e.rules.len(), e.decision.rule_ids.len());
    assert!(matches!(
        &e.rules[0],
        RuleExplained::Assignment { role, subject, .. }
            if role == "legal_reviewer" && *subject == user(MINA).to_string()
    ));
    assert!(e.rules.iter().any(|x| matches!(
        x,
        RuleExplained::ModelFieldRule { field, max, role: None, .. }
            if field == "contract.budget" && max == "none"
    )));
}

#[test]
fn an_explanation_follows_a_private_scope_and_the_overlap() {
    let pdp = kestrel();
    // C-311 sits in the board's private matter: the walk stops there.
    let mut path = vec![board()];
    path.extend(path_of(&board()));
    let r = req(
        &user(JAE),
        "contract:read",
        crate::ResourceRef {
            path,
            ..crate::tests_check::resource_of("contract", "c-311")
        },
    );
    let e = pdp.explain(&r).unwrap();
    assert_eq!(e.sides[0].outcome, "private_scope");
    assert!(e.sides[0].walk.last().unwrap().private);
    assert!(e.rules.is_empty());

    // Jae and the agent: two walks, the person's first.
    let d = delegated(&user(JAE), &agent(CLAUSE), "contract:read", c204());
    let e = pdp.explain(&d).unwrap();
    assert_eq!(e.sides.len(), 2);
    assert_eq!(e.sides[1].principal, agent(CLAUSE).to_string());
    assert!(e.rules.iter().any(|x| matches!(
        x,
        RuleExplained::Assignment { subject, role, .. }
            if *subject == agent(CLAUSE).to_string() && role == "agent"
    )));
}
