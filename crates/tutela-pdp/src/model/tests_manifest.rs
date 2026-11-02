//! The model compiler against docs/MANIFEST.md: one good manifest (the
//! worked example of PERMISSION-MODEL.md section 17) and one test per rule
//! that must refuse a manifest.

use crate::model::{
    FieldDisplay, Issues, MAX_MANIFEST_BYTES, Model, RoleKey, SeededRole, Sensitivity, Starts,
    SubjectKind, Template,
};
use tutela_contracts::keys::{ActionKey, FieldKey, ResourceType};
use tutela_contracts::level::Level;

/// The Kestrel Foods contract tracker (PERMISSION-MODEL.md section 17).
const KESTREL: &str = r#"
version = 1

[app]
name     = "contracts"
audience = "contracts"

[types.department]
parent    = "org"
container = true

[types.matter]
parent    = "department"
container = true
starts    = "private"
ai_reach  = "project"

[types.contract]
parent    = "matter"
container = true
features  = ["chat", "files", "ai"]

[types.contract.fields]
title        = { sensitivity = "internal" }
counterparty = { sensitivity = "internal" }
status       = { sensitivity = "internal" }
review_notes = { sensitivity = "internal" }
assignee     = { sensitivity = "internal", type = "principal", grants_access = true }
budget       = { sensitivity = "confidential", type = "integer" }

[types.contract.actions]
approve = { needs = "write" }

[types.invoice]
parent = "contract"

[types.invoice.fields]
number = { sensitivity = "internal" }
amount = { sensitivity = "confidential", type = "integer" }

[roles.viewer]
label  = "Viewer"
grants = { department = "read", matter = "read", contract = "read", invoice = "read", "contract.@chat" = "read", "contract.@ai" = "write" }

[roles.legal_reviewer]
label  = "Legal reviewer"
grants = { matter = "read", contract = "write", invoice = "read", "contract.title" = "read", "contract.counterparty" = "read", "contract.assignee" = "read", "contract.@chat" = "write", "contract.@ai" = "write", "contract:approve" = true }
assignable_to = ["user", "group"]

[roles.agent]
grants = { matter = "read", contract = "write", invoice = "read" }
assignable_to = ["agent"]

[[conditions]]
role = "agent"
type = "contract"
when = { is_principal = "assignee" }
else = "read"

[ui."contracts.approve_button"]
actions     = ["contract:approve"]
routes      = ["POST /api/contracts/{id}/approve"]
when_denied = "disable"
reason      = "Only reviewers can approve contracts."

[ui."contracts.budget_cell"]
fields      = ["contract.budget"]
routes      = ["PATCH /api/contracts/{id}"]
when_denied = "hide"
"#;

fn ty(s: &str) -> ResourceType {
    ResourceType::parse(s).unwrap()
}
fn field(s: &str) -> FieldKey {
    FieldKey::parse(s).unwrap()
}
fn role(s: &str) -> RoleKey {
    RoleKey::parse(s).unwrap()
}

#[test]
fn the_worked_example_compiles() {
    let m = Model::from_toml(KESTREL).unwrap();
    assert_eq!(m.app().as_str(), "contracts");
    assert_eq!(m.types().len(), 4);
    assert_eq!(m.types()[&ty("matter")].starts, Starts::Private);

    // Seeded roles are there; viewer was replaced by the manifest.
    for s in SeededRole::ALL {
        assert_eq!(m.roles()[&role(s.key())].seeded, Some(s));
    }
    assert_eq!(m.roles()[&role("viewer")].label.as_deref(), Some("Viewer"));
    assert_eq!(
        m.roles()[&role("member")].level(&ty("invoice")),
        Level::Full
    );
    // 17.4: a Viewer reads the contract and may ask the AI about it.
    assert_eq!(
        m.root_field_level(&role("viewer"), &field("contract.@ai")),
        Level::Write
    );
    assert_eq!(
        m.root_field_level(&role("viewer"), &field("contract.title")),
        Level::Read
    );

    // The Correction: budget and amount start at None for every role, even
    // for the org Owner (it opens them only through break-glass).
    for r in m.roles().keys() {
        assert_eq!(
            m.root_field_level(r, &field("contract.budget")),
            Level::None
        );
        assert_eq!(m.root_field_level(r, &field("invoice.amount")), Level::None);
    }
    let implicit: Vec<_> = m.field_rules().iter().filter(|r| r.implicit).collect();
    assert_eq!(implicit.len(), 2);
    assert!(
        implicit
            .iter()
            .all(|r| r.role.is_none() && r.max == Level::None)
    );
    assert!(
        implicit
            .iter()
            .all(|r| r.display == FieldDisplay::Restricted)
    );

    // Legal reviewer, 17.2: title read, status write, may approve.
    let lr = role("legal_reviewer");
    assert_eq!(
        m.root_field_level(&lr, &field("contract.title")),
        Level::Read
    );
    assert_eq!(
        m.root_field_level(&lr, &field("contract.status")),
        Level::Write
    );
    assert!(m.allows_custom(&lr, &ActionKey::parse("contract:approve").unwrap()));
    assert!(!m.allows_custom(
        &role("member"),
        &ActionKey::parse("contract:approve").unwrap()
    ));
    assert!(m.allows_custom(
        &role("owner"),
        &ActionKey::parse("contract:approve").unwrap()
    ));

    // The owner holds every admin key, and no agent can hold the owner role.
    let owner = &m.roles()[&role("owner")];
    assert!(owner.holds(&ActionKey::parse("matter:manage_fields").unwrap()));
    assert!(!owner.assignable_to.contains(&SubjectKind::Principal(
        tutela_contracts::principal::PrincipalKind::Agent
    )));

    // C-1: the declared agent writes contracts only when it is the assignee.
    assert_eq!(m.conditions().len(), 1);
    let c1 = &m.conditions()[0];
    assert_eq!(c1.role, role("agent"));
    assert_eq!(c1.resource_type, ty("contract"));
    assert_eq!(
        c1.when,
        Template::IsPrincipal {
            field: tutela_contracts::keys::FieldName::parse("assignee").unwrap()
        }
    );
    assert_eq!(c1.otherwise, Level::Read);
    let agent = &m.roles()[&role("agent")];
    assert_eq!(agent.level(&ty("contract")), Level::Write);
    assert_eq!(
        agent.assignable_to,
        [SubjectKind::Principal(
            tutela_contracts::principal::PrincipalKind::Agent
        )]
        .into()
    );

    assert_eq!(
        m.types()[&ty("contract")].fields
            [&tutela_contracts::keys::FieldName::parse("budget").unwrap()]
            .sensitivity,
        Sensitivity::Confidential
    );
    assert_eq!(m.ui().len(), 2);
}

/// Compiles and returns the issue texts, or panics if it compiled.
fn issues(src: &str) -> Vec<String> {
    match Model::from_toml(src) {
        Ok(_) => panic!("expected the manifest to be refused:\n{src}"),
        Err(Issues(v)) => v.iter().map(ToString::to_string).collect(),
    }
}

fn refused(src: &str, needle: &str) {
    let got = issues(src);
    assert!(
        got.iter().any(|i| i.contains(needle)),
        "expected an issue containing {needle:?}, got {got:?}"
    );
}

const HEAD: &str = "version = 1\n[app]\nname = \"crm\"\n";

fn with(body: &str) -> String {
    format!("{HEAD}{body}")
}

const PROJECT: &str = "[types.project]\nparent = \"org\"\ncontainer = true\n";

#[test]
fn unknown_keys_are_refused() {
    refused(&with("colour = 1\n"), "unknown field");
    refused(
        &with("[types.project]\nparent = \"org\"\nparnet = \"org\"\n"),
        "unknown field",
    );
    refused(
        &with(
            "[types.p]\nparent = \"org\"\n[types.p.fields]\na = { sensitivity = \"internal\", grant_access = true }\n",
        ),
        "unknown field",
    );
}

#[test]
fn version_must_be_one() {
    refused(
        "version = 2\n[app]\nname = \"crm\"\n",
        "the only manifest version is 1",
    );
}

#[test]
fn app_and_type_names_follow_the_grammar() {
    refused("version = 1\n[app]\nname = \"Crm\"\n", "app.name");
    refused(
        "version = 1\n[app]\nname = \"crm\"\naudience = \"Bad Aud\"\n",
        "app.audience",
    );
    refused(
        &with("[types.Invoice]\nparent = \"org\"\n"),
        "types.Invoice",
    );
    refused(&with("[types.org]\nparent = \"org\"\n"), "reserved");
    refused(&with("[types.tutela_role]\nparent = \"org\"\n"), "reserved");
}

#[test]
fn parents_must_be_declared_containers_and_reach_org() {
    refused(
        &with("[types.invoice]\nparent = \"project\"\n"),
        "not a declared type",
    );
    refused(
        &with("[types.project]\nparent = \"org\"\n[types.invoice]\nparent = \"project\"\n"),
        "not a container",
    );
    // a and b only point at each other: they never reach org.
    refused(
        &with(
            "[types.a]\nparent = \"b\"\ncontainer = true\n[types.b]\nparent = \"a\"\ncontainer = true\n",
        ),
        "never reaches `org`",
    );
    refused(&with("[types.a]\nparent = []\n"), "at least one parent");
    // A folder may live in a folder.
    Model::from_toml(&with(
        "[types.folder]\nparent = [\"org\", \"folder\"]\ncontainer = true\n",
    ))
    .unwrap();
}

#[test]
fn container_keys_and_their_values() {
    refused(
        &with("[types.p]\nparent = \"org\"\nstarts = \"private\"\n"),
        "containers only",
    );
    refused(
        &with("[types.p]\nparent = \"org\"\ncontainer = true\nstarts = \"closed\"\n"),
        "`open` or `private`",
    );
    refused(
        &with("[types.p]\nparent = \"org\"\ncontainer = true\nai_reach = \"org\"\n"),
        "nothing wider",
    );
}

#[test]
fn fields_features_and_actions() {
    refused(
        &with("[types.p]\nparent = \"org\"\n[types.p.fields]\na = { sensitivity = \"top\" }\n"),
        "sensitivity",
    );
    refused(
        &with(
            "[types.p]\nparent = \"org\"\n[types.p.fields]\na = { sensitivity = \"internal\", type = \"float\" }\n",
        ),
        ".type",
    );
    refused(
        &with("[types.p]\nparent = \"org\"\nfeatures = [\"ai\", \"ai\"]\n"),
        "listed twice",
    );
    refused(
        &with("[types.p]\nparent = \"org\"\nfeatures = [\"@ai\"]\n"),
        "features",
    );
    refused(
        &with("[types.p]\nparent = \"org\"\n[types.p.actions]\nread = { needs = \"read\" }\n"),
        "cannot be declared",
    );
    refused(
        &with(
            "[types.p]\nparent = \"org\"\n[types.p.actions]\nmanage_fields = { needs = \"full\" }\n",
        ),
        "cannot be declared",
    );
    refused(
        &with("[types.p]\nparent = \"org\"\n[types.p.actions]\nx = { needs = \"none\" }\n"),
        "`owner`",
    );
    refused(
        &with(
            "[types.p]\nparent = \"org\"\n[types.p.actions]\nx = { needs = \"owner\", grant = false }\n",
        ),
        "always needs a grant",
    );
}

#[test]
fn roles_follow_the_rules() {
    let base = format!(
        "{PROJECT}features = [\"ai\"]\n[types.project.fields]\nname = {{ sensitivity = \"internal\" }}\n[types.project.actions]\nexport = {{ needs = \"read\", grant = false }}\narchive = {{ needs = \"full\" }}\n"
    );
    let role = |grants: &str| with(&format!("{base}[roles.r]\ngrants = {{ {grants} }}\n"));
    Model::from_toml(&role(
        "project = \"write\", \"project.name\" = \"read\", \"project:archive\" = true",
    ))
    .unwrap();
    refused(
        &with(&format!("{base}[roles.owner]\ngrants = {{}}\n")),
        "cannot be declared or changed",
    );
    refused(&role("project = \"admin\""), "takes a level");
    refused(&role("nope = \"read\""), "not a declared type");
    refused(
        &role("project = \"read\", \"project.nope\" = \"read\""),
        "not a declared field",
    );
    refused(
        &role("project = \"read\", \"project.name\" = \"write\""),
        "above the role's level",
    );
    refused(&role("\"project.@ai\" = \"read\""), "needs at least `read`");
    // A feature may be above the type level: a viewer may ask the AI.
    Model::from_toml(&role("project = \"read\", \"project.@ai\" = \"write\"")).unwrap();
    refused(&role("\"project:read\" = true"), "come from levels");
    refused(&role("\"project:archive\" = false"), "leave it out");
    refused(&role("\"project:export\" = true"), "needs no grant");
    refused(
        &role("\"project:nope\" = true"),
        "not a declared custom action",
    );
    // Admin keys never reach agents.
    refused(
        &with(&format!(
            "{base}[roles.r]\ngrants = {{ \"project:manage_access\" = true }}\nassignable_to = [\"user\", \"agent\"]\n"
        )),
        "never be assigned to an agent",
    );
    let m = Model::from_toml(&role("\"project:manage_fields\" = true")).unwrap();
    let r = &m.roles()[&RoleKey::parse("r").unwrap()];
    assert!(r.has_admin_key());
    assert!(!r.assignable_to.contains(&SubjectKind::Principal(
        tutela_contracts::principal::PrincipalKind::Agent
    )));
    refused(
        &with(&format!("{base}[roles.r]\nassignable_to = [\"robot\"]\n")),
        "is not one of",
    );
}

#[test]
fn field_rules_follow_the_rules() {
    let base = format!(
        "{PROJECT}[types.project.fields]\nname = {{ sensitivity = \"internal\" }}\nbudget = {{ sensitivity = \"secret\" }}\n"
    );
    let rule = |r: &str| with(&format!("{base}[[field_rules]]\n{r}\n"));
    let m = Model::from_toml(&rule(
        "field = \"project.budget\"\nrole = \"member\"\nmax = \"read\"",
    ))
    .unwrap();
    assert_eq!(
        m.root_field_level(
            &RoleKey::parse("member").unwrap(),
            &FieldKey::parse("project.budget").unwrap()
        ),
        Level::Read
    );
    assert_eq!(
        m.root_field_level(
            &RoleKey::parse("viewer").unwrap(),
            &FieldKey::parse("project.budget").unwrap()
        ),
        Level::None
    );
    refused(
        &rule("field = \"project.budget\"\nmax = \"read\""),
        "already has an all-roles rule",
    );
    refused(
        &rule("field = \"project.nope\"\nmax = \"read\""),
        "not a declared field",
    );
    refused(
        &rule("field = \"project.name\"\nrole = \"nobody\"\nmax = \"read\""),
        "not a role",
    );
    refused(
        &rule("field = \"project.name\"\nmax = \"read\"\ndisplay = \"blur\""),
        "`restricted` or `remove`",
    );
    refused(
        &with(&format!(
            "{base}[[field_rules]]\nfield = \"project.name\"\nmax = \"read\"\n[[field_rules]]\nfield = \"project.name\"\nmax = \"none\"\n"
        )),
        "already declared",
    );
}

/// A bad key reaches the manifest's author with its reason. A key error's
/// own text leaves the reason in its source.
#[test]
fn a_bad_key_says_why() {
    let want = "invalid name: a name must start with a lowercase letter a-z";
    let base =
        format!("{PROJECT}[types.project.fields]\nname = {{ sensitivity = \"internal\" }}\n");
    refused(
        &with(&format!(
            "{base}[roles.r]\ngrants = {{ \"project.Name\" = \"read\" }}\n"
        )),
        want,
    );
    refused(
        &with(&format!(
            "{base}[[field_rules]]\nfield = \"project.Name\"\nmax = \"read\"\n"
        )),
        want,
    );
    refused(
        &with(&format!(
            "{base}[ui.\"a.B\"]\nactions = [\"project:read\"]\nroutes = [\"GET /x\"]\nwhen_denied = \"hide\"\n"
        )),
        want,
    );
}

#[test]
fn conditions_use_only_vetted_templates() {
    let base = format!(
        "{PROJECT}[types.project.fields]\nowner_id = {{ sensitivity = \"internal\", type = \"principal\", grants_access = true }}\nstatus = {{ sensitivity = \"internal\", grants_access = true }}\nprio = {{ sensitivity = \"internal\", type = \"integer\", grants_access = true }}\ntags = {{ sensitivity = \"internal\", type = \"string_list\", grants_access = true }}\nnote = {{ sensitivity = \"internal\" }}\n"
    );
    let cond = |role: &str, when: &str, otherwise: &str| {
        with(&format!(
            "{base}[[conditions]]\nrole = \"{role}\"\ntype = \"project\"\nwhen = {when}\nelse = \"{otherwise}\"\n"
        ))
    };
    Model::from_toml(&cond("member", "{ and = [{ eq = { field = \"status\", value = \"open\" } }, { not = { contains = { field = \"tags\", value = \"x\" } } }] }", "read")).unwrap();
    Model::from_toml(&cond(
        "member",
        "{ in = { field = \"prio\", values = [1, 2] } }",
        "none",
    ))
    .unwrap();
    Model::from_toml(&cond("member", "{ in_group = \"reviewers\" }", "read")).unwrap();
    refused(
        &cond("owner", "{ is_principal = \"owner_id\" }", "read"),
        "cannot have conditions",
    );
    refused(
        &cond("viewer", "{ is_principal = \"owner_id\" }", "write"),
        "conditions only narrow",
    );
    refused(
        &cond(
            "member",
            "{ eq = { field = \"note\", value = \"x\" } }",
            "read",
        ),
        "grants_access = true",
    );
    refused(
        &cond(
            "member",
            "{ eq = { field = \"prio\", value = \"1\" } }",
            "read",
        ),
        "does not match",
    );
    refused(
        &cond(
            "member",
            "{ eq = { field = \"owner_id\", value = \"user:x\" } }",
            "read",
        ),
        "is_principal",
    );
    refused(
        &cond(
            "member",
            "{ contains = { field = \"status\", value = \"x\" } }",
            "read",
        ),
        "`string_list` fields only",
    );
    refused(
        &cond("member", "{ is_principal = \"status\" }", "read"),
        "`principal` fields only",
    );
    refused(
        &cond("member", "{ and = [{ in_group = \"a\" }] }", "read"),
        "2 to 16",
    );
    refused(
        &cond(
            "member",
            "{ in = { field = \"prio\", values = [] } }",
            "read",
        ),
        "1 to 64",
    );
    refused(
        &cond(
            "member",
            "{ regex = { field = \"status\", value = \".*\" } }",
            "read",
        ),
        "unknown variant",
    );
    refused(
        &cond(
            "member",
            "{ not = { not = { not = { not = { in_group = \"a\" } } } } }",
            "read",
        ),
        "4 levels",
    );
    refused(
        &cond(
            "member",
            "{ eq = { field = \"nope\", value = \"x\" } }",
            "read",
        ),
        "not a declared data field",
    );
    let many = vec!["{ in_group = \"g\" }"; 16].join(", ");
    let wide =
        format!("{{ and = [{{ or = [{many}] }}, {{ or = [{many}] }}, {{ or = [{many}] }}] }}");
    refused(&cond("member", &wide, "read"), "32 nodes");
}

#[test]
fn ui_keys_name_actions_fields_and_routes() {
    let base =
        format!("{PROJECT}[types.project.fields]\nname = {{ sensitivity = \"internal\" }}\n");
    let u = |body: &str| with(&format!("{base}[ui.\"projects.edit\"]\n{body}\n"));
    Model::from_toml(&u("actions = [\"project:write\", \"project:manage_access\"]\nroutes = [\"PATCH /api/projects/{id}\"]\nwhen_denied = \"disable\"")).unwrap();
    refused(
        &u("routes = [\"PATCH /x\"]\nwhen_denied = \"hide\""),
        "at least one action or field",
    );
    refused(
        &u("actions = [\"project:write\"]\nwhen_denied = \"hide\""),
        "1 to 16 routes",
    );
    refused(
        &u("actions = [\"project:write\"]\nroutes = [\"FETCH /x\"]\nwhen_denied = \"hide\""),
        "METHOD /path",
    );
    refused(
        &u("actions = [\"project:write\"]\nroutes = [\"GET x\"]\nwhen_denied = \"hide\""),
        "METHOD /path",
    );
    refused(
        &u("actions = [\"project:write\"]\nroutes = [\"GET /x?y=1\"]\nwhen_denied = \"hide\""),
        "METHOD /path",
    );
    refused(
        &u("actions = [\"project:write\"]\nroutes = [\"GET /x/{id\"]\nwhen_denied = \"hide\""),
        "METHOD /path",
    );
    refused(
        &u("actions = [\"project:fly\"]\nroutes = [\"GET /x\"]\nwhen_denied = \"hide\""),
        "not an action",
    );
    refused(
        &u("fields = [\"project.nope\"]\nroutes = [\"GET /x\"]\nwhen_denied = \"hide\""),
        "not a declared field",
    );
    refused(
        &u("actions = [\"project:write\"]\nroutes = [\"GET /x\"]\nwhen_denied = \"blur\""),
        "when_denied",
    );
    refused(
        &with(&format!(
            "{base}[ui.\"single\"]\nactions = [\"project:write\"]\nroutes = [\"GET /x\"]\nwhen_denied = \"hide\"\n"
        )),
        "ui.\"single\"",
    );
}

#[test]
fn every_problem_is_reported_at_once() {
    let got = issues(&with(
        "[types.Bad]\nparent = \"org\"\n[types.x]\nparent = \"nowhere\"\n[roles.owner]\n",
    ));
    assert!(got.len() >= 3, "{got:?}");
}

#[test]
fn oversized_and_hostile_input_is_refused() {
    let big = format!("{HEAD}# {}\n", "x".repeat(MAX_MANIFEST_BYTES));
    refused(&big, "larger than 4 MiB");
    // Deep nesting must give an error, not a crash.
    let deep = format!(
        "{PROJECT}[[conditions]]\nrole = \"member\"\ntype = \"project\"\nwhen = {}{{ in_group = \"a\" }}{}\nelse = \"read\"\n",
        "{ not = ".repeat(5_000),
        " }".repeat(5_000)
    );
    refused(&with(&deep), "nest more than 32 levels");
    // Brackets inside strings and comments do not count.
    let quoted = format!(
        "{HEAD}# {}\n[types.p]\nparent = \"org\"\nlabel = \"{}\"\n",
        "[".repeat(100),
        "{".repeat(100)
    );
    Model::from_toml(&quoted).unwrap();
    assert!(Model::from_toml("not toml at all [").is_err());
}

/// Dotted keys open one table per part without any bracket, and the `toml`
/// crate builds and drops its tree recursively, also for input it refuses.
/// Deep input must give an error, never a stack overflow, even on a thread
/// with a 2 MiB stack (review must-fix 2, both rounds).
#[test]
fn deep_input_cannot_exhaust_the_stack() {
    let parts = |n: usize, p: &str| {
        (0..n)
            .map(|i| format!("{p}{i}"))
            .collect::<Vec<_>>()
            .join(".")
    };
    // The deepest input the pre-scan lets through: a 9-part dotted header,
    // then 32 nested multi-line inline tables, each opened by a 9-part key,
    // and a 9-part key inside the last one.
    let mut deepest = format!("{HEAD}[{}]\n", parts(9, "h"));
    for d in 0..32 {
        deepest.push_str(&format!("{} = {{\n", parts(9, &format!("k{d}_"))));
    }
    deepest.push_str(&format!("{} = 1\n", parts(9, "x")));
    deepest.push_str(&"}\n".repeat(32));
    let cases: Vec<(String, &str)> = vec![
        // A quote inside a bare word hid the rest of the line from the scan.
        (
            format!("{HEAD}x = [ a', {{ {} = 1 }} ]\n", parts(80, "k")),
            "a quote may only start",
        ),
        // `\` + line break kept the scan inside a basic string.
        (
            format!(
                "{HEAD}x = \"abc\\\ny = {}1{}\n",
                "[".repeat(60),
                "]".repeat(60)
            ),
            "not closed on its line",
        ),
        (format!("{HEAD}{} = 1\n", parts(80, "k")), "more than 8 `.`"),
        (format!("{HEAD}[[{}]]\n", parts(80, "h")), "more than 8 `.`"),
        (
            format!("{HEAD}a.b.c.d.e.f.g.h.i.j = 1\n"),
            "more than 8 `.`",
        ),
        // The lexer ends a comment at a lone CR, and so does the scan.
        (
            format!("{HEAD}# x\r{} = 1\n", parts(80, "k")),
            "more than 8 `.`",
        ),
        // Three quotes and at most two more end a multi-line string; a
        // further quote starts a new token, which the scan refuses.
        (
            format!("{HEAD}x = \"\"\"a\"\"\"\"\"\"\"\"\n"),
            "a quote may only start",
        ),
        (
            format!("{HEAD}x = '''a''''''''\n"),
            "a quote may only start",
        ),
        (format!("{HEAD}x = [ {{ ] }}\n"), "does not match"),
        (deepest, "unknown field"),
    ];
    let handle = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            cases
                .into_iter()
                .map(|(src, want)| match Model::from_toml(&src) {
                    Ok(_) => Err(format!("compiled, expected {want:?}")),
                    Err(Issues(v)) if v.iter().any(|i| i.message.contains(want)) => Ok(()),
                    Err(Issues(v)) => Err(format!("expected {want:?}, got {v:?}")),
                })
                .collect::<Vec<_>>()
        })
        .unwrap();
    for r in handle.join().unwrap() {
        assert_eq!(r, Ok(()));
    }
}

#[test]
fn a_multi_line_string_may_end_with_extra_quotes() {
    // `"""a""""` is the string `a"`. The brackets after it on the same line
    // are outside the string and must count.
    let src = format!(
        "{HEAD}[types.p]\nparent = \"org\"\nf = {{ s = \"\"\"a\"\"\"\", t = {}1{} }}\n",
        "[".repeat(40),
        "]".repeat(40)
    );
    refused(&src, "nest more than 32 levels");
}

#[test]
fn every_count_limit_is_enforced_before_any_other_work() {
    let many = |n: usize, f: &dyn Fn(usize) -> String| (0..n).map(f).collect::<String>();
    refused(
        &with(&many(513, &|i| format!("[types.t{i}]\nparent = \"org\"\n"))),
        "at most 512 types",
    );
    refused(
        &with(&many(508, &|i| format!("[roles.r{i}]\n"))),
        "at most 512 roles",
    );
    // Replacing seeded roles does not count twice.
    Model::from_toml(&with(&format!(
        "{}[roles.member]\n[roles.viewer]\n",
        many(507, &|i| format!("[roles.r{i}]\n"))
    )))
    .unwrap();
    let field =
        format!("{PROJECT}[types.project.fields]\nname = {{ sensitivity = \"internal\" }}\n");
    refused(
        &with(&format!(
            "{field}{}",
            many(10_001, &|_| {
                "[[field_rules]]\nfield = \"project.name\"\nmax = \"read\"\n".to_string()
            })
        )),
        "at most 10,000 field rules",
    );
    refused(
        &with(&format!(
            "{field}{}",
            many(1_001, &|_| {
                "[[conditions]]\nrole = \"member\"\ntype = \"project\"\nwhen = { in_group = \"a\" }\nelse = \"read\"\n".to_string()
            })
        )),
        "at most 1,000 conditions",
    );
    refused(
        &with(&format!(
            "{PROJECT}{}",
            many(2_001, &|i| format!(
                "[ui.\"a.k{i}\"]\nactions = [\"project:read\"]\nroutes = [\"GET /x\"]\nwhen_denied = \"hide\"\n"
            ))
        )),
        "at most 2,000 UI keys",
    );
    refused(
        &with(&format!(
            "{PROJECT}[types.project.fields]\n{}",
            many(257, &|i| format!(
                "f{i} = {{ sensitivity = \"internal\" }}\n"
            ))
        )),
        "at most 256 fields and features",
    );
    refused(
        &with(&format!(
            "{PROJECT}[types.project.actions]\n{}",
            many(65, &|i| format!("a{i} = {{ needs = \"read\" }}\n"))
        )),
        "at most 64 custom actions",
    );
    refused(
        &with(&format!(
            "{PROJECT}[roles.r.grants]\n{}",
            many(10_001, &|i| format!("\"project.f{i}\" = \"read\"\n"))
        )),
        "at most 10,000 grants",
    );
    refused(
        &with(&format!(
            "{PROJECT}[ui.\"a.b\"]\nactions = [{}]\nroutes = [\"GET /x\"]\nwhen_denied = \"hide\"\n",
            many(257, &|_| "\"project:read\",".to_string())
        )),
        "at most 256 actions and fields",
    );
    refused(
        &with(&format!(
            "{PROJECT}[ui.\"a.b\"]\nactions = [\"project:read\"]\nroutes = [{}]\nwhen_denied = \"hide\"\n",
            many(17, &|i| format!("\"GET /x{i}\","))
        )),
        "1 to 16 routes",
    );
}

#[test]
fn more_refusal_rules() {
    refused(
        "version = 1\n[app]\nname = \"crm\"\naudience = \"tutela-admin\"\n",
        "reserved",
    );
    // A condition must not read a hidden field: people could learn its value.
    refused(
        &with(&format!(
            "{PROJECT}[types.project.fields]\nbudget = {{ sensitivity = \"confidential\", type = \"integer\", grants_access = true }}\n[[conditions]]\nrole = \"member\"\ntype = \"project\"\nwhen = {{ eq = {{ field = \"budget\", value = 1 }} }}\nelse = \"read\"\n"
        )),
        "confidential or secret",
    );
    // Groups may hold agents, so admin powers never go to a group.
    refused(
        &with(&format!(
            "{PROJECT}[roles.r]\ngrants = {{ \"project:manage_access\" = true }}\nassignable_to = [\"user\", \"group\"]\n"
        )),
        "or a group",
    );
    let m = Model::from_toml(&with(PROJECT)).unwrap();
    let owner = &m.roles()[&role("owner")];
    assert!(!owner.assignable_to.contains(&SubjectKind::Group));
    // A declared guest keeps the seeded default; a declared agent too.
    let m = Model::from_toml(&with(&format!(
        "{PROJECT}[roles.agent]\ngrants = {{ project = \"write\" }}\n[roles.guest]\n"
    )))
    .unwrap();
    assert_eq!(m.roles()[&role("agent")].assignable_to.len(), 1);
    assert_eq!(
        m.roles()[&role("guest")].assignable_to.len(),
        SubjectKind::ALL.len()
    );
}

#[test]
fn issue_text_is_escaped_and_cut() {
    let src = format!(
        "{HEAD}[types.\"bad\\nkey{}\"]\nparent = \"org\"\n",
        "x".repeat(400)
    );
    let got = issues(&src);
    assert!(got.iter().all(|i| !i.contains('\n')), "{got:?}");
    assert!(got.iter().all(|i| i.chars().count() < 800), "{got:?}");
}

#[test]
fn invisible_characters_are_refused_and_escaped() {
    // A right-to-left override in a label is refused.
    refused(
        &with("[types.p]\nparent = \"org\"\nlabel = \"ab\\u202Ecd\"\n"),
        "label",
    );
    // In a key it is escaped in the issue, never printed as is.
    let got = issues(&with(
        "[types.\"x\\u202Ey\\u2028z\\u200Bw\"]\nparent = \"org\"\n",
    ));
    assert!(
        got.iter()
            .all(|i| !i.contains('\u{202E}') && !i.contains('\u{2028}') && !i.contains('\u{200B}')),
        "{got:?}"
    );
}

#[test]
fn more_count_limits() {
    let many = |n: usize, f: &dyn Fn(usize) -> String| (0..n).map(f).collect::<Vec<_>>().join(", ");
    refused(
        &with(&format!(
            "[types.p]\nparent = [{}]\n",
            many(65, &|_| "\"org\"".to_string())
        )),
        "at most 64 parent types",
    );
    refused(
        &with(&format!(
            "[roles.r]\nassignable_to = [{}]\n",
            many(17, &|_| "\"user\"".to_string())
        )),
        "at most 16 entries",
    );
}

#[test]
fn a_count_limit_is_the_only_problem_reported() {
    // version 2 and 513 types: only the count limit is reported, because
    // nothing else runs once a limit is exceeded.
    let mut src = "version = 2\n[app]\nname = \"crm\"\n".to_string();
    for i in 0..513 {
        src.push_str(&format!("[types.t{i}]\nparent = \"org\"\n"));
    }
    let got = issues(&src);
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(got[0].contains("at most 512 types"));
}

#[test]
fn problems_are_capped_at_100() {
    let mut src = with("");
    for i in 0..150 {
        src.push_str(&format!("[types.Bad{i}]\nparent = \"org\"\n"));
    }
    let got = issues(&src);
    assert_eq!(got.len(), 101, "{}", got.len());
    assert!(got[100].contains("and 50 more"), "{:?}", got[100]);
}

/// The real stack bound is the compiler thread. The deepest tree the `toml`
/// crate itself accepts: an 80-part `[[...]]` header, then 80 nested inline
/// tables, each opened by an 80-part key. It must parse and drop on the same
/// thread the compiler uses.
#[test]
fn the_compiler_thread_holds_tomls_own_worst_case() {
    let key = |p: &str| {
        (0..80)
            .map(|i| format!("{p}{i}"))
            .collect::<Vec<_>>()
            .join(".")
    };
    let src = format!(
        "[[{}]]\n{} = {}1{}\n",
        key("h"),
        key("b"),
        (0..80)
            .map(|d| format!("{{ {} = ", key(&format!("c{d}_"))))
            .collect::<String>(),
        " }".repeat(80)
    );
    let parsed =
        super::compile::on_compiler_stack(move || toml::from_str::<toml::Table>(&src).is_ok());
    assert_eq!(parsed, Ok(true));
}

#[test]
fn a_leading_byte_order_mark_passes_the_scan() {
    // A quoted key right after the mark: the scan must see it at a line start.
    let src = format!("\u{FEFF}\"version\" = 1\n[app]\nname = \"crm\"\n{PROJECT}");
    if let Err(Issues(v)) = Model::from_toml(&src) {
        for i in &v {
            assert!(
                !i.message.contains("quote may only") && !i.message.contains("does not match"),
                "{v:?}"
            );
        }
    }
}

#[test]
fn every_invisible_character_is_refused() {
    for c in [
        '\u{00AD}',
        '\u{034F}',
        '\u{061C}',
        '\u{115F}',
        '\u{1160}',
        '\u{17B4}',
        '\u{17B5}',
        '\u{180B}',
        '\u{180F}',
        '\u{200B}',
        '\u{200F}',
        '\u{2028}',
        '\u{202E}',
        '\u{2060}',
        '\u{206F}',
        '\u{3164}',
        '\u{FE00}',
        '\u{FE0F}',
        '\u{FEFF}',
        '\u{FFA0}',
        '\u{FFF0}',
        '\u{FFFB}',
        '\u{1BCA0}',
        '\u{1BCA3}',
        '\u{1D173}',
        '\u{1D17A}',
        '\u{E0000}',
        '\u{E0FFF}',
    ] {
        let src = with(&format!(
            "[types.p]\nparent = \"org\"\nlabel = \"a\\U{:08X}b\"\n",
            c as u32
        ));
        refused(&src, "no control or invisible characters");
    }
}

#[test]
fn the_agent_role_never_holds_admin_powers() {
    refused(
        &with(&format!(
            "{PROJECT}[roles.agent]\ngrants = {{ \"project:manage_fields\" = true }}\nassignable_to = [\"user\"]\n"
        )),
        "can never hold an admin key",
    );
}

#[test]
fn custom_actions_at_an_item_level() {
    let m = Model::from_toml(&with(&format!(
        "{PROJECT}[types.project.actions]\napprove = {{ needs = \"write\" }}\nterminate = {{ needs = \"owner\" }}\n[roles.reviewer]\ngrants = {{ project = \"write\", \"project:approve\" = true }}\n"
    )))
    .unwrap();
    let approve = ActionKey::parse("project:approve").unwrap();
    let terminate = ActionKey::parse("project:terminate").unwrap();
    // A condition that drops the reviewer to Read takes approve away.
    assert!(m.allows_custom_at(&role("reviewer"), &approve, Level::Write));
    assert!(!m.allows_custom_at(&role("reviewer"), &approve, Level::Read));
    // Owner-only needs Full: the owner at Write may not terminate.
    assert!(m.allows_custom_at(&role("owner"), &terminate, Level::Full));
    assert!(!m.allows_custom_at(&role("owner"), &terminate, Level::Write));
}

#[test]
fn a_declared_agent_never_gets_an_owner_only_grant() {
    refused(
        &with(&format!(
            "{PROJECT}[types.project.actions]\nterminate = {{ needs = \"owner\" }}\n[roles.agent]\ngrants = {{ project = \"full\", \"project:terminate\" = true }}\n"
        )),
        "can never hold an admin key or an owner-only action",
    );
}

#[test]
fn a_condition_value_with_an_invisible_character_is_refused() {
    refused(
        &with(&format!(
            "{PROJECT}[types.project.fields]\nstatus = {{ sensitivity = \"internal\", grants_access = true }}\n[[conditions]]\nrole = \"member\"\ntype = \"project\"\nwhen = {{ eq = {{ field = \"status\", value = \"op\\u202Een\" }} }}\nelse = \"read\"\n"
        )),
        "no control or invisible characters",
    );
}

#[test]
fn a_condition_integer_must_fit_every_sdk() {
    // JSON readers in other languages (JavaScript) read integers exactly
    // only up to 2^53 - 1, and the list filter sends condition values as
    // JSON. Negative values are fine.
    let with_value = |v: &str| {
        with(&format!(
            "{PROJECT}[types.project.fields]\nprio = {{ sensitivity = \"internal\", type = \"integer\", grants_access = true }}\n[[conditions]]\nrole = \"member\"\ntype = \"project\"\nwhen = {{ in = {{ field = \"prio\", values = [1, {v}] }} }}\nelse = \"read\"\n"
        ))
    };
    for ok in ["9007199254740991", "-9007199254740991", "0"] {
        assert!(Model::from_toml(&with_value(ok)).is_ok(), "{ok}");
    }
    for bad in [
        "9007199254740992",
        "-9007199254740992",
        "9223372036854775807",
    ] {
        refused(&with_value(bad), "from -(2^53 - 1) to 2^53 - 1");
    }
}
