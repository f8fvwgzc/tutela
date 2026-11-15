//! The example manifests in `examples/` (see `examples/README.md`): each one
//! compiles, and the data hiding it promises holds in the evaluator. If an
//! example changes, these tests say what it still has to do.

use std::sync::Arc;

use tutela_contracts::decision::{Decision, Effect};
use tutela_contracts::keys::{FieldKey, FieldName};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;

use crate::model::{Model, RoleKey};
use crate::tests_check::{
    action, agent, binding, direct, entry, fname, org_id, rule, tenant, user,
};
use crate::{
    AttrValue, Attrs, CheckRequest, PathEntry, Pdp, ResourceRef, ScopeFieldRule, TenantData,
};

const TRACKER: &str = include_str!("../../../examples/tracker/tutela.resources.toml");
const HR: &str = include_str!("../../../examples/hr/tutela.resources.toml");
const CRM: &str = include_str!("../../../examples/crm/tutela.resources.toml");
const PROCUREMENT: &str = include_str!("../../../examples/procurement/tutela.resources.toml");

fn pdp(manifest: &str, data: TenantData) -> Pdp {
    let model = Arc::new(Model::from_toml(manifest).unwrap());
    let mut pdp = Pdp::new();
    pdp.load(tenant(1), 1, model, data).unwrap();
    pdp
}

fn org() -> PathEntry {
    PathEntry::org(&org_id(1)).unwrap()
}

/// The path of `scope`: the scope itself, then its ancestors.
fn under(scope: &PathEntry, ancestors: &[PathEntry]) -> Vec<PathEntry> {
    let mut path = vec![scope.clone()];
    path.extend_from_slice(ancestors);
    path
}

fn person(p: &Principal) -> AttrValue {
    AttrValue::String(p.to_string())
}

fn text(s: &str) -> AttrValue {
    AttrValue::String(s.into())
}

fn labels(v: &[&str]) -> AttrValue {
    AttrValue::Strings(v.iter().map(|s| (*s).to_owned()).collect())
}

fn res(t: &str, id: &str, path: Vec<PathEntry>, attrs: &[(&str, AttrValue)]) -> ResourceRef {
    let mut a = Attrs::new();
    for (k, v) in attrs {
        a.insert(fname(k), v.clone());
    }
    let this = entry(t, id);
    ResourceRef {
        type_name: this.type_name,
        id: this.id,
        path,
        attrs: a,
    }
}

/// One check. `fields` empty asks about no single field.
fn ask(
    pdp: &Pdp,
    who: &Principal,
    actors: &[Principal],
    act: &str,
    r: &ResourceRef,
    fields: &[&str],
) -> Decision {
    let fields = (!fields.is_empty()).then(|| fields.iter().map(|f| fname(f)).collect());
    pdp.check(&CheckRequest {
        tenant: tenant(1),
        subject: who.clone(),
        actors: actors.to_vec(),
        action: action(act),
        resource: r.clone(),
        fields,
        at_least_revision: None,
    })
    .unwrap()
}

fn allowed(d: &Decision) -> bool {
    d.effect == Effect::Allow
}

fn names(v: &[FieldName]) -> Vec<&str> {
    v.iter().map(FieldName::as_str).collect()
}

fn reads(d: &Decision) -> Vec<&str> {
    names(d.field_mask.read())
}

fn writes(d: &Decision) -> Vec<&str> {
    names(d.field_mask.write())
}

#[test]
fn every_example_compiles() {
    for (name, text) in [
        ("tracker", TRACKER),
        ("hr", HR),
        ("crm", CRM),
        ("procurement", PROCUREMENT),
    ] {
        let model = Model::from_toml(text);
        assert!(model.is_ok(), "examples/{name}: {:?}", model.err());
    }
}

// ---------- examples/tracker: the access-blueprint ----------

const NOMIN: u32 = 0x701;
const SARA: u32 = 0x702;
const BAT: u32 = 0x703;
const LENA: u32 = 0x704;
const MO: u32 = 0x705;
const CODER: u32 = 0x7c1;

const ISSUE_FIELDS: &[&str] = &["contract_terms", "labels", "status", "title"];
const TASK_FIELDS: &[&str] = &["assignee", "budget", "status", "title"];

fn backend() -> PathEntry {
    entry("team", "t-backend")
}
fn payments() -> PathEntry {
    entry("project", "p-payments")
}
fn mobile() -> PathEntry {
    entry("project", "p-mobile")
}

fn issue(id: &str, project: &PathEntry, tags: &[&str]) -> ResourceRef {
    res(
        "issue",
        id,
        vec![project.clone(), backend(), org()],
        &[("labels", labels(tags))],
    )
}

fn task(
    id: &str,
    issue_id: &str,
    project: &PathEntry,
    assignee: Option<&Principal>,
) -> ResourceRef {
    res(
        "task",
        id,
        vec![entry("issue", issue_id), project.clone(), backend(), org()],
        &[("assignee", assignee.map_or(AttrValue::Null, person))],
    )
}

fn pay12() -> ResourceRef {
    issue("i-pay-12", &payments(), &["client_visible"])
}
fn pay13() -> ResourceRef {
    issue("i-pay-13", &payments(), &[])
}
fn mob7() -> ResourceRef {
    issue("i-mob-7", &mobile(), &[])
}
fn t142() -> ResourceRef {
    task("t-142", "i-pay-12", &payments(), Some(&agent(CODER)))
}
fn t143() -> ResourceRef {
    task("t-143", "i-pay-12", &payments(), Some(&user(BAT)))
}
fn t_mob1() -> ResourceRef {
    task("t-mob-1", "i-mob-7", &mobile(), None)
}

/// The blueprint's people. Payments is private, and Sara has hidden the
/// budget from members there.
fn tracker() -> Pdp {
    pdp(
        TRACKER,
        TenantData {
            orgs: [org_id(1)].into(),
            bindings: vec![
                binding("ra_nomin", direct(&user(NOMIN)), "owner", org()),
                binding("ra_sara_team", direct(&user(SARA)), "owner", backend()),
                binding("ra_sara_pay", direct(&user(SARA)), "owner", payments()),
                binding("ra_bat_team", direct(&user(BAT)), "member", backend()),
                binding("ra_bat_pay", direct(&user(BAT)), "member", payments()),
                binding("ra_lena_pay", direct(&user(LENA)), "guest", payments()),
                binding("ra_coder_pay", direct(&agent(CODER)), "agent", payments()),
                binding("ra_mo", direct(&user(MO)), "viewer", org()),
            ],
            private_scopes: [payments()].into(),
            field_rules: vec![ScopeFieldRule {
                id: rule("fr_pay_budget"),
                scope: payments(),
                field: FieldKey::parse("task.budget").unwrap(),
                role: Some(RoleKey::parse("member").unwrap()),
                max: Level::None,
            }],
            ..TenantData::default()
        },
    )
}

#[test]
fn tracker_member_edits_a_task_but_not_the_budget_the_owner_hid() {
    let d = ask(
        &tracker(),
        &user(BAT),
        &[],
        "task:write",
        &t143(),
        TASK_FIELDS,
    );
    assert!(allowed(&d));
    assert_eq!(d.level, Level::Full);
    assert_eq!(reads(&d), ["assignee", "status", "title"]);
    // `assignee` decides access (`grants_access`), so changing it needs
    // `manage_access`: a member may not.
    assert_eq!(writes(&d), ["status", "title"]);
}

#[test]
fn tracker_budget_stays_open_where_no_owner_hid_it() {
    let d = ask(
        &tracker(),
        &user(BAT),
        &[],
        "task:write",
        &t_mob1(),
        TASK_FIELDS,
    );
    assert!(allowed(&d));
    assert_eq!(writes(&d), ["budget", "status", "title"]);
}

#[test]
fn tracker_secret_field_starts_hidden_and_owners_open_it() {
    let pdp = tracker();
    let bat = ask(&pdp, &user(BAT), &[], "issue:read", &pay12(), ISSUE_FIELDS);
    assert!(allowed(&bat));
    assert_eq!(reads(&bat), ["labels", "status", "title"]);

    let sara = ask(&pdp, &user(SARA), &[], "issue:read", &pay12(), ISSUE_FIELDS);
    assert_eq!(
        reads(&sara),
        ["contract_terms", "labels", "status", "title"]
    );
    let sara_task = ask(&pdp, &user(SARA), &[], "task:read", &t143(), TASK_FIELDS);
    assert_eq!(reads(&sara_task), ["assignee", "budget", "status", "title"]);
}

#[test]
fn tracker_guest_sees_only_client_visible_issues_and_no_tasks() {
    let pdp = tracker();
    let shared = ask(&pdp, &user(LENA), &[], "issue:read", &pay12(), ISSUE_FIELDS);
    assert!(allowed(&shared));
    assert_eq!(reads(&shared), ["labels", "status", "title"]);
    assert!(!allowed(&ask(
        &pdp,
        &user(LENA),
        &[],
        "issue:read",
        &pay13(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(LENA),
        &[],
        "issue:write",
        &pay12(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(LENA),
        &[],
        "task:read",
        &t142(),
        &[]
    )));
}

#[test]
fn tracker_agent_writes_only_its_own_tasks_and_never_sees_the_budget() {
    let pdp = tracker();
    let own = ask(&pdp, &agent(CODER), &[], "task:write", &t142(), TASK_FIELDS);
    assert!(allowed(&own));
    assert_eq!(reads(&own), ["assignee", "status", "title"]);
    assert!(!allowed(&ask(
        &pdp,
        &agent(CODER),
        &[],
        "task:write",
        &t143(),
        &[]
    )));
    assert!(allowed(&ask(
        &pdp,
        &agent(CODER),
        &[],
        "task:read",
        &t143(),
        &[]
    )));
}

#[test]
fn tracker_agent_for_a_person_gets_only_the_overlap() {
    let pdp = tracker();
    let coder = [agent(CODER)];
    // Lena may not read tasks, so the agent may not read them for her.
    assert!(!allowed(&ask(
        &pdp,
        &user(LENA),
        &coder,
        "task:read",
        &t142(),
        &[]
    )));
    // Bat may write T-143; the agent may not, so neither may the pair.
    assert!(!allowed(&ask(
        &pdp,
        &user(BAT),
        &coder,
        "task:write",
        &t143(),
        &[]
    )));
    let both = ask(&pdp, &user(BAT), &coder, "task:read", &t142(), TASK_FIELDS);
    assert!(allowed(&both));
    assert_eq!(reads(&both), ["assignee", "status", "title"]);
}

#[test]
fn tracker_agent_stays_inside_its_project() {
    let pdp = tracker();
    assert!(!allowed(&ask(
        &pdp,
        &agent(CODER),
        &[],
        "issue:read",
        &mob7(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &agent(CODER),
        &[],
        "task:read",
        &t_mob1(),
        &[]
    )));
}

#[test]
fn tracker_private_project_stops_workspace_roles_but_not_the_org_owner() {
    let pdp = tracker();
    assert!(allowed(&ask(
        &pdp,
        &user(MO),
        &[],
        "issue:read",
        &mob7(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(MO),
        &[],
        "issue:read",
        &pay12(),
        &[]
    )));
    assert!(allowed(&ask(
        &pdp,
        &user(NOMIN),
        &[],
        "issue:read",
        &pay12(),
        &[]
    )));
}

// ---------- examples/hr ----------

const ANA: u32 = 0x801;
const LEE: u32 = 0x802;
const KIM: u32 = 0x803;
const HANA: u32 = 0x804;
const PAT: u32 = 0x805;
const HELPER: u32 = 0x8c1;

const EMPLOYEE_FIELDS: &[&str] = &[
    "bank_account",
    "bonus",
    "home_address",
    "job_title",
    "name",
    "national_id",
    "performance",
    "salary",
    "work_email",
];

fn acme() -> PathEntry {
    entry("company", "c-acme")
}
fn eng() -> PathEntry {
    entry("department", "d-eng")
}
fn platform() -> PathEntry {
    entry("department", "d-platform")
}
fn e_ana() -> PathEntry {
    entry("employee", "e-ana")
}
fn e_lee() -> PathEntry {
    entry("employee", "e-lee")
}
fn e_kim() -> PathEntry {
    entry("employee", "e-kim")
}

fn employee(e: &PathEntry) -> ResourceRef {
    let path = if *e == e_kim() {
        vec![eng(), acme(), org()]
    } else {
        under(&platform(), &[eng(), acme(), org()])
    };
    res("employee", e.id.as_str(), path, &[])
}

/// Ana and Lee report to Kim. Everyone is a colleague at the company and
/// holds `self_service` on their own record.
fn hr() -> Pdp {
    pdp(
        HR,
        TenantData {
            orgs: [org_id(1)].into(),
            bindings: vec![
                binding("ra_ana", direct(&user(ANA)), "colleague", acme()),
                binding("ra_lee", direct(&user(LEE)), "colleague", acme()),
                binding("ra_kim", direct(&user(KIM)), "colleague", acme()),
                binding("ra_ana_self", direct(&user(ANA)), "self_service", e_ana()),
                binding("ra_lee_self", direct(&user(LEE)), "self_service", e_lee()),
                binding("ra_kim_self", direct(&user(KIM)), "self_service", e_kim()),
                binding("ra_kim_ana", direct(&user(KIM)), "line_manager", e_ana()),
                binding("ra_kim_lee", direct(&user(KIM)), "line_manager", e_lee()),
                binding("ra_hana", direct(&user(HANA)), "hr_manager", acme()),
                binding("ra_pat", direct(&user(PAT)), "payroll", acme()),
                binding("ra_helper", direct(&agent(HELPER)), "agent", acme()),
            ],
            ..TenantData::default()
        },
    )
}

#[test]
fn hr_colleague_sees_the_directory_but_no_pay() {
    let d = ask(
        &hr(),
        &user(LEE),
        &[],
        "employee:read",
        &employee(&e_ana()),
        EMPLOYEE_FIELDS,
    );
    assert!(allowed(&d));
    assert_eq!(reads(&d), ["job_title", "name", "work_email"]);
    assert!(writes(&d).is_empty());
}

#[test]
fn hr_self_service_sees_your_own_pay_read_only() {
    let pdp = hr();
    let d = ask(
        &pdp,
        &user(ANA),
        &[],
        "employee:read",
        &employee(&e_ana()),
        EMPLOYEE_FIELDS,
    );
    assert_eq!(reads(&d), EMPLOYEE_FIELDS);
    assert!(writes(&d).is_empty());
    assert!(!allowed(&ask(
        &pdp,
        &user(ANA),
        &[],
        "employee:write",
        &employee(&e_ana()),
        &[]
    )));
}

#[test]
fn hr_line_manager_reviews_reports_without_seeing_their_pay() {
    let pdp = hr();
    let d = ask(
        &pdp,
        &user(KIM),
        &[],
        "employee:write",
        &employee(&e_ana()),
        EMPLOYEE_FIELDS,
    );
    assert!(allowed(&d));
    assert_eq!(
        reads(&d),
        ["job_title", "name", "performance", "work_email"]
    );
    assert_eq!(writes(&d), ["performance"]);
    assert!(allowed(&ask(
        &pdp,
        &user(KIM),
        &[],
        "employee:approve_leave",
        &employee(&e_lee()),
        &[]
    )));
}

#[test]
fn hr_manager_cannot_approve_their_own_leave() {
    let pdp = hr();
    // On Kim's own record `self_service` is the closest assignment.
    assert!(!allowed(&ask(
        &pdp,
        &user(KIM),
        &[],
        "employee:approve_leave",
        &employee(&e_kim()),
        &[]
    )));
    let own = ask(
        &pdp,
        &user(KIM),
        &[],
        "employee:read",
        &employee(&e_kim()),
        EMPLOYEE_FIELDS,
    );
    assert_eq!(reads(&own), EMPLOYEE_FIELDS);
}

#[test]
fn hr_manager_role_sees_pay_and_ids_but_not_bank_details() {
    let d = ask(
        &hr(),
        &user(HANA),
        &[],
        "employee:write",
        &employee(&e_lee()),
        EMPLOYEE_FIELDS,
    );
    assert!(allowed(&d));
    assert_eq!(
        reads(&d),
        [
            "bonus",
            "home_address",
            "job_title",
            "name",
            "national_id",
            "performance",
            "salary",
            "work_email"
        ]
    );
    assert_eq!(
        writes(&d),
        [
            "bonus",
            "job_title",
            "name",
            "performance",
            "salary",
            "work_email"
        ]
    );
}

#[test]
fn hr_payroll_changes_pay_but_never_sees_reviews() {
    let d = ask(
        &hr(),
        &user(PAT),
        &[],
        "employee:write",
        &employee(&e_ana()),
        EMPLOYEE_FIELDS,
    );
    assert!(allowed(&d));
    assert_eq!(
        reads(&d),
        [
            "bank_account",
            "bonus",
            "job_title",
            "name",
            "national_id",
            "salary",
            "work_email"
        ]
    );
    assert_eq!(writes(&d), ["bonus", "salary"]);
}

#[test]
fn hr_agent_sees_only_the_directory() {
    let pdp = hr();
    let alone = ask(
        &pdp,
        &agent(HELPER),
        &[],
        "employee:read",
        &employee(&e_ana()),
        EMPLOYEE_FIELDS,
    );
    assert_eq!(reads(&alone), ["job_title", "name", "work_email"]);
    // For Hana it still gets only the overlap: the agent's directory view.
    let for_hana = ask(
        &pdp,
        &user(HANA),
        &[agent(HELPER)],
        "employee:read",
        &employee(&e_ana()),
        EMPLOYEE_FIELDS,
    );
    assert_eq!(reads(&for_hana), ["job_title", "name", "work_email"]);
}

// ---------- examples/crm ----------

const REP1: u32 = 0x901;
const REP2: u32 = 0x902;
const MGR: u32 = 0x903;
const FIN: u32 = 0x904;
const PARTNER: u32 = 0x905;

const DEAL_FIELDS: &[&str] = &[
    "amount",
    "discount_percent",
    "labels",
    "margin",
    "owner",
    "stage",
    "title",
];

fn emea() -> PathEntry {
    entry("region", "r-emea")
}
fn northwind() -> PathEntry {
    entry("account", "a-northwind")
}

fn deal(id: &str, owner: &Principal, tags: &[&str]) -> ResourceRef {
    res(
        "deal",
        id,
        vec![northwind(), emea(), org()],
        &[("owner", person(owner)), ("labels", labels(tags))],
    )
}
fn d1() -> ResourceRef {
    deal("d-1", &user(REP1), &["partner_shared"])
}
fn d2() -> ResourceRef {
    deal("d-2", &user(REP2), &[])
}
fn account() -> ResourceRef {
    res("account", "a-northwind", vec![emea(), org()], &[])
}

fn crm() -> Pdp {
    pdp(
        CRM,
        TenantData {
            orgs: [org_id(1)].into(),
            bindings: vec![
                binding("ra_rep1", direct(&user(REP1)), "sales_rep", emea()),
                binding("ra_rep2", direct(&user(REP2)), "sales_rep", emea()),
                binding("ra_mgr", direct(&user(MGR)), "sales_manager", emea()),
                binding("ra_fin", direct(&user(FIN)), "finance", org()),
                binding("ra_partner", direct(&user(PARTNER)), "partner", northwind()),
            ],
            ..TenantData::default()
        },
    )
}

#[test]
fn crm_rep_edits_own_deals_and_only_reads_the_rest() {
    let pdp = crm();
    let own = ask(&pdp, &user(REP1), &[], "deal:write", &d1(), DEAL_FIELDS);
    assert!(allowed(&own));
    // `owner` and `labels` decide access: changing them needs `manage_access`.
    assert_eq!(
        writes(&own),
        ["amount", "discount_percent", "stage", "title"]
    );
    assert!(!allowed(&ask(
        &pdp,
        &user(REP1),
        &[],
        "deal:write",
        &d2(),
        &[]
    )));
    let other = ask(&pdp, &user(REP1), &[], "deal:read", &d2(), DEAL_FIELDS);
    assert!(allowed(&other));
    assert_eq!(
        reads(&other),
        [
            "amount",
            "discount_percent",
            "labels",
            "owner",
            "stage",
            "title"
        ]
    );
    assert!(writes(&other).is_empty());
}

#[test]
fn crm_only_managers_approve_discounts() {
    let pdp = crm();
    assert!(allowed(&ask(
        &pdp,
        &user(MGR),
        &[],
        "deal:approve_discount",
        &d2(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(REP1),
        &[],
        "deal:approve_discount",
        &d1(),
        &[]
    )));
}

#[test]
fn crm_finance_reads_the_margin_but_changes_nothing() {
    let pdp = crm();
    let d = ask(&pdp, &user(FIN), &[], "deal:read", &d1(), DEAL_FIELDS);
    assert_eq!(reads(&d), DEAL_FIELDS);
    assert!(!allowed(&ask(
        &pdp,
        &user(FIN),
        &[],
        "deal:write",
        &d1(),
        &[]
    )));
}

#[test]
fn crm_partner_sees_shared_deals_without_the_money() {
    let pdp = crm();
    let shared = ask(&pdp, &user(PARTNER), &[], "deal:read", &d1(), DEAL_FIELDS);
    assert!(allowed(&shared));
    assert_eq!(reads(&shared), ["labels", "owner", "stage", "title"]);
    assert!(!allowed(&ask(
        &pdp,
        &user(PARTNER),
        &[],
        "deal:read",
        &d2(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(PARTNER),
        &[],
        "deal:export",
        &d1(),
        &[]
    )));
}

#[test]
fn crm_credit_limit_is_for_managers_and_finance() {
    let pdp = crm();
    let fields = &["credit_limit", "industry", "name"];
    let rep = ask(&pdp, &user(REP1), &[], "account:read", &account(), fields);
    assert_eq!(reads(&rep), ["industry", "name"]);
    let mgr = ask(&pdp, &user(MGR), &[], "account:read", &account(), fields);
    assert_eq!(reads(&mgr), ["credit_limit", "industry", "name"]);
}

// ---------- examples/procurement ----------

const B1: u32 = 0xa01;
const B2: u32 = 0xa02;
const APR: u32 = 0xa03;
const WH: u32 = 0xa04;
const AP: u32 = 0xa05;
const AUD: u32 = 0xa06;

const PO_FIELDS: &[&str] = &[
    "buyer",
    "number",
    "payment_terms",
    "status",
    "supplier",
    "supplier_bank_account",
    "total_amount",
];
const LINE_FIELDS: &[&str] = &[
    "buyer",
    "item",
    "quantity",
    "received_quantity",
    "status",
    "unit_price",
];

fn company() -> PathEntry {
    entry("company", "co-acme")
}
fn plant() -> PathEntry {
    entry("plant", "pl-busan")
}

fn order(id: &str, buyer: &Principal, status: &str) -> ResourceRef {
    res(
        "purchase_order",
        id,
        vec![plant(), company(), org()],
        &[("buyer", person(buyer)), ("status", text(status))],
    )
}
fn line(id: &str, order_id: &str, buyer: &Principal, status: &str) -> ResourceRef {
    res(
        "po_line",
        id,
        under(
            &entry("purchase_order", order_id),
            &[plant(), company(), org()],
        ),
        &[("buyer", person(buyer)), ("status", text(status))],
    )
}
fn po1() -> ResourceRef {
    order("po-1", &user(B1), "submitted")
}
fn po2() -> ResourceRef {
    order("po-2", &user(B2), "draft")
}
fn ln1() -> ResourceRef {
    line("ln-1", "po-1", &user(B1), "submitted")
}
fn ln2() -> ResourceRef {
    line("ln-2", "po-2", &user(B2), "draft")
}

fn procurement() -> Pdp {
    pdp(
        PROCUREMENT,
        TenantData {
            orgs: [org_id(1)].into(),
            bindings: vec![
                binding("ra_b1", direct(&user(B1)), "buyer", plant()),
                binding("ra_b2", direct(&user(B2)), "buyer", plant()),
                binding("ra_apr", direct(&user(APR)), "approver", company()),
                binding("ra_wh", direct(&user(WH)), "warehouse", plant()),
                binding("ra_ap", direct(&user(AP)), "accounts_payable", company()),
                binding("ra_aud", direct(&user(AUD)), "auditor", org()),
            ],
            ..TenantData::default()
        },
    )
}

#[test]
fn procurement_buyer_edits_only_own_orders() {
    let pdp = procurement();
    assert!(allowed(&ask(
        &pdp,
        &user(B1),
        &[],
        "purchase_order:write",
        &po1(),
        &[]
    )));
    assert!(allowed(&ask(
        &pdp,
        &user(B1),
        &[],
        "po_line:write",
        &ln1(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(B1),
        &[],
        "purchase_order:write",
        &po2(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(B1),
        &[],
        "po_line:write",
        &ln2(),
        &[]
    )));
    let other = ask(
        &pdp,
        &user(B1),
        &[],
        "purchase_order:read",
        &po2(),
        PO_FIELDS,
    );
    assert!(allowed(&other));
    assert_eq!(
        reads(&other),
        [
            "buyer",
            "number",
            "payment_terms",
            "status",
            "supplier",
            "total_amount"
        ]
    );
}

#[test]
fn procurement_approver_sees_only_submitted_orders() {
    let pdp = procurement();
    assert!(allowed(&ask(
        &pdp,
        &user(APR),
        &[],
        "purchase_order:approve",
        &po1(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(APR),
        &[],
        "purchase_order:read",
        &po2(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(APR),
        &[],
        "purchase_order:approve",
        &po2(),
        &[]
    )));
    assert!(!allowed(&ask(
        &pdp,
        &user(APR),
        &[],
        "po_line:read",
        &ln2(),
        &[]
    )));
    let l = ask(&pdp, &user(APR), &[], "po_line:read", &ln1(), LINE_FIELDS);
    assert_eq!(reads(&l), LINE_FIELDS);
}

#[test]
fn procurement_warehouse_counts_goods_without_seeing_prices() {
    let pdp = procurement();
    let l = ask(&pdp, &user(WH), &[], "po_line:write", &ln1(), LINE_FIELDS);
    assert!(allowed(&l));
    assert_eq!(
        reads(&l),
        ["buyer", "item", "quantity", "received_quantity", "status"]
    );
    assert_eq!(writes(&l), ["received_quantity"]);
    let o = ask(
        &pdp,
        &user(WH),
        &[],
        "purchase_order:read",
        &po1(),
        PO_FIELDS,
    );
    assert_eq!(reads(&o), ["buyer", "number", "status", "supplier"]);
    assert!(!allowed(&ask(
        &pdp,
        &user(WH),
        &[],
        "purchase_order:approve",
        &po1(),
        &[]
    )));
}

#[test]
fn procurement_bank_account_is_only_for_accounts_payable_and_audit() {
    let pdp = procurement();
    let ap = ask(
        &pdp,
        &user(AP),
        &[],
        "purchase_order:read",
        &po1(),
        PO_FIELDS,
    );
    assert_eq!(reads(&ap), PO_FIELDS);
    let buyer = ask(
        &pdp,
        &user(B1),
        &[],
        "purchase_order:read",
        &po1(),
        PO_FIELDS,
    );
    assert!(!reads(&buyer).contains(&"supplier_bank_account"));
}

#[test]
fn procurement_auditor_reads_all_the_money_but_changes_nothing() {
    let pdp = procurement();
    let d = ask(
        &pdp,
        &user(AUD),
        &[],
        "purchase_order:read",
        &po2(),
        PO_FIELDS,
    );
    assert!(allowed(&d));
    assert_eq!(reads(&d), PO_FIELDS);
    assert!(writes(&d).is_empty());
    assert!(!allowed(&ask(
        &pdp,
        &user(AUD),
        &[],
        "purchase_order:write",
        &po2(),
        &[]
    )));
}
