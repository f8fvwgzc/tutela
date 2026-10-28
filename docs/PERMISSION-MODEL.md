# Tutela permission model

> **Status: pre-alpha.** The first commit holds only the docs, `tutela-contracts` and CI. In review for **Phase A**: the model compiler and the evaluator in `tutela-pdp` (`check`, `batch`, `list_filter`, `write_check`; [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).
> The tables (`tutela-store`), the SQL adapter for list filters, codegen and the React parts come later in **Phase A**.
> The `tutelad` service, revisions with signed bundles, the impact report, two-person publish and the Tutela Console come in **Phase B**.
> See [ROADMAP.md](ROADMAP.md).

This is the most important design doc in the repo. It says how Tutela decides who may see and change each thing, each field and each feature, for people and for AI agents. `tutela-pdp` must follow it. If code and this doc disagree, fix one of them in the same commit (see [AGENTS.md](../AGENTS.md)).

Other docs: [README](../README.md) · [AGENTS](../AGENTS.md) · [SECURITY](../SECURITY.md) · [ARCHITECTURE](ARCHITECTURE.md) · [CONTRACTS](CONTRACTS.md) · [THREAT-MODEL](THREAT-MODEL.md) · [INTEGRATION](INTEGRATION.md) · [ROADMAP](ROADMAP.md) · [DECISIONS](DECISIONS.md)

## Contents

1. [The rules on one page](#1-the-rules-on-one-page)
2. [Where this model comes from](#2-where-this-model-comes-from)
3. [The one question, and what Tutela does not answer](#3-the-one-question-and-what-tutela-does-not-answer)
4. [Concepts](#4-concepts)
5. [Levels and actions](#5-levels-and-actions)
6. [Roles, role assignments and groups](#6-roles-role-assignments-and-groups)
7. [Evaluation order, step by step](#7-evaluation-order-step-by-step)
8. [Defaults](#8-defaults)
9. [Links never grant access](#9-links-never-grant-access)
10. [Moving resources between scopes](#10-moving-resources-between-scopes)
11. [AI agents](#11-ai-agents)
12. [List filtering in SQL](#12-list-filtering-in-sql)
13. [Field masks everywhere data leaves](#13-field-masks-everywhere-data-leaves)
14. [UI components](#14-ui-components)
15. [Model changes](#15-model-changes)
16. [Consistency and revocation](#16-consistency-and-revocation)
17. [Worked example](#17-worked-example)
18. [Tables](#18-tables)
19. [Open points](#19-open-points)

---

## 1. The rules on one page

1. There are four levels on every item, field and feature: **None < Read < Write < Full**.
2. Owner-only admin actions (change roles, protect fields, set move and link rules, configure agents, approve moves) sit **above** the four levels. Full never includes them. Nobody gets them by default.
3. Every resource has **exactly one parent**. The root of every tree is an org.
4. To find someone's level on a resource, walk up from the resource. **The closest role assignment wins.**
5. A **private scope stops inheritance** from above.
6. **Field level = the lower of (role level, closest field rule).**
7. Rules can only **narrow**. Nobody grants a permission they do not hold.
8. **Links never grant access.**
9. New teams and projects **start open**. A new field marked **confidential or secret starts at None**.
10. An agent acting for a person **always** gets the **overlap**: (person allowed) AND (agent allowed). This holds for chat, task work and scheduled work.
11. Lists are **filtered inside SQL** by the same evaluator that answers `check()`. Never load rows and then drop some.
12. Field masks apply **everywhere data leaves**: responses, search and vector indexes, exports, notifications, audit and AI prompts.
13. **UI hiding is never security.** Every server checks again.
14. Every model change gets an **impact report**. Widening changes need approval.

---

## 2. Where this model comes from

The model is the owner's own **access-blueprint** (`/Users/amraaone/Documents/access-blueprint/access-blueprint.html`, English and Korean). The blueprint was written for one product with a fixed tree: workspace → team → project → issue → task. Tutela keeps its rules and its table names, and generalises the tree so each tenant defines its own resource types. A design review found two holes in the blueprint. Both are corrected here. The decision record is [ADR-0005 in DECISIONS.md](DECISIONS.md#adr-0005-the-access-blueprint-is-the-v1-permission-model-with-two-corrections).

Every rule in this doc has an **origin** tag:

| Tag | Meaning |
|---|---|
| **Blueprint** | Taken from the access-blueprint as written. |
| **Generalised** | The blueprint's idea, made to work for any tenant-defined tree. |
| **Correction** | Changes what the blueprint says, because the blueprint version is unsafe. |
| **New** | Not in the blueprint. Added by Tutela. |

### The corrections and big generalisations

Rows 1 and 2 are the two rule corrections recorded in ADR-0005. Row 3 changes only how audit values are stored. The other rows generalise or extend the blueprint.

| # | Blueprint says | Tutela does | Tag | Why |
|---|---|---|---|---|
| 1 | "Working on a task, the agent uses its own role." | The agent always uses the **overlap** with the person who caused the work (chat, task, scheduled work). | Correction | Otherwise anyone who can assign a task borrows the agent's wider access (a "confused deputy"). See [11.4](#114-the-correction-task-work-uses-the-overlap-too). |
| 2 | New teams and projects start open; every new field gets a default rule. | Teams and projects still start open. But a new field marked **confidential or secret starts at None**. | Correction | Otherwise a new secret field is readable by every member until someone remembers to protect it. |
| 3 | `audit_event` stores `before` and `after` values. | Before and after are stored as **digests** or **per-field encrypted**, and field masks apply when the audit log is read. | Correction | Otherwise anyone who can read the audit log reads hidden fields. |
| 4 | Fixed tree: workspace → team → project → issue → task. | Tenants declare **resource types** and their allowed parents. The workspace becomes the **org**. | Generalised | Tutela serves many products (a tracker, a CRM, an ERP-like product). |
| 5 | `principal_kind` = user, agent, guest. | Principal kinds are user, service account (`sa`), key, agent, workload; assignments can also target a **group**. Guest is a **role**, not a kind. | Generalised | One principal can be a guest in one place and a member in another. |
| 6 | "Adopt OpenFGA/SpiceDB when nested checks get slow; Cerbos, OPA or Cedar once conditions grow." | A small **native Rust evaluator** over these tables. Cedar only for vetted condition templates, possibly later. No OpenFGA. | New (engine choice) | Cedar and OpenFGA cannot express "closest wins" or single-field rules. See [ADR-0004](DECISIONS.md#adr-0004-a-native-evaluator-not-cedar-only-or-openfga). |
| 7 | "What the agent makes inherits labels." | Same rule, and Tutela **enforces** it: a reader who could not read the inputs cannot read the output. | New (enforcement) | A label that nobody checks protects nothing. |
| 8 | "Answers are cached per person and project. Any rule change bumps a version number." | A per-tenant **revision**, `at_least_revision`, and **signed bundles with an expiry**. | Generalised | Caches across many services need a clear rule for staleness. |
| 9 | "Our ontology already stores these links." | The **resource path comes from the caller's own database** (or onto-intelli's graph). Tutela never stores app records. | Generalised | One source of truth for parents. Tutela stays small. |

---

## 3. The one question, and what Tutela does not answer

Every check asks one question (Blueprint):

> **Can** *(who)* **do** *(action)* **on** *(which part)* **of** *(which resource)* **?**
> Example: Can Bat **edit** the **Budget** field of task **T-142**?

The boundary between Tutela and the other cores, written exactly:

- **Tutela** answers: "may this principal touch this data or resource?"
- **attache** answers: "may this agent use this tool, host or model, and at what risk?"
- **onto-intelli** keeps per-entity visibility inside graph traversal (called once per entity, in-process), fed by Tutela's permissions.
- **UI hiding is never security. Every server checks again.**

Tutela never stores a product's records, never decides an agent's tool, host or model use (attache does), and never runs workload mTLS (attache owns SPIFFE). More in [ARCHITECTURE.md](ARCHITECTURE.md) and [ADR-0007](DECISIONS.md#adr-0007-the-boundary-between-tutela-and-attache).

---

## 4. Concepts

| Concept | What it is | Blueprint example | Tag |
|---|---|---|---|
| **Tenant** | The unit of isolation inside Tutela. Every Tutela row has a `tenant_id`. A tenant has one permission model and one revision counter. It is always identified by the pair **(iss, tid)**: the token issuer and the tenant id claim. | (one product install) | New |
| **Org** | An organization inside a tenant (a Keycloak Organization in Phases A–B). It is the **root** of a resource tree. Roles in one org never reach another org. | Workspace "Acme" | Generalised |
| **Principal** | Who is asking. Opaque ids only; names are display labels: `user:usr_<uuidv7>`, `sa:sa_<uuidv7>`, `key:key_<uuidv7>`, `agent:agt_<uuidv7>`, `workload:<spiffe uri>`. | Bat, Coder AI | Generalised |
| **Resource type** | A kind of thing. Declared by a product in `tutela.resources.toml`, or pushed by onto-intelli through `tutela.admin.v1` PutResourceTypes. A type lists its fields, features, actions and allowed parent types, and says if it is a container. | team, project, issue, task | Generalised |
| **Resource** | One thing, with an id. It lives in the **product's own database**, not in Tutela. Tutela only sees its type, id, path and the attributes a condition needs. | task T-142 | Blueprint |
| **Parent tree** | Every resource has **exactly one parent**. The path is the list from the resource up to its org. The caller's database (or onto-intelli's graph) supplies it. SDK helpers load the path **server-side by id**, never from the request body. | T-142 → PAY-12 → Payments → Backend → Acme | Blueprint |
| **Scope** | Any resource in the path where assignments or rules can sit. Usually a container. A scope can be **private**. | project Payments | Blueprint |
| **Level** | None < Read < Write < Full. See [5](#5-levels-and-actions). | | Blueprint |
| **Role** | A named set of levels: per resource type, per single field, per feature, plus custom action grants and (for owner roles) admin keys. Seeded roles plus tenant-defined roles. | Owner, Member, Viewer, Guest, AI agent | Blueprint (tenant-defined roles: Generalised) |
| **Role assignment** | (principal or group, role, scope). "Bat is a Member of team Backend." | Bat → Member @ Backend | Blueprint |
| **Group** | A named set of principals in an org. A group can receive role assignments. Groups may contain groups. | | New |
| **Field** | One attribute of a resource type. Each field is registered in `field_registry` with a **sensitivity**: public, internal, confidential or secret. A field the model does not know is treated as secret (masked). | Budget | Blueprint |
| **Feature** | A part of an item that is not a data field: chat, files, AI. A feature has a level like a field. Its key starts with `@` (`@chat`, `@files`, `@ai`) so it never clashes with a field name. | chat, files, AI | Blueprint (`@` keys: New) |
| **Field rule** | At a scope: for one field (or feature) of one type, and one role (or all roles), a **maximum level**. The closest rule wins. | "Payments hides Budget from Members." | Blueprint |
| **Boundary rule** | Per scope: private or not, who may link in, who may move items in or out, what happens on a move into a looser scope, and `ai_reach`. | Payments: private, ai_reach = project | Blueprint (`private` column: Generalised) |
| **Condition** | An extra check on facts about the item or the principal (ABAC). Only from a small list of vetted templates. If the condition is false, the role's level drops to a lower level. | "AI agents edit only tasks assigned to them." | Blueprint |
| **Action** | What the principal wants to do: `read`, `write` (create or update), `delete`, a custom action (`approve`, `export`), or an admin action. Each action needs a minimum level, and custom actions can also need an explicit grant. | edit | Blueprint |
| **UI component** | A UI key declared in `tutela.resources.toml`. It names the actions **and** the API routes behind it, and a mode for when access is denied (show, disable, hide, readonly). | the Approve button | New |
| **Model revision** | The tenant revision is a number that goes up on **every** change (model or bindings). Each published **model** change (types, fields, roles, rules, UI keys) also gets a `model_revision` row with its diff, impact report and approvals. | "Any rule change bumps a version number." | Blueprint (revisions with approval: Generalised) |
| **Label** | The sensitivity a piece of output carries. Output carries the **highest** label of its inputs. | "webhook-fix.diff: Internal" | Blueprint |
| **Decision** | What a check returns: effect, level, field mask {read, write}, rule ids, reason, rev, obligations. See [7.3](#73-the-decision-object). | | New |

### 4.1 The blueprint tree, generalised

The blueprint tree becomes one example of a tenant model. Other products declare their own trees. Each resource still has one parent, and the org is always the root.

| Product | Tree (root first) | Notes |
|---|---|---|
| nexc-engine (the blueprint's own product) | org (= workspace) → team → project → issue → task | WorkspaceRole and TeamRole become seeded roles. See [INTEGRATION.md](INTEGRATION.md). |
| A CRM-like product | org → region → account → deal → invoice | |
| An ERP- or SAP-like product | org → company → plant → purchase order → line | |
| onto-intelli | org → project or partition → object types it pushes | onto pushes its object, link and action types as resource types. onto owns that adapter. |

A resource type declares (Generalised):
- `parent`: the allowed parent types;
- `container`: whether other resources live inside it;
- `starts`: `open` (the blueprint default for teams and projects) or `private`;
- its fields (with sensitivity), its features and its custom actions.

---

## 5. Levels and actions

### 5.1 The four levels (Blueprint)

The same four words work everywhere, so owners learn them once.

| Level | On an item (team, project, issue, task, any resource) | On a field | On a feature (chat, files, AI) |
|---|---|---|---|
| **None** | You cannot tell it exists. It never shows in lists, search, counts or links. | Removed, or shown as "Restricted". The owner picks which. | The tab or button is not shown. |
| **Read** | Open and view it. | See the value. | Read chat history, download files. |
| **Write** | Edit it and create items inside it. | Change the value. | Send messages, upload files, ask the AI. |
| **Full** | Write, plus delete and archive. | Write, plus clear the value and see its history. | Write, plus delete messages and files. |

### 5.2 Actions

Each action needs a minimum level on the item. A custom action can also need an explicit grant on the role (Generalised).

On the wire an action is an action key, `<type>:<action>`. Every type has four built-in actions: `read`, `write`, `delete` and `manage_access` ([CONTRACTS.md §2.3](CONTRACTS.md#23-action-keys)). Create and update are both `write`.

| Action | Needs | Notes |
|---|---|---|
| `read` | Read | Fields are filtered by the field mask. |
| `write` on the container (create an item inside it) | Write on the container | The new item starts with the parent's rules. |
| `write` on the item (update it) | Write on the item, plus Write on **each field** that changes | Checked per field by `Pdp::write_check`. Fields marked `grants_access` (for example an assignee or a label used by a condition) also need `manage_access`. |
| `delete` | Full | Blueprint decision: Full includes delete and archive for issues, tasks, files and messages. A product that needs `archive` apart from `delete` declares it as a custom action with level Full. |
| Custom, for example `contract:approve` | The level the type declares (for example Write) **and** the grant on the role | Declared in `tutela.resources.toml`. An owner-only custom action (`needs = "owner"`) needs **Full and** the grant ([MANIFEST.md §4](MANIFEST.md#4-resource-types)). |
| Feature use, for example asking the AI | The feature level (`@ai` Write) | |
| Admin actions | An admin key (see 5.3) | Never implied by Full. |

Anything the model does not know is denied: an unknown type, an undeclared action, an unregistered field (masked as secret). Default deny.

### 5.3 Owner-only admin actions (Blueprint)

"Full is not configure." These sit above the four levels and are never given by default. On the wire each one is an action key, `<type>:<name>`. `manage_access` is already a built-in action in `tutela-contracts`. The names are fixed in [MANIFEST.md §6](MANIFEST.md#6-admin-keys) ([CONTRACTS.md §2.3](CONTRACTS.md#23-action-keys)).

| Blueprint wording | Admin key |
|---|---|
| Change roles, invite people | `manage_access` |
| Set field protection | `manage_fields` |
| Set move and link rules | `manage_boundaries` |
| Configure AI agents (add them, set `ai_reach`) | `manage_agents` |
| Approve moves | `approve_move` |
| Read the audit log | `read_audit` (blueprint decision: org admins for everything, scope owners for their own scope) |

The seeded **Owner** role holds these keys at the scope where it is assigned. A tenant can build other admin roles. Two rules (New):
- An **agent can never hold an admin key, an owner-only custom action** or the Owner role. A role with an admin key is also never given to a **group**, because groups may hold agents ([ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)).
- Admin keys and owner-only custom actions are never passed through delegation (see [11.3](#113-the-overlap-rule)).

---

## 6. Roles, role assignments and groups

### 6.1 Seeded roles (Blueprint)

Every tenant starts with these roles. A manifest may replace Member, Viewer, Guest and Agent, and add its own roles. The Owner role is fixed and has no conditions ([MANIFEST.md §5.1](MANIFEST.md#51-seeded-roles), [ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)).

| Role | Default levels | Admin keys | Notes |
|---|---|---|---|
| **Owner** | Full | Yes, at its scope | The creator of a scope becomes its Owner. |
| **Member** | Full | No | People added to a new team or project. |
| **Viewer** | Read | No | |
| **Guest** | Read, only on what they are invited to | No | Blueprint example: guests see only issues labelled `client-visible` (a condition). |
| **Agent** | Read. Never an admin key or an owner-only custom action. Write only on items assigned to it is a condition on a principal field, so the product declares it (the seeded role has no condition; see [MANIFEST.md §5.1](MANIFEST.md#51-seeded-roles)). | Never | For AI agents. See [11](#11-ai-agents). |

The **org Owner** (the blueprint's workspace owner) is special (Blueprint guardrail): an org Owner keeps Full access everywhere in the org, also inside private scopes. Opening a hidden field this way needs a short reason and is always written to the audit log. This break-glass path is for people only. It never works through an agent (New).

### 6.2 Tenant-defined roles (Generalised)

A tenant defines a role as a list of levels and grants. In Phase A it comes from `tutela.resources.toml`. In Phase B a tenant's own admins edit roles at runtime in the Tutela Console or in the embeddable RoleEditor in a product.

A role entry can set a level for:
- a resource type (`contract = "write"`);
- a single field of a type (`"contract.title" = "read"`). If the role does not set a field, the field uses the role's item level **after conditions** (step 4), and a field is never above that item level;
- a feature of a type (`"contract.@ai" = "write"`);
- custom action grants (`contract:approve`) and admin keys.

### 6.3 Role assignments

A role assignment gives one principal or one group one role at one scope. There is at most one direct assignment per principal per scope.

Two assignments can meet at the same scope: one direct, one or more through groups. The rule (New, [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)): **the direct assignment wins**; this lets an owner narrow one person who sits in a wide group. If there is none, **every** group role at that scope counts: each role is evaluated on its own (its own conditions and field rules), and the results are combined **component-wise**: the highest item level, and the highest level per field and feature. A **custom action** is allowed if **any** deciding role allows it with its own item level after its own conditions (`allows_custom_at`); raw grants are never pooled, so a grant cannot escape the conditions of the role that holds it. **Admin keys** are the union of the deciding roles' keys. The model diff relies on this ([ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)).

### 6.4 Groups (New)

- A group belongs to one org. Members are principals or other groups.
- Tutela keeps a closure table, so "is this principal in that group" is one lookup. The week-1 spike measures this at depth 32 with big groups (see [ROADMAP.md](ROADMAP.md#very-next-steps)).
- In Phase A, group keys are unique in the tenant, so a binding or an `in_group` condition names one group ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).
- Removing a principal from a group removes its access through that group in the same transaction as the revision bump.
- Deleting a principal deletes its assignments and group memberships in the same transaction.

---

## 7. Evaluation order, step by step

`tutela-pdp` runs the same steps for every request: `Pdp::check`, `Pdp::batch`, `Pdp::list_filter` and `Pdp::write_check` all use this code. The remote API in `tutelad` (Phase B) calls the same engine. The order matters. The blueprint had four steps (closest role, conditions, field rules, guardrails). Tutela adds token, tenant and delegation steps around them.

Inputs: the verified token, the action, the resource `{type, id}` and, for writes, the changed fields. The SDK loads the resource's **path and attributes server-side by id** from the product's database. They never come from the request body.

### 7.1 The eight steps

**Step 1. Verify the token.** (New)
- Signature, algorithm allow-list, `iss` in the SDK trust list, exactly one `aud` and it is ours, `exp`/`nbf` with small clock skew.
- `epoch` is current (fast revocation). The principal is not disabled. (Only Tutela tokens carry `epoch`. Tokens from an external issuer in Phase A have none, so revocation waits for them to expire; see [CONTRACTS.md §4.6](CONTRACTS.md#46-external-issuer-tokens-phase-a).)
- A token with header `typ: agent+jwt` is refused unless delegation support is switched on. If it is on, the token is a delegated token: `sub` = the person, `act = {sub: agent:agt_…}`. Go on, and remember to run step 7.
- Fail → 401. Nothing else runs.

**Step 2. Resolve the tenant key (iss, tid).** (New)
- The tenant is the pair **(iss, tid)** from the token. The SDK trust list maps each issuer to the tenants it may speak for. A `tid` that issuer may not speak for → deny.
- The resource (loaded by id) must belong to the same tenant. A different tenant → deny. There is no cross-tenant grant, ever (a property test checks it).
- Load the tenant model at a revision ≥ `at_least_revision` (if the caller sent one). If the bundle is expired → 503, never a stale allow. See [16](#16-consistency-and-revocation).

**Step 3. Walk the parent path. The closest assignment wins. A private scope stops inheritance.** (Blueprint)
- If the principal is the org Owner, the level is Full. Go to step 4. (Blueprint guardrail; people only.)
- Otherwise start at the resource itself and walk up: resource → parent → … → org.
- At each node, look for assignments for the principal: direct first, then through its groups (see [6.3](#63-role-assignments)).
- **The first node with an assignment wins.** Its roles are the deciding roles: the direct one, or else every group role there. Stop walking.
- If the node is **private** and has no assignment for the principal, stop: nothing above it counts. The level is None.
- If you reach the org with no assignment, the level is None. Default deny.
- An assignment whose role the model no longer has, or whose role may no longer be given to that kind of subject (`assignable_to`), still **decides its node**: the walk stops there, and that role gives None and no grants. So removing a role, or narrowing who may hold it, only takes access away.
- For each deciding role, the item level is that role's level for this resource type.

**Step 4. Apply conditions.** (Blueprint)
- Each deciding role may carry conditions at that scope, for example `resource.assignee == principal` or `"client-visible" in resource.labels`. Each role's own conditions lower only that role's item level.
- Each condition has a level to use when it is false (for example Write when true, Read when false). That level is never higher than the role's level. Conditions only narrow.
- Conditions come from a small list of **vetted templates** that compile both to Rust and to SQL. A model with anything else is rejected when it is compiled, not at request time.
- A condition that names a group that does not exist is **false as a whole**, even under `not` (fail closed): the level drops to its `else` level ([MANIFEST.md §8](MANIFEST.md#8-conditions)).

**Step 5. Field level = min(role level, closest field rule).** (Blueprint)
- For each field and feature of the type:
  - the **role level** comes from one function the diff and the evaluator share (`effective_field_level`, [ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)). For a **data field**: the role's level for that field if the role sets one, else the item level from step 4, and **never above the item level from step 4** (a condition that drops the item to Read also drops its fields). For a **feature**: None when the item level is None; else the role's level for the feature if it sets one, else the item level (a feature may be above the item level: a Viewer may ask the AI). A field or feature the type does not declare is None;
  - the **closest field rule** is found by walking the same path upward: the first scope with a rule for this field wins. At one scope, a rule for this exact role wins over a rule for all roles;
  - **field level = the lower of the two.** If no rule exists anywhere, the field level is the role level.
- A field marked confidential or secret gets an "all roles → None" rule at the org root when it is registered (Correction). So it starts hidden.
- The org Owner sees hidden fields only through the break-glass path: a reason is required, and the decision carries an audit obligation.

**Step 6. Narrow-only guardrails.** (Blueprint + New)
These can only lower the result, never raise it:
- **Boundary rules.** Links never grant access ([9](#9-links-never-grant-access)). Move rules apply to move actions ([10](#10-moving-resources-between-scopes)).
- **Labels.** A value that carries a label is masked when the reader could not read the inputs it came from ([11.5](#115-labels-on-output)).
- **Admin actions** need an admin key. Full never implies one.
- **Nobody grants what they do not hold.** For admin actions that create or change a grant, each new grant must be ≤ what the actor holds at that scope (role-on-diff, see [15](#15-model-changes)). A child scope may tighten a parent's field rule; loosening it needs an org admin (blueprint decision).

**Step 7. Delegation overlap for agents.** (Correction)
- Only for delegated tokens (`act` present).
- Run steps 3–6 **again for the agent** with its own assignments. Also apply its `ai_reach`: the agent may only touch resources inside the scope of the work (`project`), or that scope's parent (`team`). Never the org root, never another branch.
  - In the evaluator ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)): the closest assignment is always on the resource's path, so `project` reach holds by itself. An agent whose closest assignment is at the org root gets None (`outside_ai_reach`). `team` reach never adds access; it only narrows less.
- **Overlap:** item level = min(person, agent). Each field level = min(person, agent). Custom actions = the **intersection of the allowed-action sets** of the person and the agent (each set as in [6.3](#63-role-assignments): actions some deciding role allows at its own item level after its own conditions), never raw grants. Admin keys and owner-only custom actions = none.
- If the act chain is nested (an agent acting for an agent acting for a person), every actor must be allowed, and the chain holds at most 4 actors.
- The person must be the one who caused the work and must still be enabled.
- attache's capability limits (`cap` in the token) cap the rest. Tutela does not read `cap`; attache enforces tools, hosts and models on its side. Both must allow.

**Step 8. Decision.**
- **effect** = allow if:
  - for a built-in action: the item level ≥ the action's minimum level;
  - for a custom action: it is in the **allowed-action set** of [6.3](#63-role-assignments) (some deciding role allows it with `allows_custom_at` at its own item level after its own conditions), and for a delegated token in the intersection of step 7;
  - for an admin action: a key from the union of the deciding roles' admin keys (never through delegation);
  - and, for writes, every changed field passes `write_check`.
- Otherwise deny.
- Build the decision object (7.3).
- Write an audit event for every deny, every admin change, every move, every hidden-field opening and every export (Blueprint: "every change, and every denied attempt").

### 7.2 The same steps as code (sketch)

This is a sketch for readers, not the real code.

```text
check(token, action, res_ref):
  p      = verify(token)                                   # step 1, else 401
  tenant = (p.iss, p.tid); require trust_list.allows(tenant)
  res    = load_by_id(res_ref)                             # path + attrs, server side
  require res.tenant == tenant                             # step 2, else deny
  model  = bundle(tenant, rev >= at_least_revision)        # expired -> 503

  d = evaluate(p.sub, res, model)                          # steps 3-6
  if p.act:                                                # step 7
      a = evaluate(p.act.sub, res, model, ai_reach=on)
      d = overlap(d, a)                                    # min per item and field;
                                                           # intersection of allowed actions; no admin keys
  return decide(d, action)                                 # step 8

evaluate(principal, res, model):
  if is_org_owner(principal): roles = [Owner]                # people only
  else:
      roles = []
      for node in res.path:                                # resource ... org
          roles = assignments(principal, node)             # direct, else all group roles
          if roles: break
          if node.private: break                           # stops inheritance
  results = []
  for role in roles:                                       # each role on its own
      level  = apply_conditions(role, res, principal, role.level(res.type))  # only lowers
      fields = { f: min(effective_field_level(role, f, level),   # capped by `level`
                        closest_field_rule(f, role, res.path))   # for data fields
                 for f in res.type.fields_and_features }
      actions = { a for a in res.type.custom_actions
                  if allows_custom_at(role, a, level) }    # this role's own level
      results.append((level, fields, actions, role.admin_keys))
  level, fields, actions, admin = combine(results)         # max per item, field, feature;
                                                           # union of allowed actions and admin keys
  return guardrails(level, fields, actions, admin)         # can only lower
```

The engine resolves the effective level **once per (principal, scope)** in each call. The Phase A evaluator keeps no cache across calls: `check` p99 is about 12–17 µs without one ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)). A decision cache, keyed by revision, comes with `tutela-sdk`. The week-1 spike target is `check` p99 < 1 ms in-process with a large per-tenant model.

### 7.3 The decision object

The wire shape lives in `tutela-contracts`; see [CONTRACTS.md](CONTRACTS.md).

| Field | Meaning |
|---|---|
| `effect` | `allow` or `deny`. |
| `level` | The item level the principal holds (None, Read, Write, Full). |
| `field_mask.read` | The fields and features the principal may read. **Anything not listed is masked.** |
| `field_mask.write` | The fields and features the principal may change. |
| `rule_ids` | The assignment, field rules, conditions and boundary rules that decided it. |
| `reason` | A short human reason, for logs, the Console's "explain" view and denied-UI tooltips. |
| `rev` | The model revision used. |
| `obligations` | Things the caller must do. Examples (proposed): write an audit event naming `on_behalf_of`; attach a label to output; show "Restricted" instead of removing a field; re-check online. |

---

## 8. Defaults

| Situation | Default | Tag |
|---|---|---|
| No assignment anywhere on the path | None (default deny). | Blueprint |
| A new team, project or other container type with `starts = "open"` | The creator becomes Owner. People with a role on the parent keep it inside (inheritance). People added to the new scope get Member (Full) unless the person adding them picks another role. People outside get None. | Blueprint, Generalised |
| A container type with `starts = "private"` | Only the creator (Owner) and people added to it. | Generalised |
| Guests | See only what they are invited to. | Blueprint |
| AI agents | Never see confidential data (Budget, contracts) unless an owner allows it. Stay inside their own project (`ai_reach = project`). | Blueprint |
| A new **public or internal** field | Follows the item level. | Blueprint |
| A new **confidential or secret** field | **None for every role** until an owner opens it. Opening it is a widening change: impact report and approval. | **Correction** |
| A field not in `field_registry` | Masked, as if secret. | New |
| Owner-only admin actions | Never given by default. Not part of Full. | Blueprint |
| Full includes delete and archive | Yes, for items, files and messages. | Blueprint decision |
| A hidden field on an item you can open | Shown as "Restricted", so people know whom to ask. The owner can choose "remove". Always **removed** from exports, search and AI prompts. | Blueprint decision |
| A child scope loosening a parent's rule | Not allowed without an org admin. | Blueprint decision |
| Who can read the audit log | Org admins: everything. Scope owners: their own scope. | Blueprint decision |
| The org Owner opening a hidden field | Allowed, with a short reason, always logged. | Blueprint decision |
| Links from other projects in the same team, or from other teams | On. The owner can turn them off. | Blueprint |
| A link you cannot follow | Shown as "Restricted item". The owner can choose "disappear" when even existence is sensitive. | Blueprint |
| An agent reading other projects in the same team | Off. An owner can allow it (`ai_reach = team`) with a warning; not recommended. Other teams: never. | Blueprint |
| A move into a scope with looser rules | Waits for the source owner's approval. | Blueprint |

---

## 9. Links never grant access

(Blueprint) Links cross the tree: "T-142 blocks MOB-7", "PAY-12 references northwind-msa.pdf". If links gave access, a link would become a side door into a private project.

- A link **never** gives access by itself.
- You see the linked item's title only if you can open the item. Otherwise you see "Restricted item", or nothing, as the owner chose.
- Owners choose who can link into their scope (`boundary_rule.links_from`).
- Agents do not follow links into other projects (their `ai_reach` stops them).
- Graph queries filter **both** items and links by access. onto-intelli applies this inside its graph traversal, fed by Tutela's permissions.

Link and move rules across scopes (Blueprint, with the blueprint's names):

| | Inside one project | Other project, same team | Other team |
|---|---|---|---|
| Link (refer to) issues and tasks | Yes | Yes. On by default; owner can turn it off. | Yes. On by default; owner can turn it off. |
| See what a link points to | Following your access | Only if you can open it; otherwise "Restricted item" | Only if you can open it; otherwise "Restricted item" |
| Move an issue | — | Owners and members; owner can restrict | Owners of both projects only |
| AI agent reads | Yes | Off. Owner can turn it on; not recommended. | Never |

For other trees, "project" means the scope where the agent is assigned, and "team" means that scope's parent container (Generalised).

---

## 10. Moving resources between scopes

(Blueprint) Work does not stay in one box. Moves are allowed, follow access, and owners can restrict them.

1. A move is **one operation**: a `write` that changes the item's parent (`Pdp::write_check` with a new path, see [CONTRACTS.md §6.7](CONTRACTS.md#67-write_check)). It needs the right on both sides: `moves_out` on the source scope and `moves_in` on the target scope (`boundary_rule`). Across teams, only owners of both scopes. Phase A: `write_check` refuses moves until these boundary rules exist with `tutela-store` ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).
2. The moved item **takes the rules of its new parent**. Its children, files, chat and history move with it.
3. Tutela compares access before and after (the same impact calculation as model changes, [15](#15-model-changes)). If the new scope is **looser** (for example Budget is visible there), the move **waits for the source owner's approval** (`on_looser = approve`). An owner can also set `on_looser = block`.
4. The audit log records the move with **both** scopes.
5. Because the product's database holds the parent, the product changes the parent and the ancestors in one transaction, and sends `at_least_revision` on its next check. A test proves that access through the old parent ends after the move (New).

---

## 11. AI agents

AI is the easiest place to leak data by accident, because a model will repeat anything it was given. The rule (Blueprint): **never give it something the reader is not allowed to see.**

### 11.1 Agents are principals (Blueprint)

- Each agent has its own identity (`agent:agt_<uuidv7>`), shows up in member lists, and is added to a scope like a person, with a role (usually the seeded Agent role).
- attache owns the agent registry and runtime. attache creates and disables agent principals through `tutela.admin.v1`. When attache quarantines an agent, the principal is disabled and its tokens stop working (see [INTEGRATION.md](INTEGRATION.md)).
- An agent never holds the Owner role, an admin key or an owner-only custom action (New).

### 11.2 `ai_reach` (Blueprint)

`boundary_rule.ai_reach` on the scope where the agent is assigned:

| Value | Meaning | Default |
|---|---|---|
| `project` | The agent reads only inside that scope. | Yes |
| `team` | The agent may also read other scopes under the same parent. Allowed, **not recommended**; the Console shows a warning. | No |
| (anything wider) | **Never.** Not the whole org, never another team. | — |

An agent assigned only at the org root therefore gets nothing (`outside_ai_reach`). `team` never opens a sibling scope where the agent has no assignment: that would widen access through a boundary setting ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).

### 11.3 The overlap rule

An agent acting for a person **always** gets the overlap (Correction, see [ADR-0005](DECISIONS.md#adr-0005-the-access-blueprint-is-the-v1-permission-model-with-two-corrections)):

> **allowed = (person allowed) AND (agent allowed)**, capped by attache's capability limits.

| Kind of work | "The person" is | Tag |
|---|---|---|
| Chat: someone asks the agent | The person asking | Blueprint |
| Task work: someone assigns a task to the agent | The **assigner** (or the requester, if the task came from a request) | **Correction** |
| Scheduled work | The person who **created** the schedule | **Correction** |
| Agent-to-agent work | The person at the start of the chain; every agent in the chain must also be allowed | New |

More rules:
- Per item **and per field**: min(person, agent). Custom actions: the intersection of the person's and the agent's allowed actions (never raw grants). Admin keys and owner-only custom actions: never.
- **Hidden fields are removed before the prompt is built.** The model never receives them, so it cannot repeat them. Filtering the answer afterwards is not reliable (Blueprint).
- When the person is **disabled**, their scheduled work **stops**. The next run cannot get a delegated token for a disabled person, and the `tutela.principal.disabled.v1` event tells schedulers to stop (Correction).
- The person's `epoch` is re-checked at every token exchange, so a revoked session ends long runs at the next hop (New).
- The audit log names both sides: "Clause AI, for Jae" (Blueprint). In `audit.v1`: `actor = {kind: agent, id, on_behalf_of: user:…}`.

### 11.4 The correction: task work uses the overlap too

The blueprint says: "Working on a task, the agent uses its own role." That is a **confused-deputy hole**:

1. A junior user cannot read the Budget field.
2. The agent's role can read Budget (an owner allowed it, so the agent can check invoices).
3. The junior user assigns the agent a task: "write the budget headroom into the review notes".
4. With its own role, the agent reads Budget and writes the number into a field the junior user can read.
5. The junior user now knows the budget. The agent was the "deputy" that was tricked into using its access for someone else.

Tutela replaces the line: **on task work and scheduled work, the agent uses the overlap with the person who caused the work.** The worked example walks through this case ([17.5](#175-jae-assigns-a-task-to-the-agent)).

### 11.5 Labels on output

(Blueprint) What an agent makes inherits labels. A summary or file built from internal data is labelled internal too. **Output carries the highest label of its inputs.**

(New) Tutela enforces it:
- The decision for each read returns an obligation with the highest sensitivity among the fields actually read.
- The product (or attache's runtime) stores that label with the output.
- When someone reads a labelled value, the value is masked unless the reader could read data of that label in that scope. In plain words: **a reader who could not read the inputs cannot read the output.**
- How a reader's clearance per label is stored is fixed in Phase A ([Open points](#19-open-points)). The rule above is fixed now.

### 11.6 Delegated tokens (summary)

Full details: [CONTRACTS.md](CONTRACTS.md) and [ADR-0006](DECISIONS.md#adr-0006-delegated-agent-tokens-in-phase-b-not-optional). Delegated tokens come from the token-exchange service in `tutelad` in **Phase B** (not optional).

- Header `typ: agent+jwt`. SDKs refuse it unless delegation support is on, so a server that does not understand delegation never treats the agent as the full person.
- `sub` = the person, `act = {sub: agent:agt_…}`, `cap` = attache's capability snapshot (opaque to Tutela), run and node ids.
- Issued only to audiences registered with `delegation_aware = true`. Exactly one audience. TTL 60–120 s for downstream hops. Optional mTLS binding (RFC 8705 `cnf`).
- A service that receives an agent token **never forwards it**. It exchanges it for a new one per audience.

### 11.7 What Tutela does not decide for agents

Which tools, hosts and models an agent may use, at what risk, with what budget, and whether a human must approve: **attache** decides all of that (firewall, approvals, model gateway, evidence ledger). Tutela decides only what data and resources the agent may touch, and only through the overlap.

---

## 12. List filtering in SQL

(Blueprint: "Filter lists inside the query, never after loading.") Decision record: [ADR-0009](DECISIONS.md#adr-0009-lists-are-filtered-in-sql-from-the-same-evaluator). Built in **Phase A**.

### 12.1 Why never load-then-drop

Loading 500 issues and dropping the hidden ones afterwards is slow. Worse, the **page size** and the **total count** still show that hidden items exist. "12 issues" when you can see 9 is a leak. So the filter must be part of the SQL query, and counts must use the same filter.

### 12.2 What `Pdp::list_filter` returns

`Pdp::list_filter(principal, action)` comes from the **same evaluator** as `check()`. The action key names the type to list, for example `contract:read`. For a custom action, a row matches only where some deciding role allows it (§6.3). It returns a filter with three parts:

| Part | What it holds |
|---|---|
| `ids_in` | Single resources allowed by an assignment on the resource itself (for example a guest invited to one issue). |
| `container_in` | Scopes where the principal's resolved level meets the action. Rows anywhere below them match. |
| condition AST | Everything else as a small boolean tree: role conditions (`assignee == $principal`), and exclusions for scopes nested inside an allowed scope where the level is lower (a private scope the principal is not in, or a closer, lower assignment). When allowed and excluded scopes nest more than once, the compiler emits one more nested group per level, so "closest wins" holds. |

How it is computed:
1. Find the **deciding scopes** for this principal: every scope where the principal or one of its groups has an assignment, and every private scope inside them. In an org where the principal is the org Owner, only the org root decides.
2. Resolve the effective level of each deciding scope once (closest wins, private stops inheritance, conditions).
3. A row's level is the level of the **deepest deciding scope** on its path. Turn that into `ids_in`, `container_in` and the AST: one term per nesting level of the deciding scopes ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator), "filter shape").

Tutela does not store the product's tree, so `list_filter` gets the paths of the deciding scopes from a **scope-path provider**, keyed by (tenant, type, id). An unknown scope, or a path that does not end at the tenant's own org, is an error, and the list fails closed ([CONTRACTS.md §6.6](CONTRACTS.md#66-list_filter), [ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator) F1).

For agents, the same is done for the person and the agent, `ai_reach` is applied, and the two filters are joined with AND.

### 12.3 How the SDK turns it into SQL

- The product keeps each row's parent and an **ancestors** column (the ids on its path) in its own database. The SDK gives a migration helper (Phase A; the exact shape — array, `ltree` or closure table — is chosen in the week-1 spike).
- **Every value is a bound parameter** (`$1`, `$2`, …). Text is never spliced into SQL.
- Column names come only from the product's manifest mapping, checked against a fixed list. Never from the request.
- The **SELECT list** comes from `field_mask.read`. Masked columns are not selected.
- The SQL compiler is fuzzed.
- The product's database also uses row-level security by tenant as a safety net (Blueprint: "with row-level security as a safety net"). The product template sets this up.

Example shape (Jae from the worked example, listing contracts he may read):

```sql
-- filter: container_in = [Procurement, Supplier renewals 2027]
--         condition    = NOT under [Board pricing review]
SELECT id, title, counterparty, status          -- from field_mask.read: no budget
FROM   contract
WHERE  tenant_id = $1
  AND  ancestors && $2::uuid[]                  -- container_in
  AND  NOT (ancestors && $3::uuid[])            -- nested private scope Jae is not in
ORDER  BY updated_at DESC
LIMIT  $4;

-- the count uses the same WHERE clause, so it can never show hidden rows
```

### 12.4 The differential test

A property test runs on **every commit** (blocking CI):

> For random models, principals and rows: **the rows `list_filter` returns == the rows `check()` allows.**

It covers deep paths, private scopes inside private scopes, closer lower assignments, groups, conditions and the agent overlap. The week-1 spike checks it on 100k rows. If the two ever disagree, the build fails. This is how we know the list and the single check can never tell different stories.

---

## 13. Field masks everywhere data leaves

(Blueprint: "Field rules only work if every other place that shows data respects them too.") A field leaves the system **only through a masked path**. Hiding it in one place is not enough.

| Where data leaves | What Tutela requires | Tag |
|---|---|---|
| API responses | Strip every field not in `field_mask.read`. Show "Restricted" or remove it, as the owner chose. | Blueprint |
| Writes | `Pdp::write_check` returns a verdict per changed field. If any field is denied, the whole write is refused (403) and the denied fields are named. Changes to `grants_access` fields need `manage_access`. | Blueprint (per-field write: Generalised) |
| Lists, counts, totals | Filtered in SQL ([12](#12-list-filtering-in-sql)). | Blueprint |
| Search and autocomplete | Index only fields whose read level equals the item's own visibility, or keep separate indexes per sensitivity. Ranking over a hidden field can reveal its value. | New |
| Vector indexes (AI search) | Same rule as search. Hidden fields never go into an embedding that a lower reader can query. | Blueprint ("AI prompts and the vector index") |
| AI prompts | Hidden fields are removed **before** the prompt is built. Never filter afterwards. | Blueprint |
| Exports (CSV, public API) | Hidden fields are **always removed**, never "Restricted". | Blueprint |
| Activity feed and notifications (e-mail, push) | Built per viewer. A change to a hidden field shows as "changed a restricted field", with no old or new value. | Blueprint |
| Webhooks and SSE events | Events are notifications only, with a small payload. Receivers re-read state through the API, where masks apply. | New |
| Audit log | Before and after are stored as **digests** or **per-field encrypted**. Masks apply when the audit log is read. | **Correction** |
| Files, previews, thumbnails | A file belongs to the item it was uploaded to and follows its access. Downloads use short-lived links made after a check, so a copied link stops working. Generated files carry the label of their sources. | Blueprint |
| Graph view, linked items, @mentions, link previews | "Restricted item", or dropped when even existence is sensitive. | Blueprint |
| Logs, traces, URLs | Never tokens, PII or field values. | New |

### 13.1 Places hidden data can escape (Blueprint checklist)

The blueprint lists the places that each need **their own test before launch**. Tutela turns this list into a conformance test kit that every product runs (Phase A for the kit; each product adds its own cases):

- list and board views
- search results and autocomplete
- counts and totals ("12 issues")
- activity feed and notifications
- items moving between scopes
- AI chat answers
- AI prompts and the vector index
- file previews and thumbnails
- CSV export and the public API
- webhooks and integrations
- graph view and linked items
- @mentions and link previews

---

## 14. UI components

(New; the blueprint's settings screens show the need.) Built in **Phase A** (manifest, codegen, React parts) and **Phase B** (permission map service, embeddable admin parts).

### 14.1 UI keys are tied to actions and routes

A product declares UI keys in `tutela.resources.toml`. **Each key names the actions and the API routes behind it.** This stops the classic mistake: hiding the Approve button but forgetting the check on `POST /approve`.

```toml
# tutela.resources.toml (format v1: MANIFEST.md)
[ui."contracts.approve_button"]
actions     = ["contract:approve"]
routes      = ["POST /api/contracts/{id}/approve"]
when_denied = "disable"
reason      = "Only reviewers can approve contracts."

[ui."contracts.budget_cell"]
fields      = ["contract.budget"]
routes      = ["PATCH /api/contracts/{id}"]
when_denied = "hide"
```

`tutela codegen` generates from the **same entry**:
- the React constants for the UI keys;
- the server route guards (axum for Rust; middleware for Node and Python).

Then:
- **The SDK refuses to start** if a declared route has no guard.
- A **generated test** calls each route as a denied principal and expects 403.
- The nightly suite checks that the UI map matches the server's decisions.

### 14.2 Modes when access is denied

| Mode | What the user sees | Typical use |
|---|---|---|
| `show` | The component as normal (access is allowed). | — |
| `disable` | The component, greyed out, with a tooltip that gives the reason. | Buttons people should know about ("ask your owner"). |
| `hide` | Nothing. | Things whose existence is sensitive. |
| `readonly` | The value, but not editable. | Fields at Read level. |

### 14.3 React parts

- `<Can>`: render children only if allowed; otherwise apply the mode.
- `<Field>`: render one field by its level: hidden, "Restricted", read-only or editable.
- `<Protect>`: guard a whole page or section.
- `useCan`: the same check as a hook.
- The UI gets its permission map from `POST /v1/authz/permissions` (ETag/304), or from the embedded engine in library mode.
- **Embeddable admin parts** (Phase B): RoleEditor, MembersTable and a permission matrix (role × field, with the four levels). A product's own customers manage roles at runtime with them. They use a separate token with `aud=tutela-admin`, a 5-minute TTL and step-up MFA.

Again: **UI hiding is never security. Every server checks again.**

---

## 15. Model changes

A tenant's **model** is its resource types, fields, roles, field rules, boundary rules, conditions and UI keys. Model changes come from four places: the Tutela Console, the embeddable admin parts, `tutela apply` (a product's manifest), and onto-intelli's PutResourceTypes import.

**Bindings** (role assignments and group memberships) are day-to-day admin work. An owner with `manage_access` adds or removes people directly, as in the blueprint. Binding changes still pass role-on-diff and the narrow-only rule, bump the tenant revision and are audited. They do not go through the impact-report and approval steps below (steps 3–4).

### 15.1 Every change goes through the same steps

1. **Role-on-diff (who may make this edit).** Tutela turns the diff into the permission keys it touches (for example `manage_fields` on matter X, or "grant Read on `contract.budget`") and checks **each one** for the editor. Narrow-only: nobody grants a level they do not hold. (Generalised; the idea comes from attache's charter diff check.)
2. **Classify the diff**: narrowing, neutral or **widening** (someone gains access).
3. **Impact report.** Tutela simulates the old and the new model over the tenant's principals and scopes, and says it in plain words: "**12 users gain read on contract.budget** in 3 scopes; 1 agent gains read; 0 users lose access." Tutela does not store app records, so the report counts principals and scopes, not rows. (Phase B)
4. **Approval.** A widening change needs approval by someone with the admin key at the higher scope. Loosening a parent's rule needs an org admin. **Two-person publish** is optional per tenant: the approver must be a different person from the author. (Phase B)
5. **Publish.** One transaction writes the change, a new `model_revision` row and the new revision number. Events `tutela.model.published.v1` and `tutela.permissions.changed.v1` go out through the outbox.
6. **Rollback** = publish the content of an earlier revision as a **new** revision. It goes through the same steps (a rollback can widen too).

The Console also has **explain** (why did this check say yes or no: the walk and the rule ids) and **simulate** (what would this draft model decide) (Phase B).

### 15.2 `tutela apply`

`tutela apply` reads a product's `tutela.resources.toml` and applies it.
- It **shows the diff first**.
- It **refuses a widening diff** unless it gets an **approval token** bound to the digest of that exact diff (issued after a human approved it).
- Each app has its own model namespace. An app's credentials can change only its own namespace, never another app's types or roles (New).
- New fields get their sensitivity default. Confidential and secret fields start at None.
- Imported changes from onto-intelli become a **proposal** that a tenant admin publishes; they are never published automatically.

Phase A ships the diff, the classification and the refusal. Phase B adds the impact report, approvals and two-person publish in `tutelad`.

---

## 16. Consistency and revocation

(Generalised from the blueprint's "any rule change bumps a version number, which clears the cache".) Mostly **Phase B**.

- **Per-tenant revision.** Every change (model or bindings) bumps the tenant's revision **in the same transaction** as the change.
- **`at_least_revision`.** After its own write (a role change, a move), a caller sends `at_least_revision` on its next check, so it never reads its own change as stale.
- **Signed bundles.** `tutelad` serves the model as signed bundles per (tenant, rev), with `issued_at` and `expires_at`. SDK caches get pushes over SSE (`/v1/events`) and pull by ETag.
- **No going back.** The PDP refuses a revision lower than the highest it has seen.
- **No stale allows.** The PDP refuses an expired bundle. Reads return **503**, not a stale allow.
- **Max bundle age per action class.** Configurable. Writes and admin actions fail closed sooner than reads. Revocation-sensitive actions (export, admin changes, opening a hidden field) check online.
- **Two or more `tutelad` replicas**, so one restart does not cause 503s.

### 16.1 How long until a revocation takes effect

The real numbers are measured and documented in Phase B, and tested in the nightly suite. The shape:

| What changed | How it reaches a running service | Worst case |
|---|---|---|
| A role, assignment or field rule | Revision bump → SSE push → new bundle | The max bundle age for that action class (online for revocation-sensitive actions) |
| A user is disabled or a session revoked | `epoch` bump; `tutela.principal.disabled.v1` / `tutela.session.revoked.v1`; token exchange refused | The access-token lifetime (10 min) if a service misses the epoch feed; much less with it |
| An agent is quarantined by attache | The agent principal is disabled; delegated tokens are refused at exchange | The delegated-token TTL (60–120 s) |
| Library mode (no `tutelad`) | The PDP reads the revision from `tutela-store` in the product's database | The PDP's revision-check interval |

### 16.2 Tenant isolation (summary)

Details in [THREAT-MODEL.md](THREAT-MODEL.md) and [ARCHITECTURE.md](ARCHITECTURE.md):
- `tenant_id` on every row, `FORCE ROW LEVEL SECURITY`, the tenant set with `SET LOCAL` per transaction from the verified token, app roles never own tables.
- A test with no tenant set must return zero rows.
- A cross-tenant read must fail at RLS even with an injected code bug (Phase B exit test).

---

## 17. Worked example

Everything here is **made up**: the company, the people, the amounts and the ids. Ids are shortened for reading; real ids are opaque UUIDv7 strings. The product is an imaginary contract tracker built on `tutela-sdk` and `tutela-pdp`.

### 17.1 The tenant and its model

- Tenant **Kestrel Foods**, tenant key (iss = `https://auth.kestrel.test`, the `tutelad` issuer; tid = `ten_…k00`). People sign in through Keycloak, and `tutelad` exchanges their Keycloak tokens for Tutela tokens (Phase B). Current revision: **42**.
- Resource types: `department` and `matter` (containers), `contract` (parent: matter), `invoice` (parent: contract).

Fields of `contract`:

| Field | Sensitivity | Note |
|---|---|---|
| `title`, `counterparty`, `status`, `review_notes` | internal | |
| `assignee` | internal | `grants_access = true` (a condition reads it) |
| **`budget`** | **confidential** | Starts at None for everyone (Correction) |
| `@chat`, `@files`, `@ai` | features | |

`invoice` has `number` (internal) and `amount` (confidential). Custom action: `contract:approve` (needs Write and the grant).

The tree:

```text
org         Kestrel Foods                              Dana: Owner (org)
└─ department  Procurement                             Omar: Owner · Jae: Member
   ├─ matter  Supplier renewals 2027   [private]       Omar: Owner · Mina: Legal reviewer
   │  │                                                Jae: Viewer · Clause AI: Agent
   │  ├─ contract  C-204  Cold-chain logistics renewal   assignee = Clause AI
   │  │  └─ invoice  INV-881
   │  └─ contract  C-207  Packaging supply
   ├─ matter  Price negotiations       [open]
   │  └─ contract  C-219
   └─ matter  Board pricing review     [private]       Dana: Owner
      └─ contract  C-311
```

People and agents:

| Name | Principal | Who they are |
|---|---|---|
| Dana | `user:usr_…d01` | Org Owner |
| Omar | `user:usr_…o02` | Head of procurement; created the matter "Supplier renewals 2027" |
| Mina | `user:usr_…m03` | Lawyer; **Legal reviewer** on the matter |
| Jae | `user:usr_…j04` | **Junior analyst**; Member of Procurement, Viewer on the matter |
| Clause AI | `agent:agt_…c05` | AI agent; Agent role on the matter; `ai_reach = project` |

Roles that matter here:

| Role | `contract` | Single fields set by the role | `invoice` | Features | Allowed custom actions |
|---|---|---|---|---|---|
| Owner (seeded) | Full | — | Full | Full | admin keys at its scope |
| Member (seeded) | Full | — | Full | Full | — |
| Viewer (declared by Kestrel; it replaces the seeded Viewer, so viewers may ask the AI) | Read | — | Read | `@chat` Read, `@ai` Write | — |
| **Legal reviewer** (tenant-defined) | Write | `title`, `counterparty`, `assignee`: Read | Read | `@chat` Write, `@ai` Write | `contract:approve` |
| Agent (declared by Kestrel; it replaces the seeded Agent, which is Read only) | Write, narrowed to Read by condition C-1 when not assigned | — | Read | — | — |

Rules:

| Id | Kind | Scope | Rule | Rev |
|---|---|---|---|---|
| FR-1 | field rule | org root | `contract.budget`, all roles → None (made when the field was registered as confidential) | 12 |
| FR-2 | field rule | org root | `invoice.amount`, all roles → None (same reason) | 12 |
| FR-3 | field rule | matter Supplier renewals | `contract.budget`, Owner → Full (Dana approved it: it loosens FR-1) | 40 |
| FR-4 | field rule | matter Supplier renewals | `contract.budget`, Agent → Read (so the agent can check invoices; Dana approved it) | 41 |
| BR-1 | boundary rule | matter Supplier renewals | private; `ai_reach = project`; links from the same department only; `on_looser = approve` | 39 |
| BR-2 | boundary rule | matter Board pricing review | private | 30 |
| C-1 | condition | role Agent, org root | on `contract`: Write when `assignee == principal`, else Read | 5 |

### 17.2 Mina opens contract C-204

| Step | What happens | Result |
|---|---|---|
| 1. Token | Tutela access token for Mina (exchanged from her Keycloak sign-in), `aud = contracts`, valid, epoch current. Not an agent token. | ok |
| 2. Tenant | (iss, tid) = (`https://auth.kestrel.test`, `ten_…k00`) is in the trust list. C-204 is loaded by id from the product DB: tenant `ten_…k00`, path C-204 → Supplier renewals → Procurement → Kestrel Foods. | ok, rev 42 |
| 3. Walk | Mina is not org Owner. C-204: no assignment. Supplier renewals: **Mina = Legal reviewer** → stop. | item level **Write** |
| 4. Conditions | Legal reviewer has none. | Write |
| 5. Fields | `title`, `counterparty`, `assignee`: role sets Read → Read. `status`, `review_notes`: Write. `budget`: role level Write; closest rule: matter has FR-3 (Owner) and FR-4 (Agent), neither matches; org root FR-1 (all roles → None) → **None**. | budget hidden |
| 6. Guardrails | Nothing lowers it further. | — |
| 7. Delegation | Not an agent token. | skipped |
| 8. Decision | **allow** `read`. Read mask: title, counterparty, status, review_notes, assignee. Write mask: status, review_notes. `contract:approve` is allowed (Legal reviewer allows it at Write). | |

In the UI: the Budget cell shows "Restricted" (`<Field>`), and the Approve button is shown (`<Can>`).

If Mina sends `PATCH /api/contracts/C-204 {"budget": 200000}`: `write_check` → `budget` is None → the whole write is **refused** (403, field named). The denied attempt goes to the audit log.

### 17.3 Jae lists contracts in Procurement

`Pdp::list_filter(Jae, contract:read)`:
- Deciding scopes for Jae: Procurement (Member → Full), Supplier renewals (private; Viewer → Read), Board pricing review (private; no assignment → None). "Price negotiations" is open, so it inherits Procurement.
- Filter: `container_in = [Procurement, Supplier renewals]`, condition = `NOT under [Board pricing review]`.
- SQL: the query in [12.3](#123-how-the-sdk-turns-it-into-sql). Rows: **C-204, C-207, C-219**. Not C-311. The count says 3, and C-311 never shows up in any count.

For `contract:write` (update) the filter is different: `container_in = [Procurement]`, `NOT under [Supplier renewals, Board pricing review]` (Viewer is below Write there). Rows: C-219 only.

### 17.4 Jae asks Clause AI in chat: "Is C-204 over budget?"

The chat service exchanges Jae's token for a delegated token (Phase B): `typ: agent+jwt`, `sub = user:usr_…j04`, `act = {sub: agent:agt_…c05}`, one audience, 90 s TTL.

| Step | Person side (Jae) | Agent side (Clause AI) |
|---|---|---|
| 3. Walk | Supplier renewals: **Viewer** → Read | Supplier renewals: **Agent** → Read |
| 4. Conditions | none | C-1: `assignee == Clause AI` is true → **Write** |
| 5. Fields | `budget`: no rule for Viewer at the matter; FR-1 → **None**. `@ai`: Write (Jae may ask the AI). | `budget`: FR-4 (Agent → Read) → min(Write, Read) = **Read** |
| 6. Guardrails | — | `ai_reach = project`: C-204 is inside the agent's matter → ok |
| 7. **Overlap** | item: min(Read, Write) = **Read**. `budget`: min(None, Read) = **None**. | |

Decision (illustrative; the request named only the data fields; wire shape in [CONTRACTS.md](CONTRACTS.md)):

```json
{
  "effect": "allow",
  "level": "read",
  "field_mask": {
    "read":  ["assignee", "counterparty", "review_notes", "status", "title"],
    "write": []
  },
  "rule_ids": ["ra_…jae_viewer", "ra_…clause_agent", "cond_C-1", "fr_FR-1", "fr_FR-4"],
  "reason": "allowed: overlap of user:usr_…j04 (Viewer) and agent:agt_…c05 (Agent) on the matter; budget hidden for the person by FR-1",
  "rev": 42,
  "obligations": [
    { "kind": "audit", "on_behalf_of": "user:usr_…j04" },
    { "kind": "label", "value": "internal" }
  ]
}
```

What happens next:
- The prompt builder removes `budget` **before** it builds the prompt. The model never sees the number.
- The agent answers: "I cannot see the budget for C-204. Omar owns this matter; you can ask him."
- The answer carries the label **internal** (the highest label of what was read).
- Audit: "10:40 Clause AI, for Jae, read C-204. Withheld: budget."

### 17.5 Jae assigns a task to the agent

Jae creates a task for Clause AI: "Write the budget headroom for C-204 into its review notes."

**Under the old blueprint rule** ("on task work the agent uses its own role"): Clause AI has `budget` Read (FR-4) and `review_notes` Write (C-1, it is the assignee). It reads the budget, writes "Budget $180,000; $14,000 left" into `review_notes`, and Jae — a Viewer — reads `review_notes`. **Jae has learned the budget.** This is the confused deputy.

**Under Tutela** the work was caused by Jae (the assigner), so the agent uses the overlap with Jae:

| | Jae | Clause AI | Overlap |
|---|---|---|---|
| `budget` read | None | Read | **None** |
| `review_notes` write | Read (Viewer) | Write | **Read → cannot write** |

The task stops with a clear reason: "The person who assigned this task (Jae) cannot change C-204, and cannot read its budget." Nothing leaks. The deny is in the audit log.

**When Omar assigns the same task**, the overlap with Omar is: `budget` min(Full, Read) = Read, `review_notes` min(Full, Write) = Write. The agent may do it. It read a **confidential** field, so the note carries the label **confidential**. Later, when Jae or Mina opens C-204, the review note shows "Restricted": they could not read the budget, so they cannot read output made from it ([11.5](#115-labels-on-output)).

### 17.6 Jae's scheduled work stops when Jae leaves

Jae set up a weekly job: "Every Monday, summarise new contracts in Supplier renewals." Each run uses the overlap with Jae. When Jae leaves Kestrel, Dana disables Jae's account. Tutela bumps Jae's `epoch` and sends `tutela.principal.disabled.v1`. The next Monday run cannot get a delegated token for a disabled person, so the job stops. It does not keep running on the agent's own access.

### 17.7 Omar wants Legal reviewers to see the budget

Omar adds field rule FR-5 in the Console: matter Supplier renewals, `contract.budget`, Legal reviewer → Read.

| Step | What happens |
|---|---|
| Role-on-diff | Needs `manage_fields` on the matter: Omar is its Owner → ok. Narrow-only: Read ≤ Omar's own `budget` level (Full) → ok. |
| Classify | **Widening**: more people can read `budget`. It also loosens the org-root rule FR-1, so it needs an **org admin**. |
| Impact report | "**1 user gains read on contract.budget** in 1 scope (matter Supplier renewals 2027): Mina. 0 agents gain access. 0 users lose access." |
| Approval | Kestrel has two-person publish on. Dana (a different person) approves. |
| Publish | One transaction: FR-5, `model_revision` 43, revision 42 → **43**. Events `tutela.model.published.v1` and `tutela.permissions.changed.v1`. New signed bundle (tenant `ten_…k00`, rev 43). |
| Effect | Services get the new bundle by SSE push. Mina's next check at rev ≥ 43 shows the budget. |

### 17.8 A manifest change that widens access

A developer edits the product's manifest and changes `budget` from `confidential` to `internal`. In CI, `tutela apply` runs against `tutelad` (Phase B, so it can show the impact report) and prints:

```text
tutela apply: diff against tenant ten_…k00 rev 43
  WIDENING  contract.budget sensitivity: confidential -> internal
  WIDENING  removes org-root rule FR-1 (all roles -> None)
  impact:   3 users (Jae, Omar, Dana) gain read on contract.budget in 3 scopes; 0 agents
refused: widening diff needs an approval token for this diff digest
```

Nothing is applied until a person approves that exact diff.

---

## 18. Tables

All tables live in `tutela-store` (Phase A). Library mode creates them in the product's own Postgres; `tutelad` uses the same schema (Phase B). Every table has `tenant_id` first. In `tutelad`, every table has `FORCE ROW LEVEL SECURITY`. Tutela stores bindings, groups, field rules, boundary rules and conditions — **never app records**. Resources are referenced only by type and id.

The first six table names come from the blueprint. The last five are new.

| Table | Origin | Important columns | Notes |
|---|---|---|---|
| `role_assignment` | Blueprint | `tenant_id`, `id`, `principal_kind` (user, sa, key, agent, group), `principal_id`, `scope_kind`, `scope_id`, `role_id`, `granted_by`, `created_at`, `expires_at` (optional), `rev` | Blueprint had `principal_kind` = user, agent, guest; Guest is now a role. Unique per (principal, scope). Deleting a principal deletes its rows in the same transaction. |
| `field_rule` | Blueprint | `tenant_id`, `id`, `scope_kind`, `scope_id`, `item_type`, `field_key` (a field or an `@feature`), `role_id` (null = all roles), `max_level`, `display` (restricted, remove), `created_by`, `rev` | Closest scope wins; at one scope, a role-specific rule beats an all-roles rule. Confidential and secret fields get an all-roles → None rule at the org root on registration. |
| `boundary_rule` | Blueprint | `tenant_id`, `scope_id`, `private`, `links_from`, `restricted_links` (locked, hidden), `moves_out`, `moves_in`, `on_looser` (approve, block), `ai_reach` (project, team), `rev` | `ai_reach` is never wider than team. `private` is a Tutela column (the blueprint marked projects private in the tree). |
| `condition` | Blueprint | `tenant_id`, `id`, `role_id`, `scope_id`, `item_type`, `rule` (a template id + parameters, as an AST), `level_if_false`, `rev` | Only vetted templates that compile to both Rust and SQL. `level_if_false` ≤ the role's level. |
| `field_registry` | Blueprint | `tenant_id`, `app`, `item_type`, `field_key`, `label`, `sensitivity` (public, internal, confidential, secret), `grants_access`, `created_by` (manifest, console, onto import, agent), `created_at` | Every field of every type. `grants_access` marks fields that conditions read (changing them needs `manage_access`). |
| `audit_event` | Blueprint (follows `audit.v1`) | `tenant_id`, `id` (UUIDv7), `time` (blueprint `at`), `org_id`, `actor_kind`, `actor_id`, `on_behalf_of`, `action`, `resource_type` + `resource_id` (blueprint `target`), `decision_effect`, `rule_ids`, `rev`, `outcome`, `reason`, `before_digest`, `after_digest` (blueprint `before`, `after`), `trace_id`, `request_id`, `labels`, `seq`, `prev_hash`, `hash` | Append-only: UPDATE and DELETE are refused. Hash-chained. Copies can go to attache's evidence ledger. See [CONTRACTS.md](CONTRACTS.md). |
| `resource_type` | New | `tenant_id`, `app`, `key`, `label`, `parent_types`, `container`, `starts` (open, private), `features`, `actions` (key → min level + grant key), `source` (manifest, console, onto), `rev` | Replaces the blueprint's fixed tree. Each app has its own namespace. |
| `role` | New | `tenant_id`, `id`, `app` (null = tenant-wide), `key`, `name`, `kind` (seeded, custom), `levels` (type, `type.field` and `type.@feature` → level), `grants` (custom actions, admin keys), `assignable_to`, `rev` | A role with admin keys or owner-only custom actions cannot be assigned to an agent or a group. |
| `group` (+ `group_member`) | New | `group`: `tenant_id`, `id`, `org_id`, `key`, `name`. `group_member`: `tenant_id`, `group_id`, `member_kind`, `member_id`, `added_by` | Groups may contain groups. A closure table makes membership one lookup. |
| `ui_component` | New | `tenant_id`, `app`, `key`, `actions`, `fields`, `routes` (method + path), `when_denied` (show, disable, hide, readonly), `reason`, `rev` | Source for `tutela codegen` (React constants and route guards). |
| `model_revision` | New | `tenant_id`, `rev`, `parent_rev`, `app`, `author`, `approvers`, `diff`, `class` (narrowing, neutral, widening), `impact`, `state` (draft, proposed, published, rejected), `created_at`, `published_at`, `bundle_digest`, `signature` | One row per model change. `rev` is the tenant revision at publish; the tenant revision goes up in the same transaction as every change, including binding changes (which are recorded in `audit_event`, not here). |

---

## 19. Open points

These are not decided yet. Each has a proposal so work can start. Final answers go into [DECISIONS.md](DECISIONS.md).

| # | Question | Proposal | When |
|---|---|---|---|
| 1 | A direct assignment and a group assignment at the same scope: which wins? | **Decided** ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)): the direct one; else every group role there counts, each with its own conditions and field rules, combined component-wise: the highest item level, the highest level per field and feature, a custom action allowed when any of the roles allows it with its own item level (never a pool of raw grants), and the union of admin keys (§6.3, §7.1; the model diff relies on this, [ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)). | Phase A |
| 2 | Where does a library-mode project (no `tutelad`) get an approval token for a widening diff? | A token signed by a tenant admin's key, bound to the diff digest. | Phase A |
| 3 | How is a reader's clearance per label stored, for labelled output? | Treat each label like a field of that sensitivity in the scope, with the same defaults. | Phase A |
| 4 | The ancestors column: array, `ltree` or closure table? Maximum path depth? | Decided by the week-1 spike (depth 32, 100k rows). | Week-1 spike |
| 5 | Default max bundle age per action class. | Reads longer, writes shorter, revocation-sensitive actions online. Numbers measured in Phase B. | Phase B |
| 6 | The list of condition templates in v1. | **Fixed** in [MANIFEST.md §8](MANIFEST.md#8-conditions) ([ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)): `eq`, `in`, `contains`, `is_principal`, `in_group`; `and`, `or`, `not`. | Phase A |
| 7 | The final names of admin keys and obligation kinds. | Admin keys: **fixed** as in [5.3](#53-owner-only-admin-actions-blueprint) ([MANIFEST.md §6](MANIFEST.md#6-admin-keys), [ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)). Obligation kinds: as in [7.3](#73-the-decision-object), still open. | Phase A, in `tutela-contracts` |
