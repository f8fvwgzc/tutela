# The manifest: `tutela.resources.toml`

Status: **Phase A.** The format and the model compiler are in `tutela-pdp` (module `model`). The evaluator that uses the compiled model (`Pdp::check` and the others) is in `tutela-pdp` too ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)). `tutela apply`, `tutela init` and `tutela codegen` come later in Phase A ([ROADMAP.md](ROADMAP.md)).

This file is the contract for the manifest format, version 1. If code and this file disagree, fix one of them in the same commit ([AGENTS.md](../AGENTS.md)).

Other docs: [README](../README.md) · [AGENTS](../AGENTS.md) · [PERMISSION-MODEL](PERMISSION-MODEL.md) · [CONTRACTS](CONTRACTS.md) · [INTEGRATION](INTEGRATION.md) · [DECISIONS](DECISIONS.md)

## 1. What the manifest is

A product declares its part of a tenant's permission model in one TOML file, `tutela.resources.toml`:

- resource types, their parents, fields, features and custom actions;
- roles, with their levels and grants;
- tenant-wide field rules and conditions (they sit at the **org root**);
- UI keys, with the actions, fields and API routes behind each one.

Role assignments, groups, and rules at one scope (a field rule on one project, a private flag on one matter) are **not** in the manifest. They are data in `tutela-store`, written by the product or by tenant admins.

The model compiler reads the manifest and either returns a compiled model or a list of every problem it found. It never repairs input and never guesses.

## 2. General rules

- The file is TOML 1.1 (parsed by the `toml` crate 1.1.x). It is at most 4 MiB.
- **Unknown keys are errors.** A typo must never drop a restriction silently.
- Hostile input must give an error, never a crash. TOML 1.1 allows multi-line inline tables, and the `toml` crate builds and drops its whole tree recursively, also for input it then refuses. So:
  - the compiler runs on its own thread with a fixed 32 MiB stack. The `toml` crate's own limits (80 nested brackets, 80 parts per key) keep its deepest tree far inside that stack;
  - before parsing, a conservative scan refuses early: tables and arrays that nest more than 32 levels or close the wrong bracket; more than 8 `.` on one line outside strings (each dotted-key part, as in `a.b.c = 1`, opens a table without a bracket; the point in a decimal number counts too); a quote that does not start a key or a value; and a single-line string that does not end on its line;
  - templates have their own depth limit (§8), and every other value is read without going into nested input.
- Problems are reported with their place. Text taken from the manifest is cut, and control or invisible (default-ignorable) characters are escaped, so it is safe to log. At most 100 problems are reported, then "and N more".
- Names follow the name grammar of [CONTRACTS.md §2.1](CONTRACTS.md#21-names): lowercase `snake_case`, 1–64 characters.
- Levels are `none`, `read`, `write`, `full` ([CONTRACTS.md §3](CONTRACTS.md#3-levels)).
- Display labels (`label`) are 1–128 characters with no control or invisible (default-ignorable) characters. They are for people only; code never matches on them.
- Everything that is not granted is denied.

## 3. Top level

```toml
version = 1                  # required; the only valid value is 1

[app]
name     = "contracts"       # required; a name; the app's model namespace
audience = "contracts-api"   # optional; an audience (CONTRACTS.md §4.2), not `tutela-admin`
```

Each app has its own model namespace. A diff between two manifests of different apps is refused.

## 4. Resource types

```toml
[types.matter]
parent    = "department"           # required: a type name, or an array of them
container = true                   # optional, default false
starts    = "private"              # containers only: "open" (default) or "private"
ai_reach  = "project"              # containers only: "project" (default) or "team"
features  = ["chat", "files", "ai"] # optional; feature names without "@"
label     = "Matter"               # optional

[types.contract]
parent   = "matter"
features = ["chat", "files", "ai"]

[types.contract.fields]
title    = { sensitivity = "internal" }
assignee = { sensitivity = "internal", type = "principal", grants_access = true }
labels   = { sensitivity = "internal", type = "string_list", grants_access = true }
budget   = { sensitivity = "confidential", type = "integer" }

[types.contract.actions]
approve = { needs = "write" }                # needs Write and a grant on the role
export  = { needs = "read", grant = false }  # every role with Read may export
```

Rules:

| Key | Rule |
|---|---|
| type name | A name. Not `org` and not starting with `tutela_` (reserved, CONTRACTS.md §2.1). At most 512 types. |
| `parent` | One or more types that may be the direct parent: `org` or declared types. A type may list itself (a folder inside a folder). Every type must reach `org` through its parents. A parent other than `org` must be a container. |
| `container` | `true` if other resources may live inside it. |
| `starts` | What a new scope of this type starts as: `open` (the blueprint default) or `private`. Containers only. |
| `ai_reach` | The default `ai_reach` of a new scope of this type: `project` or `team`. Nothing wider exists. Containers only. In Phase A the evaluator treats `team` like `project`; reach into sibling scopes needs its own ADR ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)). |
| `features` | Feature names without `@`, for example `ai` for `@ai`. No duplicates. |
| field name | A name, unique in the type. Fields and features together: at most 256 per type. |
| `sensitivity` | Required: `public`, `internal`, `confidential` or `secret`. |
| `type` | Optional, default `string`: `string`, `integer`, `boolean`, `string_list` or `principal`. Conditions use it to check their values. |
| `grants_access` | Optional, default `false`. `true` means the field decides access (a condition reads it). Changing it needs `manage_access`. **Every field a condition reads must have `grants_access = true`.** |
| action name | A name. Not a built-in action (`read`, `write`, `delete`, `manage_access`) and not an admin key (§6). At most 64 per type. |
| `needs` | Required: `read`, `write`, `full` or `owner`. `owner` makes it an owner-only action: it needs **Full on the item and the grant**. |
| `grant` | Optional, default `true`: the role must also hold `<type>:<action>`. Must be `true` when `needs = "owner"`. |

Every type also has the four built-in actions ([CONTRACTS.md §2.3](CONTRACTS.md#23-action-keys)) and the admin keys of §6. Nobody declares them.

A field that is **confidential or secret** gets an implicit field rule "all roles → None" at the org root ([PERMISSION-MODEL.md §8](PERMISSION-MODEL.md#8-defaults), the Correction). It starts hidden for everyone until a rule for one role opens it (§7).

## 5. Roles

```toml
[roles.legal_reviewer]
label  = "Legal reviewer"
grants = { contract = "write", "contract.title" = "read", "contract.@ai" = "write", "contract:approve" = true }
assignable_to = ["user", "group"]   # optional
```

`grants` maps permission keys to values:

| Key | Value | Meaning |
|---|---|---|
| a type, for example `contract` (or `org`) | a level | The item level for that type. A type the role does not list is `none`. |
| a field key, `contract.title` | a level | The level for one field. Not above the role's level for the type, and at runtime never above the role's item level after conditions. A field the role does not list uses that item level. |
| a feature key, `contract.@ai` | a level | The level for one feature. It **may** be above the type level (a Viewer may ask the AI about a contract it can only read: `contract = "read"`, `"contract.@ai" = "write"`, as in [PERMISSION-MODEL.md §17.4](PERMISSION-MODEL.md#174-jae-asks-clause-ai-in-chat-is-c-204-over-budget)), but the type level must be at least `read`. A feature the role does not list uses the role's item level after conditions. |
| an action key, `contract:approve` | `true` | A grant for a custom action that needs one, or an admin key (§6). Built-in actions come from levels and cannot be granted. `false` is an error: leave the key out instead. |

`assignable_to`: who may receive the role: `user`, `sa`, `key`, `agent`, `workload`, `group`. Default: all of them (for a declared seeded role: the seeded default, §5.1). A role that holds an admin key or an owner-only action **can never be assigned to an agent or to a group** ([PERMISSION-MODEL.md §5.3](PERMISSION-MODEL.md#53-owner-only-admin-actions-blueprint)): groups may hold agents. Its default leaves both out, and listing either is an error. The evaluator also never gives an admin key or an owner-only action to an agent, however it is reached.

Role keys are names. At most 512 roles, seeded roles included.

### 5.1 Seeded roles

Every model has these five roles ([PERMISSION-MODEL.md §6.1](PERMISSION-MODEL.md#61-seeded-roles-blueprint)). They cover every type in the manifest and `org`.

| Role | Levels | Grants | Assignable to |
|---|---|---|---|
| `owner` | `full` on every type | every custom-action grant and every admin key, on every type | everyone except `agent` and `group` |
| `member` | `full` on every type | none | everyone |
| `viewer` | `read` on every type | none | everyone |
| `guest` | `read` on every type (guests see only what they are invited to, through assignments) | none | everyone |
| `agent` | `read` on every type | none | `agent` only |

- `owner` cannot be declared or changed in a manifest.
- A manifest may declare `member`, `viewer`, `guest` or `agent`. Its entry **replaces** the seeded one completely, except that it keeps the seeded `assignable_to` unless it sets its own. For example, the blueprint's "an agent may write tasks assigned to it" is a declared `agent` role plus a condition (§8):

```toml
[roles.agent]                       # replaces the seeded agent; still agents only
grants = { task = "write" }

[[conditions]]
role = "agent"
type = "task"
when = { is_principal = "assignee" }
else = "read"
```

## 6. Admin keys

Owner-only admin actions sit above the four levels. Full never includes them ([PERMISSION-MODEL.md §5.3](PERMISSION-MODEL.md#53-owner-only-admin-actions-blueprint)). The names are fixed:

| Key | Blueprint wording |
|---|---|
| `manage_access` | Change roles, invite people (also a built-in action) |
| `manage_fields` | Set field protection |
| `manage_boundaries` | Set move and link rules |
| `manage_agents` | Configure AI agents |
| `approve_move` | Approve moves |
| `read_audit` | Read the audit log |

A role holds one as an action key, for example `"matter:manage_fields" = true`. These names cannot be used for custom actions.

An admin key needs **the key only**. An owner-only custom action (`needs = "owner"`, §4) needs **Full on the item and the grant**.

## 7. Field rules at the org root

```toml
[[field_rules]]
field   = "contract.budget"     # a field key or a feature key
role    = "owner"               # optional; leave it out for all roles
max     = "full"
display = "restricted"          # optional: "restricted" (default) or "remove"
```

- A field rule caps a field: field level = min(role level, closest field rule) ([PERMISSION-MODEL.md §7.1](PERMISSION-MODEL.md#71-the-eight-steps), step 5). At one scope, a rule for the role beats a rule for all roles.
- Rules in the manifest sit at the org root of every org. Rules at one scope are `tutela-store` data.
- At most one rule per (field, role) and one all-roles rule per field. A confidential or secret field already has its implicit all-roles rule, so an all-roles rule for it is an error. To open such a field for one role, add a rule for that role. That change is **widening** (§10).
- At most 10,000 field rules.

## 8. Conditions

```toml
[[conditions]]
role = "agent"
type = "contract"
when = { is_principal = "assignee" }
else = "read"
```

A condition narrows the role's level on one type: when `when` is false, the level drops to `else`. Conditions in the manifest sit at the org root, so they apply in every org. `else` must not be above the role's level for the type. The `owner` role cannot have conditions. At most 1,000 conditions.

`when` is one template. Only these templates exist; each one compiles both to the Rust check and to the SQL list filter ([ADR-0009](DECISIONS.md#adr-0009-lists-are-filtered-in-sql-from-the-same-evaluator)). Anything else is refused when the manifest is compiled.

| Template | True when | Field type |
|---|---|---|
| `{ eq = { field = "status", value = "open" } }` | the field equals the value | `string`, `integer` or `boolean`; the value has the same type |
| `{ in = { field = "status", values = ["open", "review"] } }` | the field equals one of 1–64 values | `string` or `integer`; all values have that type |
| `{ contains = { field = "labels", value = "client_visible" } }` | the list holds the value | `string_list`; the value is a string |
| `{ is_principal = "assignee" }` | the field is the principal being checked | `principal` |
| `{ in_group = "reviewers" }` | the principal is in the group (directly or through groups) | — |
| `{ and = [ ... ] }`, `{ or = [ ... ] }` | all / any of 2–16 templates | — |
| `{ not = { ... } }` | the template is false | — |

Rules:
- The field is a declared data field of the condition's type (not a feature) and has `grants_access = true`.
- A comparison with a null field is false. So `not` of a comparison is true on a null field.
- String values are 1–256 characters. Integers are from −(2^53 − 1) to 2^53 − 1, because the list filter sends them as JSON and readers in some languages (JavaScript) lose exact values above that.
- A template has at most 32 nodes and is at most 4 levels deep.
- The field must not be confidential or secret. Otherwise people could learn its value from what they may do.
- String values are checked like labels: no control or invisible (default-ignorable) characters.
- `in_group` names a group key. Groups are `tutela-store` data. If a template names a group that does not exist, the **whole condition** is false (fail closed), even under `not`: the level drops to `else`.
- Templates are read with a depth limit: input deeper than 4 levels is refused while it is read, before anything deeper is looked at.

## 9. UI keys

```toml
[ui."contracts.approve_button"]
actions     = ["contract:approve"]
fields      = ["contract.budget"]
routes      = ["POST /api/contracts/{id}/approve"]
when_denied = "disable"
reason      = "Only reviewers can approve contracts."
```

| Key | Rule |
|---|---|
| UI key | [CONTRACTS.md §2.5](CONTRACTS.md#25-ui-component-keys). At most 2,000. |
| `actions` | Action keys of declared types: built-in, custom or admin. |
| `fields` | Field or feature keys of declared types. |
| | At least one of `actions` and `fields`. |
| `routes` | Required, 1–16: `METHOD /path`. `METHOD` is `GET`, `POST`, `PUT`, `PATCH` or `DELETE`. The path starts with `/`, has no spaces, query or fragment, and may hold `{name}` placeholders. `tutela codegen` makes a server guard for each route. |
| `when_denied` | Required: `show`, `disable`, `hide` or `readonly` ([PERMISSION-MODEL.md §14.2](PERMISSION-MODEL.md#142-modes-when-access-is-denied)). |
| `reason` | Optional, 1–512 characters, no control or invisible (default-ignorable) characters. |

UI hiding is never security. Every server checks again.

## 10. Diffs: narrowing, neutral, widening

The compiler compares two compiled models of the same app and lists every change. Each change is **narrowing** (someone loses access), **neutral** (nobody gains or loses), or **widening** (someone gains access). The whole diff is widening if any change is. `tutela apply` refuses a widening diff without an approval token ([PERMISSION-MODEL.md §15.2](PERMISSION-MODEL.md#152-tutela-apply)). The decisions behind these rules: [ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening).

The compiler compares **effective** permissions, not text:

- **A type or role that the old model does not have is compared against a baseline where it gives nobody anything.** Whoever gets access on it is widening. Removing a type is narrowing and needs no token, so without this a removed and re-added type, a rename or a rollback could widen access unseen (Tutela does not know whether rows of the type still exist). A new role that gives nothing is neutral.
- **Field and feature levels are compared at every item level** a condition could leave, from `none` up to the role's level, with the same function the evaluator uses (`Model::effective_field_level`). They are also compared at the org root (with the org-root field rules applied). A field that is new in an existing type counts as going up from `none` (an unknown field is masked). This holds for a confidential or secret field too: it is hidden at the org root, but a rule at one scope in `tutela-store` (for example one left from before the field was removed) could open it.
- **The bar of each custom action is compared directly**: a lower `needs` or a dropped `grant` is widening, whoever holds which level today.

For each role and type:

| What | Widening when |
|---|---|
| The item level | it goes up |
| Each field and feature level, at every item level and at the org root | it goes up |
| Each custom action: allowed or not, at every item level | it becomes allowed at some item level |
| Each custom-action grant and admin key | the role gets it |
| The role's conditions on the type | one is removed or changed (a change counts as remove + add, to be safe) |
| `assignable_to` | a kind is added |

For the model:

| What | Widening when |
|---|---|
| `needs` of a custom action | it goes down (owner-only > full > write > read) |
| `grant` of a custom action | `true` → `false` |
| An org-root field rule | its `max` goes up; a new rule for one role is above the all-roles rule; or it is removed and the cap that then applies (the all-roles rule, or none) is higher than its `max` |
| A UI key | it is removed, or an action, field or route is taken away (a route loses its declared guard) |
| `starts` of a type | `private` → `open` |
| `ai_reach` of a type | `project` → `team` |
| `grants_access` of a field | `true` → `false` |
| `sensitivity` of a field | it goes down (labels on output get lower) |

The opposite direction is narrowing. These are neutral: labels, the audience, a field rule's `display`, a UI key's mode or reason, a new UI key, and types' parents and container flags. A removed type, field, action or role is narrowing. Every change gets its own line, even when another line already makes the diff widening.

## 11. Limits

A manifest over any count limit is refused at once, before any other check.

A valid manifest can still give a `list_filter` above the filter limits of [CONTRACTS.md §6.6](CONTRACTS.md#66-list_filter) for a principal with many deciding scopes, roles with conditions and nesting levels. Such a list fails closed. ROADMAP item 4 measured this and kept the limits: each nesting level of a principal's deciding scopes repeats the conditions of its roles, so the size grows with the bindings, and a limit on the manifest alone cannot bound it ([ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening), [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).

| Item | Limit |
|---|---|
| File size | 4 MiB |
| Types | 512 |
| Fields and features per type | 256 |
| Custom actions per type | 64 |
| Roles (seeded included) | 512 |
| Field rules | 10,000 |
| Conditions | 1,000 |
| Template nodes, depth | 32, 4 |
| `in` values | 64 |
| `and` / `or` arguments | 2–16 |
| UI keys | 2,000 |
| Routes per UI key | 16 |
| Actions and fields per UI key | 256 |
| Grants per role | 10,000 |
| Nesting of tables and arrays | 32 |
| `.` outside strings on one line | 8 |
| Parents per type | 64 |
| `assignable_to` entries | 16 |
| Problems reported | 100, then "and N more" |
| Diff lines | 10,000, then "and N more"; the class stays exact |

## 12. Applying: `tutela apply` and approval tokens

`tutela apply` (library mode) works like this ([ADR-0015](DECISIONS.md#adr-0015-approval-tokens-for-tutela-apply-in-library-mode)):
- It compiles the manifest and compares it with the applied one. For a first apply, it compares against an empty model of the same app.
- It prints every diff line, the class, and the SHA-256 digests of both manifests (`from` is `none` for a first apply).
- A **narrowing or neutral** diff is published at once.
- A **widening** diff is refused (exit code 3) unless `--approval` carries a valid token for exactly this change. The refusal prints the `tutela approve` command for an approver.
- Publishing stores the manifest and, in the same transaction, bumps every tenant's revision and records the change (`tutela-store`, [ADR-0014](DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)).

An **approval token** is `tutela-approval-v1.<payload>.<signature>`. Both parts are base64url without padding.
- **Payload:** the JSON object `{"app", "from", "to", "kid", "iat", "exp"}`. `from` and `to` are the manifest digests; `kid` is the approver key id; `iat` and `exp` are Unix seconds. Unknown keys are refused.
- **Signature:** Ed25519 over the ASCII bytes `tutela-approval-v1.<payload>`.
- **Key id:** `apk_` and the first 32 hex digits of SHA-256 of the 32-byte public key.
- **Valid only when all of these hold:**
  - the key is registered (`tutela approvers add`) and not revoked;
  - the signature verifies with the key, and `kid` is that key's id;
  - `app`, `from` and `to` match this exact change;
  - `now < exp`, `iat` is not more than 5 minutes in the future, and `exp - iat` is at most 24 hours.
- Since the diff is a function of the two manifests, the token approves exactly one diff. A revoked key approves nothing, also tokens it signed before.

An approver reviews the printed diff and signs with `tutela approve --app <app> --from <digest> --to <digest> --key <private key file>`. `tutela approvers keygen` writes the private key file, readable by its owner only; it never leaves the approver's machine. The database holds only public keys.

