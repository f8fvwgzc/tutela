# The manifest: `tutela.resources.toml`

Status: **Phase A.** The format and the model compiler are in `tutela-pdp` (module `model`). The evaluator that uses the compiled model (`Pdp::check` and the others) comes in the next Phase A step. `tutela apply`, `tutela init` and `tutela codegen` come later in Phase A ([ROADMAP.md](ROADMAP.md)).

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

- The file is TOML 1.0. It is at most 4 MiB.
- **Unknown keys are errors.** A typo must never drop a restriction silently.
- Names follow the name grammar of [CONTRACTS.md §2.1](CONTRACTS.md#21-names): lowercase `snake_case`, 1–64 characters.
- Levels are `none`, `read`, `write`, `full` ([CONTRACTS.md §3](CONTRACTS.md#3-levels)).
- Display labels (`label`) are 1–128 characters with no control characters. They are for people only; code never matches on them.
- Everything that is not granted is denied.

## 3. Top level

```toml
version = 1                  # required; the only valid value is 1

[app]
name     = "contracts"       # required; a name; the app's model namespace
audience = "contracts-api"   # optional; an audience (CONTRACTS.md §4.2)
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
| `ai_reach` | The default `ai_reach` of a new scope of this type: `project` or `team`. Nothing wider exists. Containers only. |
| `features` | Feature names without `@`, for example `ai` for `@ai`. No duplicates. |
| field name | A name, unique in the type. Fields and features together: at most 256 per type. |
| `sensitivity` | Required: `public`, `internal`, `confidential` or `secret`. |
| `type` | Optional, default `string`: `string`, `integer`, `boolean`, `string_list` or `principal`. Conditions use it to check their values. |
| `grants_access` | Optional, default `false`. `true` means the field decides access (a condition reads it). Changing it needs `manage_access`. **Every field a condition reads must have `grants_access = true`.** |
| action name | A name. Not a built-in action (`read`, `write`, `delete`, `manage_access`) and not an admin key (§6). At most 64 per type. |
| `needs` | Required: `read`, `write`, `full` or `owner`. `owner` makes it an owner-only action. |
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
| a field key, `contract.title` | a level | The level for one field. Not above the role's level for the type. A field the role does not list uses the type level. |
| a feature key, `contract.@ai` | a level | The level for one feature. It **may** be above the type level (a Viewer may ask the AI about a contract it can only read: `contract = "read"`, `"contract.@ai" = "write"`, as in [PERMISSION-MODEL.md §17.4](PERMISSION-MODEL.md#174-jae-asks-clause-ai-in-chat-is-c-204-over-budget)), but the type level must be at least `read`. A feature the role does not list uses the type level. |
| an action key, `contract:approve` | `true` | A grant for a custom action that needs one, or an admin key (§6). Built-in actions come from levels and cannot be granted. `false` is an error: leave the key out instead. |

`assignable_to`: who may receive the role: `user`, `sa`, `key`, `agent`, `workload`, `group`. Default: all of them. A role that holds an admin key or an owner-only action **can never be assigned to an agent** ([PERMISSION-MODEL.md §5.3](PERMISSION-MODEL.md#53-owner-only-admin-actions-blueprint)); its default leaves `agent` out, and listing `agent` is an error.

Role keys are names. At most 512 roles, seeded roles included.

### 5.1 Seeded roles

Every model has these five roles ([PERMISSION-MODEL.md §6.1](PERMISSION-MODEL.md#61-seeded-roles-blueprint)). They cover every type in the manifest and `org`.

| Role | Levels | Grants | Assignable to |
|---|---|---|---|
| `owner` | `full` on every type | every custom-action grant and every admin key, on every type | everyone except `agent` |
| `member` | `full` on every type | none | everyone |
| `viewer` | `read` on every type | none | everyone |
| `guest` | `read` on every type (guests see only what they are invited to, through assignments) | none | everyone |
| `agent` | `read` on every type | none | `agent` only |

- `owner` cannot be declared or changed in a manifest.
- A manifest may declare `member`, `viewer`, `guest` or `agent`. Its entry **replaces** the seeded one completely. For example, the blueprint's "an agent may write tasks assigned to it" is a declared `agent` role with `task = "write"` plus a condition (§8).

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
- String values are 1–256 characters. Integers fit in 64 bits.
- A template has at most 32 nodes and is at most 4 levels deep.
- `in_group` names a group key. Groups are `tutela-store` data; a group that does not exist makes the template false.

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
| `reason` | Optional, 1–512 characters, no control characters. |

UI hiding is never security. Every server checks again.

## 10. Diffs: narrowing, neutral, widening

The compiler compares two compiled models of the same app and lists every change. Each change is **narrowing** (someone loses access), **neutral** (nobody gains or loses), or **widening** (someone gains access). The whole diff is widening if any change is. `tutela apply` refuses a widening diff without an approval token ([PERMISSION-MODEL.md §15.2](PERMISSION-MODEL.md#152-tutela-apply)).

The compiler compares **effective** permissions, not text. For each role in both models and each type in both models it compares:

| What | Widening when |
|---|---|
| The item level | it goes up |
| Each field and feature level at the org root: min(role level, field rules at the org root) | it goes up. A field that is new in an existing type counts as going up from `none` (an unknown field is masked), so adding a public or internal field that some role can read is widening. |
| Each custom action: allowed or not | it becomes allowed (a new action, a lower `needs`, a dropped `grant`, a new grant on the role) |
| Each admin key | the role gets it |
| The role's conditions on the type | one is removed or changed (a change counts as remove + add, to be safe) |
| `assignable_to` | a kind is added |
| `starts` of a type | `private` → `open` |
| `ai_reach` of a type | `project` → `team` |
| `grants_access` of a field | `true` → `false` |
| `sensitivity` of a field | it goes down (labels on output get lower) |

The opposite direction is narrowing. These are neutral: a new type, a new role (nobody holds it yet), labels, the audience, and UI keys. A removed type, field, action or role is narrowing.

## 11. Limits

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
