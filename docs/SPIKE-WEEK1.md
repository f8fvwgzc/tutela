# Week-1 spike: notes written before the run

Status: **notes fixed before any spike code ran.** This file is committed alone, before the spike code, so the sizes, the machine, the thresholds and the go/no-go rules cannot be changed after the numbers are known. The result goes into [ADR-0011 in DECISIONS.md](DECISIONS.md). The plan comes from [ROADMAP.md "Very next steps" §2](ROADMAP.md#2-week-1-spike-gono-go).

Other docs: [ROADMAP](ROADMAP.md) · [PERMISSION-MODEL](PERMISSION-MODEL.md) · [CONTRACTS](CONTRACTS.md) · [DECISIONS](DECISIONS.md)

## 1. What the spike answers

| # | Question | Go if |
|---|---|---|
| 1 | Is the native evaluator fast enough? | `check` p99 **< 1 ms**, in process, warm cache, in each of the three workloads in §4. |
| 2 | Are group and path closures fast enough in Postgres at path depth 32? | p99 **< 5 ms** per query (rules in §5). |
| 3 | Does `list_filter` give exactly the rows that `check` allows? | **Zero** mismatches on 100k rows, random models and principals (rules in §6). |

Spike code is thrown away. It lives in `spike/week1/`, outside the Cargo workspace and outside the CI gates. Only these notes, the numbers and ADR-0011 are kept as the record.

## 2. The machine

| Item | Value |
|---|---|
| Computer | Apple M2 Pro, 10 cores (6 performance, 4 efficiency), 16 GiB memory (`hw.memsize` = 17179869184) |
| OS | macOS 26.6.2 (build 25G83), on AC power |
| Rust | 1.99.0 (the toolchain pinned in `rust-toolchain.toml`), `--release` build (opt-level 3) |
| Postgres | PostgreSQL 16.14 (Homebrew), its own data directory, port 5442, the default `postgresql.conf` from `initdb` except the port. The client connects over TCP to 127.0.0.1, so every query time includes one local round trip. |
| Clock | `std::time::Instant` around each single call. |

The machine is shared with other work. Rules for a valid latency run (questions 1 and 2):
- Start only when no `cargo` or `rustc` process runs and the 1-minute load average is below 4.0.
- A sampler writes `pgrep -x cargo`, `pgrep -x rustc` and the load average every 2 seconds during the run.
- If a `cargo` or `rustc` process appears during a latency run, that run is void and is run again. Every run, valid or void, is listed in ADR-0011.
- Latency runs are single-threaded. Question 3 is about correctness, not speed, so it may use several threads.

## 3. Semantics the spike uses

The spike follows [PERMISSION-MODEL.md §7](PERMISSION-MODEL.md#7-evaluation-order-step-by-step) and [CONTRACTS.md §6](CONTRACTS.md#6-the-decision-object-and-the-embedded-api). Where the docs leave a choice open, the spike uses the choice below. Each one is fixed in `tutela-pdp` later, with a doc change.

1. **Direct and group assignment at one scope** ([open point 1](PERMISSION-MODEL.md#19-open-points)): the direct assignment wins. If there is none, the group role with the highest level for the checked type wins. A tie goes to the lowest role id.
2. **Conditions**: every condition for (deciding role, resource type) at any scope on the path (the resource itself included) applies. A false condition lowers the level to its `level_if_false`. Several false conditions: the lowest wins.
3. **Field level**: the role's field level (or the item level when the role sets none) is capped by the item level after conditions, then `min` with the closest field rule.
4. **Org Owner**: a person with the Owner role at the org root (direct or through a group) gets Full on every resource of that org, also inside private scopes. Conditions of the Owner role still apply. Agents never hold Owner.
5. **Delegation**: level = `min(person, agent)`; a custom action needs the grant on both deciding roles; effect = allow only if both allow. `ai_reach` is **not** in the spike: it only narrows (an extra `under` clause), so it cannot add a new kind of mismatch.
6. **Actions**: `read` needs Read, `write` needs Write, `delete` needs Full. Custom action `approve` needs Write plus the grant; `export` needs Read plus the grant.
7. **The walk starts at the resource itself**, so an assignment on the row itself counts (the `ids_in` case), and a private container row stops inheritance for itself.
8. **Condition templates** ([open point 6](PERMISSION-MODEL.md#19-open-points)): attribute equals a value, attribute in a list, array attribute contains a value, attribute equals the principal, principal in a group; combined with and, or, not. A comparison with a null attribute is false.
9. **Ancestors column** ([open point 4](PERMISSION-MODEL.md#19-open-points)): the main design is a `bigint[]` column, nearest ancestor first, with a GIN index. "Row is under scope S" is `ancestors && $n`.

## 4. Question 1: `check` latency

### 4.1 The model (one tenant, fixed sizes)

| Item | Size |
|---|---|
| Resource types | **200**: `org`, 62 container types (2 per tier, tiers 1 to 31), 137 leaf types |
| Fields per type | 20 fields (3 public, 14 internal, 2 confidential, 1 secret) and 3 features (`@chat`, `@files`, `@ai`) |
| Custom actions per type | 2: `approve` (Write + grant), `export` (Read + grant) |
| Roles | **100** (the seeded Owner and 99 others). Each sets a level for every type, a field level on about 10% of fields, and about 30% of the custom-action grants. |
| Field rules | **5,000**: 600 org-root "all roles → None" rules (one per confidential or secret field: the Correction), and 4,400 random rules at random scopes |
| Role assignments (bindings) | **10,000**: 8,000 to users (300 of them at the org root), 1,500 to groups, 500 to agents. 90% on containers, 10% on single items. |
| Conditions | 200, random role, type, scope and template |
| Users and agents | **10,000** users, 100 agents |
| Groups | 500 groups, **nested 8 deep** (8 levels; each group below the top level is in 1–2 groups of the level above). Each user is in 1–3 groups. One big group holds all **10,000** users as direct members. |
| Resource tree | 1 org, 20,000 containers (depth 1 to 31), 200,000 items (path length 1 to **32**) |
| Private scopes | 10% of containers |

"Warm cache" means: the model is compiled into in-memory indexes, and each principal's transitive groups are computed at compile time. There is **no** per-decision memo: every call walks the path again. This is stricter than a decision cache.

### 4.2 The workloads

Each workload: 100,000 warm-up calls (not measured), then **1,000,000** measured calls. Each call is a full `check` that returns a Decision with the field mask for every field and feature of the type (`fields = None`), rule ids and reason. Random (principal, resource, action) with a fixed seed; principals are users with at least one assignment; actions are uniform over `read`, `write`, `delete`, `approve`, `export`.

| Workload | Resources | Principal |
|---|---|---|
| W1 mixed | all 220,000 resources | a user |
| W2 deep | only resources with a path of exactly 32 ancestors | a user |
| W3 delegated | all 220,000 resources | a user, with an agent as actor (overlap) |

**Go** if p99 < 1 ms in W1, W2 **and** W3. The report also gives p50, p90, p99.9 and the maximum, the model compile time and memory, and the time of one `list_filter` call on this model (information only, no threshold).

**If no-go:** change the compiled layout (for example precompute effective levels per scope) before more Phase A work, as the roadmap says.

## 5. Question 2: closure latency in Postgres

The same groups and resource tree as §4.1, loaded into Postgres. Tables:

- `group_member(tenant_id, group_id, member_kind, member_id)`: direct members only.
- `group_closure(tenant_id, member_kind, member_id, group_id)`: every transitive membership, kept on write.
- `node(tenant_id, id, parent_id, type, ancestors bigint[])`.
- `role_assignment(tenant_id, subject_kind, subject_id, scope_id, role_id)`.

Each query: 1,000 warm-up runs, then **10,000** measured runs with random inputs, as prepared statements.

| Query | What | Gated? |
|---|---|---|
| G1 | All groups of one user, by a recursive CTE over `group_member` (computed at read time) | yes |
| P1 | The path of one resource with exactly 32 ancestors, by a recursive CTE over `parent_id` | yes |
| G2 | All groups of one user, from `group_closure` | yes |
| P2 | The path of one resource with exactly 32 ancestors, from the `ancestors` column | yes |
| A1 | All role assignments that apply to one user (direct, plus through `group_closure`) | no, information |
| G3 | All transitive members of the top group, by a recursive CTE | no, information |
| W1 | Add one group into another group and update `group_closure`, in one transaction (rolled back) | no, information |

Decision rule, fixed now:
- G1 **and** P1 p99 < 5 ms: **go**. Reading closures at read time is fast enough; a closure table is optional.
- Else, G2 **and** P2 p99 < 5 ms: **go with the roadmap's fallback**: keep a closure table updated on write, and an ancestors column. Phase A builds that.
- Else: **no-go at depth 32**. Lower the depth cap and write new notes before a new run.

## 6. Question 3: `list_filter` ≡ `check`

### 6.1 The models

**20 random models, seeds 1 to 20.** The seeds are fixed here and are not changed after a failure. Each model is its own tenant. All 20 tenants share **one** Postgres table, and their row ids overlap on purpose (each tenant numbers its rows from 0). A filter that leaks another tenant's rows therefore shows up as a mismatch.

Each model draws its sizes from these ranges with its seed:

| Item | Range |
|---|---|
| Container types | 2 to 6, plus `org` and one listed leaf type |
| Containers | 1,000 to 5,000; one chain reaches depth 31 in every model |
| Rows of the leaf type | **100,000**, path length 1 to 32 |
| Private containers | 0% to 40% |
| Roles | 3 to 12 (Owner is role 0) |
| Users, agents, groups | 30 users, 5 agents, 0 to 40 groups nested up to 8 deep |
| Assignments | 100 to 3,000: to users, groups and agents; 85% on containers, 15% on single rows; some models have an org Owner |
| Conditions | 0 to 30, any template from §3.8, at random scopes |
| Row attributes | `assignee` (principal or null), `status` (text or null), `labels` (text array or null), `priority` (integer or null), `flag` (boolean or null) |

### 6.2 What is compared

For each model, 16 users and 4 (user, agent) delegated pairs are tested: 20 subjects. Actions: `read`, `write`, `delete`, `approve` on the leaf type, and `read`, `write` on every container type (its rows are the containers of that type).

For each (subject, action):
1. `list_filter` returns a filter (`ids_in`, `container_in`, condition AST), as in [CONTRACTS.md §6.6](CONTRACTS.md#66-list_filter).
2. `check` is called on every row of the type (with `fields = Some([])`).
3. (a) The filter is evaluated in Rust on every row. (b) The filter is compiled to SQL with bound parameters only and run in Postgres: `SELECT id FROM item WHERE tenant_id = $1 AND type = $2 AND <filter>`. On every tenth pair, `SELECT count(*)` with the same `WHERE` also runs.
4. The row sets from (a) and (b), and the counts, must equal the rows that `check` allows.

**Go** if there are **zero** mismatches over all models, subjects, actions and rows, in both (a) and (b).

Mismatches found while the spike code is being written are bugs in the spike. Each one is listed in ADR-0011 with its cause. The decision uses the final run of the final code on seeds 1 to 20.

The run counts these cases and reports them, so we can see the test reached them: path length 32, a private scope inside a private scope, a closer lower assignment, a group assignment, a direct assignment beating a group one at the same scope, a condition true and false, a null attribute, an assignment on the row itself, a deny caused by the delegation overlap, an org Owner.

**If no-go:** stop. Fix the evaluator. Nothing in Phase A is built on a mismatch.

### 6.3 Information collected (no threshold)

- The largest condition AST (nodes, depth) and the largest `ids_in` and `container_in`, to set the limits in [CONTRACTS.md §6.6](CONTRACTS.md#66-list_filter).
- SQL list-query time on 100k rows (p50, p99).
- On seed 1 only: the same list queries with a closure table (`item_ancestor(item_id, ancestor_id)`) instead of the array column, to choose the ancestors shape ([open point 4](PERMISSION-MODEL.md#19-open-points)).

## 7. Known limits of the spike

- One org per tenant. Several orgs per tenant work the same way (every path ends at its own org), but the spike does not test it.
- No bundles, no revisions, no token checks: those are not part of the go/no-go.
- `ai_reach`, labels, move rules and admin keys are not in the spike.
- The spike gives the evaluator the ancestors of every scope it needs (see §8).

## 8. A question to answer from the spike

To build `list_filter`, the evaluator must know how the deciding scopes nest: which private scopes and which conditions sit inside which assigned scopes ([PERMISSION-MODEL.md §12.2](PERMISSION-MODEL.md#122-what-pdplist_filter-returns), step 1). `ListFilterRequest` in [CONTRACTS.md §6.6](CONTRACTS.md#66-list_filter) has no place for scope paths, and Tutela does not store the product's tree. ADR-0011 must say where these paths come from.
