# Tutela wire contracts

> **Status: pre-alpha.** This file describes formats. Most of them are not built yet. The first commit has only the docs, the `tutela-contracts` crate and CI. Each section says what exists now and what is planned, with its phase (A, B, C or D; see [ROADMAP.md](ROADMAP.md)). Nothing here is ready for production.

This is the exact wire contract of Tutela. The `tutela-contracts` crate implements it. Every Tutela crate, the `tutelad` service, the SDKs and every product that talks to Tutela use these formats.

`docs/` is the source of truth for contracts. If the code and this file disagree, stop and say so. Change this file and the code **in the same commit** ([AGENTS.md](../AGENTS.md)).

Other docs: [README](../README.md) · [AGENTS](../AGENTS.md) · [SECURITY](../SECURITY.md) · [ARCHITECTURE](ARCHITECTURE.md) · [PERMISSION-MODEL](PERMISSION-MODEL.md) · [THREAT-MODEL](THREAT-MODEL.md) · [INTEGRATION](INTEGRATION.md) · [ROADMAP](ROADMAP.md) · [DECISIONS](DECISIONS.md)

What the rules **mean** (closest role wins, field rules, the agent overlap) is in [PERMISSION-MODEL.md](PERMISSION-MODEL.md). This file only fixes the **shapes** on the wire.

## Contents

- [What the first commit implements](#what-the-first-commit-implements)
- [0. Conventions](#0-conventions)
- [1. Identifiers and principals](#1-identifiers-and-principals)
- [2. Permission keys](#2-permission-keys)
- [3. Levels](#3-levels)
- [4. Access tokens](#4-access-tokens)
- [5. API keys](#5-api-keys)
- [6. The Decision object and the embedded API](#6-the-decision-object-and-the-embedded-api)
- [7. Remote check API](#7-remote-check-api)
- [8. Events](#8-events)
- [9. The audit.v1 record](#9-the-auditv1-record)
- [10. Versioning and deprecation](#10-versioning-and-deprecation)
- [11. Open points](#11-open-points)

---

## What the first commit implements

Only the left column exists in `tutela-contracts` after the first commit. Everything in the right column is planned.

| § | Contract | In `tutela-contracts` (first commit) | Planned |
|---|---|---|---|
| 1 | Ids, principals, tenant key | Parse and print UUIDv7 ids, every principal kind, tenant ids, org ids; the tenant key pair (iss, tid) | Trust-bundle binding of workload principals (B) |
| 2 | Permission keys | Type, field, feature and action names; field keys; action keys; built-in actions; UI keys | The manifest `tutela.resources.toml` (A) |
| 3 | Levels | The four levels, their order, `min` | Proto enum (B) |
| 4 | Tokens | Claim structs for access tokens and delegated tokens, and their claim checks (no size, header, signature or `epoch` check) | Full verification in `tutela-sdk` (A); token exchange in `tutelad` (B); own OIDC provider (C, optional) |
| 5 | API keys | Parse, format check, display prefix | Hashing, storage, verification, rotation (A, B) |
| 6 | Decision | The Decision object: effect, level, field mask, rule ids, reason, rev, obligations | `Pdp::check`, `Pdp::batch`, `Pdp::list_filter`, `Pdp::write_check` (A; built in `tutela-pdp`, [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)) |
| 7 | Remote check API | — | Built in `tutelad` (B): evaluation, search, the permission map, write-check and gRPC. |
| 8 | Events | CloudEvents envelope, event type grammar and names | Outbox, webhooks, SSE (B) |
| 9 | audit.v1 | The audit.v1 record | Producer signatures, sequence numbers, local hash chain, forwarding to attache's evidence ledger (B) |
| 10 | Versioning | The rules apply from the first commit | Deprecation headers on live endpoints (B) |

---

## 0. Conventions

- **"must"** means required. A reader that sees a value that breaks a "must" rule rejects the whole message. It never guesses and never repairs.
- Ids and keys are compared **byte by byte**. No case folding, no trimming, no Unicode normalisation. Every grammar in this file is ASCII.
- ABNF follows RFC 5234. **In this file, quoted strings inside ABNF are case-sensitive** (like `%s"..."` in RFC 7405). `lower` = `%x61-7A` (a–z), `DIGIT` = `%x30-39`, `ALPHA` = a–z and A–Z.
- Regexes are full-match (anchored at both ends).
- JSON is UTF-8. Field names are `snake_case`. Writers **omit** an optional field that has no value. Readers treat a missing field and `null` the same.
- Readers **ignore unknown JSON fields and unknown claims**. This is what lets v1 grow (section 10). An ignored field is never used for a decision.
- **Closed sets** (levels, effect, principal kinds, outcome) are exact: an unknown value is an error, which means deny. **Open sets** (event types, reason codes, obligation kinds) say their own fallback where they are defined.
- Integers in JSON are whole numbers from 0 to 2^53 − 1 unless a field says otherwise.
- Times in JSON: RFC 3339, UTC, `Z` suffix, exactly 3 fractional digits. Example: `2026-10-25T09:30:00.000Z`. Times inside JWTs are NumericDate: whole seconds since the Unix epoch.
- In examples, `<like this>` is a placeholder and `…` marks a shortened value. Every example value is a test value.

---

## 1. Identifiers and principals

**First commit:** all of section 1 is in `tutela-contracts` (parse, print, validate). The trust-bundle check for workloads is Phase B.

### 1.1 UUIDv7 text

Every Tutela id uses a UUID version 7 (RFC 9562) in this exact text form:

- 36 characters: 8-4-4-4-12 hex digits, separated by `-`;
- lowercase hex only (`0-9`, `a-f`);
- the version digit (first digit of the 3rd group) is `7`;
- the variant digit (first digit of the 4th group) is `8`, `9`, `a` or `b`.

```abnf
uuidv7   = 8hexl "-" 4hexl "-" "7" 3hexl "-" variant 3hexl "-" 12hexl
hexl     = DIGIT / %x61-66        ; 0-9 and a-f only
variant  = "8" / "9" / "a" / "b"
```

Regex: `[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`

Rejected (never repaired): uppercase hex, braces, a `urn:uuid:` prefix, no hyphens, any other version (for example v4), the nil and max UUIDs.

Note: the first 48 bits of a UUIDv7 are a millisecond timestamp. So an id shows when it was made. This is accepted. Ids are not secrets, and an id alone never grants access.

### 1.2 Tutela ids

| Id | Format | Example |
|---|---|---|
| User | `usr_<uuidv7>` | `usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081` |
| Service account | `sa_<uuidv7>` | `sa_0193a1b2-c3d4-7c55-ad66-7e8f90a1b2c3` |
| API key | `key_<uuidv7>` | `key_0193a1b2-c3d4-7d77-be88-9fa0b1c2d3e4` |
| Agent | `agt_<uuidv7>` | `agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102` |
| Tenant | `ten_<uuidv7>` | `ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b` |
| Org | `org_<uuidv7>` | `org_0193a1b2-c3d4-7f00-9a00-000000000002` |
| Session | `ses_<uuidv7>` | `ses_0193a1b2-c3d4-7123-8456-789abcdef012` |
| Token id (`jti`), event id, audit record id | bare `<uuidv7>` | `0193a1b2-c3d5-7000-8000-0000000000e1` |

Rules:
- Tutela makes these ids: `tutela-store` in library mode (Phase A), `tutelad` in service mode (Phase B). An id is **never reused**, also not after a delete.
- Ids from other systems (a Keycloak user id, a Keycloak organization id) are **never** used as Tutela ids. Tutela keeps a mapping. Accounts are found by the upstream `(iss, sub)`, never by e-mail.
- Names and e-mails are display labels. They never appear inside an id.

### 1.3 Principal strings

A principal is "who is asking". On the wire it is one string: `<kind>:<id>`.

```abnf
principal = user / sa / key / agent / workload
user      = "user:usr_" uuidv7
sa        = "sa:sa_" uuidv7
key       = "key:key_" uuidv7
agent     = "agent:agt_" uuidv7
workload  = "workload:" spiffe-id      ; section 1.4
```

| Kind | String | Length | What it is |
|---|---|---|---|
| `user` | `user:usr_<uuidv7>` | 45 | A person. |
| `sa` | `sa:sa_<uuidv7>` | 42 | A service account: an app or service that acts as itself (client credentials, `tut_sk_` keys). |
| `key` | `key:key_<uuidv7>` | 44 | One API key. A key never holds more than its owner. |
| `agent` | `agent:agt_<uuidv7>` | 46 | An AI agent. attache owns the agent's runtime and registry. Tutela holds the agent as a principal. |
| `workload` | `workload:spiffe://…` | at most 2057 | A workload with a SPIFFE ID. attache runs workload mTLS. Tutela only names the workload. |

Rules:
- The kind is the text before the first `:`. A parser checks the **whole** string against the grammar. A prefix match is not enough.
- The kind and the id prefix must agree. `user:sa_…` is invalid.
- A bare id (`usr_…`) is used only where the kind is already fixed, for example in a Console URL path (Phase B). Everywhere else, use the full principal string.
- A `group` is not a principal. Groups receive role assignments, but a group never makes a request ([PERMISSION-MODEL.md](PERMISSION-MODEL.md)).

### 1.4 Workload principals (SPIFFE)

`workload:` followed by a SPIFFE ID. Tutela follows the SPIFFE ID standard and adds three rules.

SPIFFE rules:
- The scheme is exactly `spiffe://` (lowercase).
- Trust domain: 1–255 characters from `a-z 0-9 . - _`. No uppercase. No port, no user info.
- Path: one or more segments, each after a `/`. A segment has 1 or more characters from `a-z A-Z 0-9 . - _`. A segment is never `.` or `..`. No empty segment (`//`), no trailing `/`.
- No query (`?`), no fragment (`#`), no percent-encoding.
- The whole SPIFFE ID is at most 2048 bytes.

attache issues every workload identity Tutela sees. It names a workload per **service**, not per Kubernetes service account: `spiffe://<trust domain>/ns/<namespace>/svc/<service>`. This path is the URI SAN of each certificate attache's embassy issues, and the identity that charters name in `authz.callers` and `authz.services`. Tutela does not check this form (any path that follows the rules here parses), but write this path in bindings and trust rules: a `/sa/<service account>` path never matches an attache workload.

Tutela's extra rules:
1. The path must not be empty. `spiffe://prod-eu1.example.test` names a trust domain, not a workload.
2. Each trust domain must be **unique per cluster**. A fixed shared name (such as `agentsc` in every cluster) is not allowed, because the ids would collide across clusters.
3. A workload principal is valid in a tenant only when the tenant is pinned to that trust domain's trust bundle. Tutela stores the pair (trust bundle, SPIFFE ID). (Phase B.)

```abnf
spiffe-id    = "spiffe://" trust-domain 1*( "/" segment )
trust-domain = 1*255( lower / DIGIT / "." / "-" / "_" )
segment      = 1*( ALPHA / DIGIT / "." / "-" / "_" )   ; but never "." or ".."
```

| Example | Valid? | Why |
|---|---|---|
| `workload:spiffe://prod-eu1.attache.example.test/ns/shop/svc/orders` | yes | |
| `workload:spiffe://Prod.example.test/ns/shop` | no | uppercase in the trust domain |
| `workload:spiffe://prod.example.test` | no | empty path |
| `workload:spiffe://prod.example.test/ns//shop` | no | empty segment |
| `workload:spiffe://prod.example.test/ns/shop/` | no | trailing `/` |
| `workload:spiffe://prod.example.test/ns/../shop` | no | `..` segment |
| `workload:spiffe://prod.example.test:8443/ns/shop` | no | port |
| `workload:spiffe://prod.example.test/ns/shop%2Fx` | no | percent-encoding |

### 1.5 Tenants and orgs

- A **tenant** is the unit of isolation. Every Tutela row has a `tenant_id`. A tenant has one permission model and one revision counter. From Phase C it also has its own signing keys ([THREAT-MODEL.md](THREAT-MODEL.md), TM-15).
- An **org** is an organization inside a tenant, for example one nexc-engine workspace. A tenant has many orgs. The org is the root of every resource tree in it.
- Tenant id: `ten_<uuidv7>`. Org id: `org_<uuidv7>`.
- How tenants and orgs map onto each product: [ARCHITECTURE.md](ARCHITECTURE.md) and [PERMISSION-MODEL.md](PERMISSION-MODEL.md).

### 1.6 The tenant key (iss, tid)

A tenant id alone is not enough. The SDK may trust more than one issuer, and two issuers could use the same `tid`. So the tenant is **always the pair** (iss, tid): in `tutela-pdp`, in database keys, in caches, in audit records, in attache's evidence-ledger chain key and in other cores' tenant mappings ([ADR-0008](DECISIONS.md#adr-0008-tenant-key-is-iss-tid-accounts-are-keyed-by-iss-sub)).

```json
{ "iss": "https://auth.example.test", "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b" }
```

| Part | Rule |
|---|---|
| `iss` | The issuer URL. An absolute `https` URL with no user info, no query and no fragment. At most 255 characters. Compared as exact text: no trailing-slash fix-ups, no case folding. `http` is allowed only for a loopback host (`localhost`, `127.0.0.1`, `[::1]`) in dev mode. |
| `tid` | A tenant id, `ten_<uuidv7>`. |

Rules:
- There is **no one-string form** on the wire. Store the tenant key as two columns. Never use `tid` alone as a key.
- The SDK trust list maps each issuer to the tenants it may speak for. A token is accepted only if its (iss, tid) pair is on the list.
- An external issuer whose tokens carry no `tid` (Phase A, for example Keycloak) must map to **exactly one** tenant in the trust list. That tenant is used. A product with many tenants on one external issuer uses Tutela tokens from token exchange instead (Phase B).
- `org` is never taken from an external issuer's claim. It comes from Tutela membership.

---

## 2. Permission keys

**First commit:** all grammars of section 2 are in `tutela-contracts`. The manifest that declares types, fields, actions and UI keys (`tutela.resources.toml`) is Phase A; its format v1 is in [MANIFEST.md](MANIFEST.md), and its compiler is in `tutela-pdp`.

### 2.1 Names

Resource type names, field names, action names, feature names (after the `@`) and label names all use one grammar: lowercase `snake_case`, 1–64 characters.

```abnf
name = lower *( lower / DIGIT ) *( "_" 1*( lower / DIGIT ) )   ; 1 to 64 characters in total
```

Regex: `[a-z][a-z0-9]*(_[a-z0-9]+)*` with a length check of 1–64.

| Example | Valid? |
|---|---|
| `invoice`, `purchase_order`, `line2`, `po_line_v2` | yes |
| `Invoice`, `_invoice`, `invoice_`, `invoice__line`, `2fa`, `invoice-line`, `invoice.line` | no |

Reserved type names:
- `org`: the root type of every resource tree. Its ids are org ids (`org_<uuidv7>`).
- Every name that starts with `tutela_`: Tutela's own types (for example roles and API keys in the admin API, Phase B).

Products and tenants cannot declare reserved names. Type names are unique per tenant. Field, feature and action names are unique per type.

### 2.2 Field keys and feature keys

| Key | Format | Example | Notes |
|---|---|---|---|
| Field key | `<type>.<field>` | `invoice.amount` | Exactly one `.`. At most 129 characters. |
| Feature key | `<type>.@<feature>` | `task.@ai` | A feature is a part of an item that is not a data field: chat, files, AI. The `@` keeps it apart from field names. At most 130 characters. |

Inside a field mask (section 6.1) the type is already known, so the mask lists bare field names (`amount`) and bare feature names (`@ai`).

### 2.3 Action keys

```abnf
action-key = name ":" name        ; <type>:<action>
```

Exactly one `:`. Example: `invoice:approve`. At most 129 characters.

**Built-in actions.** Every type has these four. Nobody declares them.

| Action | Needs | Meaning |
|---|---|---|
| `read` | Read | Open and view the item. Fields are filtered by the field mask. |
| `write` | Write | Change the item, and create items inside it. Each changed field is checked by `write_check` (6.7). |
| `delete` | Full | Delete or archive the item. |
| `manage_access` | Owner-only admin (above the four levels) | Change roles, invite people, and change fields marked `grants_access`. Never implied by Full. Never held by an agent. |

Notes:
- [PERMISSION-MODEL.md §5.2](PERMISSION-MODEL.md#52-actions) explains "create" and "update" in words. On the wire both are `write` (create is `write` on the container). A product that needs `archive` apart from `delete` declares a custom action `archive` with level `full`.
- Other owner-only admin actions use the same grammar (`<type>:<name>`). The names are fixed by the manifest format ([MANIFEST.md §6](MANIFEST.md#6-admin-keys)): `manage_fields`, `manage_boundaries`, `manage_agents`, `approve_move`, `read_audit` ([PERMISSION-MODEL.md §5.3](PERMISSION-MODEL.md#53-owner-only-admin-actions-blueprint)). A custom action may not use these names. The name is `read_audit`, not `audit.read`, because a `.` marks a field key.

**Custom actions.** A product declares them per type in `tutela.resources.toml` ([MANIFEST.md §4](MANIFEST.md#4-resource-types)), for example `contract:approve`. Each custom action names the level it needs (`read`, `write` or `full`), or says it is owner-only. A custom action may also need an explicit grant on the role ([PERMISSION-MODEL.md](PERMISSION-MODEL.md)). A custom action name must not be one of the built-in names above.

### 2.4 Permission keys

A **permission key** is an action key, a field key or a feature key. It is the value of `action` in audit.v1 (section 9), and what attache's role-on-diff returns for `tutela-pdp` to check.

### 2.5 UI component keys

```abnf
ui-key = name 1*7( "." name )     ; 2 to 8 names, at most 128 characters
```

Example: `invoices.approve_button`.

- A UI key is **not** a permission key. It appears only in the `ui` table of `tutela.resources.toml`, in the permission map (7.5) and in React props. Each UI key names the action keys and API routes behind it ([PERMISSION-MODEL.md §14](PERMISSION-MODEL.md#14-ui-components)).
- A UI key and a field key can look alike (`invoices.approve_button`, `invoice.amount`). The place where a string appears decides its kind. Parsers never guess.
- UI hiding is never security. Every server checks again.

---

## 3. Levels

**First commit:** in `tutela-contracts`. The proto enum is Phase B.

| Level | JSON | On an item | On a field | On a feature |
|---|---|---|---|---|
| None | `"none"` | You cannot tell it exists. It never shows in lists, search, counts or links. | Removed, or shown as "Restricted". | Not shown. |
| Read | `"read"` | Open and view it. | See the value. | Read chat history, download files. |
| Write | `"write"` | Edit it and create items inside it. | Change the value. | Send messages, upload files, ask the AI. |
| Full | `"full"` | Write, plus delete and archive. | Write, plus clear the value and see its history. | Write, plus delete messages and files. |

Rules:
- Order: `none < read < write < full`. In Rust the enum derives `Ord` in exactly this order.
- JSON spelling is the lowercase string. Anything else is a parse error and means deny: `"None"`, `"admin"`, `"owner"`, a number, `null`.
- `min(a, b)` is the lower of the two. It is used for:
  - field level = `min(role level, closest field rule)`;
  - delegated access = `min(person, agent)`, per item and per field.
- Owner-only admin actions sit **above** the four levels. They are not a level and never appear as a level value. They are never granted by default.
- Proto enum (Phase B), in `tutela.authz.v1`: `LEVEL_UNSPECIFIED = 0` (invalid, treated as deny), `LEVEL_NONE = 1`, `LEVEL_READ = 2`, `LEVEL_WRITE = 3`, `LEVEL_FULL = 4`.

---

## 4. Access tokens

**First commit:** the claim structs (4.2 and 4.5) are in `tutela-contracts`, with the claim checks (steps 3 and 5 to 8 of the verification order in 4.2, and the `act`, `cap` and lifetime rules of 4.5). The size, header, signature and `epoch` checks, and the delegation steps that need service config, are in `tutela-sdk` (Phase A). `tutelad` issues Tutela tokens from Phase B: a token-exchange service accepts the Keycloak token and issues a short-lived Tutela access token, with just-in-time user provisioning. Delegated agent tokens are Phase B and **not optional** ([ADR-0006](DECISIONS.md#adr-0006-delegated-agent-tokens-in-phase-b-not-optional)). Tutela's own OIDC provider is Phase C and optional; it issues the same format.

### 4.1 JOSE header

| Header | Rule |
|---|---|
| `typ` | `at+jwt` for an access token (RFC 9068). Verifiers accept `at+jwt` or `application/at+jwt` (case-insensitive). `agent+jwt` is a delegated token (4.5). Any other value: reject. For external issuers in Phase A, see 4.6. |
| `alg` | Allow-list: `ES256` (default), `RS256`, `EdDSA` (Ed25519). Never `none`, never `HS256`/`HS384`/`HS512`. The verifier takes the allowed list from its config, never from the token. |
| `kid` | Required. The RFC 7638 JWK thumbprint (SHA-256, base64url, 43 characters). Unknown `kid`: refetch the issuer's JWKS once (rate limited), then reject. A `kid` on the deny-list: reject at once. |
| `jku`, `x5u`, `jwk`, `x5c`, `crit` | Never used. A token that has any of them is rejected. |

### 4.2 Access-token claims

| Claim | JSON type | Required | Rule |
|---|---|---|---|
| `iss` | string | yes | Exact match with an issuer on the trust list. Part of the tenant key. |
| `sub` | string | yes | A principal string (1.3) of kind `user`, `sa`, `key` or `agent`. Never `workload`. Kind `agent` is only for an agent's own control calls; work that a person caused uses a delegated token (4.5). |
| `aud` | string | yes | **Exactly one** audience, equal to the verifier's own audience. Tutela writes a JSON string. Verifiers also accept an array with exactly one element; an array with 0 or 2+ elements is rejected. Grammar: `[a-z][a-z0-9-]{0,62}`. Examples: `symphony`, `onto`, `crm-api`, `tutela-admin`. |
| `azp` | string | yes | The client id of the app that got the token. 1–255 visible ASCII characters (`%x21-7E`). |
| `exp` | integer | yes | NumericDate. `exp − iat ≤ 600` (10 minutes). |
| `iat` | integer | yes | NumericDate. |
| `nbf` | integer | yes | NumericDate. Tutela sets `nbf = iat`. |
| `jti` | string | yes | `<uuidv7>`. Unique per token. Used to name a token in logs (never the token itself) and to revoke one token. |
| `sid` | string | for users | `ses_<uuidv7>`. Required when `sub` is a `user`. Absent for `sa`, `key` and `agent`. |
| `tid` | string | yes | `ten_<uuidv7>`. With `iss`, the tenant key. |
| `org` | string | no | `org_<uuidv7>`, the active org. Tutela adds it only after checking membership. It must be an org of `tid`. |
| `epoch` | integer | yes | The subject's session epoch. Tutela raises it when the principal is disabled or its sessions are revoked. |
| `rev` | integer | yes | The tenant revision when the token was issued. A lower bound for the PDP (see the rules below). |
| `scope` | string | no | OAuth scopes, separated by single spaces (RFC 6749 §3.3). Scopes only narrow: they can remove access, never add it. |
| `amr` | array of strings | for users | Authentication methods, RFC 8176 values (`pwd`, `otp`, `hwk`, `mfa`, …). Required and **non-empty** when `sub` is a `user`. |
| `acr` | string | no | Authentication context class from the issuer. Step-up checks use it (4.4). |
| `act` | — | **forbidden** | An access token never carries `act`. A token with `act` is a delegated token (4.5) sent the wrong way, so verifiers reject it, even though readers otherwise ignore unknown claims (section 0). Without this rule, a service could treat an agent as the person acting alone. |

Time rules, with a **60 s clock-skew** allowance:
- reject if `now > exp + 60`;
- reject if `now + 60 < nbf`;
- reject if `iat > now + 60`;
- reject if `exp ≤ iat`, or if `exp − iat > 600` (for `agent+jwt`: `> 120`; for `aud = tutela-admin`: `> 300`);
- reject if `nbf > exp` (the token would never be valid).

`epoch` and `rev` rules:
- The SDK learns the newest epoch per principal from `tutela.session.revoked.v1` and `tutela.principal.disabled.v1` (section 8). It rejects a token whose `epoch` is lower than the newest epoch it knows for that `sub`.
- The PDP never decides with a bundle older than the token's `rev`. It loads a newer bundle, or fails with "stale" (HTTP 503 in the remote API). It never answers allow from a stale bundle.

**Verification order** (`tutela-sdk`, Phase A). Any failure gives 401. The response says nothing about which step failed; the log names the step, never the token.
1. Size: reject tokens over 8 KiB.
2. Header: `typ`, `alg`, `kid`, forbidden headers (4.1).
3. Find the issuer on the trust list by `iss`. Its JWKS is fetched over https only, through `tutela-safenet`.
4. Verify the signature.
5. `aud`: exactly one, and it is ours.
6. Times (above).
7. (iss, tid) is on the trust list (1.6).
8. `sub` parses as a principal of an allowed kind.
9. `epoch` is current; the principal is not disabled.
10. For `agent+jwt`: the extra steps in 4.5.

### 4.3 Example

Header:

```json
{ "typ": "at+jwt", "alg": "ES256", "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" }
```

Payload:

```json
{
  "iss": "https://auth.example.test",
  "sub": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081",
  "aud": "crm-api",
  "azp": "crm-web",
  "exp": 1792921200,
  "iat": 1792920600,
  "nbf": 1792920600,
  "jti": "0193a1b2-c3d4-7e99-8f00-a1b2c3d4e5f6",
  "sid": "ses_0193a1b2-c3d4-7123-8456-789abcdef012",
  "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
  "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002",
  "epoch": 3,
  "rev": 42,
  "scope": "openid invoices",
  "amr": ["pwd", "otp", "mfa"],
  "acr": "mfa"
}
```

### 4.4 Special audiences

| Audience | Used by | Extra rules |
|---|---|---|
| `tutela-admin` | Tutela Console and the embeddable admin components (Phase B) | `exp − iat ≤ 300` (5 minutes). Step-up MFA: `acr` must be one of the values the deployment configures as MFA (before Phase C this comes from the upstream IdP). Never sent to product APIs. |
| `tutela-authz` (name planned) | The remote check API and the permission map (section 7, Phase B) | Usually a service-account token of a product backend. |

### 4.5 Delegated (agent) tokens

An agent that acts for a person uses a delegated token. Tutela issues it through RFC 8693 token exchange in `tutelad` (Phase B).

Header: `typ` = `agent+jwt`. Other header rules as in 4.1. **An SDK refuses `agent+jwt` unless delegation support is switched on in its config.**

Claims: every claim of 4.2, with these changes.

| Claim | JSON type | Required | Rule |
|---|---|---|---|
| `sub` | string | yes | The **person** (`user:usr_…`) who caused the work: the chat user, the task assigner, or the requester of scheduled work. |
| `act` | object | yes | `{"sub": "agent:agt_…"}`: the agent that acts now. It may hold a nested `act` (RFC 8693) for an agent that acts for an agent. The chain holds **at most 4** actors; deeper is rejected. Every actor in the chain must be an `agent` principal, and **every** actor must be allowed (6.4). |
| `cap` | object | yes | attache's capability snapshot. **Opaque to Tutela**: Tutela copies it from the exchange request and never reads or widens it. At most 4096 bytes as JSON. |
| `run_id` | string | yes | The run this work belongs to. 1–128 characters from `A-Z a-z 0-9 . _ : -`. The format is owned by the caller (texc-symphony, attache). |
| `node_id` | string | no | The step inside the run. Same grammar as `run_id`. |
| `aud` | string | yes | Exactly one. The audience must be registered with `delegation_aware = true`. |
| `exp`, `iat` | integer | yes | The issuer picks a TTL of 60–120 s. A verifier rejects `exp − iat > 120`. |
| `sid` | string | no | The person's session, when there is one. Scheduled work has none. |
| `epoch` | integer | yes | The **person's** epoch. Disabling the person stops their agent tokens and their scheduled work. |
| `amr` | array of strings | no | The person's methods, when known. |
| `cnf` | object | no | mTLS binding (RFC 8705): `{"x5t#S256": "<base64url SHA-256 of the client certificate>"}`. If present, the verifier checks the TLS client certificate. |

Extra verification steps:
1. Delegation support is on for this service.
2. Our audience is registered `delegation_aware`.
3. `act` parses; every actor is an `agent` principal; the chain has at most 4 actors.
4. No actor is disabled (from `tutela.principal.disabled.v1`).
5. If `cnf` is present, it matches the client certificate.

Rules:
- A service that receives an agent token **never forwards it**. To call the next service, it exchanges the token for a new one with that service's audience.
- Every decision with a delegated token uses the overlap (6.4). attache's capability limits apply on top of that, inside attache.

Example payload:

```json
{
  "iss": "https://auth.example.test",
  "sub": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081",
  "act": { "sub": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102" },
  "cap": { "snapshot": "<attache data, opaque to Tutela>" },
  "run_id": "run-2026-10-25-0001",
  "node_id": "review-step-2",
  "aud": "symphony",
  "azp": "attache-sidecar",
  "exp": 1792920750,
  "iat": 1792920660,
  "nbf": 1792920660,
  "jti": "0193a1b2-c3d4-7e99-8f00-a1b2c3d4e5f7",
  "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
  "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002",
  "epoch": 3,
  "rev": 42
}
```

(`run_id` above is only an example value; its format belongs to the caller.)

### 4.6 External issuer tokens (Phase A)

Before Phase B there is no `tutelad`. A product verifies tokens from an external OIDC issuer directly with `tutela-sdk`. Keycloak 26.x is recommended: one realm per deployment, using Keycloak Organizations. Rules:
- Header rules as in 4.1, except `typ`: `at+jwt` is preferred. `JWT` is accepted only from an issuer whose trust-list entry allows it.
- Required claims: `iss` (exact), `sub`, `aud` (exactly one: set up the Keycloak client so its tokens carry exactly one audience), `exp` and `iat`. Time rules as in 4.2 (set the access-token lifespan to 10 minutes or less). `alg` allow-list as in 4.1.
- `azp` and `nbf` are checked when present. `jti`, `sid` and `amr` are not parsed as Tutela formats; the issuer owns them.
- `tid` comes from the trust list (1.6), never from a token claim.
- `sub` is mapped through `(iss, sub)` to a Tutela principal. Never through the e-mail claim.
- `org` comes from Tutela membership, never from a token claim.
- There are no `epoch` or `rev` claims. Revocation waits for the token to expire: at most 10 minutes plus skew. This delay is documented for the product.

### 4.7 What is never in a token

- Permission lists, role lists or field masks. Tokens carry identity and a revision (`rev`), not grants.
- E-mail, names or other profile data. Read them through the API.
- Secrets.

Tokens are never written to logs, URLs or span attributes.

---

## 5. API keys

**First commit:** parsing, the format check and the display prefix are in `tutela-contracts`. Hashing, storage, verification and rotation are Phase A (library mode in `tutela-store`) and Phase B (`tutelad`).

### 5.1 Format

```
tut_sk_7f3k9q2m_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

| Part | Value |
|---|---|
| `tut_` | Fixed. Marks a Tutela key, so secret scanners can find it. |
| kind | `sk`: a key of an app or service account. `ak`: an agent key. |
| `_` | Fixed. |
| prefix | 8 characters from `a-z 0-9`, random. The public part. Used to find the key. |
| `_` | Fixed. |
| secret | 43 characters of base64url without padding: 32 random bytes. |

Total length: exactly **59** characters.

```abnf
api-key = "tut_" ( "sk" / "ak" ) "_" 8( lower / DIGIT ) "_" 43b64url
b64url  = ALPHA / DIGIT / "-" / "_"
```

Regex: `tut_(sk|ak)_[a-z0-9]{8}_[A-Za-z0-9_-]{43}`

### 5.2 Parsing rules

- Check the length (59) and parse by **fixed positions**. Never split on `_`: the secret can contain `_`.
- The secret must decode (base64url, no padding, canonical) to exactly 32 bytes. Canonical means the last character is one of `A E I M Q U Y c g k o s w 0 4 8`.
- Do not trim spaces or line breaks. A key with them is invalid.
- The **display prefix** is the first 15 characters, for example `tut_sk_7f3k9q2m`.

### 5.3 Keys and principals

- Each key has an id `key_<uuidv7>` and is the principal `key:key_…`.
- A `tut_sk_` key belongs to an app or service account. A `tut_ak_` key belongs to an agent.
- A key never holds more than its owner (narrow-only).
- The prefix is unique in a deployment. If a new prefix collides, Tutela draws a new one.

### 5.4 What is stored

| Stored | Type |
|---|---|
| key id | `key_<uuidv7>` |
| tenant key | (iss, tid) |
| kind | `sk` or `ak` |
| prefix | the 8 characters |
| owner | a principal string |
| hash | 64 lowercase hex characters: **SHA-256(pepper ‖ key)**. `key` is the full 59-byte key string. `pepper` is the raw bytes of the pepper with `pepper_version`. |
| pepper_version | integer ≥ 1 |
| created_at, last_used_at; expires_at and revoked_at when set | times |

**Never stored:** the full key, the secret part, or anything that can be turned back into them.

The pepper comes from `TUTELA_KEY_PEPPER` (at least 32 random bytes) and `TUTELA_KEY_PEPPER_VERSION`. It is separate from `TUTELA_MASTER_KEY` and **never derived** from it.

### 5.5 Display and logging

- The full key is shown **once**, when it is created (Console, `tutela apps create`, `tutela keys rotate`).
- After that, only the display prefix is ever shown or logged: `tut_sk_7f3k9q2m`. Logs, audit records, events, error messages, metrics and traces never contain the secret part.
- A bad key gets the answer "invalid API key" and nothing more.

### 5.6 Verification (Phase A, B)

1. Parse (5.2). Failure: 401.
2. Find the row by (kind, prefix). If there is no row, still compute a hash, so the timing is the same. Then 401.
3. Compute SHA-256(pepper ‖ key) with the pepper of the row's `pepper_version`. Compare in constant time.
4. Check `revoked_at`, `expires_at`, and that the owner is enabled.
5. The result is the principal `key:key_…` in the key's tenant.

Rotation is in section 10.4.

---

## 6. The Decision object and the embedded API

**First commit:** the Decision object (6.1 to 6.3) is in `tutela-contracts`. The `Pdp` API (6.5 to 6.8) is in `tutela-pdp` (Phase A; [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).

### 6.1 The Decision object

| Field | JSON type | Rule |
|---|---|---|
| `effect` | `"allow"` or `"deny"` | The answer for the requested action. Any other value is an error, which means deny. |
| `level` | level string (section 3) | The principal's effective level on the item, after the delegation overlap. It can be above `none` when `effect` is `deny` (for example `read` when the action needs `write`). |
| `field_mask` | object | `{"read": [...], "write": [...]}`. Field names and feature names (`@ai`) of the item's type. **Allow-lists: a field not in `read` is masked.** `write` is a subset of `read`. A field marked `grants_access` is in `write` only when `manage_access` also holds for the person and every actor, as `write_check` asks (6.7); so never for an agent or a delegated request. Sorted, no duplicates. If the request named `fields`, only those appear; otherwise every registered field and feature of the type. Both lists are empty when `level` is `none`. |
| `rule_ids` | array of strings | The stored rules that decided: role assignments, field rules, conditions, boundary rules. Opaque strings, 1–128 visible ASCII characters each. For explain and audit only; never parse them. Empty for a default deny. |
| `reason` | string | `<code>` or `<code>: <detail>`. The code is from 6.2. The detail is short English (at most 512 characters in total) for logs and the Console's explain view. The detail is not empty and has no control characters (no line breaks). The detail uses ids, never names, e-mails or field values. |
| `rev` | integer | The tenant revision of the bundle that was used. |
| `obligations` | array of objects | Things the caller must do (6.3). Often empty. |

What a caller must do with a Decision:
- `effect` is `deny`: do not do the action.
- Before data leaves the server, remove every field and feature not in `field_mask.read`: API responses, search and vector indexes, exports, notifications, audit, and AI prompts (removed **before** the prompt is built). ([PERMISSION-MODEL.md §13](PERMISSION-MODEL.md#13-field-masks-everywhere-data-leaves).)
- Never change a field that is not in `field_mask.write`.
- Carry out every obligation. An obligation kind you do not know means **deny**.

Example (Jae reads an invoice; `amount` is confidential and hidden from him):

```json
{
  "effect": "allow",
  "level": "write",
  "field_mask": {
    "read":  ["@ai", "assignee", "number", "status"],
    "write": ["status"]
  },
  "rule_ids": ["ra_0193a1b2-c3d4-7a00-8000-0000000000a1", "fr_0193a1b2-c3d4-7a00-8000-0000000000f1"],
  "reason": "allowed: role assignment at project p-77; amount hidden by a field rule at the org root",
  "rev": 42,
  "obligations": [
    { "kind": "label", "value": "internal" }
  ]
}
```

### 6.2 Reason codes

The code is the text before the first `:` in `reason` (or the whole string if there is no `:`). Codes use the name grammar (2.1).

| Code | Meaning | Safe to show to the end user |
|---|---|---|
| `allowed` | A role on the path allows it. | yes |
| `no_role` | No role on the path. Default deny. | no |
| `level_too_low` | A role was found, but its level is below what the action needs. | yes |
| `missing_grant` | The custom action needs an explicit grant that the role does not have. | yes |
| `admin_only` | An owner-only admin action that the principal does not hold. | yes |
| `condition_failed` | A condition on the role was false, so the level dropped. | yes |
| `private_scope` | A private scope stopped inheritance. | no |
| `delegation_overlap` | The person or the agent lacks the level; the overlap is too low. | yes |
| `outside_ai_reach` | The agent works outside its `ai_reach`. | no |
| `principal_disabled` | The subject or an actor is disabled. | no |
| `tenant_mismatch` | The resource or a principal belongs to another tenant. | no |
| `break_glass` | An org Owner opened hidden data through the break-glass path. | no |
| `not_allowed` | A generic deny. Used where the real reason must stay hidden. | yes |
| `boundary_rule` | A boundary rule of a scope stopped a move or a link. | yes |
| `approval_required` | A move into a looser scope waits for the source owner. | yes |

Rules:
- `effect` decides. The reason only explains. A reader that sees an unknown code treats it like `not_allowed`.
- The permission map (7.5) sends only codes marked "yes". Other codes are sent as `not_allowed`.
- New codes may be added inside v1 (section 10).

**Which code `tutela-pdp` sends** ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)). A request can have several deciding roles (a direct one, or every group role at one scope), roles that are gone, and a person with actors. The first row that fits wins:

| Case | Code |
|---|---|
| The resource's org is not one of the tenant's orgs | `tenant_mismatch` |
| No assignment on the path | `no_role` |
| A private scope stopped the walk before any assignment | `private_scope` |
| An agent whose closest assignment is at the org root (`ai_reach` is never the whole org) | `outside_ai_reach` |
| An admin key or an owner-only custom action, through delegation or for an agent | `admin_only` |
| Every deciding role is gone, or may not be given to that subject | `no_role` (the detail names the assignments) |
| An admin key that no deciding role holds | `admin_only` |
| A custom action whose grant no deciding role holds | `missing_grant` |
| A condition took a role below the level the action needs (for a custom action: a role that holds the grant) | `condition_failed` |
| Otherwise: the level is too low (for a custom action, judged on the roles that hold the grant; when another role has the level but not the grant, the detail says grants are never pooled) | `level_too_low` |
| The person is allowed and an actor is not | `delegation_overlap`, or the actor's own `outside_ai_reach` or `admin_only` |

### 6.3 Obligations

Each obligation is an object with a `kind`. The first kinds are below. Final names are fixed in Phase A ([PERMISSION-MODEL.md §19](PERMISSION-MODEL.md#19-open-points), point 7).

| `kind` | Other fields | The caller must |
|---|---|---|
| `audit` | `on_behalf_of` (a `user` principal string, optional; other kinds are rejected), `reason_required` (boolean, default `false`) | Write an audit.v1 record for this access before data is returned. If `on_behalf_of` is set, the record names that person. If `reason_required` is true, ask the actor for a short reason and put it in the record (`reason` = `break_glass: <text>`). |
| `label` | `value` (a label name, for example `confidential`) | Mark everything built from this item (answers, files, exports, AI output) with at least this label. Output carries the highest label of its inputs. Label names: `public`, `internal`, `confidential`, `secret` ([PERMISSION-MODEL.md](PERMISSION-MODEL.md)). |
| `restricted` | `fields` (array of field names) | Show these masked fields as "Restricted" instead of removing them. Exports still remove them. |
| `recheck_online` | — | Before acting, ask `tutelad` again (remote API). Used for revocation-sensitive actions in service mode (Phase B). If `tutelad` cannot answer, deny. |

A caller that does not know an obligation kind must treat the decision as **deny**. So a new kind can be sent only to SDKs that already know it (section 10.2).

What the Phase A evaluator sends, on an allow only: `label`, with the highest sensitivity among the readable data fields; and, for a delegated request, `audit` with `on_behalf_of` = the person. It does not send `restricted` or `recheck_online` yet, so masked fields are removed, which is the safe default.

### 6.4 Delegation in decisions

When the request carries actors (from the token's `act` chain):
- Tutela evaluates the person and each actor. Each agent is also limited by its `ai_reach` ([PERMISSION-MODEL.md §11](PERMISSION-MODEL.md)).
- `level` = the `min` of all of them.
- `field_mask.read` and `field_mask.write` = the intersection of all of them.
- `effect` = allow only if the action is allowed for **every** one of them. A custom action counts only if it is in every actor's allowed-action set ([PERMISSION-MODEL.md §6.3, §7.1 step 7](PERMISSION-MODEL.md#63-role-assignments)); raw grants are never pooled or intersected. Admin keys and owner-only custom actions are never allowed through delegation.
- `rule_ids` lists the deciding rules of all of them.
- attache's capability limits (`cap`) apply on top, inside attache. Tutela never reads `cap`.

### 6.5 Embedded API (`tutela-pdp`) — Phase A

Rust signatures of `tutela-pdp` ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)). The Rust API can still change while the crates are `0.x`; the JSON shapes in this section are the contract.

```rust
// Phase A. Crate: tutela-pdp.
impl Pdp {
    /// Loads (or replaces) a tenant's bundle: its compiled model and its data
    /// at one revision. A revision lower than one loaded before is refused;
    /// the same revision again replaces the bundle (a retry).
    pub fn load(&mut self, tenant: TenantKey, rev: u64, model: Arc<Model>, data: TenantData)
        -> Result<(), LoadError>;

    /// One decision for one action on one resource.
    pub fn check(&self, req: &CheckRequest) -> Result<Decision, PdpError>;

    /// Many decisions. Results come in the same order as `reqs`.
    /// If any request is invalid, the whole batch fails (fail closed).
    pub fn batch(&self, reqs: &[CheckRequest]) -> Result<Vec<Decision>, PdpError>;

    /// A filter to list rows of one type inside SQL (6.6). `paths` places
    /// the scopes the filter needs.
    pub fn list_filter<P: ScopePaths + ?Sized>(&self, req: &ListFilterRequest, paths: &P)
        -> Result<ListFilter, PdpError>;

    /// Per-field verdicts for a write (6.7).
    pub fn write_check(&self, req: &WriteCheckRequest) -> Result<WriteDecision, PdpError>;

    /// One page of the known resources a principal may act on, with the
    /// filter for the rest (7.4). Phase B.
    pub fn search_resources<P: ScopePaths + ?Sized>(&self, req: &ListFilterRequest, paths: &P,
        after: Option<&PathEntry>, limit: usize) -> Result<ResourcePage, PdpError>;

    /// One page of the principals `check` allows on a resource (7.4). Phase B.
    pub fn search_subjects(&self, req: &SubjectSearchRequest, after: Option<&Principal>,
        limit: usize) -> Result<SubjectPage, PdpError>;
}

pub struct CheckRequest {
    pub tenant: TenantKey,               // from the verified token: (iss, tid)
    pub subject: Principal,              // the token's `sub`
    pub actors: Vec<Principal>,          // the token's `act` chain, current actor first; empty = no delegation
    pub action: ActionKey,               // for example "invoice:approve"; its type is the resource's
    pub resource: ResourceRef,
    pub fields: Option<Vec<FieldName>>,  // limit the field mask to these fields and features
    pub at_least_revision: Option<u64>,  // sent by callers after their own writes
}

pub struct ResourceRef {
    pub type_name: ResourceType,         // "invoice"
    pub id: ResourceId,                  // the product's own id
    pub path: Vec<PathEntry>,            // ancestors, nearest first; the last entry is the org
    pub attrs: Attrs,                    // field values that conditions read
}

pub struct PathEntry {
    pub type_name: ResourceType,
    pub id: ResourceId,
}
```

`TenantData` is what the evaluator reads about a tenant besides the model: its orgs, role assignments, groups, private scopes and field rules at single scopes. It is `tutela-store` data: `tutela_store::load` reads it, with the revision and the scope paths, in one consistent view ([ADR-0014](DECISIONS.md#adr-0014-tutela-store-in-phase-a-the-schema-row-level-security-and-checked-writes)). A product may also build it itself, for example in tests. Its rules are in [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits).

Rules for `ResourceRef`:
- In JSON, `type_name` is spelled `type` (as in 6.6 and section 7).
- `id`: the product's own id, 1–256 visible ASCII characters (`%x21-7E`). Numbers are sent as strings.
- `path`: every ancestor of the resource, **nearest first** (direct parent first), not the resource itself. The last entry is `{type_name: "org", id: "org_<uuidv7>"}`, and no other entry is an `org`. At most 32 entries (Phase A limit, confirmed by the week-1 spike, [ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator)). A longer path is an error. An `org` itself has an empty path.
- A resource whose path ends at an org that is not one of the tenant's orgs is denied with `tenant_mismatch`. There is no cross-tenant grant.
- `path` and `attrs` are loaded **server-side by id** from the product's database (SDK helpers do this). They never come from the request body.
- `path` holds no entry twice, and not the resource itself; otherwise the request is invalid.
- `attrs`: a JSON object from field name to a string, an integer, a boolean, `null`, or an array of strings. A value of a declared field must have that field's type (MANIFEST.md §4; a `principal` field holds a valid principal string); otherwise the request is invalid. It is never read as null. Integers are from −(2^53 − 1) to 2^53 − 1.
- `attrs` holds **every field of the type that has `grants_access`**, with `null` when the field has no value. Conditions read only those fields, and a field left out would be read as null: under `not` that makes a comparison true, while SQL compares the real column. A request without one is invalid. (Here a missing field and `null` are **not** the same, unlike the general JSON rule in §0.) In `write_check`, `new_attrs` holds only the changed fields.
- Size bounds: at most 1,000 requests in a `batch`, and at most 512 entries in `fields`, `attrs` and `new_attrs`. More is an invalid request.

### 6.6 `list_filter`

`list_filter` comes from the **same evaluator** as `check`. A differential property test proves on every commit: **the rows `list_filter` returns == the rows `check` allows**.

```rust
// Phase A.
pub struct ListFilterRequest {
    pub tenant: TenantKey,
    pub subject: Principal,
    pub actors: Vec<Principal>,
    pub action: ActionKey,               // usually "<type>:read"; the type to list comes from here
    pub at_least_revision: Option<u64>,
}

pub struct ListFilter {
    pub tenant: TenantKey,               // the rows' tenant: the SQL adapter's tenant predicate
    pub type_name: ResourceType,
    pub rev: u64,
    pub ids_in: Vec<ResourceId>,         // rows allowed by an assignment on the row itself
    pub container_in: Vec<PathEntry>,    // scopes; rows anywhere below them match
    pub condition: Option<FilterExpr>,   // the AST below; None means true
}

/// Where list_filter gets the paths of the scopes it must place.
pub trait ScopePaths {
    /// The ancestors of one scope of one tenant, nearest first; the last is the org.
    fn ancestors(&self, tenant: &TenantKey, scope: &PathEntry)
        -> Result<Vec<PathEntry>, ScopePathError>;  // NotFound or Unavailable
    /// Every known scope below one of `scopes`, or None (the default) when the
    /// provider cannot say. The answer must be complete.
    fn below(&self, tenant: &TenantKey, scopes: &[PathEntry])
        -> Option<Result<Vec<PathEntry>, ScopePathError>> { None }
}
```

**Scope paths** ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator) F1, [ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)). Tutela does not store the product's tree, but the filter must know how the deciding scopes nest: the scopes where the principal has an assignment, and the private scopes inside them. So `list_filter` takes a scope-path provider:
- It is keyed by **(tenant, type, id)** and returns the ancestors, nearest first, or an error. With ids that are the same across tenants, it must answer with the asking tenant's scope.
- `list_filter` asks it for every scope where the principal (or the person and each actor) has an assignment, and for every private scope of the tenant, each at most once per call. A provider that implements `below` is asked once for the scopes below the principal's assigned scopes; then only the private scopes among them are placed. Its answer must be **complete** (a scope left out could widen a list, as a wrong path could). `tutela-store`'s `ScopePathSnapshot` implements it.
- These are errors (`PdpError::ScopePath`): an unknown scope; a provider that cannot answer; a path that does not end at the tenant's own org; a path with an `org` before its end; a path longer than 32; a path that holds the scope itself or one entry twice (`Malformed`); placed paths that disagree, where one entry gets two different parents, also an entry that was never placed itself, and also a cycle (`Inconsistent`). The caller fails closed: no rows. A missing path is never treated as "no ancestors".
- The paths must be current. A stale path makes `list_filter` and `check` disagree, so a cache of paths needs a test that a move changes list results at once.
- Without `below`, every private scope of the tenant is placed, so **one private scope the provider does not know fails every list** of a principal with any assignment. That fails closed, but it is an outage. So a deleted scope must leave `TenantData` (assignments, private flag, field rules) in the same revision as the delete ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).

JSON form:

```json
{
  "tenant": { "iss": "https://auth.example.test", "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b" },
  "type": "invoice",
  "rev": 42,
  "ids_in": ["inv-881"],
  "container_in": [
    { "type": "department", "id": "d-procurement" },
    { "type": "project", "id": "p-77" }
  ],
  "condition": {
    "op": "not",
    "arg": { "op": "under", "scopes": [ { "type": "project", "id": "p-board" } ] }
  }
}
```

**Meaning.** A row of the listed type and of `tenant` passes if and only if it has **at most 32 ancestors** and:

```
( row.id is in ids_in  OR  row is under a scope in container_in )  AND  condition(row)
```

A row with more than 32 ancestors never passes: `check` refuses its path (`PathTooLong`), so the SQL adapter adds this bound (for example `cardinality(ancestors) <= 32`).

The rows must also be well formed, because `check` refuses what is not, and the list must never show a row that `check` refuses. A row that breaks one of these rules never passes. The SDK's migration helper makes the database keep these rules (CHECK constraints), or the adapter adds them as predicates:
- the ancestors column ends at an org of the row's own tenant and holds no other org (the `path` rules of §6.5);
- the ancestors column never holds one entry twice, and never the row itself;
- each field column has its declared type, and the column of a `principal` field holds only valid principal strings or `NULL` (SQL would compare the text, while `check` refuses a value that is not a principal).

- "Row is under scope S" means S is one of the row's ancestors, at any depth. A row is not under itself.
- `condition` missing means true.
- Empty `ids_in` and empty `container_in` means **no rows**.

**Condition AST.** Every node is a JSON object with an `op`.

| `op` | Other fields | True when |
|---|---|---|
| `true`, `false` | — | always, never |
| `and` | `args`: 2 or more nodes | all are true |
| `or` | `args`: 2 or more nodes | any is true |
| `not` | `arg`: one node | the node is false |
| `eq` | `attr`, `value` | the row's field equals the value |
| `ne` | `attr`, `value` | the field is not null and not equal to the value |
| `in` | `attr`, `values` (1 or more) | the field equals one of the values |
| `contains` | `attr`, `value` | the field is an array of strings that holds the value (for example `labels` contains `client-visible`) |
| `is_null` | `attr` | the field is null |
| `id_in` | `ids` (1 or more resource ids) | the row's id is in the list |
| `under` | `scopes` (1 or more `{type, id}`) | one of the scopes is an ancestor of the row |

Rules:
- `attr` is a field name (2.1) registered for the type. A value is a JSON string, integer or boolean. An integer is from −(2^53 − 1) to 2^53 − 1 (the manifest refuses others), so every SDK reads it exactly. Types must match: `"5"` is not `5`. A comparison with a null field is false (use `is_null`).
- Values that depend on the principal are already filled in. For example the condition "assignee is the principal" arrives as `{"op": "eq", "attr": "assignee", "value": "user:usr_…"}`.
- An SDK that meets an unknown `op` refuses the filter (deny, no rows). New ops come only with SDK support.
- Limits (Phase A, [ADR-0016](DECISIONS.md#adr-0016-the-list-query-grouped-terms-hashed-scope-tests-and-lower-filter-limits)): at most 512 condition nodes, depth 32, 2,000 entries in `ids_in`, 2,000 in `container_in`, and 4,000 entries in total (`ids_in`, `container_in`, and every `under.scopes`, `id_in.ids` and `in.values` inside the condition: each one is a bound array element). They are set by measurement: at them the list query has p99 under 100 ms on the reference machine (`cargo bench -p tutela-sdk --bench list_query`), and they sit above the largest filter measured at the library-gate size (472 nodes, 2,661 entries). A filter that would pass a limit is an error, and the caller fails closed (no rows).
- `tutela-pdp` returns `PdpError::FilterTooLarge` for such a filter. A valid manifest can still give one: each nesting level of a principal's deciding scopes repeats the conditions of its roles ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).

**How `tutela-pdp` builds the filter** ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator), "filter shape"). The deciding scopes on one row's path form a chain. So a row's deepest deciding scope is at nesting level `k` exactly when the row is at or under a level-`k` scope and not at or under any level-`k+1` scope. The condition has one term per level: "at or under the scopes of this level where some deciding role allows the action (with that role's conditions, if any) AND NOT at or under any scope of the next level". For a delegated request, the filters of the person and of each actor are joined with `and`.

**How the SDK turns it into SQL** (Phase A; details in [PERMISSION-MODEL.md §12](PERMISSION-MODEL.md#12-list-filtering-in-sql)):
- Every value is a **bound parameter** (`$1`, `$2`, …). Text is never spliced into SQL. `ids_in` is bound as one array parameter (`id = ANY($1)`).
- Column names come only from the product's manifest mapping, never from the request.
- The product keeps an ancestors column: an array of ancestor ids, nearest first, with a GIN index ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator)). Each ancestor must be identified uniquely: by ids that are unique across types in the tenant, or by `type:id` text.
- The filter is part of the `WHERE` clause. Counts and page sizes use the same clause. Never load rows and then drop some.
- The SQL adapter runs every list and count query with a statement timeout. A timeout is an error, and the caller fails closed: no rows and no count, never a partial list ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator), F2).
- The adapter binds `tenant` as the tenant predicate (the tenant columns), and adds the 32-ancestor bound above.

**Field masks of listed rows.** `list_filter` decides which rows a list holds; it returns no field mask, because the mask can differ per row (field rules at single scopes, roles with conditions). Before rows leave the server, the product masks each row with **that row's own** decision: a `batch` of `<type>:read` checks for the rows of the page (at most 1,000 per batch). It may select fewer columns up front, but never shows a column a row's mask does not hold ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).

### 6.7 `write_check`

```rust
// Phase A.
pub struct WriteCheckRequest {
    pub tenant: TenantKey,
    pub subject: Principal,
    pub actors: Vec<Principal>,
    pub resource: ResourceRef,           // the stored item, before the write
    pub new_attrs: Attrs,                // the changed fields only, with their new values
    pub new_path: Option<Vec<PathEntry>>,// Some(...) when the write moves the item to a new parent
    pub new_links: Vec<ResourceRef>,     // the resources this write links to, at most 64
    pub approved_by: Vec<Principal>,     // who agreed to a looser move, at most 8
    pub at_least_revision: Option<u64>,
}

pub struct WriteDecision {
    pub effect: Effect,                  // allow only if every field, the move and every link are
    pub rev: u64,
    pub fields: Vec<FieldVerdict>,       // one per changed field, sorted by field name
    pub moved: Option<MoveDecision>,     // `move` in JSON
    pub links: Vec<LinkVerdict>,         // one per new link, in order
}

pub struct MoveDecision {
    pub effect: Effect,
    pub outcome: MoveOutcome,            // allowed, needs_approval or refused
    pub reason: Reason,
    pub rule_ids: Vec<RuleId>,
    pub left: Vec<PathEntry>,            // the scopes the item leaves, nearest first
    pub entered: Vec<PathEntry>,         // the scopes it enters, nearest first
    pub looser: bool,                    // someone gains, or the comparison did not finish
    pub complete: bool,                  // false: it hit a bound, and counts as looser
    pub approve_at: Vec<PathEntry>,      // the scopes that still wait for an owner
    pub gains: Vec<ImpactLine>,          // who gains what, at most 100 lines
}

pub struct LinkVerdict {
    pub target: PathEntry,
    pub effect: Effect,
    pub reason: Reason,
    pub rule_ids: Vec<RuleId>,
}

pub struct FieldVerdict {
    pub field: FieldName,
    pub effect: Effect,
    pub needs: ActionKey,                // "<type>:write", or "<type>:manage_access" for grants_access fields
    pub reason: Reason,                  // same format as Decision.reason
    pub rule_ids: Vec<RuleId>,
}
```

Rules:
- Each changed field needs Write on that field, for the person and every actor.
- A field marked `grants_access` in the manifest also needs `manage_access`. It is an admin key, so an agent or a delegated token never changes such a field.
- A name that is not a declared data field of the type (a feature, an unknown field) is denied.
- If any field is denied, the whole write is refused (403), and the denied fields are named.
- A write changes a field, moves the item or adds a link; a write that does none of these is an error.
- A move (`new_path` is set) is checked against the boundary rules of the scopes it crosses, then access is compared before and after ([PERMISSION-MODEL.md §10.1](PERMISSION-MODEL.md#101-the-rules-of-a-move-exactly), [ADR-0025](DECISIONS.md#adr-0025-moves-and-links-in-write_check)). `new_path` follows the `path` rules of 6.5; a new parent whose type may not hold this type is an error. A move into a looser scope is `needs_approval` until an owner of each scope in `approve_at` agrees. The product runs that flow and asks again with `approved_by`; each name is judged at this revision, and one who holds no `approve_move` there counts for nothing.
- A link (`new_links`) needs `write` on the source, `read` on the target for the person and every actor, and the target's `links_from` ([PERMISSION-MODEL.md §9](PERMISSION-MODEL.md#9-links-never-grant-access)). A deny for a target the person cannot read is `not_allowed`, with no detail and no rule ids. A link never changes a decision: Tutela does not store links.
- `write_check` allows a change. The product makes it, in its own transaction, and calls `tutela_store::move_scope` for a registered scope.

### 6.8 Errors

```rust
// Phase A.
pub enum PdpError {
    StaleBundle { have_rev: u64, need_rev: u64 }, // below at_least_revision or the token's rev
    ExpiredBundle,                               // older than the max age for this action class (Phase B)
    NoBundle,                                    // no model loaded for this tenant
    UnsupportedBundle,                           // bundle needs a newer PDP, min_pdp_version (Phase B)
    UnknownType(ResourceType),
    UnknownAction(ActionKey),
    PathTooLong,
    InvalidInput { index: Option<usize>, detail: String },
    ScopePath { scope: PathEntry, problem: ScopePathProblem }, // list_filter cannot place a scope (6.6):
                                                 // NotFound, Unavailable, TooLong, WrongTenant,
                                                 // Malformed or Inconsistent
    FilterTooLarge(&'static str),                // the list filter would pass a limit (6.6)
}
```

- An error is **never** an allow. The caller fails closed.
- In the remote API, `StaleBundle`, `ExpiredBundle`, `NoBundle`, `UnsupportedBundle` and `ScopePath` become HTTP 503. The others become 400, and `FilterTooLarge` is 400 `filter_too_large`: the request is well formed, but this principal's filter is above a limit, and a retry does not help.
- `ExpiredBundle` and `UnsupportedBundle` need signed bundles (Phase B); the Phase A evaluator never returns them.
- A field the model does not know is not an error: it is masked, as if secret.

**Bundles** (Phase B, part 3, [ADR-0024](DECISIONS.md#adr-0024-signed-bundles-wait-for-part-3); not built). The PDP loads a signed bundle per (tenant, rev). Each bundle carries the tenant key, `rev`, `issued_at`, `expires_at`, a schema version and a `min_pdp_version`. The PDP refuses a `rev` lower than the highest it has seen, an expired bundle, and a bundle with a bad signature. The max bundle age is set per action class; writes and admin actions fail closed sooner. The bundle body format is fixed in Phase B.

---

## 7. Remote check API

**Status: Phase B.** Built: all of this section. `tutelad` serves it. The shapes follow the OpenID AuthZEN Authorization API 1.0, checked against the published text. Where AuthZEN leaves room (`properties`, `context`), Tutela fixes the fields below. The design is in [ADR-0021](DECISIONS.md#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease).

### 7.1 Common rules

- HTTPS only. Request and response bodies are JSON (`application/json`).
- Auth: `Authorization: Bearer <token>`, with `aud = tutela-authz` (name planned). Usually a service-account token of the product backend.
- The tenant comes from the caller's verified token (iss, tid). A request never names a tenant.
- A resource whose path ends at an org of another tenant gets a deny with `tenant_mismatch`, the same answer as an org that does not exist.
- Tutela keeps no list of principals per tenant, and an answer must not tell whether a principal exists elsewhere. So a subject of another tenant is a subject with no role here: a deny with `no_role`, the same answer as a subject that exists nowhere. The answer is never an error.
- **Who may ask** ([ADR-0021](DECISIONS.md#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease)). A token of a service (`sa` or `key`) asks about any subject of its tenant. A token of a person or an agent asks about itself only, with no actors. A delegated token asks about its own `sub` and its full `act` chain, so the chain cannot be dropped to get the person's own answer. A token of an external issuer (4.6) has no principal until token exchange exists, so it cannot ask. Anything else is 403 `forbidden`. In a batch, one such question fails the whole call.
- `path` and `attrs` come from the calling service, which loaded them server-side by id (6.5). A person who asks about itself sends its own path, so that answer is a UI hint, never enforcement.
- No decision is older than `context.at_least_revision`, or than the token's `rev` (4.2). If the database is behind that revision: 503 `stale`.
- `traceparent` (W3C) is read and passed on. Tokens and personal data never go into URLs.
- Errors use `application/problem+json` (RFC 9457) with `type` (`urn:tutela:problem:<code>`), `title`, `status` and, when there is more to say, `detail`. The detail never holds secrets or personal data, and it never quotes the request body.

| Status | When |
|---|---|
| 200 | A decision (allow **or** deny). |
| 304 | Permission map not changed (7.5). |
| 400 | Invalid request (`invalid_request`), too many items (`too_many_items`), unknown type or action (`unknown_key`), a bad page token (`invalid_page`), a list filter above a limit (`filter_too_large`). |
| 401 | Bad or missing token (`invalid_token`). |
| 403 | The caller may not ask this question (`forbidden`), or a tenant that is not in the directory (`unknown_tenant`). |
| 429 | Rate limited. (Not built: Phase D.) |
| 503 | No data (`no_data`), data past its age limit or its expiry (`expired`), a revision the database has not reached (`stale`), or a database failure (`unavailable`). Has `Retry-After`. **Never a hidden allow: callers fail closed.** |

Discovery: `GET /.well-known/authzen-configuration` (AuthZEN metadata). It needs a token, like the rest of the API port. It names the endpoints that are built; an endpoint it leaves out is not supported, so `search_action_endpoint` is never there. `policy_decision_point` is the address the caller used.

How AuthZEN fields map to Tutela:

| AuthZEN | Tutela |
|---|---|
| `subject.type` | The principal kind: `user`, `sa`, `key`, `agent` or `workload`. |
| `subject.id` | The full principal string. Its kind must equal `subject.type`. |
| `subject.properties.act` | Optional. The actor chain, same shape as the token's `act` claim: `{"sub": "agent:agt_…"}`, maybe nested. The SDK copies it from the verified token. |
| `action.name` | An action key (2.3). |
| `resource.type` | A type name (2.1). |
| `resource.id` | The product's resource id (6.5). |
| `resource.properties.path` | The ancestors, nearest first, last is the org: `[{"type": "...", "id": "..."}]`. Loaded server-side by the product. |
| `resource.properties.attrs` | Field values for conditions. Loaded server-side. |
| `context.fields` | Optional. Limit the field mask to these field and feature names. |
| `context.at_least_revision` | Optional integer. |
| response `decision` | `true` exactly when the Decision's `effect` is `allow`. |
| response `context.tutela` | The full Decision object (6.1). |

### 7.2 `POST /access/v1/evaluation`

Request:

```json
{
  "subject": {
    "type": "user",
    "id": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081",
    "properties": { "act": { "sub": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102" } }
  },
  "action": { "name": "invoice:approve" },
  "resource": {
    "type": "invoice",
    "id": "inv-881",
    "properties": {
      "path": [
        { "type": "project", "id": "p-77" },
        { "type": "department", "id": "d-procurement" },
        { "type": "org", "id": "org_0193a1b2-c3d4-7f00-9a00-000000000002" }
      ],
      "attrs": { "status": "submitted", "assignee": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081" }
    }
  },
  "context": { "fields": ["amount", "status"], "at_least_revision": 42 }
}
```

Response:

```json
{
  "decision": false,
  "context": {
    "tutela": {
      "effect": "deny",
      "level": "read",
      "field_mask": { "read": ["status"], "write": [] },
      "rule_ids": ["ra_0193a1b2-c3d4-7a00-8000-0000000000a1", "ra_0193a1b2-c3d4-7a00-8000-0000000000a2"],
      "reason": "delegation_overlap: agent has read at project p-77",
      "rev": 42,
      "obligations": []
    }
  }
}
```

### 7.3 `POST /access/v1/evaluations`

Many evaluations in one call. **At most 200 items**; more gives 400 (`urn:tutela:problem:too_many_items`).

- Top-level `subject`, `action`, `resource` and `context` are defaults. Each item in `evaluations` may override any of them.
- An item that sets a key replaces that default as a whole.
- With `evaluations` missing or empty, the request is one evaluation, and the answer has the 7.2 shape.
- `options.evaluations_semantic`: `execute_all` (default), `deny_on_first_deny` or `permit_on_first_permit`. The last two stop at that result, and the response ends there. In `deny_on_first_deny`, an item with an error counts as a deny.
- The response `evaluations` array has one result per item that ran, **in the same order**. Each result has the 7.2 response shape.
- One data view answers the whole batch, so its results share one `rev`. It is at least the highest `at_least_revision` of the items, and fit for the strictest action among them.
- An item that cannot be evaluated (a bad field, an unknown action) gets `{"decision": false, "context": {"error": {"status": 400, "message": "…"}}}`. It never gets an allow, and the other items still run. Only a problem with the whole call fails the whole call: 401, 403, too many items, and every 503.

```json
{
  "subject": { "type": "user", "id": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081" },
  "action": { "name": "invoice:read" },
  "evaluations": [
    { "resource": { "type": "invoice", "id": "inv-881", "properties": { "path": ["…"] } } },
    { "resource": { "type": "invoice", "id": "inv-882", "properties": { "path": ["…"] } } }
  ],
  "options": { "evaluations_semantic": "execute_all" }
}
```

```json
{
  "evaluations": [
    { "decision": true,  "context": { "tutela": { "effect": "allow", "level": "write", "…": "…" } } },
    { "decision": false, "context": { "tutela": { "effect": "deny",  "level": "none",  "…": "…" } } }
  ]
}
```

### 7.4 Search

**`POST /access/v1/search/resource`**: "which resources of this type may this subject act on?"

Tutela never stores a product's records. So this endpoint can name only resources Tutela knows: the scopes registered with `tutela_store::put_scope`, of the asked type. A resource with an assignment on itself is always registered. For full row lists the product uses the filter in `context.tutela.filter` (the 6.6 shape) inside its own SQL.

A resource is named only when it passes **whatever its field values are**. Tutela does not hold field values, so when the answer depends on a condition over a field, the resource is not named, and the filter covers it. Every named resource is one `check` allows; when the filter reads no field, the two agree exactly. A property test on random worlds proves both ([ADR-0022](DECISIONS.md#adr-0022-the-searches-live-next-to-the-evaluator)).

`action` must be of `resource.type`; otherwise 400.

```json
{
  "subject": { "type": "user", "id": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081" },
  "action": { "name": "invoice:read" },
  "resource": { "type": "invoice" }
}
```

```json
{
  "results": [ { "type": "invoice", "id": "inv-881" } ],
  "page": { "next_token": "", "count": 1 },
  "context": {
    "tutela": {
      "rev": 42,
      "filter": {
        "type": "invoice",
        "rev": 42,
        "ids_in": ["inv-881"],
        "container_in": [ { "type": "project", "id": "p-77" } ]
      }
    }
  }
}
```

**`POST /access/v1/search/subject`**: "who may do this action on this resource?" The request names the `resource` (with its `path` and `attrs`, as in 7.2), the `action`, and `subject.type`; `subject.id` is ignored. The result lists principals of that kind, with groups expanded, each one as `{"type": "user", "id": "user:usr_…"}`. Every principal is decided by `check`, so a principal is listed exactly when `check` allows it. `context.tutela` holds `rev`. Only a service (`sa`, `key`) may ask: a person's token gets 403, because this is a question about other principals.

Both searches:
- Paging uses the AuthZEN 1.0 `page` object. Request: `page.token` (the `next_token` of the page before) and `page.limit`. Response: `page.next_token` and `page.count`. An empty `next_token` means there is nothing more. `total` is not sent: counting needs the whole list.
- `page.limit` is at most 1,000; a bigger one is lowered. Missing or `0` means 100.
- One page looks at no more than 10,000 candidates. A page cut by this can be short, or empty, and still have a `next_token`. So follow `next_token`, not the size of a page.
- The token is opaque. It says only where a sorted list goes on. A bad token is 400 `invalid_page`. Each page is decided again at the current revision, so a list that spans a change can differ between pages. Each page's `rev` says which one it used.
- `context.at_least_revision`, the age limits and the token's `rev` work as in 7.1. There is no partial list: a failure anywhere is an error.
- `search/action` of AuthZEN is not built, and the metadata does not name it.

### 7.5 `POST /v1/authz/permissions` (UI permission map)

The UI map for one subject and one resource. Used by the product **backend** (backend-for-frontend), with its own client credentials plus the user's subject. Browsers do not call `tutelad` directly by default. In library mode, the product backend builds the same map with `tutela-pdp`.

Request:

```json
{
  "subject": { "type": "user", "id": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081" },
  "resource": {
    "type": "invoice",
    "id": "inv-881",
    "path": [
      { "type": "project", "id": "p-77" },
      { "type": "org", "id": "org_0193a1b2-c3d4-7f00-9a00-000000000002" }
    ],
    "attrs": { "assignee": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081" }
  },
  "ui_keys": ["invoices.approve_button", "invoices.delete_button"],
  "actions": ["invoice:approve"],
  "fields": ["invoice.amount", "invoice.status"],
  "at_least_revision": 42
}
```

- `subject.properties.act` may be added, as in 7.1. The rules of 7.1 on who may ask apply.
- `resource.attrs` holds the field values conditions read, as in 7.2. It is needed when the type has a `grants_access` field.
- `ui_keys` missing: every UI key of the model. A name that is not in the model is 400 `unknown_key`.
- `actions` and `fields` are optional extra keys to answer. At most 2,000 names in each list; more is 400 `too_many_items`.
- An action of another type than the resource is 400. A field of another type is `none`.

Response (`ETag: "r42-9f86d081884c7d65"`):

```json
{
  "rev": 42,
  "ui": {
    "invoices.approve_button": { "mode": "show" },
    "invoices.delete_button":  { "mode": "disable", "reason": "level_too_low" }
  },
  "actions": { "invoice:approve": true },
  "fields": { "invoice.amount": "none", "invoice.status": "write" }
}
```

| `mode` | Meaning |
|---|---|
| `show` | Allowed. Show as normal. |
| `disable` | Show greyed out. `reason` holds a code that is safe to show (6.2); the UI shows the reason text from the manifest. |
| `hide` | Do not render. |
| `readonly` | Show the value, but not editable. |

How a UI key gets its mode ([ADR-0023](DECISIONS.md#adr-0023-the-permission-map-and-a-tag-that-covers-the-answer)):
- It is denied when one of its actions is denied, or one of its fields is `none`. A key about another type than the resource cannot be decided, so it is denied too. The mode is then `when_denied`, except that `readonly` becomes `hide` when a field is `none`: `readonly` shows the value, and the value cannot be read.
- It is `readonly` when nothing is denied and a field is at `read`. Otherwise it is `show`.
- `reason` is sent with `disable` only.

A field's level comes from the `<type>:read` decision's mask: `write`, `read` or `none`.

Caching: the client sends `If-None-Match` with the ETag and the same body. If nothing changed, the answer is `304 Not Modified` with no body. Weak tags (`W/`) and lists are read. `*` never gives a 304, because it holds no map. The answer has `Cache-Control: private, no-cache`.

The ETag is `"r<rev>-<16 hex digits>"`. It covers the tenant, the revision, the digest of the model, the subject, the actors, the request **and the answer itself**. The answer is worked out on every call and the check for who may ask runs first, so a 304 can never hide a change or stand in for another principal's map. The answer must be in it: an assignment can expire and change the map before the revision moves (ADR-0020). Over gRPC, `if_none_match` and `not_modified` do this job, with the same tag.

The map is a **UI hint only**. Every server route checks again.

### 7.6 gRPC `tutela.authz.v1`

The same operations over gRPC, all built: `Evaluate`, `Evaluations`, `SearchResource`, `SearchSubject`, `Permissions` and `WriteCheck` (7.8). Service `tutela.authz.v1.Authz`, on the API port, behind the same token check. The handlers call the same code as HTTP. Messages carry the same fields with the same names and meanings as the JSON above, with these differences: `properties` is flat (`subject.act`, `resource.path`, `resource.attrs`), with no items `Evaluations` answers with one item, and `SearchResource` carries the filter as JSON text in `filter_json`, because a condition is a tree of open shape. The errors of 7.1 become gRPC codes: 400 `INVALID_ARGUMENT`, 401 `UNAUTHENTICATED`, 403 `PERMISSION_DENIED`, 503 `UNAVAILABLE`. The message starts with the problem code. The `.proto` file is `crates/tutela-contracts/proto/tutela/authz/v1/authz.proto`, and it is published with each release (section 10).

---

### 7.7 `GET /v1/whoami`

**Status: Phase B, built.** Says who the service sees in the caller's token. It proves the path from a token to a tenant, and helps a caller debug its trust setup.

Auth as in 7.1. The response is:

```json
{
  "iss": "https://auth.example.test",
  "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
  "sub": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081",
  "kind": "access",
  "rev": 42
}
```

| Field | Rule |
|---|---|
| `iss`, `tid` | The tenant key (1.6), from the verified token. |
| `sub` | The subject. For an external issuer (4.6) this is the issuer's own subject. |
| `kind` | `access`, `delegated` or `external`. |
| `rev` | The tenant's current revision, read inside the tenant. |

A verified token for a tenant that is not in the directory gets 403 `unknown_tenant`. A database failure, or a role that does not isolate tenants, gets 503 `unavailable`. A caller never names a tenant: a header, a query or a body has no effect.

### 7.8 `POST /v1/authz/write-check`

**Status: Phase B, built.** `Pdp::write_check` over the network (6.7). The rules of 7.1 apply, on who may ask too. Only a service may send `approved_by`; anyone else gets 403 `forbidden`.

```json
{
  "subject": { "type": "user", "id": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081" },
  "resource": { "type": "invoice", "id": "inv-881", "properties": {
    "path": [ { "type": "project", "id": "p-77" }, { "type": "org", "id": "org_…" } ],
    "attrs": {}
  } },
  "new_attrs": { "status": "done" },
  "new_path": [ { "type": "project", "id": "p-78" }, { "type": "org", "id": "org_…" } ],
  "new_links": [ { "type": "invoice", "id": "inv-900", "properties": { "path": ["…"], "attrs": {} } } ],
  "approved_by": ["user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7082"],
  "context": { "at_least_revision": 42 }
}
```

`new_attrs`, `new_path`, `new_links` and `approved_by` are each optional, and at least one of the first three must be there. The answer is 200 for an allow and for a deny:

```json
{
  "decision": false,
  "context": { "tutela": {
    "effect": "deny",
    "rev": 42,
    "fields": [ { "field": "status", "effect": "allow", "needs": "invoice:write", "reason": "allowed", "rule_ids": ["ra_…"] } ],
    "move": {
      "effect": "deny",
      "outcome": "needs_approval",
      "reason": "approval_required: the move gives someone more access, and waits for the source owner",
      "rule_ids": ["ra_…"],
      "left": [ { "type": "project", "id": "p-77" } ],
      "entered": [ { "type": "project", "id": "p-78" } ],
      "looser": true,
      "complete": true,
      "approve_at": [ { "type": "project", "id": "p-77" } ],
      "gains": [ { "change": "gain", "kind": "user", "key": "invoice.amount", "from": "none", "to": "read", "conditional": false, "principals": ["user:usr_…"], "scopes": [ { "type": "invoice", "id": "inv-881" } ] } ]
    },
    "links": [ { "target": { "type": "invoice", "id": "inv-900" }, "effect": "allow", "reason": "allowed", "rule_ids": ["ra_…"] } ]
  } }
}
```

- `move` is there for a move, `links` for new links. A rule id of a boundary rule is `boundary:<type>/<id>`.
- `gains` names other principals, so only a service gets it. Anyone else gets `[]`. A line of kind `role` names a role, not a person: its holders below the moved item may gain. `conditional` means it depends on field values Tutela does not have.
- A write that changes a `grants_access` field, and every move, are answered from data that has just been checked ([ADR-0021](DECISIONS.md#adr-0021-the-check-api-one-code-path-a-snapshot-per-tenant-and-a-revision-lease) item 5): with no database, 503. Other writes use the age limit of a write.
- `tutelad_decisions_total` counts it as `operation="write_check"`.
- gRPC: `WriteCheck`. The answer holds `decision`, `rev` and `decision_json`, which is `context.tutela` as JSON text. A move's shape grows inside v1, so it stays one contract with the JSON.

### 7.10 Model versions

**Status: Phase B, built.** Every published model is a kept, numbered version of its tenant ([ADR-0026](DECISIONS.md#adr-0026-a-tenant-owns-its-model-versions)). A publish here changes one tenant. HTTP only: the gRPC form comes with `tutela.admin.v1` (part 3). `tutela apply` against `tutelad` (part 4) calls these routes.

**Who may ask.** The rules of 7.1 on tokens apply, and these need admin keys **at every org of the tenant**, read from data that has just been checked. A delegated token, an agent and an external token never pass: 403 `forbidden`. A service needs the keys like anyone else.

| To | Needs at every org |
|---|---|
| Look: `GET` | `org:read_audit` |
| Change: `POST /v1/models/publish` | `org:manage_access` and `org:manage_fields` |

| Route | Does |
|---|---|
| `GET /v1/models` | The active model and a page of versions, newest first. Query: `before`, `limit` (at most 100). The texts are left out. |
| `GET /v1/models/{version}` | One version, with its text. 404 for a version this tenant does not have. |
| `POST /v1/models/impact` | A dry run: what a publish of this text would do now. Nothing is written. Needs what looking needs. |
| `POST /v1/models/publish` | A new version. |

```json
{ "active": { "version": 3, "digest": "9f86…", "own": true },
  "versions": [ { "version": 3, "rev": 44, "digest": "9f86…", "class": "narrowing", "diff": "NARROWING …",
                  "author": "user:usr_…", "approvers": [], "origin": "tenant", "restores": 1,
                  "published_at": "2026-11-02T10:00:00.000Z" } ],
  "next_before": 3 }
```

- `active.version` is the tenant's newest version number; 0 until it has one. `own` is `true` when the tenant published that model itself, and `false` when it follows the app's manifest. `origin` is `tenant` or `app`.
- A version's `source` can be missing: only for one from before migration 4 that is not the current manifest.

Publish:

```json
{ "source": "version = 1\n…", "expected_version": 3, "approval": "tutela-approval-v1.…" }
```

- `source` is the new `tutela.resources.toml`. To go back, send `"restore": <version>` instead: **a rollback is a new version** with the old text, and passes every check a publish passes, because a rollback can widen too. History is never changed; the database refuses it for every role.
- `expected_version` is the `active.version` the caller compared against. Another publish in between is 409 `version_conflict`.
- A widening change needs `approval`, a token of [MANIFEST.md §12](MANIFEST.md#12-applying-tutela-apply-and-approval-tokens) with `tid` set to this tenant, from `active.digest` to the SHA-256 of the new text. Without a valid one: 403 `approval_required`. A token with no `tid`, or for another tenant, approves nothing here.
- The first publish of a tenant with no version writes two: the manifest it ran on as version 1, then the new one.

```json
{ "version": 4, "rev": 45, "digest": "60303…", "class": "widening", "restores": 1, "impact": { "…": "…" } }
```

**The impact report** ([ADR-0027](DECISIONS.md#adr-0027-the-impact-report)). `POST /v1/models/impact` takes the same body as a publish (`source` or `restore`) and answers what a publish would do, with what an approval token must name:

```json
{ "version": 3, "from": "9f86…", "to": "60303…", "class": "widening", "diff": "WIDENING …",
  "impact": {
    "complete": true,
    "no_impact": false,
    "summary": ["12 users gain read on contract.budget in 3 scopes", "1 agent gains read on contract.budget in 1 scope"],
    "lines": [ { "change": "gain", "kind": "user", "key": "contract.budget", "from": "none", "to": "read",
                 "conditional": false, "count": 12, "scopes": 3, "examples": ["user:usr_…"] } ],
    "omitted_lines": 0,
    "digest": "c3ab…"
  } }
```

- It runs on the tenant's real bindings, on two evaluators built for it: one with the active model, one with the candidate. No snapshot changes. It counts principals and scopes, never rows: Tutela holds no rows.
- `key` is a type (the item level), a field or feature, or an action (`allowed` or `denied`). A gain names the new level, a loss the old one.
- `conditional: true`: it depends on field values Tutela does not have, so it can happen and may not happen to every row. A scope whose type holds nothing by the model can still hold old rows; its lines are conditional too.
- **The bound.** A report takes at most `TUTELA_IMPACT_MAX_WORK` steps (default 2,000,000). One that stops there has `complete: false`, and its lines are a lower bound. `no_impact` is `true` only for a complete report with no line, so stopping early never reads as "no impact".
- A response holds at most 1,000 lines and 20 `examples` per line. `digest` is SHA-256 of the whole report, every principal of every line included.
- A publish stores the report with its version, and `GET /v1/models/{version}` gives it back.

| Status | When |
|---|---|
| 400 | `invalid_request`, `invalid_manifest` (the detail lists the compiler's problems), `app_mismatch`. |
| 403 | `forbidden`, `approval_required`, `unknown_tenant`. |
| 404 | `not_found`. |
| 409 | `version_conflict`, `no_change` (this text is the active model), `no_source` (a version with no kept text). |

A body may be up to 16 MiB, so a 4 MiB manifest fits after JSON escaping. `tutelad_model_operations_total` counts each call by `operation` and `outcome`: `ok`, `forbidden`, `refused`, `conflict`, `stale`, `invalid` or `error`.

### 7.9 Ports and operations

**Status: Phase B, built.** `tutelad` listens on two ports.

| Port | Default | What | Auth |
|---|---|---|---|
| API | `TUTELA_LISTEN`, `0.0.0.0:8080` | HTTP and gRPC on one listener; a `content-type` of `application/grpc` picks gRPC | A bearer token on every request, also for an unknown path. Without one: 401 with `WWW-Authenticate` (HTTP), or `grpc-status: 16` (gRPC). |
| Ops | `TUTELA_OPS_LISTEN`, `0.0.0.0:9090` | The routes below | None. Keep this port out of the public load balancer. |

| Ops route | Answer |
|---|---|
| `GET /healthz` | 200 while the process answers. It never reads the database. |
| `GET /readyz` | 200 when the database answers, the schema is at the migration this build knows, and no shutdown has started. Else 503. The body names the failed check. |
| `GET /metrics` | The Prometheus text format, prefix `tutelad_`. Labels never hold a tenant, a token or a URL: a route label is the route pattern. |

gRPC health (`grpc.health.v1.Health`) is on the API port, behind the same token check. It says `NOT_SERVING` as soon as a shutdown starts.

Every answer on the API port has `x-request-id`: the one the caller sent (AuthZEN 1.0 section 10.1.3), when it is 1 to 128 visible ASCII characters, else a new one. `traceparent` is read and its trace id logged; a malformed one is ignored.

`GET /metrics` counts every question in `tutelad_decisions_total`, labelled `operation` and `outcome` (`allow`, `deny`, `error`). Logs of a decision hold no subject and no resource, at any level.

## 8. Events

**First commit:** the CloudEvents envelope and the event type grammar and names are in `tutela-contracts`. The outbox, webhook delivery, signing and SSE are **Phase B**.

### 8.1 Envelope (CloudEvents 1.0, JSON)

Events use the CloudEvents 1.0 JSON format, structured mode (`application/cloudevents+json`).

| Attribute | Required | Rule |
|---|---|---|
| `specversion` | yes | `"1.0"`. |
| `id` | yes | `<uuidv7>`. Also the **idempotency key**: receivers dedupe by it. |
| `source` | yes | `tutela://<host>/<tid>`. `<host>` is the lowercase DNS name of the `tutelad` deployment, with an optional `:port`. `<tid>` is `ten_<uuidv7>` and must equal `tenantid`. |
| `type` | yes | `tutela.<entity>.<verb>.v<major>` (8.2). |
| `subject` | yes | The id of the thing the event is about (8.3). CloudEvents makes it optional; Tutela always sets it. Order is kept per subject. |
| `time` | yes | RFC 3339 UTC with 3 fractional digits. |
| `datacontenttype` | yes | `"application/json"`. |
| `tenantid` | yes | Extension attribute. The tenant id, `ten_<uuidv7>`. |
| `orgid` | no | Extension attribute. The org id, when the event is about one org. |
| `traceparent` | no | Extension attribute (CloudEvents distributed tracing). W3C `traceparent` of the change. Sent only to receivers inside the deployment, never to outside hosts. |
| `data` | yes | A small JSON object (8.3). Never personal data, never secrets, never field values. |

A receiver maps `source`'s host to an issuer through its own trust list. It never uses `tenantid` without that issuer: the tenant key is still (iss, tid).

Example:

```json
{
  "specversion": "1.0",
  "id": "0193a1b2-c3d5-7000-8000-0000000000e1",
  "source": "tutela://auth.example.test/ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
  "type": "tutela.permissions.changed.v1",
  "subject": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
  "time": "2026-10-25T09:31:00.000Z",
  "datacontenttype": "application/json",
  "tenantid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",
  "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
  "data": { "rev": 43 }
}
```

### 8.2 Event type grammar

```abnf
event-type = "tutela." name "." name ".v" major    ; entity, verb, major version
major      = %x31-39 *DIGIT                          ; 1, 2, ... no leading zero
```

Regex: `tutela\.[a-z][a-z0-9]*(_[a-z0-9]+)*\.[a-z][a-z0-9]*(_[a-z0-9]+)*\.v[1-9][0-9]*`

### 8.3 Event list (v1)

Events are **notifications only**. They carry ids, not state. A receiver re-reads state through the API, where masks apply.

| Type | `subject` | `data` | When |
|---|---|---|---|
| `tutela.user.created.v1` | user principal | `{"user"}` | A user was created (also by just-in-time provisioning, Phase B). |
| `tutela.user.disabled.v1` | user principal | `{"user", "epoch"}` | A user was disabled. `tutela.principal.disabled.v1` is sent too. |
| `tutela.user.deleted.v1` | user principal | `{"user"}` | A user was deleted. Receivers delete or pseudonymise their own copies. |
| `tutela.org.created.v1` | org id | `{"org"}` | Receivers create their own container (for example a workspace), idempotently. |
| `tutela.org.updated.v1` | org id | `{"org"}` | Re-read the org. |
| `tutela.org.deleted.v1` | org id | `{"org", "purge_after"}` | Soft delete. Data is purged after `purge_after` (a time), at the end of the grace period. |
| `tutela.membership.changed.v1` | principal | `{"org", "principal"}` | A principal joined or left an org, or its groups changed. Re-read memberships. |
| `tutela.session.revoked.v1` | user principal | `{"principal", "epoch", "sid"}` (`principal` must be a `user`: only users have sessions) | Sessions were revoked. `sid` is set for one session and missing for all sessions. Tokens with a lower `epoch` are refused. |
| `tutela.principal.disabled.v1` | principal | `{"principal", "epoch"}` | Any kind (user, sa, key, agent, workload) was disabled. SDK caches drop that principal's tokens and cached decisions. attache's quarantine disables an agent principal, which sends this event. |
| `tutela.model.published.v1` | tenant id | `{"rev"}` | A new model version (types, fields, roles, rules, UI keys) was published. |
| `tutela.permissions.changed.v1` | tenant id | `{"rev"}` | Assignments, groups, field rules, boundary rules or conditions changed. PDPs load a bundle with at least this `rev`. |
| `tutela.key.created.v1` | key principal | `{"key", "prefix", "owner"}` | An API key was created. `prefix` is the display prefix (5.2). |
| `tutela.key.revoked.v1` | key principal | `{"key", "prefix"}` | An API key was revoked. SDK caches drop it at once. |

All values in `data` are id strings, except `epoch` and `rev` (integers) and `purge_after` (a time). `user`, `principal`, `owner` and `key` are full principal strings (1.3), for example `key:key_<uuidv7>`. `org` is an org id, `sid` is a session id and `prefix` is the display prefix. `tutela.key.*` is about **API keys**. Signing-key revocation is an open point (section 11).

Receivers ignore event types they do not know.

### 8.4 Webhook signing (Standard Webhooks)

Each delivery is an HTTP `POST` of the event JSON with `Content-Type: application/cloudevents+json`, and these headers:

| Header | Value |
|---|---|
| `webhook-id` | The event `id`. |
| `webhook-timestamp` | Unix time in seconds when this attempt was signed. |
| `webhook-signature` | `v1,<base64 HMAC-SHA256>`. During secret rotation it holds two signatures, separated by a space. |

- Signed content: `<webhook-id>.<webhook-timestamp>.<raw body>`.
- The secret has the form `whsec_<base64 of 32 random bytes>`. The HMAC key is the decoded bytes. Each endpoint has its own secret.
- Receivers must: check the signature in constant time; refuse a timestamp more than 5 minutes away from their clock; dedupe by `webhook-id`; answer 2xx quickly; then re-read state through the API.

### 8.5 Delivery guarantees (Phase B)

- **Transactional outbox.** The event row is written in the same database transaction as the change. No change without its event, no event without its change.
- **At least once.** The same event can arrive more than once. Dedupe by `id`.
- **Order per subject** (per endpoint). An event for subject S waits until the earlier events for S are delivered or dead-lettered. Events for different subjects can arrive in any order.
- **Retries** with exponential backoff and jitter, for at least 24 hours. Then the event is dead-lettered, shown in the Tutela Console, and can be sent again by hand. The exact schedule is fixed in Phase B.
- An attempt counts as delivered on any 2xx answer within 15 seconds. Redirects are not followed.
- Endpoints are https only. `tutela-safenet` checks them when they are registered and again before each send: no loopback, private, link-local or cloud-metadata addresses, and DNS is checked again each time.

### 8.6 SSE `GET /v1/events` (Phase B)

A Server-Sent Events stream (`text/event-stream`) for browsers and SDK caches.

- Each message: `id:` the event id, `event:` the event type, `data:` the event JSON on one line.
- A client resumes with `Last-Event-ID`. If that id is older than the server keeps, the server sends a `reset` message, and the client reloads its cache.
- Auth: a bearer token for SDKs; the session cookie for browsers (through the product backend). Tokens never go into the URL.
- A stream carries only events of the caller's tenant.
- Optional filter: `?types=` with a comma-separated list of event types.

---

## 9. The audit.v1 record

**First commit:** the audit.v1 record struct is in `tutela-contracts`. Producer signatures, sequence numbers, the local hash chain and forwarding are **Phase B**.

### 9.1 Fields

| Field | JSON type | Required | Rule |
|---|---|---|---|
| `schema` | string | yes | Always `"audit.v1"`. |
| `id` | string | yes | `<uuidv7>`. |
| `time` | string | yes | RFC 3339 UTC with 3 fractional digits. |
| `tenant` | object | yes | The tenant key: `{"iss", "tid"}` (1.6). |
| `org` | string | no | `org_<uuidv7>`, when the action happened inside an org. |
| `actor` | object | yes | `{"kind", "id", "on_behalf_of"}`. |
| `actor.kind` | string | yes | `user`, `sa`, `key`, `agent` or `workload`. Must equal the kind of `actor.id`. |
| `actor.id` | string | yes | A principal string. For delegated work this is the **agent** (the current actor). |
| `actor.on_behalf_of` | string | no | The person the agent acted for (the token's `sub`). Required when the work was delegated. |
| `action` | string | yes | A permission key (2.4). Tutela's own admin actions use `tutela_*` types, for example `tutela_role:write`. |
| `resource` | object | yes | `{"type", "id"}`: a type name and a resource id. |
| `decision` | object | yes | `{"effect", "rule_ids", "rev"}`, copied from the Decision. |
| `outcome` | string | yes | `success`, `failure` or `denied`. If `decision.effect` is `deny`, the outcome is `denied`. If it is `allow`, the outcome is `success` or `failure` (the action itself failed). |
| `reason` | string | yes | Same format as `Decision.reason` (`<code>` or `<code>: <detail>`). For the break-glass path: `break_glass: <the actor's typed reason>`, at most 512 characters in total. |
| `trace_id` | string | no | W3C trace id: 32 lowercase hex characters. |
| `span_id` | string | no | W3C span id: 16 lowercase hex characters. |
| `service` | string | yes | The producer service, for example `tutelad` or `crm-api`. Grammar: `[a-z][a-z0-9-]{0,62}`. |
| `request_id` | string | no | The request id, 1–128 visible ASCII characters. |
| `ip` | string | no | The client IP: IPv4 dotted decimal or IPv6 in RFC 5952 text. This is personal data (9.5). |
| `payload_digest` | string | no | `hmac-sha256:v<n>:<64 lowercase hex>`. A **keyed** digest (HMAC-SHA256 with a per-tenant audit key, version `n`) of the request payload or of the before and after values. Keyed, so a short hidden value (a salary) cannot be guessed from the digest. |
| `labels` | array of strings | yes | The labels of the data touched (`public`, `internal`, `confidential`, `secret`). Sorted, no duplicates. May be empty. |
| `seq` | integer | yes | The producer's sequence number (9.3). |
| `signature` | object | yes | `{"key_id", "value"}`, the producer's signature (9.3). |

### 9.2 Example

```json
{
  "schema": "audit.v1",
  "id": "0193a1b2-c3d5-7001-8000-0000000000a1",
  "time": "2026-10-25T09:31:12.345Z",
  "tenant": { "iss": "https://auth.example.test", "tid": "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b" },
  "org": "org_0193a1b2-c3d4-7f00-9a00-000000000002",
  "actor": {
    "kind": "agent",
    "id": "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102",
    "on_behalf_of": "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f7081"
  },
  "action": "invoice:approve",
  "resource": { "type": "invoice", "id": "inv-881" },
  "decision": { "effect": "deny", "rule_ids": ["ra_0193a1b2-c3d4-7a00-8000-0000000000a2"], "rev": 42 },
  "outcome": "denied",
  "reason": "delegation_overlap: agent has read at project p-77",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "service": "crm-api",
  "request_id": "req-7f3k9q",
  "ip": "203.0.113.7",
  "payload_digest": "hmac-sha256:v1:<64 lowercase hex>",
  "labels": ["internal"],
  "seq": 1042,
  "signature": { "key_id": "<43 base64url characters>", "value": "<86 base64url characters>" }
}
```

### 9.3 Producer signature and sequence number (Phase B)

Each producer service signs its own records. So a record cannot be forged by another service, and gaps show.

- **Key:** one Ed25519 key per service. `signature.key_id` is the RFC 7638 JWK thumbprint of the public key (base64url, 43 characters). Verifiers (Tutela and attache's evidence ledger) know each producer's public keys.
- **What is signed:** the RFC 8785 (JCS) canonical JSON of the whole record **without** the `signature` field, as UTF-8 bytes.
- **Signature:** pure Ed25519 (RFC 8032). `signature.value` is base64url without padding (86 characters).
- Writers **never write `null`** in audit.v1. They leave the field out. So the signed bytes do not change when a record is parsed and written again.
- **`seq`:** counts per (service, tenant). It starts at 1, goes up by exactly 1 per record, and is never reused. The service's single outbox relay (it holds a lease) assigns it when the record is shipped, so replicas share one counter. A gap means a lost or held record; the receiver raises an alert.
- **Idempotency:** the receiver's key is (`service`, `id`). The same key with a different payload is refused and raises an alert.

### 9.4 Storage and delivery (Phase B)

- `tutelad` writes each audit record in the same database transaction as the change.
- Tutela keeps its **own local hash-chained audit log**, so it works alone. UPDATE and DELETE on it are refused. The chain fields (`prev_hash`, `hash`) are storage columns, not part of the audit.v1 wire record.
- When configured, Tutela forwards copies to **attache's evidence ledger** through its acknowledged Append API. A record is marked shipped only after the ledger acknowledges it.
- Audit never travels through the OpenTelemetry Collector (it can drop data). The Collector carries traces and metrics only.

### 9.5 Privacy rules

- No tokens, no secrets, no raw field values in any audit field.
- Before and after values are stored as keyed digests or encrypted per field. Field masks apply again when the audit log is read.
- `ip` and `actor` are personal data. Erasure and retention rules are in [THREAT-MODEL.md](THREAT-MODEL.md) and [SECURITY.md](../SECURITY.md).

---

## 10. Versioning and deprecation

**First commit:** these rules apply from the first commit. Header handling on live endpoints starts in Phase B.

### 10.1 Where the version lives

| Contract | Version marker | A breaking change becomes |
|---|---|---|
| Ids and principals | the prefixes (`usr_`, `agt_`, …) | a new prefix |
| Access tokens | `typ: at+jwt` and the v1 claim set | a new `typ` |
| Delegated tokens | `typ: agent+jwt` | a new `typ` |
| API keys | `tut_` plus the kind | a new prefix |
| Remote check API, permission map | the URL path (`/access/v1`, `/v1/authz`) | `/v2` |
| gRPC | the package (`tutela.authz.v1`, `tutela.admin.v1`) | `tutela.authz.v2` |
| Events | the type suffix `.v1` | `.v2` |
| Audit | `schema: "audit.v1"` | `audit.v2` |
| Rust, TypeScript and Python APIs | SemVer of the release | a new version |

### 10.2 Additive only inside v1

Allowed inside v1:
- a new **optional** field, claim or request field whose default keeps the old behaviour;
- a new event type, a new reason code, a new endpoint;
- a new obligation kind or condition op, but **only after** the SDKs of that deployment know it. Older SDKs deny on unknown kinds and ops (fail closed), so sending them early breaks callers.

Not allowed inside v1:
- removing or renaming a field, claim, event type, endpoint or code;
- changing a type, a grammar or a meaning;
- making an optional field required;
- adding a value to a closed set (levels, effect, principal kinds, `outcome`);
- changing a default.

**Never reuse** a removed field name, claim name, event type, reason code, obligation kind or proto field number. In protos, removed numbers and names are marked `reserved`.

Every breaking change needs an entry in [DECISIONS.md](DECISIONS.md).

### 10.3 Breaking changes: v2 beside v1

- A breaking change ships as a new major (v2), served **beside** v1.
- v1 stays for **at least two minor releases or 90 days, whichever is longer**. In that window both work.
- Events: during the window Tutela sends both the `.v1` and the `.v2` type. Each receiver subscribes to the one it knows.
- Mark the old item deprecated everywhere: `deprecated = true` in the proto, the OpenAPI file, `#[deprecated]` in Rust, `@deprecated` in TypeScript, and the CHANGELOG.
- A deprecated HTTP endpoint sends these headers on every answer:

```
Deprecation: @1798761600
Sunset: Thu, 01 Apr 2027 00:00:00 GMT
Link: <https://github.com/f8fvwgzc/tutela/blob/main/docs/CONTRACTS.md>; rel="deprecation"
```

`Deprecation` is a structured date (RFC 9745): the time the item became deprecated. `Sunset` (RFC 8594) is the time after which it may stop working. The values above are only an example: deprecated on 2027-01-01, sunset 90 days later.

### 10.4 Dual-acceptance windows for credentials

When a credential format or key changes:
1. The new one is accepted first.
2. One release later, the old one sits behind a flag that defaults to **off**.
3. Then the old one is removed.

| Credential | Rule |
|---|---|
| Token signing keys (Phase B) | The JWKS holds the next, current and previous keys. Publish the next key at least **twice the JWKS cache time** before using it. Keep the previous key until every token it signed has expired (the max TTL plus 60 s skew). In an emergency a `kid` deny-list applies at once. |
| API keys | `tutela keys rotate` makes a new key. The old key keeps working for an overlap the operator sets, then it is revoked (`tutela.key.revoked.v1`). |
| Key pepper | Raise `TUTELA_KEY_PEPPER_VERSION` and set the new `TUTELA_KEY_PEPPER`. The previous pepper stays available (env name fixed in Phase A; `TUTELA_KEY_PEPPER_PREVIOUS` is proposed) until every old hash was re-hashed on its next successful use, or its key was rotated. |
| Master key | `TUTELA_MASTER_KEY` and `TUTELA_MASTER_KEY_PREVIOUS`: unwrap data keys with either, wrap new data keys with the current one, and re-wrap old data keys in the background. The data itself is not re-encrypted (envelope encryption, `tutela-vault`). |
| Webhook secrets | During rotation `webhook-signature` carries two signatures, old and new. |
| Credentials of other cores and products that move to Tutela | Old formats (onto-intelli `onto1.` sessions, attache `att_` operator tokens, nexc-engine HS256 JWTs between services) follow the same three steps. Impersonation headers such as onto-intelli's `x-onto-act-*` are refused whenever a Tutela token is present. Details: [INTEGRATION.md](INTEGRATION.md). |

### 10.5 Releases

- SemVer. One git tag per release. Every artifact from this repo (crates, npm packages, the Python package, protos, the `tutelad` image, the CLI) gets the same version.
- While Tutela is `0.x`, a minor release may break the Rust, TypeScript or Python API. The **wire contracts follow 10.2 from day one**.
- The public v1 surface freezes when the first outside app uses it: `/access/v1/*`, `/v1/authz/permissions`, the claim sets, the event types, audit.v1 and the SDK surfaces.

### 10.6 Contract checks (planned)

- `buf breaking` on the protos against the last release tag.
- `oasdiff` on the OpenAPI files.
- JSON Schema compatibility checks for audit.v1 and event `data`.
- The JSON examples in this file become golden tests in `tutela-contracts`.

---

## 11. Open points

| # | Question | Proposal | When |
|---|---|---|---|
| 1 | The event that pushes the signing-key `kid` deny-list to SDKs ([THREAT-MODEL.md](THREAT-MODEL.md), TM-15). It is not in the v1 event list yet. | Add `tutela.signing_key.revoked.v1` (additive), sent over SSE and webhooks. | Phase B |
| 2 | The final audience name of the remote check API. | `tutela-authz`. | Phase B |
| 3 | The final names of the obligation kinds (6.3). The admin action names (2.3) are **fixed** ([MANIFEST.md §6](MANIFEST.md#6-admin-keys), [ADR-0012](DECISIONS.md#adr-0012-manifest-v1-seeded-roles-org-root-rules-and-what-counts-as-widening)). | As written in this file. | Phase A |
| 4 | The env name for the previous key pepper. | `TUTELA_KEY_PEPPER_PREVIOUS`. | Phase A |
| 5 | Limits of `list_filter`: AST nodes, depth, size of `ids_in`; the ancestors column shape. | **Answered** by [ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator): limits in §6.6; an array of ancestor ids with a GIN index. | Week-1 spike |
| 6 | The exact AuthZEN 1.0 page field names, and the retry schedule for webhooks. | Follow the final AuthZEN 1.0 text; at least 24 hours of retries. | Phase B |

Answers go into [DECISIONS.md](DECISIONS.md), and this file changes in the same commit.
