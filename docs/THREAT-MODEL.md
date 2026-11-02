# Tutela threat model

Status: **pre-alpha**. In the first commit only the design docs, `tutela-contracts` and CI exist. Every control in this file is a **plan**, unless the summary table says it is built. Do not use Tutela in production yet.

This file lists who can attack Tutela, what each one can break, and the control and the test for each threat. If a design doc and this file disagree, stop and fix one of them in the same commit (see [AGENTS.md](../AGENTS.md)).

Other docs: [README](../README.md) · [AGENTS](../AGENTS.md) · [SECURITY](../SECURITY.md) · [ARCHITECTURE](ARCHITECTURE.md) · [PERMISSION-MODEL](PERMISSION-MODEL.md) · [CONTRACTS](CONTRACTS.md) · [INTEGRATION](INTEGRATION.md) · [ROADMAP](ROADMAP.md) · [DECISIONS](DECISIONS.md)

To report a vulnerability, follow [SECURITY.md](../SECURITY.md). Do not open a public issue.

## Contents

1. [Scope](#1-scope)
2. [Security goals](#2-security-goals)
3. [Actors](#3-actors)
4. [Trust boundaries](#4-trust-boundaries)
5. [Threats and controls](#5-threats-and-controls)
6. [What Tutela cannot stop](#6-what-tutela-cannot-stop)
7. [Known gaps in the first commit](#7-known-gaps-in-the-first-commit)
8. [External review before Phase C](#8-external-review-before-phase-c)
9. [Keeping this file true](#9-keeping-this-file-true)

## 1. Scope

**In scope:**

- The packages: `tutela-contracts`, `tutela-pdp`, `tutela-sdk`, `tutela-store`, `tutela-vault`, `tutela-safenet`, `@f8fvwgzc/tutela-react`, `@f8fvwgzc/tutela-node`, `@f8fvwgzc/tutela-js`, `tutela-py`.
- The service `tutelad`, the Tutela Console and the `tutela` CLI.
- The edges between Tutela and products, attache, upstream identity providers (IdPs), Postgres, and outside hosts (webhook receivers, JWKS endpoints).
- How Tutela is built and released.

**Out of scope (other repos own these):**

- attache's own threats: agent tool, host and model use, SPIFFE mTLS, sidecar admission, guardrails, taint, the model gateway and the evidence ledger itself.
- onto-intelli's per-entity checks inside graph traversal.
- A product's own records and its own database. Tutela never stores them.

The boundary rule, written exactly:

> Tutela answers: "may this principal touch this data or resource?"
> attache answers: "may this agent use this tool, host or model, and at what risk?"
> onto-intelli keeps per-entity visibility inside graph traversal (called once per entity, in-process), fed by Tutela's permissions.
> UI hiding is never security. Every server checks again.

**Phases.** A = packages and library mode. B = `tutelad` and the Tutela Console. C = own login server (optional). D = hardening. Details: [ROADMAP.md](ROADMAP.md).

## 2. Security goals

| Id | Goal |
|---|---|
| G1 | No tenant can read or change another tenant's data, through any API, cache, event or log. |
| G2 | Nobody gets more access than an approved model gives them. Delegation only narrows. |
| G3 | An agent that acts for a person never gets more than (person allowed) AND (agent allowed), capped by attache's limits. |
| G4 | A revoked role, session or principal stops working within a documented delay. A stale cache never allows after its bundle expires. |
| G5 | A hidden field never leaves the system: not in responses, search, vector indexes, exports, notifications, audit or AI prompts. |
| G6 | Every decision and admin change is in an audit log that shows tampering and gaps. |
| G7 | A self-hoster who keeps the defaults gets a safe setup. |
| G8 | When Tutela cannot decide (down, expired bundle), it fails closed. It never fails open. |

## 3. Actors

| Actor | Trusted for | Not trusted for | If hostile or compromised, it can break | Main limits |
|---|---|---|---|---|
| **Platform operator** (runs `tutelad`, Postgres, Keycloak; holds `TUTELA_MASTER_KEY`, `TUTELA_KEY_PEPPER`, signing keys) | The whole deployment | Nothing in Tutela can fully stop a hostile operator | Everything in that deployment: read all tenants, mint tokens, edit the local audit | KMS/HSM option so keys cannot be copied (TM-15); audit copies in attache's ledger, a different trust zone (TM-20); operator settings are never part of tenant roles (TM-08) |
| **Tenant owner** | Their own tenant: model, roles, members, IdP setup, webhook URLs | Other tenants, the platform, the internal network | Their own tenant's data (by design). Attack paths to others: IdP e-mail claims (TM-04), tenant id tricks (TM-05), SSRF through URLs they set (TM-18) | Owner-only admin actions are never granted by default (TM-08) |
| **Tenant admins** | What their own role grants | Granting more than they hold | Quiet widening inside the tenant | Narrow-only delegation, impact report, approval for widening, optional two-person publish (TM-08) |
| **End users** | Nothing beyond their own token | Every input they send | IDOR, path spoofing, list and count probing, field probing, CSRF | TM-09 to TM-12, TM-06 |
| **Product backend** (uses `tutela-sdk` and `tutela-pdp`; may be the backend-for-frontend) | Enforcing decisions on its own routes; loading paths from its own DB; applying field masks | Other audiences; tenants not in its trust list | Its own data, if it skips a guard or filters after loading | Codegen route guards (TM-12), SQL list filters (TM-10), exactly one audience so its tokens work nowhere else (TM-01) |
| **Browser** | Nothing. Assume XSS can happen | Holding long-lived tokens | The user's session | Backend-for-frontend cookies, short admin tokens, step-up MFA (TM-06) |
| **Agent runtime** (the process that runs an agent; may be steered by prompt injection) | Nothing about identity | Choosing which person it acts for; naming itself; setting its own limits | Anything the overlap allows, for the life of its token | `typ: agent+jwt`, one audience, 60–120 s TTL, no forwarding (TM-02); the overlap rule (TM-03) |
| **attache sidecar** | Tool, host and model decisions; the `cap` capability snapshot; workload identity (SPIFFE) | Data access decisions (Tutela makes those) | Tool and model use beyond limits. It **cannot** widen data access: Tutela still checks person AND agent | Workload principals bound to a trust bundle; quarantine disables the agent principal in Tutela (TM-02, TM-05) |
| **Upstream IdP** (Keycloak 26.x in Phases A–B, or an org's own IdP) | The `(iss, sub)` it issues; e-mails only in domains the org proved | Other issuers' users; other orgs' domains; tenant and org claims | If Keycloak is compromised: forged users for every tenant mapped to it | Issuer-to-tenant trust list (TM-05); accounts keyed by `(iss, sub)` (TM-04) |
| **Tutela itself** (`tutelad`, Console, packages) | Decisions, tokens, audit | — | One bug can affect every connected product. Tutela is the highest-value target in the platform | Fail closed, no `unsafe`, no `unwrap`/`panic!` outside tests, property tests, fuzzing, human review of auth changes, external review (section 8) |
| **Build pipeline and AI coding agents** | Building what is on protected `main` | Releasing from a laptop; holding release rights | Code that runs inside every product | TM-21 |

## 4. Trust boundaries

```
              B1                          B2
 [Browser] ---------> [Product backend] ---------> [tutelad + Tutela Console]
  cookie only          tutela-sdk                   token exchange, AuthZEN API,
                       tutela-pdp (in process)      admin API, events, audit
                       product DB (records,           |         |          |
                       resource paths)                | B4      | B5       | B7
                            ^                         v         v          v
                            | B6                  [Postgres] [outside   [attache
 [Agent runtime] --> [attache sidecar]             with RLS   hosts]     evidence
  agent+jwt, one aud   tool, host, model                      via        ledger]
                       checks                                 tutela-safenet

 [Upstream IdP: Keycloak 26.x or an org IdP] --B3--> tutelad (and tutela-sdk in Phase A)
 [Source -> CI -> registries -> deploy] --B8--> every package and image
 [Tenant X] <--B9 (logical, inside tutelad)--> [Tenant Y]
```

| Id | Boundary | What crosses it | Main checks |
|---|---|---|---|
| B1 | Browser → product backend or Tutela Console | Session cookie, form posts, SSE | HttpOnly, Secure, SameSite cookie; CSRF and Origin checks; CSP (TM-06) |
| B2 | Product backend → `tutelad` | Client credentials, Tutela access tokens, check and search requests | TLS; exactly one `aud`; tenant taken from the verified token (TM-01, TM-05) |
| B3 | Upstream IdP → `tutelad` / `tutela-sdk` | ID tokens, access tokens, discovery documents, JWKS | Issuer trust list, algorithm allow-list, fetches through `tutela-safenet` (TM-01, TM-04, TM-18) |
| B4 | `tutelad` → Postgres | Tenant-scoped queries | `FORCE ROW LEVEL SECURITY`, `SET LOCAL`, app roles own no tables (TM-14) |
| B5 | `tutelad` → outside hosts | Webhooks; JWKS and discovery fetches | `tutela-safenet`; Standard Webhooks signatures (TM-18, TM-19) |
| B6 | Agent runtime → services (through attache) | Delegated agent tokens | `typ: agent+jwt`, `delegation_aware` audiences, TTL 60–120 s, no forwarding (TM-02, TM-03) |
| B7 | `tutelad` → attache evidence ledger | Signed audit events | Ed25519 producer signature, sequence numbers, acknowledged Append (TM-20) |
| B8 | Source → CI → registries → deploy | Code, crates, npm and PyPI packages, images | Blocking CI, `cargo-deny`, `cargo-audit`, signed releases, pinned dependencies (TM-21) |
| B9 | Tenant ↔ tenant inside `tutelad` | Nothing should cross | `(iss, tid)` tenant key, RLS, per-tenant signing keys from Phase C (TM-05, TM-14, TM-15) |

## 5. Threats and controls

Each threat has an id (TM-01 ... TM-23). Its tests carry the id in their name, for example `tm01_refuses_two_audiences`. Tests exist only where the "Built" column says so. The column is honest: "Partly" names what exists.

### Summary

| Id | Threat | Main control | Phase | Built? |
|---|---|---|---|---|
| TM-01 | Token audience confusion | Exactly one `aud`; strict verifier | A, B, C | **Partly**: the `tutela-sdk` verifier refuses no audience, two or more, or another one (`tm01_*`). `tutelad` issues single-audience tokens by token exchange, only for registered audiences, and refuses ID tokens as subject tokens (`crates/tutelad/tests/exchange.rs`, ADR-0031). A `tutela-admin` token is refused on every route but the admin routes, and the admin routes refuse a person's `tutela-authz` token (`tm06_*` in `crates/tutelad/tests/models.rs`, ADR-0032) |
| TM-02 | Delegated tokens mistaken for user tokens | `typ: agent+jwt`; `delegation_aware` audiences | A, B | **Partly**: the `tutela-sdk` verifier refuses `agent+jwt` unless delegation is on and the audience is `delegation_aware`, refuses an access token with `act`, and checks disabled actors and `cnf` (`tm02_*`); issuing delegated tokens is Phase B |
| TM-03 | Confused deputy in agent work | Overlap rule for chat, task and scheduled work | A, B | **Partly**: the overlap in `tutela-pdp`, with property tests (`tm03_*`); delegated tokens are Phase B |
| TM-04 | Account linking across tenant IdPs | `(iss, sub)` keys; DNS-proven domains; local credential to link | B, C | **Partly**: just-in-time provisioning in `tutelad` keys on the upstream `(iss, sub)` and never reads an e-mail; two realms with the same subject or e-mail are two people (`tm04_*` in `tutela-store` and `crates/tutelad/tests/exchange.rs`). Domain proof and linking: Phase C |
| TM-05 | Tenant id collision across issuers | `(iss, tid)` tenant key; issuer trust list | A, B | **Partly**: `tutela-pdp` keys bundles by `(iss, tid)` and denies resources of other tenants; `tutela-store` checks `(iss, tid)` and has forced row-level security, tested on a real Postgres (`tm05_*`). Token exchange takes the tenant from the trust list only, never from a token claim or the request (`tm05_*` in `crates/tutelad/tests/exchange.rs`) |
| TM-06 | Browser token theft | Backend-for-frontend cookies; 5-minute admin token; step-up MFA | A, B, C | **Partly**: the admin token (`aud=tutela-admin`) lives at most 300 s, is issued only to a person after step-up (`acr` in `TUTELA_ADMIN_ACR`), and a 6-minute-old one or one without step-up is refused (`tm06_*`, ADR-0032). BFF cookies, CSRF and the browser test: with the Console (part 4) |
| TM-07 | Attacks on the own login server | Code + PKCE S256 only; conformance suite | C | No |
| TM-08 | Privilege escalation by admins and model changes | Narrow-only delegation; impact report; `tutela apply` refuses widening | A, B | **Partly**: the model diff, a property test that a change it does not call widening never widens a decision (`tm08_*`), and `tutela apply`, which refuses a widening diff without an approval token (ADR-0015). In `tutelad`: moves checked against boundary rules (ADR-0025), a tenant's own model versions with the same refusal (ADR-0026), the impact report (ADR-0027), and two-person publish (ADR-0029) |
| TM-09 | Resource path spoofing | Paths loaded server-side by id | A | No |
| TM-10 | List and count leaks | SQL filters from the same evaluator | A, B | **Partly**: `list_filter` ≡ `check` in `tutela-pdp`, and scope paths that are current after a move in `tutela-store` (`tm10_*`); and the `tutela-sdk` SQL adapter, whose rows equal the rows `check` allows on Postgres, with no other tenant's rows and an exact count (`tm10_*`) |
| TM-11 | Field leaks into search, vectors, exports, audit, prompts | Field masks on every exit path | A, B | No |
| TM-12 | UI-only checks | Codegen route guards; SDK refuses to start without them | A | No |
| TM-13 | Stale permission caches and slow revocation | `rev`, bundle expiry, refuse lower rev, documented delay | A, B | **Partly**: `tutela-pdp` refuses a lower or stale revision (`tm13_*`). `tutelad` replicas: built and tested end to end, with the delay measured (`crates/tutelad/tests/ha.rs`). Signed bundles: not built ([ADR-0024](DECISIONS.md#adr-0024-signed-bundles-wait-for-part-3)) |
| TM-14 | Row-level security mistakes | `FORCE` RLS, `SET LOCAL`, app roles own no tables | A, B | **Yes** for `tutela-store` and `tutelad`: forced RLS on every tenant table, the tenant only from the verified token, a non-owner role, `check_isolation` at start-up and in readiness. Tested on a real Postgres in `crates/tutelad/tests/rls.rs` ([ADR-0019](DECISIONS.md#adr-0019-tenants-in-tutelad-the-tenant-comes-from-the-token-and-rls-is-checked)). Soft-delete of tenants is not built |
| TM-15 | Signing key theft and rotation mistakes | `Signer` trait, per-tenant keys, KMS option, rotation timing, kid deny-list | B, C | **Partly**: `tutela-vault` master-key rotation (old blobs open with `TUTELA_MASTER_KEY_PREVIOUS` and are re-wrapped, `tm15_*`) and its KMS trait; the `tutela-sdk` `kid` deny-list, the rate-limited refetch of an unknown `kid`, the forced refetch, and fail-closed stale keys (`tm15_*`). `tutelad`'s signing keys: sealed by `tutela-vault`, never in plain text, behind a `Signer` trait, rotated with pre-publication, a previous key kept until its tokens expire, a deny-list that holds at once and for good (`tm15_*` in `tutela-store` and `crates/tutelad/tests/keys.rs`, ADR-0030). Per-tenant keys and KMS/HSM backends: Phase C |
| TM-16 | API key theft | Separate, versioned pepper; hashed keys | B | No |
| TM-17 | Secrets and personal data in logs, URLs, traces | Redacted types; no tokens in URLs | A, B | **Partly**: the `ApiKey` type in `tutela-contracts` never prints its secret |
| TM-18 | SSRF through webhooks and JWKS fetches | `tutela-safenet` | A, B, C | **Partly**: the `tutela-safenet` crate with the TM-18 table of bad targets (`tm18_*`); fuzzing the URL parser is a library-gate item; webhooks in `tutelad` are Phase B |
| TM-19 | Webhook forgery and replay | Standard Webhooks signatures; time window; dedupe by id | B, D | No |
| TM-20 | Audit tampering and gaps | Local hash chain; producer signatures; sequence numbers; acknowledged Append | B | No |
| TM-21 | Supply chain | `cargo-deny`, `cargo-audit`, signed images, registered names, pinned git deps | first commit, A, D | **Partly**: blocking CI with `cargo-deny` and `cargo-audit`, workspace lints |
| TM-22 | Insecure self-hosted defaults | TLS required, signup off, no dev mode outside loopback | B, D | **Partly**: `tutelad` refuses to start without `TUTELA_MASTER_KEY`, `TUTELA_KEY_PEPPER` (32 bytes or more, not the master key) or `TUTELA_ISSUER`, and names the variable, never its value (`tm22_*`); `http` issuers only on loopback in dev mode. TLS checks, signup and the Helm bootstrap job: later |
| TM-23 | Outage and overload of `tutelad` | Offline token checks; in-process PDP; fail closed | A, B, D | **Partly**: replicas fail closed in a database outage, and a batch over 200 items is refused (`crates/tutelad/tests/ha.rs`, `tests/authz.rs`). Rate limits and load tests: Phase D |

### 5.1 Tokens and identity

#### TM-01. Token audience confusion

- **Threat.** A token made for service X is sent to service Y, and Y accepts it. Variants: a token with several audiences; an ID token used as an access token; `alg: none`; HS256 signed with a public key as the secret; a token from an issuer Y does not trust.
- **Impact.** One leaked token opens every service. A low-risk service that leaks tokens becomes a key to high-risk ones.
- **Control.**
  - Every Tutela access token has exactly ONE `aud`. The SDK refuses an `aud` list with zero entries or more than one entry. It refuses an `aud` that is not exactly equal to its configured audience (no prefix or substring match).
  - The SDK checks `iss` against its trust list (exact match), plus `exp` (10 minutes for access tokens), `nbf` and `iat` with a small clock-skew allowance, and `azp` when present.
  - Algorithm allow-list: ES256, RS256, EdDSA. `none` and HMAC algorithms are refused. The key comes only from the trusted issuer's JWKS, chosen by `kid`.
  - ID tokens are never accepted as access tokens. Tutela's own provider issues RFC 9068 `at+jwt` tokens (Phase C).
  - A service never forwards a token it received. It exchanges it for a new token for the next audience (token exchange in `tutelad`, Phase B).
  - Admin components use their own audience, `aud=tutela-admin`. Product APIs refuse it. The admin API refuses product tokens.
  - With Keycloak in Phases A–B, each client must be set up so its tokens carry exactly one audience. [INTEGRATION.md](INTEGRATION.md) has the setup.
- **Phase.** A (`tutela-sdk` verifier). B (`tutelad` issues single-audience tokens and runs token exchange). C (own provider, `at+jwt`).
- **Test.** `tm01_*` verifier tests with shared test vectors in Rust, TypeScript and Python. Each case must be refused: two audiences; wrong audience; `alg: none`; HS256 with the public key as secret; an ID token; an unknown issuer; a `tutela-admin` token on a product route. Fuzz the token parser (library gate).

#### TM-02. Delegated tokens mistaken for user tokens

- **Threat.** A delegated token has `sub` = the person and the agent in `act`. A service that does not understand `act` sees a normal user token. It gives the agent all of the person's rights.
- **Impact.** An agent, maybe steered by prompt injection, acts with the person's full rights instead of the overlap. The overlap rule breaks silently.
- **Control.**
  - Delegated tokens have the header `typ: agent+jwt`. The SDKs refuse this type unless delegation support is switched on for that service.
  - `tutelad` issues a delegated token only for an audience registered with `delegation_aware = true`.
  - Exactly one audience. TTL 60–120 s for downstream hops. Optional mTLS binding (RFC 8705 `cnf`).
  - Claims: `sub` = the person, `act = {sub: agent:agt_…}`, `cap` (attache's capability snapshot, opaque to Tutela), run and node ids. Tutela never widens `cap`.
  - The PDP checks every actor in a nested `act` chain, not only the outer one. The chain holds at most 4 actors.
  - At issue time `tutelad` checks the agent principal itself: it exists, it is enabled, and it is in the same `(iss, tid)`. When attache quarantines an agent, the principal is disabled through `tutela.admin.v1`, and no new tokens are issued for it.
  - A service that receives an agent token never forwards it. It exchanges it for a new one per audience.
  - Agent API keys have their own prefix (`tut_ak_`) and resolve only to `agent:` principals.
  - Adopting products drop old impersonation headers. For example onto-intelli refuses `x-onto-act-*` headers whenever a Tutela token is present.
- **Phase.** A (SDK `typ` check; overlap in `tutela-pdp`). B (token exchange, delegated tokens, `delegation_aware` registry). Delegated tokens are part of Phase B, not optional ([DECISIONS.md](DECISIONS.md), ADR-0006).
- **Test.** A conformance test in every SDK language: on a route where the agent lacks a permission but the person has it, the delegated token is **denied**. More cases, each refused: `agent+jwt` sent to a service without delegation support; token exchange for an audience that is not `delegation_aware`; an `act` chain deeper than the cap; a token for a disabled agent.

#### TM-03. Confused deputy in agent work

- **Threat.** An agent has its own role. On task work or scheduled work it uses that role instead of the overlap with the person who caused the work. Example: a person with no access to project P assigns a task to an agent that can read P. The agent reads P for them. (The access-blueprint said "on task work the agent uses its own role". That line is a confused-deputy hole and is **replaced** by the overlap rule. See [PERMISSION-MODEL.md](PERMISSION-MODEL.md).)
- **Impact.** Any user can read or change data they cannot see, just by asking an agent. A summary built from secret inputs reaches a reader without clearance.
- **Control.**
  - Overlap rule, always: (person allowed) AND (agent allowed), capped by attache's capability limits. It applies to chat, task work and scheduled work.
  - "The person" is whoever caused the work: the assigner or the requester. It is stored with the task or the schedule.
  - When that person is disabled, their scheduled work stops. The person's `epoch` is checked again at every token exchange.
  - `ai_reach` is project (default) or team (allowed, not recommended). Never the whole workspace (the org) or another team. The model compiler refuses other values. In Phase A, `team` acts like `project`, and an agent assigned only at the org root gets nothing ([ADR-0013](DECISIONS.md#adr-0013-the-evaluator-deciding-roles-reasons-scope-paths-and-phase-a-limits)).
  - Output carries the highest label of its inputs. Readers need that label's level.
  - Narrow-only delegation: nobody grants a permission they do not hold.
- **Phase.** A (overlap and `ai_reach` in `tutela-pdp` and the compiler). B (delegated tokens carry the person; epoch check at exchange).
- **Test.** Property test "delegation ≤ person AND agent" (Phase A exit). Scenario tests: assigner without access + agent with access → task denied; scheduled run after the assigner is disabled → refused; an output label equals the highest input label; `ai_reach = workspace` in a model → compile error.

#### TM-04. Account linking across tenant-controlled IdPs

- **Threat.** A tenant controls its own upstream IdP. It asserts `email: ceo@other-company.example`. If accounts are matched by e-mail, the attacker signs in as a user of another org.
- **Impact.** Full account takeover across tenants.
- **Control.**
  - Accounts are keyed by `(iss, sub)`. Never by e-mail.
  - An org's IdP may assert e-mails only in domains the org proved with a DNS TXT record. Other e-mails are not accepted.
  - Linking a new sign-in to an existing account needs that account's own credential (password or passkey) in the same session.
  - Never auto-link across orgs.
  - In Phases A–B, Keycloak (one realm, Keycloak Organizations) brokers org IdPs. The Keycloak setup must follow the same rules ([INTEGRATION.md](INTEGRATION.md)). `tutelad`'s just-in-time provisioning keys on `(iss, sub)` and never merges by e-mail.
- **Phase.** B (just-in-time provisioning). C (per-org upstream IdPs, domain proof and linking in the own login server).
- **Test.** A hostile-IdP fixture that claims another org's domain: no link, and the e-mail is not accepted. The same e-mail from two issuers → two separate accounts. Linking without the old account's credential → refused.

#### TM-05. Tenant id collision across issuers

- **Threat.** Two issuers both send `tid: acme`. Or a tenant id looks like another one after case folding or Unicode normalisation. A service mixes their data or cache entries.
- **Impact.** Cross-tenant read or write.
- **Control.**
  - The tenant key everywhere is the pair `(iss, tid)`: in `tutela-pdp`, in the database, in cache keys, in audit and in the ledger chain key.
  - The SDK trust list maps each issuer to the tenants it may speak for. A token whose `(iss, tid)` is not on the list is refused.
  - Tenant ids are opaque and compared byte for byte. No case folding, no normalisation.
  - `org` is never taken from a raw IdP claim. `tutelad` sets it from its own membership data when it issues a Tutela token.
  - Principal strings are opaque ids (`user:usr_<uuidv7>` and so on). Names are display labels only.
  - `workload:<spiffe uri>` principals are bound to a trust bundle. The SPIFFE trust domain must be unique per cluster.
- **Phase.** A (SDK trust list; PDP and cache keys). B (`tutelad` storage and token exchange).
- **Test.** Property test "no cross-tenant grant" (Phase A exit). Two issuers with the same `tid` → separate decisions and cache entries. A token from issuer X that claims a tenant mapped only to issuer Y → refused. Two tenant ids that differ only in case → two tenants.

#### TM-06. Browser token theft

- **Threat.** XSS in a product page reads tokens from JavaScript memory or `localStorage`. CSRF makes a signed-in browser change roles. A hostile page frames an admin page (clickjacking).
- **Impact.** Session takeover. Silent role changes.
- **Control.**
  - Backend-for-frontend (BFF) by default. The browser holds only an HttpOnly, Secure, SameSite session cookie. Tokens stay on the server.
  - The product backend fetches the UI permission map (`POST /v1/authz/permissions`) itself, with its own credentials.
  - Embeddable admin components (RoleEditor, MembersTable, permission matrix) use a separate `aud=tutela-admin` token with a 5-minute TTL, issued only after step-up MFA (checked through `acr` and `amr`).
  - State-changing requests check `Origin` and a CSRF token.
  - The Tutela Console sends a strict Content-Security-Policy and `frame-ancestors`.
  - Browser SSE (`/v1/events`) uses the session cookie. Tokens never go into a URL.
  - Pure single-page apps that keep access tokens in browser JavaScript are not a default in v1 (DPoP, which would bind them, is out of v1). If a product does it anyway: memory only, never `localStorage`, short TTL.
- **Phase.** A (React and Node SDKs default to BFF). B (Console, admin token, permission map). C (step-up MFA in the own login server; before that, step-up comes from the upstream IdP's `acr`).
- **Test.** An admin call with a 6-minute-old admin token → refused. An admin call without step-up `acr` → refused. An end-to-end browser test: no token in `document.cookie`, `localStorage` or `sessionStorage`. A cross-origin POST without the CSRF token → refused.

#### TM-07. Attacks on the own login server

- **Threat.** Authorization code theft, open redirects, IdP mix-up, code replay, refresh-token theft, password stuffing, weak MFA.
- **Impact.** Account takeover in every product that trusts this server.
- **Control.**
  - Authorization code + PKCE S256 only. Exact redirect-URI match. `state` and `nonce` required. RFC 9207 `iss` in the response.
  - Single-use codes, 60 s or less.
  - Rotating refresh tokens with family revocation: reuse of an old refresh token revokes the whole family.
  - `client_credentials`, token exchange, RFC 9068 `at+jwt`.
  - Argon2id passwords. TOTP and recovery codes. Passkeys (webauthn-rs). SMTP outbox (lettre).
  - Swapping Keycloak for `tutelad` is a config change only. So Keycloak stays a safe way back.
- **Phase.** C (optional). Nobody uses it before the login-server gate passes ([ROADMAP.md](ROADMAP.md)).
- **Test.** OpenID Foundation Basic OP and Config OP conformance in CI. Fuzzing of the authorize and token endpoints. Negative tests, each refused: a redirect URI with an extra path or query; a second use of a code; `plain` PKCE; a missing `nonce`. A reused refresh token → the whole family is revoked.

### 5.2 Permissions and data

#### TM-08. Privilege escalation by admins and model changes

- **Threat.** A tenant admin grants a role higher than their own. A model change quietly widens access ("now everyone reads contracts"). A normal update sets an access-granting field (owner, parent, ACL) on the side.
- **Impact.** Widening that nobody approved. Insider abuse.
- **Control.**
  - Narrow-only delegation: nobody grants a permission they do not hold.
  - Owner-only admin actions sit above the four levels (None < Read < Write < Full) and are never granted by default.
  - Every model change gets an impact report ("12 users gain read on contract"). Widening changes need approval. Two-person publish is optional.
  - `tutela apply` shows the diff first. It fails on a widening diff without an approval token.
  - `Pdp::write_check` gives per-field verdicts for a write. Changes to access-granting fields need `manage_access`.
  - A move (a change of parent) is checked against the boundary rules of both scopes (`moves_out` on the source, `moves_in` on the target). A move into a looser scope waits for the source owner's approval ([PERMISSION-MODEL.md §10](PERMISSION-MODEL.md#10-moving-resources-between-scopes)).
  - A new field marked confidential or secret starts at None (a correction to the blueprint).
  - Operator settings (issuer trust list, signup policy, signing keys) are not tenant permissions. No tenant role can hold them.
- **Phase.** A (narrow-only rule, `write_check`, widening detection in the compiler). B (impact report, approvals, two-person publish, `tutela apply` against `tutelad`).
- **Test.** Property test "no widening" (Phase A exit): random grant attempts never give anyone more than the granter holds. `tutela apply` with a widening diff and no approval token → non-zero exit. A move without `moves_out` on the source or `moves_in` on the target → denied. A move into a looser scope without approval → not applied (`tm08_*` in `tutela-pdp` and `crates/tutelad/tests/write_check.rs`). A new secret field → None for every role until a rule grants it.

#### TM-09. Resource path spoofing

- **Threat.** A decision depends on the resource's parent path (for example workspace → team → project → issue). If the path or attributes come from the request body, the attacker sends a fake path ("this issue is in my project") and passes the check.
- **Impact.** Read or write of any resource whose id the attacker knows (IDOR).
- **Control.**
  - SDK helpers load the path and attributes on the server, by id, from the caller's own database (or onto-intelli's graph). Never from the request body.
  - Every resource has exactly one parent. The closest role assignment wins. A private scope stops inheritance.
  - Links never grant access.
  - Moving a resource is checked against the boundary rules of both scopes (TM-08).
- **Phase.** A.
- **Test.** A handler built with the SDK helper ignores path fields in the body: a request with a forged parent id gets the decision for the real path. A link between two resources gives no access across the link.

#### TM-10. List and count leaks

- **Threat.** A service loads all rows, then drops the denied ones. Page sizes, total counts, facets and timing show that hidden rows exist. Or the SQL filter and `check` disagree.
- **Impact.** The existence and number of hidden records leak ("there are 3 contracts with the acquisition label"). If the two paths disagree, whole rows leak.
- **Control.**
  - One evaluator. It resolves the effective level once per (principal, scope) and emits **both** the decision and the SQL list filter (`ids_in` + `container_in` + condition AST) from the same code.
  - Lists are filtered inside SQL. Never load-then-drop. Counts, facets and pagination run on the filtered query.
  - All values are bound as parameters. The compiler never pastes text into SQL.
  - The compiler accepts only condition templates that both paths support, and refuses a model that uses anything else.
  - The remote search endpoints (`/access/v1/search/resource`, `/access/v1/search/subject`) use the same evaluator.
  - `list_filter` gets scope paths from a provider keyed by (tenant, type, id). An unknown id, a path that does not end at the tenant's own org, or a path longer than 32 is an error, and the list fails closed ([ADR-0011](DECISIONS.md#adr-0011-week-1-spike-go-for-the-native-evaluator) F1).
  - List and count queries run with a statement timeout that fails closed, never with a partial result.
- **Phase.** A (`Pdp::list_filter`). B (AuthZEN search endpoints).
- **Test.** Differential property test on every commit: for random models, principals and rows, the rows that `list_filter` returns == the rows that `check` allows. Fuzz the SQL filter compiler (library gate). Week-1 spike: `list_filter` correct on 100k rows. The `tutela-pdp` differential tests also cover scope-path provider misses, wrong-tenant paths and ids that are the same across tenants. Product template test: the total count equals the number of visible rows.

#### TM-11. Field leaks into search, vector indexes, exports, audit and prompts

- **Threat.** The API hides a field, but the value leaves through another path: full-text search, a vector index, a CSV export, a notification, a webhook, SSE, audit before/after values, or an AI prompt.
- **Impact.** Confidential fields (salary, contract value) reach users and models that cannot read them.
- **Control.**
  - The decision carries `field_mask {read, write}`. Field level = the lower of (role level, closest field rule).
  - Rule: a field leaves the system only through a masked path. Masks apply to API responses, search and vector indexes, exports, notifications, webhooks, SSE, audit and AI prompts.
  - Hidden fields are removed **before** a prompt is built, not after.
  - Search and vector indexes hold only fields whose read level equals the entity's base visibility, or keep separate indexes per sensitivity.
  - Audit stores before/after values as digests or encrypted per field. Masks apply again when audit is read.
  - New confidential or secret fields start at None. Output carries the highest label of its inputs.
- **Phase.** A (`field_mask`, SDK strip helpers). B (Tutela's own channels: audit, webhooks, SSE, Console). Each product and onto-intelli add masking to their own channels when they adopt Tutela ([INTEGRATION.md](INTEGRATION.md)).
- **Test.** A canary test kit: put a unique canary value in a masked field, drive every channel (API, search, vector index, export, notification, webhook, SSE, audit read, prompt builder), and fail if the canary reaches a principal without read access. The kit ships with the product template, so every product runs it.

#### TM-12. UI-only checks

- **Threat.** The UI hides a button, but the API route behind it has no check. A user calls the route directly.
- **Impact.** Every hidden action is open to anyone with a token.
- **Control.**
  - UI hiding is never security. Every server checks again.
  - Each UI key in `tutela.resources.toml` names its actions AND the API routes behind it. `tutela codegen` generates both the React constants and the server route guards from the same entry.
  - The SDK refuses to start if a declared route has no guard.
  - UI modes (show, disable with a reason tooltip, hide, readonly) are display only.
- **Phase.** A (codegen and the start-up check).
- **Test.** The generated test calls each declared route as a denied principal and expects 403. Start-up test: a declared route without a guard → the service does not start.

#### TM-13. Stale permission caches and slow revocation

- **Threat.** A role is removed, but a cache still allows: the SDK decision cache, the in-process PDP bundle, or a lagging replica. An attacker replays an older signed bundle.
- **Impact.** A removed employee keeps access. A quarantined agent keeps acting.
- **Control.**
  - A per-tenant revision `rev` is bumped in the same transaction as the change. Callers send `at_least_revision` after their own writes.
  - Signed bundles per (tenant, rev) with `issued_at` and `expires_at`. The PDP refuses a lower `rev` than it has seen, and refuses expired bundles. Reads then return 503 instead of a stale allow.
  - Max bundle age is set per action class. Writes and admin actions fail closed sooner.
  - The `epoch` claim gives fast session revocation. `tutela.session.revoked.v1`, `tutela.principal.disabled.v1` and `tutela.permissions.changed.v1` events over SSE drop caches.
  - Tokens never carry permission lists, so a token cannot keep old permissions alive.
  - Short lifetimes: access tokens 10 minutes; delegated hops 60–120 s; admin tokens 5 minutes.
  - 2+ `tutelad` replicas.
  - **Documented delay.** On a `tutelad` replica: at most 1.5 s in normal running, measured at a worst case of 1.010 s over 60 rounds on two real processes. Cut off from the database, the max age of the action's class: 60 s for reads, 10 s for other actions, 1 s for admin keys and owner-only actions ([PERMISSION-MODEL.md 16.1](PERMISSION-MODEL.md#161-how-long-until-a-revocation-takes-effect), [ARCHITECTURE.md section 7](ARCHITECTURE.md#7-availability)). Worst case for a disabled principal or a revoked session = the time to receive the event, and never more than the token lifetime plus clock skew.
- **Phase.** A (rev-keyed decision cache; bundle rules in `tutela-pdp`). B (revisions in `tutelad`, signed bundles, SSE).
- **Test.** Phase B exit: a revoked role takes effect within the documented delay, measured end to end. The PDP is fed a lower-rev bundle → refused. An expired bundle → 503, never an allow. A bundle with a bad signature → refused. A read with `at_least_revision` on a lagging replica → waits or fails, never answers from the old revision.

### 5.3 Tenant isolation in storage

#### TM-14. Row-level security mistakes

- **Threat.** `tutelad` keeps many tenants in one Postgres database. Common RLS mistakes: the table owner bypasses RLS (no `FORCE`); the app role is a superuser or has `BYPASSRLS`; a session-level `SET` leaks the tenant to the next request on a pooled connection; the tenant comes from a header instead of the verified token; a `SECURITY DEFINER` function runs with the owner's rights.
- **Impact.** One code bug becomes a cross-tenant read or write.
- **Control.**
  - `tenant_id` on every row. `FORCE ROW LEVEL SECURITY` on every tenant table.
  - The tenant is set with `SET LOCAL` inside each transaction, only from the verified token.
  - App roles never own tables. They are not superusers and have no `BYPASSRLS`. Migrations run as a separate owner role.
  - With no tenant set, the policies match zero rows.
  - No `SECURITY DEFINER` functions or owner-rights views over tenant tables.
  - Tenants are soft-deleted with a grace period. Never `DROP SCHEMA ... CASCADE`.
  - `tutela-store` ships the same pattern, so library-mode products get it too.
- **Phase.** A (`tutela-store` migrations). B (`tutelad`; service gate).
- **Test.** A query with no tenant set returns zero rows. Phase B exit: a cross-tenant read fails at RLS even with an injected code bug (a query with the tenant filter removed). Pooled-connection test: after a tenant-A transaction, the next transaction on the same connection sees nothing until it runs its own `SET LOCAL`. A CI check fails if the app role owns a table or has `BYPASSRLS`.
- **Built.** `crates/tutelad/tests/rls.rs` runs each of these on a real Postgres, with the service's own role and pool.
  - `with_no_tenant_set_every_table_returns_zero_rows` covers every tenant table the catalog lists, and fails if a new one has no seed rows.
  - `a_cross_tenant_read_fails_at_rls_with_an_injected_bug` puts a handler with no tenant filter behind the real token check. It then turns RLS off and shows the same request leaks, so RLS is what stopped it.
  - `an_unsafe_role_or_schema_is_refused` is the check on the role and the schema. `tutelad` runs the same check at start-up and in readiness (`tutela_store::check_isolation`).
- **Known limit.** RLS trusts `tutela.tenant_id`. SQL injection that can call `set_config` could change it, so `tutela-store` binds every value, and a transaction refuses a second tenant through the store's own calls.

### 5.4 Keys and secrets

#### TM-15. Signing key theft and rotation mistakes

- **Threat.** A signing key is stolen. Or a rotation breaks verification because SDKs still cache the old JWKS. Or one tenant's key can sign tokens that another tenant accepts.
- **Impact.** Forged tokens for any user. Or an outage during rotation.
- **Control.**
  - Signing goes through a `Signer` trait. Backends: a local key for development and small self-hosts; KMS or HSM for production. With KMS or HSM the private key never leaves the device.
  - Separate signing keys per tenant. The SDK refuses a token whose `kid` belongs to another tenant.
  - Algorithms: ES256 default; RS256 always published (OIDC Discovery); EdDSA allowed.
  - Rotation timing: publish the next key **at least twice the JWKS cache time** before using it. Keep the old key published until every token it signed has expired.
  - Emergency: a `kid` deny-list that every SDK applies at once (pushed over SSE and also settable in config), plus a forced JWKS refetch.
  - The SDK refetches JWKS on an unknown `kid` at most once per short interval, so an attacker cannot force fetch storms.
  - `tutela-vault` uses envelope encryption. The master key (`TUTELA_MASTER_KEY`) rotates with `TUTELA_MASTER_KEY_PREVIOUS`: data keys are re-wrapped, data is not re-encrypted. Production can use the KMS trait instead of an env key.
  - Encrypted key backups and a key-restore drill.
- **Phase.** A (`tutela-vault`; SDK deny-list and refetch rules). B (`tutelad` signs its first tokens in token exchange, so rotation timing and the deny-list must work from the start). C (per-tenant keys behind the `Signer` trait with KMS/HSM backends; key-restore drill in the login-server gate). Recommendation: put the very first signing key behind the `Signer` trait already in Phase B, so Phase C does not change call sites.
- **Test.** Rotation test with a fake clock: through a full rotation, every SDK whose JWKS cache is within the configured age verifies every valid token. A deny-listed `kid` → refused at once, even when cached. A token for tenant B signed with tenant A's key → refused. Master key rotation: data sealed under the old key still opens with `TUTELA_MASTER_KEY_PREVIOUS` set, and is re-wrapped to the new key. Key-restore drill (Phase C gate).

#### TM-16. API key theft

- **Threat.** The database leaks (a backup, an injection bug). Stored API keys are used or cracked. Or the pepper and the master key are the same secret, so one leak gives both.
- **Impact.** Long-lived machine access to a tenant.
- **Control.**
  - Format: `tut_sk_<8-char prefix>_<43 base64url chars>` for app and service-account keys; `tut_ak_...` for agent keys. The 43 characters carry 256 bits of randomness.
  - Stored as SHA-256(pepper || key) together with the pepper version. Never stored in plain text. Shown once, at creation.
  - The pepper (`TUTELA_KEY_PEPPER`, `TUTELA_KEY_PEPPER_VERSION`) is separate and versioned. It is **never** derived from the master key.
  - Lookup by the 8-character prefix. Hash compare in constant time.
  - Pepper rotation: verify with the stored version; after a successful check, store a new hash under the current version.
  - The fixed prefixes let secret scanners find leaked keys in code and logs.
  - Revoking a key emits `tutela.key.revoked.v1`.
- **Phase.** B (`tutelad` key store). The format is fixed in [CONTRACTS.md](CONTRACTS.md).
- **Test.** A database dump without the pepper cannot confirm any key. Pepper rotation: keys hashed under the old version still work and move to the new version. A key whose stored version has no pepper configured → refused, not silently accepted. A revoked key → refused at once.

#### TM-17. Secrets and personal data in logs, URLs and traces

- **Threat.** Tokens, API keys or personal data end up in logs, query strings or span attributes, and then in log storage that many people can read.
- **Impact.** Token theft from logs. A privacy breach.
- **Control.**
  - Never tokens or personal data in logs, URLs or span attributes.
  - Token, key and secret types have redacted `Debug` and `Display` output.
  - No tokens in query strings. Browser SSE uses the session cookie.
  - W3C `traceparent` on every hop, OTLP to an OpenTelemetry collector. `tutela-safenet` does not send `baggage` to outside hosts.
  - Agent tokens never go into a model's context, a child process's environment or tool output. attache enforces this. Tutela keeps delegated TTLs short so a leak expires fast.
- **Phase.** A (redacted types in `tutela-contracts` and `tutela-sdk`). B (`tutelad` logging and tracing).
- **Test.** A log-scan test runs the end-to-end suite with known canary tokens and keys. It fails if any `tut_sk_`, `tut_ak_` or JWT-shaped string appears in logs or exported spans. Unit tests assert that `format!("{:?}", secret)` prints a redacted value.

### 5.5 Outbound calls and events

#### TM-18. SSRF through webhooks and JWKS fetches

- **Threat.** A tenant admin sets a webhook URL, an upstream issuer or a JWKS URL that points inside the network: cloud metadata (`169.254.169.254`), localhost admin ports, Postgres, the Kubernetes API. Tricks: DNS rebinding, redirects, decimal or hex IPs, IPv4-mapped IPv6.
- **Impact.** Cloud credentials stolen; internal services reached from `tutelad`'s network position.
- **Control.** All outbound HTTP from `tutelad` for tenant-supplied URLs goes through `tutela-safenet` (ported from onto-intelli's `net.rs` designs). It:
  - resolves DNS once, checks every resolved IP, then connects to that checked IP (no second lookup, so no rebinding);
  - denies loopback, private, link-local, CGNAT, multicast and unspecified ranges, cloud metadata addresses, and the IPv4-mapped IPv6 forms of all of them;
  - allows `https` only (`http` only on loopback in dev mode);
  - turns redirects off, or checks every hop again;
  - sets timeouts and response size limits;
  - supports an operator allow-list for private hosts that are needed on purpose (for example an internal Keycloak).
  - Tenant URLs are checked when they are saved and again on every fetch.
  - nexc-engine's URL-text SSRF checks move to `tutela-safenet` when it adopts Tutela.
- **Phase.** A (the crate). B (webhooks, JWKS and discovery fetches in `tutelad`). C (per-org upstream IdPs).
- **Test.** A table of bad targets, each refused: `http://169.254.169.254/`, `http://2130706433/`, `http://0x7f.1/`, `http://[::ffff:127.0.0.1]/`, a name that resolves to a private IP, a name that changes its answer between lookups, a public URL that redirects to a private one. Fuzz the URL parser.

#### TM-19. Webhook forgery and replay

- **Threat.** An attacker sends fake events to a receiver, replays a real one, or changes the body.
- **Impact.** Receivers act on false events (for example they re-create a deleted org).
- **Control.**
  - Standard Webhooks HMAC-SHA256 signatures over id, timestamp and body. One secret per endpoint. Rotation keeps the old and new secret valid for a short overlap.
  - Receivers check the signature in constant time, refuse timestamps outside a short window, and dedupe by event id (UUIDv7, also the idempotency key).
  - Events are notifications only. Receivers re-read state through the API. So a forged or replayed event cannot grant access by itself.
  - Delivery: transactional outbox, retries with backoff, at-least-once, order kept per subject.
  - The Helm bootstrap job creates webhook secrets. Nobody types them by hand.
  - Verifiers ship in the Rust, Node and Python SDKs, so products do not write their own.
- **Phase.** B (outbox, signing, SSE). D (webhook hardening).
- **Test.** Shared test vectors in all three SDKs: changed body → refused; old timestamp → refused; replayed id → ignored; wrong secret → refused; old secret inside the rotation overlap → accepted, after the overlap → refused.

### 5.6 Audit

#### TM-20. Audit tampering and gaps

- **Threat.** Someone with database access edits or deletes audit rows to hide an action. Events are lost on the way (for example in a collector that drops data). A producer is impersonated.
- **Impact.** Attacks cannot be traced. The audit is worthless as evidence.
- **Control.**
  - Tutela keeps its own local hash-chained audit log: each row stores the hash of the previous row. UPDATE and DELETE are refused by the database, not only by code. So Tutela works alone, without attache.
  - Each producer signs its events with its own Ed25519 key and a per-producer sequence number, so gaps show.
  - When configured, `tutelad` forwards copies to attache's evidence ledger through an **acknowledged** Append API. Not through the OpenTelemetry collector, which can drop data. Events that are not acknowledged stay in the outbox and are sent again.
  - `audit.v1` records the actor (with `on_behalf_of` for agents), the action, the resource, the decision `{effect, rule_ids, rev}`, the outcome and a `payload_digest`.
  - Before/after values are digests or encrypted per field. This should let personal data be erased later without breaking the chain. The exact erasure flow is an open item (section 7).
  - Honest limit: someone with full database and key access could rebuild the whole local chain. The copy in attache's ledger, in another trust zone, is what shows that.
- **Phase.** B (local chain, signatures, forwarding).
- **Test.** Chain verifier: change one row → it reports the first broken row. Delete a row → it reports the sequence gap. UPDATE or DELETE as the app role → refused by Postgres. The ledger is down → events wait in the outbox and arrive later, none lost. A forged producer signature → refused (tested together with attache).

### 5.7 Build, deploy and run

#### TM-21. Supply chain

- **Threat.** A malicious or vulnerable dependency. Dependency confusion: someone publishes a package named like ours on a public registry and a build pulls it. A moved git tag. A tampered release image. A stolen token or an AI coding agent pushes to `main` or cuts a release.
- **Impact.** Code runs inside every product that links the SDK. Total compromise.
- **Control.**
  - **Built in the first commit:** blocking CI with `cargo fmt`, `clippy -D warnings`, tests, `cargo doc`, `cargo-deny` and `cargo-audit --deny warnings`. `deny.toml` fails on any advisory, allows only the licences on its list (permissive ones, plus MPL-2.0 for `webauthn-rs`), bans `openssl`, `openssl-sys` and `native-tls`, and denies unknown registries and git sources. `Cargo.lock` is committed and builds use `--locked`. Workspace lints forbid `unsafe` and deny `unwrap`, `expect`, `panic!` and `todo!` outside tests. Dependabot checks cargo and GitHub Actions weekly.
  - Register our names on public registries before the first publish: crates.io `tutela-*`, the npm scope `@f8fvwgzc`, PyPI `tutela-py`. This stops dependency confusion. Mark private package indexes as explicit (for example uv `explicit = true`). Install with `npm ci`.
  - Pin git dependencies by commit SHA, not only by tag.
  - Release only from CI on protected tags. Sign images and packages (cosign) with build provenance. Consumers verify the signature against the exact workflow identity.
  - Protect `main` and release tags. Every auth-related change gets a human review (CODEOWNERS on auth code).
  - AI coding agents get fine-grained tokens for one repo, with no workflow-write, tag or release rights.
  - Hardware-key 2FA on the GitHub account.
- **Phase.** First commit (CI, lints, `deny.toml`). A (name registration; v0.1 tagged and signed). D (signed `tutelad` images and Helm chart).
- **Test.** CI itself is the test: a crate from an unknown git source fails `cargo deny`; a crate with a known advisory fails `cargo audit`; an OpenSSL dependency fails the bans. Later: the release job runs `cosign verify` on its own output, and a scheduled job checks that every public name still belongs to the owner.

#### TM-22. Insecure self-hosted defaults

- **Threat.** A self-hoster runs `tutelad` with development settings on a public address: plain HTTP, open signup, debug options, default secrets.
- **Impact.** Anyone on the internet creates accounts, or reads tokens in transit.
- **Control.**
  - TLS required. Plain HTTP only on loopback in dev mode. If TLS ends at a proxy or ingress, the operator must say so in config.
  - Secure cookies always (outside dev mode).
  - Signup is off by default.
  - Dev mode refuses to start on any non-loopback address.
  - No default passwords. Bootstrap tokens are single-use and expire. The Helm bootstrap job creates client credentials and webhook secrets before other charts start.
  - Missing required secrets (`TUTELA_MASTER_KEY`, `TUTELA_KEY_PEPPER`) stop the start-up. They are never made up silently.
  - The Helm chart runs 2+ replicas by default.
- **Phase.** B (config checks, Helm bootstrap job). D (Helm and compose hardening).
- **Test.** Start-up tests, each must exit with an error: dev mode on `0.0.0.0`; a non-loopback listener without TLS or a declared proxy; a missing pepper. On a fresh install the signup endpoint refuses. A bootstrap token used twice → refused.

#### TM-23. Outage and overload of `tutelad`

- **Threat.** `tutelad` is down or flooded (token exchange, evaluation, search, signup). Products then fail open (a security hole) or all stop (an outage).
- **Impact.** Fail open = unauthorized access. Fail closed = every product is down.
- **Control.**
  - Tokens are verified offline in the SDK with a cached JWKS. A request does not need `tutelad` to check identity.
  - Library mode: `tutela-pdp` runs in process. In service mode the PDP keeps its last good bundle until `expires_at`, then reads return 503. It never fails open.
  - `/access/v1/evaluations` takes at most 200 items per call.
  - Rate limits on token, exchange, search and signup endpoints (numbers are an open item, Phase D).
  - 2+ replicas. The outbox buffers events while receivers are down.
- **Phase.** A (offline verification, in-process PDP). B (replicas). D (rate limits, load and soak tests).
- **Test.** Stop `tutelad` during an end-to-end run: reads keep working until bundle expiry, then return 503, never an allow. A batch with 201 items → refused. Load and soak tests (Phase D).

## 6. What Tutela cannot stop

These risks stay, even when every control above is built:

- **A hostile platform operator.** They own the keys and the database. Tutela makes their changes visible (the ledger copy in attache), not impossible.
- **A product that skips the SDK**, or never declares a route in `tutela.resources.toml`. Codegen checks only declared routes. Product review must catch the rest.
- **A compromised product backend.** It can misuse its own data and the tokens it receives. Because each token has exactly one audience and a short life, the damage stays inside that product, for that time.
- **A compromised issuer.** In Phases A–B that is Keycloak. It can forge users for every tenant mapped to it in the trust list.
- **Admins who misuse rights they really have.** Audit and impact reports make it visible.
- **What an agent does with data it may read.** Tutela limits what an agent can reach (the overlap). It does not judge what the agent does with it. attache's guardrails and taint tracking cover that.

## 7. Known gaps in the first commit

Everything in section 5 is unbuilt, except the CI and lint parts of TM-21 and the redacted `ApiKey` type of TM-17.

| Area | State in the first commit | Needed by |
|---|---|---|
| `tutela-pdp`, `tutela-sdk`, `tutela-store`, `tutela-vault`, `tutela-safenet` | Not written | Phase A |
| `@f8fvwgzc/tutela-react`, `@f8fvwgzc/tutela-node`, `@f8fvwgzc/tutela-js`, `tutela-py` | Not written | Phase A |
| `tutela` CLI (`init`, `codegen`, `apply`, `apps create`, `keys rotate`) | Not written | Phases A–B |
| `tutelad`, Tutela Console, token exchange, delegated tokens | Not written | Phase B |
| `tutela-contracts` | Wire types with their format and claim checks only. No signature or token verification (that is `tutela-sdk`, Phase A) | Grows in Phase A |
| Every `tmNN_*` test in this file | None exist | Phase of each item |
| Permission property tests (no cross-tenant grant, no widening, delegation, `list_filter` ≡ `check`), fuzzing jobs, latency checks | None exist. `tutela-contracts` has only parser property tests. | Library gate (end of A) |
| CI | Blocking: fmt, clippy, tests, doc, `cargo-deny`, `cargo-audit` | Built |
| GitHub Actions pinning | Pinned by version tag, not by commit SHA | Before the first release (A) |
| Release signing and provenance | No release job yet | v0.1 (end of A) |
| Package names on crates.io, npm, PyPI | Not registered; not yet checked that they are free | Before the first publish (A) |
| Branch protection, tag rulesets, CODEOWNERS | Not confirmed by this file | Before any AI agent or second person gets push access ([ROADMAP.md](ROADMAP.md), "Very next steps") |
| External security review | Not done | See section 8 |

**Open items** (decide and record in [DECISIONS.md](DECISIONS.md)):

- Max bundle ages per action class, for a PDP outside `tutelad` (TM-13). A replica's numbers are set.
- Rate-limit numbers for token, exchange, search and signup endpoints (TM-23).
- Account recovery and MFA reset, and how to resist help-desk social engineering (Phase C).
- Tenant offboarding: key destruction, crypto-shredding, data export and erasure, and how erasure fits with the hash-chained audit (TM-20).
- Incident runbooks: signing-key compromise, mass session revocation, a cross-tenant breach, a ledger chain mismatch (Phase D).

## 8. External review before Phase C

Tutela is the highest-value target in the platform. AI help writes code fast, but it does not replace an outside review.

1. **Before Phase C starts:** an external security review of the Phase A and B work, and all findings fixed or recorded with a reason in [DECISIONS.md](DECISIONS.md). Scope:
   - `tutela-pdp`: the evaluator, the SQL filter compiler, the overlap rule, narrow-only delegation;
   - `tutela-sdk` token verifiers in Rust, TypeScript and Python;
   - token exchange and delegated agent tokens;
   - RLS and tenant isolation in `tutelad` and `tutela-store`;
   - key management, `tutela-vault`, the API-key pepper;
   - `tutela-safenet`, webhook signing, the audit chain.
2. **Before anyone uses the Phase C login server:** the login-server gate. OpenID Foundation Basic OP and Config OP conformance in CI, fuzzing, its own external security review, and a key-restore drill ([ROADMAP.md](ROADMAP.md)).
3. **Before the first pilot with real users:** a penetration test of the delegation path, and prompt-injection red-team runs together with attache.
4. **Time.** Plan 2–4 calendar weeks per review, plus fix time. AI help does not shorten this.
5. **No review, no Phase C.** If there is no budget for a review, Keycloak stays the login server for good and only Phases A, B and D are built. Swapping Keycloak for `tutelad` is a config change only, so this path stays safe.

## 9. Keeping this file true

- Every control has an id (TM-nn). Its tests use the id in their name, so `grep tm13_` finds the proof for TM-13.
- An auth-related change updates this file in the same commit, adds a regression test, and gets a human review ([AGENTS.md](../AGENTS.md), section 4).
- When a control is built, change its "Built?" cell in the summary table and name the test. When a control is dropped, record why in [DECISIONS.md](DECISIONS.md).
- New threats get the next free id. Ids are never reused.
