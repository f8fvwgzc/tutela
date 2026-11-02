# @f8fvwgzc/tutela-js

The framework-free client of `tutelad`, Tutela's service. It runs in browsers and in Node 22, with no dependency. The React admin components (`@f8fvwgzc/tutela-react`) are built on it.

The full guide is [docs/JS-SDK.md](../../docs/JS-SDK.md). The routes and JSON shapes are CONTRACTS.md 7.5, 7.9, 7.10 and 7.13; the decisions are [ADR-0047](../../docs/DECISIONS.md#adr-0047-the-javascript-sdks-a-pnpm-workspace-under-sdk-checked-by-make) and [ADR-0048](../../docs/DECISIONS.md#adr-0048-tutela-js-the-browser-token-flow-in-memory-typed-errors-and-a-retry-that-never-makes-twice).

## A person in a browser

```ts
import { TutelaClient, StepUpRequiredError } from "@f8fvwgzc/tutela-js";

const tutela = new TutelaClient({
  baseUrl: "https://tutela.example.com",
  auth: {
    kind: "browser",
    // A fresh Keycloak access token (aud = tutela-authz) each time: each
    // upstream token is exchanged once.
    getUpstreamToken: async () => {
      await keycloak.updateToken(-1);
      return keycloak.token!;
    },
  },
});

try {
  const page = await tutela.assignments.page({ scope: { type: "project", id: "p-1" } });
} catch (e) {
  if (e instanceof StepUpRequiredError) {
    await keycloak.login({ acr: { values: ["mfa"], essential: true } });
    await tutela.session?.stepUp();
  }
}
```

The session exchanges the upstream token once at `POST /oauth2/token` for a `tutela-authz` token (no client authentication), and that token for an admin token (`audience=tutela-admin`, at most 300 s, only after step-up). It renews both before they expire from a fresh upstream token, never keeps a token past the token it came from, and keeps every token in memory only: never `localStorage`, `sessionStorage`, cookies or IndexedDB.

## A pipeline or a core

```ts
const tutela = new TutelaClient({
  baseUrl: process.env.TUTELA_URL!,
  auth: { kind: "service", getToken: () => myAppToken() }, // an app's client_credentials token
});
```

## What the client does for you

- Every route of the Console: `tenant`, `orgs`, `scopes`, `assignments`, `groups`, `roles()`, `models`, `principals`, `agents`, `apps`, `webhooks`, `permissions()`, `explain()`, `simulate()`, `whoami()`.
- Pages as async iterators: `for await (const a of tutela.assignments.list({ scope }))`.
- Typed errors: `NotHeldError` (`gains`, counts only), `MoveRefusedError` (`waitingFor`), `ForbiddenError`, `ConflictError`, `NotFoundError`, `UnavailableError` (`retryAfter`), `UnauthorizedError`, `InvalidRequestError`, `StepUpRequiredError`, `TokenExchangeError`, `NetworkError`. Each problem error has `status`, `code`, `detail`, `retryAfter` and `requestId`.
- The `rev` of a write is kept (`tutela.revision`) and sent as `at_least_revision` on the next permission map and explain, so a page shows its own write.
- The permission map (`tutela.permissions(...)`) with ETag and 304, kept in `tutela.permissionStore`; `tutela.can("project:manage_access", scope)` answers from it, `false` for anything not loaded. A UI hint only: every route checks again.
- A 503 is retried after `Retry-After`, at most twice and at most 5 s each by default, and only for calls that are safe to send again: never for one that makes something (an app, a webhook, an agent, an org, a proposal).
- `permissionMatrix(roles)` and `setRoleGrants(source, draft)`: the permission matrix, and a role change as a model change.

## Develop

`make js` at the repo root runs the build, `tsc`, Biome, the unit tests (a mocked fetch) and the integration test against a real `tutelad` (`make js-it`, which needs `TUTELA_TEST_DATABASE_URL`).
