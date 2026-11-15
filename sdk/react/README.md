# @f8fvwgzc/tutela-react

React 19 admin components for Tutela, built on [`@f8fvwgzc/tutela-js`](../js/README.md): `MembersTable`, `RoleEditor` and `PermissionMatrix`, a provider and hooks. They embed in someone else's app: no CSS framework, no global CSS, light and dark themes through CSS variables, keyboard and screen-reader friendly, and no motion beyond a 120 ms colour change (none under `prefers-reduced-motion`).

The full guide, with embedding behind a product's own Keycloak sign-in, is [docs/JS-SDK.md](../../docs/JS-SDK.md).

```tsx
import { TutelaClient } from "@f8fvwgzc/tutela-js";
import { MembersTable, PermissionMatrix, RoleEditor, TutelaProvider } from "@f8fvwgzc/tutela-react";
import "@f8fvwgzc/tutela-react/styles.css";

const tutela = new TutelaClient({
  baseUrl: "/tutela", // tutelad, or your proxy of it on this origin
  auth: { kind: "browser", getUpstreamToken: async () => (await keycloak.updateToken(-1), keycloak.token!) },
});

export function ProjectAccess({ project, org }: { project: string; org: string }) {
  return (
    <TutelaProvider client={tutela}>
      <MembersTable
        scope={{ type: "project", id: project }}
        path={[{ type: "org", id: org }]}
        renderSubject={(s) => <PersonName principal={s} />}
        onAskAdmin={(request) => openAccessRequest(request)}
        onStepUp={() => keycloak.login({ acr: { values: ["mfa"], essential: true } })}
      />
    </TutelaProvider>
  );
}
```

| Component | What it does |
|---|---|
| `MembersTable` | Members of a scope, paged. Give a role with an optional end, change an end, remove a role. Hides what the person may not do (the permission map, then a 403 `forbidden`); on `not_held` shows the counts-only detail and an "Ask an admin who holds more" button (`onAskAdmin`); on 409 loads again; on 503 tries again after `Retry-After`. |
| `RoleEditor` | One role's levels, field levels, custom actions and admin keys. Builds the model change, shows `POST /v1/models/impact` as sentences, asks for an approval token when the change widens, publishes with `expected_version` or proposes when the tenant needs two people. |
| `PermissionMatrix` | Roles × types from `GET /v1/admin/roles`, field rows under their type (never above the item level), custom actions and admin keys. `editable` lets a person change one role's column and hands the draft to `onReview` for a `RoleEditor`. |
| `ErrorNotice` | Any typed error of `tutela-js`, said plainly, with the next step. |

For a product's own pages:

| Component | What it does |
|---|---|
| `Protect` | Loads one permission map for a resource (with the UI keys and fields inside) and shows its children only when the action is allowed; otherwise `fallback`. |
| `Can` | Shows a part by a UI key's mode (`show`, `disable`, `readonly`, `hide`) or by one action. Disabled parts sit in a disabled `<fieldset class="tutela-can">`; a function child gets the mode and draws the part itself. |
| `Field` | Shows one field's value when the person may read it, else "Restricted" (or nothing with `whenHidden="remove"`). A function child gets `read` or `write`. |

Hooks: `useTutela`, `useCan(action, resource)`, `usePermissionMap(resource, actions, { uiKeys?, fields? }?)`, `useUi(uiKey, resource)`, `useField(name, resource)`, `useAssignments(scope)`, `useRoles(scope?)`, `useModel()`, `useSessionState()`.

Theme: `theme="light" | "dark" | "system"` (default `system`). Override any `--tutela-*` variable on `.tutela`, for example `--tutela-accent`, `--tutela-font`, `--tutela-row`.

Hiding a button is never security: `tutelad` checks every change again, with the narrow-only rule.
