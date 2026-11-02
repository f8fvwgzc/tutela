// What the signed-in person may do, from the permission map (CONTRACTS.md
// 7.5): the orgs they can see (a resource search for `org:read`, 7.4) and
// the admin keys they hold at each. Asked again every POLL_MS while the
// page is visible, with the map's ETag, so a change of roles shows within
// the revocation delay (ADR-0052). A UI hint only: every route checks again.

import {
  type ScopeRef,
  type TutelaClient,
  UnauthorizedError,
  type WhoAmI,
} from "@f8fvwgzc/tutela-js";
import { useEffect, useState } from "react";

/** The admin keys of MANIFEST.md 6. */
export const ADMIN_KEYS = [
  "read_audit",
  "manage_access",
  "manage_fields",
  "manage_boundaries",
  "manage_agents",
  "approve_move",
] as const;
export type AdminKey = (typeof ADMIN_KEYS)[number];

export interface OrgAccess {
  org: ScopeRef;
  keys: Record<AdminKey, boolean>;
}

export interface Access {
  loaded: boolean;
  me: WhoAmI | undefined;
  orgs: OrgAccess[];
  /** The last error; the person keeps the last answer meanwhile. */
  error: unknown;
}

/** How often the permission map is asked again, while the page is visible. */
export const POLL_MS = 500;
/** The orgs are searched again every this many polls. */
const SEARCH_EVERY = 20;

const NONE: Access = { loaded: false, me: undefined, orgs: [], error: undefined };

/** Whether `key` is held at any org (`"any"`) or at every org seen (`"every"`). */
export function holds(a: Access, key: AdminKey, mode: "any" | "every"): boolean {
  if (a.orgs.length === 0) return false;
  return mode === "any" ? a.orgs.some((o) => o.keys[key]) : a.orgs.every((o) => o.keys[key]);
}

/** The orgs where any of `keys` is held. */
export function orgsWith(a: Access, ...keys: AdminKey[]): ScopeRef[] {
  return a.orgs.filter((o) => keys.some((k) => o.keys[k])).map((o) => o.org);
}

/** The pages of the rail, and whether the person may open each. */
export type PageKey =
  | "overview"
  | "scopes"
  | "roles"
  | "models"
  | "groups"
  | "people"
  | "apps"
  | "webhooks"
  | "tenant"
  | "explain";

export const PAGES: { key: PageKey; label: string; path: string }[] = [
  { key: "overview", label: "Overview", path: "/console/" },
  { key: "scopes", label: "Scopes", path: "/console/scopes" },
  { key: "roles", label: "Roles", path: "/console/roles" },
  { key: "models", label: "Model history", path: "/console/models" },
  { key: "groups", label: "Groups", path: "/console/groups" },
  { key: "people", label: "People and agents", path: "/console/people" },
  { key: "apps", label: "Apps", path: "/console/apps" },
  { key: "webhooks", label: "Webhooks", path: "/console/webhooks" },
  { key: "tenant", label: "Tenant and orgs", path: "/console/tenant" },
  { key: "explain", label: "Explain and simulate", path: "/console/explain" },
];

/** Which pages the permission map lets the person see (the server decides the rest). */
export function visiblePages(a: Access): Set<PageKey> {
  const every = (k: AdminKey) => holds(a, k, "every");
  const any = (k: AdminKey) => holds(a, k, "any");
  const v = new Set<PageKey>(["overview"]);
  if (any("read_audit") || any("manage_access")) v.add("scopes").add("groups");
  if (every("read_audit")) v.add("roles").add("models").add("tenant");
  if (every("manage_access") || every("manage_agents")) v.add("people");
  if (ADMIN_KEYS.every(every)) v.add("apps");
  if (every("read_audit") && every("manage_access")) v.add("webhooks");
  if (any("read_audit")) v.add("explain");
  return v;
}

function same(a: OrgAccess[], b: OrgAccess[]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

async function searchOrgs(client: TutelaClient, signal: AbortSignal): Promise<ScopeRef[]> {
  const found: ScopeRef[] = [];
  for await (const r of client.searchResources({ type: "org", action: "org:read" }, { signal })) {
    found.push(r);
    if (found.length >= 50) break;
  }
  return found;
}

async function keysAt(
  client: TutelaClient,
  org: ScopeRef,
  signal: AbortSignal,
): Promise<OrgAccess> {
  const map = await client.permissions(
    { resource: { ...org, path: [] }, actions: ADMIN_KEYS.map((k) => `org:${k}`) },
    { signal },
  );
  const keys = Object.fromEntries(ADMIN_KEYS.map((k) => [k, map.can(`org:${k}`)])) as Record<
    AdminKey,
    boolean
  >;
  return { org, keys };
}

/**
 * The person's access, kept fresh. `onSignedOut` runs when `tutelad`
 * refuses the session (a revoked session, a disabled person).
 */
export function useAccess(client: TutelaClient, onSignedOut: () => void, pollMs = POLL_MS): Access {
  const [access, setAccess] = useState<Access>(NONE);
  useEffect(() => {
    const ctl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let orgs: ScopeRef[] = [];
    let held: OrgAccess[] = [];
    let me: WhoAmI | undefined;
    let n = 0;
    const tick = async () => {
      try {
        if (me === undefined) me = await client.whoami({ signal: ctl.signal });
        if (n % SEARCH_EVERY === 0) orgs = await searchOrgs(client, ctl.signal);
        const next = await Promise.all(orgs.map((o) => keysAt(client, o, ctl.signal)));
        if (!same(next, held) || n === 0) {
          held = next;
          setAccess({ loaded: true, me, orgs: next, error: undefined });
        }
      } catch (error) {
        if (ctl.signal.aborted) return;
        if (error instanceof UnauthorizedError) {
          onSignedOut();
          return;
        }
        setAccess((a) => ({ ...a, loaded: true, me: me ?? a.me, error }));
      }
      n++;
      schedule();
    };
    const schedule = () => {
      if (ctl.signal.aborted) return;
      timer = setTimeout(
        () => {
          if (document.visibilityState === "hidden") schedule();
          else void tick();
        },
        n === 0 ? 0 : pollMs,
      );
    };
    schedule();
    return () => {
      ctl.abort();
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [client, onSignedOut, pollMs]);
  return access;
}
