// A fake tutelad for the component tests: a little state, every request
// recorded, and any route made to fail on demand. No network.

import { type Assignment, type RolesAnswer, TutelaClient } from "@f8fvwgzc/tutela-js";
import axe from "axe-core";

export interface Seen {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  json: unknown;
}

export const PROJECT = { type: "project", id: "p-1" };
export const ORG = { type: "org", id: "org_1" };

export const ROLES: RolesAnswer = {
  version: 3,
  roles: [
    {
      key: "owner",
      seeded: "owner",
      levels: { project: "full", invoice: "full" },
      field_levels: {},
      grants: ["project:manage_access"],
      assignable_to: ["user", "sa"],
    },
    {
      key: "reader",
      levels: { project: "read", invoice: "read" },
      field_levels: { "invoice.amount": "write" },
      grants: [],
      assignable_to: ["user", "group"],
    },
    {
      key: "approver",
      label: "Approver",
      levels: { project: "write", invoice: "write" },
      field_levels: { "invoice.amount": "read" },
      grants: ["invoice:approve"],
      assignable_to: ["user", "group"],
    },
  ],
  types: [
    {
      name: "project",
      parents: ["org"],
      container: true,
      starts_private: false,
      fields: [],
      features: [],
      actions: [],
    },
    {
      name: "invoice",
      parents: ["project"],
      container: false,
      starts_private: false,
      fields: [{ name: "amount", sensitivity: "confidential" }],
      features: [],
      actions: ["approve"],
    },
  ],
};

export const MANIFEST = `version = 1
[app]
name = "crm"

[roles.reader]
grants = { project = "read", invoice = "read", "invoice.amount" = "write" }

[roles.approver]
label = "Approver"
grants = { project = "write", invoice = "write", "invoice.amount" = "read", "invoice:approve" = true }
`;

type Override = (req: Seen) => Response | undefined;

export function json(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export function problem(
  status: number,
  code: string,
  detail?: string,
  headers: Record<string, string> = {},
): Response {
  return new Response(
    JSON.stringify({
      type: `urn:tutela:problem:${code}`,
      title: code,
      status,
      ...(detail === undefined ? {} : { detail }),
    }),
    { status, headers: { "content-type": "application/problem+json", ...headers } },
  );
}

/** The fake service. */
export class Fake {
  seen: Seen[] = [];
  assignments: Assignment[] = [
    {
      id: "ra_1",
      subject: "user:usr_alice",
      role: "reader",
      scope: PROJECT,
      granted_by: "user:usr_owner",
    },
    {
      id: "ra_2",
      subject: "group:legal",
      role: "approver",
      scope: PROJECT,
      expires_at: "2027-01-01T00:00:00Z",
    },
  ];
  manage = true;
  rev = 10;
  pageSize: number | undefined;
  twoPerson = false;
  activeVersion = 3;
  impactClass: "narrowing" | "neutral" | "widening" = "widening";
  overrides: Override[] = [];
  n = 0;

  /** Makes the next request that `match` accepts answer `res` (once). */
  once(match: (req: Seen) => boolean, res: () => Response): void {
    let used = false;
    this.overrides.push((req) => {
      if (used || !match(req)) return undefined;
      used = true;
      return res();
    });
  }

  count(method: string, path: string): number {
    return this.seen.filter((s) => s.method === method && s.path === path).length;
  }

  last(method: string, path: string): Seen | undefined {
    return this.seen.filter((s) => s.method === method && s.path === path).at(-1);
  }

  answer(req: Seen): Response {
    for (const o of this.overrides) {
      const r = o(req);
      if (r !== undefined) return r;
    }
    const key = `${req.method} ${req.path}`;
    const body = (req.json ?? {}) as Record<string, unknown>;
    switch (key) {
      case "GET /v1/whoami":
        return json(200, {
          iss: "x",
          tid: "ten_1",
          sub: "user:usr_me",
          kind: "access",
          rev: this.rev,
        });
      case "POST /v1/authz/permissions":
        return json(
          200,
          {
            rev: this.rev,
            ui: {},
            actions: { "project:manage_access": this.manage, "project:read_audit": true },
            fields: {},
          },
          { etag: `"r${this.rev}-${this.manage ? 1 : 0}"` },
        );
      case "POST /v1/admin/assignments/list": {
        const limit = (body.limit as number | undefined) ?? 100;
        const after = body.after as string | undefined;
        const sorted = [...this.assignments].sort((a, b) => (a.id < b.id ? -1 : 1));
        const from = after === undefined ? 0 : sorted.findIndex((a) => a.id > after);
        const page = from < 0 ? [] : sorted.slice(from, from + limit);
        const last = page.at(-1);
        const more = from >= 0 && from + limit < sorted.length;
        return json(200, {
          assignments: page,
          ...(more && last !== undefined ? { next_after: last.id } : {}),
        });
      }
      case "POST /v1/admin/assignments": {
        this.n++;
        this.rev++;
        const a: Assignment = {
          id: `ra_new${this.n}`,
          subject: body.subject as string,
          role: body.role as string,
          scope: body.scope as Assignment["scope"],
          ...(typeof body.expires_at === "string" ? { expires_at: body.expires_at } : {}),
        };
        this.assignments.push(a);
        return json(200, { assignment: a, rev: this.rev });
      }
      case "GET /v1/admin/roles":
        return json(200, ROLES);
      case "GET /v1/models/active":
        return json(200, {
          version: this.activeVersion,
          digest: "d".repeat(64),
          own: true,
          source: MANIFEST,
        });
      case "GET /v1/models/settings":
        return json(200, { two_person: this.twoPerson });
      case "POST /v1/models/impact":
        return json(200, {
          version: this.activeVersion,
          from: "a".repeat(64),
          to: "b".repeat(64),
          class: this.impactClass,
          diff: `${this.impactClass.toUpperCase()} roles.reader`,
          impact: {
            complete: true,
            no_impact: false,
            summary: ["12 users gain read on contract"],
            lines: [],
            omitted_lines: 0,
            digest: "c",
          },
        });
      case "POST /v1/models/publish":
        this.rev++;
        this.activeVersion++;
        return json(200, {
          version: this.activeVersion,
          rev: this.rev,
          digest: "e",
          class: this.impactClass,
          impact: {},
        });
      case "POST /v1/models/proposals":
        return json(200, {
          id: "mpr_1",
          state: "proposed",
          base_version: this.activeVersion,
          from: "a",
          to: "b",
          class: this.impactClass,
          diff: "",
          rev: this.rev,
          proposed_by: "user:usr_me",
        });
    }
    if (req.method === "PATCH" && req.path.startsWith("/v1/admin/assignments/")) {
      const id = decodeURIComponent(req.path.split("/").at(-1) ?? "");
      const a = this.assignments.find((x) => x.id === id);
      if (a === undefined) return problem(404, "not_found");
      if (body.expires_at === null) delete a.expires_at;
      else a.expires_at = body.expires_at as string;
      this.rev++;
      return json(200, { assignment: a, rev: this.rev });
    }
    if (req.method === "DELETE" && req.path.startsWith("/v1/admin/assignments/")) {
      const id = decodeURIComponent(req.path.split("/").at(-1) ?? "");
      this.assignments = this.assignments.filter((x) => x.id !== id);
      this.rev++;
      return json(200, { rev: this.rev });
    }
    return problem(404, "not_found");
  }

  client(): TutelaClient {
    const f = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      const body = typeof init?.body === "string" ? init.body : undefined;
      const req: Seen = {
        method: init?.method ?? "GET",
        path: url.pathname,
        query: url.searchParams,
        headers: new Headers(init?.headers),
        json: body === undefined ? undefined : JSON.parse(body),
      };
      this.seen.push(req);
      return this.answer(req);
    };
    return new TutelaClient({
      baseUrl: "https://tutela.example.test",
      fetch: f as typeof fetch,
      maxRetries: 0,
      auth: { kind: "service", getToken: () => "test-token" },
    });
  }
}

/** axe-core's violations in `node`, by rule id. */
export async function violations(node: Element): Promise<string[]> {
  const r = await axe.run(node, { rules: { "color-contrast": { enabled: false } } });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
}
