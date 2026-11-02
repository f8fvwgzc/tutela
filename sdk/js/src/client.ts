/**
 * The typed client of `tutelad`: every route of the ROADMAP's "Every route
 * the Console calls" (CONTRACTS.md 7.5, 7.9, 7.10, 7.13).
 *
 * - The tenant always comes from the token; no call names one.
 * - Principals go in JSON bodies, never in a URL (CONTRACTS.md 9.5).
 * - A write's `rev` is kept, and sent as `at_least_revision` on the next
 *   check, so a page shows its own write (CONTRACTS.md 7.1).
 * - A 503 is retried, at most `maxRetries` times and only after
 *   `Retry-After`, for a call that is safe to send again; a call that would
 *   make something twice (an app, a webhook, an agent, an org, a proposal)
 *   is never retried by itself.
 */

import {
  BrowserSession,
  type BrowserSessionOptions,
  serviceAuth,
  type TokenAudience,
  type TokenSource,
} from "./auth.js";
import { UnauthorizedError } from "./errors.js";
import { type Answer, type Call, Transport, type TransportOptions } from "./http.js";
import { PermissionMap, PermissionStore } from "./permissions.js";
import type {
  ActiveModel,
  AgentsPage,
  App,
  AppWithSecret,
  Assignment,
  AssignmentChange,
  AssignmentsPage,
  CheckSubject,
  DeliveriesPage,
  Delivery,
  EvaluationBody,
  Group,
  GroupsPage,
  MembersPage,
  ModelChange,
  ModelChangeBody,
  ModelSettings,
  ModelVersion,
  ModelVersions,
  Org,
  PermissionMapAnswer,
  PermissionQuery,
  PrincipalState,
  Proposal,
  PublishResult,
  RevAnswer,
  RolesAnswer,
  Scope,
  ScopeChange,
  ScopeRef,
  ScopesPage,
  SearchResourceAnswer,
  SimulateCandidate,
  SubjectString,
  Tenant,
  Webhook,
  WebhookWithSecret,
  WhoAmI,
} from "./types.js";

/** How the client authenticates: one of the two. */
export type ClientAuth =
  /** A person in a browser: the token flow of the ROADMAP notes for part 4b. */
  | ({ kind: "browser" } & BrowserSessionOptions)
  /** A pipeline or a core: its own service token, for every route. */
  | { kind: "service"; getToken: (audience: TokenAudience) => string | Promise<string> }
  /** Any other {@link TokenSource}. */
  | { kind: "custom"; source: TokenSource };

/** The client's options. */
export interface TutelaClientOptions extends TransportOptions {
  auth: ClientAuth;
}

/** Options of one call. */
export interface CallOptions {
  signal?: AbortSignal;
}

/** A page query: `after` is the `next_after` of the page before. */
export interface PageQuery {
  after?: string;
  /** At most 1000; the server's default is 100. */
  limit?: number;
}

/** `scope` given as `{type, id}`, sent as `type:id` in a query. */
function scopeText(s: ScopeRef): string {
  return `${s.type}:${s.id}`;
}

function seg(s: string): string {
  return encodeURIComponent(s);
}

/** Walks the pages of a list, item by item. */
async function* walk<P, T>(
  first: string | undefined,
  page: (after: string | undefined) => Promise<P>,
  items: (p: P) => T[],
  next: (p: P) => string | undefined,
): AsyncGenerator<T, void, undefined> {
  let after = first;
  const seen = new Set<string>();
  for (;;) {
    const p = await page(after);
    yield* items(p);
    after = next(p);
    // A cursor that does not move would loop for ever.
    if (after === undefined || seen.has(after)) return;
    seen.add(after);
  }
}

/** The client of `tutelad`. */
export class TutelaClient {
  readonly #http: Transport;
  readonly #tokens: TokenSource;
  /** The browser session, when `auth.kind` is `browser`. */
  readonly session: BrowserSession | undefined;
  /** The permission maps this client has loaded. */
  readonly permissionStore = new PermissionStore();
  #rev = 0;
  #self: CheckSubject | undefined;
  readonly #etags = new Map<string, { etag: string; map: PermissionMap }>();
  readonly #revListeners = new Set<(rev: number) => void>();

  constructor(o: TutelaClientOptions) {
    this.#http = new Transport(o);
    switch (o.auth.kind) {
      case "browser":
        this.session = new BrowserSession(this.#http, o.auth);
        this.#tokens = this.session;
        break;
      case "service":
        this.session = undefined;
        this.#tokens = serviceAuth(o.auth.getToken);
        break;
      case "custom":
        this.session = undefined;
        this.#tokens = o.auth.source;
        break;
    }
  }

  /** The highest revision a write of this client answered (0: none yet). */
  get revision(): number {
    return this.#rev;
  }

  /** Keeps `rev` if it is newer, so the next check is at least that new. */
  observeRevision(rev: number | undefined): void {
    if (typeof rev === "number" && rev > this.#rev) {
      this.#rev = rev;
      for (const l of this.#revListeners) l(rev);
    }
  }

  /** Calls `listener` when a write moves {@link revision}. Returns an unsubscribe. */
  onRevision(listener: (rev: number) => void): () => void {
    this.#revListeners.add(listener);
    return () => this.#revListeners.delete(listener);
  }

  /**
   * One call with a token of `audience`. A 401 drops the token and tries
   * once more with a new one, when the token source can get one.
   */
  async #call(audience: TokenAudience, c: Omit<Call, "token">, o?: CallOptions): Promise<Answer> {
    const signal = o?.signal ?? c.signal;
    const call: Call = { ...c, ...(signal === undefined ? {} : { signal }) };
    for (let attempt = 0; ; attempt++) {
      const token = await this.#tokens.token(audience, signal);
      try {
        return await this.#http.send({ ...call, token });
      } catch (e) {
        if (
          e instanceof UnauthorizedError &&
          attempt === 0 &&
          this.#tokens.rejected(audience, token)
        ) {
          continue;
        }
        throw e;
      }
    }
  }

  async #admin<T>(c: Omit<Call, "token">, o?: CallOptions): Promise<T> {
    const a = await this.#call("admin", c, o);
    const body = a.body as T;
    const rev = (body as { rev?: unknown } | undefined)?.rev;
    if (c.method !== "GET" && typeof rev === "number") this.observeRevision(rev);
    return body;
  }

  // ---------- Who am I, and the permission map (7.5, 7.7) ----------

  /** `GET /v1/whoami`, with the `tutela-authz` token. */
  async whoami(o?: CallOptions): Promise<WhoAmI> {
    const a = await this.#call("authz", { method: "GET", path: "/v1/whoami", retry: true }, o);
    return a.body as WhoAmI;
  }

  /** The caller as a check subject, from `GET /v1/whoami` (asked once). */
  async self(o?: CallOptions): Promise<CheckSubject> {
    if (this.#self === undefined) {
      const me = await this.whoami(o);
      this.#self = { type: me.sub.split(":")[0] ?? "user", id: me.sub };
    }
    return this.#self;
  }

  /**
   * `POST /v1/authz/permissions` for one resource, with the `tutela-authz`
   * token: by default for the caller itself, at least as new as this
   * client's last write. A 304 gives back the map it had; the answer is
   * kept in {@link permissionStore}.
   */
  async permissions(q: PermissionQuery, o?: CallOptions): Promise<PermissionMap> {
    const subject = q.subject ?? (await this.self(o));
    const ask = {
      subject,
      resource: q.resource,
      ui_keys: q.uiKeys ?? [],
      ...(q.actions === undefined ? {} : { actions: q.actions }),
      ...(q.fields === undefined ? {} : { fields: q.fields }),
    };
    const key = JSON.stringify(ask);
    const cached = this.#etags.get(key);
    const at = this.#rev;
    const body = at > 0 ? { ...ask, at_least_revision: at } : ask;
    const a = await this.#call(
      "authz",
      {
        method: "POST",
        path: "/v1/authz/permissions",
        json: body,
        retry: true,
        ...(cached === undefined ? {} : { headers: { "if-none-match": cached.etag } }),
      },
      o,
    );
    let map: PermissionMap;
    if (a.status === 304 && cached !== undefined) {
      map = cached.map;
    } else {
      map = new PermissionMap(a.body as PermissionMapAnswer);
      const etag = a.headers.get("etag");
      if (etag !== null) this.#etags.set(key, { etag, map });
    }
    this.permissionStore.set(q.resource, map);
    return map;
  }

  /**
   * `POST /access/v1/search/resource` (CONTRACTS.md 7.4), with the
   * `tutela-authz` token: the registered scopes of `type` where the caller
   * (or `subject`) may do `action`, page by page. A UI uses it to find the
   * orgs and scopes a person can reach before it may list them.
   */
  async *searchResources(
    q: { type: string; action: string; subject?: CheckSubject; limit?: number },
    o?: CallOptions,
  ): AsyncGenerator<ScopeRef, void, undefined> {
    const subject = q.subject ?? (await this.self(o));
    const seen = new Set<string>();
    let token = "";
    for (;;) {
      const body = {
        subject,
        action: { name: q.action },
        resource: { type: q.type },
        page: { token, limit: q.limit ?? 100 },
        ...(this.#rev > 0 ? { context: { at_least_revision: this.#rev } } : {}),
      };
      const a = await this.#call(
        "authz",
        { method: "POST", path: "/access/v1/search/resource", json: body, retry: true },
        o,
      );
      const r = a.body as SearchResourceAnswer;
      yield* r.results;
      token = r.page?.next_token ?? "";
      // A token that does not move would loop for ever.
      if (token === "" || seen.has(token)) return;
      seen.add(token);
    }
  }

  /** `true` when a loaded map allows `action` on `resource` (see {@link permissionStore}). */
  can(action: string, resource: ScopeRef): boolean {
    return this.permissionStore.can(action, resource);
  }

  /** `POST /v1/authz/explain` (needs `read_audit` on the resource). */
  async explain(body: EvaluationBody, o?: CallOptions): Promise<unknown> {
    return this.#admin(
      { method: "POST", path: "/v1/authz/explain", json: this.#atLeast(body), retry: true },
      o,
    );
  }

  /** `POST /v1/authz/simulate`: nothing is written. */
  async simulate(
    body: EvaluationBody,
    candidate: SimulateCandidate,
    o?: CallOptions,
  ): Promise<unknown> {
    return this.#admin(
      {
        method: "POST",
        path: "/v1/authz/simulate",
        json: { ...this.#atLeast(body), candidate },
        retry: true,
      },
      o,
    );
  }

  #atLeast(body: EvaluationBody): EvaluationBody {
    if (this.#rev === 0) return body;
    return { ...body, context: { ...body.context, at_least_revision: this.#rev } };
  }

  // ---------- The tenant and its orgs (7.13.5) ----------

  readonly tenant = {
    get: (o?: CallOptions) =>
      this.#admin<Tenant>({ method: "GET", path: "/v1/admin/tenant", retry: true }, o),
    rename: (name: string | null, o?: CallOptions) =>
      this.#admin<Tenant>(
        { method: "PATCH", path: "/v1/admin/tenant", json: { name }, retry: true },
        o,
      ),
    /** Soft delete: answers the tenant with `purge_after`. */
    delete: (o?: CallOptions) =>
      this.#admin<Tenant>({ method: "DELETE", path: "/v1/admin/tenant", retry: true }, o),
  };

  readonly orgs = {
    list: async (o?: CallOptions) =>
      (
        await this.#admin<{ orgs: Org[] }>(
          { method: "GET", path: "/v1/admin/orgs", retry: true },
          o,
        )
      ).orgs,
    /** Never retried by itself: a lost answer could make two. */
    create: (name?: string, o?: CallOptions) =>
      this.#admin<Org>(
        {
          method: "POST",
          path: "/v1/admin/orgs",
          json: name === undefined ? {} : { name },
          retry: false,
        },
        o,
      ),
    rename: (org: string, name: string | null, o?: CallOptions) =>
      this.#admin<Org>(
        { method: "PATCH", path: `/v1/admin/orgs/${seg(org)}`, json: { name }, retry: true },
        o,
      ),
    delete: (org: string, o?: CallOptions) =>
      this.#admin<Org>({ method: "DELETE", path: `/v1/admin/orgs/${seg(org)}`, retry: true }, o),
    restore: (org: string, o?: CallOptions) =>
      this.#admin<Org>(
        { method: "POST", path: `/v1/admin/orgs/${seg(org)}/restore`, retry: true },
        o,
      ),
  };

  // ---------- Scopes (7.13.2, 7.13.7) ----------

  readonly scopes = {
    /** One page of the registered scopes below `under` (an org or a scope). */
    page: (q: { under: ScopeRef } & PageQuery, o?: CallOptions) =>
      this.#admin<ScopesPage>(
        {
          method: "GET",
          path: "/v1/admin/scopes",
          query: { under: scopeText(q.under), after: q.after, limit: q.limit },
          retry: true,
        },
        o,
      ),
    /** Every scope below `under`, page by page. */
    list: (q: { under: ScopeRef } & PageQuery, o?: CallOptions): AsyncGenerator<Scope> =>
      walk(
        q.after,
        (after) => this.scopes.page({ ...q, ...(after === undefined ? {} : { after }) }, o),
        (p) => p.scopes,
        (p) => p.next_after,
      ),
    register: (b: { scope: ScopeRef; parent: ScopeRef; private?: boolean }, o?: CallOptions) =>
      this.#admin<ScopeChange>(
        { method: "POST", path: "/v1/admin/scopes", json: b, retry: true },
        o,
      ),
    /** Behind `write_check`'s move verdict: 403 `move_refused` when it refuses or waits. */
    move: (b: { scope: ScopeRef; parent: ScopeRef; approved_by?: string[] }, o?: CallOptions) =>
      this.#admin<ScopeChange>(
        { method: "POST", path: "/v1/admin/scopes/move", json: b, retry: true },
        o,
      ),
    delete: (scope: ScopeRef, o?: CallOptions) =>
      this.#admin<RevAnswer>(
        { method: "POST", path: "/v1/admin/scopes/delete", json: { scope }, retry: true },
        o,
      ),
    setPrivate: (scope: ScopeRef, isPrivate: boolean, o?: CallOptions) =>
      this.#admin<RevAnswer>(
        {
          method: "PUT",
          path: "/v1/admin/scopes/private",
          json: { scope, private: isPrivate },
          retry: true,
        },
        o,
      ),
    setBoundary: (
      b: Pick<Scope, "scope" | "moves_out" | "moves_in" | "on_looser" | "links_from">,
      o?: CallOptions,
    ) =>
      this.#admin<RevAnswer>(
        { method: "PUT", path: "/v1/admin/boundaries", json: b, retry: true },
        o,
      ),
  };

  // ---------- Role assignments (7.13.7) ----------

  readonly assignments = {
    /** One page, by `scope` or by `subject` (sent in the body, never the URL). */
    page: (q: ({ scope: ScopeRef } | { subject: SubjectString }) & PageQuery, o?: CallOptions) =>
      this.#admin<AssignmentsPage>(
        { method: "POST", path: "/v1/admin/assignments/list", json: q, retry: true },
        o,
      ),
    /** Every assignment that still counts, page by page. */
    list: (
      q: ({ scope: ScopeRef } | { subject: SubjectString }) & PageQuery,
      o?: CallOptions,
    ): AsyncGenerator<Assignment> =>
      walk(
        q.after,
        (after) => this.assignments.page({ ...q, ...(after === undefined ? {} : { after }) }, o),
        (p) => p.assignments,
        (p) => p.next_after,
      ),
    /** Gives `role` at `scope`, until `expires_at` (RFC 3339) if set. */
    assign: (
      b: { subject: SubjectString; role: string; scope: ScopeRef; expires_at?: string },
      o?: CallOptions,
    ) =>
      this.#admin<AssignmentChange>(
        { method: "POST", path: "/v1/admin/assignments", json: b, retry: true },
        o,
      ),
    /** A new end, or `null` for none. A later end is checked as a new grant. */
    setExpiry: (id: string, expiresAt: string | null, o?: CallOptions) =>
      this.#admin<AssignmentChange>(
        {
          method: "PATCH",
          path: `/v1/admin/assignments/${seg(id)}`,
          json: { expires_at: expiresAt },
          retry: true,
        },
        o,
      ),
    unassign: (id: string, o?: CallOptions) =>
      this.#admin<RevAnswer>(
        { method: "DELETE", path: `/v1/admin/assignments/${seg(id)}`, retry: true },
        o,
      ),
  };

  // ---------- Groups (7.13.7) ----------

  readonly groups = {
    page: (q: { org?: string } & PageQuery = {}, o?: CallOptions) =>
      this.#admin<GroupsPage>(
        {
          method: "GET",
          path: "/v1/admin/groups",
          query: { org: q.org, after: q.after, limit: q.limit },
          retry: true,
        },
        o,
      ),
    list: (q: { org?: string } & PageQuery = {}, o?: CallOptions): AsyncGenerator<Group> =>
      walk(
        q.after,
        (after) => this.groups.page({ ...q, ...(after === undefined ? {} : { after }) }, o),
        (p) => p.groups,
        (p) => p.next_after,
      ),
    create: (b: { org: string; key: string; name: string }, o?: CallOptions) =>
      this.#admin<Group>({ method: "POST", path: "/v1/admin/groups", json: b, retry: true }, o),
    delete: (key: string, o?: CallOptions) =>
      this.#admin<RevAnswer>(
        { method: "DELETE", path: `/v1/admin/groups/${seg(key)}`, retry: true },
        o,
      ),
    membersPage: (key: string, q: PageQuery = {}, o?: CallOptions) =>
      this.#admin<MembersPage>(
        {
          method: "GET",
          path: `/v1/admin/groups/${seg(key)}/members`,
          query: { after: q.after, limit: q.limit },
          retry: true,
        },
        o,
      ),
    members: (key: string, q: PageQuery = {}, o?: CallOptions): AsyncGenerator<SubjectString> =>
      walk(
        q.after,
        (after) =>
          this.groups.membersPage(key, { ...q, ...(after === undefined ? {} : { after }) }, o),
        (p) => p.members,
        (p) => p.next_after,
      ),
    addMember: (key: string, member: SubjectString, o?: CallOptions) =>
      this.#admin<RevAnswer>(
        {
          method: "POST",
          path: `/v1/admin/groups/${seg(key)}/members`,
          json: { member },
          retry: true,
        },
        o,
      ),
    removeMember: (key: string, member: SubjectString, o?: CallOptions) =>
      this.#admin<RevAnswer>(
        {
          method: "POST",
          path: `/v1/admin/groups/${seg(key)}/members/remove`,
          json: { member },
          retry: true,
        },
        o,
      ),
  };

  // ---------- Roles: the permission matrix (7.13.7) ----------

  /** `GET /v1/admin/roles[?scope=]`: the active model's roles and types. */
  roles(scope?: ScopeRef, o?: CallOptions): Promise<RolesAnswer> {
    return this.#admin<RolesAnswer>(
      {
        method: "GET",
        path: "/v1/admin/roles",
        query: { scope: scope === undefined ? undefined : scopeText(scope) },
        retry: true,
      },
      o,
    );
  }

  // ---------- Model versions (7.9) ----------

  readonly models = {
    versions: (q: { before?: number; limit?: number } = {}, o?: CallOptions) =>
      this.#admin<ModelVersions>(
        {
          method: "GET",
          path: "/v1/models",
          query: { before: q.before, limit: q.limit },
          retry: true,
        },
        o,
      ),
    version: (version: number, o?: CallOptions) =>
      this.#admin<ModelVersion>({ method: "GET", path: `/v1/models/${version}`, retry: true }, o),
    /** The model the tenant runs on now, with its text: where a change starts. */
    active: (o?: CallOptions) =>
      this.#admin<ActiveModel>({ method: "GET", path: "/v1/models/active", retry: true }, o),
    /** A dry run: the diff and the impact report. Nothing is written. */
    impact: (b: ModelChangeBody, o?: CallOptions) =>
      this.#admin<ModelChange>(
        { method: "POST", path: "/v1/models/impact", json: b, retry: true },
        o,
      ),
    /** With `expected_version` (409 on a race) and an approval token when it widens. */
    publish: (b: ModelChangeBody, o?: CallOptions) =>
      this.#admin<PublishResult>(
        { method: "POST", path: "/v1/models/publish", json: b, retry: true },
        o,
      ),
    settings: (o?: CallOptions) =>
      this.#admin<ModelSettings>({ method: "GET", path: "/v1/models/settings", retry: true }, o),
    putSettings: (twoPerson: boolean, o?: CallOptions) =>
      this.#admin<ModelSettings>(
        {
          method: "PUT",
          path: "/v1/models/settings",
          json: { two_person: twoPerson },
          retry: true,
        },
        o,
      ),
    /** Never retried by itself: a lost answer could make two proposals. */
    propose: (b: Omit<ModelChangeBody, "approval">, o?: CallOptions) =>
      this.#admin<Proposal>(
        { method: "POST", path: "/v1/models/proposals", json: b, retry: false },
        o,
      ),
    proposals: async (o?: CallOptions) => {
      const a = await this.#admin<{ proposals: Proposal[] } | Proposal[]>(
        { method: "GET", path: "/v1/models/proposals", retry: true },
        o,
      );
      return Array.isArray(a) ? a : a.proposals;
    },
    proposal: (id: string, o?: CallOptions) =>
      this.#admin<Proposal>(
        { method: "GET", path: `/v1/models/proposals/${seg(id)}`, retry: true },
        o,
      ),
    approve: (id: string, approval?: string, o?: CallOptions) =>
      this.#admin<PublishResult>(
        {
          method: "POST",
          path: `/v1/models/proposals/${seg(id)}/approve`,
          json: approval === undefined ? {} : { approval },
          retry: true,
        },
        o,
      ),
    reject: (id: string, o?: CallOptions) =>
      this.#admin<Proposal>(
        { method: "POST", path: `/v1/models/proposals/${seg(id)}/reject`, retry: true },
        o,
      ),
  };

  // ---------- People and agents (7.13.1, 7.13.5) ----------

  readonly principals = {
    state: (principal: string, o?: CallOptions) =>
      this.#admin<PrincipalState>(
        { method: "POST", path: "/v1/admin/principals/state", json: { principal }, retry: true },
        o,
      ),
    setDisabled: (principal: string, disabled: boolean, o?: CallOptions) =>
      this.#admin<PrincipalState>(
        {
          method: "POST",
          path: "/v1/admin/principals/disabled",
          json: { principal, disabled },
          retry: true,
        },
        o,
      ),
    revokeSessions: (principal: string, o?: CallOptions) =>
      this.#admin<PrincipalState>(
        {
          method: "POST",
          path: "/v1/admin/principals/revoke-sessions",
          json: { principal },
          retry: true,
        },
        o,
      ),
    /** Deletes a person for good (ADR-0041 item 7). */
    deleteUser: (principal: string, o?: CallOptions) =>
      this.#admin<PrincipalState>(
        { method: "POST", path: "/v1/admin/users/delete", json: { principal }, retry: true },
        o,
      ),
  };

  readonly agents = {
    page: (q: { workload?: string } & PageQuery = {}, o?: CallOptions) =>
      this.#admin<AgentsPage>(
        {
          method: "GET",
          path: "/v1/admin/agents",
          query: { after: q.after, limit: q.limit, workload: q.workload },
          retry: true,
        },
        o,
      ),
    list: (
      q: { workload?: string } & PageQuery = {},
      o?: CallOptions,
    ): AsyncGenerator<PrincipalState> =>
      walk(
        q.after,
        (after) => this.agents.page({ ...q, ...(after === undefined ? {} : { after }) }, o),
        (p) => p.agents,
        (p) => p.next_after,
      ),
    /** Never retried by itself; find a lost one again with `page({workload})`. */
    register: (workload?: string, o?: CallOptions) =>
      this.#admin<PrincipalState>(
        {
          method: "POST",
          path: "/v1/admin/agents",
          json: workload === undefined ? {} : { workload },
          retry: false,
        },
        o,
      ),
  };

  // ---------- Apps (7.13.8) ----------

  readonly apps = {
    list: async (o?: CallOptions) =>
      (
        await this.#admin<{ apps: App[] }>(
          { method: "GET", path: "/v1/admin/apps", retry: true },
          o,
        )
      ).apps,
    /** The client secret is in this answer only. Never retried by itself. */
    create: (name: string, o?: CallOptions) =>
      this.#admin<AppWithSecret>(
        { method: "POST", path: "/v1/admin/apps", json: { name }, retry: false },
        o,
      ),
    /** The new secret is in this answer only. Never retried by itself. */
    rotate: (id: string, overlapSecs?: number, o?: CallOptions) =>
      this.#admin<AppWithSecret>(
        {
          method: "POST",
          path: `/v1/admin/apps/${seg(id)}/rotate`,
          json: overlapSecs === undefined ? {} : { overlap_secs: overlapSecs },
          retry: false,
        },
        o,
      ),
    disable: (id: string, o?: CallOptions) =>
      this.#admin<App>(
        { method: "POST", path: `/v1/admin/apps/${seg(id)}/disable`, retry: true },
        o,
      ),
  };

  // ---------- Webhooks (7.13.6) ----------

  readonly webhooks = {
    list: async (o?: CallOptions) =>
      (
        await this.#admin<{ webhooks: Webhook[] }>(
          { method: "GET", path: "/v1/admin/webhooks", retry: true },
          o,
        )
      ).webhooks,
    /** The secret is in this answer only. Never retried by itself. */
    register: (b: { url: string; types?: string[] }, o?: CallOptions) =>
      this.#admin<WebhookWithSecret>(
        { method: "POST", path: "/v1/admin/webhooks", json: b, retry: false },
        o,
      ),
    rotate: (id: string, overlapSecs?: number, o?: CallOptions) =>
      this.#admin<WebhookWithSecret>(
        {
          method: "POST",
          path: `/v1/admin/webhooks/${seg(id)}/rotate`,
          json: overlapSecs === undefined ? {} : { overlap_secs: overlapSecs },
          retry: false,
        },
        o,
      ),
    disable: (id: string, o?: CallOptions) =>
      this.#admin<Webhook>(
        { method: "POST", path: `/v1/admin/webhooks/${seg(id)}/disable`, retry: true },
        o,
      ),
    deliveries: (
      id: string,
      q: { state?: "dead"; after?: number; limit?: number } = {},
      o?: CallOptions,
    ) =>
      this.#admin<DeliveriesPage>(
        {
          method: "GET",
          path: `/v1/admin/webhooks/${seg(id)}/deliveries`,
          query: { state: q.state, after: q.after, limit: q.limit },
          retry: true,
        },
        o,
      ),
    redeliver: (id: string, seq: number, o?: CallOptions) =>
      this.#admin<Delivery>(
        {
          method: "POST",
          path: `/v1/admin/webhooks/${seg(id)}/deliveries/${seq}/redeliver`,
          retry: true,
        },
        o,
      ),
  };
}
