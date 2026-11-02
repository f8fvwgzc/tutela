/**
 * The JSON shapes of `tutelad`'s API, as CONTRACTS.md 4.8, 7.5, 7.9, 7.10
 * and 7.13 give them. Wire names are kept (`next_after`, `expires_at`), so a
 * value can be compared with the docs as it is.
 *
 * A `?` field may be missing from an answer. Fields added later in `v1`
 * (CONTRACTS.md 10.2) are passed through untouched.
 */

/** A level (CONTRACTS.md 3). */
export type Level = "none" | "read" | "write" | "full";

/** The order of the levels, lowest first. */
export const LEVELS: readonly Level[] = ["none", "read", "write", "full"];

/** The six admin keys (MANIFEST.md 6). */
export const ADMIN_KEYS = [
  "manage_access",
  "manage_fields",
  "manage_boundaries",
  "manage_agents",
  "approve_move",
  "read_audit",
] as const;

/** One of the six admin keys. */
export type AdminKey = (typeof ADMIN_KEYS)[number];

/** A scope or a resource: `{type, id}`. An org is `{type: "org", id: "org_…"}`. */
export interface ScopeRef {
  type: string;
  id: string;
}

/** A principal string (`user:usr_…`, `sa:sa_…`, `agent:agt_…`) or `group:<key>`. */
export type SubjectString = string;

// ---------- Scopes, role assignments and groups (CONTRACTS.md 7.13.7) ----------

/** A registered scope. */
export interface Scope {
  scope: ScopeRef;
  /** Nearest first; the last is the org. */
  ancestors: ScopeRef[];
  private: boolean;
  moves_out?: "members" | "owners" | "none";
  moves_in?: "members" | "owners" | "none";
  on_looser?: "approve" | "block";
  links_from?: "any" | "team" | "none";
}

/** A role assignment that still counts. */
export interface Assignment {
  id: string;
  subject: SubjectString;
  role: string;
  scope: ScopeRef;
  granted_by?: string;
  /** RFC 3339. */
  created_at?: string;
  /** RFC 3339; missing: no end. */
  expires_at?: string;
}

/** A group of one org. */
export interface Group {
  key: string;
  org: string;
  name: string;
  created_at?: string;
  /** The number of direct members, in a list. */
  members?: number;
  rev?: number;
}

/** A role of the active model, a row of the permission matrix. */
export interface Role {
  key: string;
  label?: string;
  /** For a seeded role (MANIFEST.md 5.1): which one. */
  seeded?: string;
  /** The item level per type; a type left out is `none`. */
  levels: Record<string, Level>;
  /** `"type.field"` (or `"type.@feature"`) to a level; left out: the item level. */
  field_levels: Record<string, Level>;
  /** Custom-action grants and admin keys: `"type:action"`. */
  grants: string[];
  assignable_to: string[];
}

/** A field of a type. */
export interface TypeField {
  name: string;
  sensitivity: "public" | "internal" | "confidential" | "secret";
  label?: string;
}

/** A type of the active model, a column of the permission matrix. */
export interface ResourceTypeInfo {
  name: string;
  label?: string;
  parents: string[];
  container: boolean;
  starts_private: boolean;
  fields: TypeField[];
  /** Feature names with their `@`. */
  features: string[];
  /** Custom actions. */
  actions: string[];
}

/** `GET /v1/admin/roles`. */
export interface RolesAnswer {
  version: number;
  roles: Role[];
  types: ResourceTypeInfo[];
}

/** `GET /v1/admin/scopes`: a page. Pass `next_after` back as `after`. */
export interface ScopesPage {
  scopes: Scope[];
  next_after?: string;
}

/** `POST /v1/admin/assignments/list`: a page. */
export interface AssignmentsPage {
  assignments: Assignment[];
  next_after?: string;
}

/** `GET /v1/admin/groups`: a page. */
export interface GroupsPage {
  groups: Group[];
  next_after?: string;
}

/** `GET /v1/admin/groups/{key}/members`: a page of `user:usr_…` and `group:<key>`. */
export interface MembersPage {
  members: SubjectString[];
  next_after?: string;
}

/** `GET /v1/admin/agents`: a page. */
export interface AgentsPage {
  agents: PrincipalState[];
  next_after?: string;
}

/** `GET /v1/admin/webhooks/{id}/deliveries`: a page; `next_after` is an event number. */
export interface DeliveriesPage {
  deliveries: Delivery[];
  next_after?: number;
}

/** The answer of a write that bumps the revision. */
export interface RevAnswer {
  rev: number;
}

/** `POST /v1/admin/assignments`, `PATCH /v1/admin/assignments/{id}`. */
export interface AssignmentChange {
  assignment?: Assignment;
  rev: number;
}

/** `POST /v1/admin/scopes`, `POST /v1/admin/scopes/move`. */
export interface ScopeChange {
  scope: Scope;
  rev: number;
}

// ---------- People, agents, the tenant and its orgs (7.13.1, 7.13.5) ----------

/** A principal's state. */
export interface PrincipalState {
  principal: string;
  epoch: number;
  disabled: boolean;
  workload?: string;
  rev?: number;
}

/** The tenant. */
export interface Tenant {
  tid: string;
  iss: string;
  name?: string;
  created_at?: string;
  purge_after?: string;
}

/** An org. */
export interface Org {
  org: string;
  name?: string;
  created_at?: string;
  deleted_at?: string;
  purge_after?: string;
  purged_at?: string;
  rev?: number;
}

// ---------- Apps and webhooks (7.13.6, 7.13.8) ----------

/** An app. Never a secret. */
export interface App {
  client_id: string;
  name: string;
  principal: string;
  created_by: string;
  created_at?: string;
  disabled_at?: string;
}

/** An app with its client secret, shown this once. */
export interface AppWithSecret {
  app: App;
  client_secret: string;
}

/** A webhook. Never a secret. */
export interface Webhook {
  id: string;
  url: string;
  types: string[];
  disabled: boolean;
  created_by: string;
}

/** A webhook with its secret, shown this once. */
export interface WebhookWithSecret {
  webhook: Webhook;
  secret: string;
}

/** A delivery of an event to a webhook. */
export interface Delivery {
  webhook: string;
  seq: number;
  state: "pending" | "delivered" | "dead";
  attempts: number;
  last_status?: number;
  last_error?: string;
}

// ---------- Model versions (7.9) ----------

/** One line of an impact report. */
export interface ImpactLine {
  change: "gain" | "lose";
  kind: string;
  key: string;
  from: Level | "allowed" | "denied";
  to: Level | "allowed" | "denied";
  conditional: boolean;
  count: number;
  scopes: number;
  examples: string[];
}

/** An impact report (ADR-0027). */
export interface Impact {
  complete: boolean;
  no_impact: boolean;
  /** Plain sentences: "12 users gain read on contract.budget in 3 scopes". */
  summary: string[];
  lines: ImpactLine[];
  omitted_lines: number;
  digest: string;
}

/** `POST /v1/models/impact`. */
export interface ModelChange {
  version: number;
  from: string;
  to: string;
  class: "narrowing" | "neutral" | "widening";
  diff: string;
  impact: Impact;
}

/** `POST /v1/models/publish`, and an approved proposal. */
export interface PublishResult {
  version: number;
  rev: number;
  digest: string;
  class: "narrowing" | "neutral" | "widening";
  restores?: number;
  impact: Impact;
}

/** A model version. `source` only from `GET /v1/models/{version}`. */
export interface ModelVersion {
  version: number;
  rev: number;
  digest: string;
  class: string;
  diff: string;
  author?: string;
  approvers: string[];
  origin: string;
  restores?: number;
  published_at?: string;
  impact?: Impact;
  source?: string;
}

/** `GET /v1/models`. */
export interface ModelVersions {
  active: { version: number; digest: string; own: boolean };
  versions: ModelVersion[];
  next_before?: number;
}

/** `GET /v1/models/active`: the model the tenant runs on, with its text. */
export interface ActiveModel {
  /** The newest version; 0 while the tenant follows the app's manifest. */
  version: number;
  digest: string;
  own: boolean;
  source: string;
}

/** `GET`/`PUT /v1/models/settings`. */
export interface ModelSettings {
  two_person: boolean;
  off_requested_by?: string;
}

/** A proposal (two-person publish, ADR-0029). */
export interface Proposal {
  id: string;
  state: "proposed" | "published" | "rejected" | "stale";
  base_version: number;
  from: string;
  to: string;
  restores?: number;
  class: string;
  diff: string;
  impact?: Impact | null;
  rev: number;
  proposed_by: string;
  decided_by?: string;
  version?: number;
  created_at?: string;
  decided_at?: string;
  source?: string;
}

/** The body of a publish, an impact report or a proposal. */
export type ModelChangeBody = (
  | { source: string; restore?: never }
  | { restore: number; source?: never }
) & {
  expected_version?: number;
  approval?: string;
};

// ---------- Checks: the permission map, explain, simulate (7.5, 7.10) ----------

/** A subject of a check. */
export interface CheckSubject {
  type: string;
  id: string;
  properties?: { act?: unknown };
}

/** A resource of a check: its path is loaded server-side by the product. */
export interface CheckResource extends ScopeRef {
  /** The ancestors, nearest first, last the org. */
  path: ScopeRef[];
  attrs?: Record<string, unknown>;
}

/** How a UI key shows (CONTRACTS.md 7.5). */
export interface UiEntry {
  mode: "show" | "disable" | "hide" | "readonly";
  reason?: string;
}

/** `POST /v1/authz/permissions`. */
export interface PermissionMapAnswer {
  rev: number;
  ui: Record<string, UiEntry>;
  actions: Record<string, boolean>;
  fields: Record<string, Level>;
}

/** What to ask the permission map about one resource. */
export interface PermissionQuery {
  resource: CheckResource;
  /** Missing: none (the client sends `[]`; the API's own default is every key). */
  uiKeys?: string[];
  actions?: string[];
  fields?: string[];
  /** Missing: the caller itself (from `GET /v1/whoami`). */
  subject?: CheckSubject;
}

/** The body of `POST /access/v1/evaluation`, explain and simulate. */
export interface EvaluationBody {
  subject: CheckSubject;
  action: { name: string };
  resource: {
    type: string;
    id: string;
    properties: { path: ScopeRef[]; attrs?: Record<string, unknown> };
  };
  context?: { fields?: string[]; at_least_revision?: number };
}

/** A simulation's candidate (CONTRACTS.md 7.10). */
export interface SimulateCandidate {
  source?: string;
  restore?: number;
  add?: { subject: SubjectString; role: string; scope: ScopeRef }[];
  remove?: string[];
}

/** `GET /v1/whoami`. */
export interface WhoAmI {
  iss: string;
  tid: string;
  sub: string;
  kind: "access" | "delegated" | "external";
  rev: number;
}
