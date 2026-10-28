-- tutela-store migration 0001: the Phase A permission tables
-- (PERMISSION-MODEL.md 18, ADR-0014).
--
-- Rules for every migration: additive only; never DROP or rename a column in
-- a released migration; never DROP SCHEMA ... CASCADE on tenant data.
--
-- Every table that holds tenant data has `tenant_id` first and FORCE ROW
-- LEVEL SECURITY: a row is seen and written only when `tutela.tenant_id` is
-- set to its tenant in the current transaction (set_config(..., true), the
-- same as SET LOCAL). With no tenant set, every query returns zero rows.

-- The tenant directory: which tenants exist and their issuer. No tenant data
-- lives here, so it has no row-level security; the tenant key is
-- (iss, tenant_id), and a tenant id is never reused.
CREATE TABLE tutela.tenant (
    tenant_id  text PRIMARY KEY CHECK (tenant_id ~ '^ten_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    iss        text NOT NULL CHECK (length(iss) BETWEEN 1 AND 2048),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (iss, tenant_id)
);

-- The applied manifest of each app (library mode). One model for every
-- tenant of the app; `tutela apply` publishes it and bumps every tenant's
-- revision in the same transaction.
CREATE TABLE tutela.app_manifest (
    app        text PRIMARY KEY CHECK (app ~ '^[a-z][a-z0-9_]{0,63}$'),
    source     text NOT NULL,
    digest     text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    version    bigint NOT NULL CHECK (version >= 1),
    applied_at timestamptz NOT NULL DEFAULT now(),
    applied_by text
);

-- The tenant revision. It goes up in the same transaction as every change
-- to the tenant's model or data. Writers lock this row first, so writes to
-- one tenant are serialized.
CREATE TABLE tutela.tenant_rev (
    tenant_id text PRIMARY KEY REFERENCES tutela.tenant (tenant_id),
    rev       bigint NOT NULL DEFAULT 0 CHECK (rev BETWEEN 0 AND 9007199254740991)
);

-- The orgs of a tenant. An org belongs to exactly one tenant.
CREATE TABLE tutela.org (
    tenant_id  text NOT NULL REFERENCES tutela.tenant (tenant_id),
    org_id     text NOT NULL UNIQUE CHECK (org_id ~ '^org_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, org_id)
);

-- Groups (PERMISSION-MODEL.md 6.4). Keys are unique in the tenant.
CREATE TABLE tutela."group" (
    tenant_id  text NOT NULL REFERENCES tutela.tenant (tenant_id),
    id         text NOT NULL,
    org_id     text NOT NULL,
    key        text NOT NULL,
    name       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, key),
    FOREIGN KEY (tenant_id, org_id) REFERENCES tutela.org (tenant_id, org_id)
);

-- Direct members of a group: a principal, or another group (by group id).
CREATE TABLE tutela.group_member (
    tenant_id   text NOT NULL,
    group_id    text NOT NULL,
    member_kind text NOT NULL CHECK (member_kind IN ('user', 'sa', 'key', 'agent', 'workload', 'group')),
    member_id   text NOT NULL,
    added_by    text,
    added_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_id, member_kind, member_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES tutela."group" (tenant_id, id) ON DELETE CASCADE
);

-- Role assignments (PERMISSION-MODEL.md 6.3, 18). One per (subject, scope).
CREATE TABLE tutela.role_assignment (
    tenant_id      text NOT NULL REFERENCES tutela.tenant (tenant_id),
    id             text NOT NULL,
    principal_kind text NOT NULL CHECK (principal_kind IN ('user', 'sa', 'key', 'agent', 'workload', 'group')),
    principal_id   text NOT NULL,
    scope_kind     text NOT NULL,
    scope_id       text NOT NULL,
    role_id        text NOT NULL,
    granted_by     text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz,
    rev            bigint NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, principal_kind, principal_id, scope_kind, scope_id)
);

-- Field rules at one scope (PERMISSION-MODEL.md 7.1 step 5, 18). Rules at
-- the org root come from the manifest, never from here.
CREATE TABLE tutela.field_rule (
    tenant_id  text NOT NULL REFERENCES tutela.tenant (tenant_id),
    id         text NOT NULL,
    scope_kind text NOT NULL CHECK (scope_kind <> 'org'),
    scope_id   text NOT NULL,
    item_type  text NOT NULL,
    field_key  text NOT NULL,
    role_id    text,
    max_level  text NOT NULL CHECK (max_level IN ('none', 'read', 'write', 'full')),
    display    text NOT NULL DEFAULT 'restricted' CHECK (display IN ('restricted', 'remove')),
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    rev        bigint NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
-- At most one rule per (scope, field, role); NULL role = all roles.
CREATE UNIQUE INDEX field_rule_one_per_role
    ON tutela.field_rule (tenant_id, scope_kind, scope_id, field_key, coalesce(role_id, ''));

-- Boundary settings of one scope (PERMISSION-MODEL.md 9, 10, 18). Phase A
-- reads `private` only; the move and link columns are kept for the rules
-- that come with the impact calculation (ADR-0014).
CREATE TABLE tutela.boundary_rule (
    tenant_id        text NOT NULL REFERENCES tutela.tenant (tenant_id),
    scope_kind       text NOT NULL CHECK (scope_kind <> 'org'),
    scope_id         text NOT NULL,
    private          boolean NOT NULL DEFAULT false,
    links_from       text CHECK (links_from IN ('any', 'team', 'none')),
    restricted_links text CHECK (restricted_links IN ('locked', 'hidden')),
    moves_out        text CHECK (moves_out IN ('members', 'owners', 'none')),
    moves_in         text CHECK (moves_in IN ('members', 'owners', 'none')),
    on_looser        text CHECK (on_looser IN ('approve', 'block')),
    ai_reach         text CHECK (ai_reach IN ('project', 'team')),
    rev              bigint NOT NULL,
    PRIMARY KEY (tenant_id, scope_kind, scope_id)
);

-- Scope paths for `list_filter` (ADR-0011 F1): the ancestors of each scope
-- the product registers, nearest first, as `type:id`; the last is the org.
-- `move_scope` rewrites a scope and every scope below it in the product's
-- own transaction, with the revision bump.
CREATE TABLE tutela.scope_path (
    tenant_id  text NOT NULL REFERENCES tutela.tenant (tenant_id),
    scope_kind text NOT NULL CHECK (scope_kind <> 'org'),
    scope_id   text NOT NULL,
    ancestors  text[] NOT NULL CHECK (cardinality(ancestors) BETWEEN 1 AND 32),
    PRIMARY KEY (tenant_id, scope_kind, scope_id)
);
CREATE INDEX scope_path_ancestors ON tutela.scope_path USING gin (ancestors);

-- Model changes (PERMISSION-MODEL.md 15, 18). One row per published model
-- change per tenant. Binding changes bump the revision but are not recorded
-- here.
CREATE TABLE tutela.model_revision (
    tenant_id     text NOT NULL REFERENCES tutela.tenant (tenant_id),
    rev           bigint NOT NULL,
    parent_rev    bigint NOT NULL,
    app           text NOT NULL,
    author        text,
    approvers     text[] NOT NULL DEFAULT '{}',
    diff          text NOT NULL,
    class         text NOT NULL CHECK (class IN ('narrowing', 'neutral', 'widening')),
    impact        text,
    state         text NOT NULL DEFAULT 'published' CHECK (state IN ('draft', 'proposed', 'published', 'rejected')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    published_at  timestamptz,
    bundle_digest text NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
    signature     text,
    PRIMARY KEY (tenant_id, rev)
);

-- Row-level security on every table with tenant data.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tenant_rev', 'org', 'group', 'group_member', 'role_assignment',
                             'field_rule', 'boundary_rule', 'scope_path', 'model_revision']
    LOOP
        EXECUTE format('ALTER TABLE tutela.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE tutela.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON tutela.%I '
            'USING (tenant_id = current_setting(''tutela.tenant_id'', true)) '
            'WITH CHECK (tenant_id = current_setting(''tutela.tenant_id'', true))', t);
    END LOOP;
END
$$;
