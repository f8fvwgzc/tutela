-- tutela-store migration 0013: apps and their client secrets (ADR-0044).
--
-- An app belongs to one tenant. Its client id is `app_<uuidv7>`, its
-- principal a service account `sa:sa_<uuidv7>` of that tenant, and its
-- client secrets are API keys of CONTRACTS.md 5 (`tut_sk_…`), stored only as
-- SHA-256(pepper || key) with the pepper's version. During a rotation the
-- old secret keeps working until its `expires_at`.
--
-- The token endpoint learns an app's tenant before it can enter one, so
-- `app_directory` maps a client id to its tenant and holds nothing else,
-- like the tenant directory: every role may read it, a runtime role may add
-- a row only for the tenant its transaction entered, and nobody changes or
-- removes one.

CREATE TABLE tutela.app_directory (
    app_id    text PRIMARY KEY CHECK (app_id ~ '^app_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    tenant_id text NOT NULL REFERENCES tutela.tenant (tenant_id)
);
ALTER TABLE tutela.app_directory ENABLE ROW LEVEL SECURITY;
ALTER TABLE tutela.app_directory FORCE ROW LEVEL SECURITY;
CREATE POLICY app_directory_read ON tutela.app_directory FOR SELECT USING (true);
CREATE POLICY app_directory_add ON tutela.app_directory FOR INSERT
    WITH CHECK (tenant_id = current_setting('tutela.tenant_id', true));

CREATE TABLE tutela.app (
    tenant_id   text NOT NULL REFERENCES tutela.tenant (tenant_id),
    id          text NOT NULL REFERENCES tutela.app_directory (app_id),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200 AND name !~ '[[:cntrl:]]'),
    principal   text NOT NULL CHECK (principal ~ '^sa:sa_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, principal)
);

CREATE TABLE tutela.app_secret (
    tenant_id      text NOT NULL,
    app_id         text NOT NULL,
    key_id         text NOT NULL CHECK (key_id ~ '^key_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    prefix         text NOT NULL CHECK (prefix ~ '^[a-z0-9]{8}$'),
    hash           text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    pepper_version integer NOT NULL CHECK (pepper_version >= 1),
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz,
    PRIMARY KEY (tenant_id, key_id),
    FOREIGN KEY (tenant_id, app_id) REFERENCES tutela.app (tenant_id, id)
);
-- A prefix finds one key in the deployment (CONTRACTS.md 5.3).
CREATE UNIQUE INDEX app_secret_prefix ON tutela.app_secret (prefix);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['app', 'app_secret']
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

-- An app's service account has an epoch, so disabling the app stops the
-- tokens it holds (ADR-0031 item 8).
ALTER TABLE tutela.principal DROP CONSTRAINT principal_principal_check;
ALTER TABLE tutela.principal ADD CONSTRAINT principal_principal_check
    CHECK (principal ~ '^(user:usr_|agent:agt_|sa:sa_)[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
