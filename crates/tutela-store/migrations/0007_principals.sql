-- tutela-store migration 0007: principals that tutelad issues tokens for,
-- the upstream accounts they come from, and the subject tokens already
-- exchanged (ADR-0031, THREAT-MODEL.md TM-02, TM-04).

-- A person or an agent of a tenant. A row exists for every principal
-- `tutelad` has issued a token for: a person made by just-in-time
-- provisioning, an agent registered by attache. `epoch` goes up when the
-- principal's sessions are revoked or it is disabled, and a token with a
-- lower `epoch` is refused (CONTRACTS.md 4.2). A principal with no row has
-- epoch 0 and is enabled.
CREATE TABLE tutela.principal (
    tenant_id   text NOT NULL REFERENCES tutela.tenant (tenant_id),
    principal   text NOT NULL CHECK (principal ~ '^(user:usr_|agent:agt_)[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    epoch       bigint NOT NULL DEFAULT 0 CHECK (epoch BETWEEN 0 AND 9007199254740991),
    disabled_at timestamptz,
    -- An agent that runs as a workload: its SPIFFE id, on attache's path
    -- `/ns/<namespace>/svc/<service>` (CONTRACTS.md 1.4).
    workload    text CHECK (workload ~ '^spiffe://[a-z0-9._-]{1,255}/ns/[A-Za-z0-9._-]+/svc/[A-Za-z0-9._-]+$'),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, principal),
    CHECK (workload IS NULL OR principal LIKE 'agent:%')
);
CREATE UNIQUE INDEX principal_workload ON tutela.principal (tenant_id, workload)
    WHERE workload IS NOT NULL;

-- Who an upstream account is: (issuer, subject) of an external issuer, never
-- an e-mail address (ADR-0008, TM-04).
CREATE TABLE tutela.upstream_account (
    tenant_id  text NOT NULL,
    iss        text NOT NULL CHECK (length(iss) BETWEEN 1 AND 2048),
    sub        text NOT NULL CHECK (length(sub) BETWEEN 1 AND 255),
    principal  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, iss, sub),
    FOREIGN KEY (tenant_id, principal) REFERENCES tutela.principal (tenant_id, principal)
);

-- External subject tokens already exchanged, by issuer and the SHA-256 of
-- their `jti`, until they expire: each is exchanged once.
CREATE TABLE tutela.exchanged_token (
    tenant_id  text NOT NULL REFERENCES tutela.tenant (tenant_id),
    iss        text NOT NULL,
    jti_digest text NOT NULL CHECK (jti_digest ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, iss, jti_digest)
);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['principal', 'upstream_account', 'exchanged_token']
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
