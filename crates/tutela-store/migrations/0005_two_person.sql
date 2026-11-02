-- tutela-store migration 0005: two-person publish, optional per tenant
-- (ADR-0029).

-- A tenant's settings. While `two_person` is on, a model is published only
-- through a proposal that another person approves. Turning it off takes two
-- people as well: the first asks (`off_requested_by`), a second agrees.
CREATE TABLE tutela.tenant_setting (
    tenant_id        text PRIMARY KEY REFERENCES tutela.tenant (tenant_id),
    two_person       boolean NOT NULL DEFAULT false,
    off_requested_by text,
    changed_by       text,
    changed_at       timestamptz NOT NULL DEFAULT now()
);

-- A model change that waits for a second person. It keeps what the proposer
-- saw: the version it was compared against and the digest of its impact
-- report, so an approval can tell whether the tenant moved under it.
CREATE TABLE tutela.model_proposal (
    tenant_id       text NOT NULL REFERENCES tutela.tenant (tenant_id),
    id              text NOT NULL,
    state           text NOT NULL DEFAULT 'proposed'
                    CHECK (state IN ('proposed', 'published', 'rejected', 'stale')),
    app             text NOT NULL,
    source          text NOT NULL,
    digest          text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    base_version    bigint NOT NULL,
    base_digest     text NOT NULL,
    restores        bigint,
    class           text NOT NULL CHECK (class IN ('narrowing', 'neutral', 'widening')),
    diff            text NOT NULL,
    impact          text NOT NULL,
    impact_digest   text NOT NULL,
    impact_complete boolean NOT NULL,
    rev             bigint NOT NULL,
    proposed_by     text NOT NULL,
    decided_by      text,
    version         bigint,
    created_at      timestamptz NOT NULL DEFAULT now(),
    decided_at      timestamptz,
    PRIMARY KEY (tenant_id, id),
    -- The same principal never proposes and approves one change.
    CHECK (state <> 'published' OR (decided_by IS NOT NULL AND decided_by <> proposed_by))
);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tenant_setting', 'model_proposal']
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
