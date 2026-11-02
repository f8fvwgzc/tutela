-- tutela-store migration 0012: the lifecycle of tenants, orgs and people
-- (ADR-0041).
--
-- A tenant and an org are soft-deleted: `deleted_at` is set, and their data
-- is purged after `purge_after`. A deleted tenant leaves the directory for
-- every request and every job; its audit chain is never deleted. A deleted
-- org leaves its tenant's decisions at once and its data is purged later.
-- A deleted person stays as a disabled principal, so no token of it works
-- again, and its link to an upstream account is removed.

ALTER TABLE tutela.tenant
    ADD COLUMN name        text CHECK (name IS NULL OR (length(name) BETWEEN 1 AND 200 AND name !~ '[[:cntrl:]]')),
    ADD COLUMN deleted_at  timestamptz,
    ADD COLUMN purge_after timestamptz,
    ADD COLUMN purged_at   timestamptz,
    ADD CONSTRAINT tenant_soft_delete CHECK ((deleted_at IS NULL) = (purge_after IS NULL)),
    ADD CONSTRAINT tenant_purged_after_delete CHECK (purged_at IS NULL OR deleted_at IS NOT NULL);

ALTER TABLE tutela.org
    ADD COLUMN name        text CHECK (name IS NULL OR (length(name) BETWEEN 1 AND 200 AND name !~ '[[:cntrl:]]')),
    ADD COLUMN deleted_at  timestamptz,
    ADD COLUMN purge_after timestamptz,
    ADD COLUMN purged_at   timestamptz,
    ADD CONSTRAINT org_soft_delete CHECK ((deleted_at IS NULL) = (purge_after IS NULL)),
    ADD CONSTRAINT org_purged_after_delete CHECK (purged_at IS NULL OR deleted_at IS NOT NULL);

ALTER TABLE tutela.principal
    ADD COLUMN deleted_at timestamptz,
    ADD CONSTRAINT principal_deleted_is_disabled CHECK (deleted_at IS NULL OR disabled_at IS NOT NULL);

-- The directory holds no tenant data, so anyone who may read it reads every
-- row. A runtime role may change only the row of the tenant its
-- transaction entered (`grant_service` gives it UPDATE on the lifecycle
-- columns, never INSERT or DELETE). Not forced: the owner creates and
-- restores tenants, as the operator (`tutelad tenant`).
ALTER TABLE tutela.tenant ENABLE ROW LEVEL SECURITY;
CREATE POLICY directory_read ON tutela.tenant FOR SELECT USING (true);
CREATE POLICY directory_update ON tutela.tenant FOR UPDATE
    USING (tenant_id = current_setting('tutela.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('tutela.tenant_id', true));

-- History is never rewritten (migration 4). A tenant's purge is the one
-- exception: once its grace has passed, its model versions go with the rest
-- of its data. The audit chain stays.
CREATE OR REPLACE FUNCTION tutela.refuse_history_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND EXISTS (
        SELECT 1 FROM tutela.tenant t
         WHERE t.tenant_id = OLD.tenant_id
           AND t.deleted_at IS NOT NULL AND t.purge_after <= now()) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'published model versions are never changed'
        USING ERRCODE = 'integrity_constraint_violation';
END
$$;
