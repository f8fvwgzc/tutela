-- tutela-store migration 0004: every published model is a kept, numbered
-- version of its tenant (ADR-0026).
--
-- `model_revision` was one row per published change, with a digest and no
-- text. It now keeps the text, so an old version can be read and published
-- again. A row's `origin` says where it came from: `app` for a manifest the
-- whole app published, `tenant` for a model this tenant published for itself.

ALTER TABLE tutela.model_revision
    ADD COLUMN version  bigint CHECK (version >= 1),
    ADD COLUMN source   text,
    ADD COLUMN origin   text NOT NULL DEFAULT 'app' CHECK (origin IN ('app', 'tenant')),
    ADD COLUMN restores bigint;

-- Number what is there. Row-level security holds for this role too, so each
-- tenant is entered in turn. Only the current manifest's text is known; older
-- rows keep their digest and diff, and cannot be published again.
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN SELECT tenant_id FROM tutela.tenant LOOP
        PERFORM set_config('tutela.tenant_id', t, true);
        UPDATE tutela.model_revision m
           SET version = n.v
          FROM (SELECT rev, row_number() OVER (ORDER BY rev) AS v
                  FROM tutela.model_revision) n
         WHERE m.rev = n.rev;
        UPDATE tutela.model_revision m
           SET source = a.source
          FROM tutela.app_manifest a
         WHERE a.digest = m.bundle_digest;
    END LOOP;
    PERFORM set_config('tutela.tenant_id', '', true);
END
$$;

ALTER TABLE tutela.model_revision ALTER COLUMN version SET NOT NULL;
CREATE UNIQUE INDEX model_revision_version ON tutela.model_revision (tenant_id, version);

-- History is never rewritten: a rollback is a new version. This holds for
-- every role, the table's owner too.
CREATE FUNCTION tutela.refuse_history_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'published model versions are never changed'
        USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER model_revision_append_only
    BEFORE UPDATE OR DELETE ON tutela.model_revision
    FOR EACH ROW EXECUTE FUNCTION tutela.refuse_history_change();
