-- tutela-store migration 0008: the local hash-chained audit log
-- (CONTRACTS.md 9.4, THREAT-MODEL.md TM-20, ADR-0034).
--
-- One chain per tenant. Each record holds the canonical JSON of its audit.v1
-- record without the producer signature (`body`, with the chain's `seq`),
-- the hash of the record before it, and its own hash:
--   hash = SHA-256("tutela-audit-chain-v1" LF prev_hash LF body), in hex,
-- and the first record's prev_hash is 64 zeros. A record is written in the
-- transaction of the change it describes; `audit_head` is the chain's last
-- link, locked by each writer, so two writers in one tenant make one chain.
--
-- The deployment's own records (signing keys) have their own chain under a
-- tenant id that is never in the directory, ten_00000000-0000-7000-8000-000000000000.
-- So neither table refers to tutela.tenant.

CREATE TABLE tutela.audit_head (
    tenant_id text PRIMARY KEY,
    seq       bigint NOT NULL CHECK (seq BETWEEN 0 AND 9007199254740991),
    hash      text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE tutela.audit_record (
    tenant_id  text NOT NULL,
    seq        bigint NOT NULL CHECK (seq BETWEEN 1 AND 9007199254740991),
    id         text NOT NULL,
    body       text NOT NULL,
    prev_hash  text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    hash       text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, seq),
    UNIQUE (tenant_id, id)
);

-- UPDATE, DELETE and TRUNCATE of a record are refused for every role, the
-- owner too. The service role has no grant for them either (grant_service),
-- and readiness checks both (check_isolation).
CREATE FUNCTION tutela.refuse_audit_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'the audit log is append-only'
        USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER audit_record_kept
    BEFORE UPDATE OR DELETE ON tutela.audit_record
    FOR EACH ROW EXECUTE FUNCTION tutela.refuse_audit_change();
CREATE TRIGGER audit_record_not_truncated
    BEFORE TRUNCATE ON tutela.audit_record
    FOR EACH STATEMENT EXECUTE FUNCTION tutela.refuse_audit_change();

-- The head only moves forward, and is never removed.
CREATE FUNCTION tutela.refuse_audit_head_back() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR NEW.tenant_id <> OLD.tenant_id OR NEW.seq <= OLD.seq THEN
        RAISE EXCEPTION 'the audit chain head only moves forward'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER audit_head_forward
    BEFORE UPDATE OR DELETE ON tutela.audit_head
    FOR EACH ROW EXECUTE FUNCTION tutela.refuse_audit_head_back();
CREATE TRIGGER audit_head_not_truncated
    BEFORE TRUNCATE ON tutela.audit_head
    FOR EACH STATEMENT EXECUTE FUNCTION tutela.refuse_audit_change();

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['audit_head', 'audit_record']
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
