-- tutela-store migration 0014: the deployment's audit producer key, sealed
-- (ADR-0045, CONTRACTS.md 9.3).
--
-- The Ed25519 key that signs every audit record `tutelad` forwards to
-- attache's evidence ledger. It was `TUTELA_AUDIT_KEY` in the environment;
-- now its seed is stored only as a `tutela-vault` envelope, sealed under
-- TUTELA_MASTER_KEY for the purpose `audit_key` and its `kid`, as signing
-- keys are (migration 6). One key signs at a time: the one not retired. A
-- rotation retires it and makes the next; a retired key keeps its public
-- key for good, so a record it signed stays verifiable. Like signing keys,
-- this is the deployment's, not a tenant's: no row-level security.
CREATE TABLE tutela.audit_key (
    kid        text PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_-]{43}$'),
    alg        text NOT NULL CHECK (alg = 'EdDSA'),
    public_key bytea NOT NULL CHECK (length(public_key) = 32),
    sealed     bytea NOT NULL,
    origin     text NOT NULL CHECK (origin IN ('made', 'imported')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at timestamptz
);
-- At most one key signs.
CREATE UNIQUE INDEX audit_key_signing ON tutela.audit_key ((true)) WHERE retired_at IS NULL;

-- A key keeps its identity and its public key, a retirement stays, and no
-- key is deleted: old records stay verifiable. Re-wrapping under a new
-- master key changes `sealed` only.
CREATE FUNCTION tutela.refuse_audit_key_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'audit keys are never deleted'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.kid <> OLD.kid OR NEW.alg <> OLD.alg OR NEW.public_key <> OLD.public_key
       OR NEW.origin <> OLD.origin
       OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at) THEN
        RAISE EXCEPTION 'an audit key keeps its identity, and a retirement stays'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER audit_key_kept
    BEFORE UPDATE OR DELETE ON tutela.audit_key
    FOR EACH ROW EXECUTE FUNCTION tutela.refuse_audit_key_change();
