-- tutela-store migration 0006: tutelad's token signing keys (ADR-0030,
-- THREAT-MODEL.md TM-15).
--
-- One key set for the deployment, not per tenant: per-tenant keys are
-- Phase C. So this is not tenant data and has no row-level security. The
-- private key is stored only as a `tutela-vault` envelope, sealed under
-- TUTELA_MASTER_KEY for the purpose `signing_key` and the key's `kid`;
-- it is never stored or logged in plain text.
--
-- A key is published in the JWKS from the moment it is made, signs from
-- `signs_from`, and leaves the JWKS at `retire_at`. A rotation makes the next
-- key with `signs_from` at least twice the JWKS cache time ahead, and keeps
-- the old one published until every token it signed has expired. A denied
-- key leaves the JWKS at once and is on the `kid` deny-list for good.
CREATE TABLE tutela.signing_key (
    kid        text PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_-]{43}$'),
    alg        text NOT NULL CHECK (alg = 'ES256'),
    public_jwk text NOT NULL,
    sealed     bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    signs_from timestamptz NOT NULL,
    retire_at  timestamptz,
    denied_at  timestamptz,
    CHECK (retire_at IS NULL OR retire_at > signs_from)
);

-- A key's identity never changes, a denial is never undone, and no key is
-- deleted: the deny-list and the history stay. Re-wrapping under a new
-- master key changes `sealed` only.
CREATE FUNCTION tutela.refuse_signing_key_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'signing keys are never deleted'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.kid <> OLD.kid OR NEW.alg <> OLD.alg OR NEW.public_jwk <> OLD.public_jwk
       OR (OLD.denied_at IS NOT NULL AND NEW.denied_at IS DISTINCT FROM OLD.denied_at) THEN
        RAISE EXCEPTION 'a signing key keeps its identity, and a denial stays'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER signing_key_kept
    BEFORE UPDATE OR DELETE ON tutela.signing_key
    FOR EACH ROW EXECUTE FUNCTION tutela.refuse_signing_key_change();
