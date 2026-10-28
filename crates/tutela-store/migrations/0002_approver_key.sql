-- tutela-store migration 0002: approver keys for `tutela apply` in library
-- mode (ADR-0015).
--
-- A widening model change needs an approval token signed by one of these
-- Ed25519 keys. The table holds only public keys. It is not tenant data
-- (the manifest is the same for every tenant of the app), so it has no
-- row-level security; whoever may write this table may change the model
-- anyway.
CREATE TABLE tutela.approver_key (
    id         text PRIMARY KEY CHECK (id ~ '^apk_[0-9a-f]{32}$'),
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    public_key bytea NOT NULL UNIQUE CHECK (length(public_key) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
