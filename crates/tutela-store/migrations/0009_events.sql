-- tutela-store migration 0009: the transactional outbox of events
-- (CONTRACTS.md 8, ADR-0035).
--
-- An event row is written in the transaction of the change it is about,
-- with the tenant's next event number (`seq`). The counter lives on the
-- tenant's revision row, which a writer locks until it commits, so numbers
-- are given in commit order with no gap: a reader that walks `seq` never
-- skips an event that commits late, and a rolled-back change uses no
-- number. `data` is the event's JSON object as text. Rows never change;
-- old ones are pruned.

ALTER TABLE tutela.tenant_rev
    ADD COLUMN event_seq bigint NOT NULL DEFAULT 0
    CHECK (event_seq BETWEEN 0 AND 9007199254740991);

CREATE TABLE tutela.event (
    tenant_id text NOT NULL REFERENCES tutela.tenant (tenant_id),
    seq       bigint NOT NULL CHECK (seq BETWEEN 1 AND 9007199254740991),
    id        text NOT NULL CHECK (id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    type      text NOT NULL CHECK (type ~ '^tutela\.[a-z][a-z0-9]*(_[a-z0-9]+)*\.[a-z][a-z0-9]*(_[a-z0-9]+)*\.v[1-9][0-9]*$'),
    subject   text NOT NULL CHECK (length(subject) BETWEEN 1 AND 2057),
    org_id    text,
    data      text NOT NULL CHECK (left(data, 1) = '{'),
    time      timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, seq),
    UNIQUE (tenant_id, id)
);
CREATE INDEX event_time ON tutela.event (tenant_id, time);

-- An event never changes once written.
CREATE FUNCTION tutela.refuse_event_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'an event never changes'
        USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER event_kept
    BEFORE UPDATE ON tutela.event
    FOR EACH ROW EXECUTE FUNCTION tutela.refuse_event_change();

ALTER TABLE tutela.event ENABLE ROW LEVEL SECURITY;
ALTER TABLE tutela.event FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tutela.event
    USING (tenant_id = current_setting('tutela.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('tutela.tenant_id', true));
