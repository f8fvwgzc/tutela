-- tutela-store migration 0010: webhooks (CONTRACTS.md 8.4, 8.5, ADR-0036).
--
-- A webhook is a tenant's endpoint for its events. Its secret is stored
-- only as a `tutela-vault` envelope (purpose `webhook_secret`); during a
-- rotation the previous secret is kept until `previous_until`, and both
-- sign. `after_seq` is how far the tenant's events have been handed to the
-- webhook: a delivery row is made for each later event of its types.
--
-- A delivery is claimed by one replica for a short lease before it is
-- sent, so two replicas never send one event to one webhook at once. It
-- waits while an earlier delivery of the same subject to the same webhook
-- is pending (order per subject), is retried with backoff, and ends
-- `delivered` or `dead`.

CREATE TABLE tutela.webhook (
    tenant_id        text NOT NULL REFERENCES tutela.tenant (tenant_id),
    id               text NOT NULL CHECK (id ~ '^whk_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    url              text NOT NULL CHECK (length(url) BETWEEN 8 AND 2048),
    types            text[] NOT NULL DEFAULT '{}',
    secret           bytea NOT NULL,
    secret_version   integer NOT NULL DEFAULT 1 CHECK (secret_version >= 1),
    previous         bytea,
    previous_version integer,
    previous_until   timestamptz,
    after_seq        bigint NOT NULL CHECK (after_seq >= 0),
    disabled_at      timestamptz,
    created_by       text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CHECK ((previous IS NULL) = (previous_until IS NULL)),
    CHECK ((previous IS NULL) = (previous_version IS NULL))
);

CREATE TABLE tutela.webhook_delivery (
    tenant_id     text NOT NULL,
    webhook_id    text NOT NULL,
    seq           bigint NOT NULL,
    subject       text NOT NULL,
    state         text NOT NULL DEFAULT 'pending'
                  CHECK (state IN ('pending', 'delivered', 'dead')),
    attempts      integer NOT NULL DEFAULT 0,
    next_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    first_at      timestamptz,
    last_status   integer,
    last_error    text,
    claimed_by    text,
    claimed_until timestamptz,
    done_at       timestamptz,
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, webhook_id, seq),
    FOREIGN KEY (tenant_id, webhook_id) REFERENCES tutela.webhook (tenant_id, id)
);
CREATE INDEX webhook_delivery_due ON tutela.webhook_delivery (tenant_id, state, next_at);
CREATE INDEX webhook_delivery_subject ON tutela.webhook_delivery (tenant_id, webhook_id, subject, seq)
    WHERE state = 'pending';

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['webhook', 'webhook_delivery']
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
