-- tutela-store migration 0011: forwarding audit records to attache's
-- evidence ledger (CONTRACTS.md 9.4, ADR-0039).
--
-- One row per chain: how far its records were acknowledged by the ledger
-- (`shipped_seq`), and which replica holds the chain while it sends a
-- batch (`claimed_by` until `claimed_until`), so two replicas never send
-- one chain at once. A record is marked shipped only after the ledger
-- acknowledged it; a replica that stops mid-send leaves its lease to run
-- out, and the next one sends the batch again (the ledger dedupes by
-- `(service, id)`).

CREATE TABLE tutela.audit_forward (
    tenant_id     text PRIMARY KEY,
    shipped_seq   bigint NOT NULL DEFAULT 0 CHECK (shipped_seq >= 0),
    claimed_by    text,
    claimed_until timestamptz,
    shipped_at    timestamptz
);

ALTER TABLE tutela.audit_forward ENABLE ROW LEVEL SECURITY;
ALTER TABLE tutela.audit_forward FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tutela.audit_forward
    USING (tenant_id = current_setting('tutela.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('tutela.tenant_id', true));
