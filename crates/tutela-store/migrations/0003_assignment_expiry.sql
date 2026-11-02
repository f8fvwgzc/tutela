-- tutela-store migration 0003: reads for the bindings store and assignment
-- expiry (ADR-0020).

-- What has expired, without reading the whole tenant.
CREATE INDEX role_assignment_expiry ON tutela.role_assignment (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;

-- A member to its groups, for the walk up the group tree. The primary key
-- only walks down.
CREATE INDEX group_member_by_member ON tutela.group_member (tenant_id, member_kind, member_id);
