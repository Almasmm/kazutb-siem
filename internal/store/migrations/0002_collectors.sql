CREATE TABLE IF NOT EXISTS collectors (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    collector_id TEXT NOT NULL,
    name TEXT NOT NULL,
    collector_type TEXT NOT NULL,
    auth_subject TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED')),
    capabilities TEXT[] NOT NULL DEFAULT '{}',
    version TEXT NOT NULL DEFAULT '',
    observed_ip TEXT NOT NULL DEFAULT '',
    health_metadata JSONB NOT NULL DEFAULT '{}',
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, collector_id),
    UNIQUE (tenant_id, auth_subject)
);

CREATE INDEX IF NOT EXISTS collectors_tenant_state_idx
ON collectors (tenant_id, state, updated_at DESC);

CREATE INDEX IF NOT EXISTS collectors_last_seen_idx
ON collectors (tenant_id, last_seen_at DESC NULLS LAST);
