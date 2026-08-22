CREATE TABLE IF NOT EXISTS tenant_retention_policies (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    raw_days INTEGER NOT NULL DEFAULT 30 CHECK (raw_days BETWEEN 1 AND 3650),
    normalized_days INTEGER NOT NULL DEFAULT 90 CHECK (normalized_days BETWEEN 1 AND 3650),
    findings_days INTEGER NOT NULL DEFAULT 180 CHECK (findings_days BETWEEN 1 AND 3650),
    evidence_days INTEGER NOT NULL DEFAULT 2555 CHECK (evidence_days BETWEEN 1 AND 36500),
    updated_by TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (raw_days <= normalized_days)
);

INSERT INTO tenant_retention_policies(tenant_id,updated_by)
SELECT tenant_id,'system:migration' FROM tenants
ON CONFLICT DO NOTHING;
