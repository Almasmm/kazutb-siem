CREATE TABLE IF NOT EXISTS detection_rule_versions (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('DRAFT', 'VALIDATED', 'PUBLISHED', 'SUPERSEDED', 'DISABLED')),
    sigma_yaml TEXT NOT NULL,
    positive_tests JSONB NOT NULL DEFAULT '[]',
    negative_tests JSONB NOT NULL DEFAULT '[]',
    rule_metadata JSONB NOT NULL DEFAULT '{}',
    validation_report JSONB NOT NULL DEFAULT '{}',
    performance_budget_micros BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, rule_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS detection_rule_one_published_idx
ON detection_rule_versions (tenant_id, rule_id)
WHERE state = 'PUBLISHED';

CREATE INDEX IF NOT EXISTS detection_rule_versions_tenant_state_idx
ON detection_rule_versions (tenant_id, state, updated_at DESC);
