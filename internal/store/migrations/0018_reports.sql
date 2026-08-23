CREATE TABLE IF NOT EXISTS report_runs (
    tenant_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    report_type TEXT NOT NULL CHECK (report_type IN ('EXECUTIVE_SECURITY','SOC_OPERATIONS','INCIDENT','CASE_CLOSURE')),
    title TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('COMPLETED','FAILED')),
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    snapshot JSONB NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    created_by TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, report_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_report_runs_request ON report_runs (tenant_id, request_id) WHERE request_id <> '';
CREATE INDEX IF NOT EXISTS idx_report_runs_catalog ON report_runs (tenant_id, report_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_runs_status ON report_runs (tenant_id, status, created_at DESC);
