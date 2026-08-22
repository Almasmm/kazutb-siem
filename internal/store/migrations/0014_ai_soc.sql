CREATE TABLE ai_soc_policies (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    cloud_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    pii_redaction BOOLEAN NOT NULL DEFAULT TRUE,
    maximum_context_items INTEGER NOT NULL DEFAULT 20 CHECK (maximum_context_items BETWEEN 1 AND 50),
    local_model TEXT NOT NULL DEFAULT 'kcsp-grounded-rules-v1',
    cloud_model TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_by TEXT NOT NULL DEFAULT 'system',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_soc_requests (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    function TEXT NOT NULL CHECK (function IN (
        'INCIDENT_SUMMARY','EVENT_EXPLANATION','INVESTIGATION_STEPS','CQL_GENERATION',
        'SIGMA_DRAFT','PARSER_DRAFT','MITRE_SUGGESTION','EVIDENCE_TIMELINE',
        'CASE_CLOSURE_REPORT','EXECUTIVE_REPORT'
    )),
    question TEXT NOT NULL DEFAULT '',
    context_refs JSONB NOT NULL,
    context_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
    context_digest TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','BLOCKED')),
    provider TEXT NOT NULL CHECK (provider IN ('LOCAL','CLOUD')),
    model TEXT NOT NULL,
    recommendation JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_by TEXT NOT NULL,
    prompt_injection_detected BOOLEAN NOT NULL DEFAULT FALSE,
    redaction_count INTEGER NOT NULL DEFAULT 0 CHECK (redaction_count >= 0),
    failure_class TEXT NOT NULL DEFAULT '',
    failure_detail TEXT NOT NULL DEFAULT '',
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, request_id),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX ai_soc_requests_queue_idx
    ON ai_soc_requests(status, created_at)
    WHERE status IN ('QUEUED','RUNNING');
CREATE INDEX ai_soc_requests_tenant_idx
    ON ai_soc_requests(tenant_id, updated_at DESC);

CREATE TABLE ai_soc_decisions (
    tenant_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ACCEPTED','REJECTED')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, decision_id),
    UNIQUE (tenant_id, request_id),
    FOREIGN KEY (tenant_id, request_id)
        REFERENCES ai_soc_requests(tenant_id, request_id) ON DELETE CASCADE
);
