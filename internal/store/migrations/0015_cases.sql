CREATE TABLE IF NOT EXISTS cases (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL,
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 200),
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATION', 'RESPONSE', 'CLOSED')),
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 255),
    version INTEGER NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, case_id),
    UNIQUE (tenant_id, request_id)
);

CREATE INDEX IF NOT EXISTS cases_queue_idx ON cases (tenant_id, status, severity, updated_at DESC);
CREATE INDEX IF NOT EXISTS cases_owner_idx ON cases (tenant_id, owner, updated_at DESC);

CREATE TABLE IF NOT EXISTS case_incidents (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, case_id, incident_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, incident_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS case_incidents_reverse_idx ON case_incidents (tenant_id, incident_id, linked_at DESC);

ALTER TABLE evidence_items ADD COLUMN IF NOT EXISTS case_id TEXT;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'evidence_items_case_fk') THEN
        ALTER TABLE evidence_items ADD CONSTRAINT evidence_items_case_fk
            FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id) ON DELETE RESTRICT;
    END IF;
END $$;

ALTER TABLE evidence_items DROP CONSTRAINT IF EXISTS evidence_items_check;
ALTER TABLE evidence_items DROP CONSTRAINT IF EXISTS evidence_investigation_link_check;
ALTER TABLE evidence_items ADD CONSTRAINT evidence_investigation_link_check
    CHECK (case_id IS NOT NULL OR incident_id <> '' OR alert_id <> '' OR event_id <> '');

CREATE INDEX IF NOT EXISTS evidence_case_idx ON evidence_items (tenant_id, case_id, created_at DESC) WHERE case_id IS NOT NULL;
