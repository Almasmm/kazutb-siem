CREATE TABLE IF NOT EXISTS evidence_items (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL,
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 200),
    incident_id TEXT NOT NULL DEFAULT '',
    alert_id TEXT NOT NULL DEFAULT '',
    event_id TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL CHECK (length(filename) BETWEEN 1 AND 255),
    content_type TEXT NOT NULL CHECK (length(content_type) BETWEEN 1 AND 255),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    bucket TEXT NOT NULL,
    object_key TEXT NOT NULL,
    object_version TEXT NOT NULL DEFAULT '',
    etag TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'AVAILABLE', 'FAILED')),
    failure TEXT NOT NULL DEFAULT '' CHECK (length(failure) <= 2000),
    retain_until TIMESTAMPTZ NOT NULL,
    legal_hold BOOLEAN NOT NULL DEFAULT false,
    uploader TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    verified_at TIMESTAMPTZ,
    custody_head_hash TEXT NOT NULL DEFAULT '' CHECK (custody_head_hash = '' OR length(custody_head_hash) = 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, evidence_id),
    UNIQUE (tenant_id, request_id),
    UNIQUE (tenant_id, object_key),
    CHECK (incident_id <> '' OR alert_id <> '' OR event_id <> '')
);

CREATE INDEX IF NOT EXISTS evidence_incident_idx ON evidence_items (tenant_id, incident_id, created_at DESC) WHERE incident_id <> '';
CREATE INDEX IF NOT EXISTS evidence_alert_idx ON evidence_items (tenant_id, alert_id, created_at DESC) WHERE alert_id <> '';
CREATE INDEX IF NOT EXISTS evidence_event_idx ON evidence_items (tenant_id, event_id, created_at DESC) WHERE event_id <> '';
CREATE INDEX IF NOT EXISTS evidence_status_idx ON evidence_items (tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS evidence_custody_entries (
    sequence BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    custody_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
    request_id TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}',
    previous_hash TEXT NOT NULL DEFAULT '' CHECK (previous_hash = '' OR length(previous_hash) = 64),
    hash TEXT NOT NULL CHECK (length(hash) = 64),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, custody_id),
    FOREIGN KEY (tenant_id, evidence_id) REFERENCES evidence_items(tenant_id, evidence_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS evidence_custody_order_idx
    ON evidence_custody_entries (tenant_id, evidence_id, sequence);
