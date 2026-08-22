CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    updated_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    event_id TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    ingest_time TIMESTAMPTZ NOT NULL,
    category TEXT NOT NULL,
    severity INTEGER NOT NULL,
    raw_hash TEXT NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS security_events_tenant_time_idx ON security_events (tenant_id, event_time DESC);
CREATE INDEX IF NOT EXISTS security_events_tenant_category_idx ON security_events (tenant_id, category, event_time DESC);

CREATE TABLE IF NOT EXISTS findings (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    finding_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, finding_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES security_events(tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS findings_tenant_event_idx ON findings (tenant_id, event_id, created_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    alert_id TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    assignee TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, alert_id)
);
CREATE INDEX IF NOT EXISTS alerts_tenant_queue_idx ON alerts (tenant_id, status, severity, updated_at DESC);
CREATE INDEX IF NOT EXISTS alerts_tenant_dedup_idx ON alerts (tenant_id, dedup_key, last_seen DESC) WHERE status <> 'CLOSED';

CREATE TABLE IF NOT EXISTS incidents (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    incident_id TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    assignee TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL,
    version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, incident_id)
);
CREATE INDEX IF NOT EXISTS incidents_tenant_queue_idx ON incidents (tenant_id, status, severity, updated_at DESC);

CREATE TABLE IF NOT EXISTS audit_heads (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
    head_hash TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_entries (
    sequence_id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    audit_id TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    UNIQUE (tenant_id, audit_id)
);
CREATE INDEX IF NOT EXISTS audit_entries_tenant_sequence_idx ON audit_entries (tenant_id, sequence_id DESC);
