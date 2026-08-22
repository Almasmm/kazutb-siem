CREATE TABLE IF NOT EXISTS detection_correlation_observations (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    correlation_rule_id TEXT NOT NULL,
    correlation_rule_version TEXT NOT NULL,
    group_key_hash TEXT NOT NULL CHECK (length(group_key_hash) = 64),
    group_key TEXT NOT NULL,
    source_rule_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, correlation_rule_id, correlation_rule_version, group_key_hash, source_rule_id, event_id)
);

CREATE INDEX IF NOT EXISTS detection_correlation_window_idx
    ON detection_correlation_observations (tenant_id, correlation_rule_id, correlation_rule_version, group_key_hash, event_time);

CREATE INDEX IF NOT EXISTS detection_correlation_retention_idx
    ON detection_correlation_observations (event_time);

CREATE TABLE IF NOT EXISTS detection_correlation_emissions (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    correlation_rule_id TEXT NOT NULL,
    correlation_rule_version TEXT NOT NULL,
    group_key_hash TEXT NOT NULL CHECK (length(group_key_hash) = 64),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    triggering_event_id TEXT NOT NULL,
    event_ids TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, correlation_rule_id, correlation_rule_version, fingerprint)
);

CREATE INDEX IF NOT EXISTS detection_correlation_emission_lookup_idx
    ON detection_correlation_emissions (tenant_id, correlation_rule_id, correlation_rule_version, group_key_hash, created_at DESC);
