CREATE TABLE ueba_entity_baselines (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    entity_type TEXT NOT NULL CHECK (entity_type IN ('user','device','peer')),
    entity_id TEXT NOT NULL,
    entity_name TEXT NOT NULL,
    peer_group TEXT NOT NULL,
    model_version TEXT NOT NULL,
    feature_version TEXT NOT NULL,
    training_window_days INTEGER NOT NULL CHECK (training_window_days BETWEEN 1 AND 365),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 0),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    drift_score DOUBLE PRECISION NOT NULL CHECK (drift_score >= 0 AND drift_score <= 100),
    drift_status TEXT NOT NULL CHECK (drift_status IN ('COLD_START','STABLE','WATCH','DRIFTING')),
    profile JSONB NOT NULL CHECK (jsonb_typeof(profile) = 'object'),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, entity_type, entity_id)
);

CREATE INDEX ueba_baselines_peer_idx
    ON ueba_entity_baselines(tenant_id, peer_group, entity_type, updated_at DESC);

CREATE TABLE ueba_volume_windows (
    tenant_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    event_count INTEGER NOT NULL CHECK (event_count > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, entity_type, entity_id, window_start),
    FOREIGN KEY (tenant_id, entity_type, entity_id)
        REFERENCES ueba_entity_baselines(tenant_id, entity_type, entity_id) ON DELETE RESTRICT
);

CREATE INDEX ueba_volume_windows_age_idx ON ueba_volume_windows(updated_at);

CREATE TABLE ueba_anomalies (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    anomaly_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    entity_name TEXT NOT NULL,
    peer_group TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH')),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 79),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    features JSONB NOT NULL CHECK (jsonb_typeof(features) = 'array'),
    explanation JSONB NOT NULL CHECK (jsonb_typeof(explanation) = 'object'),
    model_version TEXT NOT NULL,
    feature_version TEXT NOT NULL,
    training_window_days INTEGER NOT NULL,
    baseline_observations INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('NEW','CONFIRMED','FALSE_POSITIVE')),
    version INTEGER NOT NULL CHECK (version > 0),
    feedback_by TEXT NOT NULL DEFAULT '',
    feedback_reason TEXT NOT NULL DEFAULT '',
    feedback_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, anomaly_id),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, entity_type, entity_id)
        REFERENCES ueba_entity_baselines(tenant_id, entity_type, entity_id) ON DELETE RESTRICT
);

CREATE INDEX ueba_anomalies_queue_idx
    ON ueba_anomalies(tenant_id, status, risk_score DESC, created_at DESC);
CREATE INDEX ueba_anomalies_entity_idx
    ON ueba_anomalies(tenant_id, entity_type, entity_id, created_at DESC);
