CREATE TABLE soar_connectors (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    connector_id TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('WEBHOOK')),
    state TEXT NOT NULL CHECK (state IN ('CONFIGURED','CREDENTIALS_REQUIRED','READY','DEGRADED','DISABLED')),
    endpoint TEXT NOT NULL,
    auth_type TEXT NOT NULL CHECK (auth_type IN ('NONE','BEARER','HMAC_SHA256')),
    secret_ref TEXT NOT NULL DEFAULT '',
    allowed_actions JSONB NOT NULL CHECK (jsonb_typeof(allowed_actions) = 'array'),
    settings JSONB NOT NULL CHECK (jsonb_typeof(settings) = 'object'),
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 60),
    retry_policy JSONB NOT NULL CHECK (jsonb_typeof(retry_policy) = 'object'),
    rate_limit_per_minute INTEGER NOT NULL CHECK (rate_limit_per_minute BETWEEN 1 AND 600),
    version INTEGER NOT NULL CHECK (version > 0),
    health_status TEXT NOT NULL CHECK (health_status IN ('UNKNOWN','HEALTHY','UNHEALTHY','CREDENTIALS_REQUIRED','DISABLED')),
    health_error_class TEXT NOT NULL DEFAULT '',
    health_detail TEXT NOT NULL DEFAULT '',
    last_tested_at TIMESTAMPTZ,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, connector_id)
);

CREATE UNIQUE INDEX soar_connectors_tenant_name_uq ON soar_connectors(tenant_id, lower(name));
CREATE INDEX soar_connectors_state_idx ON soar_connectors(tenant_id, state, kind, updated_at DESC);

CREATE TABLE soar_connector_tests (
    tenant_id TEXT NOT NULL,
    test_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','CREDENTIALS_REQUIRED','CANCELLED')),
    error_class TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    http_status INTEGER NOT NULL DEFAULT 0 CHECK (http_status BETWEEN 0 AND 599),
    latency_ms BIGINT NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
    tested_by TEXT NOT NULL,
    worker_id TEXT NOT NULL DEFAULT '',
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, test_id),
    UNIQUE (tenant_id, request_id),
    FOREIGN KEY (tenant_id, connector_id) REFERENCES soar_connectors(tenant_id, connector_id) ON DELETE RESTRICT
);

CREATE INDEX soar_connector_tests_queue_idx
    ON soar_connector_tests(status, created_at, lease_until)
    WHERE status IN ('QUEUED','RUNNING');
CREATE INDEX soar_connector_tests_connector_idx
    ON soar_connector_tests(tenant_id, connector_id, created_at DESC);
