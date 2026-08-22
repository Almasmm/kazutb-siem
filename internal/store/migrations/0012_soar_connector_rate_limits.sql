CREATE TABLE soar_connector_rate_windows (
    tenant_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    used INTEGER NOT NULL CHECK (used > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, connector_id, window_start),
    FOREIGN KEY (tenant_id, connector_id) REFERENCES soar_connectors(tenant_id, connector_id) ON DELETE RESTRICT
);

CREATE INDEX soar_connector_rate_windows_age_idx ON soar_connector_rate_windows(updated_at);
