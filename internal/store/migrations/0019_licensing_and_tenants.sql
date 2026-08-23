ALTER TABLE tenants ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE','SUSPENDED'));

CREATE TABLE IF NOT EXISTS tenant_licenses (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    license_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    envelope JSONB NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    installed_by TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, license_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_licenses_active ON tenant_licenses (tenant_id) WHERE active;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_licenses_request ON tenant_licenses (tenant_id, request_id) WHERE request_id <> '';
CREATE INDEX IF NOT EXISTS idx_tenant_licenses_history ON tenant_licenses (tenant_id, installed_at DESC);
