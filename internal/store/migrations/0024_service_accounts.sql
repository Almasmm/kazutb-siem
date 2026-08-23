CREATE TABLE IF NOT EXISTS service_accounts (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    service_account_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scopes TEXT[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 32),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    token_version INTEGER NOT NULL DEFAULT 1 CHECK (token_version > 0),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, service_account_id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS service_accounts_active_idx
ON service_accounts (tenant_id, expires_at DESC)
WHERE revoked_at IS NULL;
