CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    token_id TEXT NOT NULL,
    label TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    collector_type TEXT NOT NULL,
    capabilities TEXT[] NOT NULL DEFAULT '{}',
    state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED', 'EXHAUSTED', 'EXPIRED')),
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 10000),
    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0 AND use_count <= max_uses),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, token_id)
);

CREATE INDEX IF NOT EXISTS agent_enrollment_tokens_tenant_state_idx
ON agent_enrollment_tokens (tenant_id, state, expires_at DESC);

CREATE TABLE IF NOT EXISTS agent_credentials (
    credential_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    auth_subject TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, collector_id)
        REFERENCES collectors(tenant_id, collector_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS agent_credentials_active_idx
ON agent_credentials (tenant_id, collector_id, expires_at DESC)
WHERE revoked_at IS NULL;
