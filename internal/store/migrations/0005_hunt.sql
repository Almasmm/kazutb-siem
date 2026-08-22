CREATE TABLE IF NOT EXISTS saved_hunts (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    hunt_id TEXT NOT NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
    visibility TEXT NOT NULL CHECK (visibility IN ('PRIVATE', 'TENANT')),
    query JSONB NOT NULL,
    owner TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, hunt_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS saved_hunts_name_active_idx
    ON saved_hunts (tenant_id, lower(name)) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS saved_hunts_visibility_idx
    ON saved_hunts (tenant_id, visibility, updated_at DESC) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS hunt_executions (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    execution_id TEXT NOT NULL,
    saved_hunt_id TEXT,
    actor TEXT NOT NULL,
    query JSONB NOT NULL,
    query_hash TEXT NOT NULL CHECK (query_hash = '' OR length(query_hash) = 64),
    status TEXT NOT NULL CHECK (status IN ('SUCCEEDED', 'FAILED')),
    returned INTEGER NOT NULL DEFAULT 0 CHECK (returned >= 0),
    duration_micros BIGINT NOT NULL DEFAULT 0 CHECK (duration_micros >= 0),
    error TEXT NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, execution_id)
);

CREATE INDEX IF NOT EXISTS hunt_executions_actor_idx
    ON hunt_executions (tenant_id, actor, created_at DESC);

CREATE INDEX IF NOT EXISTS hunt_executions_saved_idx
    ON hunt_executions (tenant_id, saved_hunt_id, created_at DESC) WHERE saved_hunt_id IS NOT NULL;
