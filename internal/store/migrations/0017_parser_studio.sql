CREATE TABLE IF NOT EXISTS parser_versions (
    tenant_id TEXT NOT NULL,
    parser_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    name TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('DRAFT','VALIDATED','PUBLISHED','SUPERSEDED','DISABLED')),
    spec JSONB NOT NULL,
    validation JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, parser_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_parser_versions_request ON parser_versions (tenant_id, request_id) WHERE request_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_parser_versions_published_format ON parser_versions (tenant_id, (spec->>'format')) WHERE state = 'PUBLISHED';
CREATE INDEX IF NOT EXISTS idx_parser_versions_catalog ON parser_versions (tenant_id, updated_at DESC);
