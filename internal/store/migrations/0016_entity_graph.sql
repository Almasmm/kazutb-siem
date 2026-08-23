CREATE TABLE IF NOT EXISTS security_entities (
    tenant_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    natural_key TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    criticality TEXT NOT NULL DEFAULT '',
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    observation_count BIGINT NOT NULL DEFAULT 1 CHECK (observation_count > 0),
    last_event_id TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id, entity_id),
    UNIQUE (tenant_id, entity_type, natural_key)
);

CREATE INDEX IF NOT EXISTS idx_security_entities_queue ON security_entities (tenant_id, risk_score DESC, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_security_entities_type ON security_entities (tenant_id, entity_type, last_seen DESC);

CREATE TABLE IF NOT EXISTS entity_relations (
    tenant_id TEXT NOT NULL,
    relation_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    observation_count BIGINT NOT NULL DEFAULT 1 CHECK (observation_count > 0),
    last_event_id TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id, relation_id),
    FOREIGN KEY (tenant_id, source_entity_id) REFERENCES security_entities (tenant_id, entity_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, target_entity_id) REFERENCES security_entities (tenant_id, entity_id) ON DELETE CASCADE,
    CHECK (source_entity_id <> target_entity_id)
);

CREATE INDEX IF NOT EXISTS idx_entity_relations_source ON entity_relations (tenant_id, source_entity_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_entity_relations_target ON entity_relations (tenant_id, target_entity_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_entity_relations_type ON entity_relations (tenant_id, relation_type, last_seen DESC);

CREATE TABLE IF NOT EXISTS entity_event_observations (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id, entity_id),
    FOREIGN KEY (tenant_id, entity_id) REFERENCES security_entities (tenant_id, entity_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS entity_relation_observations (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    relation_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id, relation_id),
    FOREIGN KEY (tenant_id, relation_id) REFERENCES entity_relations (tenant_id, relation_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);
