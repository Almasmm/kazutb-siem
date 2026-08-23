CREATE TABLE IF NOT EXISTS entity_observations (
    tenant_id String,
    event_id String,
    event_time DateTime64(3, 'UTC'),
    entity_id String,
    entity_type LowCardinality(String),
    natural_key String,
    display_name String,
    role LowCardinality(String),
    payload String,
    version UInt64,
    expires_at DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(version)
PARTITION BY (tenant_id, toYYYYMM(event_time))
ORDER BY (tenant_id, event_id, entity_id)
TTL expires_at DELETE;

CREATE TABLE IF NOT EXISTS entity_relation_observations (
    tenant_id String,
    event_id String,
    event_time DateTime64(3, 'UTC'),
    relation_id String,
    relation_type LowCardinality(String),
    source_entity_id String,
    target_entity_id String,
    payload String,
    version UInt64,
    expires_at DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(version)
PARTITION BY (tenant_id, toYYYYMM(event_time))
ORDER BY (tenant_id, event_id, relation_id)
TTL expires_at DELETE;
