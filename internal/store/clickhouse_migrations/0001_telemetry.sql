CREATE TABLE IF NOT EXISTS raw_events (
    tenant_id String,
    event_id String,
    message_id String,
    collector_id String,
    event_timestamp DateTime64(3, 'UTC'),
    received_at DateTime64(3, 'UTC'),
    content_type LowCardinality(String),
    schema_version LowCardinality(String),
    raw_hash String,
    payload String
) ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(received_at))
ORDER BY (tenant_id, event_id, received_at, message_id)
TTL received_at + INTERVAL 30 DAY DELETE;

CREATE TABLE IF NOT EXISTS normalized_events (
    tenant_id String,
    event_id String,
    event_time DateTime64(3, 'UTC'),
    ingest_time DateTime64(3, 'UTC'),
    category LowCardinality(String),
    severity UInt8,
    source_vendor LowCardinality(String),
    source_product LowCardinality(String),
    source_type LowCardinality(String),
    user_name String,
    device_hostname String,
    src_ip String,
    dst_ip String,
    raw_hash String,
    payload String,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
PARTITION BY (tenant_id, toYYYYMM(event_time))
ORDER BY (tenant_id, event_id)
TTL event_time + INTERVAL 90 DAY DELETE;

CREATE TABLE IF NOT EXISTS findings (
    tenant_id String,
    finding_id String,
    event_id String,
    rule_id LowCardinality(String),
    severity LowCardinality(String),
    risk_score UInt8,
    created_at DateTime64(3, 'UTC'),
    payload String,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
PARTITION BY (tenant_id, toYYYYMM(created_at))
ORDER BY (tenant_id, finding_id)
TTL created_at + INTERVAL 180 DAY DELETE;
