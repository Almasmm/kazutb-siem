CREATE TABLE threat_intel_feeds (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    feed_id TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('MANUAL','CUSTOM','STIX','TAXII','MISP','OPENCTI')),
    description TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','DISABLED')),
    source_url TEXT NOT NULL DEFAULT '',
    auth_reference TEXT NOT NULL DEFAULT '',
    refresh_interval_seconds INTEGER NOT NULL CHECK (refresh_interval_seconds >= 0 AND refresh_interval_seconds <= 604800),
    default_confidence SMALLINT NOT NULL CHECK (default_confidence BETWEEN 0 AND 100),
    tags JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tags) = 'array'),
    version INTEGER NOT NULL CHECK (version > 0),
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, feed_id)
);

CREATE UNIQUE INDEX threat_intel_feeds_tenant_name_uq
    ON threat_intel_feeds (tenant_id, lower(name));
CREATE INDEX threat_intel_feeds_active_idx
    ON threat_intel_feeds (tenant_id, state, updated_at DESC);

CREATE TABLE threat_intel_indicators (
    tenant_id TEXT NOT NULL,
    indicator_id TEXT NOT NULL,
    feed_id TEXT NOT NULL,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('IPV4','IPV6','DOMAIN','URL','HASH','EMAIL','CERTIFICATE_FINGERPRINT')),
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    reputation TEXT NOT NULL CHECK (reputation IN ('MALICIOUS','SUSPICIOUS','UNKNOWN','TRUSTED')),
    ttl_seconds BIGINT NOT NULL CHECK (ttl_seconds >= 0 AND ttl_seconds <= 315360000),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tags) = 'array'),
    campaign TEXT NOT NULL DEFAULT '',
    malware TEXT NOT NULL DEFAULT '',
    threat_actors JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(threat_actors) = 'array'),
    description TEXT NOT NULL DEFAULT '',
    external_id TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    version INTEGER NOT NULL CHECK (version > 0),
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, indicator_id),
    UNIQUE (tenant_id, indicator_type, normalized_value),
    FOREIGN KEY (tenant_id, feed_id) REFERENCES threat_intel_feeds(tenant_id, feed_id) ON DELETE RESTRICT,
    CHECK (first_seen <= last_seen),
    CHECK (valid_until IS NULL OR valid_from < valid_until)
);

CREATE INDEX threat_intel_indicators_match_idx
    ON threat_intel_indicators (tenant_id, indicator_type, normalized_value)
    WHERE state = 'ACTIVE';
CREATE INDEX threat_intel_indicators_feed_idx
    ON threat_intel_indicators (tenant_id, feed_id, last_seen DESC);
CREATE INDEX threat_intel_indicators_expiry_idx
    ON threat_intel_indicators (tenant_id, valid_until)
    WHERE state = 'ACTIVE' AND valid_until IS NOT NULL;

CREATE TABLE threat_intel_indicator_sources (
    tenant_id TEXT NOT NULL,
    indicator_id TEXT NOT NULL,
    source_key TEXT NOT NULL,
    feed_id TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    payload_hash TEXT NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, indicator_id, source_key),
    FOREIGN KEY (tenant_id, indicator_id) REFERENCES threat_intel_indicators(tenant_id, indicator_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, feed_id) REFERENCES threat_intel_feeds(tenant_id, feed_id) ON DELETE RESTRICT
);

CREATE INDEX threat_intel_indicator_sources_feed_idx
    ON threat_intel_indicator_sources (tenant_id, feed_id, imported_at DESC);

CREATE TABLE threat_intel_matches (
    tenant_id TEXT NOT NULL,
    match_id TEXT NOT NULL,
    indicator_id TEXT NOT NULL,
    indicator_version INTEGER NOT NULL,
    feed_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    matched_field TEXT NOT NULL,
    matched_value TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    reputation TEXT NOT NULL,
    matched_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, match_id),
    UNIQUE (tenant_id, indicator_id, event_id, matched_field),
    FOREIGN KEY (tenant_id, indicator_id) REFERENCES threat_intel_indicators(tenant_id, indicator_id) ON DELETE RESTRICT
);

CREATE INDEX threat_intel_matches_indicator_idx
    ON threat_intel_matches (tenant_id, indicator_id, matched_at DESC);
CREATE INDEX threat_intel_matches_event_idx
    ON threat_intel_matches (tenant_id, event_id, matched_at DESC);
