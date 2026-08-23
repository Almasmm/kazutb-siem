ALTER TABLE threat_intel_feeds
    ADD COLUMN sync_status TEXT NOT NULL DEFAULT 'NOT_APPLICABLE'
        CHECK (sync_status IN ('NOT_APPLICABLE','QUEUED','RUNNING','SUCCEEDED','FAILED','CREDENTIALS_REQUIRED')),
    ADD COLUMN health_status TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK (health_status IN ('UNKNOWN','HEALTHY','DEGRADED','CREDENTIALS_REQUIRED')),
    ADD COLUMN health_error_class TEXT NOT NULL DEFAULT '',
    ADD COLUMN health_detail TEXT NOT NULL DEFAULT '',
    ADD COLUMN sync_cursor TEXT NOT NULL DEFAULT '',
    ADD COLUMN last_sync_at TIMESTAMPTZ,
    ADD COLUMN last_tested_at TIMESTAMPTZ,
    ADD COLUMN next_sync_at TIMESTAMPTZ,
    ADD COLUMN last_imported INTEGER NOT NULL DEFAULT 0 CHECK (last_imported >= 0),
    ADD COLUMN last_deduplicated INTEGER NOT NULL DEFAULT 0 CHECK (last_deduplicated >= 0),
    ADD COLUMN last_rejected INTEGER NOT NULL DEFAULT 0 CHECK (last_rejected >= 0),
    ADD COLUMN sync_attempt INTEGER NOT NULL DEFAULT 0 CHECK (sync_attempt >= 0),
    ADD COLUMN sync_lease_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN sync_lease_until TIMESTAMPTZ;

UPDATE threat_intel_feeds
SET sync_status = CASE WHEN auth_reference = '' THEN 'CREDENTIALS_REQUIRED' ELSE 'QUEUED' END,
    health_status = CASE WHEN auth_reference = '' THEN 'CREDENTIALS_REQUIRED' ELSE 'UNKNOWN' END,
    next_sync_at = now()
WHERE kind IN ('MISP','OPENCTI') AND state = 'ACTIVE';

CREATE INDEX threat_intel_feeds_sync_due_idx
    ON threat_intel_feeds (next_sync_at, tenant_id, feed_id)
    WHERE state = 'ACTIVE' AND kind IN ('MISP','OPENCTI');
