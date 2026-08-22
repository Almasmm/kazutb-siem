ALTER TABLE raw_events
ADD COLUMN IF NOT EXISTS format LowCardinality(String) DEFAULT 'ocsf-json-v1' AFTER received_at;
