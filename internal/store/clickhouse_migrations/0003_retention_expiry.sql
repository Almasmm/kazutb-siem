ALTER TABLE raw_events
ADD COLUMN IF NOT EXISTS expires_at DateTime64(3, 'UTC') DEFAULT received_at + INTERVAL 30 DAY;

ALTER TABLE raw_events
MODIFY TTL expires_at DELETE;

ALTER TABLE normalized_events
ADD COLUMN IF NOT EXISTS expires_at DateTime64(3, 'UTC') DEFAULT event_time + INTERVAL 90 DAY;

ALTER TABLE normalized_events
MODIFY TTL expires_at DELETE;

ALTER TABLE findings
ADD COLUMN IF NOT EXISTS expires_at DateTime64(3, 'UTC') DEFAULT created_at + INTERVAL 180 DAY;

ALTER TABLE findings
MODIFY TTL expires_at DELETE;
