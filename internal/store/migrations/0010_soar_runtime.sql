ALTER TABLE soar_node_executions
    ADD COLUMN timeout_seconds INTEGER NOT NULL DEFAULT 60
        CHECK (timeout_seconds >= 1 AND timeout_seconds <= 3600);

ALTER TABLE soar_node_executions
    ADD COLUMN retry_policy JSONB NOT NULL
        DEFAULT '{"maximum_attempts":1,"backoff_seconds":1,"maximum_backoff_seconds":60}'::jsonb
        CHECK (jsonb_typeof(retry_policy) = 'object');

CREATE INDEX soar_approvals_status_idx
    ON soar_approvals(tenant_id, status, requested_at DESC);
