CREATE TABLE soar_playbooks (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    playbook_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('DRAFT','PUBLISHED','DISABLED')),
    latest_version INTEGER NOT NULL CHECK (latest_version > 0),
    published_version INTEGER NOT NULL DEFAULT 0 CHECK (published_version >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, playbook_id)
);

CREATE UNIQUE INDEX soar_playbooks_tenant_name_uq ON soar_playbooks(tenant_id, lower(name));
CREATE INDEX soar_playbooks_state_idx ON soar_playbooks(tenant_id, state, updated_at DESC);

CREATE TABLE soar_playbook_versions (
    tenant_id TEXT NOT NULL,
    playbook_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    state TEXT NOT NULL CHECK (state IN ('DRAFT','VALIDATED','PUBLISHED','RETIRED')),
    spec JSONB NOT NULL CHECK (jsonb_typeof(spec) = 'object'),
    spec_hash TEXT NOT NULL,
    validation JSONB NOT NULL CHECK (jsonb_typeof(validation) = 'object'),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    validated_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, playbook_id, version),
    FOREIGN KEY (tenant_id, playbook_id) REFERENCES soar_playbooks(tenant_id, playbook_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX soar_one_published_version_uq ON soar_playbook_versions(tenant_id, playbook_id)
    WHERE state = 'PUBLISHED';

CREATE TABLE soar_executions (
    tenant_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    playbook_id TEXT NOT NULL,
    playbook_version INTEGER NOT NULL,
    request_id TEXT NOT NULL,
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('MANUAL','ALERT','INCIDENT')),
    trigger_resource_type TEXT NOT NULL DEFAULT '',
    trigger_resource_id TEXT NOT NULL DEFAULT '',
    context JSONB NOT NULL CHECK (jsonb_typeof(context) = 'object'),
    status TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','WAITING_APPROVAL','WAITING_MANUAL','SUCCEEDED','FAILED','CANCELLED')),
    version INTEGER NOT NULL CHECK (version > 0),
    triggered_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, execution_id),
    UNIQUE (tenant_id, request_id),
    FOREIGN KEY (tenant_id, playbook_id, playbook_version)
        REFERENCES soar_playbook_versions(tenant_id, playbook_id, version) ON DELETE RESTRICT
);

CREATE INDEX soar_executions_status_idx ON soar_executions(tenant_id, status, updated_at);
CREATE INDEX soar_executions_playbook_idx ON soar_executions(tenant_id, playbook_id, created_at DESC);

CREATE TABLE soar_node_executions (
    tenant_id TEXT NOT NULL,
    node_execution_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    node_name TEXT NOT NULL,
    depends_on JSONB NOT NULL CHECK (jsonb_typeof(depends_on) = 'array'),
    config JSONB NOT NULL CHECK (jsonb_typeof(config) = 'object'),
    status TEXT NOT NULL CHECK (status IN ('PENDING','READY','RUNNING','WAITING_APPROVAL','WAITING_MANUAL','SUCCEEDED','SKIPPED','FAILED','CANCELLED')),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    available_at TIMESTAMPTZ NOT NULL,
    output JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(output) = 'object'),
    error_code TEXT NOT NULL DEFAULT '',
    error_detail TEXT NOT NULL DEFAULT '',
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_until TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, node_execution_id),
    UNIQUE (tenant_id, execution_id, node_id),
    FOREIGN KEY (tenant_id, execution_id) REFERENCES soar_executions(tenant_id, execution_id) ON DELETE RESTRICT
);

CREATE INDEX soar_nodes_ready_idx ON soar_node_executions(status, available_at, lease_until)
    WHERE status IN ('READY','RUNNING');

CREATE TABLE soar_approvals (
    tenant_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    node_execution_id TEXT NOT NULL,
    risk_level SMALLINT NOT NULL CHECK (risk_level BETWEEN 0 AND 6),
    required_approvals SMALLINT NOT NULL CHECK (required_approvals BETWEEN 1 AND 2),
    status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED','CANCELLED')),
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, approval_id),
    UNIQUE (tenant_id, node_execution_id),
    FOREIGN KEY (tenant_id, execution_id) REFERENCES soar_executions(tenant_id, execution_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, node_execution_id) REFERENCES soar_node_executions(tenant_id, node_execution_id) ON DELETE RESTRICT
);

CREATE TABLE soar_approval_decisions (
    tenant_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
    reason TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, approval_id, approver),
    FOREIGN KEY (tenant_id, approval_id) REFERENCES soar_approvals(tenant_id, approval_id) ON DELETE RESTRICT
);

CREATE TABLE soar_action_attempts (
    tenant_id TEXT NOT NULL,
    action_attempt_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    node_execution_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    risk_level SMALLINT NOT NULL CHECK (risk_level BETWEEN 0 AND 6),
    mode TEXT NOT NULL CHECK (mode IN ('DRY_RUN','LIVE')),
    status TEXT NOT NULL CHECK (status IN ('PLANNED','RUNNING','SUCCEEDED','FAILED','VERIFICATION_FAILED','COMPENSATED')),
    request JSONB NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    result JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(result) = 'object'),
    error_class TEXT NOT NULL DEFAULT '',
    error_detail TEXT NOT NULL DEFAULT '',
    verification_status TEXT NOT NULL DEFAULT '',
    compensation_status TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, action_attempt_id),
    UNIQUE (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, execution_id) REFERENCES soar_executions(tenant_id, execution_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, node_execution_id) REFERENCES soar_node_executions(tenant_id, node_execution_id) ON DELETE RESTRICT
);

CREATE INDEX soar_action_attempts_execution_idx ON soar_action_attempts(tenant_id, execution_id, created_at);
