package core

import "time"

const (
	SOARPlaybookDraft     = "DRAFT"
	SOARPlaybookPublished = "PUBLISHED"
	SOARPlaybookDisabled  = "DISABLED"
)

const (
	SOARVersionDraft     = "DRAFT"
	SOARVersionValidated = "VALIDATED"
	SOARVersionPublished = "PUBLISHED"
	SOARVersionRetired   = "RETIRED"
)

const (
	SOARExecutionQueued          = "QUEUED"
	SOARExecutionRunning         = "RUNNING"
	SOARExecutionWaitingApproval = "WAITING_APPROVAL"
	SOARExecutionWaitingManual   = "WAITING_MANUAL"
	SOARExecutionSucceeded       = "SUCCEEDED"
	SOARExecutionFailed          = "FAILED"
	SOARExecutionCancelled       = "CANCELLED"
)

type ApprovalDecision string

const (
	ApprovalDecisionApprove ApprovalDecision = "APPROVE"
	ApprovalDecisionReject  ApprovalDecision = "REJECT"
)

func (decision ApprovalDecision) Valid() bool {
	return decision == ApprovalDecisionApprove || decision == ApprovalDecisionReject
}

type ApprovalStatus string

const (
	ApprovalStatusPending   ApprovalStatus = "PENDING"
	ApprovalStatusApproved  ApprovalStatus = "APPROVED"
	ApprovalStatusRejected  ApprovalStatus = "REJECTED"
	ApprovalStatusExpired   ApprovalStatus = "EXPIRED"
	ApprovalStatusCancelled ApprovalStatus = "CANCELLED"
)

const (
	SOARNodeTrigger      = "TRIGGER"
	SOARNodeCondition    = "CONDITION"
	SOARNodeAction       = "ACTION"
	SOARNodeTransform    = "TRANSFORM"
	SOARNodeLoop         = "LOOP"
	SOARNodeParallel     = "PARALLEL"
	SOARNodeDelay        = "DELAY"
	SOARNodeRetry        = "RETRY"
	SOARNodeApproval     = "HUMAN_APPROVAL"
	SOARNodeSubPlaybook  = "SUB_PLAYBOOK"
	SOARNodeManualTask   = "MANUAL_TASK"
	SOARNodeWebhook      = "WEBHOOK"
	SOARNodeNotification = "NOTIFICATION"
)

type SOARRetryPolicy struct {
	MaximumAttempts int `json:"maximum_attempts"`
	BackoffSeconds  int `json:"backoff_seconds"`
	MaximumBackoff  int `json:"maximum_backoff_seconds"`
}

type SOARTrigger struct {
	Type string `json:"type"`
}

type SOARNode struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	Name           string                 `json:"name"`
	DependsOn      []string               `json:"depends_on,omitempty"`
	TimeoutSeconds int                    `json:"timeout_seconds,omitempty"`
	Retry          SOARRetryPolicy        `json:"retry,omitempty"`
	Config         map[string]interface{} `json:"config,omitempty"`
}

type SOARPlaybookSpec struct {
	SchemaVersion string      `json:"schema_version"`
	Trigger       SOARTrigger `json:"trigger"`
	Nodes         []SOARNode  `json:"nodes"`
}

type SOARValidationIssue struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

type SOARValidationReport struct {
	Valid       bool                  `json:"valid"`
	SpecHash    string                `json:"spec_hash"`
	NodeCount   int                   `json:"node_count"`
	Issues      []SOARValidationIssue `json:"issues"`
	ValidatedAt time.Time             `json:"validated_at"`
}

type SOARPlaybook struct {
	ID               string    `json:"playbook_id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	Description      string    `json:"description,omitempty"`
	State            string    `json:"state"`
	LatestVersion    int       `json:"latest_version"`
	PublishedVersion int       `json:"published_version,omitempty"`
	Revision         int       `json:"revision"`
	CreatedBy        string    `json:"created_by"`
	UpdatedBy        string    `json:"updated_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type SOARPlaybookVersion struct {
	TenantID    string               `json:"tenant_id"`
	PlaybookID  string               `json:"playbook_id"`
	Version     int                  `json:"version"`
	State       string               `json:"state"`
	Spec        SOARPlaybookSpec     `json:"spec"`
	SpecHash    string               `json:"spec_hash"`
	Validation  SOARValidationReport `json:"validation"`
	CreatedBy   string               `json:"created_by"`
	CreatedAt   time.Time            `json:"created_at"`
	ValidatedAt *time.Time           `json:"validated_at,omitempty"`
	PublishedAt *time.Time           `json:"published_at,omitempty"`
}

type SOARPlaybookDetails struct {
	Playbook SOARPlaybook          `json:"playbook"`
	Versions []SOARPlaybookVersion `json:"versions"`
}

type SOARExecution struct {
	ID                  string                 `json:"execution_id"`
	TenantID            string                 `json:"tenant_id"`
	PlaybookID          string                 `json:"playbook_id"`
	PlaybookVersion     int                    `json:"playbook_version"`
	RequestID           string                 `json:"request_id"`
	TriggerType         string                 `json:"trigger_type"`
	TriggerResourceType string                 `json:"trigger_resource_type,omitempty"`
	TriggerResourceID   string                 `json:"trigger_resource_id,omitempty"`
	Context             map[string]interface{} `json:"context"`
	Status              string                 `json:"status"`
	Version             int                    `json:"version"`
	TriggeredBy         string                 `json:"triggered_by"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	StartedAt           *time.Time             `json:"started_at,omitempty"`
	CompletedAt         *time.Time             `json:"completed_at,omitempty"`
	Nodes               []SOARNodeExecution    `json:"nodes"`
}

type SOARNodeExecution struct {
	ID             string                 `json:"node_execution_id"`
	TenantID       string                 `json:"tenant_id"`
	ExecutionID    string                 `json:"execution_id"`
	NodeID         string                 `json:"node_id"`
	NodeType       string                 `json:"node_type"`
	NodeName       string                 `json:"node_name"`
	DependsOn      []string               `json:"depends_on"`
	Config         map[string]interface{} `json:"config"`
	TimeoutSeconds int                    `json:"timeout_seconds"`
	Retry          SOARRetryPolicy        `json:"retry"`
	Status         string                 `json:"status"`
	Attempt        int                    `json:"attempt"`
	AvailableAt    time.Time              `json:"available_at"`
	Output         map[string]interface{} `json:"output,omitempty"`
	ErrorCode      string                 `json:"error_code,omitempty"`
	ErrorDetail    string                 `json:"error_detail,omitempty"`
	LeaseOwner     string                 `json:"lease_owner,omitempty"`
	LeaseUntil     *time.Time             `json:"lease_until,omitempty"`
	StartedAt      *time.Time             `json:"started_at,omitempty"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type SOARWorkItem struct {
	Execution SOARExecution     `json:"execution"`
	Node      SOARNodeExecution `json:"node"`
}

type SOARApprovalDecision struct {
	Approver  string           `json:"approver"`
	Decision  ApprovalDecision `json:"decision"`
	Reason    string           `json:"reason"`
	DecidedAt time.Time        `json:"decided_at"`
}

type SOARApproval struct {
	ID                string                 `json:"approval_id"`
	TenantID          string                 `json:"tenant_id"`
	ExecutionID       string                 `json:"execution_id"`
	NodeExecutionID   string                 `json:"node_execution_id"`
	RiskLevel         int                    `json:"risk_level"`
	RequiredApprovals int                    `json:"required_approvals"`
	Status            ApprovalStatus         `json:"status"`
	Version           int                    `json:"version"`
	RequestedBy       string                 `json:"requested_by"`
	RequestedAt       time.Time              `json:"requested_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	DecidedAt         *time.Time             `json:"decided_at,omitempty"`
	Decisions         []SOARApprovalDecision `json:"decisions"`
}

type SOARApprovalCommand struct {
	Decision      ApprovalDecision
	Reason        string
	Version       int
	RequestID     string
	CorrelationID string
	ActorType     string
	Source        map[string]interface{}
}

type SOARApprovalFilter struct {
	Status      string
	ExecutionID string
	Limit       int
}

type SOARActionAttempt struct {
	ID                 string                 `json:"action_attempt_id"`
	TenantID           string                 `json:"tenant_id"`
	ExecutionID        string                 `json:"execution_id"`
	NodeExecutionID    string                 `json:"node_execution_id"`
	IdempotencyKey     string                 `json:"idempotency_key"`
	ConnectorID        string                 `json:"connector_id"`
	ActionType         string                 `json:"action_type"`
	RiskLevel          int                    `json:"risk_level"`
	Mode               string                 `json:"mode"`
	Status             string                 `json:"status"`
	Request            map[string]interface{} `json:"request"`
	Result             map[string]interface{} `json:"result"`
	ErrorClass         string                 `json:"error_class,omitempty"`
	ErrorDetail        string                 `json:"error_detail,omitempty"`
	VerificationStatus string                 `json:"verification_status,omitempty"`
	CompensationStatus string                 `json:"compensation_status,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

type SOARExecutionFilter struct {
	PlaybookID string
	Status     string
	Limit      int
}
