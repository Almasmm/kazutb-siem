package core

import "time"

const (
	SOARConnectorKindWebhook         = "WEBHOOK"
	SOARConnectorKindFirewallREST    = "FIREWALL_REST"
	SOARConnectorKindITSMREST        = "ITSM_REST"
	SOARConnectorKindKCSPAPI         = "KCSP_API"
	SOARConnectorKindThreatIntelREST = "THREAT_INTEL_REST"
	SOARConnectorKindNotification    = "NOTIFICATION_REST"
	SOARConnectorKindEDRXDRREST      = "EDR_XDR_REST"
	SOARConnectorKindEmailSMTP       = "EMAIL_SMTP"
	SOARConnectorKindLDAPDirectory   = "LDAP_DIRECTORY"
)

const (
	SOARConnectorAuthNone   = "NONE"
	SOARConnectorAuthBearer = "BEARER"
	SOARConnectorAuthHMAC   = "HMAC_SHA256"
	SOARConnectorAuthBasic  = "BASIC"
	SOARConnectorAuthAPIKey = "API_KEY"
)

const (
	SOARConnectorConfigured        = "CONFIGURED"
	SOARConnectorCredentialsNeeded = "CREDENTIALS_REQUIRED"
	SOARConnectorReady             = "READY"
	SOARConnectorDegraded          = "DEGRADED"
	SOARConnectorDisabled          = "DISABLED"

	SOARConnectorHealthUnknown     = "UNKNOWN"
	SOARConnectorHealthHealthy     = "HEALTHY"
	SOARConnectorHealthUnhealthy   = "UNHEALTHY"
	SOARConnectorHealthCredentials = "CREDENTIALS_REQUIRED"

	SOARConnectorTestQueued      = "QUEUED"
	SOARConnectorTestRunning     = "RUNNING"
	SOARConnectorTestSucceeded   = "SUCCEEDED"
	SOARConnectorTestFailed      = "FAILED"
	SOARConnectorTestCredentials = "CREDENTIALS_REQUIRED"
	SOARConnectorTestCancelled   = "CANCELLED"
)

type SOARConnector struct {
	ID                 string                 `json:"connector_id"`
	TenantID           string                 `json:"tenant_id"`
	Name               string                 `json:"name"`
	Kind               string                 `json:"kind"`
	State              string                 `json:"state"`
	Endpoint           string                 `json:"endpoint"`
	AuthType           string                 `json:"auth_type"`
	SecretRef          string                 `json:"secret_ref,omitempty"`
	AllowedActions     []string               `json:"allowed_actions"`
	Settings           map[string]interface{} `json:"settings"`
	TimeoutSeconds     int                    `json:"timeout_seconds"`
	Retry              SOARRetryPolicy        `json:"retry"`
	RateLimitPerMinute int                    `json:"rate_limit_per_minute"`
	Version            int                    `json:"version"`
	HealthStatus       string                 `json:"health_status"`
	HealthErrorClass   string                 `json:"health_error_class,omitempty"`
	HealthDetail       string                 `json:"health_detail,omitempty"`
	LastTestedAt       *time.Time             `json:"last_tested_at,omitempty"`
	CreatedBy          string                 `json:"created_by"`
	UpdatedBy          string                 `json:"updated_by"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

type SOARConnectorFilter struct {
	Kind  string
	State string
	Limit int
}

type SOARConnectorTest struct {
	ID          string     `json:"test_id"`
	TenantID    string     `json:"tenant_id"`
	ConnectorID string     `json:"connector_id"`
	RequestID   string     `json:"request_id"`
	Status      string     `json:"status"`
	ErrorClass  string     `json:"error_class,omitempty"`
	Detail      string     `json:"detail,omitempty"`
	HTTPStatus  int        `json:"http_status,omitempty"`
	LatencyMS   int64      `json:"latency_ms,omitempty"`
	TestedBy    string     `json:"tested_by"`
	WorkerID    string     `json:"worker_id,omitempty"`
	Attempt     int        `json:"attempt"`
	LeaseUntil  *time.Time `json:"lease_until,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type SOARConnectorTestWorkItem struct {
	Connector SOARConnector     `json:"connector"`
	Test      SOARConnectorTest `json:"test"`
}
