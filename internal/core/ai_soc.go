package core

import "time"

const (
	AISOCProviderLocal = "LOCAL"
	AISOCProviderCloud = "CLOUD"

	AISOCRequestQueued    = "QUEUED"
	AISOCRequestRunning   = "RUNNING"
	AISOCRequestSucceeded = "SUCCEEDED"
	AISOCRequestFailed    = "FAILED"
	AISOCRequestBlocked   = "BLOCKED"

	AISOCDecisionAccepted = "ACCEPTED"
	AISOCDecisionRejected = "REJECTED"

	AISOCIncidentSummary    = "INCIDENT_SUMMARY"
	AISOCEventExplanation   = "EVENT_EXPLANATION"
	AISOCInvestigationSteps = "INVESTIGATION_STEPS"
	AISOCCQLGeneration      = "CQL_GENERATION"
	AISOCSigmaDraft         = "SIGMA_DRAFT"
	AISOCParserDraft        = "PARSER_DRAFT"
	AISOCMITRESuggestion    = "MITRE_SUGGESTION"
	AISOCEvidenceTimeline   = "EVIDENCE_TIMELINE"
	AISOCCaseClosureReport  = "CASE_CLOSURE_REPORT"
	AISOCExecutiveReport    = "EXECUTIVE_REPORT"
)

type AISOCPolicy struct {
	TenantID            string    `json:"tenant_id"`
	Enabled             bool      `json:"enabled"`
	CloudAllowed        bool      `json:"cloud_allowed"`
	PIIRedaction        bool      `json:"pii_redaction"`
	MaximumContextItems int       `json:"maximum_context_items"`
	LocalModel          string    `json:"local_model"`
	CloudModel          string    `json:"cloud_model,omitempty"`
	Version             int       `json:"version"`
	UpdatedBy           string    `json:"updated_by"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type AISOCContextRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type AISOCContextDocument struct {
	Ref     AISOCContextRef        `json:"ref"`
	Content map[string]interface{} `json:"content"`
}

type AISOCRecommendation struct {
	Summary            string            `json:"summary"`
	KeyFindings        []string          `json:"key_findings"`
	InvestigationSteps []string          `json:"investigation_steps"`
	SuggestedQueries   []string          `json:"suggested_queries"`
	SigmaDraft         string            `json:"sigma_draft,omitempty"`
	ParserDraft        string            `json:"parser_draft,omitempty"`
	MITRE              []string          `json:"mitre"`
	Limitations        []string          `json:"limitations"`
	Citations          []AISOCContextRef `json:"citations"`
	Confidence         int               `json:"confidence"`
	Disclaimer         string            `json:"disclaimer"`
}

type AISOCRequest struct {
	ID                      string                 `json:"request_id"`
	TenantID                string                 `json:"tenant_id"`
	IdempotencyKey          string                 `json:"-"`
	RequestHash             string                 `json:"request_hash"`
	Function                string                 `json:"function"`
	Question                string                 `json:"question,omitempty"`
	ContextRefs             []AISOCContextRef      `json:"context_refs"`
	ContextDocuments        []AISOCContextDocument `json:"-"`
	ContextDigest           string                 `json:"context_digest,omitempty"`
	Status                  string                 `json:"status"`
	Provider                string                 `json:"provider"`
	Model                   string                 `json:"model"`
	Recommendation          AISOCRecommendation    `json:"recommendation"`
	RequestedBy             string                 `json:"requested_by"`
	PromptInjectionDetected bool                   `json:"prompt_injection_detected"`
	RedactionCount          int                    `json:"redaction_count"`
	FailureClass            string                 `json:"failure_class,omitempty"`
	FailureDetail           string                 `json:"failure_detail,omitempty"`
	Attempt                 int                    `json:"attempt"`
	Version                 int                    `json:"version"`
	LeaseOwner              string                 `json:"-"`
	LeaseExpiresAt          *time.Time             `json:"-"`
	CreatedAt               time.Time              `json:"created_at"`
	StartedAt               *time.Time             `json:"started_at,omitempty"`
	CompletedAt             *time.Time             `json:"completed_at,omitempty"`
	UpdatedAt               time.Time              `json:"updated_at"`
}

type AISOCRequestFilter struct {
	Status      string
	Function    string
	Provider    string
	RequestedBy string
	Limit       int
}

type AISOCDecision struct {
	ID        string    `json:"decision_id"`
	TenantID  string    `json:"tenant_id"`
	RequestID string    `json:"request_id"`
	Decision  string    `json:"decision"`
	Reason    string    `json:"reason"`
	DecidedBy string    `json:"decided_by"`
	CreatedAt time.Time `json:"created_at"`
}

type AISOCRequestDetails struct {
	Request  AISOCRequest   `json:"request"`
	Decision *AISOCDecision `json:"decision,omitempty"`
}
