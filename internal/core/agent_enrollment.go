package core

import "time"

const (
	AgentEnrollmentStateActive    = "ACTIVE"
	AgentEnrollmentStateRevoked   = "REVOKED"
	AgentEnrollmentStateExhausted = "EXHAUSTED"
	AgentEnrollmentStateExpired   = "EXPIRED"
)

type AgentEnrollmentToken struct {
	ID            string     `json:"token_id"`
	TenantID      string     `json:"tenant_id"`
	Label         string     `json:"label"`
	CollectorType string     `json:"collector_type"`
	Capabilities  []string   `json:"capabilities"`
	State         string     `json:"state"`
	ExpiresAt     time.Time  `json:"expires_at"`
	MaxUses       int        `json:"max_uses"`
	UseCount      int        `json:"use_count"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
}

type AgentEnrollmentTokenIssue struct {
	EnrollmentToken string               `json:"enrollment_token"`
	Token           AgentEnrollmentToken `json:"token"`
}

type AgentCredential struct {
	ID          string     `json:"credential_id"`
	TenantID    string     `json:"tenant_id"`
	CollectorID string     `json:"collector_id"`
	AuthSubject string     `json:"auth_subject"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type AgentEnrollmentRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	AgentID         string `json:"agent_id"`
	Name            string `json:"name"`
	Hostname        string `json:"hostname"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Architecture    string `json:"architecture"`
}

type AgentCredentialGrant struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type AgentEnrollmentResponse struct {
	Collector  Collector            `json:"collector"`
	Credential AgentCredentialGrant `json:"credential"`
}
