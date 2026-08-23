package core

import "time"

const (
	ServiceAccountStateActive  = "ACTIVE"
	ServiceAccountStateExpired = "EXPIRED"
	ServiceAccountStateRevoked = "REVOKED"
)

type ServiceAccount struct {
	ID           string     `json:"service_account_id"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	Description  string     `json:"description,omitempty"`
	Scopes       []string   `json:"scopes"`
	State        string     `json:"state"`
	TokenVersion int        `json:"token_version"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

type ServiceAccountTokenIssue struct {
	AccessToken    string         `json:"access_token"`
	TokenType      string         `json:"token_type"`
	ServiceAccount ServiceAccount `json:"service_account"`
}
