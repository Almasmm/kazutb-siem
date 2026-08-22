package core

import "time"

type RetentionPolicy struct {
	TenantID       string    `json:"tenant_id"`
	RawDays        int       `json:"raw_days"`
	NormalizedDays int       `json:"normalized_days"`
	FindingsDays   int       `json:"findings_days"`
	EvidenceDays   int       `json:"evidence_days"`
	UpdatedBy      string    `json:"updated_by"`
	Version        int       `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
