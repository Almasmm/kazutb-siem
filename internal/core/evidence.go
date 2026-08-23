package core

import "time"

type EvidenceItem struct {
	ID              string                 `json:"evidence_id"`
	TenantID        string                 `json:"tenant_id"`
	RequestID       string                 `json:"request_id"`
	CaseID          string                 `json:"case_id,omitempty"`
	IncidentID      string                 `json:"incident_id,omitempty"`
	AlertID         string                 `json:"alert_id,omitempty"`
	EventID         string                 `json:"event_id,omitempty"`
	Filename        string                 `json:"filename"`
	ContentType     string                 `json:"content_type"`
	Description     string                 `json:"description,omitempty"`
	Size            int64                  `json:"size"`
	SHA256          string                 `json:"sha256"`
	Bucket          string                 `json:"bucket"`
	ObjectKey       string                 `json:"object_key"`
	ObjectVersion   string                 `json:"object_version,omitempty"`
	ETag            string                 `json:"etag,omitempty"`
	Status          string                 `json:"status"`
	Failure         string                 `json:"failure,omitempty"`
	RetainUntil     time.Time              `json:"retain_until"`
	LegalHold       bool                   `json:"legal_hold"`
	Uploader        string                 `json:"uploader"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	VerifiedAt      *time.Time             `json:"verified_at,omitempty"`
	CustodyHeadHash string                 `json:"custody_head_hash"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

type EvidenceMutation struct {
	Actor     string                 `json:"actor"`
	Action    string                 `json:"action"`
	Reason    string                 `json:"reason"`
	RequestID string                 `json:"request_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type EvidenceCustodyEntry struct {
	Sequence     int64                  `json:"sequence"`
	ID           string                 `json:"custody_id"`
	TenantID     string                 `json:"tenant_id"`
	EvidenceID   string                 `json:"evidence_id"`
	Actor        string                 `json:"actor"`
	Action       string                 `json:"action"`
	Reason       string                 `json:"reason"`
	RequestID    string                 `json:"request_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	PreviousHash string                 `json:"previous_hash"`
	Hash         string                 `json:"hash"`
	CreatedAt    time.Time              `json:"created_at"`
}

type EvidenceFilter struct {
	CaseID     string
	IncidentID string
	AlertID    string
	EventID    string
	Status     string
	Limit      int
}

type EvidenceVerification struct {
	EvidenceID string    `json:"evidence_id"`
	Expected   string    `json:"expected_sha256"`
	Actual     string    `json:"actual_sha256"`
	Size       int64     `json:"size"`
	Valid      bool      `json:"valid"`
	VerifiedAt time.Time `json:"verified_at"`
}
