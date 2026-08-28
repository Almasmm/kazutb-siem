package core

import "time"

type Collector struct {
	ID             string                 `json:"collector_id"`
	TenantID       string                 `json:"tenant_id"`
	Name           string                 `json:"name"`
	Type           string                 `json:"type"`
	AuthSubject    string                 `json:"auth_subject"`
	State          string                 `json:"state"`
	Health         string                 `json:"health"`
	Capabilities   []string               `json:"capabilities"`
	Version        string                 `json:"version,omitempty"`
	ObservedIP     string                 `json:"observed_ip,omitempty"`
	HealthMetadata map[string]interface{} `json:"health_metadata,omitempty"`
	// Operational is derived server-side from HealthMetadata and heartbeat
	// recency so every client sees one consistent health policy.
	Operational *CollectorOperational `json:"operational,omitempty"`
	LastSeenAt     *time.Time             `json:"last_seen_at,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type CollectorHeartbeat struct {
	Version  string                 `json:"version"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}
