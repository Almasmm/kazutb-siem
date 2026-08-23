package core

import "time"

type EntityType string

const (
	EntityTypeUser        EntityType = "USER"
	EntityTypeAccount     EntityType = "ACCOUNT"
	EntityTypeDevice      EntityType = "DEVICE"
	EntityTypeServer      EntityType = "SERVER"
	EntityTypeIP          EntityType = "IP"
	EntityTypeMAC         EntityType = "MAC"
	EntityTypeDomain      EntityType = "DOMAIN"
	EntityTypeProcess     EntityType = "PROCESS"
	EntityTypeFile        EntityType = "FILE"
	EntityTypeHash        EntityType = "HASH"
	EntityTypeApplication EntityType = "APPLICATION"
	EntityTypeService     EntityType = "SERVICE"
	EntityTypeIOC         EntityType = "IOC"
)

type SecurityEntity struct {
	ID               string            `json:"entity_id"`
	TenantID         string            `json:"tenant_id,omitempty"`
	Type             EntityType        `json:"entity_type"`
	NaturalKey       string            `json:"natural_key"`
	DisplayName      string            `json:"display_name"`
	Label            string            `json:"label,omitempty"`
	RiskScore        int               `json:"risk_score"`
	Criticality      string            `json:"criticality,omitempty"`
	Attributes       map[string]string `json:"attributes,omitempty"`
	FirstSeen        time.Time         `json:"first_seen"`
	LastSeen         time.Time         `json:"last_seen"`
	ObservationCount int64             `json:"observation_count"`
	LastEventID      string            `json:"last_event_id,omitempty"`
	Version          int               `json:"version"`
}

type EntityRelation struct {
	ID               string            `json:"relation_id"`
	TenantID         string            `json:"tenant_id,omitempty"`
	Type             string            `json:"relation_type"`
	SourceEntityID   string            `json:"source_entity_id"`
	TargetEntityID   string            `json:"target_entity_id"`
	Attributes       map[string]string `json:"attributes,omitempty"`
	FirstSeen        time.Time         `json:"first_seen"`
	LastSeen         time.Time         `json:"last_seen"`
	ObservationCount int64             `json:"observation_count"`
	LastEventID      string            `json:"last_event_id,omitempty"`
	Version          int               `json:"version"`
}

type EntityProjection struct {
	Entities  []SecurityEntity `json:"entities"`
	Relations []EntityRelation `json:"relations"`
}

type EntityFilter struct {
	Type        EntityType
	Query       string
	MinimumRisk int
	Limit       int
}

type EntityGraph struct {
	Root              SecurityEntity   `json:"root"`
	Entities          []SecurityEntity `json:"entities"`
	Relations         []EntityRelation `json:"relations"`
	EventIDs          []string         `json:"event_ids"`
	Depth             int              `json:"depth"`
	TotalObservations int64            `json:"total_observations"`
}
