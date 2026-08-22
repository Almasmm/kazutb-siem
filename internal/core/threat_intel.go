package core

import "time"

type ThreatIndicatorType string

const (
	ThreatIndicatorIPv4                   ThreatIndicatorType = "IPV4"
	ThreatIndicatorIPv6                   ThreatIndicatorType = "IPV6"
	ThreatIndicatorDomain                 ThreatIndicatorType = "DOMAIN"
	ThreatIndicatorURL                    ThreatIndicatorType = "URL"
	ThreatIndicatorHash                   ThreatIndicatorType = "HASH"
	ThreatIndicatorEmail                  ThreatIndicatorType = "EMAIL"
	ThreatIndicatorCertificateFingerprint ThreatIndicatorType = "CERTIFICATE_FINGERPRINT"
)

const (
	ThreatIntelStateActive   = "ACTIVE"
	ThreatIntelStateDisabled = "DISABLED"
	ThreatIntelStateRevoked  = "REVOKED"
	ThreatIntelStateExpired  = "EXPIRED"
)

type ThreatIntelFeed struct {
	ID                     string    `json:"feed_id"`
	TenantID               string    `json:"tenant_id"`
	Name                   string    `json:"name"`
	Kind                   string    `json:"kind"`
	Description            string    `json:"description,omitempty"`
	State                  string    `json:"state"`
	SourceURL              string    `json:"source_url,omitempty"`
	AuthReference          string    `json:"auth_reference,omitempty"`
	RefreshIntervalSeconds int       `json:"refresh_interval_seconds"`
	DefaultConfidence      int       `json:"default_confidence"`
	Tags                   []string  `json:"tags"`
	Version                int       `json:"version"`
	CreatedBy              string    `json:"created_by"`
	UpdatedBy              string    `json:"updated_by"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type ThreatIndicator struct {
	ID              string              `json:"indicator_id"`
	TenantID        string              `json:"tenant_id"`
	FeedID          string              `json:"feed_id"`
	Type            ThreatIndicatorType `json:"type"`
	Value           string              `json:"value"`
	NormalizedValue string              `json:"normalized_value"`
	Source          string              `json:"source"`
	Confidence      int                 `json:"confidence"`
	Reputation      string              `json:"reputation"`
	TTLSeconds      int64               `json:"ttl_seconds"`
	FirstSeen       time.Time           `json:"first_seen"`
	LastSeen        time.Time           `json:"last_seen"`
	ValidFrom       time.Time           `json:"valid_from"`
	ValidUntil      *time.Time          `json:"valid_until,omitempty"`
	Tags            []string            `json:"tags"`
	Campaign        string              `json:"campaign,omitempty"`
	Malware         string              `json:"malware,omitempty"`
	ThreatActors    []string            `json:"threat_actors"`
	Description     string              `json:"description,omitempty"`
	ExternalID      string              `json:"external_id,omitempty"`
	State           string              `json:"state"`
	Version         int                 `json:"version"`
	CreatedBy       string              `json:"created_by"`
	UpdatedBy       string              `json:"updated_by"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

type ThreatIndicatorFilter struct {
	FeedID string
	Type   ThreatIndicatorType
	State  string
	Query  string
	Limit  int
}

type ThreatObservable struct {
	Type            ThreatIndicatorType `json:"type"`
	NormalizedValue string              `json:"normalized_value"`
	Field           string              `json:"field"`
	RawValue        string              `json:"raw_value"`
}

type ThreatIntelMatch struct {
	ID               string              `json:"match_id"`
	TenantID         string              `json:"tenant_id"`
	IndicatorID      string              `json:"indicator_id"`
	IndicatorVersion int                 `json:"indicator_version"`
	FeedID           string              `json:"feed_id"`
	EventID          string              `json:"event_id"`
	Type             ThreatIndicatorType `json:"type"`
	Value            string              `json:"value"`
	MatchedField     string              `json:"matched_field"`
	MatchedValue     string              `json:"matched_value"`
	Confidence       int                 `json:"confidence"`
	Reputation       string              `json:"reputation"`
	MatchedAt        time.Time           `json:"matched_at"`
}
