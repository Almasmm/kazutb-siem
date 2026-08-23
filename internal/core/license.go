package core

import "time"

const (
	LicenseModuleSIEMCore    = "SIEM_CORE"
	LicenseModuleSOCCore     = "SOC_CORE"
	LicenseModuleSOAR        = "SOAR"
	LicenseModuleAISOC       = "AI_SOC"
	LicenseModuleUEBA        = "UEBA"
	LicenseModuleThreatIntel = "THREAT_INTEL"
	LicenseModuleMSSP        = "MSSP"
	LicenseModuleXDR         = "XDR"
)

var LicenseModules = []string{
	LicenseModuleSIEMCore, LicenseModuleSOCCore, LicenseModuleSOAR, LicenseModuleAISOC,
	LicenseModuleUEBA, LicenseModuleThreatIntel, LicenseModuleMSSP, LicenseModuleXDR,
}

type LicenseLimits struct {
	EPS               int     `json:"eps,omitempty"`
	EventsPerDay      int64   `json:"events_per_day,omitempty"`
	GBPerDay          float64 `json:"gb_per_day,omitempty"`
	RetentionDays     int     `json:"retention_days,omitempty"`
	Assets            int     `json:"assets,omitempty"`
	Analysts          int     `json:"analysts,omitempty"`
	Tenants           int     `json:"tenants,omitempty"`
	AIRequestsPerDay  int64   `json:"ai_requests_per_day,omitempty"`
	PremiumConnectors int     `json:"premium_connectors,omitempty"`
}

type LicensePolicy struct {
	IngestAfterExpiry string `json:"ingest_after_expiry"`
	ReadOnlyOnExpiry  bool   `json:"read_only_on_expiry"`
}

type LicensePayload struct {
	SchemaVersion int           `json:"schema_version"`
	LicenseID     string        `json:"license_id"`
	Customer      string        `json:"customer"`
	TenantIDs     []string      `json:"tenant_ids"`
	Modules       []string      `json:"modules"`
	Features      []string      `json:"features,omitempty"`
	Limits        LicenseLimits `json:"limits"`
	Policy        LicensePolicy `json:"policy"`
	IssuedAt      time.Time     `json:"issued_at"`
	NotBefore     time.Time     `json:"not_before"`
	ExpiresAt     time.Time     `json:"expires_at"`
	GraceUntil    time.Time     `json:"grace_until"`
}

type LicenseEnvelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type LicenseRecord struct {
	TenantID    string          `json:"tenant_id"`
	LicenseID   string          `json:"license_id"`
	KeyID       string          `json:"key_id"`
	Payload     LicensePayload  `json:"payload"`
	Envelope    LicenseEnvelope `json:"envelope"`
	Fingerprint string          `json:"fingerprint_sha256"`
	InstalledBy string          `json:"installed_by"`
	RequestID   string          `json:"request_id,omitempty"`
	Active      bool            `json:"active"`
	InstalledAt time.Time       `json:"installed_at"`
}

type LicenseModuleStatus struct {
	Module  string `json:"module"`
	Enabled bool   `json:"enabled"`
}

type LicenseLimitStatus struct {
	Name     string  `json:"name"`
	Used     float64 `json:"used"`
	Limit    float64 `json:"limit"`
	Unit     string  `json:"unit"`
	Percent  float64 `json:"percent"`
	Exceeded bool    `json:"exceeded"`
}

type LicenseStatus struct {
	TenantID  string                `json:"tenant_id"`
	State     string                `json:"state"`
	ReadOnly  bool                  `json:"read_only"`
	License   *LicenseRecord        `json:"license,omitempty"`
	Modules   []LicenseModuleStatus `json:"modules"`
	Limits    []LicenseLimitStatus  `json:"limits"`
	Features  []string              `json:"features"`
	Warnings  []string              `json:"warnings"`
	CheckedAt time.Time             `json:"checked_at"`
}

type Tenant struct {
	ID          string    `json:"tenant_id"`
	DisplayName string    `json:"display_name"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type TenantSummary struct {
	Tenant         Tenant    `json:"tenant"`
	LicenseState   string    `json:"license_state"`
	ReadOnly       bool      `json:"read_only"`
	IngestionEPS   float64   `json:"ingestion_eps"`
	Events24Hours  float64   `json:"events_24h"`
	OpenAlerts     float64   `json:"open_alerts"`
	OpenIncidents  float64   `json:"open_incidents"`
	CollectorsUp   float64   `json:"collectors_online"`
	CollectorsDown float64   `json:"collectors_offline"`
	Warnings       []string  `json:"warnings"`
	CheckedAt      time.Time `json:"checked_at"`
}

type TenantFilter struct {
	Query  string
	Limit  int
	Offset int
}
