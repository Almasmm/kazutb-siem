package core

import "time"

const (
	ReportTypeExecutive = "EXECUTIVE_SECURITY"
	ReportTypeSOC       = "SOC_OPERATIONS"
	ReportTypeIncident  = "INCIDENT"
	ReportTypeCase      = "CASE_CLOSURE"
)

type ReportMetric struct {
	Key   string  `json:"key"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit,omitempty"`
}

type ReportBucket struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type ReportParameters struct {
	Start      time.Time `json:"start,omitempty"`
	End        time.Time `json:"end,omitempty"`
	IncidentID string    `json:"incident_id,omitempty"`
	CaseID     string    `json:"case_id,omitempty"`
}

type ReportRun struct {
	ID          string                 `json:"report_id"`
	TenantID    string                 `json:"tenant_id,omitempty"`
	Type        string                 `json:"report_type"`
	Title       string                 `json:"title"`
	Status      string                 `json:"status"`
	Parameters  ReportParameters       `json:"parameters"`
	Snapshot    map[string]interface{} `json:"snapshot"`
	Checksum    string                 `json:"checksum_sha256"`
	CreatedBy   string                 `json:"created_by"`
	RequestID   string                 `json:"request_id,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
}

type ReportFilter struct {
	Type   string
	Status string
	Limit  int
}
