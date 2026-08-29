package core

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const (
	DefaultTenantID = "university-kulazhanov"
	LabTenantID     = "kcsp-lab"
)

type Severity string

const (
	SeverityCritical      Severity = "CRITICAL"
	SeverityHigh          Severity = "HIGH"
	SeverityMedium        Severity = "MEDIUM"
	SeverityLow           Severity = "LOW"
	SeverityInformational Severity = "INFORMATIONAL"
)

type EventSource struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Type    string `json:"type"`
}

type SchemaRef struct {
	OCSFVersion string `json:"ocsf_version"`
	ClassUID    int    `json:"class_uid"`
}

type UserRef struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	IsPrivileged bool   `json:"is_privileged,omitempty"`
}

type DeviceRef struct {
	ID          string `json:"id,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	IP          string `json:"ip,omitempty"`
	Department  string `json:"department,omitempty"`
	Criticality int    `json:"criticality,omitempty"`
}

type EndpointRef struct {
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

type ProcessRef struct {
	Name        string `json:"name,omitempty"`
	PID         int    `json:"pid,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
}

type SecurityResult struct {
	Action  string `json:"action,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

type RawRef struct {
	Message   string `json:"message,omitempty"`
	Hash      string `json:"hash"`
	Reference string `json:"reference,omitempty"`
}

type ParserRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// CanonicalEvent is the deliberately small, OCSF-compatible V0.1 envelope.
// It is not a claim that the physical storage schema implements every OCSF field.
type CanonicalEvent struct {
	ID             string                 `json:"event_id"`
	TenantID       string                 `json:"tenant_id"`
	EventTime      time.Time              `json:"event_time"`
	IngestTime     time.Time              `json:"ingest_time"`
	CollectorID    string                 `json:"collector_id"`
	SourceID       string                 `json:"source_id,omitempty"`
	SourceAddress  string                 `json:"source_address,omitempty"`
	Category       string                 `json:"category"`
	ActivityName   string                 `json:"activity_name"`
	Source         EventSource            `json:"source"`
	Schema         SchemaRef              `json:"schema"`
	Severity       int                    `json:"severity"`
	Confidence     int                    `json:"confidence"`
	User           UserRef                `json:"user"`
	Device         DeviceRef              `json:"device"`
	SrcEndpoint    EndpointRef            `json:"src_endpoint"`
	DstEndpoint    EndpointRef            `json:"dst_endpoint"`
	Process        ProcessRef             `json:"process"`
	SecurityResult SecurityResult         `json:"security_result"`
	Raw            RawRef                 `json:"raw"`
	Parser         ParserRef              `json:"parser"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type RiskFactor struct {
	Code            string `json:"code"`
	Label           string `json:"label"`
	Delta           int    `json:"delta"`
	SourceReference string `json:"source_reference,omitempty"`
}

type RuleRef struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Version string `json:"version"`
}

type DetectionRule struct {
	ID                  string    `json:"rule_id"`
	Title               string    `json:"title"`
	Description         string    `json:"description"`
	Version             string    `json:"version"`
	Severity            Severity  `json:"severity"`
	Confidence          int       `json:"confidence"`
	MITRE               []string  `json:"mitre"`
	RequiredDataSources []string  `json:"required_data_sources"`
	KnownFalsePositives []string  `json:"known_false_positives"`
	Owner               string    `json:"owner"`
	State               string    `json:"state"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type Finding struct {
	ID            string       `json:"finding_id"`
	TenantID      string       `json:"tenant_id"`
	EventID       string       `json:"event_id"`
	Rule          RuleRef      `json:"rule"`
	Title         string       `json:"title"`
	Severity      Severity     `json:"severity"`
	Confidence    int          `json:"confidence"`
	MITRE         []string     `json:"mitre"`
	MatchedFields []string     `json:"matched_fields"`
	RiskScore     int          `json:"risk_score"`
	RiskBreakdown []RiskFactor `json:"risk_breakdown"`
	CreatedAt     time.Time    `json:"created_at"`
}

type EntitySummary struct {
	Type  string `json:"type"`
	ID    string `json:"id,omitempty"`
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
}

type SLAInfo struct {
	AcknowledgeBy time.Time  `json:"acknowledge_by"`
	Breached      bool       `json:"breached"`
	Acknowledged  *time.Time `json:"acknowledged_at,omitempty"`
}

type Alert struct {
	ID            string        `json:"alert_id"`
	TenantID      string        `json:"tenant_id"`
	Title         string        `json:"title"`
	Severity      Severity      `json:"severity"`
	RiskScore     int           `json:"risk_score"`
	RiskBreakdown []RiskFactor  `json:"risk_breakdown"`
	Status        string        `json:"status"`
	Disposition   string        `json:"disposition,omitempty"`
	Assignee      string        `json:"assignee,omitempty"`
	Rule          RuleRef       `json:"rule"`
	MITRE         []string      `json:"mitre"`
	Entity        EntitySummary `json:"entity"`
	FindingIDs    []string      `json:"finding_ids"`
	EventIDs      []string      `json:"event_ids"`
	EventCount    int           `json:"event_count"`
	FirstSeen     time.Time     `json:"first_seen"`
	LastSeen      time.Time     `json:"last_seen"`
	SLA           SLAInfo       `json:"sla"`
	Version       int           `json:"version"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

type TimelineEntry struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Message   string                 `json:"message"`
	Actor     string                 `json:"actor"`
	CreatedAt time.Time              `json:"created_at"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

type Incident struct {
	ID                 string          `json:"incident_id"`
	TenantID           string          `json:"tenant_id"`
	Title              string          `json:"title"`
	Summary            string          `json:"summary"`
	Severity           Severity        `json:"severity"`
	Status             string          `json:"status"`
	Disposition        string          `json:"disposition,omitempty"`
	ClosureReason      string          `json:"closure_reason,omitempty"`
	Assignee           string          `json:"assignee,omitempty"`
	AlertIDs           []string        `json:"alert_ids"`
	FindingIDs         []string        `json:"finding_ids"`
	EventIDs           []string        `json:"event_ids"`
	Entities           []EntitySummary `json:"entities"`
	MITRE              []string        `json:"mitre"`
	RiskScore          int             `json:"risk_score"`
	Timeline           []TimelineEntry `json:"timeline"`
	SLA                SLAInfo         `json:"sla"`
	AllowedTransitions []string        `json:"allowed_transitions"`
	Version            int             `json:"version"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

type AuditEntry struct {
	ID           string                 `json:"audit_id"`
	TenantID     string                 `json:"tenant_id"`
	Actor        string                 `json:"actor"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Outcome      string                 `json:"outcome"`
	RequestID    string                 `json:"request_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	PreviousHash string                 `json:"previous_hash"`
	Hash         string                 `json:"hash"`
	CreatedAt    time.Time              `json:"created_at"`
}

type IngestResult struct {
	Event     CanonicalEvent `json:"event"`
	Findings  []Finding      `json:"findings"`
	Alerts    []Alert        `json:"alerts"`
	Duplicate bool           `json:"duplicate"`
}

func NewID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return prefix + "_" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func SeverityRank(value Severity) int {
	switch value {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

func SeverityFromRisk(score int) Severity {
	switch {
	case score >= 85:
		return SeverityCritical
	case score >= 65:
		return SeverityHigh
	case score >= 40:
		return SeverityMedium
	case score >= 20:
		return SeverityLow
	default:
		return SeverityInformational
	}
}
