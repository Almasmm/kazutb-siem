package core

import "time"

const (
	CaseStatusOpen          = "OPEN"
	CaseStatusInvestigation = "INVESTIGATION"
	CaseStatusResponse      = "RESPONSE"
	CaseStatusClosed        = "CLOSED"

	CaseTaskOpen       = "OPEN"
	CaseTaskInProgress = "IN_PROGRESS"
	CaseTaskDone       = "DONE"
	CaseTaskCancelled  = "CANCELLED"
)

type CaseParticipant struct {
	UserID  string    `json:"user_id"`
	Role    string    `json:"role"`
	AddedBy string    `json:"added_by"`
	AddedAt time.Time `json:"added_at"`
}

type CaseObservable struct {
	ID        string    `json:"observable_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Source    string    `json:"source,omitempty"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
}

type CaseTask struct {
	ID          string     `json:"task_id"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Status      string     `json:"status"`
	Assignee    string     `json:"assignee,omitempty"`
	DueAt       *time.Time `json:"due_at,omitempty"`
	CreatedBy   string     `json:"created_by"`
	CompletedBy string     `json:"completed_by,omitempty"`
	Version     int        `json:"version"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type CaseComment struct {
	ID        string    `json:"comment_id"`
	Body      string    `json:"body"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
}

type CaseHistoryEntry struct {
	ID        string                 `json:"history_id"`
	Action    string                 `json:"action"`
	Message   string                 `json:"message"`
	Actor     string                 `json:"actor"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

type CaseSLA struct {
	DueAt    time.Time `json:"due_at"`
	Breached bool      `json:"breached"`
}

type Case struct {
	ID                 string             `json:"case_id"`
	TenantID           string             `json:"tenant_id"`
	RequestID          string             `json:"-"`
	Title              string             `json:"title"`
	Description        string             `json:"description,omitempty"`
	Status             string             `json:"status"`
	Severity           Severity           `json:"severity"`
	Owner              string             `json:"owner"`
	ClosureSummary     string             `json:"closure_summary,omitempty"`
	IncidentIDs        []string           `json:"incident_ids"`
	EvidenceIDs        []string           `json:"evidence_ids"`
	Participants       []CaseParticipant  `json:"participants"`
	Observables        []CaseObservable   `json:"observables"`
	Tasks              []CaseTask         `json:"tasks"`
	Comments           []CaseComment      `json:"comments"`
	History            []CaseHistoryEntry `json:"history"`
	SLA                CaseSLA            `json:"sla"`
	AllowedTransitions []string           `json:"allowed_transitions"`
	Version            int                `json:"version"`
	CreatedBy          string             `json:"created_by"`
	UpdatedBy          string             `json:"updated_by"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
	ClosedAt           *time.Time         `json:"closed_at,omitempty"`
}

type CaseFilter struct {
	Query      string
	Status     string
	Severity   string
	Owner      string
	IncidentID string
	Limit      int
}
