package core

import "time"

const (
	ParserStateDraft      = "DRAFT"
	ParserStateValidated  = "VALIDATED"
	ParserStatePublished  = "PUBLISHED"
	ParserStateSuperseded = "SUPERSEDED"
	ParserStateDisabled   = "DISABLED"
)

type ParserTestCase struct {
	Name     string            `json:"name"`
	Payload  string            `json:"payload"`
	Expected map[string]string `json:"expected"`
}

type ParserSpec struct {
	Format    string            `json:"format"`
	InputKind string            `json:"input_kind"`
	Mappings  map[string]string `json:"mappings"`
	Defaults  map[string]string `json:"defaults"`
	Tests     []ParserTestCase  `json:"tests,omitempty"`
}

type ParserTestResult struct {
	Name    string   `json:"name"`
	Passed  bool     `json:"passed"`
	Errors  []string `json:"errors,omitempty"`
	EventID string   `json:"event_id,omitempty"`
}

type ParserValidationReport struct {
	Valid          bool               `json:"valid"`
	SpecHash       string             `json:"spec_hash"`
	MappedFields   int                `json:"mapped_fields"`
	TestsPassed    int                `json:"tests_passed"`
	TestsTotal     int                `json:"tests_total"`
	Errors         []string           `json:"errors,omitempty"`
	Warnings       []string           `json:"warnings,omitempty"`
	TestResults    []ParserTestResult `json:"test_results,omitempty"`
	ValidatedAt    time.Time          `json:"validated_at,omitempty"`
	Compiler       string             `json:"compiler"`
	OCSFCompatible string             `json:"ocsf_compatible"`
}

type ParserContent struct {
	ParserID    string                 `json:"parser_id"`
	TenantID    string                 `json:"tenant_id,omitempty"`
	Version     int                    `json:"version"`
	Name        string                 `json:"name"`
	State       string                 `json:"state"`
	Spec        ParserSpec             `json:"spec"`
	Validation  ParserValidationReport `json:"validation"`
	CreatedBy   string                 `json:"created_by"`
	RequestID   string                 `json:"request_id,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	PublishedAt *time.Time             `json:"published_at,omitempty"`
}

type ParserSimulation struct {
	ParserID string            `json:"parser_id"`
	Version  int               `json:"version"`
	Event    CanonicalEvent    `json:"event"`
	Fields   map[string]string `json:"fields"`
}
