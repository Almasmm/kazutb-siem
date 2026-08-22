package core

import "time"

type DetectionSample struct {
	Name  string         `json:"name"`
	Event CanonicalEvent `json:"event"`
}

type DetectionValidationReport struct {
	Valid           bool      `json:"valid"`
	CompilerVersion string    `json:"compiler_version"`
	PositivePassed  int       `json:"positive_passed"`
	PositiveTotal   int       `json:"positive_total"`
	NegativePassed  int       `json:"negative_passed"`
	NegativeTotal   int       `json:"negative_total"`
	Errors          []string  `json:"errors"`
	DurationMicros  int64     `json:"duration_micros"`
	ValidatedAt     time.Time `json:"validated_at"`
}

type DetectionContent struct {
	TenantID                string                    `json:"tenant_id"`
	RuleID                  string                    `json:"rule_id"`
	Version                 string                    `json:"version"`
	State                   string                    `json:"state"`
	SigmaYAML               string                    `json:"sigma_yaml"`
	PositiveTests           []DetectionSample         `json:"positive_tests"`
	NegativeTests           []DetectionSample         `json:"negative_tests"`
	Rule                    DetectionRule             `json:"rule"`
	Validation              DetectionValidationReport `json:"validation"`
	PerformanceBudgetMicros int64                     `json:"performance_budget_micros"`
	CreatedBy               string                    `json:"created_by"`
	CreatedAt               time.Time                 `json:"created_at"`
	UpdatedAt               time.Time                 `json:"updated_at"`
	PublishedAt             *time.Time                `json:"published_at,omitempty"`
}

type DetectionReplayReport struct {
	RuleID         string    `json:"rule_id"`
	Version        string    `json:"version"`
	Start          time.Time `json:"start"`
	End            time.Time `json:"end"`
	EventsScanned  int       `json:"events_scanned"`
	Matches        int       `json:"matches"`
	SampleEventIDs []string  `json:"sample_event_ids"`
	DurationMicros int64     `json:"duration_micros"`
	Truncated      bool      `json:"truncated"`
}
