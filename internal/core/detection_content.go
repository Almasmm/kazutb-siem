package core

import "time"

type DetectionSample struct {
	Name   string           `json:"name"`
	Event  CanonicalEvent   `json:"event"`
	Events []CanonicalEvent `json:"events,omitempty"`
}

const (
	CorrelationEventCount      = "event_count"
	CorrelationValueCount      = "value_count"
	CorrelationTemporal        = "temporal"
	CorrelationTemporalOrdered = "temporal_ordered"
)

type CorrelationSpec struct {
	Type            string   `json:"type"`
	Rules           []string `json:"rules"`
	GroupBy         []string `json:"group_by,omitempty"`
	ValueField      string   `json:"value_field,omitempty"`
	TimespanSeconds int64    `json:"timespan_seconds"`
	Threshold       int      `json:"threshold"`
}

type CorrelationObservation struct {
	TenantID      string          `json:"tenant_id"`
	RuleID        string          `json:"rule_id"`
	RuleVersion   string          `json:"rule_version"`
	GroupKey      string          `json:"group_key"`
	SourceRuleIDs []string        `json:"source_rule_ids"`
	EventID       string          `json:"event_id"`
	EventTime     time.Time       `json:"event_time"`
	Value         string          `json:"value,omitempty"`
	Spec          CorrelationSpec `json:"spec"`
}

type CorrelationRecord struct {
	SourceRuleID string    `json:"source_rule_id"`
	EventID      string    `json:"event_id"`
	EventTime    time.Time `json:"event_time"`
	Value        string    `json:"value,omitempty"`
}

type CorrelationEvaluation struct {
	Satisfied      bool     `json:"satisfied"`
	Triggered      bool     `json:"triggered"`
	Count          int      `json:"count"`
	DistinctValues int      `json:"distinct_values"`
	EventIDs       []string `json:"event_ids"`
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
