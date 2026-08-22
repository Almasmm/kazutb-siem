package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var ErrInvalidEvent = errors.New("invalid event")

const (
	PowerShellRuleID = "KCSP-WIN-PS-001"
	AuthRuleID       = "KCSP-AUTH-THRESHOLD-001"
)

type failureObservation struct {
	At      time.Time
	User    string
	EventID string
}

type Engine struct {
	store        Repository
	mu           sync.Mutex
	authFailures map[string][]failureObservation
	rules        map[string]core.DetectionRule
}

// Repository is the data-plane port used by the embedded executor. Production
// adapters can route events/findings to ClickHouse and control objects to PostgreSQL
// without leaking those SDK types into the domain pipeline.
type Repository interface {
	SetRules([]core.DetectionRule)
	PutEvent(core.CanonicalEvent) (core.CanonicalEvent, bool)
	PutFinding(core.Finding)
	UpsertAlert(core.Alert, string, time.Duration) (core.Alert, bool)
	AppendAudit(core.AuditEntry) core.AuditEntry
}

type detectionMatch struct {
	Rule          core.DetectionRule
	MatchedFields []string
	Factors       []core.RiskFactor
}

func New(memory Repository) *Engine {
	now := time.Now().UTC()
	rules := []core.DetectionRule{
		{
			ID: PowerShellRuleID, Title: "Suspicious PowerShell execution",
			Description: "Detects encoded or download-oriented PowerShell command lines in process creation telemetry.",
			Version:     "1.0.0", Severity: core.SeverityHigh, Confidence: 82,
			MITRE: []string{"T1059.001"}, RequiredDataSources: []string{"Sysmon Event ID 1", "Windows process creation"},
			KnownFalsePositives: []string{"Approved administration and software deployment tooling"},
			Owner:               "KCSP Detection Engineering", State: "PUBLISHED", UpdatedAt: now,
		},
		{
			ID: AuthRuleID, Title: "Authentication failure threshold",
			Description: "Detects five authentication failures from one source within five minutes.",
			Version:     "1.0.0", Severity: core.SeverityMedium, Confidence: 74,
			MITRE: []string{"T1110"}, RequiredDataSources: []string{"AD", "VPN", "RADIUS"},
			KnownFalsePositives: []string{"Stale credentials on a managed service or device"},
			Owner:               "KCSP Detection Engineering", State: "PUBLISHED", UpdatedAt: now,
		},
	}
	byID := make(map[string]core.DetectionRule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	memory.SetRules(rules)
	return &Engine{store: memory, authFailures: map[string][]failureObservation{}, rules: byID}
}

func (e *Engine) ResetTenant(tenantID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for key := range e.authFailures {
		if strings.HasPrefix(key, tenantID+"|") {
			delete(e.authFailures, key)
		}
	}
}

func (e *Engine) Ingest(_ context.Context, tenantID string, input core.CanonicalEvent) (core.IngestResult, error) {
	event, err := normalize(tenantID, input)
	if err != nil {
		return core.IngestResult{}, err
	}
	stored, duplicate := e.store.PutEvent(event)
	if duplicate {
		return core.IngestResult{Event: stored, Duplicate: true, Findings: []core.Finding{}, Alerts: []core.Alert{}}, nil
	}

	matches := e.detect(stored)
	result := core.IngestResult{Event: stored, Findings: []core.Finding{}, Alerts: []core.Alert{}}
	for _, match := range matches {
		finding := e.makeFinding(stored, match)
		e.store.PutFinding(finding)
		result.Findings = append(result.Findings, finding)

		candidate, dedupKey := makeAlert(stored, finding)
		alert, created := e.store.UpsertAlert(candidate, dedupKey, 15*time.Minute)
		result.Alerts = append(result.Alerts, alert)
		action := "alert.updated"
		if created {
			action = "alert.created"
		}
		e.store.AppendAudit(core.AuditEntry{
			TenantID: tenantID, Actor: "system:detection-engine", Action: action,
			ResourceType: "alert", ResourceID: alert.ID, Outcome: "success",
			Metadata: map[string]interface{}{"event_id": stored.ID, "rule_id": finding.Rule.ID, "risk_score": finding.RiskScore},
		})
	}
	return result, nil
}

func normalize(tenantID string, input core.CanonicalEvent) (core.CanonicalEvent, error) {
	if strings.TrimSpace(tenantID) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: tenant context is required", ErrInvalidEvent)
	}
	if strings.TrimSpace(input.Category) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: category is required", ErrInvalidEvent)
	}
	if input.Source.Type == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: source.type is required", ErrInvalidEvent)
	}
	now := time.Now().UTC()
	input.TenantID = tenantID // tenant identity is derived from the authenticated source, never the payload.
	if input.ID == "" {
		input.ID = core.NewID("evt")
	}
	if input.EventTime.IsZero() {
		input.EventTime = now
	} else {
		input.EventTime = input.EventTime.UTC()
	}
	input.IngestTime = now
	if input.CollectorID == "" {
		input.CollectorID = "collector-http-dev"
	}
	if input.Schema.OCSFVersion == "" {
		input.Schema.OCSFVersion = "KCSP-OCSF-compatible-v0.1"
	}
	if input.Parser.ID == "" {
		input.Parser = core.ParserRef{ID: "embedded-json", Version: "0.1.0"}
	}
	if input.Raw.Message == "" {
		payload, _ := json.Marshal(struct {
			Category string           `json:"category"`
			Activity string           `json:"activity_name"`
			Source   core.EventSource `json:"source"`
			User     core.UserRef     `json:"user"`
			Device   core.DeviceRef   `json:"device"`
			Process  core.ProcessRef  `json:"process"`
		}{input.Category, input.ActivityName, input.Source, input.User, input.Device, input.Process})
		input.Raw.Message = string(payload)
	}
	sum := sha256.Sum256([]byte(input.Raw.Message))
	input.Raw.Hash = "sha256:" + hex.EncodeToString(sum[:])
	if input.Raw.Reference == "" {
		input.Raw.Reference = "embedded://raw/" + strings.TrimPrefix(input.Raw.Hash, "sha256:")
	}
	return input, nil
}

func (e *Engine) detect(event core.CanonicalEvent) []detectionMatch {
	matches := make([]detectionMatch, 0, 2)
	if matchedFields, tokenFactors := suspiciousPowerShell(event); len(matchedFields) > 0 {
		factors := []core.RiskFactor{
			{Code: "base_severity", Label: "High-confidence process detection", Delta: 30, SourceReference: PowerShellRuleID},
			{Code: "rule_confidence", Label: "Validated rule confidence", Delta: 20, SourceReference: PowerShellRuleID + "@1.0.0"},
		}
		factors = append(factors, tokenFactors...)
		factors = append(factors, contextFactors(event)...)
		matches = append(matches, detectionMatch{Rule: e.rules[PowerShellRuleID], MatchedFields: matchedFields, Factors: factors})
	}
	if threshold, fields, factors := e.observeAuthenticationFailure(event); threshold {
		matches = append(matches, detectionMatch{Rule: e.rules[AuthRuleID], MatchedFields: fields, Factors: factors})
	}
	return matches
}

func suspiciousPowerShell(event core.CanonicalEvent) ([]string, []core.RiskFactor) {
	processName := strings.ToLower(event.Process.Name)
	if !strings.Contains(processName, "powershell") && !strings.Contains(processName, "pwsh") {
		return nil, nil
	}
	command := strings.ToLower(event.Process.CommandLine)
	tokens := []struct {
		value string
		code  string
		label string
		delta int
	}{
		{"encodedcommand", "encoded_command", "Encoded PowerShell command", 15},
		{" -enc ", "encoded_command", "Encoded PowerShell command", 15},
		{"frombase64string", "base64_decode", "In-memory Base64 decoding", 12},
		{"downloadstring", "download_cradle", "PowerShell download cradle", 12},
		{"invoke-webrequest", "web_request", "PowerShell web request", 10},
		{" iwr ", "web_request", "PowerShell web request alias", 10},
		{"iex ", "dynamic_execution", "Dynamic command execution", 10},
	}
	fields := []string{}
	factors := []core.RiskFactor{}
	seen := map[string]bool{}
	for _, token := range tokens {
		if strings.Contains(" "+command+" ", token.value) && !seen[token.code] {
			fields = append(fields, "process.command_line")
			factors = append(factors, core.RiskFactor{Code: token.code, Label: token.label, Delta: token.delta, SourceReference: "process.command_line"})
			seen[token.code] = true
		}
	}
	return fields, factors
}

func contextFactors(event core.CanonicalEvent) []core.RiskFactor {
	factors := []core.RiskFactor{}
	if event.Device.Criticality >= 4 {
		factors = append(factors, core.RiskFactor{Code: "critical_asset", Label: "Critical university asset", Delta: 20, SourceReference: event.Device.Hostname})
	}
	if event.User.IsPrivileged {
		factors = append(factors, core.RiskFactor{Code: "privileged_user", Label: "Privileged identity involved", Delta: 15, SourceReference: event.User.Name})
	}
	return factors
}

func (e *Engine) observeAuthenticationFailure(event core.CanonicalEvent) (bool, []string, []core.RiskFactor) {
	if !strings.EqualFold(event.Category, "authentication") || !strings.EqualFold(event.SecurityResult.Outcome, "failure") {
		return false, nil, nil
	}
	source := event.SrcEndpoint.IP
	if source == "" {
		source = event.Device.IP
	}
	if source == "" {
		return false, nil, nil
	}
	key := event.TenantID + "|" + source
	cutoff := event.EventTime.Add(-5 * time.Minute)
	e.mu.Lock()
	defer e.mu.Unlock()
	observations := e.authFailures[key][:0]
	for _, observation := range e.authFailures[key] {
		if !observation.At.Before(cutoff) {
			observations = append(observations, observation)
		}
	}
	observations = append(observations, failureObservation{At: event.EventTime, User: event.User.Name, EventID: event.ID})
	e.authFailures[key] = observations
	if len(observations) != 5 {
		return false, nil, nil
	}
	users := map[string]bool{}
	for _, observation := range observations {
		if observation.User != "" {
			users[observation.User] = true
		}
	}
	factors := []core.RiskFactor{
		{Code: "base_severity", Label: "Authentication threshold reached", Delta: 35, SourceReference: AuthRuleID},
		{Code: "rule_confidence", Label: "Threshold confidence", Delta: 20, SourceReference: AuthRuleID + "@1.0.0"},
	}
	if len(users) >= 3 {
		factors = append(factors, core.RiskFactor{Code: "multiple_accounts", Label: "Multiple accounts targeted", Delta: 15, SourceReference: source})
	}
	factors = append(factors, contextFactors(event)...)
	return true, []string{"security_result.outcome", "src_endpoint.ip", "user.name"}, factors
}

func (e *Engine) makeFinding(event core.CanonicalEvent, match detectionMatch) core.Finding {
	risk := 0
	for _, factor := range match.Factors {
		risk += factor.Delta
	}
	if risk < 0 {
		risk = 0
	}
	if risk > 100 {
		risk = 100
	}
	return core.Finding{
		ID: core.NewID("fnd"), TenantID: event.TenantID, EventID: event.ID,
		Rule:  core.RuleRef{ID: match.Rule.ID, Title: match.Rule.Title, Version: match.Rule.Version},
		Title: match.Rule.Title, Severity: core.SeverityFromRisk(risk), Confidence: match.Rule.Confidence,
		MITRE: append([]string(nil), match.Rule.MITRE...), MatchedFields: match.MatchedFields,
		RiskScore: risk, RiskBreakdown: match.Factors, CreatedAt: time.Now().UTC(),
	}
}

func makeAlert(event core.CanonicalEvent, finding core.Finding) (core.Alert, string) {
	now := time.Now().UTC()
	entity := core.EntitySummary{Type: "device", ID: event.Device.ID, Name: event.Device.Hostname, Label: event.Device.Department}
	if event.User.Name != "" {
		entity = core.EntitySummary{Type: "user", ID: event.User.ID, Name: event.User.Name, Label: event.Device.Hostname}
	}
	if entity.Name == "" {
		entity = core.EntitySummary{Type: "ip", Name: event.SrcEndpoint.IP}
	}
	dedupKey := finding.Rule.ID + "|" + entity.Type + "|" + entity.Name
	return core.Alert{
		ID: core.NewID("alt"), TenantID: event.TenantID, Title: finding.Title,
		Severity: finding.Severity, RiskScore: finding.RiskScore, RiskBreakdown: finding.RiskBreakdown,
		Status: "NEW", Rule: finding.Rule, MITRE: finding.MITRE, Entity: entity,
		FindingIDs: []string{finding.ID}, EventIDs: []string{event.ID}, EventCount: 1,
		FirstSeen: event.EventTime, LastSeen: event.EventTime,
		SLA:     core.SLAInfo{AcknowledgeBy: now.Add(acknowledgementWindow(finding.Severity))},
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}, dedupKey
}

func acknowledgementWindow(severity core.Severity) time.Duration {
	switch severity {
	case core.SeverityCritical:
		return 15 * time.Minute
	case core.SeverityHigh:
		return 30 * time.Minute
	case core.SeverityMedium:
		return 4 * time.Hour
	default:
		return 24 * time.Hour
	}
}
