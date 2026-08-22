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
	"github.com/kcsp/platform/internal/detection"
)

var ErrInvalidEvent = errors.New("invalid event")

const (
	PowerShellRuleID  = "KCSP-WIN-PS-001"
	AuthRuleID        = "KCSP-AUTH-THRESHOLD-001"
	ThreatIntelRuleID = "KCSP-TI-IOC-MATCH"
	UEBARuleID        = "KCSP-UEBA-BEHAVIOR-DEVIATION"
	authBaseRuleID    = "KCSP-AUTH-FAILURE-BASE"
)

type Engine struct {
	store             Repository
	rules             map[string]core.DetectionRule
	dynamicMu         sync.Mutex
	dynamicRules      map[string]dynamicRuleSnapshot
	correlationMemory *detection.MemoryCorrelationStore
}

type dynamicRuleSnapshot struct {
	Rules    []*detection.CompiledRule
	LoadedAt time.Time
}

type publishedContentProvider interface {
	PublishedDetectionContent(context.Context, string) ([]core.DetectionContent, error)
}

type correlationStateStore interface {
	ObserveCorrelation(context.Context, core.CorrelationObservation) (core.CorrelationEvaluation, error)
}

type threatIntelProvider interface {
	MatchThreatIntelEvent(context.Context, core.CanonicalEvent) ([]core.ThreatIntelMatch, error)
}

type uebaProvider interface {
	ObserveUEBAEvent(context.Context, core.CanonicalEvent) (*core.UEBAAnomaly, error)
}

// Repository is the data-plane port used by the embedded executor. Production
// adapters can route events/findings to ClickHouse and control objects to PostgreSQL
// without leaking those SDK types into the domain pipeline.
type Repository interface {
	SetRules(context.Context, []core.DetectionRule) error
	PutEvent(context.Context, core.CanonicalEvent) (core.CanonicalEvent, bool, error)
	PutFinding(context.Context, core.Finding) error
	UpsertAlert(context.Context, core.Alert, string, time.Duration) (core.Alert, bool, error)
	AppendAudit(context.Context, core.AuditEntry) (core.AuditEntry, error)
}

type detectionMatch struct {
	Rule               core.DetectionRule
	MatchedFields      []string
	Factors            []core.RiskFactor
	EventIDs           []string
	DedupDiscriminator string
	ReferenceID        string
}

func New(ctx context.Context, repository Repository) (*Engine, error) {
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
		{
			ID: ThreatIntelRuleID, Title: "Threat intelligence IOC match",
			Description: "Matches canonical event observables against active, tenant-scoped threat indicators.",
			Version:     "1.0.0", Severity: core.SeverityMedium, Confidence: 70,
			MITRE: []string{}, RequiredDataSources: []string{"Threat Intelligence", "Normalized security events"},
			KnownFalsePositives: []string{"Shared infrastructure, stale intelligence, or low-confidence community feeds"},
			Owner:               "KCSP Threat Intelligence", State: "PUBLISHED", UpdatedAt: now,
		},
		{
			ID: UEBARuleID, Title: "Explainable behavior deviation",
			Description: "Detects deterministic deviations from tenant-scoped rolling user and device baselines.",
			Version:     "1.0.0", Severity: core.SeverityHigh, Confidence: 70,
			MITRE: []string{}, RequiredDataSources: []string{"Normalized identity, endpoint, network, and process telemetry"},
			KnownFalsePositives: []string{"Role changes, travel, onboarding, and newly deployed administrative tooling"},
			Owner:               "KCSP UEBA", State: "PUBLISHED", UpdatedAt: now,
		},
	}
	byID := make(map[string]core.DetectionRule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	if err := repository.SetRules(ctx, rules); err != nil {
		return nil, fmt.Errorf("publish built-in detection rules: %w", err)
	}
	return &Engine{
		store: repository, rules: byID, dynamicRules: map[string]dynamicRuleSnapshot{},
		correlationMemory: detection.NewMemoryCorrelationStore(),
	}, nil
}

func (e *Engine) ResetTenant(tenantID string) {
	e.dynamicMu.Lock()
	delete(e.dynamicRules, tenantID)
	e.dynamicMu.Unlock()
	e.correlationMemory.ResetTenant(tenantID)
}

func (e *Engine) Ingest(ctx context.Context, tenantID string, input core.CanonicalEvent) (core.IngestResult, error) {
	event, err := normalize(tenantID, input)
	if err != nil {
		return core.IngestResult{}, err
	}
	stored, duplicate, err := e.store.PutEvent(ctx, event)
	if err != nil {
		return core.IngestResult{}, fmt.Errorf("persist canonical event: %w", err)
	}
	if duplicate {
		return core.IngestResult{Event: stored, Duplicate: true, Findings: []core.Finding{}, Alerts: []core.Alert{}}, nil
	}

	matches, err := e.detect(ctx, stored)
	if err != nil {
		return core.IngestResult{}, err
	}
	result := core.IngestResult{Event: stored, Findings: []core.Finding{}, Alerts: []core.Alert{}}
	for _, match := range matches {
		finding := e.makeFinding(stored, match)
		if err := e.store.PutFinding(ctx, finding); err != nil {
			return core.IngestResult{}, fmt.Errorf("persist finding: %w", err)
		}
		result.Findings = append(result.Findings, finding)

		candidate, dedupKey := makeAlert(stored, finding, match.EventIDs, match.DedupDiscriminator)
		alert, created, err := e.store.UpsertAlert(ctx, candidate, dedupKey, 15*time.Minute)
		if err != nil {
			return core.IngestResult{}, fmt.Errorf("persist alert: %w", err)
		}
		result.Alerts = append(result.Alerts, alert)
		action := "alert.updated"
		if created {
			action = "alert.created"
		}
		auditMetadata := map[string]interface{}{"event_id": stored.ID, "rule_id": finding.Rule.ID, "risk_score": finding.RiskScore}
		if match.Rule.ID == ThreatIntelRuleID && match.ReferenceID != "" {
			auditMetadata["threat_indicator_id"] = match.ReferenceID
		}
		if match.Rule.ID == UEBARuleID && match.ReferenceID != "" {
			auditMetadata["ueba_anomaly_id"] = match.ReferenceID
		}
		if _, err := e.store.AppendAudit(ctx, core.AuditEntry{
			TenantID: tenantID, Actor: "system:detection-engine", Action: action,
			ResourceType: "alert", ResourceID: alert.ID, Outcome: "success",
			Metadata: auditMetadata,
		}); err != nil {
			return core.IngestResult{}, fmt.Errorf("append detection audit: %w", err)
		}
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
	if input.IngestTime.IsZero() {
		input.IngestTime = now
	} else {
		input.IngestTime = input.IngestTime.UTC()
	}
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

func (e *Engine) detect(ctx context.Context, event core.CanonicalEvent) ([]detectionMatch, error) {
	matches := make([]detectionMatch, 0, 3)
	matchedRuleIDs := map[string]bool{}
	if matchedFields, tokenFactors := suspiciousPowerShell(event); len(matchedFields) > 0 {
		factors := []core.RiskFactor{
			{Code: "base_severity", Label: "High-confidence process detection", Delta: 30, SourceReference: PowerShellRuleID},
			{Code: "rule_confidence", Label: "Validated rule confidence", Delta: 20, SourceReference: PowerShellRuleID + "@1.0.0"},
		}
		factors = append(factors, tokenFactors...)
		factors = append(factors, contextFactors(event)...)
		matches = append(matches, detectionMatch{Rule: e.rules[PowerShellRuleID], MatchedFields: matchedFields, Factors: factors, EventIDs: []string{event.ID}})
		matchedRuleIDs[PowerShellRuleID] = true
	}
	threshold, fields, factors, err := e.observeAuthenticationFailure(ctx, event)
	if err != nil {
		return nil, fmt.Errorf("evaluate authentication threshold: %w", err)
	}
	if threshold.Triggered {
		matches = append(matches, detectionMatch{Rule: e.rules[AuthRuleID], MatchedFields: fields, Factors: factors, EventIDs: threshold.EventIDs})
	}
	threatMatches, err := e.matchThreatIntelligence(ctx, event)
	if err != nil {
		return nil, fmt.Errorf("evaluate threat intelligence: %w", err)
	}
	matches = append(matches, threatMatches...)
	behaviorMatch, err := e.matchUEBA(ctx, event)
	if err != nil {
		return nil, fmt.Errorf("evaluate behavior baseline: %w", err)
	}
	if behaviorMatch != nil {
		matches = append(matches, *behaviorMatch)
	}
	dynamicRules, err := e.rulesForTenant(ctx, event.TenantID)
	if err != nil {
		return nil, fmt.Errorf("load published detection content: %w", err)
	}
	for _, compiled := range dynamicRules {
		if _, builtIn := e.rules[compiled.Rule.ID]; builtIn {
			continue
		}
		if compiled.IsCorrelation() {
			continue
		}
		matched, fields := compiled.Evaluate(event)
		if !matched {
			continue
		}
		factors := []core.RiskFactor{
			{Code: "base_severity", Label: "Published Sigma detection", Delta: severityRisk(compiled.Rule.Severity), SourceReference: compiled.Rule.ID},
			{Code: "rule_confidence", Label: "Validated rule confidence", Delta: max(5, compiled.Rule.Confidence/5), SourceReference: compiled.Rule.ID + "@" + compiled.Rule.Version},
		}
		factors = append(factors, contextFactors(event)...)
		matches = append(matches, detectionMatch{Rule: compiled.Rule, MatchedFields: fields, Factors: factors, EventIDs: []string{event.ID}})
		matchedRuleIDs[compiled.Rule.ID] = true
	}
	for _, compiled := range dynamicRules {
		spec, isCorrelation := compiled.CorrelationSpec()
		if !isCorrelation {
			continue
		}
		matchedSources := make([]string, 0, len(spec.Rules))
		for _, sourceRuleID := range spec.Rules {
			if matchedRuleIDs[sourceRuleID] {
				matchedSources = append(matchedSources, sourceRuleID)
			}
		}
		if len(matchedSources) == 0 {
			continue
		}
		groupKey, ok := detection.CorrelationGroup(event, spec.GroupBy)
		if !ok {
			continue
		}
		value := ""
		if spec.Type == core.CorrelationValueCount {
			value, ok = detection.CorrelationValue(event, spec.ValueField)
			if !ok {
				continue
			}
		}
		correlated, err := e.observeCorrelation(ctx, core.CorrelationObservation{
			TenantID: event.TenantID, RuleID: compiled.Rule.ID, RuleVersion: compiled.Rule.Version,
			GroupKey: groupKey, SourceRuleIDs: matchedSources, EventID: event.ID, EventTime: event.EventTime,
			Value: value, Spec: spec,
		})
		if err != nil {
			return nil, fmt.Errorf("evaluate correlation rule %s: %w", compiled.Rule.ID, err)
		}
		if !correlated.Triggered {
			continue
		}
		matchedFields := append([]string(nil), spec.GroupBy...)
		if spec.ValueField != "" {
			matchedFields = append(matchedFields, spec.ValueField)
		}
		matchedFields = append(matchedFields, "correlation.rules")
		factors := []core.RiskFactor{
			{Code: "base_severity", Label: "Published Sigma correlation", Delta: severityRisk(compiled.Rule.Severity), SourceReference: compiled.Rule.ID},
			{Code: "rule_confidence", Label: "Validated correlation confidence", Delta: max(5, compiled.Rule.Confidence/5), SourceReference: compiled.Rule.ID + "@" + compiled.Rule.Version},
			{Code: "correlation_count", Label: "Correlated security events", Delta: min(20, max(5, correlated.Count)), SourceReference: fmt.Sprint(correlated.Count)},
		}
		factors = append(factors, contextFactors(event)...)
		matches = append(matches, detectionMatch{Rule: compiled.Rule, MatchedFields: matchedFields, Factors: factors, EventIDs: correlated.EventIDs})
	}
	return matches, nil
}

func (e *Engine) matchThreatIntelligence(ctx context.Context, event core.CanonicalEvent) ([]detectionMatch, error) {
	provider, ok := e.store.(threatIntelProvider)
	if !ok {
		return nil, nil
	}
	intelligence, err := provider.MatchThreatIntelEvent(ctx, event)
	if err != nil {
		return nil, err
	}
	type aggregate struct {
		indicator core.ThreatIntelMatch
		fields    []string
		seen      map[string]bool
	}
	byIndicator := make(map[string]*aggregate, len(intelligence))
	order := make([]string, 0, len(intelligence))
	for _, indicator := range intelligence {
		item, exists := byIndicator[indicator.IndicatorID]
		if !exists {
			item = &aggregate{indicator: indicator, seen: map[string]bool{}}
			byIndicator[indicator.IndicatorID] = item
			order = append(order, indicator.IndicatorID)
		}
		if indicator.MatchedField != "" && !item.seen[indicator.MatchedField] {
			item.seen[indicator.MatchedField] = true
			item.fields = append(item.fields, indicator.MatchedField)
		}
	}
	matches := make([]detectionMatch, 0, len(order))
	for _, indicatorID := range order {
		item := byIndicator[indicatorID]
		indicator := item.indicator
		reputationDelta := 5
		switch indicator.Reputation {
		case "MALICIOUS":
			reputationDelta = 25
		case "SUSPICIOUS":
			reputationDelta = 15
		}
		rule := e.rules[ThreatIntelRuleID]
		rule.Confidence = indicator.Confidence
		rule.Title = fmt.Sprintf("Threat intelligence %s match", strings.ToLower(string(indicator.Type)))
		factors := []core.RiskFactor{
			{Code: "base_severity", Label: "Active threat intelligence match", Delta: 35, SourceReference: ThreatIntelRuleID},
			{Code: "ioc_confidence", Label: "Indicator confidence", Delta: max(5, indicator.Confidence/5), SourceReference: indicator.IndicatorID},
			{Code: "threat_intelligence", Label: indicator.Reputation + " indicator reputation", Delta: reputationDelta, SourceReference: indicator.IndicatorID},
		}
		factors = append(factors, contextFactors(event)...)
		matches = append(matches, detectionMatch{
			Rule: rule, MatchedFields: item.fields, Factors: factors,
			EventIDs: []string{event.ID}, DedupDiscriminator: indicator.IndicatorID, ReferenceID: indicator.IndicatorID,
		})
	}
	return matches, nil
}

func (e *Engine) matchUEBA(ctx context.Context, event core.CanonicalEvent) (*detectionMatch, error) {
	provider, ok := e.store.(uebaProvider)
	if !ok {
		return nil, nil
	}
	anomaly, err := provider.ObserveUEBAEvent(ctx, event)
	if err != nil || anomaly == nil {
		return nil, err
	}
	rule := e.rules[UEBARuleID]
	rule.Title = anomaly.Title
	rule.Severity = anomaly.Severity
	rule.Confidence = anomaly.Confidence
	fields := make([]string, 0, len(anomaly.Features))
	seen := map[string]bool{}
	for _, feature := range anomaly.Features {
		if feature.Field != "" && !seen[feature.Field] {
			fields = append(fields, feature.Field)
			seen[feature.Field] = true
		}
	}
	return &detectionMatch{
		Rule: rule, MatchedFields: fields, EventIDs: []string{event.ID},
		Factors: []core.RiskFactor{{Code: "behavior_anomaly", Label: "Explainable rolling-baseline deviation",
			Delta: min(75, max(0, anomaly.RiskScore)), SourceReference: anomaly.ID}},
		DedupDiscriminator: anomaly.EntityType + ":" + anomaly.EntityID, ReferenceID: anomaly.ID,
	}, nil
}

func (e *Engine) rulesForTenant(ctx context.Context, tenantID string) ([]*detection.CompiledRule, error) {
	provider, ok := e.store.(publishedContentProvider)
	if !ok {
		return nil, nil
	}
	e.dynamicMu.Lock()
	defer e.dynamicMu.Unlock()
	if snapshot, found := e.dynamicRules[tenantID]; found && time.Since(snapshot.LoadedAt) < 5*time.Second {
		return snapshot.Rules, nil
	}
	contents, err := provider.PublishedDetectionContent(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	compiledRules := make([]*detection.CompiledRule, 0, len(contents))
	for _, content := range contents {
		compiled, err := detection.Compile(content)
		if err != nil {
			return nil, fmt.Errorf("compile published rule %s@%s: %w", content.RuleID, content.Version, err)
		}
		compiledRules = append(compiledRules, compiled)
	}
	e.dynamicRules[tenantID] = dynamicRuleSnapshot{Rules: compiledRules, LoadedAt: time.Now()}
	return compiledRules, nil
}

func severityRisk(severity core.Severity) int {
	switch severity {
	case core.SeverityCritical:
		return 65
	case core.SeverityHigh:
		return 50
	case core.SeverityMedium:
		return 35
	case core.SeverityLow:
		return 20
	default:
		return 10
	}
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

func (e *Engine) observeAuthenticationFailure(ctx context.Context, event core.CanonicalEvent) (core.CorrelationEvaluation, []string, []core.RiskFactor, error) {
	if !strings.EqualFold(event.Category, "authentication") || !strings.EqualFold(event.SecurityResult.Outcome, "failure") {
		return core.CorrelationEvaluation{}, nil, nil, nil
	}
	source := event.SrcEndpoint.IP
	if source == "" {
		source = event.Device.IP
	}
	if source == "" {
		return core.CorrelationEvaluation{}, nil, nil, nil
	}
	groupEvent := event
	groupEvent.SrcEndpoint.IP = source
	groupKey, _ := detection.CorrelationGroup(groupEvent, []string{"src_endpoint.ip"})
	evaluation, err := e.observeCorrelation(ctx, core.CorrelationObservation{
		TenantID: event.TenantID, RuleID: AuthRuleID, RuleVersion: "1.0.0", GroupKey: groupKey,
		SourceRuleIDs: []string{authBaseRuleID}, EventID: event.ID, EventTime: event.EventTime, Value: event.User.Name,
		Spec: core.CorrelationSpec{
			Type: core.CorrelationEventCount, Rules: []string{authBaseRuleID}, GroupBy: []string{"src_endpoint.ip"},
			TimespanSeconds: int64((5 * time.Minute) / time.Second), Threshold: 5,
		},
	})
	if err != nil || !evaluation.Triggered {
		return evaluation, nil, nil, err
	}
	factors := []core.RiskFactor{
		{Code: "base_severity", Label: "Authentication threshold reached", Delta: 35, SourceReference: AuthRuleID},
		{Code: "rule_confidence", Label: "Threshold confidence", Delta: 20, SourceReference: AuthRuleID + "@1.0.0"},
	}
	if evaluation.DistinctValues >= 3 {
		factors = append(factors, core.RiskFactor{Code: "multiple_accounts", Label: "Multiple accounts targeted", Delta: 15, SourceReference: source})
	}
	factors = append(factors, contextFactors(event)...)
	return evaluation, []string{"security_result.outcome", "src_endpoint.ip", "user.name"}, factors, nil
}

func (e *Engine) observeCorrelation(ctx context.Context, observation core.CorrelationObservation) (core.CorrelationEvaluation, error) {
	if state, ok := e.store.(correlationStateStore); ok {
		return state.ObserveCorrelation(ctx, observation)
	}
	return e.correlationMemory.ObserveCorrelation(ctx, observation)
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

func makeAlert(event core.CanonicalEvent, finding core.Finding, correlatedEventIDs []string, dedupDiscriminator string) (core.Alert, string) {
	now := time.Now().UTC()
	eventIDs := make([]string, 0, len(correlatedEventIDs)+1)
	seenEventIDs := map[string]bool{}
	for _, eventID := range correlatedEventIDs {
		if eventID != "" && !seenEventIDs[eventID] {
			seenEventIDs[eventID] = true
			eventIDs = append(eventIDs, eventID)
		}
	}
	if len(eventIDs) == 0 {
		eventIDs = append(eventIDs, event.ID)
	}
	entity := core.EntitySummary{Type: "device", ID: event.Device.ID, Name: event.Device.Hostname, Label: event.Device.Department}
	if event.User.Name != "" {
		entity = core.EntitySummary{Type: "user", ID: event.User.ID, Name: event.User.Name, Label: event.Device.Hostname}
	}
	if entity.Name == "" {
		entity = core.EntitySummary{Type: "ip", Name: event.SrcEndpoint.IP}
	}
	dedupKey := finding.Rule.ID + "|" + entity.Type + "|" + entity.Name
	if dedupDiscriminator != "" {
		dedupKey += "|" + dedupDiscriminator
	}
	return core.Alert{
		ID: core.NewID("alt"), TenantID: event.TenantID, Title: finding.Title,
		Severity: finding.Severity, RiskScore: finding.RiskScore, RiskBreakdown: finding.RiskBreakdown,
		Status: "NEW", Rule: finding.Rule, MITRE: finding.MITRE, Entity: entity,
		FindingIDs: []string{finding.ID}, EventIDs: eventIDs, EventCount: len(eventIDs),
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
