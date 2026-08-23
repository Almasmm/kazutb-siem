package store

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
	"github.com/kcsp/platform/internal/observability"
	"github.com/kcsp/platform/internal/threatintel"
)

type Hybrid struct {
	control     *Postgres
	telemetry   *ClickHouse
	retentionMu sync.Mutex
	retention   map[string]retentionSnapshot
}

type retentionSnapshot struct {
	policy   core.RetentionPolicy
	loadedAt time.Time
}

func OpenHybrid(ctx context.Context, databaseURL, clickhouseURL string) (*Hybrid, error) {
	control, err := OpenPostgres(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	telemetry, err := OpenClickHouse(ctx, clickhouseURL)
	if err != nil {
		control.Close()
		return nil, err
	}
	return &Hybrid{control: control, telemetry: telemetry, retention: map[string]retentionSnapshot{}}, nil
}

func (h *Hybrid) Health(ctx context.Context) error {
	if err := h.control.Health(ctx); err != nil {
		return err
	}
	return h.telemetry.Health(ctx)
}
func (h *Hybrid) Close() { h.telemetry.Close(); h.control.Close() }
func (h *Hybrid) EnsureTenant(ctx context.Context, tenantID, name string) error {
	return h.control.EnsureTenant(ctx, tenantID, name)
}
func (h *Hybrid) RegisterCollector(ctx context.Context, collector core.Collector) (core.Collector, error) {
	return h.control.RegisterCollector(ctx, collector)
}
func (h *Hybrid) ListCollectors(ctx context.Context, tenantID string) ([]core.Collector, error) {
	return h.control.ListCollectors(ctx, tenantID)
}
func (h *Hybrid) CollectorBySubject(ctx context.Context, tenantID, subject string) (core.Collector, error) {
	return h.control.CollectorBySubject(ctx, tenantID, subject)
}
func (h *Hybrid) HeartbeatCollector(ctx context.Context, tenantID, subject string, heartbeat core.CollectorHeartbeat, observedIP string) (core.Collector, error) {
	return h.control.HeartbeatCollector(ctx, tenantID, subject, heartbeat, observedIP)
}
func (h *Hybrid) SetCollectorState(ctx context.Context, tenantID, collectorID, state string) (core.Collector, error) {
	return h.control.SetCollectorState(ctx, tenantID, collectorID, state)
}
func (h *Hybrid) CreateDetectionDraft(ctx context.Context, content core.DetectionContent) (core.DetectionContent, error) {
	return h.control.CreateDetectionDraft(ctx, content)
}
func (h *Hybrid) DetectionContent(ctx context.Context, tenantID, ruleID, version string) (core.DetectionContent, error) {
	return h.control.DetectionContent(ctx, tenantID, ruleID, version)
}
func (h *Hybrid) ListDetectionContent(ctx context.Context, tenantID string) ([]core.DetectionContent, error) {
	return h.control.ListDetectionContent(ctx, tenantID)
}
func (h *Hybrid) SaveDetectionValidation(ctx context.Context, content core.DetectionContent, rule core.DetectionRule, report core.DetectionValidationReport) (core.DetectionContent, error) {
	return h.control.SaveDetectionValidation(ctx, content, rule, report)
}
func (h *Hybrid) PublishDetectionContent(ctx context.Context, tenantID, ruleID, version string) (core.DetectionContent, error) {
	return h.control.PublishDetectionContent(ctx, tenantID, ruleID, version)
}
func (h *Hybrid) DisableDetectionContent(ctx context.Context, tenantID, ruleID string) (core.DetectionContent, error) {
	return h.control.DisableDetectionContent(ctx, tenantID, ruleID)
}
func (h *Hybrid) RollbackDetectionContent(ctx context.Context, tenantID, ruleID string) (core.DetectionContent, error) {
	return h.control.RollbackDetectionContent(ctx, tenantID, ruleID)
}
func (h *Hybrid) PublishedDetectionContent(ctx context.Context, tenantID string) ([]core.DetectionContent, error) {
	return h.control.PublishedDetectionContent(ctx, tenantID)
}
func (h *Hybrid) ObserveCorrelation(ctx context.Context, input core.CorrelationObservation) (core.CorrelationEvaluation, error) {
	return h.control.ObserveCorrelation(ctx, input)
}
func (h *Hybrid) ResetTenant(ctx context.Context, tenantID string) error {
	if err := h.telemetry.ResetTenant(ctx, tenantID); err != nil {
		return err
	}
	if err := h.control.ResetTenant(ctx, tenantID); err != nil {
		return err
	}
	h.retentionMu.Lock()
	delete(h.retention, tenantID)
	h.retentionMu.Unlock()
	return nil
}
func (h *Hybrid) SetRules(ctx context.Context, rules []core.DetectionRule) error {
	return h.control.SetRules(ctx, rules)
}
func (h *Hybrid) ListRules(ctx context.Context) ([]core.DetectionRule, error) {
	return h.control.ListRules(ctx)
}
func (h *Hybrid) PutRawEnvelope(ctx context.Context, envelope ingest.RawEnvelope) error {
	started := time.Now()
	defer func() { observability.Default.ObserveClickHouse(time.Since(started)) }()
	policy, err := h.cachedRetentionPolicy(ctx, envelope.TenantID)
	if err != nil {
		return err
	}
	return h.telemetry.PutRawEnvelopeWithExpiry(ctx, envelope, envelope.ReceivedAt.Add(time.Duration(policy.RawDays)*24*time.Hour))
}
func (h *Hybrid) PutEvent(ctx context.Context, event core.CanonicalEvent) (core.CanonicalEvent, bool, error) {
	started := time.Now()
	defer func() { observability.Default.ObserveClickHouse(time.Since(started)) }()
	policy, err := h.cachedRetentionPolicy(ctx, event.TenantID)
	if err != nil {
		return core.CanonicalEvent{}, false, err
	}
	return h.telemetry.PutEventWithExpiry(ctx, event, event.EventTime.Add(time.Duration(policy.NormalizedDays)*24*time.Hour))
}
func (h *Hybrid) GetEvent(ctx context.Context, tenantID, eventID string) (core.CanonicalEvent, error) {
	started := time.Now()
	defer func() { observability.Default.ObserveClickHouse(time.Since(started)) }()
	event, err := h.telemetry.GetEvent(ctx, tenantID, eventID)
	if !errors.Is(err, ErrNotFound) {
		return event, err
	}
	return h.control.GetEvent(ctx, tenantID, eventID)
}
func (h *Hybrid) ListEvents(ctx context.Context, tenantID string, filter EventFilter) ([]core.CanonicalEvent, error) {
	started := time.Now()
	defer func() { observability.Default.ObserveClickHouse(time.Since(started)) }()
	current, err := h.telemetry.ListEvents(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}
	legacy, err := h.control.ListEvents(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	merged := make([]core.CanonicalEvent, 0, len(current)+len(legacy))
	for _, event := range append(current, legacy...) {
		if !seen[event.ID] {
			merged = append(merged, event)
			seen[event.ID] = true
		}
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].EventTime.After(merged[j].EventTime) })
	limit := normalizedLimit(filter.Limit)
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged, nil
}
func (h *Hybrid) HuntEvents(ctx context.Context, tenantID string, request core.HuntRequest) (core.HuntPage, error) {
	return h.telemetry.HuntEvents(ctx, tenantID, request)
}
func (h *Hybrid) CreateSavedHunt(ctx context.Context, item core.SavedHunt) (core.SavedHunt, error) {
	return h.control.CreateSavedHunt(ctx, item)
}
func (h *Hybrid) ListSavedHunts(ctx context.Context, tenantID, viewer string, includeAll bool) ([]core.SavedHunt, error) {
	return h.control.ListSavedHunts(ctx, tenantID, viewer, includeAll)
}
func (h *Hybrid) SavedHunt(ctx context.Context, tenantID, huntID, viewer string, includeAll bool) (core.SavedHunt, error) {
	return h.control.SavedHunt(ctx, tenantID, huntID, viewer, includeAll)
}
func (h *Hybrid) UpdateSavedHunt(ctx context.Context, item core.SavedHunt, actor string, includeAll bool) (core.SavedHunt, error) {
	return h.control.UpdateSavedHunt(ctx, item, actor, includeAll)
}
func (h *Hybrid) DeleteSavedHunt(ctx context.Context, tenantID, huntID string, version int, actor string, includeAll bool) error {
	return h.control.DeleteSavedHunt(ctx, tenantID, huntID, version, actor, includeAll)
}
func (h *Hybrid) RecordHuntExecution(ctx context.Context, execution core.HuntExecution) error {
	return h.control.RecordHuntExecution(ctx, execution)
}
func (h *Hybrid) ListHuntExecutions(ctx context.Context, tenantID, savedHuntID, viewer string, includeAll bool, limit int) ([]core.HuntExecution, error) {
	return h.control.ListHuntExecutions(ctx, tenantID, savedHuntID, viewer, includeAll, limit)
}
func (h *Hybrid) PutFinding(ctx context.Context, finding core.Finding) error {
	policy, err := h.cachedRetentionPolicy(ctx, finding.TenantID)
	if err != nil {
		return err
	}
	return h.telemetry.PutFindingWithExpiry(ctx, finding, finding.CreatedAt.Add(time.Duration(policy.FindingsDays)*24*time.Hour))
}

func (h *Hybrid) RetentionPolicy(ctx context.Context, tenantID string) (core.RetentionPolicy, error) {
	return h.cachedRetentionPolicy(ctx, tenantID)
}

func (h *Hybrid) UpdateRetentionPolicy(ctx context.Context, policy core.RetentionPolicy) (core.RetentionPolicy, error) {
	updated, err := h.control.UpdateRetentionPolicy(ctx, policy)
	if err != nil {
		return core.RetentionPolicy{}, err
	}
	h.retentionMu.Lock()
	h.retention[policy.TenantID] = retentionSnapshot{policy: updated, loadedAt: time.Now()}
	h.retentionMu.Unlock()
	return updated, nil
}

func (h *Hybrid) ReserveEvidence(ctx context.Context, item core.EvidenceItem, mutation core.EvidenceMutation) (core.EvidenceItem, bool, error) {
	return h.control.ReserveEvidence(ctx, item, mutation)
}
func (h *Hybrid) FinalizeEvidence(ctx context.Context, tenantID, evidenceID, objectVersion, etag string, mutation core.EvidenceMutation) (core.EvidenceItem, error) {
	return h.control.FinalizeEvidence(ctx, tenantID, evidenceID, objectVersion, etag, mutation)
}
func (h *Hybrid) FailEvidence(ctx context.Context, tenantID, evidenceID, failure string, mutation core.EvidenceMutation) (core.EvidenceItem, error) {
	return h.control.FailEvidence(ctx, tenantID, evidenceID, failure, mutation)
}
func (h *Hybrid) Evidence(ctx context.Context, tenantID, evidenceID string) (core.EvidenceItem, error) {
	return h.control.Evidence(ctx, tenantID, evidenceID)
}
func (h *Hybrid) ListEvidence(ctx context.Context, tenantID string, filter core.EvidenceFilter) ([]core.EvidenceItem, error) {
	return h.control.ListEvidence(ctx, tenantID, filter)
}
func (h *Hybrid) AppendEvidenceCustody(ctx context.Context, tenantID, evidenceID string, mutation core.EvidenceMutation) (core.EvidenceCustodyEntry, error) {
	return h.control.AppendEvidenceCustody(ctx, tenantID, evidenceID, mutation)
}
func (h *Hybrid) ListEvidenceCustody(ctx context.Context, tenantID, evidenceID string) ([]core.EvidenceCustodyEntry, error) {
	return h.control.ListEvidenceCustody(ctx, tenantID, evidenceID)
}
func (h *Hybrid) RecordEvidenceVerification(ctx context.Context, tenantID, evidenceID string, valid bool, mutation core.EvidenceMutation) (core.EvidenceItem, error) {
	return h.control.RecordEvidenceVerification(ctx, tenantID, evidenceID, valid, mutation)
}
func (h *Hybrid) VerifyEvidenceCustody(ctx context.Context, tenantID, evidenceID string) (bool, error) {
	return h.control.VerifyEvidenceCustody(ctx, tenantID, evidenceID)
}

func (h *Hybrid) CreateCase(ctx context.Context, item core.Case) (core.Case, bool, error) {
	return h.control.CreateCase(ctx, item)
}
func (h *Hybrid) GetCase(ctx context.Context, tenantID, caseID string) (core.Case, error) {
	return h.control.GetCase(ctx, tenantID, caseID)
}
func (h *Hybrid) ListCases(ctx context.Context, tenantID string, filter core.CaseFilter) ([]core.Case, error) {
	return h.control.ListCases(ctx, tenantID, filter)
}
func (h *Hybrid) MutateCase(ctx context.Context, tenantID, caseID string, version int, mutate func(*core.Case) error) (core.Case, error) {
	return h.control.MutateCase(ctx, tenantID, caseID, version, mutate)
}

func (h *Hybrid) CreateThreatIntelFeed(ctx context.Context, feed core.ThreatIntelFeed) (core.ThreatIntelFeed, error) {
	return h.control.CreateThreatIntelFeed(ctx, feed)
}
func (h *Hybrid) GetThreatIntelFeed(ctx context.Context, tenantID, feedID string) (core.ThreatIntelFeed, error) {
	return h.control.GetThreatIntelFeed(ctx, tenantID, feedID)
}
func (h *Hybrid) ListThreatIntelFeeds(ctx context.Context, tenantID string) ([]core.ThreatIntelFeed, error) {
	return h.control.ListThreatIntelFeeds(ctx, tenantID)
}
func (h *Hybrid) UpdateThreatIntelFeed(ctx context.Context, feed core.ThreatIntelFeed) (core.ThreatIntelFeed, error) {
	return h.control.UpdateThreatIntelFeed(ctx, feed)
}
func (h *Hybrid) UpsertThreatIndicator(ctx context.Context, indicator core.ThreatIndicator) (core.ThreatIndicator, bool, error) {
	return h.control.UpsertThreatIndicator(ctx, indicator)
}
func (h *Hybrid) GetThreatIndicator(ctx context.Context, tenantID, indicatorID string) (core.ThreatIndicator, error) {
	return h.control.GetThreatIndicator(ctx, tenantID, indicatorID)
}
func (h *Hybrid) ListThreatIndicators(ctx context.Context, tenantID string, filter core.ThreatIndicatorFilter) ([]core.ThreatIndicator, error) {
	return h.control.ListThreatIndicators(ctx, tenantID, filter)
}
func (h *Hybrid) SetThreatIndicatorState(ctx context.Context, tenantID, indicatorID, state string, version int, actor string) (core.ThreatIndicator, error) {
	return h.control.SetThreatIndicatorState(ctx, tenantID, indicatorID, state, version, actor)
}
func (h *Hybrid) ListThreatIntelMatches(ctx context.Context, tenantID, indicatorID, eventID string, limit int) ([]core.ThreatIntelMatch, error) {
	return h.control.ListThreatIntelMatches(ctx, tenantID, indicatorID, eventID, limit)
}
func (h *Hybrid) MatchThreatIntelEvent(ctx context.Context, event core.CanonicalEvent) ([]core.ThreatIntelMatch, error) {
	observables := threatintel.ExtractObservables(event)
	return h.control.MatchThreatIntelObservables(ctx, event.TenantID, event.ID, event.EventTime, observables)
}
func (h *Hybrid) ObserveUEBAEvent(ctx context.Context, event core.CanonicalEvent) (*core.UEBAAnomaly, error) {
	return h.control.ObserveUEBAEvent(ctx, event)
}
func (h *Hybrid) ListUEBAAnomalies(ctx context.Context, tenantID string, filter core.UEBAAnomalyFilter) ([]core.UEBAAnomaly, error) {
	return h.control.ListUEBAAnomalies(ctx, tenantID, filter)
}
func (h *Hybrid) GetUEBABaseline(ctx context.Context, tenantID, entityType, entityID string) (core.UEBABaselineSummary, error) {
	return h.control.GetUEBABaseline(ctx, tenantID, entityType, entityID)
}
func (h *Hybrid) UpdateUEBAAnomalyFeedback(ctx context.Context, tenantID, anomalyID, status, actor, reason string, version int) (core.UEBAAnomaly, error) {
	return h.control.UpdateUEBAAnomalyFeedback(ctx, tenantID, anomalyID, status, actor, reason, version)
}
func (h *Hybrid) GetAISOCPolicy(ctx context.Context, tenantID string) (core.AISOCPolicy, error) {
	return h.control.GetAISOCPolicy(ctx, tenantID)
}
func (h *Hybrid) UpdateAISOCPolicy(ctx context.Context, policy core.AISOCPolicy, version int) (core.AISOCPolicy, error) {
	return h.control.UpdateAISOCPolicy(ctx, policy, version)
}
func (h *Hybrid) CreateAISOCRequest(ctx context.Context, request core.AISOCRequest) (core.AISOCRequest, bool, error) {
	return h.control.CreateAISOCRequest(ctx, request)
}
func (h *Hybrid) GetAISOCRequest(ctx context.Context, tenantID, requestID string) (core.AISOCRequestDetails, error) {
	return h.control.GetAISOCRequest(ctx, tenantID, requestID)
}
func (h *Hybrid) ListAISOCRequests(ctx context.Context, tenantID string, filter core.AISOCRequestFilter) ([]core.AISOCRequest, error) {
	return h.control.ListAISOCRequests(ctx, tenantID, filter)
}
func (h *Hybrid) CreateAISOCDecision(ctx context.Context, decision core.AISOCDecision) (core.AISOCDecision, error) {
	return h.control.CreateAISOCDecision(ctx, decision)
}
func (h *Hybrid) ClaimAISOCRequest(ctx context.Context, workerID, tenantID string, lease time.Duration) (core.AISOCRequest, bool, error) {
	return h.control.ClaimAISOCRequest(ctx, workerID, tenantID, lease)
}
func (h *Hybrid) CompleteAISOCRequest(ctx context.Context, request core.AISOCRequest, workerID string) (core.AISOCRequest, error) {
	return h.control.CompleteAISOCRequest(ctx, request, workerID)
}
func (h *Hybrid) FinishAISOCRequestFailure(ctx context.Context, tenantID, requestID, workerID,
	status, class, detail string, documents []core.AISOCContextDocument, digest string,
	redactions int, injectionDetected bool) (core.AISOCRequest, error) {
	return h.control.FinishAISOCRequestFailure(ctx, tenantID, requestID, workerID, status, class,
		detail, documents, digest, redactions, injectionDetected)
}
func (h *Hybrid) RetrosearchThreatIndicator(ctx context.Context, indicator core.ThreatIndicator, request core.ThreatIntelRetrosearchRequest) (core.ThreatIntelRetrosearchResult, error) {
	started := time.Now()
	expression, err := threatintel.RetrosearchExpression(indicator)
	if err != nil {
		return core.ThreatIntelRetrosearchResult{}, err
	}
	result := core.ThreatIntelRetrosearchResult{
		IndicatorID: indicator.ID, Start: request.Start, End: request.End, Matches: []core.ThreatIntelMatch{},
	}
	remaining := request.Limit
	cursor := ""
	for remaining > 0 {
		pageLimit := min(remaining, 200)
		page, err := h.telemetry.HuntEvents(ctx, indicator.TenantID, core.HuntRequest{
			Start: request.Start, End: request.End, Expression: expression, Limit: pageLimit, Cursor: cursor,
		})
		if err != nil {
			return core.ThreatIntelRetrosearchResult{}, err
		}
		result.CandidateEvents += len(page.Items)
		for _, event := range page.Items {
			observables := threatintel.ExtractObservables(event)
			filtered := make([]core.ThreatObservable, 0, len(observables))
			for _, observable := range observables {
				if observable.Type == indicator.Type && observable.NormalizedValue == indicator.NormalizedValue {
					filtered = append(filtered, observable)
				}
			}
			if len(filtered) == 0 {
				continue
			}
			matches, err := h.control.RecordThreatIntelMatches(ctx, indicator, event.ID, filtered)
			if err != nil {
				return core.ThreatIntelRetrosearchResult{}, err
			}
			result.EventsMatched++
			result.Matches = append(result.Matches, matches...)
		}
		remaining -= len(page.Items)
		result.Partial = result.Partial || page.Partial
		if page.NextCursor == "" {
			break
		}
		if remaining == 0 {
			result.Partial = true
			break
		}
		cursor = page.NextCursor
	}
	result.Returned = len(result.Matches)
	result.DurationMicros = time.Since(started).Microseconds()
	return result, nil
}

func (h *Hybrid) CreateSOARPlaybook(ctx context.Context, playbook core.SOARPlaybook, version core.SOARPlaybookVersion) (core.SOARPlaybookDetails, error) {
	return h.control.CreateSOARPlaybook(ctx, playbook, version)
}
func (h *Hybrid) CreateSOARPlaybookVersion(ctx context.Context, tenantID, playbookID, actor string, spec core.SOARPlaybookSpec, report core.SOARValidationReport) (core.SOARPlaybookVersion, error) {
	return h.control.CreateSOARPlaybookVersion(ctx, tenantID, playbookID, actor, spec, report)
}
func (h *Hybrid) GetSOARPlaybook(ctx context.Context, tenantID, playbookID string) (core.SOARPlaybookDetails, error) {
	return h.control.GetSOARPlaybook(ctx, tenantID, playbookID)
}
func (h *Hybrid) ListSOARPlaybooks(ctx context.Context, tenantID string) ([]core.SOARPlaybook, error) {
	return h.control.ListSOARPlaybooks(ctx, tenantID)
}
func (h *Hybrid) SaveSOARValidation(ctx context.Context, tenantID, playbookID string, version int, report core.SOARValidationReport) (core.SOARPlaybookVersion, error) {
	return h.control.SaveSOARValidation(ctx, tenantID, playbookID, version, report)
}
func (h *Hybrid) PublishSOARPlaybookVersion(ctx context.Context, tenantID, playbookID string, version int, actor string) (core.SOARPlaybookDetails, error) {
	return h.control.PublishSOARPlaybookVersion(ctx, tenantID, playbookID, version, actor)
}
func (h *Hybrid) DisableSOARPlaybook(ctx context.Context, tenantID, playbookID, actor string) (core.SOARPlaybook, error) {
	return h.control.DisableSOARPlaybook(ctx, tenantID, playbookID, actor)
}
func (h *Hybrid) CreateSOARExecution(ctx context.Context, execution core.SOARExecution, nodes []core.SOARNode) (core.SOARExecution, bool, error) {
	return h.control.CreateSOARExecution(ctx, execution, nodes)
}
func (h *Hybrid) GetSOARExecution(ctx context.Context, tenantID, executionID string) (core.SOARExecution, error) {
	return h.control.GetSOARExecution(ctx, tenantID, executionID)
}
func (h *Hybrid) ListSOARExecutions(ctx context.Context, tenantID string, filter core.SOARExecutionFilter) ([]core.SOARExecution, error) {
	return h.control.ListSOARExecutions(ctx, tenantID, filter)
}
func (h *Hybrid) ListSOARApprovals(ctx context.Context, tenantID string, filter core.SOARApprovalFilter) ([]core.SOARApproval, error) {
	return h.control.ListSOARApprovals(ctx, tenantID, filter)
}
func (h *Hybrid) DecideSOARApproval(ctx context.Context, tenantID, approvalID, approver, decision, reason string) (core.SOARApproval, error) {
	return h.control.DecideSOARApproval(ctx, tenantID, approvalID, approver, decision, reason)
}
func (h *Hybrid) CompleteSOARManualTask(ctx context.Context, tenantID, executionID, nodeID string, output map[string]interface{}) (core.SOARExecution, error) {
	return h.control.CompleteSOARManualTask(ctx, tenantID, executionID, nodeID, output)
}
func (h *Hybrid) ListSOARActionAttempts(ctx context.Context, tenantID, executionID string, limit int) ([]core.SOARActionAttempt, error) {
	return h.control.ListSOARActionAttempts(ctx, tenantID, executionID, limit)
}
func (h *Hybrid) CreateSOARConnector(ctx context.Context, connector core.SOARConnector) (core.SOARConnector, error) {
	return h.control.CreateSOARConnector(ctx, connector)
}
func (h *Hybrid) GetSOARConnector(ctx context.Context, tenantID, connectorID string) (core.SOARConnector, error) {
	return h.control.GetSOARConnector(ctx, tenantID, connectorID)
}
func (h *Hybrid) ListSOARConnectors(ctx context.Context, tenantID string, filter core.SOARConnectorFilter) ([]core.SOARConnector, error) {
	return h.control.ListSOARConnectors(ctx, tenantID, filter)
}
func (h *Hybrid) UpdateSOARConnector(ctx context.Context, connector core.SOARConnector, version int) (core.SOARConnector, error) {
	return h.control.UpdateSOARConnector(ctx, connector, version)
}
func (h *Hybrid) DisableSOARConnector(ctx context.Context, tenantID, connectorID, actor string, version int) (core.SOARConnector, error) {
	return h.control.DisableSOARConnector(ctx, tenantID, connectorID, actor, version)
}
func (h *Hybrid) CreateSOARConnectorTest(ctx context.Context, test core.SOARConnectorTest) (core.SOARConnectorTest, bool, error) {
	return h.control.CreateSOARConnectorTest(ctx, test)
}
func (h *Hybrid) ListSOARConnectorTests(ctx context.Context, tenantID, connectorID string, limit int) ([]core.SOARConnectorTest, error) {
	return h.control.ListSOARConnectorTests(ctx, tenantID, connectorID, limit)
}

func (h *Hybrid) cachedRetentionPolicy(ctx context.Context, tenantID string) (core.RetentionPolicy, error) {
	h.retentionMu.Lock()
	if snapshot, ok := h.retention[tenantID]; ok && time.Since(snapshot.loadedAt) < time.Minute {
		h.retentionMu.Unlock()
		return snapshot.policy, nil
	}
	h.retentionMu.Unlock()
	policy, err := h.control.RetentionPolicy(ctx, tenantID)
	if err != nil {
		return core.RetentionPolicy{}, err
	}
	h.retentionMu.Lock()
	h.retention[tenantID] = retentionSnapshot{policy: policy, loadedAt: time.Now()}
	h.retentionMu.Unlock()
	return policy, nil
}
func (h *Hybrid) ListFindings(ctx context.Context, tenantID, eventID string, limit int) ([]core.Finding, error) {
	current, err := h.telemetry.ListFindings(ctx, tenantID, eventID, limit)
	if err != nil {
		return nil, err
	}
	legacy, err := h.control.ListFindings(ctx, tenantID, eventID, limit)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	merged := make([]core.Finding, 0, len(current)+len(legacy))
	for _, finding := range append(current, legacy...) {
		if !seen[finding.ID] {
			merged = append(merged, finding)
			seen[finding.ID] = true
		}
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].CreatedAt.After(merged[j].CreatedAt) })
	limit = normalizedLimit(limit)
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged, nil
}
func (h *Hybrid) UpsertAlert(ctx context.Context, alert core.Alert, key string, window time.Duration) (core.Alert, bool, error) {
	return h.control.UpsertAlert(ctx, alert, key, window)
}
func (h *Hybrid) GetAlert(ctx context.Context, tenantID, alertID string) (core.Alert, error) {
	return h.control.GetAlert(ctx, tenantID, alertID)
}
func (h *Hybrid) ListAlerts(ctx context.Context, tenantID string, filter AlertFilter) ([]core.Alert, error) {
	return h.control.ListAlerts(ctx, tenantID, filter)
}
func (h *Hybrid) MutateAlert(ctx context.Context, tenantID, alertID string, version int, mutate func(*core.Alert) error) (core.Alert, error) {
	return h.control.MutateAlert(ctx, tenantID, alertID, version, mutate)
}
func (h *Hybrid) CreateIncident(ctx context.Context, incident core.Incident) (core.Incident, error) {
	return h.control.CreateIncident(ctx, incident)
}
func (h *Hybrid) GetIncident(ctx context.Context, tenantID, incidentID string) (core.Incident, error) {
	return h.control.GetIncident(ctx, tenantID, incidentID)
}
func (h *Hybrid) ListIncidents(ctx context.Context, tenantID string, filter IncidentFilter) ([]core.Incident, error) {
	return h.control.ListIncidents(ctx, tenantID, filter)
}
func (h *Hybrid) MutateIncident(ctx context.Context, tenantID, incidentID string, version int, mutate func(*core.Incident) error) (core.Incident, error) {
	return h.control.MutateIncident(ctx, tenantID, incidentID, version, mutate)
}
func (h *Hybrid) AppendAudit(ctx context.Context, entry core.AuditEntry) (core.AuditEntry, error) {
	return h.control.AppendAudit(ctx, entry)
}
func (h *Hybrid) ListAudit(ctx context.Context, tenantID string, limit int) ([]core.AuditEntry, error) {
	return h.control.ListAudit(ctx, tenantID, limit)
}
func (h *Hybrid) VerifyAudit(ctx context.Context, tenantID string) (bool, error) {
	return h.control.VerifyAudit(ctx, tenantID)
}
func (h *Hybrid) Overview(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	overview, err := h.control.Overview(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	telemetry, err := h.telemetry.Metrics(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	metrics := overview["metrics"].(map[string]interface{})
	legacyEvents, _ := metrics["events_24h"].(int)
	metrics["events_24h"] = legacyEvents + telemetry.Events24h
	metrics["detection_latency_ms"] = telemetry.DetectionLatencyMS
	platform := overview["platform"].(map[string]interface{})
	platform["profile"] = "kafka-clickhouse-postgres"
	return overview, nil
}
