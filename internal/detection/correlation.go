package detection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var ErrInvalidCorrelationObservation = errors.New("invalid correlation observation")

func CorrelationGroup(event core.CanonicalEvent, fields []string) (string, bool) {
	if len(fields) == 0 {
		return "global", true
	}
	parts := make([]map[string]interface{}, 0, len(fields))
	for _, field := range fields {
		values := eventFieldValues(event, field)
		if len(values) == 0 {
			return "", false
		}
		sort.Strings(values)
		parts = append(parts, map[string]interface{}{"field": field, "values": values})
	}
	payload, _ := json.Marshal(parts)
	return string(payload), true
}

func CorrelationValue(event core.CanonicalEvent, field string) (string, bool) {
	values := eventFieldValues(event, field)
	if len(values) == 0 {
		return "", false
	}
	sort.Strings(values)
	return strings.Join(values, "\x1f"), true
}

func EvaluateCorrelation(spec core.CorrelationSpec, records []core.CorrelationRecord) core.CorrelationEvaluation {
	allowed := make(map[string]bool, len(spec.Rules))
	for _, ruleID := range spec.Rules {
		allowed[ruleID] = true
	}
	filtered := make([]core.CorrelationRecord, 0, len(records))
	for _, record := range records {
		if allowed[record.SourceRuleID] {
			filtered = append(filtered, record)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].EventTime.Equal(filtered[j].EventTime) {
			if filtered[i].EventID == filtered[j].EventID {
				return filtered[i].SourceRuleID < filtered[j].SourceRuleID
			}
			return filtered[i].EventID < filtered[j].EventID
		}
		return filtered[i].EventTime.Before(filtered[j].EventTime)
	})

	switch spec.Type {
	case core.CorrelationEventCount:
		ids := uniqueEventIDs(filtered)
		values := map[string]bool{}
		for _, record := range filtered {
			if record.Value != "" {
				values[record.Value] = true
			}
		}
		return core.CorrelationEvaluation{Satisfied: len(ids) >= spec.Threshold, Count: len(ids), DistinctValues: len(values), EventIDs: boundedCorrelationIDs(ids)}
	case core.CorrelationValueCount:
		values := map[string]bool{}
		for _, record := range filtered {
			if record.Value != "" {
				values[record.Value] = true
			}
		}
		ids := uniqueEventIDs(filtered)
		return core.CorrelationEvaluation{
			Satisfied: len(values) >= spec.Threshold, Count: len(ids), DistinctValues: len(values), EventIDs: boundedCorrelationIDs(ids),
		}
	case core.CorrelationTemporal:
		ids, satisfied := matchTemporal(spec.Rules, filtered, false)
		return core.CorrelationEvaluation{Satisfied: satisfied, Count: len(ids), EventIDs: ids}
	case core.CorrelationTemporalOrdered:
		ids, satisfied := matchTemporal(spec.Rules, filtered, true)
		return core.CorrelationEvaluation{Satisfied: satisfied, Count: len(ids), EventIDs: ids}
	default:
		return core.CorrelationEvaluation{}
	}
}

func uniqueEventIDs(records []core.CorrelationRecord) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, record := range records {
		if record.EventID != "" && !seen[record.EventID] {
			seen[record.EventID] = true
			result = append(result, record.EventID)
		}
	}
	return result
}

func boundedCorrelationIDs(ids []string) []string {
	const maximumEvidenceIDs = 1000
	if len(ids) <= maximumEvidenceIDs {
		return ids
	}
	return append([]string(nil), ids[:maximumEvidenceIDs]...)
}

func matchTemporal(ruleIDs []string, records []core.CorrelationRecord, ordered bool) ([]string, bool) {
	if !ordered {
		assigned := make([]string, len(ruleIDs))
		used := map[string]bool{}
		var assign func(int) bool
		assign = func(position int) bool {
			if position == len(ruleIDs) {
				return true
			}
			for _, record := range records {
				if record.SourceRuleID != ruleIDs[position] || used[record.EventID] {
					continue
				}
				used[record.EventID] = true
				assigned[position] = record.EventID
				if assign(position + 1) {
					return true
				}
				delete(used, record.EventID)
			}
			return false
		}
		if !assign(0) {
			return nil, false
		}
		return assigned, true
	}
	used := map[string]bool{}
	matched := []string{}
	position := 0
	for _, ruleID := range ruleIDs {
		found := false
		start := position
		for index := start; index < len(records); index++ {
			record := records[index]
			if record.SourceRuleID != ruleID || used[record.EventID] {
				continue
			}
			used[record.EventID] = true
			matched = append(matched, record.EventID)
			position = index + 1
			found = true
			break
		}
		if !found {
			return nil, false
		}
	}
	return matched, true
}

func CorrelationFingerprint(observation core.CorrelationObservation, evaluation core.CorrelationEvaluation) string {
	ids := append([]string(nil), evaluation.EventIDs...)
	sort.Strings(ids)
	payload, _ := json.Marshal(struct {
		Tenant  string   `json:"tenant"`
		Rule    string   `json:"rule"`
		Version string   `json:"version"`
		Group   string   `json:"group"`
		Trigger string   `json:"trigger"`
		Events  []string `json:"events"`
	}{observation.TenantID, observation.RuleID, observation.RuleVersion, observation.GroupKey, observation.EventID, ids})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

type MemoryCorrelationStore struct {
	mu          sync.Mutex
	records     map[string][]core.CorrelationRecord
	emissions   map[string]bool
	observation map[string]bool
}

func NewMemoryCorrelationStore() *MemoryCorrelationStore {
	return &MemoryCorrelationStore{
		records: map[string][]core.CorrelationRecord{}, emissions: map[string]bool{}, observation: map[string]bool{},
	}
}

func (m *MemoryCorrelationStore) ObserveCorrelation(ctx context.Context, input core.CorrelationObservation) (core.CorrelationEvaluation, error) {
	if err := ctx.Err(); err != nil {
		return core.CorrelationEvaluation{}, err
	}
	if err := validateCorrelationObservation(input); err != nil {
		return core.CorrelationEvaluation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := input.TenantID + "\x1e" + input.RuleID + "\x1e" + input.RuleVersion + "\x1e" + input.GroupKey
	newRecords := make([]core.CorrelationRecord, 0, len(input.SourceRuleIDs))
	for _, sourceRuleID := range uniqueStrings(input.SourceRuleIDs) {
		observationKey := key + "\x1e" + sourceRuleID + "\x1e" + input.EventID
		if m.observation[observationKey] {
			continue
		}
		m.observation[observationKey] = true
		newRecords = append(newRecords, core.CorrelationRecord{
			SourceRuleID: sourceRuleID, EventID: input.EventID, EventTime: input.EventTime.UTC(), Value: input.Value,
		})
	}
	if len(newRecords) == 0 {
		return core.CorrelationEvaluation{}, nil
	}
	window := time.Duration(input.Spec.TimespanSeconds) * time.Second
	cutoff := input.EventTime.Add(-window)
	retentionCutoff := input.EventTime.Add(-2 * window)
	retained := m.records[key][:0]
	windowRecords := []core.CorrelationRecord{}
	for _, record := range m.records[key] {
		if !record.EventTime.Before(retentionCutoff) {
			retained = append(retained, record)
		}
		if !record.EventTime.Before(cutoff) && !record.EventTime.After(input.EventTime) {
			windowRecords = append(windowRecords, record)
		}
	}
	before := EvaluateCorrelation(input.Spec, windowRecords)
	retained = append(retained, newRecords...)
	m.records[key] = retained
	windowRecords = append(windowRecords, newRecords...)
	after := EvaluateCorrelation(input.Spec, windowRecords)
	if before.Satisfied || !after.Satisfied {
		return after, nil
	}
	fingerprint := CorrelationFingerprint(input, after)
	if m.emissions[fingerprint] {
		return after, nil
	}
	m.emissions[fingerprint] = true
	after.Triggered = true
	return after, nil
}

func (m *MemoryCorrelationStore) ResetTenant(tenantID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := tenantID + "\x1e"
	for key := range m.records {
		if strings.HasPrefix(key, prefix) {
			delete(m.records, key)
		}
	}
	for key := range m.observation {
		if strings.HasPrefix(key, prefix) {
			delete(m.observation, key)
		}
	}
	// Emission fingerprints are tenant-derived hashes and are intentionally
	// discarded with the in-memory executor as a whole on test/demo resets.
	m.emissions = map[string]bool{}
}

func validateCorrelationObservation(input core.CorrelationObservation) error {
	if strings.TrimSpace(input.TenantID) == "" || strings.TrimSpace(input.RuleID) == "" || strings.TrimSpace(input.RuleVersion) == "" ||
		strings.TrimSpace(input.GroupKey) == "" || strings.TrimSpace(input.EventID) == "" || input.EventTime.IsZero() || len(input.SourceRuleIDs) == 0 {
		return fmt.Errorf("%w: tenant, rule, version, group, event, time and source rules are required", ErrInvalidCorrelationObservation)
	}
	if input.Spec.TimespanSeconds <= 0 || input.Spec.TimespanSeconds > int64((24*time.Hour)/time.Second) {
		return fmt.Errorf("%w: timespan is outside supported bounds", ErrInvalidCorrelationObservation)
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
