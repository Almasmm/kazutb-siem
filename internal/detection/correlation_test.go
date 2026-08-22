package detection

import (
	"context"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

const eventCountCorrelationSigma = `title: Distributed authentication failures
id: KCSP-CORR-AUTH-001
description: Correlates authentication failures by source.
level: high
confidence: 88
tags:
  - attack.t1110
correlation:
  type: event_count
  rules:
    - KCSP-AUTH-FAIL-BASE
  group-by:
    - src_endpoint.ip
  timespan: 5m
  condition:
    gte: 3
`

func TestCompileSigmaEventCountCorrelation(t *testing.T) {
	compiled, err := Compile(core.DetectionContent{RuleID: "KCSP-CORR-AUTH-001", Version: "1.2.0", SigmaYAML: eventCountCorrelationSigma})
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := compiled.CorrelationSpec()
	if !ok || spec.Type != core.CorrelationEventCount || spec.Threshold != 3 || spec.TimespanSeconds != 300 {
		t.Fatalf("unexpected correlation spec: %+v", spec)
	}
	if len(spec.Rules) != 1 || spec.Rules[0] != "KCSP-AUTH-FAIL-BASE" || len(spec.GroupBy) != 1 {
		t.Fatalf("correlation references were not compiled: %+v", spec)
	}
	if matched, _ := compiled.Evaluate(core.CanonicalEvent{Category: "authentication"}); matched {
		t.Fatal("correlation document must not directly match one event")
	}
}

func TestMemoryCorrelationThresholdValueAndTemporalOrdering(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	store := NewMemoryCorrelationStore()
	eventSpec := core.CorrelationSpec{Type: core.CorrelationEventCount, Rules: []string{"base"}, TimespanSeconds: 300, Threshold: 3}
	for index := 0; index < 3; index++ {
		result, err := store.ObserveCorrelation(ctx, observation(eventSpec, "event-count", "base", string(rune('a'+index)), base.Add(time.Duration(index)*time.Second), "user"))
		if err != nil {
			t.Fatal(err)
		}
		if result.Triggered != (index == 2) {
			t.Fatalf("event_count trigger at index %d: %+v", index, result)
		}
	}
	duplicate, err := store.ObserveCorrelation(ctx, observation(eventSpec, "event-count", "base", "c", base.Add(2*time.Second), "user"))
	if err != nil || duplicate.Triggered {
		t.Fatalf("duplicate observation emitted: %+v err=%v", duplicate, err)
	}

	valueSpec := core.CorrelationSpec{Type: core.CorrelationValueCount, Rules: []string{"dns"}, ValueField: "dst_endpoint.ip", TimespanSeconds: 60, Threshold: 2}
	first, _ := store.ObserveCorrelation(ctx, observation(valueSpec, "value-count", "dns", "v1", base, "10.0.0.1"))
	second, _ := store.ObserveCorrelation(ctx, observation(valueSpec, "value-count", "dns", "v2", base.Add(time.Second), "10.0.0.1"))
	third, _ := store.ObserveCorrelation(ctx, observation(valueSpec, "value-count", "dns", "v3", base.Add(2*time.Second), "10.0.0.2"))
	if first.Triggered || second.Triggered || !third.Triggered || third.DistinctValues != 2 {
		t.Fatalf("value_count semantics failed: first=%+v second=%+v third=%+v", first, second, third)
	}

	orderedSpec := core.CorrelationSpec{Type: core.CorrelationTemporalOrdered, Rules: []string{"login", "process", "network"}, TimespanSeconds: 120, Threshold: 3}
	ordered := NewMemoryCorrelationStore()
	_, _ = ordered.ObserveCorrelation(ctx, observation(orderedSpec, "ordered", "process", "o2", base.Add(time.Second), ""))
	_, _ = ordered.ObserveCorrelation(ctx, observation(orderedSpec, "ordered", "login", "o1", base.Add(2*time.Second), ""))
	outOfOrder, _ := ordered.ObserveCorrelation(ctx, observation(orderedSpec, "ordered", "network", "o3", base.Add(3*time.Second), ""))
	if outOfOrder.Triggered {
		t.Fatalf("out-of-order sequence emitted: %+v", outOfOrder)
	}
	ordered = NewMemoryCorrelationStore()
	_, _ = ordered.ObserveCorrelation(ctx, observation(orderedSpec, "ordered", "login", "s1", base, ""))
	_, _ = ordered.ObserveCorrelation(ctx, observation(orderedSpec, "ordered", "process", "s2", base.Add(time.Second), ""))
	sequence, _ := ordered.ObserveCorrelation(ctx, observation(orderedSpec, "ordered", "network", "s3", base.Add(2*time.Second), ""))
	if !sequence.Triggered || len(sequence.EventIDs) != 3 {
		t.Fatalf("ordered sequence did not emit: %+v", sequence)
	}
}

func TestCorrelationGroupRequiresEveryEntity(t *testing.T) {
	event := core.CanonicalEvent{User: core.UserRef{Name: "student"}, SrcEndpoint: core.EndpointRef{IP: "10.1.2.3"}}
	first, ok := CorrelationGroup(event, []string{"user.name", "src_endpoint.ip"})
	second, secondOK := CorrelationGroup(event, []string{"user.name", "src_endpoint.ip"})
	if !ok || !secondOK || first != second {
		t.Fatalf("group key is not deterministic: %q %q", first, second)
	}
	if _, ok := CorrelationGroup(event, []string{"device.hostname"}); ok {
		t.Fatal("missing group-by entity must not collapse into a global group")
	}
}

func observation(spec core.CorrelationSpec, ruleID, sourceRuleID, eventID string, eventTime time.Time, value string) core.CorrelationObservation {
	return core.CorrelationObservation{
		TenantID: "tenant-a", RuleID: ruleID, RuleVersion: "1.0.0", GroupKey: "group-a",
		SourceRuleIDs: []string{sourceRuleID}, EventID: eventID, EventTime: eventTime, Value: value, Spec: spec,
	}
}
