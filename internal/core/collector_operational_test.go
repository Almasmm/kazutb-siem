package core

import (
	"testing"
	"time"
)

var evaluatedAt = time.Date(2026, 8, 28, 10, 30, 0, 0, time.UTC)

func seenAt(offset time.Duration) *time.Time {
	moment := evaluatedAt.Add(-offset)
	return &moment
}

func sourceEntry(name, state string) map[string]interface{} {
	return map[string]interface{}{"name": name, "state": state}
}

func healthyMetadata() map[string]interface{} {
	return map[string]interface{}{
		"queue_depth": float64(12), "queue_bytes": float64(24000),
		"source_health": []interface{}{
			sourceEntry("windows-event:Security", "HEALTHY"),
			sourceEntry("windows-event:System", "HEALTHY"),
		},
		"throughput": map[string]interface{}{
			"collection_rate_eps": 12.0, "delivery_rate_eps": 12.0, "net_backlog_rate_eps": 0.0,
			"events_collected_total": float64(5000), "events_delivered_total": float64(4988),
		},
	}
}

func TestOperationalHealthyAgent(t *testing.T) {
	view := EvaluateCollectorOperational(Collector{
		State: "ACTIVE", LastSeenAt: seenAt(20 * time.Second), HealthMetadata: healthyMetadata(),
	}, evaluatedAt)

	if view.Connectivity != ConnectivityOnline || view.Telemetry != TelemetryHealthy || view.Overall != OperationalHealthy {
		t.Fatalf("healthy agent = %+v", view)
	}
	if len(view.Reasons) != 0 {
		t.Fatalf("healthy agent should have no reasons: %v", view.Reasons)
	}
	if view.SourceTotal != 2 || view.SourceHealthy != 2 || view.SourceDegraded != 0 {
		t.Fatalf("source summary = %d/%d/%d", view.SourceTotal, view.SourceHealthy, view.SourceDegraded)
	}
}

// TestOperationalDegradedByGrowingBacklog is the pilot case: heartbeat works,
// so connectivity is ONLINE, but collection outruns delivery.
func TestOperationalDegradedByGrowingBacklog(t *testing.T) {
	metadata := healthyMetadata()
	metadata["queue_depth"] = float64(51198)
	metadata["queue_bytes"] = float64(105728926)
	metadata["throughput"] = map[string]interface{}{
		"collection_rate_eps": 8.0, "delivery_rate_eps": 4.0, "net_backlog_rate_eps": 4.0,
	}
	view := EvaluateCollectorOperational(Collector{
		State: "ACTIVE", LastSeenAt: seenAt(20 * time.Second), HealthMetadata: metadata,
	}, evaluatedAt)

	if view.Connectivity != ConnectivityOnline {
		t.Fatalf("connectivity = %q, want ONLINE", view.Connectivity)
	}
	if view.Telemetry != TelemetryDegraded || view.Overall != OperationalDegraded {
		t.Fatalf("a growing backlog must degrade the agent: %+v", view)
	}
	if !containsReason(view.Reasons, "BACKLOG_GROWING") || !containsReason(view.Reasons, "BACKLOG_HIGH") {
		t.Fatalf("reasons = %v", view.Reasons)
	}
	if view.BacklogDraining {
		t.Fatal("a growing backlog must not report as draining")
	}
	if view.QueueDepth != 51198 || view.QueueBytes != 105728926 {
		t.Fatalf("queue figures = %d/%d", view.QueueDepth, view.QueueBytes)
	}
}

func TestOperationalDrainingBacklogIsNotGrowing(t *testing.T) {
	metadata := healthyMetadata()
	metadata["queue_depth"] = float64(4000)
	metadata["throughput"] = map[string]interface{}{
		"collection_rate_eps": 10.0, "delivery_rate_eps": 100.0, "net_backlog_rate_eps": -90.0,
	}
	view := EvaluateCollectorOperational(Collector{
		State: "ACTIVE", LastSeenAt: seenAt(10 * time.Second), HealthMetadata: metadata,
	}, evaluatedAt)

	if !view.BacklogDraining {
		t.Fatal("delivery above collection must report the backlog as draining")
	}
	if view.Telemetry != TelemetryHealthy {
		t.Fatalf("a draining backlog below threshold stays healthy: %+v", view)
	}
	if containsReason(view.Reasons, "BACKLOG_GROWING") {
		t.Fatalf("reasons = %v", view.Reasons)
	}
}

func TestOperationalDegradedBySource(t *testing.T) {
	metadata := healthyMetadata()
	metadata["source_health"] = []interface{}{
		sourceEntry("windows-event:Security", "HEALTHY"),
		sourceEntry("windows-event:Microsoft-Windows-Sysmon/Operational", "DEGRADED"),
	}
	view := EvaluateCollectorOperational(Collector{
		State: "ACTIVE", LastSeenAt: seenAt(5 * time.Second), HealthMetadata: metadata,
	}, evaluatedAt)

	if view.Connectivity != ConnectivityOnline || view.Overall != OperationalDegraded {
		t.Fatalf("one failing source must degrade the agent: %+v", view)
	}
	if view.SourceDegraded != 1 || len(view.DegradedSources) != 1 {
		t.Fatalf("degraded sources = %d %v", view.SourceDegraded, view.DegradedSources)
	}
	if !containsReason(view.Reasons, "SOURCE_DEGRADED") {
		t.Fatalf("reasons = %v", view.Reasons)
	}
}

func TestOperationalSourceRecoveryClearsDegradation(t *testing.T) {
	degraded := healthyMetadata()
	degraded["source_health"] = []interface{}{sourceEntry("windows-event:System", "DEGRADED")}
	before := EvaluateCollectorOperational(Collector{State: "ACTIVE", LastSeenAt: seenAt(5 * time.Second), HealthMetadata: degraded}, evaluatedAt)
	if before.Overall != OperationalDegraded {
		t.Fatalf("precondition: %+v", before)
	}
	after := EvaluateCollectorOperational(Collector{State: "ACTIVE", LastSeenAt: seenAt(5 * time.Second), HealthMetadata: healthyMetadata()}, evaluatedAt)
	if after.Overall != OperationalHealthy || len(after.Reasons) != 0 {
		t.Fatalf("recovered agent = %+v", after)
	}
}

func TestOperationalOfflineOnStaleHeartbeat(t *testing.T) {
	view := EvaluateCollectorOperational(Collector{
		State: "ACTIVE", LastSeenAt: seenAt(10 * time.Minute), HealthMetadata: healthyMetadata(),
	}, evaluatedAt)
	if view.Connectivity != ConnectivityOffline || view.Overall != OperationalOffline {
		t.Fatalf("stale heartbeat = %+v", view)
	}
	if view.SecondsSinceLastSeen < 599 || view.SecondsSinceLastSeen > 601 {
		t.Fatalf("seconds since last seen = %f", view.SecondsSinceLastSeen)
	}
}

func TestOperationalNeverSeenAndRevoked(t *testing.T) {
	never := EvaluateCollectorOperational(Collector{State: "ACTIVE"}, evaluatedAt)
	if never.Connectivity != ConnectivityNeverSeen || never.Overall != OperationalNeverSeen {
		t.Fatalf("never seen = %+v", never)
	}
	revoked := EvaluateCollectorOperational(Collector{State: "REVOKED", LastSeenAt: seenAt(time.Second)}, evaluatedAt)
	if revoked.Connectivity != ConnectivityRevoked || revoked.Overall != OperationalRevoked {
		t.Fatalf("revoked = %+v", revoked)
	}
}

func TestOperationalDegradedBySendFailureAndStaleBacklog(t *testing.T) {
	metadata := healthyMetadata()
	metadata["queue_oldest_age_seconds"] = 3600.0
	metadata["throughput"] = map[string]interface{}{
		"collection_rate_eps": 1.0, "delivery_rate_eps": 0.0,
		"send_failures_total": float64(9), "last_send_error": "KCSP gateway returned 503",
	}
	view := EvaluateCollectorOperational(Collector{
		State: "ACTIVE", LastSeenAt: seenAt(5 * time.Second), HealthMetadata: metadata,
	}, evaluatedAt)
	if view.Overall != OperationalDegraded {
		t.Fatalf("send failures must degrade: %+v", view)
	}
	if !containsReason(view.Reasons, "SEND_FAILING") || !containsReason(view.Reasons, "BACKLOG_STALE") {
		t.Fatalf("reasons = %v", view.Reasons)
	}
	if view.SendFailures != 9 || view.LastSendError == "" {
		t.Fatalf("send failure detail lost: %+v", view)
	}
}

func TestOperationalUnknownWithoutMetadata(t *testing.T) {
	view := EvaluateCollectorOperational(Collector{State: "ACTIVE", LastSeenAt: seenAt(time.Second)}, evaluatedAt)
	if view.Connectivity != ConnectivityOnline {
		t.Fatalf("connectivity = %q", view.Connectivity)
	}
	if view.Telemetry != TelemetryUnknown {
		t.Fatalf("an agent that reported no metadata has unknown telemetry, got %q", view.Telemetry)
	}
}

func containsReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}
