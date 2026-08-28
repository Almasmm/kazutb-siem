package core

import (
	"sort"
	"strings"
	"time"
)

// Connectivity states describe whether the agent is reaching the platform.
const (
	ConnectivityOnline    = "ONLINE"
	ConnectivityOffline   = "OFFLINE"
	ConnectivityNeverSeen = "NEVER_SEEN"
	ConnectivityRevoked   = "REVOKED"
)

// Telemetry states describe whether data is actually flowing. Connectivity and
// telemetry are deliberately separate: an agent whose heartbeat succeeds while
// its channels fail or its backlog grows is reachable but not working, and
// reporting only ONLINE hides exactly the failure an operator needs to see.
const (
	TelemetryHealthy  = "HEALTHY"
	TelemetryDegraded = "DEGRADED"
	TelemetryUnknown  = "UNKNOWN"
)

// Overall states combine the two for a single column in the console.
const (
	OperationalHealthy   = "HEALTHY"
	OperationalDegraded  = "DEGRADED"
	OperationalOffline   = "OFFLINE"
	OperationalNeverSeen = "NEVER_SEEN"
	OperationalRevoked   = "REVOKED"
)

// Thresholds for calling an otherwise-reachable agent degraded. They are
// deliberately generous: a short burst of queueing during a spike is normal,
// a persistently growing or stale backlog is not.
const (
	BacklogDegradedDepth   = 5000
	BacklogDegradedAge     = 15 * time.Minute
	BacklogGrowthDepthFloor = 500
	HeartbeatOfflineAfter  = 2 * time.Minute
)

// CollectorOperational is the derived operational view of one collector. It is
// computed on the server so every client applies the same policy.
type CollectorOperational struct {
	Connectivity string   `json:"connectivity"`
	Telemetry    string   `json:"telemetry"`
	Overall      string   `json:"overall"`
	Reasons      []string `json:"reasons,omitempty"`

	QueueDepth  int64 `json:"queue_depth"`
	QueueBytes  int64 `json:"queue_bytes"`
	SourceTotal int   `json:"source_total"`
	SourceHealthy  int `json:"source_healthy"`
	SourceDegraded int `json:"source_degraded"`

	CollectionRate float64 `json:"collection_rate_eps"`
	DeliveryRate   float64 `json:"delivery_rate_eps"`
	NetBacklogRate float64 `json:"net_backlog_rate_eps"`

	EventsCollectedTotal int64 `json:"events_collected_total"`
	EventsDeliveredTotal int64 `json:"events_delivered_total"`
	SendFailures         int64 `json:"send_failures_total"`

	QueueOldestAgeSeconds float64    `json:"queue_oldest_age_seconds,omitempty"`
	QueueDrainETASeconds  float64    `json:"queue_drain_eta_seconds,omitempty"`
	BacklogDraining       bool       `json:"backlog_draining"`
	LastDeliveryAt        *time.Time `json:"last_delivery_at,omitempty"`
	LastSendError         string     `json:"last_send_error,omitempty"`
	SecondsSinceLastSeen  float64    `json:"seconds_since_last_seen,omitempty"`
	AgentStartedAt        *time.Time `json:"agent_started_at,omitempty"`
	UptimeSeconds         float64    `json:"uptime_seconds,omitempty"`
	DegradedSources       []string   `json:"degraded_sources,omitempty"`
}

// EvaluateCollectorOperational derives the operational view from the collector
// record and the metadata its agent last reported.
func EvaluateCollectorOperational(collector Collector, now time.Time) CollectorOperational {
	metadata := collector.HealthMetadata
	view := CollectorOperational{
		Connectivity: connectivityOf(collector, now),
		Telemetry:    TelemetryUnknown,
	}
	view.QueueDepth = metadataInt(metadata, "queue_depth")
	view.QueueBytes = metadataInt(metadata, "queue_bytes")
	view.QueueOldestAgeSeconds = metadataFloat(metadata, "queue_oldest_age_seconds")
	view.QueueDrainETASeconds = metadataFloat(metadata, "queue_drain_eta_seconds")

	if throughput := metadataObject(metadata, "throughput"); throughput != nil {
		view.CollectionRate = metadataFloat(throughput, "collection_rate_eps")
		view.DeliveryRate = metadataFloat(throughput, "delivery_rate_eps")
		view.NetBacklogRate = metadataFloat(throughput, "net_backlog_rate_eps")
		view.EventsCollectedTotal = metadataInt(throughput, "events_collected_total")
		view.EventsDeliveredTotal = metadataInt(throughput, "events_delivered_total")
		view.SendFailures = metadataInt(throughput, "send_failures_total")
		view.LastSendError = metadataString(throughput, "last_send_error")
		if moment, ok := metadataTime(throughput, "last_delivery_at"); ok {
			view.LastDeliveryAt = &moment
		}
	}
	if moment, ok := metadataTime(metadata, "agent_started_at"); ok {
		view.AgentStartedAt = &moment
		view.UptimeSeconds = roundSeconds(now.Sub(moment))
	}
	if collector.LastSeenAt != nil {
		view.SecondsSinceLastSeen = roundSeconds(now.Sub(collector.LastSeenAt.UTC()))
	}
	view.BacklogDraining = view.QueueDepth > 0 && view.DeliveryRate > view.CollectionRate

	view.SourceTotal, view.SourceHealthy, view.SourceDegraded, view.DegradedSources = summarizeSources(metadata)

	view.Telemetry, view.Reasons = evaluateTelemetry(view, metadata)
	view.Overall = overallState(view)
	return view
}

func connectivityOf(collector Collector, now time.Time) string {
	if strings.EqualFold(collector.State, "REVOKED") {
		return ConnectivityRevoked
	}
	if collector.LastSeenAt == nil {
		return ConnectivityNeverSeen
	}
	if now.Sub(collector.LastSeenAt.UTC()) > HeartbeatOfflineAfter {
		return ConnectivityOffline
	}
	return ConnectivityOnline
}

// evaluateTelemetry decides whether data is actually flowing, and records why.
func evaluateTelemetry(view CollectorOperational, metadata map[string]interface{}) (string, []string) {
	var reasons []string
	if len(metadata) == 0 {
		return TelemetryUnknown, nil
	}
	if view.SourceDegraded > 0 {
		reasons = append(reasons, "SOURCE_DEGRADED")
	}
	// A backlog that is growing means collection is outrunning delivery, which
	// no amount of successful heartbeating makes acceptable.
	if view.QueueDepth >= BacklogGrowthDepthFloor && view.NetBacklogRate > 0 {
		reasons = append(reasons, "BACKLOG_GROWING")
	}
	if view.QueueDepth >= BacklogDegradedDepth {
		reasons = append(reasons, "BACKLOG_HIGH")
	}
	if view.QueueOldestAgeSeconds > BacklogDegradedAge.Seconds() {
		reasons = append(reasons, "BACKLOG_STALE")
	}
	if strings.TrimSpace(view.LastSendError) != "" {
		reasons = append(reasons, "SEND_FAILING")
	}
	if len(reasons) > 0 {
		return TelemetryDegraded, reasons
	}
	if view.SourceTotal == 0 {
		return TelemetryUnknown, nil
	}
	return TelemetryHealthy, nil
}

func overallState(view CollectorOperational) string {
	switch view.Connectivity {
	case ConnectivityRevoked:
		return OperationalRevoked
	case ConnectivityNeverSeen:
		return OperationalNeverSeen
	case ConnectivityOffline:
		return OperationalOffline
	}
	if view.Telemetry == TelemetryDegraded {
		return OperationalDegraded
	}
	if view.Telemetry == TelemetryHealthy {
		return OperationalHealthy
	}
	return OperationalHealthy
}

func summarizeSources(metadata map[string]interface{}) (total, healthy, degraded int, degradedNames []string) {
	entries, ok := metadata["source_health"].([]interface{})
	if !ok {
		return 0, 0, 0, nil
	}
	for _, entry := range entries {
		source, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		total++
		switch strings.ToUpper(metadataString(source, "state")) {
		case TelemetryHealthy:
			healthy++
		case TelemetryDegraded:
			degraded++
			if name := metadataString(source, "name"); name != "" {
				degradedNames = append(degradedNames, name)
			}
		}
	}
	sort.Strings(degradedNames)
	return total, healthy, degraded, degradedNames
}

// Metadata arrives as free-form JSON, so every read is defensive.
func metadataObject(metadata map[string]interface{}, key string) map[string]interface{} {
	if metadata == nil {
		return nil
	}
	nested, _ := metadata[key].(map[string]interface{})
	return nested
}

func metadataFloat(metadata map[string]interface{}, key string) float64 {
	if metadata == nil {
		return 0
	}
	switch value := metadata[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	default:
		return 0
	}
}

func metadataInt(metadata map[string]interface{}, key string) int64 {
	return int64(metadataFloat(metadata, key))
}

func metadataString(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func metadataTime(metadata map[string]interface{}, key string) (time.Time, bool) {
	raw := metadataString(metadata, key)
	if raw == "" {
		return time.Time{}, false
	}
	moment, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return moment.UTC(), true
}

func roundSeconds(value time.Duration) float64 {
	return float64(int64(value.Seconds()*100+0.5)) / 100
}
