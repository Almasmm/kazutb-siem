package observability

import (
	"strings"
	"testing"
	"time"
)

func TestRegistryExportsRealCountersAndHistograms(t *testing.T) {
	registry := NewRegistry("processor", "test-version")
	registry.EventReceived()
	registry.EventParsed()
	registry.AlertCreated()
	registry.IncidentCreated()
	registry.ObserveDetection(12 * time.Millisecond)
	registry.ObserveAPI(8 * time.Millisecond)
	registry.ObserveClickHouse(4 * time.Millisecond)
	builder := &strings.Builder{}
	registry.WritePrometheus(builder)
	output := builder.String()
	for _, expected := range []string{
		"events_received_total 1", "events_parsed_total 1", "alerts_created_total 1",
		"incidents_created_total 1", "detection_latency_seconds_count 1",
		"api_latency_seconds_count 1", "clickhouse_query_latency_seconds_count 1",
		`kcsp_build_info{service="processor",version="test-version"} 1`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing metric %q in:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "kafka_lag 0") || strings.Contains(output, "collector_status 0") {
		t.Fatal("unknown operational gauges must not be exported as fake zeroes")
	}
}
