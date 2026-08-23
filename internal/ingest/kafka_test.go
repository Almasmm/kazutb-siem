package ingest

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestKafkaPartitionKeyUsesStableTenantScopedSourceShards(t *testing.T) {
	t.Parallel()
	base := RawEnvelope{TenantID: "tenant-a", CollectorID: "collector-a", SourceID: "10.20.30.40"}
	first := kafkaPartitionKey(base)
	second := base
	second.EventID = "another-event"
	if !bytes.Equal(first, kafkaPartitionKey(second)) {
		t.Fatal("events from one trusted source must retain a stable partition key")
	}
	differentSource := base
	differentSource.SourceID = "10.20.30.41"
	if bytes.Equal(first, kafkaPartitionKey(differentSource)) {
		t.Fatal("independent sources must be eligible for different partitions")
	}
	differentTenant := base
	differentTenant.TenantID = "tenant-b"
	if bytes.Equal(first, kafkaPartitionKey(differentTenant)) {
		t.Fatal("partition keys must remain tenant scoped")
	}
}

func TestKafkaPartitionKeyFallsBackToCanonicalDevice(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(map[string]interface{}{"device": map[string]string{"hostname": "LAB-PC-001"}})
	if err != nil {
		t.Fatal(err)
	}
	first := RawEnvelope{TenantID: "tenant-a", CollectorID: "api", Payload: payload}
	second := first
	second.Payload = json.RawMessage(`{"device":{"hostname":"lab-pc-002"}}`)
	if bytes.Equal(kafkaPartitionKey(first), kafkaPartitionKey(second)) {
		t.Fatal("canonical devices must be independently shardable")
	}
	withoutHint := RawEnvelope{TenantID: "tenant-a", CollectorID: "api"}
	if got, want := string(kafkaPartitionKey(withoutHint)), "tenant-a|api"; got != want {
		t.Fatalf("fallback key = %q, want %q", got, want)
	}
}
