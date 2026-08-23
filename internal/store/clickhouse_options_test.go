package store

import (
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func TestTelemetryAsyncInsertsAlwaysWaitForDurableFlush(t *testing.T) {
	t.Parallel()
	options := &clickhouse.Options{}
	configureTelemetryInsertOptions(options)
	if options.Settings["async_insert"] != 1 || options.Settings["wait_for_async_insert"] != 1 {
		t.Fatalf("unsafe telemetry settings: %#v", options.Settings)
	}

	options = &clickhouse.Options{Settings: clickhouse.Settings{"async_insert": 0, "wait_for_async_insert": 0}}
	configureTelemetryInsertOptions(options)
	if options.Settings["async_insert"] != 0 {
		t.Fatal("an explicit synchronous insert policy was overwritten")
	}
	if options.Settings["wait_for_async_insert"] != 1 {
		t.Fatal("fire-and-forget acknowledgement must never be enabled")
	}
}
