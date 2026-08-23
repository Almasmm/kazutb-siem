package ingest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

func TestProcessorHealthFailsWhenKafkaIsUnavailable(t *testing.T) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers("127.0.0.1:1"),
		kgo.DialTimeout(25*time.Millisecond),
		kgo.RequestTimeoutOverhead(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	processor := &Processor{consumer: client}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := processor.Health(ctx); err == nil {
		t.Fatal("health check succeeded against an unavailable Kafka broker")
	} else if !strings.Contains(err.Error(), "ping Kafka") {
		t.Fatalf("health error = %q, want Kafka context", err)
	}
}
