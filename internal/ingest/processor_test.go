package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/twmb/franz-go/pkg/kgo"
)

type orderedRawStore struct{ order *[]string }

func (s orderedRawStore) PutRawEnvelope(context.Context, RawEnvelope) error {
	*s.order = append(*s.order, "raw-store")
	return nil
}

type orderedFailingParser struct{ order *[]string }

func (p orderedFailingParser) Parse(context.Context, RawEnvelope) (core.CanonicalEvent, error) {
	*p.order = append(*p.order, "parser")
	return core.CanonicalEvent{}, errors.New("unsupported vendor event")
}

type forbiddenPipeline struct{ called bool }

func (p *forbiddenPipeline) Ingest(context.Context, string, core.CanonicalEvent) (core.IngestResult, error) {
	p.called = true
	return core.IngestResult{}, nil
}

type recordingDeadLetter struct {
	order      *[]string
	deadLetter DeadLetter
}

func (d *recordingDeadLetter) PublishDeadLetter(_ context.Context, deadLetter DeadLetter) error {
	*d.order = append(*d.order, "dlq")
	d.deadLetter = deadLetter
	return nil
}

func TestProcessorPersistsRawBeforeParserFailureIsQuarantined(t *testing.T) {
	order := []string{}
	pipeline := &forbiddenPipeline{}
	dlq := &recordingDeadLetter{order: &order}
	processor := &Processor{
		rawStore: orderedRawStore{order: &order}, parser: orderedFailingParser{order: &order},
		pipeline: pipeline, dlq: dlq,
	}
	envelope := RawEnvelope{
		MessageID: "message-1", EventID: "event-1", TenantID: "tenant-1", CollectorID: "collector-1",
		Format: "unknown-vendor-v1", ReceivedAt: time.Now().UTC(), RawPayload: []byte("opaque evidence"),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.processRecord(context.Background(), &kgo.Record{Value: body}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"raw-store", "parser", "dlq"}) {
		t.Fatalf("incorrect failure ordering: %v", order)
	}
	if pipeline.called {
		t.Fatal("detection pipeline must not receive an unparsed event")
	}
	if dlq.deadLetter.Stage != "parser" || dlq.deadLetter.Envelope.EventID != envelope.EventID {
		t.Fatalf("invalid dead letter: %+v", dlq.deadLetter)
	}
}
