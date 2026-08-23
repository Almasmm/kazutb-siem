package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/twmb/franz-go/pkg/kgo"
)

type concurrentRawStore struct {
	active  atomic.Int32
	peak    atomic.Int32
	entered chan struct{}
	release <-chan struct{}
}

func (s *concurrentRawStore) PutRawEnvelope(ctx context.Context, _ RawEnvelope) error {
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for {
		peak := s.peak.Load()
		if active <= peak || s.peak.CompareAndSwap(peak, active) {
			break
		}
	}
	select {
	case s.entered <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type successfulParser struct{}

func (successfulParser) Parse(_ context.Context, envelope RawEnvelope) (core.CanonicalEvent, error) {
	return core.CanonicalEvent{ID: envelope.EventID}, nil
}

type successfulPipeline struct{}

func (successfulPipeline) Ingest(context.Context, string, core.CanonicalEvent) (core.IngestResult, error) {
	return core.IngestResult{}, nil
}

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
		pipeline: pipeline, dlq: dlq, authenticator: testEnvelopeAuthenticator(t),
	}
	envelope := testRawEnvelope("tenant-1", []byte("opaque evidence"))
	if err := processor.authenticator.Sign(&envelope); err != nil {
		t.Fatal(err)
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

func TestProcessorBoundsConcurrentRecordProcessing(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	rawStore := &concurrentRawStore{entered: make(chan struct{}, 4), release: release}
	processor := &Processor{
		rawStore: rawStore, parser: successfulParser{}, pipeline: successfulPipeline{},
		dlq: &recordingDeadLetter{order: &[]string{}}, authenticator: testEnvelopeAuthenticator(t), maxWorkers: 2,
	}
	records := make([]*kgo.Record, 0, 4)
	for index := 0; index < 4; index++ {
		envelope := testRawEnvelope("tenant-1", []byte(fmt.Sprintf("payload-%d", index)))
		envelope.MessageID = fmt.Sprintf("message-%d", index)
		envelope.EventID = fmt.Sprintf("event-%d", index)
		if err := processor.authenticator.Sign(&envelope); err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, &kgo.Record{Topic: "raw", Partition: 1, Offset: int64(index), Value: body})
	}

	done := make(chan error, 1)
	go func() { done <- processor.processRecords(context.Background(), records) }()
	for entered := 0; entered < 2; entered++ {
		select {
		case <-rawStore.entered:
		case <-time.After(time.Second):
			t.Fatal("processor did not start the configured workers")
		}
	}
	if peak := rawStore.peak.Load(); peak != 2 {
		t.Fatalf("peak workers = %d, want 2", peak)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("processor worker pool did not drain")
	}
	if peak := rawStore.peak.Load(); peak > 2 {
		t.Fatalf("worker bound exceeded: %d", peak)
	}
}
