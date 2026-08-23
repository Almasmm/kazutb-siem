package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/twmb/franz-go/pkg/kgo"
)

type RawStore interface {
	PutRawEnvelope(context.Context, RawEnvelope) error
}

type EnvelopeParser interface {
	Parse(context.Context, RawEnvelope) (core.CanonicalEvent, error)
}

type DetectionPipeline interface {
	Ingest(context.Context, string, core.CanonicalEvent) (core.IngestResult, error)
}

type DeadLetterPublisher interface {
	PublishDeadLetter(context.Context, DeadLetter) error
}

type ProcessorConfig struct {
	Brokers         []string
	ClientID        string
	GroupID         string
	Topic           string
	EnvelopeHMACKey string
	MaxWorkers      int
}

type Processor struct {
	consumer      *kgo.Client
	rawStore      RawStore
	parser        EnvelopeParser
	pipeline      DetectionPipeline
	dlq           DeadLetterPublisher
	authenticator *EnvelopeAuthenticator
	maxWorkers    int
}

const (
	defaultProcessorWorkers = 64
	maximumProcessorWorkers = 256
)

func OpenProcessor(config ProcessorConfig, rawStore RawStore, eventParser EnvelopeParser, pipeline DetectionPipeline, dlq DeadLetterPublisher) (*Processor, error) {
	authenticator, err := NewEnvelopeAuthenticator(config.EnvelopeHMACKey)
	if err != nil {
		return nil, fmt.Errorf("configure Kafka envelope integrity: %w", err)
	}
	if config.ClientID == "" {
		config.ClientID = "kcsp-processor"
	}
	if config.GroupID == "" {
		config.GroupID = "kcsp-canonical-processing-v1"
	}
	if config.Topic == "" {
		config.Topic = "kcsp.raw.events.v1"
	}
	consumer, err := kgo.NewClient(
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.ConsumerGroup(config.GroupID),
		kgo.ConsumeTopics(config.Topic),
		kgo.DisableAutoCommit(),
		kgo.BlockRebalanceOnPoll(),
		kgo.FetchMinBytes(256<<10),
		kgo.FetchMaxWait(200*time.Millisecond),
		kgo.FetchMaxBytes(32<<20),
	)
	if err != nil {
		return nil, fmt.Errorf("create Kafka processor: %w", err)
	}
	return &Processor{
		consumer: consumer, rawStore: rawStore, parser: eventParser, pipeline: pipeline, dlq: dlq,
		authenticator: authenticator, maxWorkers: normalizeProcessorWorkers(config.MaxWorkers),
	}, nil
}

func (p *Processor) Close() { p.consumer.Close() }

func (p *Processor) Health(ctx context.Context) error {
	if err := p.consumer.Ping(ctx); err != nil {
		return fmt.Errorf("ping Kafka: %w", err)
	}
	return nil
}

func (p *Processor) Run(ctx context.Context) error {
	for {
		fetches := p.consumer.PollFetches(ctx)
		if ctx.Err() != nil {
			p.consumer.AllowRebalance()
			return nil
		}
		err := func() error {
			defer p.consumer.AllowRebalance()
			for _, fetchError := range fetches.Errors() {
				if fetchError.Err != nil {
					return fmt.Errorf("consume Kafka partition %s/%d: %w", fetchError.Topic, fetchError.Partition, fetchError.Err)
				}
			}
			records := fetches.Records()
			if err := p.processRecords(ctx, records); err != nil {
				return err
			}
			if len(records) > 0 {
				if err := p.consumer.CommitRecords(ctx, records...); err != nil {
					return fmt.Errorf("commit Kafka offsets: %w", err)
				}
			}
			return nil
		}()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

// processRecords bounds concurrency while allowing independent telemetry to
// overlap durable PostgreSQL and ClickHouse I/O. Kafka offsets are committed
// only after the entire fetched block succeeds, so a hard failure replays the
// block rather than acknowledging partially processed security telemetry.
func (p *Processor) processRecords(ctx context.Context, records []*kgo.Record) error {
	if len(records) == 0 {
		return nil
	}
	workers := normalizeProcessorWorkers(p.maxWorkers)
	if workers > len(records) {
		workers = len(records)
	}
	if workers == 1 {
		for _, record := range records {
			if err := p.processRecord(ctx, record); err != nil {
				return err
			}
		}
		return nil
	}

	batchContext, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan *kgo.Record)
	var wait sync.WaitGroup
	var errorOnce sync.Once
	var firstError error
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for record := range jobs {
				if batchContext.Err() != nil {
					return
				}
				if err := p.processRecord(batchContext, record); err != nil {
					errorOnce.Do(func() {
						firstError = fmt.Errorf("process Kafka record %s/%d/%d: %w", record.Topic, record.Partition, record.Offset, err)
						cancel()
					})
					return
				}
			}
		}()
	}

dispatch:
	for _, record := range records {
		select {
		case jobs <- record:
		case <-batchContext.Done():
			break dispatch
		}
	}
	close(jobs)
	wait.Wait()
	if firstError != nil {
		return firstError
	}
	return ctx.Err()
}

func normalizeProcessorWorkers(value int) int {
	if value <= 0 {
		return defaultProcessorWorkers
	}
	if value > maximumProcessorWorkers {
		return maximumProcessorWorkers
	}
	return value
}

func (p *Processor) processRecord(ctx context.Context, record *kgo.Record) error {
	var envelope RawEnvelope
	if err := json.Unmarshal(record.Value, &envelope); err != nil {
		return p.deadLetter(ctx, envelope, "envelope", fmt.Errorf("decode raw envelope: %w", err))
	}
	if err := p.authenticator.Verify(envelope); err != nil {
		return p.deadLetter(ctx, envelope, "envelope", err)
	}
	if err := p.rawStore.PutRawEnvelope(ctx, envelope); err != nil {
		return fmt.Errorf("persist raw envelope before acknowledgement: %w", err)
	}
	event, err := p.parser.Parse(ctx, envelope)
	if err != nil {
		return p.deadLetter(ctx, envelope, "parser", err)
	}
	if _, err := p.pipeline.Ingest(ctx, envelope.TenantID, event); err != nil {
		return p.deadLetter(ctx, envelope, "pipeline", err)
	}
	return nil
}

func (p *Processor) deadLetter(ctx context.Context, envelope RawEnvelope, stage string, cause error) error {
	deadLetter := DeadLetter{Envelope: envelope, Stage: stage, Error: cause.Error(), FailedAt: time.Now().UTC()}
	if err := p.dlq.PublishDeadLetter(ctx, deadLetter); err != nil {
		return fmt.Errorf("publish dead letter after %s failure (%v): %w", stage, cause, err)
	}
	return nil
}
