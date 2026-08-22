package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Brokers  []string
	ClientID string
	GroupID  string
	Topic    string
}

type Processor struct {
	consumer *kgo.Client
	rawStore RawStore
	parser   EnvelopeParser
	pipeline DetectionPipeline
	dlq      DeadLetterPublisher
}

func OpenProcessor(config ProcessorConfig, rawStore RawStore, eventParser EnvelopeParser, pipeline DetectionPipeline, dlq DeadLetterPublisher) (*Processor, error) {
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
		kgo.FetchMaxBytes(32<<20),
	)
	if err != nil {
		return nil, fmt.Errorf("create Kafka processor: %w", err)
	}
	return &Processor{consumer: consumer, rawStore: rawStore, parser: eventParser, pipeline: pipeline, dlq: dlq}, nil
}

func (p *Processor) Close() { p.consumer.Close() }

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
			for _, record := range records {
				if err := p.processRecord(ctx, record); err != nil {
					return err
				}
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

func (p *Processor) processRecord(ctx context.Context, record *kgo.Record) error {
	var envelope RawEnvelope
	if err := json.Unmarshal(record.Value, &envelope); err != nil {
		return p.deadLetter(ctx, envelope, "envelope", fmt.Errorf("decode raw envelope: %w", err))
	}
	if envelope.TenantID == "" || envelope.EventID == "" || envelope.MessageID == "" {
		return p.deadLetter(ctx, envelope, "envelope", errors.New("raw envelope identity fields are required"))
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
