package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

type KafkaConfig struct {
	Brokers           []string
	ClientID          string
	RawTopic          string
	DeadLetterTopic   string
	Partitions        int32
	ReplicationFactor int16
}

type KafkaPublisher struct {
	client          *kgo.Client
	rawTopic        string
	deadLetterTopic string
}

func OpenKafkaPublisher(ctx context.Context, config KafkaConfig) (*KafkaPublisher, error) {
	config = normalizeKafkaConfig(config)
	if len(config.Brokers) == 0 {
		return nil, errors.New("at least one Kafka broker is required")
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.ZstdCompression()),
		kgo.ProducerLinger(5*time.Millisecond),
		kgo.RecordDeliveryTimeout(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("create Kafka producer: %w", err)
	}
	if err := client.Ping(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("connect Kafka: %w", err)
	}
	publisher := &KafkaPublisher{client: client, rawTopic: config.RawTopic, deadLetterTopic: config.DeadLetterTopic}
	if err := publisher.ensureTopics(ctx, config); err != nil {
		client.Close()
		return nil, err
	}
	return publisher, nil
}

func (p *KafkaPublisher) Close()                  { p.client.Close() }
func (p *KafkaPublisher) RawTopic() string        { return p.rawTopic }
func (p *KafkaPublisher) DeadLetterTopic() string { return p.deadLetterTopic }

func (p *KafkaPublisher) Health(ctx context.Context) error {
	if err := p.client.Ping(ctx); err != nil {
		return fmt.Errorf("ping Kafka: %w", err)
	}
	return nil
}

func (p *KafkaPublisher) Publish(ctx context.Context, envelope RawEnvelope) error {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode raw envelope: %w", err)
	}
	record := &kgo.Record{
		Topic: p.rawTopic, Key: kafkaPartitionKey(envelope), Value: payload,
		Headers: []kgo.RecordHeader{
			{Key: "message_id", Value: []byte(envelope.MessageID)},
			{Key: "event_id", Value: []byte(envelope.EventID)},
			{Key: "tenant_id", Value: []byte(envelope.TenantID)},
			{Key: "schema_version", Value: []byte(envelope.SchemaVersion)},
		},
		Timestamp: envelope.ReceivedAt,
	}
	if err := p.client.ProduceSync(ctx, record).FirstErr(); err != nil {
		return fmt.Errorf("produce %s: %w", p.rawTopic, err)
	}
	return nil
}

func kafkaPartitionKey(envelope RawEnvelope) []byte {
	base := envelope.TenantID + "|" + envelope.CollectorID
	identity := strings.TrimSpace(envelope.SourceID)
	if identity != "" {
		identity = "source:" + identity
	} else if len(envelope.Payload) > 0 {
		var hint struct {
			Device struct {
				Hostname string `json:"hostname"`
			} `json:"device"`
		}
		if json.Unmarshal(envelope.Payload, &hint) == nil {
			hostname := strings.ToLower(strings.TrimSpace(hint.Device.Hostname))
			if hostname != "" && len(hostname) <= 256 {
				identity = "device:" + hostname
			}
		}
	}
	if identity == "" {
		return []byte(base)
	}
	digest := sha256.Sum256([]byte(identity))
	return []byte(fmt.Sprintf("%s|%x", base, digest[:12]))
}

func (p *KafkaPublisher) PublishDeadLetter(ctx context.Context, deadLetter DeadLetter) error {
	payload, err := json.Marshal(deadLetter)
	if err != nil {
		return fmt.Errorf("encode dead letter: %w", err)
	}
	record := &kgo.Record{
		Topic: p.deadLetterTopic,
		Key:   []byte(deadLetter.Envelope.TenantID + "|" + deadLetter.Envelope.EventID),
		Value: payload,
		Headers: []kgo.RecordHeader{
			{Key: "message_id", Value: []byte(deadLetter.Envelope.MessageID)},
			{Key: "failure_stage", Value: []byte(deadLetter.Stage)},
		},
		Timestamp: deadLetter.FailedAt,
	}
	if err := p.client.ProduceSync(ctx, record).FirstErr(); err != nil {
		return fmt.Errorf("produce %s: %w", p.deadLetterTopic, err)
	}
	return nil
}

func (p *KafkaPublisher) ensureTopics(ctx context.Context, config KafkaConfig) error {
	admin := kadm.NewClient(p.client)
	cleanup := "delete"
	retention := "604800000"
	results, err := admin.CreateTopics(ctx, config.Partitions, config.ReplicationFactor, map[string]*string{
		"cleanup.policy": &cleanup,
		"retention.ms":   &retention,
	}, config.RawTopic, config.DeadLetterTopic)
	if err != nil {
		return fmt.Errorf("create Kafka topics: %w", err)
	}
	for topic, result := range results {
		if result.Err != nil && !errors.Is(result.Err, kerr.TopicAlreadyExists) {
			return fmt.Errorf("create Kafka topic %s: %w", topic, result.Err)
		}
	}
	return nil
}

func normalizeKafkaConfig(config KafkaConfig) KafkaConfig {
	brokers := make([]string, 0, len(config.Brokers))
	for _, broker := range config.Brokers {
		if broker = strings.TrimSpace(broker); broker != "" {
			brokers = append(brokers, broker)
		}
	}
	config.Brokers = brokers
	if config.ClientID == "" {
		config.ClientID = "kcsp"
	}
	if config.RawTopic == "" {
		config.RawTopic = "kcsp.raw.events.v1"
	}
	if config.DeadLetterTopic == "" {
		config.DeadLetterTopic = "kcsp.raw.events.dlq.v1"
	}
	if config.Partitions <= 0 {
		config.Partitions = 12
	}
	if config.ReplicationFactor <= 0 {
		config.ReplicationFactor = 1
	}
	return config
}
