package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

type KafkaTLSConfig struct {
	Enabled    bool
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
}

type KafkaSASLConfig struct {
	Mechanism string
	Username  string
	Password  string
}

type KafkaSecurityConfig struct {
	RequireTLS bool
	TLS        KafkaTLSConfig
	SASL       KafkaSASLConfig
}

type KafkaConfig struct {
	Brokers           []string
	ClientID          string
	RawTopic          string
	DeadLetterTopic   string
	Partitions        int32
	ReplicationFactor int16
	Security          KafkaSecurityConfig
}

func KafkaSecurityConfigFromEnvironment(requireTLS bool) (KafkaSecurityConfig, error) {
	tlsEnabled := requireTLS
	if value := strings.TrimSpace(os.Getenv("KCSP_KAFKA_TLS_ENABLED")); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return KafkaSecurityConfig{}, fmt.Errorf("parse KCSP_KAFKA_TLS_ENABLED: %w", err)
		}
		tlsEnabled = parsed
	}
	config := KafkaSecurityConfig{
		RequireTLS: requireTLS,
		TLS: KafkaTLSConfig{
			Enabled: tlsEnabled, CAFile: strings.TrimSpace(os.Getenv("KCSP_KAFKA_TLS_CA_FILE")),
			CertFile: strings.TrimSpace(os.Getenv("KCSP_KAFKA_TLS_CERT_FILE")), KeyFile: strings.TrimSpace(os.Getenv("KCSP_KAFKA_TLS_KEY_FILE")),
			ServerName: strings.TrimSpace(os.Getenv("KCSP_KAFKA_TLS_SERVER_NAME")),
		},
		SASL: KafkaSASLConfig{
			Mechanism: strings.TrimSpace(os.Getenv("KCSP_KAFKA_SASL_MECHANISM")),
			Username:  strings.TrimSpace(os.Getenv("KCSP_KAFKA_SASL_USERNAME")), Password: os.Getenv("KCSP_KAFKA_SASL_PASSWORD"),
		},
	}
	if err := config.Validate(); err != nil {
		return KafkaSecurityConfig{}, err
	}
	return config, nil
}

func (c KafkaSecurityConfig) Validate() error {
	if c.RequireTLS && !c.TLS.Enabled {
		return errors.New("Kafka TLS is required for a secure runtime profile")
	}
	if !c.TLS.Enabled && (c.TLS.CAFile != "" || c.TLS.CertFile != "" || c.TLS.KeyFile != "" || c.TLS.ServerName != "") {
		return errors.New("Kafka TLS settings require KCSP_KAFKA_TLS_ENABLED=true")
	}
	if c.TLS.Enabled {
		if _, err := loadKafkaTLSConfig(c.TLS); err != nil {
			return err
		}
	}

	mechanism := strings.ToLower(strings.TrimSpace(c.SASL.Mechanism))
	if mechanism == "" {
		if c.SASL.Username != "" || c.SASL.Password != "" {
			return errors.New("Kafka SASL credentials require a SASL mechanism")
		}
		if c.RequireTLS && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
			return errors.New("secure Kafka requires SASL credentials or an mTLS client certificate")
		}
		return nil
	}
	if strings.TrimSpace(c.SASL.Username) == "" || c.SASL.Password == "" {
		return errors.New("Kafka SASL username and password are required")
	}
	if mechanism == "plain" && !c.TLS.Enabled {
		return errors.New("Kafka SASL PLAIN is forbidden without TLS")
	}
	_, err := kafkaSASLMechanism(c.SASL)
	return err
}

func kafkaClientOptions(brokers []string, clientID string, security KafkaSecurityConfig) ([]kgo.Opt, error) {
	if err := security.Validate(); err != nil {
		return nil, err
	}
	options := []kgo.Opt{kgo.SeedBrokers(brokers...), kgo.ClientID(clientID)}
	if security.TLS.Enabled {
		tlsConfig, err := loadKafkaTLSConfig(security.TLS)
		if err != nil {
			return nil, err
		}
		options = append(options, kgo.DialTLSConfig(tlsConfig))
	}
	mechanism, err := kafkaSASLMechanism(security.SASL)
	if err != nil {
		return nil, err
	}
	if mechanism != nil {
		options = append(options, kgo.SASL(mechanism))
	}
	return options, nil
}

func loadKafkaTLSConfig(config KafkaTLSConfig) (*tls.Config, error) {
	if (config.CertFile == "") != (config.KeyFile == "") {
		return nil, errors.New("Kafka TLS client certificate and key must be configured together")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.ServerName}
	if config.CAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		// #nosec G304 -- the CA path is an administrator-controlled runtime setting.
		certificate, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read Kafka CA bundle: %w", err)
		}
		if !roots.AppendCertsFromPEM(certificate) {
			return nil, errors.New("Kafka CA bundle contains no valid certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if config.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load Kafka mTLS client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

func kafkaSASLMechanism(config KafkaSASLConfig) (sasl.Mechanism, error) {
	auth := scram.Auth{User: config.Username, Pass: config.Password}
	switch strings.ToLower(strings.TrimSpace(config.Mechanism)) {
	case "":
		return nil, nil
	case "plain":
		return plain.Auth{User: config.Username, Pass: config.Password}.AsMechanism(), nil
	case "scram-sha-256":
		return auth.AsSha256Mechanism(), nil
	case "scram-sha-512":
		return auth.AsSha512Mechanism(), nil
	default:
		return nil, fmt.Errorf("unsupported Kafka SASL mechanism %q", config.Mechanism)
	}
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
	clientOptions, err := kafkaClientOptions(config.Brokers, config.ClientID, config.Security)
	if err != nil {
		return nil, fmt.Errorf("configure Kafka producer security: %w", err)
	}
	clientOptions = append(clientOptions,
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.ZstdCompression()),
		kgo.ProducerLinger(5*time.Millisecond),
		kgo.RecordDeliveryTimeout(30*time.Second),
	)
	client, err := kgo.NewClient(clientOptions...)
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
