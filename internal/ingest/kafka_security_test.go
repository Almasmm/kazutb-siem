package ingest

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestKafkaSecurityProductionRequirements(t *testing.T) {
	tests := []struct {
		name   string
		config KafkaSecurityConfig
		want   string
	}{
		{name: "TLS required", config: KafkaSecurityConfig{RequireTLS: true}, want: "TLS is required"},
		{name: "authentication required", config: KafkaSecurityConfig{RequireTLS: true, TLS: KafkaTLSConfig{Enabled: true}}, want: "SASL credentials or an mTLS"},
		{name: "SASL credentials required", config: KafkaSecurityConfig{TLS: KafkaTLSConfig{Enabled: true}, SASL: KafkaSASLConfig{Mechanism: "scram-sha-512"}}, want: "username and password"},
		{name: "PLAIN requires TLS", config: KafkaSecurityConfig{SASL: KafkaSASLConfig{Mechanism: "plain", Username: "kcsp", Password: "secret"}}, want: "forbidden without TLS"},
		{name: "unknown mechanism", config: KafkaSecurityConfig{TLS: KafkaTLSConfig{Enabled: true}, SASL: KafkaSASLConfig{Mechanism: "unknown", Username: "kcsp", Password: "secret"}}, want: "unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestKafkaSecurityAcceptsProductionSCRAMOverTLS(t *testing.T) {
	config := KafkaSecurityConfig{
		RequireTLS: true,
		TLS:        KafkaTLSConfig{Enabled: true},
		SASL:       KafkaSASLConfig{Mechanism: "scram-sha-512", Username: "kcsp", Password: "secret"},
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := loadKafkaTLSConfig(config.TLS)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %d, want TLS 1.2", tlsConfig.MinVersion)
	}
}

func TestKafkaSecurityEnvironmentFailsClosed(t *testing.T) {
	t.Setenv("KCSP_KAFKA_TLS_ENABLED", "false")
	t.Setenv("KCSP_KAFKA_SASL_MECHANISM", "")
	t.Setenv("KCSP_KAFKA_SASL_USERNAME", "")
	t.Setenv("KCSP_KAFKA_SASL_PASSWORD", "")
	if _, err := KafkaSecurityConfigFromEnvironment(true); err == nil {
		t.Fatal("production Kafka environment accepted plaintext transport")
	}
}
