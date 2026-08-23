package ingest

import (
	"context"
	"errors"
	"testing"
)

type healthPublisher struct {
	err error
}

func (p *healthPublisher) Publish(context.Context, RawEnvelope) error { return nil }
func (p *healthPublisher) RawTopic() string                           { return "kcsp.test.raw.v1" }
func (p *healthPublisher) Health(context.Context) error               { return p.err }

func TestGatewayHealthDelegatesToPublisher(t *testing.T) {
	expected := errors.New("Kafka unavailable")
	gateway := NewGateway(&healthPublisher{err: expected}, testEnvelopeAuthenticator(t))
	if err := gateway.Health(context.Background()); !errors.Is(err, expected) {
		t.Fatalf("health error = %v, want publisher error", err)
	}
}

func TestGatewayHealthRejectsMissingPublisher(t *testing.T) {
	if err := (*Gateway)(nil).Health(context.Background()); err == nil {
		t.Fatal("nil gateway reported healthy")
	}
}
