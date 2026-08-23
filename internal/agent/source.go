package agent

import "context"

// TelemetrySource reads host telemetry and advances its durable checkpoint only
// after the caller has persisted the returned event in the local disk queue.
type TelemetrySource interface {
	Name() string
	Read(context.Context, int) ([]Event, error)
	CommitEvent(Event) error
}
