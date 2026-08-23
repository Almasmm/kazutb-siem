package quota

import (
	"context"
	"time"
)

// IngestBaseline is the durable usage observed before a shared UTC-day quota
// bucket is initialized. The ledger applies it exactly once across API replicas.
type IngestBaseline struct {
	Events int64
	Bytes  int64
}

type IngestLimits struct {
	EventsPerDay int64
	BytesPerDay  int64
	EventsPerSec int64
}

type IngestReservation struct {
	TenantID string
	Now      time.Time
	Events   int64
	Bytes    int64
	Limits   IngestLimits
	Baseline *IngestBaseline
}

type IngestResult struct {
	Allowed        bool
	NeedsBootstrap bool
	Limit          string
	Events         int64
	Bytes          int64
}

// IngestLedger atomically checks and reserves all licensed ingest dimensions.
// Implementations must share state across API replicas and fail closed.
type IngestLedger interface {
	ReserveIngest(context.Context, IngestReservation) (IngestResult, error)
}
