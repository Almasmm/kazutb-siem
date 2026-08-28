package agent

import (
	"sync"
	"time"
)

// ThroughputTracker measures collection and delivery rates on the agent so the
// console can tell a healthy endpoint from one whose backlog is growing.
// Collection and delivery are counted separately: an agent that reads faster
// than it ships is ONLINE but not healthy, and only the two rates together make
// that visible.
type ThroughputTracker struct {
	mu sync.Mutex

	collectedTotal uint64
	deliveredTotal uint64
	sendFailures   uint64

	windowStart     time.Time
	windowCollected uint64
	windowDelivered uint64

	// Rates from the most recently completed window, so a reader never sees a
	// rate computed over a few milliseconds.
	collectionRate float64
	deliveryRate   float64

	lastDeliveryAt time.Time
	lastFailureAt  time.Time
	lastSendError  string
	now            func() time.Time
}

// rateWindow is the interval over which EPS is averaged and reported.
const rateWindow = 30 * time.Second

func NewThroughputTracker(start time.Time) *ThroughputTracker {
	return &ThroughputTracker{windowStart: start, now: time.Now}
}

// ThroughputSnapshot is the delivery view published in heartbeat metadata.
type ThroughputSnapshot struct {
	EventsCollectedTotal uint64    `json:"events_collected_total"`
	EventsDeliveredTotal uint64    `json:"events_delivered_total"`
	CollectionRate       float64   `json:"collection_rate_eps"`
	DeliveryRate         float64   `json:"delivery_rate_eps"`
	NetBacklogRate       float64   `json:"net_backlog_rate_eps"`
	SendFailures         uint64    `json:"send_failures_total"`
	LastDeliveryAt       time.Time `json:"last_delivery_at,omitempty"`
	LastSendErrorAt      time.Time `json:"last_send_error_at,omitempty"`
	LastSendError        string    `json:"last_send_error,omitempty"`
	RateWindowSeconds    float64   `json:"rate_window_seconds"`
}

func (t *ThroughputTracker) RecordCollected(count int) {
	if count <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.collectedTotal += uint64(count)
	t.windowCollected += uint64(count)
	t.rollLocked(t.now())
}

func (t *ThroughputTracker) RecordDelivered(count int) {
	if count <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	moment := t.now()
	t.deliveredTotal += uint64(count)
	t.windowDelivered += uint64(count)
	t.lastDeliveryAt = moment
	t.rollLocked(moment)
}

func (t *ThroughputTracker) RecordSendFailure(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sendFailures++
	t.lastFailureAt = t.now()
	if err != nil {
		t.lastSendError = truncateError(err.Error())
	}
}

// rollLocked closes the measurement window once it is old enough, so reported
// rates describe a full window rather than a partial one.
func (t *ThroughputTracker) rollLocked(moment time.Time) {
	elapsed := moment.Sub(t.windowStart)
	if elapsed < rateWindow {
		return
	}
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return
	}
	t.collectionRate = float64(t.windowCollected) / seconds
	t.deliveryRate = float64(t.windowDelivered) / seconds
	t.windowCollected = 0
	t.windowDelivered = 0
	t.windowStart = moment
}

// Snapshot reports the current rates. A window that has been open long enough
// is reported live, so a stalled agent does not keep publishing a stale rate.
func (t *ThroughputTracker) Snapshot() ThroughputSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	collection := t.collectionRate
	delivery := t.deliveryRate
	if elapsed := t.now().Sub(t.windowStart); elapsed >= time.Second {
		seconds := elapsed.Seconds()
		collection = float64(t.windowCollected) / seconds
		delivery = float64(t.windowDelivered) / seconds
	}
	return ThroughputSnapshot{
		EventsCollectedTotal: t.collectedTotal,
		EventsDeliveredTotal: t.deliveredTotal,
		CollectionRate:       round2(collection),
		DeliveryRate:         round2(delivery),
		NetBacklogRate:       round2(collection - delivery),
		SendFailures:         t.sendFailures,
		LastDeliveryAt:       t.lastDeliveryAt,
		LastSendErrorAt:      t.lastFailureAt,
		LastSendError:        t.lastSendError,
		RateWindowSeconds:    rateWindow.Seconds(),
	}
}

func round2(value float64) float64 {
	return float64(int64(value*100+0.5)) / 100
}
