package agent

import (
	"sort"
	"sync"
	"time"
)

// Source health states reported separately from agent connectivity. An agent
// whose heartbeat succeeds is ONLINE, but a channel that cannot be read is
// DEGRADED, and the two must not be conflated.
const (
	SourceStateStarting    = "STARTING"
	SourceStateHealthy     = "HEALTHY"
	SourceStateDegraded    = "DEGRADED"
	SourceStateUnsupported = "UNSUPPORTED"
)

// backoffSchedule bounds how often a failing source is retried. A permanently
// broken channel settles at one attempt per minute instead of one every poll.
var backoffSchedule = []time.Duration{
	2 * time.Second,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

// SourceHealth is the per-source view surfaced in heartbeat metadata.
type SourceHealth struct {
	Name              string    `json:"name"`
	Channel           string    `json:"channel,omitempty"`
	State             string    `json:"state"`
	LastSuccessAt     time.Time `json:"last_success_at,omitempty"`
	LastErrorAt       time.Time `json:"last_error_at,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	ErrorCount        uint64    `json:"error_count"`
	ConsecutiveErrors int       `json:"consecutive_errors"`
	EventsRead        uint64    `json:"events_read"`
	Checkpoint        uint64    `json:"checkpoint"`
	Quarantined       uint64    `json:"quarantined,omitempty"`
	Encoding          string    `json:"encoding,omitempty"`
	NextAttemptAt     time.Time `json:"next_attempt_at,omitempty"`
	BackoffSeconds    float64   `json:"backoff_seconds,omitempty"`
}

// SourceTracker records per-source outcomes, applies retry backoff, and rate
// limits repeated error logging.
type SourceTracker struct {
	mu      sync.Mutex
	entries map[string]*sourceEntry
	order   []string
}

type sourceEntry struct {
	health        SourceHealth
	backoffIndex  int
	loggedAtLevel int
	suppressed    uint64
}

func NewSourceTracker() *SourceTracker {
	return &SourceTracker{entries: make(map[string]*sourceEntry)}
}

// Register declares a source before its first read so health reporting lists
// it as STARTING rather than omitting it.
func (t *SourceTracker) Register(name, channel string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, found := t.entries[name]; found {
		return
	}
	t.entries[name] = &sourceEntry{health: SourceHealth{Name: name, Channel: channel, State: SourceStateStarting}}
	t.order = append(t.order, name)
}

func (t *SourceTracker) entry(name string) *sourceEntry {
	item, found := t.entries[name]
	if !found {
		item = &sourceEntry{health: SourceHealth{Name: name, State: SourceStateStarting}}
		t.entries[name] = item
		t.order = append(t.order, name)
	}
	return item
}

// ShouldAttempt reports whether a source is due for a read.
func (t *SourceTracker) ShouldAttempt(name string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	item := t.entry(name)
	if item.health.NextAttemptAt.IsZero() {
		return true
	}
	return !now.Before(item.health.NextAttemptAt)
}

// RecordSuccess clears the backoff and marks the source healthy. A successful
// read after failures resets the schedule to its first step.
func (t *SourceTracker) RecordSuccess(name string, now time.Time, eventsRead int, checkpoint, quarantined uint64, encoding string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	item := t.entry(name)
	item.backoffIndex = 0
	item.loggedAtLevel = 0
	item.suppressed = 0
	item.health.State = SourceStateHealthy
	item.health.LastSuccessAt = now
	item.health.ConsecutiveErrors = 0
	item.health.LastError = ""
	item.health.NextAttemptAt = time.Time{}
	item.health.BackoffSeconds = 0
	item.health.EventsRead += uint64(eventsRead)
	item.health.Checkpoint = checkpoint
	item.health.Quarantined = quarantined
	item.health.Encoding = encoding
}

// RecordFailure applies the next backoff step and reports whether this failure
// should be logged. Repeats at the same backoff level are suppressed, so a
// permanently failing source logs on escalation rather than every poll.
func (t *SourceTracker) RecordFailure(name string, now time.Time, err error, unsupported bool) (shouldLog bool, suppressed uint64, retryAt time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	item := t.entry(name)
	item.health.ErrorCount++
	item.health.ConsecutiveErrors++
	item.health.LastErrorAt = now
	if err != nil {
		item.health.LastError = truncateError(err.Error())
	}
	if unsupported {
		item.health.State = SourceStateUnsupported
	} else {
		item.health.State = SourceStateDegraded
	}
	level := item.backoffIndex
	if level >= len(backoffSchedule) {
		level = len(backoffSchedule) - 1
	}
	delay := backoffSchedule[level]
	item.health.NextAttemptAt = now.Add(delay)
	item.health.BackoffSeconds = delay.Seconds()
	if item.backoffIndex < len(backoffSchedule)-1 {
		item.backoffIndex++
	}
	// Log the first failure at each backoff level; suppress the repeats in
	// between and report how many were folded away.
	if item.loggedAtLevel <= level {
		item.loggedAtLevel = level + 1
		suppressed = item.suppressed
		item.suppressed = 0
		return true, suppressed, item.health.NextAttemptAt
	}
	item.suppressed++
	return false, 0, item.health.NextAttemptAt
}

// Snapshot returns the per-source health list ordered by registration.
func (t *SourceTracker) Snapshot() []SourceHealth {
	t.mu.Lock()
	defer t.mu.Unlock()
	names := append([]string(nil), t.order...)
	sort.SliceStable(names, func(i, j int) bool { return names[i] < names[j] })
	snapshot := make([]SourceHealth, 0, len(names))
	for _, name := range names {
		snapshot = append(snapshot, t.entries[name].health)
	}
	return snapshot
}

// Overall summarises source health for the heartbeat. It is DEGRADED whenever
// any supported source is failing, even though agent connectivity is fine.
func (t *SourceTracker) Overall() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.order) == 0 {
		return SourceStateStarting
	}
	healthy := 0
	degraded := 0
	supported := 0
	for _, name := range t.order {
		switch t.entries[name].health.State {
		case SourceStateHealthy:
			healthy++
			supported++
		case SourceStateDegraded:
			degraded++
			supported++
		case SourceStateStarting:
			supported++
		}
	}
	if supported == 0 {
		return SourceStateUnsupported
	}
	if degraded > 0 {
		return SourceStateDegraded
	}
	if healthy == 0 {
		return SourceStateStarting
	}
	return SourceStateHealthy
}

// DegradedSources lists the names of sources that are currently failing.
func (t *SourceTracker) DegradedSources() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	names := make([]string, 0)
	for _, name := range t.order {
		if t.entries[name].health.State == SourceStateDegraded {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func truncateError(message string) string {
	const limit = 512
	if len(message) <= limit {
		return message
	}
	return message[:limit]
}
