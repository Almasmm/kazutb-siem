package agent

import (
	"errors"
	"testing"
	"time"
)

func TestSourceTrackerBacksOffAndRateLimitsLogging(t *testing.T) {
	tracker := NewSourceTracker()
	tracker.Register("windows-event:Security", "Security")
	now := time.Unix(1756000000, 0).UTC()
	failure := errors.New("decode Windows Event Log channel: invalid UTF-8")

	// The schedule escalates 2s, 5s, 10s, 30s, 60s and then holds at 60s. Each
	// escalation is logged once; once the ceiling is reached the repeats are
	// suppressed, which is what stops the every-two-seconds log storm.
	wantDelays := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second, 60 * time.Second}
	for index, want := range wantDelays {
		shouldLog, _, retryAt := tracker.RecordFailure("windows-event:Security", now, failure, false)
		escalating := index < len(backoffSchedule)
		if shouldLog != escalating {
			t.Fatalf("failure %d logged = %t, want %t", index, shouldLog, escalating)
		}
		if got := retryAt.Sub(now); got != want {
			t.Fatalf("failure %d retry delay = %s, want %s", index, got, want)
		}
		now = now.Add(want)
	}
}

func TestSourceTrackerSuppressesRepeatsWithinBackoffLevel(t *testing.T) {
	tracker := NewSourceTracker()
	tracker.Register("windows-event:System", "System")
	now := time.Unix(1756000000, 0).UTC()
	failure := errors.New("read failed")

	// Drive the tracker to its maximum level, where repeats must be folded away
	// instead of producing a log line every poll.
	for i := 0; i < 6; i++ {
		tracker.RecordFailure("windows-event:System", now, failure, false)
		now = now.Add(time.Minute)
	}
	logged := 0
	for i := 0; i < 20; i++ {
		if shouldLog, _, _ := tracker.RecordFailure("windows-event:System", now, failure, false); shouldLog {
			logged++
		}
		now = now.Add(time.Minute)
	}
	if logged != 0 {
		t.Fatalf("repeated failures at the same level logged %d times, want 0", logged)
	}
	health := tracker.Snapshot()[0]
	if health.State != SourceStateDegraded {
		t.Fatalf("state = %q, want DEGRADED", health.State)
	}
	if health.ErrorCount != 26 {
		t.Fatalf("error count = %d, want 26", health.ErrorCount)
	}
}

func TestSourceTrackerResetsBackoffAfterSuccess(t *testing.T) {
	tracker := NewSourceTracker()
	tracker.Register("windows-event:Security", "Security")
	now := time.Unix(1756000000, 0).UTC()
	for i := 0; i < 4; i++ {
		tracker.RecordFailure("windows-event:Security", now, errors.New("boom"), false)
		now = now.Add(time.Minute)
	}
	tracker.RecordSuccess("windows-event:Security", now, 3, 44473, 0, string(WindowsTextUTF16LE))

	health := tracker.Snapshot()[0]
	if health.State != SourceStateHealthy {
		t.Fatalf("state = %q, want HEALTHY", health.State)
	}
	if health.ConsecutiveErrors != 0 || health.LastError != "" {
		t.Fatalf("success must clear the error state: %+v", health)
	}
	if health.EventsRead != 3 || health.Checkpoint != 44473 {
		t.Fatalf("success must record progress: %+v", health)
	}
	if !tracker.ShouldAttempt("windows-event:Security", now) {
		t.Fatal("a healthy source must be attempted immediately")
	}
	// The next failure restarts the schedule at its first step.
	_, _, retryAt := tracker.RecordFailure("windows-event:Security", now, errors.New("boom"), false)
	if got := retryAt.Sub(now); got != 2*time.Second {
		t.Fatalf("backoff after success = %s, want 2s", got)
	}
}

func TestSourceTrackerGatesAttemptsUntilRetryTime(t *testing.T) {
	tracker := NewSourceTracker()
	tracker.Register("windows-event:System", "System")
	now := time.Unix(1756000000, 0).UTC()
	if !tracker.ShouldAttempt("windows-event:System", now) {
		t.Fatal("a fresh source must be attempted")
	}
	tracker.RecordFailure("windows-event:System", now, errors.New("boom"), false)
	if tracker.ShouldAttempt("windows-event:System", now.Add(time.Second)) {
		t.Fatal("a source inside its backoff window must be skipped")
	}
	if !tracker.ShouldAttempt("windows-event:System", now.Add(2*time.Second)) {
		t.Fatal("a source past its backoff window must be attempted")
	}
}

// TestSourceHealthIsSeparateFromAgentConnectivity covers the reporting defect:
// an agent whose heartbeat works still reports DEGRADED sources.
func TestSourceHealthIsSeparateFromAgentConnectivity(t *testing.T) {
	tracker := NewSourceTracker()
	for _, channel := range []string{"Security", "System", SysmonChannel} {
		tracker.Register("windows-event:"+channel, channel)
	}
	now := time.Unix(1756000000, 0).UTC()
	if tracker.Overall() != SourceStateStarting {
		t.Fatalf("overall before any read = %q", tracker.Overall())
	}
	tracker.RecordSuccess("windows-event:Security", now, 1, 10, 0, "utf-16le")
	tracker.RecordSuccess("windows-event:System", now, 1, 11, 0, "utf-16le")
	tracker.RecordSuccess("windows-event:"+SysmonChannel, now, 1, 12, 0, "utf-16le")
	if tracker.Overall() != SourceStateHealthy {
		t.Fatalf("overall with every source reading = %q, want HEALTHY", tracker.Overall())
	}
	if len(tracker.DegradedSources()) != 0 {
		t.Fatalf("no source should be degraded: %v", tracker.DegradedSources())
	}

	tracker.RecordFailure("windows-event:"+SysmonChannel, now, errors.New("invalid UTF-8"), false)
	if tracker.Overall() != SourceStateDegraded {
		t.Fatalf("one failing source must degrade the overall state, got %q", tracker.Overall())
	}
	degraded := tracker.DegradedSources()
	if len(degraded) != 1 || degraded[0] != "windows-event:"+SysmonChannel {
		t.Fatalf("degraded sources = %v", degraded)
	}
	// Health is reported per source, with the failure isolated to Sysmon.
	for _, health := range tracker.Snapshot() {
		want := SourceStateHealthy
		if health.Channel == SysmonChannel {
			want = SourceStateDegraded
		}
		if health.State != want {
			t.Fatalf("source %q state = %q, want %q", health.Name, health.State, want)
		}
	}
}

func TestSourceTrackerReportsUnsupportedSeparately(t *testing.T) {
	tracker := NewSourceTracker()
	tracker.Register("journald", "")
	tracker.RecordFailure("journald", time.Unix(1756000000, 0).UTC(), ErrUnsupportedSource, true)
	if got := tracker.Snapshot()[0].State; got != SourceStateUnsupported {
		t.Fatalf("state = %q, want UNSUPPORTED", got)
	}
	if tracker.Overall() != SourceStateUnsupported {
		t.Fatalf("overall = %q, want UNSUPPORTED", tracker.Overall())
	}
	if len(tracker.DegradedSources()) != 0 {
		t.Fatal("an unsupported source is not a degraded source")
	}
}
