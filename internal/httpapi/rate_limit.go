package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAgentEnrollmentRatePerMinute = 600
	maximumEnrollmentRateLimitEntries   = 16384
)

type ipRateLimitEntry struct {
	windowStarted time.Time
	requests      int
}

type ipRateLimiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	maxEntries int
	now        func() time.Time
	entries    map[string]ipRateLimitEntry
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	if limit <= 0 {
		limit = defaultAgentEnrollmentRatePerMinute
	}
	if window <= 0 {
		window = time.Minute
	}
	return &ipRateLimiter{
		limit: limit, window: window, maxEntries: maximumEnrollmentRateLimitEntries,
		now: time.Now, entries: make(map[string]ipRateLimitEntry),
	}
}

func (l *ipRateLimiter) Allow(key string) (bool, time.Duration) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.entries[key]
	if exists && !now.Before(entry.windowStarted.Add(l.window)) {
		delete(l.entries, key)
		exists = false
	}
	if !exists {
		if len(l.entries) >= l.maxEntries {
			for candidate, current := range l.entries {
				if !now.Before(current.windowStarted.Add(l.window)) {
					delete(l.entries, candidate)
				}
			}
		}
		if len(l.entries) >= l.maxEntries {
			return false, l.window
		}
		l.entries[key] = ipRateLimitEntry{windowStarted: now, requests: 1}
		return true, 0
	}
	if entry.requests >= l.limit {
		retryAfter := entry.windowStarted.Add(l.window).Sub(now)
		if retryAfter <= 0 {
			retryAfter = time.Second
		}
		return false, retryAfter
	}
	entry.requests++
	l.entries[key] = entry
	return true, 0
}

func (s *Server) limitAgentEnrollment(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, retryAfter := s.enrollmentLimiter.Allow(remoteIP(r.RemoteAddr))
		if !allowed {
			seconds := int((retryAfter + time.Second - 1) / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			s.problem(w, r, http.StatusTooManyRequests, "agent_enrollment_rate_limited", "Agent enrollment rate limited", "Too many enrollment attempts were received from this network address.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
