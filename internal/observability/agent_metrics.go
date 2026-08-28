package observability

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// AgentState is the per-endpoint operational sample published to Prometheus.
// It is refreshed from the collector heartbeat, so a scrape never has to query
// the database.
type AgentState struct {
	TenantID     string
	CollectorID  string
	Online       bool
	QueueDepth   int64
	QueueBytes   int64
	CollectionRate float64
	DeliveryRate   float64
	SendFailures   int64
	SourceErrors   int64
	SourcesTotal   int
	SourcesDegraded int
	EventLagSeconds float64
	LastSeen        time.Time
}

// agentMetrics holds one sample per collector. Cardinality is bounded by the
// number of enrolled endpoints, and the only labels are tenant and collector
// identifiers - never per-event values, which would make the series unbounded.
type agentMetrics struct {
	mu     sync.RWMutex
	states map[string]AgentState
}

// maxTrackedAgents caps the series count so a runaway enrollment cannot turn
// the scrape endpoint into an unbounded time series.
const maxTrackedAgents = 5000

func (m *agentMetrics) set(state AgentState) {
	if strings.TrimSpace(state.CollectorID) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.states == nil {
		m.states = make(map[string]AgentState)
	}
	if _, exists := m.states[state.CollectorID]; !exists && len(m.states) >= maxTrackedAgents {
		return
	}
	m.states[state.CollectorID] = state
}

func (m *agentMetrics) snapshot() []AgentState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	states := make([]AgentState, 0, len(m.states))
	for _, state := range m.states {
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].CollectorID < states[j].CollectorID })
	return states
}

// SetAgentState records the latest operational sample for one collector.
func (r *Registry) SetAgentState(state AgentState) {
	r.agents.set(state)
}

func (r *Registry) writeAgentMetrics(builder *strings.Builder) {
	states := r.agents.snapshot()
	if len(states) == 0 {
		return
	}
	type gauge struct {
		name  string
		help  string
		value func(AgentState) float64
	}
	gauges := []gauge{
		{"kcsp_agent_online", "1 when the agent heartbeat is current, 0 otherwise.", func(s AgentState) float64 {
			if s.Online {
				return 1
			}
			return 0
		}},
		{"kcsp_agent_queue_depth", "Events buffered in the agent's local store-and-forward queue.", func(s AgentState) float64 { return float64(s.QueueDepth) }},
		{"kcsp_agent_queue_bytes", "Bytes buffered in the agent's local queue.", func(s AgentState) float64 { return float64(s.QueueBytes) }},
		{"kcsp_agent_collection_rate", "Events per second the agent reads from its telemetry sources.", func(s AgentState) float64 { return s.CollectionRate }},
		{"kcsp_agent_delivery_rate", "Events per second the agent delivers to the platform.", func(s AgentState) float64 { return s.DeliveryRate }},
		{"kcsp_agent_last_seen_timestamp", "Unix timestamp of the agent's last heartbeat.", func(s AgentState) float64 {
			if s.LastSeen.IsZero() {
				return 0
			}
			return float64(s.LastSeen.Unix())
		}},
		{"kcsp_agent_event_lag_seconds", "Age of the oldest event still queued on the agent.", func(s AgentState) float64 { return s.EventLagSeconds }},
		{"kcsp_agent_sources_total", "Telemetry sources configured on the agent.", func(s AgentState) float64 { return float64(s.SourcesTotal) }},
		{"kcsp_agent_sources_degraded", "Telemetry sources currently failing to read.", func(s AgentState) float64 { return float64(s.SourcesDegraded) }},
	}
	for _, item := range gauges {
		writeHelp(builder, item.name, item.help, "gauge")
		for _, state := range states {
			fmt.Fprintf(builder, "%s{tenant=%q,collector_id=%q} %g\n", item.name, state.TenantID, state.CollectorID, item.value(state))
		}
	}

	counters := []struct {
		name  string
		help  string
		value func(AgentState) int64
	}{
		{"kcsp_agent_send_failures_total", "Batch deliveries the agent could not complete.", func(s AgentState) int64 { return s.SendFailures }},
		{"kcsp_agent_source_errors_total", "Telemetry source read failures observed by the agent.", func(s AgentState) int64 { return s.SourceErrors }},
	}
	for _, item := range counters {
		writeHelp(builder, item.name, item.help, "counter")
		for _, state := range states {
			fmt.Fprintf(builder, "%s{tenant=%q,collector_id=%q} %d\n", item.name, state.TenantID, state.CollectorID, item.value(state))
		}
	}
}
