package core

import "time"

const (
	UEBAAnomalyNew           = "NEW"
	UEBAAnomalyConfirmed     = "CONFIRMED"
	UEBAAnomalyFalsePositive = "FALSE_POSITIVE"
)

type UEBAFeatureEvidence struct {
	Code              string  `json:"code"`
	Field             string  `json:"field"`
	Value             string  `json:"value,omitempty"`
	Score             int     `json:"score"`
	BaselineFrequency float64 `json:"baseline_frequency"`
	Explanation       string  `json:"explanation"`
}

type UEBAAnomaly struct {
	ID                   string                 `json:"anomaly_id"`
	TenantID             string                 `json:"tenant_id"`
	EventID              string                 `json:"event_id"`
	EntityType           string                 `json:"entity_type"`
	EntityID             string                 `json:"entity_id"`
	EntityName           string                 `json:"entity_name"`
	PeerGroup            string                 `json:"peer_group"`
	Title                string                 `json:"title"`
	Severity             Severity               `json:"severity"`
	RiskScore            int                    `json:"risk_score"`
	Confidence           int                    `json:"confidence"`
	Features             []UEBAFeatureEvidence  `json:"features"`
	Explanation          map[string]interface{} `json:"explanation"`
	ModelVersion         string                 `json:"model_version"`
	FeatureVersion       string                 `json:"feature_version"`
	TrainingWindowDays   int                    `json:"training_window_days"`
	BaselineObservations int                    `json:"baseline_observations"`
	Status               string                 `json:"status"`
	Version              int                    `json:"version"`
	FeedbackBy           string                 `json:"feedback_by,omitempty"`
	FeedbackReason       string                 `json:"feedback_reason,omitempty"`
	FeedbackAt           *time.Time             `json:"feedback_at,omitempty"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

type UEBAAnomalyFilter struct {
	EntityType  string
	EntityID    string
	Status      string
	MinimumRisk int
	Limit       int
}

type UEBABaselineSummary struct {
	TenantID           string    `json:"tenant_id"`
	EntityType         string    `json:"entity_type"`
	EntityID           string    `json:"entity_id"`
	EntityName         string    `json:"entity_name"`
	PeerGroup          string    `json:"peer_group"`
	ModelVersion       string    `json:"model_version"`
	FeatureVersion     string    `json:"feature_version"`
	TrainingWindowDays int       `json:"training_window_days"`
	ObservationCount   int       `json:"observation_count"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	DriftScore         float64   `json:"drift_score"`
	DriftStatus        string    `json:"drift_status"`
	UpdatedAt          time.Time `json:"updated_at"`
}
