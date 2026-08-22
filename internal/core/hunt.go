package core

import "time"

type HuntPredicate struct {
	Field      string   `json:"field"`
	Comparator string   `json:"comparator"`
	Value      string   `json:"value,omitempty"`
	Values     []string `json:"values,omitempty"`
}

type HuntExpression struct {
	All       []HuntExpression `json:"all,omitempty"`
	Any       []HuntExpression `json:"any,omitempty"`
	Not       *HuntExpression  `json:"not,omitempty"`
	Predicate *HuntPredicate   `json:"predicate,omitempty"`
}

type HuntRequest struct {
	Start           time.Time       `json:"start,omitempty"`
	End             time.Time       `json:"end,omitempty"`
	LookbackSeconds int64           `json:"lookback_seconds,omitempty"`
	Expression      *HuntExpression `json:"expression,omitempty"`
	Limit           int             `json:"limit,omitempty"`
	Cursor          string          `json:"cursor,omitempty"`
}

type HuntPage struct {
	ExecutionID    string           `json:"execution_id"`
	QueryHash      string           `json:"query_hash"`
	Start          time.Time        `json:"start"`
	End            time.Time        `json:"end"`
	Items          []CanonicalEvent `json:"items"`
	Returned       int              `json:"returned"`
	NextCursor     string           `json:"next_cursor,omitempty"`
	DurationMicros int64            `json:"duration_micros"`
	Partial        bool             `json:"partial"`
}

type SavedHunt struct {
	ID          string      `json:"hunt_id"`
	TenantID    string      `json:"tenant_id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Visibility  string      `json:"visibility"`
	Query       HuntRequest `json:"query"`
	Owner       string      `json:"owner"`
	Version     int         `json:"version"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

type HuntExecution struct {
	ID             string      `json:"execution_id"`
	TenantID       string      `json:"tenant_id"`
	SavedHuntID    string      `json:"saved_hunt_id,omitempty"`
	Actor          string      `json:"actor"`
	Query          HuntRequest `json:"query"`
	QueryHash      string      `json:"query_hash"`
	Status         string      `json:"status"`
	Returned       int         `json:"returned"`
	DurationMicros int64       `json:"duration_micros"`
	Error          string      `json:"error,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
}
