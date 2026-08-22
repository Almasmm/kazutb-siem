package ueba

import (
	"context"
	"errors"
	"strings"

	"github.com/kcsp/platform/internal/core"
)

var (
	ErrInvalidFilter   = errors.New("invalid UEBA filter")
	ErrInvalidFeedback = errors.New("invalid UEBA feedback")
)

type Store interface {
	ListUEBAAnomalies(context.Context, string, core.UEBAAnomalyFilter) ([]core.UEBAAnomaly, error)
	GetUEBABaseline(context.Context, string, string, string) (core.UEBABaselineSummary, error)
	UpdateUEBAAnomalyFeedback(context.Context, string, string, string, string, string, int) (core.UEBAAnomaly, error)
}

type Service struct {
	store Store
}

type FeedbackRequest struct {
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Version int    `json:"version"`
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Anomalies(ctx context.Context, tenantID string, filter core.UEBAAnomalyFilter) ([]core.UEBAAnomaly, error) {
	filter.EntityType = strings.ToLower(strings.TrimSpace(filter.EntityType))
	filter.EntityID = strings.ToLower(strings.TrimSpace(filter.EntityID))
	filter.Status = strings.ToUpper(strings.TrimSpace(filter.Status))
	if filter.EntityType != "" && filter.EntityType != "user" && filter.EntityType != "device" {
		return nil, ErrInvalidFilter
	}
	if filter.Status != "" && filter.Status != core.UEBAAnomalyNew &&
		filter.Status != core.UEBAAnomalyConfirmed && filter.Status != core.UEBAAnomalyFalsePositive {
		return nil, ErrInvalidFilter
	}
	if filter.MinimumRisk < 0 || filter.MinimumRisk > 75 || filter.Limit < 0 || filter.Limit > 1000 {
		return nil, ErrInvalidFilter
	}
	return s.store.ListUEBAAnomalies(ctx, tenantID, filter)
}

func (s *Service) Baseline(ctx context.Context, tenantID, entityType, entityID string) (core.UEBABaselineSummary, error) {
	entityType = strings.ToLower(strings.TrimSpace(entityType))
	entityID = strings.ToLower(strings.TrimSpace(entityID))
	if (entityType != "user" && entityType != "device") || entityID == "" {
		return core.UEBABaselineSummary{}, ErrInvalidFilter
	}
	return s.store.GetUEBABaseline(ctx, tenantID, entityType, entityID)
}

func (s *Service) Feedback(ctx context.Context, tenantID, anomalyID, actor string, request FeedbackRequest) (core.UEBAAnomaly, error) {
	request.Status = strings.ToUpper(strings.TrimSpace(request.Status))
	request.Reason = strings.TrimSpace(request.Reason)
	actor = strings.TrimSpace(actor)
	if request.Status != core.UEBAAnomalyConfirmed && request.Status != core.UEBAAnomalyFalsePositive {
		return core.UEBAAnomaly{}, ErrInvalidFeedback
	}
	if request.Version < 1 || len(request.Reason) < 2 || len(request.Reason) > 2000 || actor == "" {
		return core.UEBAAnomaly{}, ErrInvalidFeedback
	}
	return s.store.UpdateUEBAAnomalyFeedback(ctx, tenantID, anomalyID, request.Status, actor, request.Reason, request.Version)
}
