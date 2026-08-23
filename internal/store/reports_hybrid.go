package store

import (
	"context"

	"github.com/kcsp/platform/internal/core"
)

func (h *Hybrid) CreateReportRun(ctx context.Context, run core.ReportRun) (core.ReportRun, bool, error) {
	return h.control.CreateReportRun(ctx, run)
}

func (h *Hybrid) GetReportRun(ctx context.Context, tenantID, reportID string) (core.ReportRun, error) {
	return h.control.GetReportRun(ctx, tenantID, reportID)
}

func (h *Hybrid) ListReportRuns(ctx context.Context, tenantID string, filter core.ReportFilter) ([]core.ReportRun, error) {
	return h.control.ListReportRuns(ctx, tenantID, filter)
}
