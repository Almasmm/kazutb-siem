package store

import (
	"context"

	"github.com/kcsp/platform/internal/core"
)

func (h *Hybrid) CreateParserDraft(ctx context.Context, value core.ParserContent) (core.ParserContent, error) {
	return h.control.CreateParserDraft(ctx, value)
}
func (h *Hybrid) ParserContent(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	return h.control.ParserContent(ctx, tenantID, parserID, version)
}
func (h *Hybrid) ListParserContent(ctx context.Context, tenantID string) ([]core.ParserContent, error) {
	return h.control.ListParserContent(ctx, tenantID)
}
func (h *Hybrid) SaveParserValidation(ctx context.Context, value core.ParserContent) (core.ParserContent, error) {
	return h.control.SaveParserValidation(ctx, value)
}
func (h *Hybrid) PublishParserContent(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	return h.control.PublishParserContent(ctx, tenantID, parserID, version)
}
func (h *Hybrid) DisableParserContent(ctx context.Context, tenantID, parserID string) (core.ParserContent, error) {
	return h.control.DisableParserContent(ctx, tenantID, parserID)
}
func (h *Hybrid) PublishedParserByFormat(ctx context.Context, tenantID, format string) (core.ParserContent, bool, error) {
	return h.control.PublishedParserByFormat(ctx, tenantID, format)
}
