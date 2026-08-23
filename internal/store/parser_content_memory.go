package store

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func (m *MemoryRepository) CreateParserDraft(ctx context.Context, content core.ParserContent) (core.ParserContent, error) {
	if err := ctx.Err(); err != nil {
		return core.ParserContent{}, err
	}
	m.parserMu.Lock()
	defer m.parserMu.Unlock()
	if content.RequestID != "" {
		if existing, ok := m.parserRequests[content.TenantID+"\x00"+content.RequestID]; ok {
			return cloneParserContent(existing), nil
		}
	}
	if m.parserContents[content.TenantID] == nil {
		m.parserContents[content.TenantID] = map[string]map[int]core.ParserContent{}
	}
	if m.parserContents[content.TenantID][content.ParserID] == nil {
		m.parserContents[content.TenantID][content.ParserID] = map[int]core.ParserContent{}
	}
	content.Version = len(m.parserContents[content.TenantID][content.ParserID]) + 1
	content.State = core.ParserStateDraft
	content.CreatedAt, content.UpdatedAt = time.Now().UTC(), time.Now().UTC()
	m.parserContents[content.TenantID][content.ParserID][content.Version] = cloneParserContent(content)
	if content.RequestID != "" {
		m.parserRequests[content.TenantID+"\x00"+content.RequestID] = cloneParserContent(content)
	}
	return cloneParserContent(content), nil
}

func (m *MemoryRepository) ParserContent(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	if err := ctx.Err(); err != nil {
		return core.ParserContent{}, err
	}
	m.parserMu.RLock()
	defer m.parserMu.RUnlock()
	versions := m.parserContents[tenantID][parserID]
	if version == 0 {
		for candidate := range versions {
			if candidate > version {
				version = candidate
			}
		}
	}
	content, ok := versions[version]
	if !ok {
		return core.ParserContent{}, ErrNotFound
	}
	return cloneParserContent(content), nil
}

func (m *MemoryRepository) ListParserContent(ctx context.Context, tenantID string) ([]core.ParserContent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.parserMu.RLock()
	defer m.parserMu.RUnlock()
	items := []core.ParserContent{}
	for _, versions := range m.parserContents[tenantID] {
		for _, content := range versions {
			items = append(items, cloneParserContent(content))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ParserID != items[j].ParserID {
			return items[i].ParserID < items[j].ParserID
		}
		return items[i].Version > items[j].Version
	})
	return items, nil
}

func (m *MemoryRepository) SaveParserValidation(ctx context.Context, content core.ParserContent) (core.ParserContent, error) {
	if err := ctx.Err(); err != nil {
		return core.ParserContent{}, err
	}
	m.parserMu.Lock()
	defer m.parserMu.Unlock()
	if _, ok := m.parserContents[content.TenantID][content.ParserID][content.Version]; !ok {
		return core.ParserContent{}, ErrNotFound
	}
	if content.Validation.Valid {
		content.State = core.ParserStateValidated
	} else {
		content.State = core.ParserStateDraft
	}
	content.UpdatedAt = time.Now().UTC()
	m.parserContents[content.TenantID][content.ParserID][content.Version] = cloneParserContent(content)
	return cloneParserContent(content), nil
}

func (m *MemoryRepository) PublishParserContent(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	if err := ctx.Err(); err != nil {
		return core.ParserContent{}, err
	}
	m.parserMu.Lock()
	defer m.parserMu.Unlock()
	content, ok := m.parserContents[tenantID][parserID][version]
	if !ok {
		return core.ParserContent{}, ErrNotFound
	}
	if !content.Validation.Valid {
		return core.ParserContent{}, ErrParserStateConflict
	}
	now := time.Now().UTC()
	for id, versions := range m.parserContents[tenantID] {
		for candidate, existing := range versions {
			if existing.State == core.ParserStatePublished && existing.Spec.Format == content.Spec.Format {
				existing.State, existing.UpdatedAt = core.ParserStateSuperseded, now
				m.parserContents[tenantID][id][candidate] = existing
			}
		}
	}
	content.State, content.PublishedAt, content.UpdatedAt = core.ParserStatePublished, &now, now
	m.parserContents[tenantID][parserID][version] = content
	return cloneParserContent(content), nil
}

func (m *MemoryRepository) DisableParserContent(ctx context.Context, tenantID, parserID string) (core.ParserContent, error) {
	if err := ctx.Err(); err != nil {
		return core.ParserContent{}, err
	}
	m.parserMu.Lock()
	defer m.parserMu.Unlock()
	var disabled core.ParserContent
	found := false
	for version, content := range m.parserContents[tenantID][parserID] {
		if content.State == core.ParserStatePublished {
			content.State, content.UpdatedAt = core.ParserStateDisabled, time.Now().UTC()
			m.parserContents[tenantID][parserID][version] = content
			disabled, found = content, true
		}
	}
	if !found {
		return core.ParserContent{}, ErrNotFound
	}
	return cloneParserContent(disabled), nil
}

func (m *MemoryRepository) PublishedParserByFormat(ctx context.Context, tenantID, format string) (core.ParserContent, bool, error) {
	if err := ctx.Err(); err != nil {
		return core.ParserContent{}, false, err
	}
	m.parserMu.RLock()
	defer m.parserMu.RUnlock()
	for _, versions := range m.parserContents[tenantID] {
		for _, content := range versions {
			if content.State == core.ParserStatePublished && content.Spec.Format == strings.ToLower(strings.TrimSpace(format)) {
				return cloneParserContent(content), true, nil
			}
		}
	}
	return core.ParserContent{}, false, nil
}

func (m *MemoryRepository) resetParsers(tenantID string) {
	m.parserMu.Lock()
	defer m.parserMu.Unlock()
	delete(m.parserContents, tenantID)
	prefix := tenantID + "\x00"
	for key := range m.parserRequests {
		if strings.HasPrefix(key, prefix) {
			delete(m.parserRequests, key)
		}
	}
}

func cloneParserContent(content core.ParserContent) core.ParserContent {
	content.Spec.Mappings = cloneStringMap(content.Spec.Mappings)
	content.Spec.Defaults = cloneStringMap(content.Spec.Defaults)
	content.Spec.Tests = append([]core.ParserTestCase(nil), content.Spec.Tests...)
	for index := range content.Spec.Tests {
		content.Spec.Tests[index].Expected = cloneStringMap(content.Spec.Tests[index].Expected)
	}
	content.Validation.Errors = append([]string(nil), content.Validation.Errors...)
	content.Validation.Warnings = append([]string(nil), content.Validation.Warnings...)
	content.Validation.TestResults = append([]core.ParserTestResult(nil), content.Validation.TestResults...)
	return content
}
