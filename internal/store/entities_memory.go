package store

import (
	"context"
	"sort"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/entitygraph"
)

func (m *MemoryRepository) ObserveEntityEvent(ctx context.Context, event core.CanonicalEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	projection := entitygraph.Project(event)
	m.entityMu.Lock()
	defer m.entityMu.Unlock()
	if m.entities[event.TenantID] == nil {
		m.entities[event.TenantID] = map[string]core.SecurityEntity{}
	}
	if m.entityRelations[event.TenantID] == nil {
		m.entityRelations[event.TenantID] = map[string]core.EntityRelation{}
	}
	for _, entity := range projection.Entities {
		observationKey := event.TenantID + "\x00" + event.ID + "\x00" + entity.ID
		if _, duplicate := m.seenEntityObservations[observationKey]; duplicate {
			continue
		}
		m.seenEntityObservations[observationKey] = struct{}{}
		current, exists := m.entities[event.TenantID][entity.ID]
		if exists {
			entity = mergeEntity(current, entity)
		}
		m.entities[event.TenantID][entity.ID] = entity
	}
	for _, relation := range projection.Relations {
		observationKey := event.TenantID + "\x00" + event.ID + "\x00" + relation.ID
		if _, duplicate := m.seenRelationEvents[observationKey]; duplicate {
			continue
		}
		m.seenRelationEvents[observationKey] = struct{}{}
		current, exists := m.entityRelations[event.TenantID][relation.ID]
		if exists {
			relation = mergeRelation(current, relation)
		}
		m.entityRelations[event.TenantID][relation.ID] = relation
	}
	return nil
}

func (m *MemoryRepository) ListEntities(ctx context.Context, tenantID string, filter core.EntityFilter) ([]core.SecurityEntity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.entityMu.RLock()
	defer m.entityMu.RUnlock()
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	items := []core.SecurityEntity{}
	for _, entity := range m.entities[tenantID] {
		if filter.Type != "" && entity.Type != filter.Type {
			continue
		}
		if entity.RiskScore < filter.MinimumRisk {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(entity.DisplayName+" "+entity.NaturalKey+" "+entity.Label), query) {
			continue
		}
		items = append(items, cloneEntity(entity))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].RiskScore != items[j].RiskScore {
			return items[i].RiskScore > items[j].RiskScore
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
	limit := normalizedLimit(filter.Limit)
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (m *MemoryRepository) GetEntity(ctx context.Context, tenantID, entityID string) (core.SecurityEntity, error) {
	if err := ctx.Err(); err != nil {
		return core.SecurityEntity{}, err
	}
	m.entityMu.RLock()
	defer m.entityMu.RUnlock()
	entity, ok := m.entities[tenantID][entityID]
	if !ok {
		return core.SecurityEntity{}, ErrNotFound
	}
	return cloneEntity(entity), nil
}

func (m *MemoryRepository) GetEntityGraph(ctx context.Context, tenantID, entityID string, depth, limit int) (core.EntityGraph, error) {
	if err := ctx.Err(); err != nil {
		return core.EntityGraph{}, err
	}
	m.entityMu.RLock()
	defer m.entityMu.RUnlock()
	root, ok := m.entities[tenantID][entityID]
	if !ok {
		return core.EntityGraph{}, ErrNotFound
	}
	if depth < 1 {
		depth = 1
	}
	maxItems := normalizedLimit(limit)
	visited := map[string]int{entityID: 0}
	frontier := []string{entityID}
	for len(frontier) > 0 {
		currentID := frontier[0]
		frontier = frontier[1:]
		currentDepth := visited[currentID]
		if currentDepth >= depth || len(visited) >= maxItems {
			continue
		}
		for _, relation := range m.entityRelations[tenantID] {
			next := ""
			if relation.SourceEntityID == currentID {
				next = relation.TargetEntityID
			} else if relation.TargetEntityID == currentID {
				next = relation.SourceEntityID
			}
			if next == "" {
				continue
			}
			if _, seen := visited[next]; !seen {
				visited[next] = currentDepth + 1
				frontier = append(frontier, next)
			}
		}
	}
	graph := core.EntityGraph{Root: cloneEntity(root), Depth: depth, Entities: []core.SecurityEntity{}, Relations: []core.EntityRelation{}, EventIDs: []string{}}
	events := map[string]bool{}
	for id := range visited {
		entity := cloneEntity(m.entities[tenantID][id])
		graph.Entities = append(graph.Entities, entity)
		graph.TotalObservations += entity.ObservationCount
		if entity.LastEventID != "" && !events[entity.LastEventID] {
			events[entity.LastEventID] = true
			graph.EventIDs = append(graph.EventIDs, entity.LastEventID)
		}
	}
	for _, relation := range m.entityRelations[tenantID] {
		_, source := visited[relation.SourceEntityID]
		_, target := visited[relation.TargetEntityID]
		if !source || !target {
			continue
		}
		graph.Relations = append(graph.Relations, cloneRelation(relation))
		graph.TotalObservations += relation.ObservationCount
		if relation.LastEventID != "" && !events[relation.LastEventID] {
			events[relation.LastEventID] = true
			graph.EventIDs = append(graph.EventIDs, relation.LastEventID)
		}
	}
	sort.Slice(graph.Entities, func(i, j int) bool { return graph.Entities[i].ID < graph.Entities[j].ID })
	sort.Slice(graph.Relations, func(i, j int) bool { return graph.Relations[i].ID < graph.Relations[j].ID })
	sort.Strings(graph.EventIDs)
	return graph, nil
}

func (m *MemoryRepository) resetEntities(tenantID string) {
	m.entityMu.Lock()
	defer m.entityMu.Unlock()
	delete(m.entities, tenantID)
	delete(m.entityRelations, tenantID)
	prefix := tenantID + "\x00"
	for key := range m.seenEntityObservations {
		if strings.HasPrefix(key, prefix) {
			delete(m.seenEntityObservations, key)
		}
	}
	for key := range m.seenRelationEvents {
		if strings.HasPrefix(key, prefix) {
			delete(m.seenRelationEvents, key)
		}
	}
}

func mergeEntity(current, observed core.SecurityEntity) core.SecurityEntity {
	current.LastSeen = observed.LastSeen
	if observed.FirstSeen.Before(current.FirstSeen) {
		current.FirstSeen = observed.FirstSeen
	}
	if observed.RiskScore > current.RiskScore {
		current.RiskScore = observed.RiskScore
	}
	if observed.DisplayName != "" {
		current.DisplayName = observed.DisplayName
	}
	if observed.Label != "" {
		current.Label = observed.Label
	}
	if current.Attributes == nil {
		current.Attributes = map[string]string{}
	}
	for key, value := range observed.Attributes {
		current.Attributes[key] = value
	}
	current.ObservationCount++
	current.LastEventID = observed.LastEventID
	current.Version++
	return current
}

func mergeRelation(current, observed core.EntityRelation) core.EntityRelation {
	current.LastSeen = observed.LastSeen
	if observed.FirstSeen.Before(current.FirstSeen) {
		current.FirstSeen = observed.FirstSeen
	}
	if current.Attributes == nil {
		current.Attributes = map[string]string{}
	}
	for key, value := range observed.Attributes {
		current.Attributes[key] = value
	}
	current.ObservationCount++
	current.LastEventID = observed.LastEventID
	current.Version++
	return current
}

func cloneEntity(entity core.SecurityEntity) core.SecurityEntity {
	entity.Attributes = cloneStringMap(entity.Attributes)
	return entity
}

func cloneRelation(relation core.EntityRelation) core.EntityRelation {
	relation.Attributes = cloneStringMap(relation.Attributes)
	return relation
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
