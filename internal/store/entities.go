package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/entitygraph"
)

type entityRow interface{ Scan(...any) error }

func (p *Postgres) ObserveEntityEvent(ctx context.Context, event core.CanonicalEvent) error {
	return p.observeEntityProjection(ctx, event, entitygraph.Project(event))
}

func (p *Postgres) observeEntityProjection(ctx context.Context, event core.CanonicalEvent, projection core.EntityProjection) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin entity projection: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, entity := range projection.Entities {
		var inserted bool
		err := tx.QueryRow(ctx, `INSERT INTO entity_event_observations (tenant_id,event_id,entity_id,observed_at)
			VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING TRUE`, event.TenantID, event.ID, entity.ID, entity.LastSeen).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("deduplicate entity observation: %w", err)
		}
		attributes, err := json.Marshal(entity.Attributes)
		if err != nil {
			return fmt.Errorf("encode entity attributes: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_entities
			(tenant_id,entity_id,entity_type,natural_key,display_name,label,risk_score,criticality,attributes,first_seen,last_seen,observation_count,last_event_id,version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,1)
			ON CONFLICT (tenant_id,entity_id) DO UPDATE SET
			entity_type=EXCLUDED.entity_type,natural_key=EXCLUDED.natural_key,
			display_name=CASE WHEN EXCLUDED.display_name<>'' THEN EXCLUDED.display_name ELSE security_entities.display_name END,
			label=CASE WHEN EXCLUDED.label<>'' THEN EXCLUDED.label ELSE security_entities.label END,
			risk_score=GREATEST(security_entities.risk_score,EXCLUDED.risk_score),
			criticality=CASE WHEN EXCLUDED.criticality<>'' THEN EXCLUDED.criticality ELSE security_entities.criticality END,
			attributes=security_entities.attributes || EXCLUDED.attributes,
			first_seen=LEAST(security_entities.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(security_entities.last_seen,EXCLUDED.last_seen),
			observation_count=security_entities.observation_count+1,last_event_id=EXCLUDED.last_event_id,version=security_entities.version+1`,
			entity.TenantID, entity.ID, entity.Type, entity.NaturalKey, entity.DisplayName, entity.Label, entity.RiskScore,
			entity.Criticality, attributes, entity.FirstSeen, entity.LastSeen, entity.LastEventID); err != nil {
			return fmt.Errorf("upsert security entity: %w", err)
		}
	}
	for _, relation := range projection.Relations {
		var inserted bool
		err := tx.QueryRow(ctx, `INSERT INTO entity_relation_observations (tenant_id,event_id,relation_id,observed_at)
			VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING TRUE`, event.TenantID, event.ID, relation.ID, relation.LastSeen).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("deduplicate entity relation observation: %w", err)
		}
		attributes, err := json.Marshal(relation.Attributes)
		if err != nil {
			return fmt.Errorf("encode relation attributes: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO entity_relations
			(tenant_id,relation_id,relation_type,source_entity_id,target_entity_id,attributes,first_seen,last_seen,observation_count,last_event_id,version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,$9,1)
			ON CONFLICT (tenant_id,relation_id) DO UPDATE SET attributes=entity_relations.attributes || EXCLUDED.attributes,
			first_seen=LEAST(entity_relations.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(entity_relations.last_seen,EXCLUDED.last_seen),
			observation_count=entity_relations.observation_count+1,last_event_id=EXCLUDED.last_event_id,version=entity_relations.version+1`,
			relation.TenantID, relation.ID, relation.Type, relation.SourceEntityID, relation.TargetEntityID, attributes,
			relation.FirstSeen, relation.LastSeen, relation.LastEventID); err != nil {
			return fmt.Errorf("upsert entity relation: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit entity projection: %w", err)
	}
	return nil
}

func (p *Postgres) ListEntities(ctx context.Context, tenantID string, filter core.EntityFilter) ([]core.SecurityEntity, error) {
	where := []string{"tenant_id=$1"}
	args := []interface{}{tenantID}
	if filter.Type != "" {
		args = append(args, filter.Type)
		where = append(where, fmt.Sprintf("entity_type=$%d", len(args)))
	}
	if filter.MinimumRisk > 0 {
		args = append(args, filter.MinimumRisk)
		where = append(where, fmt.Sprintf("risk_score>=$%d", len(args)))
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+query+"%")
		where = append(where, fmt.Sprintf("(display_name ILIKE $%d OR natural_key ILIKE $%d OR label ILIKE $%d)", len(args), len(args), len(args)))
	}
	args = append(args, normalizedLimit(filter.Limit))
	rows, err := p.pool.Query(ctx, `SELECT entity_id,tenant_id,entity_type,natural_key,display_name,label,risk_score,criticality,attributes,
		first_seen,last_seen,observation_count,last_event_id,version FROM security_entities WHERE `+strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY risk_score DESC,last_seen DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list security entities: %w", err)
	}
	defer rows.Close()
	items := []core.SecurityEntity{}
	for rows.Next() {
		entity, err := scanSecurityEntity(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, entity)
	}
	return items, rows.Err()
}

func (p *Postgres) GetEntity(ctx context.Context, tenantID, entityID string) (core.SecurityEntity, error) {
	entity, err := scanSecurityEntity(p.pool.QueryRow(ctx, `SELECT entity_id,tenant_id,entity_type,natural_key,display_name,label,risk_score,criticality,attributes,
		first_seen,last_seen,observation_count,last_event_id,version FROM security_entities WHERE tenant_id=$1 AND entity_id=$2`, tenantID, entityID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SecurityEntity{}, ErrNotFound
	}
	return entity, err
}

func (p *Postgres) GetEntityGraph(ctx context.Context, tenantID, entityID string, depth, limit int) (core.EntityGraph, error) {
	root, err := p.GetEntity(ctx, tenantID, entityID)
	if err != nil {
		return core.EntityGraph{}, err
	}
	if depth < 1 {
		depth = 1
	}
	limit = normalizedLimit(limit)
	walk := `WITH RECURSIVE connected(entity_id,depth) AS (
		SELECT entity_id,0 FROM security_entities WHERE tenant_id=$1 AND entity_id=$2
		UNION SELECT CASE WHEN r.source_entity_id=c.entity_id THEN r.target_entity_id ELSE r.source_entity_id END,c.depth+1
		FROM entity_relations r JOIN connected c ON r.source_entity_id=c.entity_id OR r.target_entity_id=c.entity_id
		WHERE r.tenant_id=$1 AND c.depth<$3)`
	rows, err := p.pool.Query(ctx, walk+` SELECT DISTINCT e.entity_id,e.tenant_id,e.entity_type,e.natural_key,e.display_name,e.label,e.risk_score,e.criticality,e.attributes,
		e.first_seen,e.last_seen,e.observation_count,e.last_event_id,e.version FROM security_entities e JOIN connected c ON c.entity_id=e.entity_id
		WHERE e.tenant_id=$1 ORDER BY e.risk_score DESC,e.last_seen DESC LIMIT $4`, tenantID, entityID, depth, limit)
	if err != nil {
		return core.EntityGraph{}, fmt.Errorf("query entity graph nodes: %w", err)
	}
	entities := []core.SecurityEntity{}
	for rows.Next() {
		entity, scanErr := scanSecurityEntity(rows)
		if scanErr != nil {
			rows.Close()
			return core.EntityGraph{}, scanErr
		}
		entities = append(entities, entity)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return core.EntityGraph{}, err
	}
	rows.Close()
	relationRows, err := p.pool.Query(ctx, walk+` SELECT r.relation_id,r.tenant_id,r.relation_type,r.source_entity_id,r.target_entity_id,r.attributes,
		r.first_seen,r.last_seen,r.observation_count,r.last_event_id,r.version FROM entity_relations r
		WHERE r.tenant_id=$1 AND r.source_entity_id IN (SELECT entity_id FROM connected) AND r.target_entity_id IN (SELECT entity_id FROM connected)
		ORDER BY r.last_seen DESC LIMIT $4`, tenantID, entityID, depth, limit)
	if err != nil {
		return core.EntityGraph{}, fmt.Errorf("query entity graph edges: %w", err)
	}
	defer relationRows.Close()
	relations := []core.EntityRelation{}
	for relationRows.Next() {
		relation, scanErr := scanEntityRelation(relationRows)
		if scanErr != nil {
			return core.EntityGraph{}, scanErr
		}
		relations = append(relations, relation)
	}
	if err := relationRows.Err(); err != nil {
		return core.EntityGraph{}, err
	}
	graph := core.EntityGraph{Root: root, Entities: entities, Relations: relations, EventIDs: []string{}, Depth: depth}
	seenEvents := map[string]bool{}
	for _, entity := range entities {
		graph.TotalObservations += entity.ObservationCount
		if entity.LastEventID != "" && !seenEvents[entity.LastEventID] {
			seenEvents[entity.LastEventID] = true
			graph.EventIDs = append(graph.EventIDs, entity.LastEventID)
		}
	}
	for _, relation := range relations {
		graph.TotalObservations += relation.ObservationCount
		if relation.LastEventID != "" && !seenEvents[relation.LastEventID] {
			seenEvents[relation.LastEventID] = true
			graph.EventIDs = append(graph.EventIDs, relation.LastEventID)
		}
	}
	return graph, nil
}

func scanSecurityEntity(row entityRow) (core.SecurityEntity, error) {
	var entity core.SecurityEntity
	var attributes []byte
	err := row.Scan(&entity.ID, &entity.TenantID, &entity.Type, &entity.NaturalKey, &entity.DisplayName, &entity.Label, &entity.RiskScore,
		&entity.Criticality, &attributes, &entity.FirstSeen, &entity.LastSeen, &entity.ObservationCount, &entity.LastEventID, &entity.Version)
	if err != nil {
		return core.SecurityEntity{}, err
	}
	if len(attributes) > 0 {
		if err := json.Unmarshal(attributes, &entity.Attributes); err != nil {
			return core.SecurityEntity{}, fmt.Errorf("decode entity attributes: %w", err)
		}
	}
	return entity, nil
}

func scanEntityRelation(row entityRow) (core.EntityRelation, error) {
	var relation core.EntityRelation
	var attributes []byte
	err := row.Scan(&relation.ID, &relation.TenantID, &relation.Type, &relation.SourceEntityID, &relation.TargetEntityID, &attributes,
		&relation.FirstSeen, &relation.LastSeen, &relation.ObservationCount, &relation.LastEventID, &relation.Version)
	if err != nil {
		return core.EntityRelation{}, err
	}
	if len(attributes) > 0 {
		if err := json.Unmarshal(attributes, &relation.Attributes); err != nil {
			return core.EntityRelation{}, fmt.Errorf("decode relation attributes: %w", err)
		}
	}
	return relation, nil
}
