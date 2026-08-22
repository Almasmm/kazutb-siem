package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ueba"
)

const uebaAnomalyColumns = `tenant_id,anomaly_id,event_id,entity_type,entity_id,entity_name,peer_group,
	title,severity,risk_score,confidence,features,explanation,model_version,feature_version,
	training_window_days,baseline_observations,status,version,feedback_by,feedback_reason,
	feedback_at,created_at,updated_at`

const uebaBaselineColumns = `tenant_id,entity_type,entity_id,entity_name,peer_group,model_version,
	feature_version,training_window_days,observation_count,first_seen,last_seen,drift_score,
	drift_status,profile,updated_at`

func (p *Postgres) ObserveUEBAEvent(ctx context.Context, event core.CanonicalEvent) (*core.UEBAAnomaly, error) {
	entityType, entityID, entityName, ok := ueba.EntityForEvent(event)
	if !ok {
		return nil, nil
	}
	now := event.IngestTime.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	peerGroup := ueba.PeerGroupForEvent(event)
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin UEBA observation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	lockKeys := []string{
		event.TenantID + "|ueba|" + entityType + "|" + entityID,
		event.TenantID + "|ueba|peer|" + peerGroup,
	}
	sort.Strings(lockKeys)
	for _, key := range lockKeys {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", key); err != nil {
			return nil, fmt.Errorf("lock UEBA baseline: %w", err)
		}
	}
	baseline, err := lockUEBABaseline(ctx, tx, event.TenantID, entityType, entityID, entityName, peerGroup, now)
	if err != nil {
		return nil, err
	}
	peer, err := lockUEBABaseline(ctx, tx, event.TenantID, "peer", peerGroup, peerGroup, peerGroup, now)
	if err != nil {
		return nil, err
	}
	windowStart := now.Truncate(15 * time.Minute)
	var currentCount int
	err = tx.QueryRow(ctx, `INSERT INTO ueba_volume_windows(tenant_id,entity_type,entity_id,window_start,event_count,updated_at)
		VALUES($1,$2,$3,$4,1,$5) ON CONFLICT(tenant_id,entity_type,entity_id,window_start)
		DO UPDATE SET event_count=ueba_volume_windows.event_count+1,updated_at=EXCLUDED.updated_at RETURNING event_count`,
		event.TenantID, entityType, entityID, windowStart, now).Scan(&currentCount)
	if err != nil {
		return nil, fmt.Errorf("update UEBA volume window: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT event_count FROM ueba_volume_windows
		WHERE tenant_id=$1 AND entity_type=$2 AND entity_id=$3 AND window_start<$4
		AND window_start >= $4-make_interval(days => $5) ORDER BY window_start DESC LIMIT 2688`,
		event.TenantID, entityType, entityID, windowStart, baseline.TrainingWindowDays)
	if err != nil {
		return nil, fmt.Errorf("read UEBA volume history: %w", err)
	}
	historical := []int{}
	for rows.Next() {
		var count int
		if err := rows.Scan(&count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan UEBA volume history: %w", err)
		}
		historical = append(historical, count)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate UEBA volume history: %w", err)
	}
	rows.Close()
	anomaly := ueba.Evaluate(&baseline, &peer, event, ueba.BuildVolumeStats(currentCount, historical), ueba.DefaultConfig(), now)
	if err := saveUEBABaseline(ctx, tx, baseline); err != nil {
		return nil, err
	}
	if err := saveUEBABaseline(ctx, tx, peer); err != nil {
		return nil, err
	}
	if anomaly != nil {
		stored, err := insertUEBAAnomaly(ctx, tx, *anomaly)
		if err != nil {
			return nil, err
		}
		anomaly = &stored
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit UEBA observation: %w", err)
	}
	return anomaly, nil
}

func lockUEBABaseline(ctx context.Context, tx pgx.Tx, tenantID, entityType, entityID, entityName, peerGroup string, at time.Time) (ueba.Baseline, error) {
	candidate := ueba.NewBaseline(tenantID, entityType, entityID, entityName, peerGroup, at)
	profile, err := json.Marshal(candidate.Profile)
	if err != nil {
		return ueba.Baseline{}, fmt.Errorf("encode new UEBA profile: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO ueba_entity_baselines(
		tenant_id,entity_type,entity_id,entity_name,peer_group,model_version,feature_version,
		training_window_days,observation_count,first_seen,last_seen,drift_score,drift_status,profile,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,$9,$9,0,$10,$11,$9) ON CONFLICT DO NOTHING`,
		candidate.TenantID, candidate.EntityType, candidate.EntityID, candidate.EntityName, candidate.PeerGroup,
		candidate.ModelVersion, candidate.FeatureVersion, candidate.TrainingWindowDays, at, candidate.DriftStatus, profile)
	if err != nil {
		return ueba.Baseline{}, fmt.Errorf("create UEBA baseline: %w", err)
	}
	var baseline ueba.Baseline
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT `+uebaBaselineColumns+` FROM ueba_entity_baselines
		WHERE tenant_id=$1 AND entity_type=$2 AND entity_id=$3 FOR UPDATE`, tenantID, entityType, entityID).Scan(
		&baseline.TenantID, &baseline.EntityType, &baseline.EntityID, &baseline.EntityName, &baseline.PeerGroup,
		&baseline.ModelVersion, &baseline.FeatureVersion, &baseline.TrainingWindowDays, &baseline.ObservationCount,
		&baseline.FirstSeen, &baseline.LastSeen, &baseline.DriftScore, &baseline.DriftStatus, &payload, &baseline.UpdatedAt)
	if err != nil {
		return ueba.Baseline{}, fmt.Errorf("lock UEBA baseline: %w", err)
	}
	if err := json.Unmarshal(payload, &baseline.Profile); err != nil {
		return ueba.Baseline{}, fmt.Errorf("decode UEBA profile: %w", err)
	}
	return baseline, nil
}

func saveUEBABaseline(ctx context.Context, tx pgx.Tx, baseline ueba.Baseline) error {
	profile, err := json.Marshal(baseline.Profile)
	if err != nil {
		return fmt.Errorf("encode UEBA profile: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE ueba_entity_baselines SET entity_name=$4,peer_group=$5,model_version=$6,
		feature_version=$7,training_window_days=$8,observation_count=$9,first_seen=$10,last_seen=$11,
		drift_score=$12,drift_status=$13,profile=$14,updated_at=$15
		WHERE tenant_id=$1 AND entity_type=$2 AND entity_id=$3`, baseline.TenantID, baseline.EntityType,
		baseline.EntityID, baseline.EntityName, baseline.PeerGroup, baseline.ModelVersion, baseline.FeatureVersion,
		baseline.TrainingWindowDays, baseline.ObservationCount, baseline.FirstSeen, baseline.LastSeen,
		baseline.DriftScore, baseline.DriftStatus, profile, baseline.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save UEBA baseline: %w", err)
	}
	return nil
}

func insertUEBAAnomaly(ctx context.Context, tx pgx.Tx, anomaly core.UEBAAnomaly) (core.UEBAAnomaly, error) {
	features, err := json.Marshal(anomaly.Features)
	if err != nil {
		return core.UEBAAnomaly{}, fmt.Errorf("encode UEBA features: %w", err)
	}
	explanation, err := json.Marshal(anomaly.Explanation)
	if err != nil {
		return core.UEBAAnomaly{}, fmt.Errorf("encode UEBA explanation: %w", err)
	}
	row := tx.QueryRow(ctx, `INSERT INTO ueba_anomalies(`+uebaAnomalyColumns+`)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
		ON CONFLICT(tenant_id,event_id) DO UPDATE SET event_id=EXCLUDED.event_id RETURNING `+uebaAnomalyColumns,
		anomaly.TenantID, anomaly.ID, anomaly.EventID, anomaly.EntityType, anomaly.EntityID, anomaly.EntityName,
		anomaly.PeerGroup, anomaly.Title, anomaly.Severity, anomaly.RiskScore, anomaly.Confidence, features,
		explanation, anomaly.ModelVersion, anomaly.FeatureVersion, anomaly.TrainingWindowDays,
		anomaly.BaselineObservations, anomaly.Status, anomaly.Version, anomaly.FeedbackBy, anomaly.FeedbackReason,
		anomaly.FeedbackAt, anomaly.CreatedAt, anomaly.UpdatedAt)
	stored, err := scanUEBAAnomaly(row)
	if err != nil {
		return core.UEBAAnomaly{}, fmt.Errorf("store UEBA anomaly: %w", err)
	}
	return stored, nil
}

func (p *Postgres) ListUEBAAnomalies(ctx context.Context, tenantID string, filter core.UEBAAnomalyFilter) ([]core.UEBAAnomaly, error) {
	args := []interface{}{tenantID}
	where := []string{"tenant_id=$1"}
	if filter.EntityType != "" {
		args = append(args, strings.ToLower(filter.EntityType))
		where = append(where, fmt.Sprintf("entity_type=$%d", len(args)))
	}
	if filter.EntityID != "" {
		args = append(args, strings.ToLower(filter.EntityID))
		where = append(where, fmt.Sprintf("entity_id=$%d", len(args)))
	}
	if filter.Status != "" {
		args = append(args, strings.ToUpper(filter.Status))
		where = append(where, fmt.Sprintf("status=$%d", len(args)))
	}
	if filter.MinimumRisk > 0 {
		args = append(args, filter.MinimumRisk)
		where = append(where, fmt.Sprintf("risk_score >= $%d", len(args)))
	}
	args = append(args, normalizedLimit(filter.Limit))
	rows, err := p.pool.Query(ctx, `SELECT `+uebaAnomalyColumns+` FROM ueba_anomalies WHERE `+
		strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list UEBA anomalies: %w", err)
	}
	defer rows.Close()
	items := []core.UEBAAnomaly{}
	for rows.Next() {
		item, err := scanUEBAAnomaly(rows)
		if err != nil {
			return nil, fmt.Errorf("scan UEBA anomaly: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) GetUEBABaseline(ctx context.Context, tenantID, entityType, entityID string) (core.UEBABaselineSummary, error) {
	var item core.UEBABaselineSummary
	err := p.pool.QueryRow(ctx, `SELECT tenant_id,entity_type,entity_id,entity_name,peer_group,model_version,
		feature_version,training_window_days,observation_count,first_seen,last_seen,drift_score,drift_status,updated_at
		FROM ueba_entity_baselines WHERE tenant_id=$1 AND entity_type=$2 AND entity_id=$3`,
		tenantID, strings.ToLower(entityType), strings.ToLower(entityID)).Scan(
		&item.TenantID, &item.EntityType, &item.EntityID, &item.EntityName, &item.PeerGroup,
		&item.ModelVersion, &item.FeatureVersion, &item.TrainingWindowDays, &item.ObservationCount,
		&item.FirstSeen, &item.LastSeen, &item.DriftScore, &item.DriftStatus, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.UEBABaselineSummary{}, ErrNotFound
	}
	if err != nil {
		return core.UEBABaselineSummary{}, fmt.Errorf("get UEBA baseline: %w", err)
	}
	return item, nil
}

func (p *Postgres) UpdateUEBAAnomalyFeedback(ctx context.Context, tenantID, anomalyID, status, actor, reason string, expectedVersion int) (core.UEBAAnomaly, error) {
	now := time.Now().UTC()
	item, err := scanUEBAAnomaly(p.pool.QueryRow(ctx, `UPDATE ueba_anomalies SET status=$4,feedback_by=$5,
		feedback_reason=$6,feedback_at=$7,version=version+1,updated_at=$7
		WHERE tenant_id=$1 AND anomaly_id=$2 AND version=$3 RETURNING `+uebaAnomalyColumns,
		tenantID, anomalyID, expectedVersion, status, actor, reason, now))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if checkErr := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ueba_anomalies
			WHERE tenant_id=$1 AND anomaly_id=$2)`, tenantID, anomalyID).Scan(&exists); checkErr != nil {
			return core.UEBAAnomaly{}, fmt.Errorf("check UEBA anomaly version: %w", checkErr)
		}
		if !exists {
			return core.UEBAAnomaly{}, ErrNotFound
		}
		return core.UEBAAnomaly{}, ErrVersionConflict
	}
	if err != nil {
		return core.UEBAAnomaly{}, fmt.Errorf("update UEBA feedback: %w", err)
	}
	return item, nil
}

type uebaRow interface {
	Scan(...interface{}) error
}

func scanUEBAAnomaly(row uebaRow) (core.UEBAAnomaly, error) {
	var item core.UEBAAnomaly
	var features, explanation []byte
	var feedbackBy, feedbackReason sql.NullString
	var feedbackAt sql.NullTime
	err := row.Scan(&item.TenantID, &item.ID, &item.EventID, &item.EntityType, &item.EntityID,
		&item.EntityName, &item.PeerGroup, &item.Title, &item.Severity, &item.RiskScore, &item.Confidence,
		&features, &explanation, &item.ModelVersion, &item.FeatureVersion, &item.TrainingWindowDays,
		&item.BaselineObservations, &item.Status, &item.Version, &feedbackBy, &feedbackReason, &feedbackAt,
		&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return core.UEBAAnomaly{}, err
	}
	if err := json.Unmarshal(features, &item.Features); err != nil {
		return core.UEBAAnomaly{}, fmt.Errorf("decode UEBA features: %w", err)
	}
	if err := json.Unmarshal(explanation, &item.Explanation); err != nil {
		return core.UEBAAnomaly{}, fmt.Errorf("decode UEBA explanation: %w", err)
	}
	item.FeedbackBy = feedbackBy.String
	item.FeedbackReason = feedbackReason.String
	if feedbackAt.Valid {
		item.FeedbackAt = &feedbackAt.Time
	}
	return item, nil
}
