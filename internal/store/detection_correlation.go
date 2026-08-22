package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/detection"
)

func (p *Postgres) ObserveCorrelation(ctx context.Context, input core.CorrelationObservation) (core.CorrelationEvaluation, error) {
	if strings.TrimSpace(input.TenantID) == "" || strings.TrimSpace(input.RuleID) == "" || strings.TrimSpace(input.RuleVersion) == "" ||
		strings.TrimSpace(input.GroupKey) == "" || strings.TrimSpace(input.EventID) == "" || input.EventTime.IsZero() || len(input.SourceRuleIDs) == 0 {
		return core.CorrelationEvaluation{}, fmt.Errorf("observe correlation: required identity fields are missing")
	}
	window := time.Duration(input.Spec.TimespanSeconds) * time.Second
	if window < time.Second || window > 24*time.Hour {
		return core.CorrelationEvaluation{}, fmt.Errorf("observe correlation: invalid timespan")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.CorrelationEvaluation{}, fmt.Errorf("begin correlation observation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	lockKey := input.RuleID + "\x1e" + input.RuleVersion + "\x1e" + input.GroupKey
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))`, input.TenantID, lockKey); err != nil {
		return core.CorrelationEvaluation{}, fmt.Errorf("lock correlation group: %w", err)
	}
	groupSum := sha256.Sum256([]byte(input.GroupKey))
	groupHash := hex.EncodeToString(groupSum[:])
	inserted := int64(0)
	for _, sourceRuleID := range uniqueCorrelationSources(input.SourceRuleIDs) {
		tag, err := tx.Exec(ctx, `INSERT INTO detection_correlation_observations(
			tenant_id,correlation_rule_id,correlation_rule_version,group_key_hash,group_key,source_rule_id,event_id,event_time,value)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, input.TenantID, input.RuleID, input.RuleVersion,
			groupHash, input.GroupKey, sourceRuleID, input.EventID, input.EventTime.UTC(), input.Value)
		if err != nil {
			return core.CorrelationEvaluation{}, fmt.Errorf("persist correlation observation: %w", err)
		}
		inserted += tag.RowsAffected()
	}
	if inserted == 0 {
		if err := tx.Commit(ctx); err != nil {
			return core.CorrelationEvaluation{}, err
		}
		return core.CorrelationEvaluation{}, nil
	}
	retentionCutoff := input.EventTime.UTC().Add(-2 * window)
	if _, err := tx.Exec(ctx, `DELETE FROM detection_correlation_observations
		WHERE tenant_id=$1 AND correlation_rule_id=$2 AND correlation_rule_version=$3 AND group_key_hash=$4 AND event_time < $5`,
		input.TenantID, input.RuleID, input.RuleVersion, groupHash, retentionCutoff); err != nil {
		return core.CorrelationEvaluation{}, fmt.Errorf("prune correlation observations: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT source_rule_id,event_id,event_time,value FROM detection_correlation_observations
		WHERE tenant_id=$1 AND correlation_rule_id=$2 AND correlation_rule_version=$3 AND group_key_hash=$4
		AND event_time >= $5 AND event_time <= $6 ORDER BY event_time,event_id,source_rule_id`, input.TenantID, input.RuleID,
		input.RuleVersion, groupHash, input.EventTime.UTC().Add(-window), input.EventTime.UTC())
	if err != nil {
		return core.CorrelationEvaluation{}, fmt.Errorf("query correlation window: %w", err)
	}
	records := []core.CorrelationRecord{}
	for rows.Next() {
		var record core.CorrelationRecord
		if err := rows.Scan(&record.SourceRuleID, &record.EventID, &record.EventTime, &record.Value); err != nil {
			rows.Close()
			return core.CorrelationEvaluation{}, fmt.Errorf("scan correlation observation: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return core.CorrelationEvaluation{}, err
	}
	rows.Close()
	beforeRecords := make([]core.CorrelationRecord, 0, len(records))
	for _, record := range records {
		if record.EventID != input.EventID {
			beforeRecords = append(beforeRecords, record)
		}
	}
	before := detection.EvaluateCorrelation(input.Spec, beforeRecords)
	after := detection.EvaluateCorrelation(input.Spec, records)
	if !before.Satisfied && after.Satisfied {
		fingerprint := detection.CorrelationFingerprint(input, after)
		tag, err := tx.Exec(ctx, `INSERT INTO detection_correlation_emissions(
			tenant_id,correlation_rule_id,correlation_rule_version,group_key_hash,fingerprint,triggering_event_id,event_ids)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, input.TenantID, input.RuleID, input.RuleVersion,
			groupHash, fingerprint, input.EventID, after.EventIDs)
		if err != nil {
			return core.CorrelationEvaluation{}, fmt.Errorf("persist correlation emission: %w", err)
		}
		after.Triggered = tag.RowsAffected() == 1
	}
	if err := tx.Commit(ctx); err != nil {
		return core.CorrelationEvaluation{}, fmt.Errorf("commit correlation observation: %w", err)
	}
	return after, nil
}

func uniqueCorrelationSources(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
