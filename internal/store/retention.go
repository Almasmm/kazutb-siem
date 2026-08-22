package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kcsp/platform/internal/core"
)

const (
	DefaultRawRetentionDays        = 30
	DefaultNormalizedRetentionDays = 90
	DefaultFindingsRetentionDays   = 180
	DefaultEvidenceRetentionDays   = 2555
)

var ErrInvalidRetentionPolicy = errors.New("invalid retention policy")

type RetentionStore interface {
	RetentionPolicy(context.Context, string) (core.RetentionPolicy, error)
	UpdateRetentionPolicy(context.Context, core.RetentionPolicy) (core.RetentionPolicy, error)
}

func ValidateRetentionPolicy(policy core.RetentionPolicy) error {
	values := []struct {
		name       string
		value, max int
	}{
		{"raw_days", policy.RawDays, 3650},
		{"normalized_days", policy.NormalizedDays, 3650},
		{"findings_days", policy.FindingsDays, 3650},
		{"evidence_days", policy.EvidenceDays, 36500},
	}
	for _, item := range values {
		if item.value < 1 || item.value > item.max {
			return fmt.Errorf("%w: %s must be between 1 and %d", ErrInvalidRetentionPolicy, item.name, item.max)
		}
	}
	if policy.RawDays > policy.NormalizedDays {
		return fmt.Errorf("%w: raw_days cannot exceed normalized_days", ErrInvalidRetentionPolicy)
	}
	return nil
}

func (p *Postgres) RetentionPolicy(ctx context.Context, tenantID string) (core.RetentionPolicy, error) {
	if _, err := p.pool.Exec(ctx, `INSERT INTO tenant_retention_policies(
		tenant_id,raw_days,normalized_days,findings_days,evidence_days,updated_by)
		VALUES($1,$2,$3,$4,$5,'system:defaults') ON CONFLICT DO NOTHING`, tenantID, DefaultRawRetentionDays,
		DefaultNormalizedRetentionDays, DefaultFindingsRetentionDays, DefaultEvidenceRetentionDays); err != nil {
		return core.RetentionPolicy{}, fmt.Errorf("initialize retention policy: %w", err)
	}
	policy, err := scanRetentionPolicy(p.pool.QueryRow(ctx, retentionPolicySelect+` WHERE tenant_id=$1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.RetentionPolicy{}, ErrNotFound
	}
	if err != nil {
		return core.RetentionPolicy{}, fmt.Errorf("get retention policy: %w", err)
	}
	return policy, nil
}

func (p *Postgres) UpdateRetentionPolicy(ctx context.Context, policy core.RetentionPolicy) (core.RetentionPolicy, error) {
	if policy.TenantID == "" || policy.UpdatedBy == "" || policy.Version < 1 {
		return core.RetentionPolicy{}, fmt.Errorf("%w: tenant, updater and current version are required", ErrInvalidRetentionPolicy)
	}
	if err := ValidateRetentionPolicy(policy); err != nil {
		return core.RetentionPolicy{}, err
	}
	if _, err := p.RetentionPolicy(ctx, policy.TenantID); err != nil {
		return core.RetentionPolicy{}, err
	}
	updated, err := scanRetentionPolicy(p.pool.QueryRow(ctx, `UPDATE tenant_retention_policies SET raw_days=$3,
		normalized_days=$4,findings_days=$5,evidence_days=$6,updated_by=$7,version=version+1,updated_at=$8
		WHERE tenant_id=$1 AND version=$2 RETURNING tenant_id,raw_days,normalized_days,findings_days,evidence_days,
		updated_by,version,created_at,updated_at`, policy.TenantID, policy.Version, policy.RawDays, policy.NormalizedDays,
		policy.FindingsDays, policy.EvidenceDays, policy.UpdatedBy, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.RetentionPolicy{}, ErrVersionConflict
	}
	if err != nil {
		return core.RetentionPolicy{}, fmt.Errorf("update retention policy: %w", err)
	}
	return updated, nil
}

const retentionPolicySelect = `SELECT tenant_id,raw_days,normalized_days,findings_days,evidence_days,
	updated_by,version,created_at,updated_at FROM tenant_retention_policies`

func scanRetentionPolicy(scanner detectionScanner) (core.RetentionPolicy, error) {
	var policy core.RetentionPolicy
	err := scanner.Scan(&policy.TenantID, &policy.RawDays, &policy.NormalizedDays, &policy.FindingsDays,
		&policy.EvidenceDays, &policy.UpdatedBy, &policy.Version, &policy.CreatedAt, &policy.UpdatedAt)
	return policy, err
}
