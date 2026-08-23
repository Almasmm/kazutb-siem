package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kcsp/platform/internal/core"
)

var ErrEvidenceState = errors.New("invalid evidence state")

type EvidenceStore interface {
	ReserveEvidence(context.Context, core.EvidenceItem, core.EvidenceMutation) (core.EvidenceItem, bool, error)
	FinalizeEvidence(context.Context, string, string, string, string, core.EvidenceMutation) (core.EvidenceItem, error)
	FailEvidence(context.Context, string, string, string, core.EvidenceMutation) (core.EvidenceItem, error)
	Evidence(context.Context, string, string) (core.EvidenceItem, error)
	ListEvidence(context.Context, string, core.EvidenceFilter) ([]core.EvidenceItem, error)
	AppendEvidenceCustody(context.Context, string, string, core.EvidenceMutation) (core.EvidenceCustodyEntry, error)
	ListEvidenceCustody(context.Context, string, string) ([]core.EvidenceCustodyEntry, error)
	RecordEvidenceVerification(context.Context, string, string, bool, core.EvidenceMutation) (core.EvidenceItem, error)
	VerifyEvidenceCustody(context.Context, string, string) (bool, error)
}

func (p *Postgres) ReserveEvidence(ctx context.Context, item core.EvidenceItem, mutation core.EvidenceMutation) (core.EvidenceItem, bool, error) {
	if item.ID == "" || item.TenantID == "" || item.RequestID == "" || item.Filename == "" || item.ContentType == "" ||
		item.SHA256 == "" || item.Bucket == "" || item.ObjectKey == "" || item.Uploader == "" || item.RetainUntil.IsZero() ||
		(item.CaseID == "" && item.IncidentID == "" && item.AlertID == "" && item.EventID == "") {
		return core.EvidenceItem{}, false, errors.New("reserve evidence: required fields are missing")
	}
	if item.CaseID != "" {
		var exists bool
		if err := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cases WHERE tenant_id=$1 AND case_id=$2)`, item.TenantID, item.CaseID).Scan(&exists); err != nil {
			return core.EvidenceItem{}, false, err
		}
		if !exists {
			return core.EvidenceItem{}, false, ErrNotFound
		}
	}
	metadata, err := json.Marshal(item.Metadata)
	if err != nil {
		return core.EvidenceItem{}, false, err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.EvidenceItem{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	item.Status = "PENDING"
	reserved, err := scanEvidence(tx.QueryRow(ctx, `INSERT INTO evidence_items(
		tenant_id,evidence_id,request_id,case_id,incident_id,alert_id,event_id,filename,content_type,description,size_bytes,sha256,
		bucket,object_key,status,retain_until,legal_hold,uploader,metadata,created_at,updated_at)
		VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'PENDING',$15,$16,$17,$18,$19,$19)
		ON CONFLICT (tenant_id,request_id) DO NOTHING
		RETURNING `+evidenceColumns, item.TenantID, item.ID, item.RequestID, item.CaseID, item.IncidentID, item.AlertID, item.EventID,
		item.Filename, item.ContentType, item.Description, item.Size, item.SHA256, item.Bucket, item.ObjectKey,
		item.RetainUntil.UTC(), item.LegalHold, item.Uploader, metadata, now))
	if errors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		existing, lookupErr := p.evidenceByRequestID(ctx, item.TenantID, item.RequestID)
		return existing, false, lookupErr
	}
	if err != nil {
		return core.EvidenceItem{}, false, fmt.Errorf("reserve evidence: %w", err)
	}
	entry, err := appendEvidenceCustodyTx(ctx, tx, reserved.TenantID, reserved.ID, mutation)
	if err != nil {
		return core.EvidenceItem{}, false, err
	}
	reserved.CustodyHeadHash = entry.Hash
	if err := tx.Commit(ctx); err != nil {
		return core.EvidenceItem{}, false, err
	}
	return reserved, true, nil
}

func (p *Postgres) FinalizeEvidence(ctx context.Context, tenantID, evidenceID, objectVersion, etag string, mutation core.EvidenceMutation) (core.EvidenceItem, error) {
	return p.transitionEvidence(ctx, tenantID, evidenceID, "AVAILABLE", objectVersion, etag, "", mutation)
}

func (p *Postgres) FailEvidence(ctx context.Context, tenantID, evidenceID, failure string, mutation core.EvidenceMutation) (core.EvidenceItem, error) {
	return p.transitionEvidence(ctx, tenantID, evidenceID, "FAILED", "", "", truncateEvidenceFailure(failure), mutation)
}

func (p *Postgres) transitionEvidence(ctx context.Context, tenantID, evidenceID, status, objectVersion, etag, failure string, mutation core.EvidenceMutation) (core.EvidenceItem, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.EvidenceItem{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var currentStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM evidence_items WHERE tenant_id=$1 AND evidence_id=$2 FOR UPDATE`, tenantID, evidenceID).Scan(&currentStatus); errors.Is(err, pgx.ErrNoRows) {
		return core.EvidenceItem{}, ErrNotFound
	} else if err != nil {
		return core.EvidenceItem{}, err
	}
	if currentStatus != "PENDING" {
		return core.EvidenceItem{}, fmt.Errorf("%w: evidence is %s", ErrEvidenceState, currentStatus)
	}
	now := time.Now().UTC()
	item, err := scanEvidence(tx.QueryRow(ctx, `UPDATE evidence_items SET status=$3,object_version=$4,etag=$5,failure=$6,updated_at=$7
		WHERE tenant_id=$1 AND evidence_id=$2 RETURNING `+evidenceColumns, tenantID, evidenceID, status, objectVersion, etag, failure, now))
	if err != nil {
		return core.EvidenceItem{}, err
	}
	entry, err := appendEvidenceCustodyTx(ctx, tx, tenantID, evidenceID, mutation)
	if err != nil {
		return core.EvidenceItem{}, err
	}
	item.CustodyHeadHash = entry.Hash
	if err := tx.Commit(ctx); err != nil {
		return core.EvidenceItem{}, err
	}
	return item, nil
}

func (p *Postgres) Evidence(ctx context.Context, tenantID, evidenceID string) (core.EvidenceItem, error) {
	item, err := scanEvidence(p.pool.QueryRow(ctx, `SELECT `+evidenceColumns+` FROM evidence_items WHERE tenant_id=$1 AND evidence_id=$2`, tenantID, evidenceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.EvidenceItem{}, ErrNotFound
	}
	if err != nil {
		return core.EvidenceItem{}, fmt.Errorf("get evidence: %w", err)
	}
	return item, nil
}

func (p *Postgres) evidenceByRequestID(ctx context.Context, tenantID, requestID string) (core.EvidenceItem, error) {
	item, err := scanEvidence(p.pool.QueryRow(ctx, `SELECT `+evidenceColumns+` FROM evidence_items WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.EvidenceItem{}, ErrNotFound
	}
	return item, err
}

func (p *Postgres) ListEvidence(ctx context.Context, tenantID string, filter core.EvidenceFilter) ([]core.EvidenceItem, error) {
	args := []interface{}{tenantID}
	where := []string{"tenant_id=$1"}
	for _, item := range []struct {
		column, value string
	}{{"case_id", filter.CaseID}, {"incident_id", filter.IncidentID}, {"alert_id", filter.AlertID}, {"event_id", filter.EventID}, {"status", strings.ToUpper(filter.Status)}} {
		if item.value != "" {
			args = append(args, item.value)
			where = append(where, fmt.Sprintf("%s=$%d", item.column, len(args)))
		}
	}
	args = append(args, normalizedLimit(filter.Limit))
	rows, err := p.pool.Query(ctx, `SELECT `+evidenceColumns+` FROM evidence_items WHERE `+strings.Join(where, " AND ")+` ORDER BY created_at DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	defer rows.Close()
	items := []core.EvidenceItem{}
	for rows.Next() {
		item, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) AppendEvidenceCustody(ctx context.Context, tenantID, evidenceID string, mutation core.EvidenceMutation) (core.EvidenceCustodyEntry, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.EvidenceCustodyEntry{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	entry, err := appendEvidenceCustodyTx(ctx, tx, tenantID, evidenceID, mutation)
	if err != nil {
		return core.EvidenceCustodyEntry{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.EvidenceCustodyEntry{}, err
	}
	return entry, nil
}

func appendEvidenceCustodyTx(ctx context.Context, tx pgx.Tx, tenantID, evidenceID string, mutation core.EvidenceMutation) (core.EvidenceCustodyEntry, error) {
	mutation.Actor = strings.TrimSpace(mutation.Actor)
	mutation.Action = strings.TrimSpace(mutation.Action)
	mutation.Reason = strings.TrimSpace(mutation.Reason)
	if mutation.Actor == "" || mutation.Action == "" || mutation.Reason == "" || len(mutation.Reason) > 2000 {
		return core.EvidenceCustodyEntry{}, errors.New("evidence custody actor, action and reason are required")
	}
	var previousHash string
	if err := tx.QueryRow(ctx, `SELECT custody_head_hash FROM evidence_items WHERE tenant_id=$1 AND evidence_id=$2 FOR UPDATE`, tenantID, evidenceID).Scan(&previousHash); errors.Is(err, pgx.ErrNoRows) {
		return core.EvidenceCustodyEntry{}, ErrNotFound
	} else if err != nil {
		return core.EvidenceCustodyEntry{}, err
	}
	entry := core.EvidenceCustodyEntry{
		ID: core.NewID("chain"), TenantID: tenantID, EvidenceID: evidenceID, Actor: mutation.Actor,
		Action: mutation.Action, Reason: mutation.Reason, RequestID: mutation.RequestID,
		Metadata: mutation.Metadata, PreviousHash: previousHash, CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	entry.Hash = evidenceCustodyHash(entry)
	metadata, _ := json.Marshal(entry.Metadata)
	err := tx.QueryRow(ctx, `INSERT INTO evidence_custody_entries(
		tenant_id,evidence_id,custody_id,actor,action,reason,request_id,metadata,previous_hash,hash,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING sequence`, entry.TenantID, entry.EvidenceID,
		entry.ID, entry.Actor, entry.Action, entry.Reason, entry.RequestID, metadata, entry.PreviousHash, entry.Hash, entry.CreatedAt).Scan(&entry.Sequence)
	if err != nil {
		return core.EvidenceCustodyEntry{}, fmt.Errorf("append evidence custody: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE evidence_items SET custody_head_hash=$3,updated_at=$4 WHERE tenant_id=$1 AND evidence_id=$2`, tenantID, evidenceID, entry.Hash, entry.CreatedAt); err != nil {
		return core.EvidenceCustodyEntry{}, err
	}
	return entry, nil
}

func (p *Postgres) ListEvidenceCustody(ctx context.Context, tenantID, evidenceID string) ([]core.EvidenceCustodyEntry, error) {
	rows, err := p.pool.Query(ctx, `SELECT sequence,custody_id,tenant_id,evidence_id,actor,action,reason,request_id,metadata,
		previous_hash,hash,created_at FROM evidence_custody_entries WHERE tenant_id=$1 AND evidence_id=$2 ORDER BY sequence`, tenantID, evidenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []core.EvidenceCustodyEntry{}
	for rows.Next() {
		var item core.EvidenceCustodyEntry
		var metadata []byte
		if err := rows.Scan(&item.Sequence, &item.ID, &item.TenantID, &item.EvidenceID, &item.Actor, &item.Action,
			&item.Reason, &item.RequestID, &metadata, &item.PreviousHash, &item.Hash, &item.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(metadata, &item.Metadata); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) RecordEvidenceVerification(ctx context.Context, tenantID, evidenceID string, valid bool, mutation core.EvidenceMutation) (core.EvidenceItem, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.EvidenceItem{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM evidence_items WHERE tenant_id=$1 AND evidence_id=$2 FOR UPDATE`, tenantID, evidenceID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return core.EvidenceItem{}, ErrNotFound
	} else if err != nil {
		return core.EvidenceItem{}, err
	}
	if status != "AVAILABLE" {
		return core.EvidenceItem{}, fmt.Errorf("%w: evidence is %s", ErrEvidenceState, status)
	}
	verifiedAt := time.Now().UTC()
	if !valid {
		verifiedAt = time.Time{}
	}
	if valid {
		if _, err := tx.Exec(ctx, `UPDATE evidence_items SET verified_at=$3,updated_at=$3 WHERE tenant_id=$1 AND evidence_id=$2`, tenantID, evidenceID, verifiedAt); err != nil {
			return core.EvidenceItem{}, err
		}
	}
	if _, err := appendEvidenceCustodyTx(ctx, tx, tenantID, evidenceID, mutation); err != nil {
		return core.EvidenceItem{}, err
	}
	item, err := scanEvidence(tx.QueryRow(ctx, `SELECT `+evidenceColumns+` FROM evidence_items WHERE tenant_id=$1 AND evidence_id=$2`, tenantID, evidenceID))
	if err != nil {
		return core.EvidenceItem{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.EvidenceItem{}, err
	}
	return item, nil
}

func (p *Postgres) VerifyEvidenceCustody(ctx context.Context, tenantID, evidenceID string) (bool, error) {
	items, err := p.ListEvidenceCustody(ctx, tenantID, evidenceID)
	if err != nil {
		return false, err
	}
	if len(items) == 0 {
		return false, nil
	}
	previous := ""
	for _, item := range items {
		if item.PreviousHash != previous || evidenceCustodyHash(item) != item.Hash {
			return false, nil
		}
		previous = item.Hash
	}
	item, err := p.Evidence(ctx, tenantID, evidenceID)
	if err != nil {
		return false, err
	}
	return item.CustodyHeadHash == previous, nil
}

const evidenceColumns = `tenant_id,evidence_id,request_id,COALESCE(case_id,''),incident_id,alert_id,event_id,filename,content_type,
	description,size_bytes,sha256,bucket,object_key,object_version,etag,status,failure,retain_until,legal_hold,
	uploader,metadata,verified_at,custody_head_hash,created_at,updated_at`

func scanEvidence(scanner detectionScanner) (core.EvidenceItem, error) {
	var item core.EvidenceItem
	var metadata []byte
	err := scanner.Scan(&item.TenantID, &item.ID, &item.RequestID, &item.CaseID, &item.IncidentID, &item.AlertID, &item.EventID,
		&item.Filename, &item.ContentType, &item.Description, &item.Size, &item.SHA256, &item.Bucket, &item.ObjectKey,
		&item.ObjectVersion, &item.ETag, &item.Status, &item.Failure, &item.RetainUntil, &item.LegalHold,
		&item.Uploader, &metadata, &item.VerifiedAt, &item.CustodyHeadHash, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return core.EvidenceItem{}, err
	}
	if err := json.Unmarshal(metadata, &item.Metadata); err != nil {
		return core.EvidenceItem{}, err
	}
	return item, nil
}

func evidenceCustodyHash(entry core.EvidenceCustodyEntry) string {
	payload, _ := json.Marshal(struct {
		TenantID     string                 `json:"tenant_id"`
		EvidenceID   string                 `json:"evidence_id"`
		CustodyID    string                 `json:"custody_id"`
		Actor        string                 `json:"actor"`
		Action       string                 `json:"action"`
		Reason       string                 `json:"reason"`
		RequestID    string                 `json:"request_id"`
		Metadata     map[string]interface{} `json:"metadata"`
		PreviousHash string                 `json:"previous_hash"`
		CreatedAt    time.Time              `json:"created_at"`
	}{entry.TenantID, entry.EvidenceID, entry.ID, entry.Actor, entry.Action, entry.Reason, entry.RequestID,
		entry.Metadata, entry.PreviousHash, entry.CreatedAt.UTC()})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func truncateEvidenceFailure(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 2000 {
		return value[:2000]
	}
	return value
}
