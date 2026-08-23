package evidence

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

var (
	ErrInvalidEvidence     = errors.New("invalid evidence")
	ErrEvidencePending     = errors.New("evidence upload is in progress")
	ErrEvidenceIntegrity   = errors.New("evidence integrity check failed")
	ErrIdempotencyMismatch = errors.New("evidence idempotency request does not match original content")
)

const DefaultMaximumBytes int64 = 100 << 20

type Repository interface {
	store.EvidenceStore
	store.RetentionStore
}

type Config struct {
	MaximumBytes int64
}

type UploadInput struct {
	TenantID       string
	RequestID      string
	Actor          string
	Filename       string
	ContentType    string
	Description    string
	CaseID         string
	IncidentID     string
	AlertID        string
	EventID        string
	ExpectedSHA256 string
	Reader         io.Reader
}

type Service struct {
	repository Repository
	blobs      BlobStore
	maximum    int64
}

func NewService(repository Repository, blobs BlobStore, config Config) *Service {
	maximum := config.MaximumBytes
	if maximum <= 0 {
		maximum = DefaultMaximumBytes
	}
	return &Service{repository: repository, blobs: blobs, maximum: maximum}
}

func (s *Service) MaximumBytes() int64 { return s.maximum }

func (s *Service) Health(ctx context.Context) error { return s.blobs.Health(ctx) }

func (s *Service) Upload(ctx context.Context, input UploadInput) (core.EvidenceItem, bool, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.Actor = strings.TrimSpace(input.Actor)
	input.Description = strings.TrimSpace(input.Description)
	input.CaseID = strings.TrimSpace(input.CaseID)
	input.IncidentID = strings.TrimSpace(input.IncidentID)
	input.AlertID = strings.TrimSpace(input.AlertID)
	input.EventID = strings.TrimSpace(input.EventID)
	filename, err := safeFilename(input.Filename)
	if err != nil {
		return core.EvidenceItem{}, false, err
	}
	contentType, err := safeContentType(input.ContentType)
	if err != nil {
		return core.EvidenceItem{}, false, err
	}
	if input.TenantID == "" || input.RequestID == "" || input.Actor == "" || input.Reader == nil ||
		(input.CaseID == "" && input.IncidentID == "" && input.AlertID == "" && input.EventID == "") || len(input.Description) > 4000 {
		return core.EvidenceItem{}, false, fmt.Errorf("%w: tenant, request, actor, content and one investigation link are required", ErrInvalidEvidence)
	}
	temporary, err := os.CreateTemp("", "kcsp-evidence-*")
	if err != nil {
		return core.EvidenceItem{}, false, fmt.Errorf("create evidence spool: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(input.Reader, s.maximum+1))
	if err != nil {
		return core.EvidenceItem{}, false, fmt.Errorf("spool evidence: %w", err)
	}
	if size > s.maximum {
		return core.EvidenceItem{}, false, fmt.Errorf("%w: content exceeds %d bytes", ErrInvalidEvidence, s.maximum)
	}
	if err := temporary.Sync(); err != nil {
		return core.EvidenceItem{}, false, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	expected := normalizeSHA256(input.ExpectedSHA256)
	if strings.TrimSpace(input.ExpectedSHA256) != "" && expected == "" {
		return core.EvidenceItem{}, false, fmt.Errorf("%w: supplied SHA-256 is malformed", ErrInvalidEvidence)
	}
	if expected != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(digest)) != 1 {
		return core.EvidenceItem{}, false, fmt.Errorf("%w: supplied SHA-256 does not match content", ErrEvidenceIntegrity)
	}
	policy, err := s.repository.RetentionPolicy(ctx, input.TenantID)
	if err != nil {
		return core.EvidenceItem{}, false, err
	}
	now := time.Now().UTC()
	evidenceID := core.NewID("evd")
	objectKey := evidenceObjectKey(input.TenantID, evidenceID, filename, now)
	item := core.EvidenceItem{
		ID: evidenceID, TenantID: input.TenantID, RequestID: input.RequestID, CaseID: input.CaseID, IncidentID: input.IncidentID,
		AlertID: input.AlertID, EventID: input.EventID, Filename: filename, ContentType: contentType,
		Description: input.Description, Size: size, SHA256: digest, Bucket: s.blobs.Bucket(), ObjectKey: objectKey,
		Status: "PENDING", RetainUntil: now.AddDate(0, 0, policy.EvidenceDays), Uploader: input.Actor,
		Metadata: map[string]interface{}{"retention_policy_version": policy.Version},
	}
	reserved, created, err := s.repository.ReserveEvidence(ctx, item, core.EvidenceMutation{
		Actor: input.Actor, Action: "evidence.reserved", Reason: "Evidence upload reserved",
		RequestID: input.RequestID, Metadata: map[string]interface{}{"sha256": digest, "size": size},
	})
	if err != nil {
		return core.EvidenceItem{}, false, err
	}
	if !created {
		if reserved.SHA256 != digest || reserved.Size != size {
			return core.EvidenceItem{}, false, ErrIdempotencyMismatch
		}
		if reserved.Status == "AVAILABLE" {
			return reserved, true, nil
		}
		if reserved.Status != "PENDING" {
			return core.EvidenceItem{}, false, fmt.Errorf("%w: existing request is %s", store.ErrEvidenceState, reserved.Status)
		}
		blob, statErr := s.blobs.Stat(ctx, reserved.ObjectKey, reserved.ObjectVersion)
		if statErr != nil {
			if errors.Is(statErr, ErrBlobNotFound) {
				return core.EvidenceItem{}, false, ErrEvidencePending
			}
			return core.EvidenceItem{}, false, statErr
		}
		finalized, finalizeErr := s.repository.FinalizeEvidence(ctx, reserved.TenantID, reserved.ID, blob.VersionID, blob.ETag, core.EvidenceMutation{
			Actor: input.Actor, Action: "evidence.recovered", Reason: "Recovered completed object upload after metadata retry",
			RequestID: input.RequestID, Metadata: map[string]interface{}{"object_version": blob.VersionID},
		})
		return finalized, true, finalizeErr
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return core.EvidenceItem{}, false, err
	}
	blob, err := s.blobs.Put(ctx, item.ObjectKey, temporary, item.Size, item.ContentType, map[string]string{
		"evidence-id": item.ID, "tenant-id": item.TenantID, "sha256": item.SHA256, "request-id": item.RequestID,
	}, item.RetainUntil)
	if err != nil {
		_, _ = s.repository.FailEvidence(ctx, item.TenantID, item.ID, err.Error(), core.EvidenceMutation{
			Actor: input.Actor, Action: "evidence.upload_failed", Reason: "Immutable object upload failed",
			RequestID: input.RequestID, Metadata: map[string]interface{}{"error": err.Error()},
		})
		return core.EvidenceItem{}, false, err
	}
	finalized, err := s.repository.FinalizeEvidence(ctx, item.TenantID, item.ID, blob.VersionID, blob.ETag, core.EvidenceMutation{
		Actor: input.Actor, Action: "evidence.uploaded", Reason: "Evidence stored in immutable object storage",
		RequestID: input.RequestID, Metadata: map[string]interface{}{"object_version": blob.VersionID, "etag": blob.ETag},
	})
	if err != nil {
		return core.EvidenceItem{}, false, err
	}
	return finalized, false, nil
}

func (s *Service) Evidence(ctx context.Context, tenantID, evidenceID string) (core.EvidenceItem, error) {
	return s.repository.Evidence(ctx, tenantID, evidenceID)
}

func (s *Service) List(ctx context.Context, tenantID string, filter core.EvidenceFilter) ([]core.EvidenceItem, error) {
	return s.repository.ListEvidence(ctx, tenantID, filter)
}

func (s *Service) Open(ctx context.Context, tenantID, evidenceID, actor, reason, requestID string) (io.ReadCloser, core.EvidenceItem, error) {
	if strings.TrimSpace(actor) == "" || len(strings.TrimSpace(reason)) < 3 {
		return nil, core.EvidenceItem{}, fmt.Errorf("%w: actor and access reason are required", ErrInvalidEvidence)
	}
	item, err := s.repository.Evidence(ctx, tenantID, evidenceID)
	if err != nil {
		return nil, core.EvidenceItem{}, err
	}
	if item.Status != "AVAILABLE" {
		return nil, core.EvidenceItem{}, fmt.Errorf("%w: evidence is %s", store.ErrEvidenceState, item.Status)
	}
	reader, info, err := s.blobs.Open(ctx, item.ObjectKey, item.ObjectVersion)
	if err != nil {
		return nil, core.EvidenceItem{}, err
	}
	if info.Size != item.Size || metadataSHA(info.Metadata) != item.SHA256 {
		_ = reader.Close()
		return nil, core.EvidenceItem{}, ErrEvidenceIntegrity
	}
	if _, err := s.repository.AppendEvidenceCustody(ctx, tenantID, evidenceID, core.EvidenceMutation{
		Actor: actor, Action: "evidence.accessed", Reason: strings.TrimSpace(reason), RequestID: requestID,
		Metadata: map[string]interface{}{"object_version": item.ObjectVersion},
	}); err != nil {
		_ = reader.Close()
		return nil, core.EvidenceItem{}, err
	}
	return reader, item, nil
}

func (s *Service) Verify(ctx context.Context, tenantID, evidenceID, actor, reason, requestID string) (core.EvidenceVerification, error) {
	if strings.TrimSpace(actor) == "" || len(strings.TrimSpace(reason)) < 3 {
		return core.EvidenceVerification{}, fmt.Errorf("%w: actor and verification reason are required", ErrInvalidEvidence)
	}
	item, err := s.repository.Evidence(ctx, tenantID, evidenceID)
	if err != nil {
		return core.EvidenceVerification{}, err
	}
	if item.Status != "AVAILABLE" {
		return core.EvidenceVerification{}, fmt.Errorf("%w: evidence is %s", store.ErrEvidenceState, item.Status)
	}
	reader, _, err := s.blobs.Open(ctx, item.ObjectKey, item.ObjectVersion)
	if err != nil {
		return core.EvidenceVerification{}, err
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(hasher, reader)
	closeErr := reader.Close()
	if copyErr != nil {
		return core.EvidenceVerification{}, copyErr
	}
	if closeErr != nil {
		return core.EvidenceVerification{}, closeErr
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	valid := size == item.Size && subtle.ConstantTimeCompare([]byte(actual), []byte(item.SHA256)) == 1
	verifiedAt := time.Now().UTC()
	action := "evidence.verified"
	if !valid {
		action = "evidence.verification_failed"
	}
	_, err = s.repository.RecordEvidenceVerification(ctx, tenantID, evidenceID, valid, core.EvidenceMutation{
		Actor: actor, Action: action, Reason: strings.TrimSpace(reason), RequestID: requestID,
		Metadata: map[string]interface{}{"expected_sha256": item.SHA256, "actual_sha256": actual, "size": size},
	})
	if err != nil {
		return core.EvidenceVerification{}, err
	}
	return core.EvidenceVerification{EvidenceID: evidenceID, Expected: item.SHA256, Actual: actual, Size: size, Valid: valid, VerifiedAt: verifiedAt}, nil
}

func (s *Service) Custody(ctx context.Context, tenantID, evidenceID string) ([]core.EvidenceCustodyEntry, bool, error) {
	items, err := s.repository.ListEvidenceCustody(ctx, tenantID, evidenceID)
	if err != nil {
		return nil, false, err
	}
	valid, err := s.repository.VerifyEvidenceCustody(ctx, tenantID, evidenceID)
	return items, valid, err
}

var unsafeFilenameCharacters = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeFilename(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	value = path.Base(value)
	value = unsafeFilenameCharacters.ReplaceAllString(value, "_")
	value = strings.Trim(value, "._-")
	if value == "" || len(value) > 255 {
		return "", fmt.Errorf("%w: filename must contain between 1 and 255 safe characters", ErrInvalidEvidence)
	}
	return value, nil
}

func safeContentType(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "application/octet-stream", nil
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil || len(mediaType) > 255 {
		return "", fmt.Errorf("%w: invalid content type", ErrInvalidEvidence)
	}
	return mediaType, nil
}

func evidenceObjectKey(tenantID, evidenceID, filename string, now time.Time) string {
	tenantID = unsafeFilenameCharacters.ReplaceAllString(tenantID, "_")
	return fmt.Sprintf("%s/%04d/%02d/%02d/%s/%s", tenantID, now.Year(), now.Month(), now.Day(), evidenceID, filename)
}

func normalizeSHA256(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "sha256:")))
	if len(value) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return value
}

func metadataSHA(metadata map[string]string) string {
	for key, value := range metadata {
		if strings.EqualFold(strings.TrimPrefix(key, "x-amz-meta-"), "sha256") {
			return strings.ToLower(value)
		}
	}
	return ""
}
