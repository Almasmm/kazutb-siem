package dr

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

const manifestSchema = "kcsp.dr/v1"

type Artifact struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ObjectRecord struct {
	Key          string            `json:"key"`
	Size         int64             `json:"size"`
	SHA256       string            `json:"sha256"`
	ETag         string            `json:"etag,omitempty"`
	VersionID    string            `json:"version_id,omitempty"`
	LastModified time.Time         `json:"last_modified,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type StoreSummary struct {
	PostgresDatabase      string `json:"postgres_database"`
	ClickHouseDatabase    string `json:"clickhouse_database"`
	ClickHouseArchive     string `json:"clickhouse_archive"`
	MinIOSourceBucket     string `json:"minio_source_bucket"`
	MinIOObjectCount      int64  `json:"minio_object_count"`
	MinIOBytes            int64  `json:"minio_bytes"`
	ConfigurationIncluded bool   `json:"configuration_included"`
}

type Manifest struct {
	SchemaVersion   string       `json:"schema_version"`
	BackupID        string       `json:"backup_id"`
	Status          string       `json:"status"`
	PlatformVersion string       `json:"platform_version"`
	StartedAt       time.Time    `json:"started_at"`
	CompletedAt     time.Time    `json:"completed_at"`
	RPOTargetSec    int64        `json:"rpo_target_seconds"`
	Stores          StoreSummary `json:"stores"`
	Artifacts       []Artifact   `json:"artifacts"`
}

type DrillReport struct {
	SchemaVersion       string    `json:"schema_version"`
	BackupID            string    `json:"backup_id"`
	Mode                string    `json:"mode"`
	Status              string    `json:"status"`
	StartedAt           time.Time `json:"started_at"`
	CompletedAt         time.Time `json:"completed_at"`
	DurationSeconds     float64   `json:"duration_seconds"`
	BackupAgeSeconds    float64   `json:"backup_age_seconds"`
	RPOTargetSeconds    float64   `json:"rpo_target_seconds"`
	RTOTargetSeconds    float64   `json:"rto_target_seconds"`
	RPOMet              bool      `json:"rpo_met"`
	RTOMet              bool      `json:"rto_met"`
	PostgresDatabase    string    `json:"postgres_database"`
	ClickHouseDatabase  string    `json:"clickhouse_database"`
	MinIOBucket         string    `json:"minio_bucket"`
	ArtifactsVerified   int       `json:"artifacts_verified"`
	ObjectsRestored     int64     `json:"objects_restored"`
	EvidenceHashesValid int64     `json:"evidence_hashes_valid"`
	Error               string    `json:"error,omitempty"`
}

func newBackupID(now time.Time) (string, error) {
	var entropy [12]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("create backup id: %w", err)
	}
	return fmt.Sprintf("%d-%s", now.UTC().Unix(), hex.EncodeToString(entropy[:])), nil
}

func (m *Manifest) Normalize() {
	sort.Slice(m.Artifacts, func(i, j int) bool { return m.Artifacts[i].Path < m.Artifacts[j].Path })
	m.StartedAt = m.StartedAt.UTC()
	m.CompletedAt = m.CompletedAt.UTC()
}

func (m Manifest) Validate(expectedID string) error {
	if m.SchemaVersion != manifestSchema || m.Status != "COMPLETE" {
		return errors.New("backup manifest is not complete or uses an unsupported schema")
	}
	if m.BackupID != expectedID || !backupIDPattern.MatchString(m.BackupID) {
		return errors.New("backup manifest identity mismatch")
	}
	if m.StartedAt.IsZero() || m.CompletedAt.Before(m.StartedAt) {
		return errors.New("backup manifest timestamps are invalid")
	}
	seen := make(map[string]struct{}, len(m.Artifacts))
	for _, artifact := range m.Artifacts {
		if err := validateArtifactPath(artifact.Path); err != nil {
			return err
		}
		if artifact.Size < 0 || len(artifact.SHA256) != sha256.Size*2 {
			return fmt.Errorf("artifact %q has invalid integrity metadata", artifact.Path)
		}
		if _, ok := seen[artifact.Path]; ok {
			return fmt.Errorf("artifact %q is duplicated", artifact.Path)
		}
		seen[artifact.Path] = struct{}{}
	}
	return nil
}

func marshalSignedJSON(value any, key []byte) ([]byte, string, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, "", err
	}
	body = append(body, '\n')
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	return body, hex.EncodeToString(mac.Sum(nil)), nil
}

func verifySignedJSON(body []byte, signature string, key []byte) bool {
	provided, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	return hmac.Equal(mac.Sum(nil), provided)
}

func fileArtifact(localPath, artifactPath, kind string) (Artifact, error) {
	if err := validateArtifactPath(artifactPath); err != nil {
		return Artifact{}, err
	}
	file, err := os.Open(localPath)
	if err != nil {
		return Artifact{}, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Path: artifactPath, Kind: kind, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func validateArtifactPath(value string) error {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") ||
		path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("unsafe artifact path %q", value)
	}
	return nil
}
