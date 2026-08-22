package evidence_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/evidence"
	"github.com/kcsp/platform/internal/store"
)

func TestEvidenceServiceStoresImmutableVersionAndVerifiesCustody(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	endpoint := os.Getenv("KCSP_TEST_MINIO_ENDPOINT")
	accessKey := os.Getenv("KCSP_TEST_MINIO_ACCESS_KEY")
	secretKey := os.Getenv("KCSP_TEST_MINIO_SECRET_KEY")
	if databaseURL == "" || endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skip("PostgreSQL and MinIO integration settings are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	tenantID := "evidence-service-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "Evidence Service Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})
	secure, _ := strconv.ParseBool(os.Getenv("KCSP_TEST_MINIO_SECURE"))
	blobs, err := evidence.OpenMinIOBlob(ctx, evidence.MinIOConfig{
		Endpoint: endpoint, AccessKey: accessKey, SecretKey: secretKey, Bucket: "kcsp-evidence-test", Region: "us-east-1", Secure: secure,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := evidence.NewService(repository, blobs, evidence.Config{MaximumBytes: 1 << 20})
	payload := []byte("KCSP immutable forensic evidence\n")
	digest := sha256.Sum256(payload)
	upload := evidence.UploadInput{
		TenantID: tenantID, RequestID: "evidence-service-request-1", Actor: "analyst-l2", Filename: "forensics.txt",
		ContentType: "text/plain; charset=utf-8", Description: "Integration evidence", EventID: "event-forensics-1",
		ExpectedSHA256: hex.EncodeToString(digest[:]), Reader: bytes.NewReader(payload),
	}
	item, duplicate, err := service.Upload(ctx, upload)
	if err != nil || duplicate || item.Status != "AVAILABLE" || item.ObjectVersion == "" || item.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("upload immutable evidence: %+v duplicate=%v err=%v", item, duplicate, err)
	}
	upload.Reader = bytes.NewReader(payload)
	second, duplicate, err := service.Upload(ctx, upload)
	if err != nil || !duplicate || second.ID != item.ID || second.ObjectVersion != item.ObjectVersion {
		t.Fatalf("idempotent upload: %+v duplicate=%v err=%v", second, duplicate, err)
	}
	reader, opened, err := service.Open(ctx, tenantID, item.ID, "analyst-l2", "Malware investigation", "download-request-1")
	if err != nil {
		t.Fatal(err)
	}
	downloaded, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || !bytes.Equal(downloaded, payload) || opened.ID != item.ID {
		t.Fatalf("download immutable evidence: bytes=%q err=%v close=%v", downloaded, err, closeErr)
	}
	report, err := service.Verify(ctx, tenantID, item.ID, "analyst-l2", "Scheduled integrity verification", "verify-request-1")
	if err != nil || !report.Valid || report.Actual != item.SHA256 {
		t.Fatalf("verify immutable evidence: %+v err=%v", report, err)
	}
	entries, chainValid, err := service.Custody(ctx, tenantID, item.ID)
	if err != nil || !chainValid || len(entries) != 4 {
		t.Fatalf("evidence custody: entries=%+v valid=%v err=%v", entries, chainValid, err)
	}
}
