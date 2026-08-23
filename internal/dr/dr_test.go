package dr

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedManifestRejectsTampering(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	manifest := Manifest{
		SchemaVersion: manifestSchema, BackupID: "1770000000-00112233445566778899aabb", Status: "COMPLETE",
		StartedAt: time.Unix(1770000000, 0), CompletedAt: time.Unix(1770000001, 0),
		Artifacts: []Artifact{{Path: "config/a.tar.gz", Kind: "configuration", Size: 1, SHA256: strings.Repeat("a", 64)}},
	}
	body, signature, err := marshalSignedJSON(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	if !verifySignedJSON(body, signature, key) {
		t.Fatal("valid signature was rejected")
	}
	body[len(body)/2] ^= 1
	if verifySignedJSON(body, signature, key) {
		t.Fatal("tampered manifest was accepted")
	}
}

func TestManifestRejectsTraversalAndDuplicateArtifacts(t *testing.T) {
	base := Manifest{
		SchemaVersion: manifestSchema, BackupID: "1770000000-00112233445566778899aabb", Status: "COMPLETE",
		StartedAt: time.Unix(1770000000, 0), CompletedAt: time.Unix(1770000001, 0),
	}
	for _, value := range []string{"../secret", "/absolute", `windows\path`, "a/../../b"} {
		manifest := base
		manifest.Artifacts = []Artifact{{Path: value, Size: 1, SHA256: strings.Repeat("a", 64)}}
		if err := manifest.Validate(manifest.BackupID); err == nil {
			t.Fatalf("unsafe path %q was accepted", value)
		}
	}
	manifest := base
	manifest.Artifacts = []Artifact{
		{Path: "a", Size: 1, SHA256: strings.Repeat("a", 64)},
		{Path: "a", Size: 1, SHA256: strings.Repeat("b", 64)},
	}
	if err := manifest.Validate(manifest.BackupID); err == nil {
		t.Fatal("duplicate artifact was accepted")
	}
}

func TestEndpointPolicy(t *testing.T) {
	if _, err := parseEndpoint("http://backup:9000", false); err == nil {
		t.Fatal("plaintext endpoint was accepted without opt-in")
	}
	endpoint, err := parseEndpoint("https://BACKUP.EXAMPLE:9000/", false)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Host != "backup.example:9000" || !endpoint.Secure {
		t.Fatalf("unexpected endpoint: %+v", endpoint)
	}
	for _, value := range []string{"ftp://backup", "https://user:pass@backup", "https://backup/path"} {
		if _, err := parseEndpoint(value, true); err == nil {
			t.Fatalf("unsafe endpoint %q was accepted", value)
		}
	}
}

func TestExtractConfigurationRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "malicious.tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	writer := tar.NewWriter(gz)
	content := []byte("escape")
	if err := writer.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractConfiguration(archivePath, filepath.Join(root, "restore")); err == nil {
		t.Fatal("path traversal archive was accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "escape")); !os.IsNotExist(err) {
		t.Fatal("archive escaped restore directory")
	}
}

func TestSelfTest(t *testing.T) {
	if err := SelfTest(); err != nil {
		t.Fatal(err)
	}
}
