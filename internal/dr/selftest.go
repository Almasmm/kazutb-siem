package dr

import (
	"os"
	"path/filepath"
	"time"
)

func SelfTest() error {
	key := []byte("kcsp-dr-self-test-key-that-is-long-enough")
	manifest := Manifest{
		SchemaVersion:   manifestSchema,
		BackupID:        "1770000000-00112233445566778899aabb",
		Status:          "COMPLETE",
		PlatformVersion: "self-test",
		StartedAt:       time.Unix(1770000000, 0).UTC(),
		CompletedAt:     time.Unix(1770000001, 0).UTC(),
		Artifacts: []Artifact{{
			Path: "postgres/kcsp.dump", Kind: "postgres-dump", Size: 1,
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
	}
	body, signature, err := marshalSignedJSON(manifest, key)
	if err != nil {
		return err
	}
	if !verifySignedJSON(body, signature, key) {
		return os.ErrInvalid
	}
	body[0] ^= 1
	if verifySignedJSON(body, signature, key) {
		return os.ErrInvalid
	}
	root, err := os.MkdirTemp("", "kcsp-dr-self-test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	source := filepath.Join(root, "source")
	for _, relative := range configurationPaths {
		path := filepath.Join(source, filepath.FromSlash(relative))
		if filepath.Ext(path) != "" {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte("self-test\n"), 0o640); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(path, 0o750); err != nil {
			return err
		}
	}
	required := map[string]string{
		"content/sigma/windows/kcsp_suspicious_powershell.yml":    "title: self-test\n",
		"internal/store/migrations/0001_control_plane.sql":        "SELECT 1;\n",
		"internal/store/clickhouse_migrations/0001_telemetry.sql": "SELECT 1;\n",
	}
	for relative, content := range required {
		path := filepath.Join(source, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			return err
		}
	}
	archive := filepath.Join(root, "config.tar.gz")
	if err := archiveConfiguration(source, archive); err != nil {
		return err
	}
	return extractConfiguration(archive, filepath.Join(root, "restored"))
}
