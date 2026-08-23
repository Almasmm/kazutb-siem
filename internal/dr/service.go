package dr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const postgresInventorySQL = `
SELECT kind || '|' || schema_name || '|' || object_name
FROM (
    SELECT 'relation' AS kind, n.nspname AS schema_name, c.relname AS object_name
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname !~ '^pg_toast'
      AND c.relkind IN ('r','p','v','m','S','f')
    UNION ALL
    SELECT 'policy', schemaname, tablename || ':' || policyname
    FROM pg_catalog.pg_policies
    UNION ALL
    SELECT 'extension', 'public', extname
    FROM pg_catalog.pg_extension
) inventory
ORDER BY kind, schema_name, object_name;
`

type Service struct {
	cfg    Config
	stores *objectStores
	runner commandRunner
	now    func() time.Time
}

type BackupResult struct {
	BackupID     string    `json:"backup_id"`
	CompletedAt  time.Time `json:"completed_at"`
	Artifacts    int       `json:"artifacts"`
	MinIOObjects int64     `json:"minio_objects"`
	MinIOBytes   int64     `json:"minio_bytes"`
}

type RestoreResult struct {
	BackupID           string `json:"backup_id"`
	Mode               string `json:"mode"`
	PostgresDatabase   string `json:"postgres_database"`
	ClickHouseDatabase string `json:"clickhouse_database"`
	MinIOBucket        string `json:"minio_bucket"`
	ConfigDirectory    string `json:"config_directory"`
	ObjectsRestored    int64  `json:"objects_restored"`
	EvidenceVerified   int64  `json:"evidence_verified"`
	RPOMet             bool   `json:"rpo_met"`
	RTOMet             bool   `json:"rto_met"`
}

func NewService(cfg Config) (*Service, error) {
	stores, err := newObjectStores(cfg)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, stores: stores, runner: execCommandRunner{}, now: time.Now}, nil
}

func (s *Service) Backup(ctx context.Context) (BackupResult, error) {
	if err := os.MkdirAll(s.cfg.WorkDir, 0o750); err != nil {
		return BackupResult{}, err
	}
	lock, err := acquireLock(filepath.Join(s.cfg.WorkDir, ".kcsp-dr.lock"))
	if err != nil {
		return BackupResult{}, err
	}
	defer releaseLock(lock)
	if err := s.stores.prepare(ctx); err != nil {
		return BackupResult{}, err
	}
	started := s.now().UTC()
	backupID, err := newBackupID(started)
	if err != nil {
		return BackupResult{}, err
	}
	prefix := "snapshots/" + backupID
	exists, err := s.stores.objectExists(ctx, prefix+"/_SUCCESS")
	if err != nil {
		return BackupResult{}, err
	}
	if exists {
		return BackupResult{}, errors.New("generated backup identity already exists")
	}
	work := filepath.Join(s.cfg.WorkDir, "backup-"+backupID)
	if err := os.Mkdir(work, 0o750); err != nil {
		return BackupResult{}, err
	}
	clickHouseArchive := filepath.Join(s.cfg.ClickHouseDir, backupID+".zip")
	defer func() {
		_ = os.RemoveAll(work)
		_ = os.Remove(clickHouseArchive)
	}()

	postgresDir := filepath.Join(work, "postgres")
	configDir := filepath.Join(work, "config")
	minioDir := filepath.Join(work, "minio")
	for _, directory := range []string{postgresDir, configDir, minioDir, s.cfg.ClickHouseDir} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return BackupResult{}, err
		}
	}
	if err := s.backupPostgres(ctx, postgresDir); err != nil {
		return BackupResult{}, err
	}
	clickHouseInventory := filepath.Join(work, "clickhouse-inventory.txt")
	if err := s.backupClickHouse(ctx, backupID+".zip", clickHouseArchive, clickHouseInventory, work); err != nil {
		return BackupResult{}, err
	}
	configArchive := filepath.Join(configDir, "kcsp-config.tar.gz")
	if err := archiveConfiguration(s.cfg.ConfigRoot, configArchive); err != nil {
		return BackupResult{}, fmt.Errorf("archive configuration: %w", err)
	}
	objectInventory := filepath.Join(minioDir, "inventory.jsonl")
	objectCount, objectBytes, err := s.stores.backupObjects(ctx, prefix, objectInventory)
	if err != nil {
		return BackupResult{}, err
	}

	localArtifacts := []struct {
		path string
		kind string
		file string
	}{
		{"postgres/kcsp.dump", "postgres-dump", filepath.Join(postgresDir, "kcsp.dump")},
		{"postgres/globals.sql", "postgres-globals", filepath.Join(postgresDir, "globals.sql")},
		{"postgres/inventory.txt", "postgres-inventory", filepath.Join(postgresDir, "inventory.txt")},
		{"clickhouse/backup.zip", "clickhouse-backup", clickHouseArchive},
		{"clickhouse/inventory.txt", "clickhouse-inventory", clickHouseInventory},
		{"config/kcsp-config.tar.gz", "configuration", configArchive},
		{"minio/inventory.jsonl", "minio-inventory", objectInventory},
	}
	artifacts := make([]Artifact, 0, len(localArtifacts))
	files := make(map[string]string, len(localArtifacts))
	for _, item := range localArtifacts {
		artifact, err := fileArtifact(item.file, item.path, item.kind)
		if err != nil {
			return BackupResult{}, fmt.Errorf("inventory artifact %s: %w", item.path, err)
		}
		artifacts = append(artifacts, artifact)
		files[item.path] = item.file
	}
	for _, artifact := range artifacts {
		if err := s.stores.putFile(ctx, prefix+"/"+artifact.Path, files[artifact.Path], artifact); err != nil {
			return BackupResult{}, fmt.Errorf("upload artifact %s: %w", artifact.Path, err)
		}
	}
	completed := s.now().UTC()
	manifest := Manifest{
		SchemaVersion: manifestSchema, BackupID: backupID, Status: "COMPLETE", PlatformVersion: s.cfg.Version,
		StartedAt: started, CompletedAt: completed, RPOTargetSec: int64(s.cfg.RPOTarget.Seconds()),
		Stores: StoreSummary{
			PostgresDatabase: s.cfg.PostgresDatabase, ClickHouseDatabase: s.cfg.ClickHouseDatabase,
			ClickHouseArchive: backupID + ".zip", MinIOSourceBucket: s.cfg.SourceBucket,
			MinIOObjectCount: objectCount, MinIOBytes: objectBytes, ConfigurationIncluded: true,
		},
		Artifacts: artifacts,
	}
	manifest.Normalize()
	body, signature, err := marshalSignedJSON(manifest, s.cfg.ManifestHMACKey)
	if err != nil {
		return BackupResult{}, err
	}
	if err := s.stores.putBytes(ctx, prefix+"/manifest.json", "application/json", body); err != nil {
		return BackupResult{}, err
	}
	if err := s.stores.putBytes(ctx, prefix+"/manifest.hmac", "text/plain", []byte(signature+"\n")); err != nil {
		return BackupResult{}, err
	}
	marker, _ := json.Marshal(map[string]any{"backup_id": backupID, "completed_at": completed})
	if err := s.stores.putBytes(ctx, prefix+"/_SUCCESS", "application/json", append(marker, '\n')); err != nil {
		return BackupResult{}, err
	}
	log.Printf("KCSP DR backup complete id=%s artifacts=%d objects=%d bytes=%d", backupID, len(artifacts), objectCount, objectBytes)
	return BackupResult{BackupID: backupID, CompletedAt: completed, Artifacts: len(artifacts), MinIOObjects: objectCount, MinIOBytes: objectBytes}, nil
}

func (s *Service) backupPostgres(ctx context.Context, directory string) error {
	environment := []string{"PGPASSWORD=" + s.cfg.PostgresPassword}
	common := []string{
		"--host", s.cfg.PostgresHost, "--port", strconv.Itoa(s.cfg.PostgresPort),
		"--username", s.cfg.PostgresUser,
	}
	dumpArguments := append(append([]string{}, common...),
		"--dbname", s.cfg.PostgresDatabase, "--format=custom", "--compress=6",
		"--no-owner", "--no-privileges", "--file", filepath.Join(directory, "kcsp.dump"),
	)
	if err := s.runner.Run(ctx, s.cfg.CommandTimeout, io.Discard, environment, "pg_dump", dumpArguments...); err != nil {
		return fmt.Errorf("PostgreSQL backup: %w", err)
	}
	globals, err := os.OpenFile(filepath.Join(directory, "globals.sql"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	globalArguments := append(append([]string{}, common...), "--globals-only", "--no-role-passwords")
	runErr := s.runner.Run(ctx, s.cfg.CommandTimeout, globals, environment, "pg_dumpall", globalArguments...)
	closeErr := globals.Close()
	if runErr != nil {
		return fmt.Errorf("PostgreSQL globals backup: %w", runErr)
	}
	if closeErr != nil {
		return closeErr
	}
	return s.postgresInventory(ctx, s.cfg.PostgresDatabase, filepath.Join(directory, "inventory.txt"))
}

func (s *Service) postgresInventory(ctx context.Context, database, destination string) error {
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	arguments := []string{
		"--host", s.cfg.PostgresHost, "--port", strconv.Itoa(s.cfg.PostgresPort), "--username", s.cfg.PostgresUser,
		"--dbname", database, "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--tuples-only", "--no-align",
		"--command", postgresInventorySQL,
	}
	runErr := s.runner.Run(ctx, s.cfg.CommandTimeout, output, []string{"PGPASSWORD=" + s.cfg.PostgresPassword}, "psql", arguments...)
	closeErr := output.Close()
	if runErr != nil {
		return runErr
	}
	return closeErr
}

func (s *Service) backupClickHouse(ctx context.Context, archiveName, archivePath, inventoryPath, work string) error {
	if _, err := os.Stat(archivePath); err == nil {
		return fmt.Errorf("ClickHouse backup archive %s already exists", archiveName)
	} else if !os.IsNotExist(err) {
		return err
	}
	configPath, err := s.writeClickHouseConfig(work)
	if err != nil {
		return err
	}
	if err := s.clickHouseQuery(ctx, configPath, clickHouseInventorySQL(s.cfg.ClickHouseDatabase), inventoryPath); err != nil {
		return fmt.Errorf("ClickHouse inventory: %w", err)
	}
	query := fmt.Sprintf("BACKUP DATABASE %s TO Disk('%s', '%s')", quoteIdentifier(s.cfg.ClickHouseDatabase), s.cfg.ClickHouseBackupDisk, archiveName)
	if err := s.clickHouseQuery(ctx, configPath, query, ""); err != nil {
		return fmt.Errorf("ClickHouse backup: %w", err)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		return fmt.Errorf("ClickHouse did not create backup archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("ClickHouse backup archive is empty or not a regular file")
	}
	return nil
}

func (s *Service) writeClickHouseConfig(directory string) (string, error) {
	escape := func(value string) string {
		var output bytes.Buffer
		_ = xml.EscapeText(&output, []byte(value))
		return output.String()
	}
	body := fmt.Sprintf("<config><host>%s</host><port>%d</port><user>%s</user><password>%s</password></config>\n",
		escape(s.cfg.ClickHouseHost), s.cfg.ClickHousePort, escape(s.cfg.ClickHouseUser), escape(s.cfg.ClickHousePassword))
	filename := filepath.Join(directory, "clickhouse-client.xml")
	if err := os.WriteFile(filename, []byte(body), 0o600); err != nil {
		return "", err
	}
	return filename, nil
}

func (s *Service) clickHouseQuery(ctx context.Context, configPath, query, outputPath string) error {
	var output io.Writer = io.Discard
	var file *os.File
	var err error
	if outputPath != "" {
		file, err = os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		output = file
	}
	runErr := s.runner.Run(ctx, s.cfg.CommandTimeout, output, nil, "clickhouse-client", "--config-file", configPath, "--query", query)
	if file != nil {
		closeErr := file.Close()
		if runErr == nil {
			runErr = closeErr
		}
	}
	return runErr
}

func clickHouseInventorySQL(database string) string {
	return fmt.Sprintf("SELECT name, engine FROM system.tables WHERE database = '%s' ORDER BY name FORMAT TabSeparated", database)
}

func quoteIdentifier(value string) string {
	return "`" + value + "`"
}

func (s *Service) Restore(ctx context.Context, requestedID string, drill bool) (result RestoreResult, retErr error) {
	if err := os.MkdirAll(s.cfg.WorkDir, 0o750); err != nil {
		return RestoreResult{}, err
	}
	lock, err := acquireLock(filepath.Join(s.cfg.WorkDir, ".kcsp-dr.lock"))
	if err != nil {
		return RestoreResult{}, err
	}
	defer releaseLock(lock)
	if err := s.stores.prepare(ctx); err != nil {
		return RestoreResult{}, err
	}
	backupID, err := s.ResolveBackupID(ctx, requestedID)
	if err != nil {
		return RestoreResult{}, err
	}
	prefix := "snapshots/" + backupID
	manifestBody, err := s.stores.getBytes(ctx, prefix+"/manifest.json", 16*1024*1024)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("download manifest: %w", err)
	}
	signature, err := s.stores.getBytes(ctx, prefix+"/manifest.hmac", 1024)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("download manifest signature: %w", err)
	}
	if !verifySignedJSON(manifestBody, string(signature), s.cfg.ManifestHMACKey) {
		return RestoreResult{}, errors.New("backup manifest HMAC verification failed")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBody, &manifest); err != nil {
		return RestoreResult{}, err
	}
	if err := manifest.Validate(backupID); err != nil {
		return RestoreResult{}, err
	}

	started := s.now().UTC()
	suffix := strings.SplitN(backupID, "-", 2)[1][:10]
	postgresDB := s.cfg.RestorePostgresDB
	clickHouseDB := s.cfg.RestoreClickHouseDB
	minioBucket := s.cfg.RestoreMinIOBucket
	if drill || postgresDB == "" {
		postgresDB = "kcsp_dr_pg_" + suffix
	}
	if drill || clickHouseDB == "" {
		clickHouseDB = "kcsp_dr_ch_" + suffix
	}
	if drill || minioBucket == "" {
		minioBucket = "kcsp-dr-" + suffix
	}
	for name, value := range map[string]string{
		"PostgreSQL restore database": postgresDB,
		"ClickHouse restore database": clickHouseDB,
	} {
		if !identifierPattern.MatchString(value) {
			return RestoreResult{}, fmt.Errorf("%s is unsafe", name)
		}
	}
	if !bucketPattern.MatchString(minioBucket) {
		return RestoreResult{}, errors.New("MinIO restore bucket is unsafe")
	}
	mode := "restore"
	if drill {
		mode = "restore-drill"
	}
	work := filepath.Join(s.cfg.WorkDir, mode+"-"+backupID)
	if err := os.Mkdir(work, 0o750); err != nil {
		return RestoreResult{}, err
	}
	configDestination := filepath.Join(work, "restored-config")
	clickHouseRestoreArchive := filepath.Join(s.cfg.ClickHouseDir, backupID+"-restore.zip")
	createdPostgres := false
	createdClickHouse := false
	createdBucket := false
	success := false
	report := DrillReport{
		SchemaVersion: manifestSchema, BackupID: backupID, Mode: mode, Status: "FAILED", StartedAt: started,
		RPOTargetSeconds: s.cfg.RPOTarget.Seconds(), RTOTargetSeconds: s.cfg.RTOTarget.Seconds(),
		PostgresDatabase: postgresDB, ClickHouseDatabase: clickHouseDB, MinIOBucket: minioBucket,
	}
	defer func() {
		cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancelCleanup()
		if drill || !success {
			var cleanupErrors []error
			if createdPostgres {
				if err := s.dropPostgres(cleanupContext, postgresDB); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("drop drill PostgreSQL database: %w", err))
				}
			}
			if createdClickHouse {
				if err := s.dropClickHouse(cleanupContext, clickHouseDB, work); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("drop drill ClickHouse database: %w", err))
				}
			}
			if createdBucket {
				if err := s.stores.removeSourceBucket(cleanupContext, minioBucket); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("drop drill MinIO bucket: %w", err))
				}
			}
			if err := os.RemoveAll(work); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove drill work directory: %w", err))
			}
			if len(cleanupErrors) > 0 {
				cleanupErr := errors.Join(cleanupErrors...)
				if retErr == nil {
					retErr = cleanupErr
				} else {
					retErr = errors.Join(retErr, cleanupErr)
				}
			}
		}
		if err := os.Remove(clickHouseRestoreArchive); err != nil && !os.IsNotExist(err) && retErr == nil {
			retErr = fmt.Errorf("remove ClickHouse restore archive: %w", err)
		}
		completed := s.now().UTC()
		report.CompletedAt = completed
		report.DurationSeconds = completed.Sub(started).Seconds()
		report.BackupAgeSeconds = started.Sub(manifest.CompletedAt).Seconds()
		report.RPOMet = report.BackupAgeSeconds <= s.cfg.RPOTarget.Seconds()
		report.RTOMet = report.DurationSeconds <= s.cfg.RTOTarget.Seconds()
		if retErr != nil {
			report.Error = retErr.Error()
		} else if !report.RPOMet || !report.RTOMet {
			report.Status = "TARGET_MISSED"
			retErr = errors.New("restore succeeded but declared RPO or RTO was missed")
		} else {
			report.Status = "SUCCEEDED"
		}
		if uploadErr := s.uploadReport(ctx, report); uploadErr != nil && retErr == nil {
			retErr = fmt.Errorf("upload restore report: %w", uploadErr)
		}
	}()

	files := make(map[string]string, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		local := filepath.Join(work, filepath.FromSlash(artifact.Path))
		if err := s.stores.getFile(ctx, prefix+"/"+artifact.Path, local, artifact); err != nil {
			return RestoreResult{}, err
		}
		files[artifact.Path] = local
		report.ArtifactsVerified++
	}
	for _, required := range []string{
		"postgres/kcsp.dump",
		"postgres/inventory.txt",
		"clickhouse/backup.zip",
		"clickhouse/inventory.txt",
		"config/kcsp-config.tar.gz",
		"minio/inventory.jsonl",
	} {
		if files[required] == "" {
			return RestoreResult{}, fmt.Errorf("manifest is missing required artifact %s", required)
		}
	}
	if err := extractConfiguration(files["config/kcsp-config.tar.gz"], configDestination); err != nil {
		return RestoreResult{}, fmt.Errorf("restore configuration: %w", err)
	}
	if err := s.restorePostgres(ctx, files["postgres/kcsp.dump"], files["postgres/inventory.txt"], postgresDB, work); err != nil {
		return RestoreResult{}, err
	}
	createdPostgres = true
	if err := copyFile(files["clickhouse/backup.zip"], clickHouseRestoreArchive); err != nil {
		return RestoreResult{}, err
	}
	if err := s.restoreClickHouse(ctx, backupID+"-restore.zip", files["clickhouse/inventory.txt"], clickHouseDB, work); err != nil {
		return RestoreResult{}, err
	}
	createdClickHouse = true
	objects, _, err := s.stores.restoreObjects(ctx, prefix, files["minio/inventory.jsonl"], minioBucket)
	if err != nil {
		return RestoreResult{}, err
	}
	createdBucket = true
	report.ObjectsRestored = objects
	evidenceVerified, err := s.verifyEvidence(ctx, postgresDB, minioBucket, work)
	if err != nil {
		return RestoreResult{}, err
	}
	report.EvidenceHashesValid = evidenceVerified
	success = true
	result = RestoreResult{
		BackupID: backupID, Mode: mode, PostgresDatabase: postgresDB, ClickHouseDatabase: clickHouseDB,
		MinIOBucket: minioBucket, ConfigDirectory: configDestination, ObjectsRestored: objects,
		EvidenceVerified: evidenceVerified, RPOMet: true, RTOMet: true,
	}
	return result, nil
}

func (s *Service) restorePostgres(ctx context.Context, dumpPath, expectedInventory, database, work string) error {
	exists, err := s.postgresDatabaseExists(ctx, database)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("PostgreSQL restore target %s already exists", database)
	}
	common := []string{"--host", s.cfg.PostgresHost, "--port", strconv.Itoa(s.cfg.PostgresPort), "--username", s.cfg.PostgresUser}
	environment := []string{"PGPASSWORD=" + s.cfg.PostgresPassword}
	if err := s.runner.Run(ctx, s.cfg.CommandTimeout, io.Discard, environment, "createdb", append(common, "--template", "template0", database)...); err != nil {
		return fmt.Errorf("create PostgreSQL restore database: %w", err)
	}
	restoreArguments := append(append([]string{}, common...), "--exit-on-error", "--no-owner", "--no-privileges", "--dbname", database, dumpPath)
	if err := s.runner.Run(ctx, s.cfg.CommandTimeout, io.Discard, environment, "pg_restore", restoreArguments...); err != nil {
		_ = s.dropPostgres(ctx, database)
		return fmt.Errorf("restore PostgreSQL: %w", err)
	}
	actualInventory := filepath.Join(work, "postgres-restored-inventory.txt")
	if err := s.postgresInventory(ctx, database, actualInventory); err != nil {
		_ = s.dropPostgres(ctx, database)
		return err
	}
	if err := compareFiles(expectedInventory, actualInventory); err != nil {
		_ = s.dropPostgres(ctx, database)
		return fmt.Errorf("PostgreSQL restored inventory: %w", err)
	}
	return nil
}

func (s *Service) postgresDatabaseExists(ctx context.Context, database string) (bool, error) {
	var output bytes.Buffer
	query := fmt.Sprintf("SELECT 1 FROM pg_database WHERE datname = '%s'", database)
	arguments := []string{
		"--host", s.cfg.PostgresHost, "--port", strconv.Itoa(s.cfg.PostgresPort), "--username", s.cfg.PostgresUser,
		"--dbname", "postgres", "--no-psqlrc", "--tuples-only", "--no-align", "--command", query,
	}
	if err := s.runner.Run(ctx, s.cfg.CommandTimeout, &output, []string{"PGPASSWORD=" + s.cfg.PostgresPassword}, "psql", arguments...); err != nil {
		return false, err
	}
	return strings.TrimSpace(output.String()) == "1", nil
}

func (s *Service) dropPostgres(ctx context.Context, database string) error {
	arguments := []string{
		"--host", s.cfg.PostgresHost, "--port", strconv.Itoa(s.cfg.PostgresPort), "--username", s.cfg.PostgresUser,
		"--if-exists", "--force", database,
	}
	return s.runner.Run(ctx, s.cfg.CommandTimeout, io.Discard, []string{"PGPASSWORD=" + s.cfg.PostgresPassword}, "dropdb", arguments...)
}

func (s *Service) restoreClickHouse(ctx context.Context, archiveName, expectedInventory, database, work string) error {
	configPath, err := s.writeClickHouseConfig(work)
	if err != nil {
		return err
	}
	var exists bytes.Buffer
	query := fmt.Sprintf("SELECT count() FROM system.databases WHERE name = '%s'", database)
	if err := s.clickHouseQueryTo(ctx, configPath, query, &exists); err != nil {
		return err
	}
	if strings.TrimSpace(exists.String()) != "0" {
		return fmt.Errorf("ClickHouse restore target %s already exists", database)
	}
	restoreQuery := fmt.Sprintf("RESTORE DATABASE %s AS %s FROM Disk('%s', '%s')",
		quoteIdentifier(s.cfg.ClickHouseDatabase), quoteIdentifier(database), s.cfg.ClickHouseBackupDisk, archiveName)
	if err := s.clickHouseQuery(ctx, configPath, restoreQuery, ""); err != nil {
		return fmt.Errorf("restore ClickHouse: %w", err)
	}
	actualInventory := filepath.Join(work, "clickhouse-restored-inventory.txt")
	if err := s.clickHouseQuery(ctx, configPath, clickHouseInventorySQL(database), actualInventory); err != nil {
		_ = s.dropClickHouse(ctx, database, work)
		return err
	}
	if err := compareFiles(expectedInventory, actualInventory); err != nil {
		_ = s.dropClickHouse(ctx, database, work)
		return fmt.Errorf("ClickHouse restored inventory: %w", err)
	}
	return nil
}

func (s *Service) clickHouseQueryTo(ctx context.Context, configPath, query string, output io.Writer) error {
	return s.runner.Run(ctx, s.cfg.CommandTimeout, output, nil, "clickhouse-client", "--config-file", configPath, "--query", query)
}

func (s *Service) dropClickHouse(ctx context.Context, database, work string) error {
	configPath, err := s.writeClickHouseConfig(work)
	if err != nil {
		return err
	}
	return s.clickHouseQuery(ctx, configPath, "DROP DATABASE IF EXISTS "+quoteIdentifier(database)+" SYNC", "")
}

func (s *Service) verifyEvidence(ctx context.Context, database, bucket, work string) (int64, error) {
	outputPath := filepath.Join(work, "evidence-inventory.csv")
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	query := fmt.Sprintf(`COPY (
SELECT encode(convert_to(object_key, 'UTF8'), 'base64'), sha256
FROM evidence_items
WHERE bucket = '%s' AND object_key <> '' AND sha256 <> '' AND status NOT IN ('PENDING','FAILED')
ORDER BY object_key
) TO STDOUT WITH (FORMAT csv)`, s.cfg.SourceBucket)
	arguments := []string{
		"--host", s.cfg.PostgresHost, "--port", strconv.Itoa(s.cfg.PostgresPort), "--username", s.cfg.PostgresUser,
		"--dbname", database, "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--command", query,
	}
	runErr := s.runner.Run(ctx, s.cfg.CommandTimeout, output, []string{"PGPASSWORD=" + s.cfg.PostgresPassword}, "psql", arguments...)
	closeErr := output.Close()
	if runErr != nil {
		return 0, runErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	file, err := os.Open(outputPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	var verified int64
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return verified, err
		}
		if len(record) != 2 {
			return verified, errors.New("invalid evidence inventory row")
		}
		keyBytes, err := base64.StdEncoding.DecodeString(record[0])
		if err != nil {
			return verified, err
		}
		if err := s.stores.verifySourceObject(ctx, bucket, string(keyBytes), record[1]); err != nil {
			return verified, err
		}
		verified++
	}
	return verified, nil
}

func (s *Service) uploadReport(ctx context.Context, report DrillReport) error {
	body, signature, err := marshalSignedJSON(report, s.cfg.ManifestHMACKey)
	if err != nil {
		return err
	}
	stamp := report.CompletedAt.UTC().Format("20060102T150405Z")
	prefix := "reports/" + report.BackupID + "/" + stamp
	if err := s.stores.putBytes(ctx, prefix+".json", "application/json", body); err != nil {
		return err
	}
	return s.stores.putBytes(ctx, prefix+".hmac", "text/plain", []byte(signature+"\n"))
}

func (s *Service) ResolveBackupID(ctx context.Context, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested != "" && requested != "latest" {
		if !backupIDPattern.MatchString(requested) {
			return "", errors.New("backup id is invalid")
		}
		complete, err := s.stores.objectExists(ctx, "snapshots/"+requested+"/_SUCCESS")
		if err != nil {
			return "", err
		}
		if !complete {
			return "", errors.New("backup is incomplete or does not exist")
		}
		return requested, nil
	}
	ids, err := s.stores.snapshotIDs(ctx)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", errors.New("no complete backups found")
	}
	return ids[0], nil
}

func (s *Service) List(ctx context.Context) ([]string, error) {
	if err := s.stores.prepare(ctx); err != nil {
		return nil, err
	}
	return s.stores.snapshotIDs(ctx)
}

func (s *Service) Prune(ctx context.Context) ([]string, error) {
	if err := os.MkdirAll(s.cfg.WorkDir, 0o750); err != nil {
		return nil, err
	}
	lock, err := acquireLock(filepath.Join(s.cfg.WorkDir, ".kcsp-dr.lock"))
	if err != nil {
		return nil, err
	}
	defer releaseLock(lock)
	if err := s.stores.prepare(ctx); err != nil {
		return nil, err
	}
	ids, err := s.stores.snapshotIDs(ctx)
	if err != nil {
		return nil, err
	}
	cutoff := s.now().UTC().AddDate(0, 0, -s.cfg.RetentionDays).Unix()
	var removed []string
	for index, id := range ids {
		if index < s.cfg.MinimumBackups || backupEpoch(id) >= cutoff {
			continue
		}
		if err := s.stores.removePrefix(ctx, "snapshots/"+id+"/"); err != nil {
			return removed, err
		}
		removed = append(removed, id)
	}
	return removed, nil
}

func compareFiles(expected, actual string) error {
	left, err := os.ReadFile(expected)
	if err != nil {
		return err
	}
	right, err := os.ReadFile(actual)
	if err != nil {
		return err
	}
	normalize := func(value []byte) string {
		return strings.TrimSpace(strings.ReplaceAll(string(value), "\r\n", "\n"))
	}
	if normalize(left) != normalize(right) {
		return errors.New("restored schema inventory differs from the backup")
	}
	return nil
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
