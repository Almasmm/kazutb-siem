package dr

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
	bucketPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	backupIDPattern   = regexp.MustCompile(`^[0-9]{10,12}-[a-f0-9]{24}$`)
)

type Endpoint struct {
	URL    string
	Host   string
	Secure bool
}

type Config struct {
	PostgresHost     string
	PostgresPort     int
	PostgresUser     string
	PostgresPassword string
	PostgresDatabase string

	ClickHouseHost       string
	ClickHousePort       int
	ClickHouseUser       string
	ClickHousePassword   string
	ClickHouseDatabase   string
	ClickHouseBackupDisk string

	SourceEndpoint  Endpoint
	SourceAccessKey string
	SourceSecretKey string
	SourceRegion    string
	SourceBucket    string

	TargetEndpoint  Endpoint
	TargetAccessKey string
	TargetSecretKey string
	TargetRegion    string
	TargetBucket    string

	ManifestHMACKey []byte
	WorkDir         string
	ClickHouseDir   string
	ConfigRoot      string
	Version         string

	RPOTarget      time.Duration
	RTOTarget      time.Duration
	ScheduleEvery  time.Duration
	CommandTimeout time.Duration
	RetentionDays  int
	MinimumBackups int

	RestorePostgresDB   string
	RestoreClickHouseDB string
	RestoreMinIOBucket  string
	AllowSharedTarget   bool
}

func LoadConfig() (Config, error) {
	var cfg Config
	var err error

	cfg.PostgresHost = envOr("KCSP_DR_POSTGRES_HOST", "postgres")
	cfg.PostgresPort, err = envInt("KCSP_DR_POSTGRES_PORT", 5432, 1, 65535)
	if err != nil {
		return Config{}, err
	}
	cfg.PostgresUser = envOr("KCSP_DR_POSTGRES_USER", "kcsp")
	cfg.PostgresPassword = strings.TrimSpace(os.Getenv("KCSP_DR_POSTGRES_PASSWORD"))
	cfg.PostgresDatabase = envOr("KCSP_DR_POSTGRES_DATABASE", "kcsp")

	cfg.ClickHouseHost = envOr("KCSP_DR_CLICKHOUSE_HOST", "clickhouse")
	cfg.ClickHousePort, err = envInt("KCSP_DR_CLICKHOUSE_PORT", 9000, 1, 65535)
	if err != nil {
		return Config{}, err
	}
	cfg.ClickHouseUser = envOr("KCSP_DR_CLICKHOUSE_USER", "kcsp")
	cfg.ClickHousePassword = strings.TrimSpace(os.Getenv("KCSP_DR_CLICKHOUSE_PASSWORD"))
	cfg.ClickHouseDatabase = envOr("KCSP_DR_CLICKHOUSE_DATABASE", "kcsp")
	cfg.ClickHouseBackupDisk = envOr("KCSP_DR_CLICKHOUSE_BACKUP_DISK", "backups")

	cfg.SourceEndpoint, err = parseEndpoint(
		envOr("KCSP_DR_SOURCE_S3_ENDPOINT", "http://minio:9000"),
		envBool("KCSP_DR_SOURCE_ALLOW_INSECURE", false),
	)
	if err != nil {
		return Config{}, fmt.Errorf("source object store: %w", err)
	}
	cfg.SourceAccessKey = strings.TrimSpace(os.Getenv("KCSP_DR_SOURCE_S3_ACCESS_KEY"))
	cfg.SourceSecretKey = strings.TrimSpace(os.Getenv("KCSP_DR_SOURCE_S3_SECRET_KEY"))
	cfg.SourceRegion = envOr("KCSP_DR_SOURCE_S3_REGION", "us-east-1")
	cfg.SourceBucket = envOr("KCSP_DR_SOURCE_S3_BUCKET", "kcsp-evidence")

	cfg.TargetEndpoint, err = parseEndpoint(
		strings.TrimSpace(os.Getenv("KCSP_DR_TARGET_S3_ENDPOINT")),
		envBool("KCSP_DR_TARGET_ALLOW_INSECURE", false),
	)
	if err != nil {
		return Config{}, fmt.Errorf("backup object store: %w", err)
	}
	cfg.TargetAccessKey = strings.TrimSpace(os.Getenv("KCSP_DR_TARGET_S3_ACCESS_KEY"))
	cfg.TargetSecretKey = strings.TrimSpace(os.Getenv("KCSP_DR_TARGET_S3_SECRET_KEY"))
	cfg.TargetRegion = envOr("KCSP_DR_TARGET_S3_REGION", "us-east-1")
	cfg.TargetBucket = envOr("KCSP_DR_TARGET_S3_BUCKET", "kcsp-dr")

	cfg.ManifestHMACKey = []byte(os.Getenv("KCSP_DR_MANIFEST_HMAC_KEY"))
	cfg.WorkDir = envOr("KCSP_DR_WORK_DIR", "/var/lib/kcsp/dr")
	cfg.ClickHouseDir = envOr("KCSP_DR_CLICKHOUSE_BACKUP_DIR", "/var/lib/kcsp/clickhouse-backups")
	cfg.ConfigRoot = envOr("KCSP_DR_CONFIG_ROOT", "/workspace")
	cfg.Version = envOr("KCSP_VERSION", "development")
	cfg.AllowSharedTarget = envBool("KCSP_DR_ALLOW_SHARED_FAILURE_DOMAIN", false)

	cfg.RPOTarget, err = envSeconds("KCSP_DR_RPO_SECONDS", 86400)
	if err != nil {
		return Config{}, err
	}
	cfg.RTOTarget, err = envSeconds("KCSP_DR_RTO_SECONDS", 3600)
	if err != nil {
		return Config{}, err
	}
	cfg.ScheduleEvery, err = envSeconds("KCSP_DR_SCHEDULE_SECONDS", 21600)
	if err != nil {
		return Config{}, err
	}
	cfg.CommandTimeout, err = envSeconds("KCSP_DR_COMMAND_TIMEOUT_SECONDS", 86400)
	if err != nil {
		return Config{}, err
	}
	cfg.RetentionDays, err = envInt("KCSP_DR_RETENTION_DAYS", 30, 1, 3650)
	if err != nil {
		return Config{}, err
	}
	cfg.MinimumBackups, err = envInt("KCSP_DR_MINIMUM_BACKUPS", 7, 1, 1000)
	if err != nil {
		return Config{}, err
	}

	cfg.RestorePostgresDB = strings.TrimSpace(os.Getenv("KCSP_DR_RESTORE_POSTGRES_DATABASE"))
	cfg.RestoreClickHouseDB = strings.TrimSpace(os.Getenv("KCSP_DR_RESTORE_CLICKHOUSE_DATABASE"))
	cfg.RestoreMinIOBucket = strings.TrimSpace(os.Getenv("KCSP_DR_RESTORE_MINIO_BUCKET"))

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	required := map[string]string{
		"KCSP_DR_POSTGRES_PASSWORD":    c.PostgresPassword,
		"KCSP_DR_CLICKHOUSE_PASSWORD":  c.ClickHousePassword,
		"KCSP_DR_SOURCE_S3_ACCESS_KEY": c.SourceAccessKey,
		"KCSP_DR_SOURCE_S3_SECRET_KEY": c.SourceSecretKey,
		"KCSP_DR_TARGET_S3_ACCESS_KEY": c.TargetAccessKey,
		"KCSP_DR_TARGET_S3_SECRET_KEY": c.TargetSecretKey,
	}
	for name, value := range required {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if len(c.ManifestHMACKey) < 32 {
		return errors.New("KCSP_DR_MANIFEST_HMAC_KEY must contain at least 32 bytes")
	}
	for name, value := range map[string]string{
		"PostgreSQL database":    c.PostgresDatabase,
		"PostgreSQL user":        c.PostgresUser,
		"ClickHouse database":    c.ClickHouseDatabase,
		"ClickHouse user":        c.ClickHouseUser,
		"ClickHouse backup disk": c.ClickHouseBackupDisk,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s is not a safe identifier", name)
		}
	}
	for name, value := range map[string]string{
		"source bucket": c.SourceBucket,
		"target bucket": c.TargetBucket,
	} {
		if !bucketPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	for name, value := range map[string]string{
		"restore PostgreSQL database": c.RestorePostgresDB,
		"restore ClickHouse database": c.RestoreClickHouseDB,
	} {
		if value != "" && !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s is not a safe identifier", name)
		}
	}
	if c.RestoreMinIOBucket != "" && !bucketPattern.MatchString(c.RestoreMinIOBucket) {
		return errors.New("restore MinIO bucket is invalid")
	}
	if c.SourceEndpoint.Host == c.TargetEndpoint.Host && !c.AllowSharedTarget {
		return errors.New("backup target must use a separate failure domain; set KCSP_DR_ALLOW_SHARED_FAILURE_DOMAIN=true only for a controlled test")
	}
	if c.ScheduleEvery > c.RPOTarget {
		return errors.New("backup schedule exceeds the declared RPO")
	}
	for name, value := range map[string]string{
		"work directory":              c.WorkDir,
		"ClickHouse backup directory": c.ClickHouseDir,
		"configuration root":          c.ConfigRoot,
	} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("%s must be absolute", name)
		}
	}
	return nil
}

func parseEndpoint(raw string, allowInsecure bool) (Endpoint, error) {
	if raw == "" {
		return Endpoint{}, errors.New("endpoint is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return Endpoint{}, errors.New("endpoint must be an absolute http(s) URL")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return Endpoint{}, errors.New("endpoint must not include a path")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return Endpoint{}, errors.New("endpoint must not include credentials, query, or fragment")
	}
	secure := parsed.Scheme == "https"
	if parsed.Scheme != "http" && !secure {
		return Endpoint{}, errors.New("endpoint scheme must be http or https")
	}
	if !secure && !allowInsecure {
		return Endpoint{}, errors.New("plaintext endpoint is denied; explicitly allow it only on an isolated development network")
	}
	host := strings.ToLower(parsed.Host)
	return Endpoint{URL: parsed.Scheme + "://" + host, Host: host, Secure: secure}, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	return err == nil && parsed
}

func envInt(name string, fallback, minimum, maximum int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return parsed, nil
}

func envSeconds(name string, fallback int) (time.Duration, error) {
	value, err := envInt(name, fallback, 1, 31*24*60*60)
	if err != nil {
		return 0, err
	}
	return time.Duration(value) * time.Second, nil
}
