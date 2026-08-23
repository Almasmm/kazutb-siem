# KCSP backup and restore runbook

## Safety model

KCSP backs up the PostgreSQL control plane, the ClickHouse telemetry database,
the MinIO evidence bucket, and versioned repository configuration. A snapshot is
eligible for restore only when all artifacts are uploaded, its manifest has a
valid HMAC-SHA-256 signature, every artifact has a SHA-256 digest, and the
`_SUCCESS` marker exists.

The backup target must be in a different failure domain from primary MinIO.
Production must use TLS, storage encryption, a write-only backup credential for
the scheduled job, a separately controlled deletion credential for retention,
and an HMAC key stored outside both object stores. The Compose `backup-store` is
only a local restore-drill target; it is not an off-site production backup.

The restore command never overwrites an existing PostgreSQL database,
ClickHouse database, or MinIO bucket. A restore drill uses generated temporary
names and deletes only those generated resources after its signed report has
been uploaded.

## Local credentials

Set development-only values without committing them:

```powershell
$env:KCSP_POSTGRES_PASSWORD = '<local PostgreSQL secret>'
$env:KCSP_CLICKHOUSE_PASSWORD = '<local ClickHouse secret>'
$env:KCSP_MINIO_ROOT_USER = '<local MinIO access key>'
$env:KCSP_MINIO_ROOT_PASSWORD = '<local MinIO secret key>'
$env:KCSP_GRAFANA_ADMIN_PASSWORD = '<local Grafana secret>'
$env:KCSP_DR_TARGET_ACCESS_KEY = '<different backup access key>'
$env:KCSP_DR_TARGET_SECRET_KEY = '<different backup secret key>'
$env:KCSP_DR_TARGET_ALLOW_INSECURE = 'true'
$env:KCSP_DR_MANIFEST_HMAC_KEY = '<at least 32 random bytes>'
```

Never reuse the local values in production.

## Create and list snapshots

Start the independent local target and create a snapshot:

```powershell
docker compose --profile dr up -d backup-store
docker compose --profile dr run --rm dr backup
docker compose --profile dr run --rm dr list
```

The command exits non-zero on any failed database command, missing source
bucket, insecure target without explicit development opt-in, artifact upload
failure, or integrity error. An interrupted upload has no `_SUCCESS` marker and
cannot be selected as `latest`.

For an external S3-compatible production target, set
`KCSP_DR_TARGET_ENDPOINT=https://...` and leave
`KCSP_DR_TARGET_ALLOW_INSECURE=false`.

## Mandatory restore drill

Restore the newest complete snapshot into isolated temporary names:

```powershell
docker compose --profile dr run --rm dr restore-drill latest
```

The drill performs all of the following:

1. Downloads and authenticates the signed manifest.
2. Downloads every database/configuration artifact and verifies SHA-256.
3. Restores PostgreSQL into a newly created database and compares its schema,
   policy, extension, and relation inventory with the captured inventory.
4. Restores the native ClickHouse archive into a newly created database and
   compares table/engine inventory.
5. Restores every MinIO object into a newly created bucket and verifies the
   SHA-256 recorded while the source object was backed up.
6. Re-reads each persisted evidence object referenced by PostgreSQL and checks
   its application-level SHA-256.
7. Safely extracts rules, API contracts, migrations, Compose configuration,
   and observability configuration into a temporary directory.
8. Uploads an HMAC-signed drill report and fails if measured backup age exceeds
   `KCSP_DR_RPO_SECONDS` or restore duration exceeds `KCSP_DR_RTO_SECONDS`.
9. Removes only the temporary drill databases, bucket, archive, and files.

A backup is not accepted operationally until this command succeeds against the
target from which disaster recovery would actually occur.

## Retention and scheduling

Run one scheduler replica:

```powershell
docker compose --profile dr-scheduled up -d backup-store dr-scheduler
```

The scheduler creates a backup every `KCSP_DR_SCHEDULE_SECONDS` and then prunes
complete snapshots older than `KCSP_DR_RETENTION_DAYS` while always preserving
at least `KCSP_DR_MINIMUM_BACKUPS`. Configuration fails when the schedule
interval is greater than the declared RPO. Concurrent backup/restore/prune
processes are rejected by an advisory file lock on the shared DR work volume.

Manual retention is available with:

```powershell
docker compose --profile dr run --rm dr prune
```

## Non-destructive retained restore

`restore` keeps recovered resources for a controlled cutover. Set unique target
names or allow generated names:

```powershell
$env:KCSP_DR_RESTORE_POSTGRES_DATABASE = 'kcsp_recovered'
$env:KCSP_DR_RESTORE_CLICKHOUSE_DATABASE = 'kcsp_recovered'
$env:KCSP_DR_RESTORE_MINIO_BUCKET = 'kcsp-recovered'
docker compose --profile dr run --rm dr restore latest
```

The output reports the recovered names and extracted configuration directory.
Application cutover remains an explicit operator action: stop writers, verify
the signed report, reconcile Kafka offsets against the backup timestamp, switch
service endpoints, run acceptance checks, and only then reopen ingestion.

## Current recovery boundary

This implementation provides scheduled full logical PostgreSQL backups and
verified restore. PostgreSQL continuous WAL archiving/PITR and clustered
failover are separate production gates and must not be inferred from a
successful full-backup drill. Kafka is a transport/replay plane, not the
authoritative backup for PostgreSQL, ClickHouse, or evidence.
