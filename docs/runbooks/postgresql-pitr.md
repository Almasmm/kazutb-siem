# PostgreSQL point-in-time recovery

## Recovery contract

KCSP uses PostgreSQL 17 with pgBackRest 2.58. The PITR repository is:

- stored in an S3-compatible failure domain separate from primary PostgreSQL;
- encrypted client-side with AES-256-CBC before upload;
- protected by credentials and a cipher passphrase that are not written to the
  generated pgBackRest configuration;
- populated by synchronous `archive-push` from PostgreSQL;
- bounded by `KCSP_PITR_ARCHIVE_TIMEOUT_SECONDS`, which is rejected when it is
  greater than the declared `KCSP_PITR_RPO_SECONDS`;
- seeded by full backups and maintained with differential backups and explicit
  retention counts.

The Compose `pitr-s3-proxy` provides TLS only for an isolated local proof against
the development backup-store. It uses a short-lived self-signed certificate.
Production must connect pgBackRest directly to a verified TLS S3 endpoint and
must set `KCSP_PITR_TLS_VERIFY=y`.

## Local proof credentials

Set transient development values:

```powershell
$env:KCSP_POSTGRES_PASSWORD = '<local PostgreSQL secret>'
$env:KCSP_CLICKHOUSE_PASSWORD = '<local ClickHouse secret>'
$env:KCSP_MINIO_ROOT_USER = '<local MinIO access key>'
$env:KCSP_MINIO_ROOT_PASSWORD = '<local MinIO secret key>'
$env:KCSP_GRAFANA_ADMIN_PASSWORD = '<local Grafana secret>'
$env:KCSP_DR_TARGET_ACCESS_KEY = '<backup-store access key>'
$env:KCSP_DR_TARGET_SECRET_KEY = '<backup-store secret key>'
$env:KCSP_PITR_ENABLED = 'true'
$env:KCSP_PITR_SCHEDULER_ENABLED = 'false'
$env:KCSP_PITR_S3_ENDPOINT = 'pitr-s3-proxy'
$env:KCSP_PITR_S3_PORT = '9443'
$env:KCSP_PITR_TLS_VERIFY = 'n'
$env:KCSP_PITR_S3_ACCESS_KEY = $env:KCSP_DR_TARGET_ACCESS_KEY
$env:KCSP_PITR_S3_SECRET_KEY = $env:KCSP_DR_TARGET_SECRET_KEY
$env:KCSP_PITR_REPO_CIPHER_PASS = '<at least 32 random bytes>'
```

Start the target/proxy and recreate PostgreSQL with WAL archiving enabled:

```powershell
docker compose --profile pitr up -d --wait backup-store pitr-s3-proxy
docker compose --profile pitr up -d --build --wait postgres
docker compose exec -T --user postgres postgres `
  pgbackrest --stanza=kcsp stanza-create
docker compose exec -T --user postgres postgres `
  pgbackrest --stanza=kcsp check
```

## Full backup and named recovery point

Create the disposable proof relation before the full backup:

```powershell
docker compose exec -T postgres psql -U kcsp -d kcsp -v ON_ERROR_STOP=1 -c @'
DROP SCHEMA IF EXISTS kcsp_pitr_probe CASCADE;
CREATE SCHEMA kcsp_pitr_probe;
CREATE TABLE kcsp_pitr_probe.entries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    phase text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
'@

docker compose exec -T --user postgres postgres `
  pgbackrest --stanza=kcsp --type=full backup
```

Insert the row that must survive, create a named WAL restore point, and then
insert the row that must not be present after recovery:

```powershell
$target = 'kcsp_pitr_' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

docker compose exec -T postgres psql -U kcsp -d kcsp -v ON_ERROR_STOP=1 `
  -c "INSERT INTO kcsp_pitr_probe.entries(phase) VALUES ('before_target');"
docker compose exec -T postgres psql -U kcsp -d kcsp -v ON_ERROR_STOP=1 `
  -c "SELECT pg_create_restore_point('$target');"
docker compose exec -T postgres psql -U kcsp -d kcsp -v ON_ERROR_STOP=1 `
  -c "INSERT INTO kcsp_pitr_probe.entries(phase) VALUES ('after_target'); SELECT pg_switch_wal();"
docker compose exec -T --user postgres postgres `
  pgbackrest --stanza=kcsp check
```

## Mandatory isolated restore drill

The drill has no primary PostgreSQL data-volume mount. It restores into a
separate volume, starts PostgreSQL on a private Unix socket, verifies six KCSP
control-plane tables and all schema migrations, proves the row boundary around
the named restore point, records an RTO report and removes the temporary
cluster.

```powershell
$env:KCSP_PITR_TARGET_NAME = $target
docker compose --profile pitr run --rm pitr-drill
```

Expected invariants:

- `before_target_rows` is `1`;
- `after_target_rows` is `0`;
- `core_tables_verified` is `6`;
- `rto_met` is `true`.

Remove only the disposable probe from the live database after the drill:

```powershell
docker compose exec -T postgres psql -U kcsp -d kcsp `
  -c 'DROP SCHEMA kcsp_pitr_probe CASCADE;'
```

## Scheduled operation

Enable `KCSP_PITR_SCHEDULER_ENABLED=true` for exactly one PostgreSQL primary.
The scheduler writes its current state to
`/var/lib/pgbackrest/status/scheduler`, creates an immediate full backup when no
full marker exists, creates differential backups every
`KCSP_PITR_SCHEDULE_SECONDS`, and refreshes the full backup after
`KCSP_PITR_FULL_INTERVAL_SECONDS`.

Repository encryption keys, S3 credentials, and the cipher passphrase must be
escrowed in the university secret-management process. Losing the cipher
passphrase makes the repository intentionally unrecoverable.

PITR is not PostgreSQL HA. Patroni/consensus-based failover, synchronous replica
policy, fencing, split-brain tests, and Kubernetes topology remain separate
production gates.
