#!/bin/sh
set -eu

umask 077

is_true() {
    case "${1:-}" in
        true|TRUE|1|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

required() {
    name="$1"
    eval "value=\${$name:-}"
    if [ -z "$value" ]; then
        echo "$name is required when KCSP_PITR_ENABLED=true" >&2
        exit 1
    fi
    case "$value" in
        *'
'*|*''*) echo "$name must not contain line breaks" >&2; exit 1 ;;
    esac
}

safe_match() {
    name="$1"
    value="$2"
    pattern="$3"
    if ! printf '%s' "$value" | grep -Eq "$pattern"; then
        echo "$name contains an unsafe value" >&2
        exit 1
    fi
}

positive_integer() {
    name="$1"
    value="$2"
    safe_match "$name" "$value" '^[0-9]+$'
    if [ "$value" -le 0 ]; then
        echo "$name must be greater than zero" >&2
        exit 1
    fi
}

if ! is_true "${KCSP_PITR_ENABLED:-false}"; then
    exit 0
fi

for variable in \
    PGBACKREST_REPO1_S3_KEY \
    PGBACKREST_REPO1_S3_KEY_SECRET \
    PGBACKREST_REPO1_CIPHER_PASS \
    KCSP_PITR_S3_ENDPOINT \
    KCSP_PITR_S3_BUCKET; do
    required "$variable"
done

if [ "${#PGBACKREST_REPO1_S3_KEY_SECRET}" -lt 16 ]; then
    echo "PGBACKREST_REPO1_S3_KEY_SECRET must contain at least 16 bytes" >&2
    exit 1
fi
if [ "${#PGBACKREST_REPO1_CIPHER_PASS}" -lt 32 ]; then
    echo "PGBACKREST_REPO1_CIPHER_PASS must contain at least 32 bytes" >&2
    exit 1
fi

stanza="${KCSP_PITR_STANZA:-kcsp}"
endpoint="$KCSP_PITR_S3_ENDPOINT"
port="${KCSP_PITR_S3_PORT:-443}"
bucket="$KCSP_PITR_S3_BUCKET"
region="${KCSP_PITR_S3_REGION:-us-east-1}"
repo_path="${KCSP_PITR_REPO_PATH:-/pgbackrest}"
verify_tls="${KCSP_PITR_TLS_VERIFY:-y}"
retention_full="${KCSP_PITR_RETENTION_FULL:-7}"
retention_diff="${KCSP_PITR_RETENTION_DIFF:-14}"
process_max="${KCSP_PITR_PROCESS_MAX:-2}"
pg_path="${PGDATA:-/var/lib/postgresql/data}"
pg_port="${PGPORT:-5432}"
pg_user="${POSTGRES_USER:-kcsp}"
pg_database="${POSTGRES_DB:-kcsp}"
config="${PGBACKREST_CONFIG:-/etc/pgbackrest/pgbackrest.conf}"
state_path="${KCSP_PITR_STATE_PATH:-/var/lib/pgbackrest}"

safe_match KCSP_PITR_STANZA "$stanza" '^[A-Za-z][A-Za-z0-9_-]{0,62}$'
safe_match KCSP_PITR_S3_ENDPOINT "$endpoint" '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$'
safe_match KCSP_PITR_S3_BUCKET "$bucket" '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
safe_match KCSP_PITR_S3_REGION "$region" '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'
safe_match KCSP_PITR_REPO_PATH "$repo_path" '^/[A-Za-z0-9/_-]+$'
case "$verify_tls" in y|n) ;; *) echo "KCSP_PITR_TLS_VERIFY must be y or n" >&2; exit 1 ;; esac
positive_integer KCSP_PITR_S3_PORT "$port"
positive_integer KCSP_PITR_RETENTION_FULL "$retention_full"
positive_integer KCSP_PITR_RETENTION_DIFF "$retention_diff"
positive_integer KCSP_PITR_PROCESS_MAX "$process_max"
positive_integer PGPORT "$pg_port"
safe_match POSTGRES_USER "$pg_user" '^[A-Za-z_][A-Za-z0-9_]{0,62}$'
safe_match POSTGRES_DB "$pg_database" '^[A-Za-z_][A-Za-z0-9_]{0,62}$'

config_dir="$(dirname "$config")"
mkdir -p "$config_dir" "$state_path/spool" "$state_path/status" /var/log/pgbackrest
temporary="${config}.tmp.$$"
cat >"$temporary" <<EOF
[global]
repo1-type=s3
repo1-path=$repo_path
repo1-s3-bucket=$bucket
repo1-s3-endpoint=$endpoint
repo1-s3-region=$region
repo1-s3-key-type=shared
repo1-s3-uri-style=path
repo1-storage-port=$port
repo1-storage-verify-tls=$verify_tls
repo1-cipher-type=aes-256-cbc
repo1-retention-full=$retention_full
repo1-retention-diff=$retention_diff
repo1-retention-archive-type=diff
process-max=$process_max
start-fast=y
spool-path=$state_path/spool
log-path=/var/log/pgbackrest
log-level-console=info
log-level-file=detail

[$stanza]
pg1-path=$pg_path
pg1-port=$pg_port
pg1-user=$pg_user
pg1-database=$pg_database
EOF
chmod 0600 "$temporary"
mv "$temporary" "$config"

if [ "$(id -u)" -eq 0 ]; then
    chown -R postgres:postgres "$config_dir" "$state_path" /var/log/pgbackrest
fi
