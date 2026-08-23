#!/bin/sh
set -eu

umask 077

target="${KCSP_PITR_TARGET_NAME:-}"
case "$target" in
    ''|*[!A-Za-z0-9_.-]*) echo "KCSP_PITR_TARGET_NAME must be a safe named restore point" >&2; exit 1 ;;
esac

stanza="${KCSP_PITR_STANZA:-kcsp}"
database="${KCSP_PITR_VERIFY_DATABASE:-kcsp}"
rto_seconds="${KCSP_PITR_RTO_SECONDS:-3600}"
root="/var/lib/postgresql/pitr-drill"
run_id="$(date +%s)-$$"
destination="$root/$run_id"
socket_dir="/tmp/kcsp-pitr-$run_id"
state_path="${KCSP_PITR_STATE_PATH:-/var/lib/pgbackrest}"
report_dir="$state_path/pitr-reports"
server_pid=""
started="$(date +%s)"

case "$rto_seconds" in ''|*[!0-9]*) echo "KCSP_PITR_RTO_SECONDS must be a positive integer" >&2; exit 1 ;; esac
if [ "$rto_seconds" -le 0 ]; then
    echo "KCSP_PITR_RTO_SECONDS must be a positive integer" >&2
    exit 1
fi

cleanup() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        pg_ctl -D "$destination" -m immediate stop >/dev/null 2>&1 || true
        wait "$server_pid" 2>/dev/null || true
    fi
    case "$destination" in
        /var/lib/postgresql/pitr-drill/*) rm -rf -- "$destination" ;;
        *) echo "refusing unsafe PITR cleanup path" >&2; exit 1 ;;
    esac
    rm -rf -- "$socket_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$destination" "$socket_dir" "$report_dir"
/usr/local/bin/kcsp-configure-pgbackrest

pgbackrest \
    --stanza="$stanza" \
    --pg1-path="$destination" \
    --type=name \
    --target="$target" \
    --target-action=promote \
    --archive-mode=off \
    restore

postgres \
    -D "$destination" \
    -p 55432 \
    -k "$socket_dir" \
    -c listen_addresses= \
    -c archive_mode=off \
    >"$destination/postgres.log" 2>&1 &
server_pid="$!"

ready=0
for _ in $(seq 1 120); do
    if pg_isready -h "$socket_dir" -p 55432 -d "$database" >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$destination/postgres.log" >&2
        exit 1
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    cat "$destination/postgres.log" >&2
    echo "restored PostgreSQL did not become ready" >&2
    exit 1
fi

psql_base="psql -h $socket_dir -p 55432 -U ${POSTGRES_USER:-kcsp} -d $database -At -v ON_ERROR_STOP=1"
core_tables="$($psql_base -c "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public' AND tablename IN ('kcsp_schema_migrations','security_events','alerts','incidents','audit_entries','detection_rules');")"
migrations="$($psql_base -c "SELECT count(*) FROM kcsp_schema_migrations;")"
before_target="$($psql_base -c "SELECT count(*) FROM kcsp_pitr_probe.entries WHERE phase='before_target';")"
after_target="$($psql_base -c "SELECT count(*) FROM kcsp_pitr_probe.entries WHERE phase='after_target';")"

if [ "$core_tables" -ne 6 ] || [ "$migrations" -le 0 ] || [ "$before_target" -ne 1 ] || [ "$after_target" -ne 0 ]; then
    echo "PITR data-boundary verification failed" >&2
    exit 1
fi

pg_ctl -D "$destination" -m fast stop >/dev/null
wait "$server_pid" 2>/dev/null || true
server_pid=""

completed="$(date +%s)"
duration=$((completed - started))
rto_met=false
if [ "$duration" -le "$rto_seconds" ]; then
    rto_met=true
fi
report="$report_dir/${run_id}.json"
cat >"$report" <<EOF
{
  "schema_version": "kcsp.pitr-drill/v1",
  "status": "SUCCEEDED",
  "target": "$target",
  "started_epoch": $started,
  "completed_epoch": $completed,
  "duration_seconds": $duration,
  "rto_target_seconds": $rto_seconds,
  "rto_met": $rto_met,
  "core_tables_verified": $core_tables,
  "migrations_verified": $migrations,
  "before_target_rows": $before_target,
  "after_target_rows": $after_target
}
EOF
sha256sum "$report" >"${report}.sha256"
cat "$report"

if [ "$rto_met" != true ]; then
    echo "PITR restore succeeded but exceeded the declared RTO" >&2
    exit 1
fi
