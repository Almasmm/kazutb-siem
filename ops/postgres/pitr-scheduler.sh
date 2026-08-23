#!/bin/sh
set -u

stanza="${KCSP_PITR_STANZA:-kcsp}"
schedule_seconds="${KCSP_PITR_SCHEDULE_SECONDS:-21600}"
full_seconds="${KCSP_PITR_FULL_INTERVAL_SECONDS:-604800}"
retry_seconds="${KCSP_PITR_RETRY_SECONDS:-60}"
state_path="${KCSP_PITR_STATE_PATH:-/var/lib/pgbackrest}"
status_file="$state_path/status/scheduler"
full_marker="$state_path/status/last-full"

for pair in \
    "KCSP_PITR_SCHEDULE_SECONDS:$schedule_seconds" \
    "KCSP_PITR_FULL_INTERVAL_SECONDS:$full_seconds" \
    "KCSP_PITR_RETRY_SECONDS:$retry_seconds"; do
    name="${pair%%:*}"
    value="${pair#*:}"
    case "$value" in ''|*[!0-9]*) echo "$name must be a positive integer" >&2; exit 1 ;; esac
    if [ "$value" -le 0 ]; then
        echo "$name must be a positive integer" >&2
        exit 1
    fi
done

mkdir -p "$(dirname "$status_file")"
printf 'INITIALIZING|%s\n' "$(date +%s)" >"$status_file"

until pg_isready -h /var/run/postgresql -p "${PGPORT:-5432}" >/dev/null 2>&1; do
    sleep 2
done

until pgbackrest --stanza="$stanza" stanza-create >/dev/null 2>&1; do
    printf 'DEGRADED|%s|stanza-create\n' "$(date +%s)" >"$status_file"
    sleep "$retry_seconds"
done

while true; do
    now="$(date +%s)"
    backup_type=diff
    if [ ! -s "$full_marker" ]; then
        backup_type=full
    else
        last_full="$(cat "$full_marker" 2>/dev/null || printf '0')"
        case "$last_full" in ''|*[!0-9]*) last_full=0 ;; esac
        if [ $((now - last_full)) -ge "$full_seconds" ]; then
            backup_type=full
        fi
    fi

    printf 'BACKUP|%s|%s\n' "$now" "$backup_type" >"$status_file"
    if pgbackrest --stanza="$stanza" --type="$backup_type" backup; then
        completed="$(date +%s)"
        if [ "$backup_type" = "full" ]; then
            printf '%s\n' "$completed" >"$full_marker"
        fi
        printf 'HEALTHY|%s|%s\n' "$completed" "$backup_type" >"$status_file"
        sleep "$schedule_seconds"
    else
        printf 'DEGRADED|%s|%s\n' "$(date +%s)" "$backup_type" >"$status_file"
        sleep "$retry_seconds"
    fi
done
