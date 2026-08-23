#!/bin/sh
set -eu

is_true() {
    case "${1:-}" in
        true|TRUE|1|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

if [ "${1#-}" != "$1" ]; then
    set -- postgres "$@"
fi

if is_true "${KCSP_PITR_ENABLED:-false}"; then
    /usr/local/bin/kcsp-configure-pgbackrest

    archive_timeout="${KCSP_PITR_ARCHIVE_TIMEOUT_SECONDS:-60}"
    rpo_target="${KCSP_PITR_RPO_SECONDS:-300}"
    case "$archive_timeout:$rpo_target" in
        *[!0-9:]*|:*|*:) echo "PITR archive timeout and RPO must be positive integers" >&2; exit 1 ;;
    esac
    if [ "$archive_timeout" -le 0 ] || [ "$rpo_target" -le 0 ] || [ "$archive_timeout" -gt "$rpo_target" ]; then
        echo "KCSP_PITR_ARCHIVE_TIMEOUT_SECONDS must be positive and no greater than KCSP_PITR_RPO_SECONDS" >&2
        exit 1
    fi

    if [ "$1" = "postgres" ]; then
        set -- "$@" \
            -c archive_mode=on \
            -c "archive_command=pgbackrest --stanza=${KCSP_PITR_STANZA:-kcsp} archive-push %p" \
            -c "restore_command=pgbackrest --stanza=${KCSP_PITR_STANZA:-kcsp} archive-get %f %p" \
            -c "archive_timeout=${archive_timeout}s" \
            -c wal_level=replica \
            -c wal_compression=on

        if is_true "${KCSP_PITR_SCHEDULER_ENABLED:-true}"; then
            if [ "$(id -u)" -eq 0 ]; then
                gosu postgres:postgres /usr/local/bin/kcsp-pitr-scheduler &
            else
                /usr/local/bin/kcsp-pitr-scheduler &
            fi
        fi
    fi
fi

exec /usr/local/bin/docker-entrypoint.sh "$@"
