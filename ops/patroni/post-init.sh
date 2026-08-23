#!/bin/sh
set -eu

connection="${1:?Patroni post_init connection string is required}"
database="${KCSP_HA_DATABASE:-kcsp}"
owner="${KCSP_HA_SUPERUSER:-kcsp}"

case "$database:$owner" in
    *[!A-Za-z0-9_:]*) echo "unsafe KCSP HA database or owner" >&2; exit 1 ;;
esac

exists="$(psql "$connection" -At -v ON_ERROR_STOP=1 -c "SELECT 1 FROM pg_database WHERE datname = '$database'")"
if [ "$exists" != "1" ]; then
    createdb --maintenance-db="$connection" --owner="$owner" "$database"
fi
