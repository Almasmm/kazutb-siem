#!/bin/sh
set -eu

: "${KCSP_HA_POSTGRES_PASSWORD:?KCSP_HA_POSTGRES_PASSWORD is required}"

services="patroni-1 patroni-2 patroni-3"
network="${KCSP_HA_DCS_NETWORK:-kcsp-ha-dcs}"
project="${KCSP_COMPOSE_PROJECT_NAME:-kcsp}"
leader=""
leader_container=""
reconnected=true

find_leader() {
    for service in $services; do
        container="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$service" --filter status=running | sed -n '1p')"
        if [ -n "$container" ] && docker exec "$container" wget -q --spider http://127.0.0.1:8008/primary; then
            printf '%s|%s\n' "$service" "$container"
            return 0
        fi
    done
    return 1
}

sql() {
    docker run --rm \
        --network kcsp-ha-data \
        --entrypoint psql \
        -e "PGPASSWORD=$KCSP_HA_POSTGRES_PASSWORD" \
        kcsp-postgres:17 \
        -h postgres-ha -p 5432 -U kcsp -d kcsp -At -v ON_ERROR_STOP=1 "$@"
}

cleanup() {
    if [ "$reconnected" = false ] && [ -n "$leader_container" ]; then
        docker network connect "$network" "$leader_container" >/dev/null 2>&1 || true
    fi
    sql -c "DROP SCHEMA IF EXISTS kcsp_ha_probe CASCADE" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

for _ in $(seq 1 90); do
    result="$(find_leader || true)"
    if [ -n "$result" ]; then
        leader="${result%%|*}"
        leader_container="${result#*|}"
        break
    fi
    sleep 1
done
if [ -z "$leader" ]; then
    echo "no Patroni leader elected" >&2
    exit 1
fi

sql -c "DROP SCHEMA IF EXISTS kcsp_ha_probe CASCADE; CREATE SCHEMA kcsp_ha_probe; CREATE TABLE kcsp_ha_probe.entries(id bigint PRIMARY KEY, phase text NOT NULL); INSERT INTO kcsp_ha_probe.entries VALUES (1, 'before_partition');" >/dev/null
sync_count="$(sql -c "SELECT count(*) FROM pg_stat_replication WHERE sync_state IN ('sync','quorum')")"
if [ "$sync_count" -lt 1 ]; then
    echo "primary has no synchronous standby" >&2
    exit 1
fi

docker network disconnect "$network" "$leader_container"
reconnected=false

new_leader=""
for _ in $(seq 1 90); do
    result="$(find_leader || true)"
    candidate="${result%%|*}"
    if [ -n "$candidate" ] && [ "$candidate" != "$leader" ]; then
        new_leader="$candidate"
        break
    fi
    sleep 1
done
if [ -z "$new_leader" ]; then
    echo "DCS partition did not elect a replacement leader" >&2
    exit 1
fi
if docker exec "$leader_container" wget -q --spider http://127.0.0.1:8008/primary; then
    echo "partitioned former leader was not fenced" >&2
    exit 1
fi

write_ready=false
for _ in $(seq 1 30); do
    if sql -c "INSERT INTO kcsp_ha_probe.entries VALUES (2, 'after_failover') ON CONFLICT (id) DO NOTHING" >/dev/null 2>&1; then
        write_ready=true
        break
    fi
    sleep 1
done
if [ "$write_ready" != true ]; then
    echo "HAProxy write endpoint did not recover after failover" >&2
    exit 1
fi
rows="$(sql -c "SELECT count(*) FROM kcsp_ha_probe.entries")"
if [ "$rows" -ne 2 ]; then
    echo "write endpoint lost committed rows across failover" >&2
    exit 1
fi

docker network connect "$network" "$leader_container"
reconnected=true
for _ in $(seq 1 90); do
    if docker exec "$leader_container" wget -q --spider http://127.0.0.1:8008/replica; then
        break
    fi
    sleep 1
done
if ! docker exec "$leader_container" wget -q --spider http://127.0.0.1:8008/replica; then
    echo "former leader did not rejoin as a replica" >&2
    exit 1
fi

printf '{"status":"ok","old_leader":"%s","new_leader":"%s","sync_standbys":%s,"rows":%s}\n' \
    "$leader" "$new_leader" "$sync_count" "$rows"
