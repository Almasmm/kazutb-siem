#!/bin/sh
set -eu

: "${KCSP_HA_POSTGRES_PASSWORD:?KCSP_HA_POSTGRES_PASSWORD is required}"

services="patroni-1 patroni-2 patroni-3"
restart_services="etcd-1 etcd-2 etcd-3 patroni-1 patroni-2 patroni-3 postgres-ha"
network="${KCSP_HA_DCS_NETWORK:-kcsp-ha-dcs}"
project="${KCSP_COMPOSE_PROJECT_NAME:-kcsp}"
rto_budget_seconds="${KCSP_HA_RTO_SECONDS:-60}"
leader=""
leader_container=""
reconnected=true

case "$rto_budget_seconds" in
    ''|*[!0-9]*) echo "KCSP_HA_RTO_SECONDS must be a positive integer" >&2; exit 1 ;;
esac
if [ "$rto_budget_seconds" -lt 1 ]; then
    echo "KCSP_HA_RTO_SECONDS must be a positive integer" >&2
    exit 1
fi

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

restart_policy_services=0
for service in $restart_services; do
    container="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$service" --filter status=running | sed -n '1p')"
    if [ -z "$container" ]; then
        echo "$service is not running" >&2
        exit 1
    fi
    policy="$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$container")"
    if [ "$policy" != "unless-stopped" ]; then
        echo "$service restart policy is $policy, expected unless-stopped" >&2
        exit 1
    fi
    restart_policy_services="$((restart_policy_services + 1))"
done

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
partition_started="$(date +%s)"

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
write_recovered="$(date +%s)"
write_rto_seconds="$((write_recovered - partition_started))"
if [ "$write_rto_seconds" -gt "$rto_budget_seconds" ]; then
    echo "HAProxy write RTO exceeded ${rto_budget_seconds}s budget" >&2
    exit 1
fi
rows="$(sql -c "SELECT count(*) FROM kcsp_ha_probe.entries")"
if [ "$rows" -ne 2 ]; then
    echo "write endpoint lost committed rows across failover" >&2
    exit 1
fi
committed_rows_lost=0

docker network connect "$network" "$leader_container"
reconnected=true
rejoin_started="$(date +%s)"
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
rejoin_completed="$(date +%s)"
rejoin_seconds="$((rejoin_completed - rejoin_started))"

printf '{"status":"ok","old_leader":"%s","new_leader":"%s","sync_standbys":%s,"rows":%s,"committed_rows_lost":%s,"write_rto_seconds":%s,"rto_budget_seconds":%s,"rejoin_seconds":%s,"restart_policy_services":%s}\n' \
	"$leader" "$new_leader" "$sync_count" "$rows" "$committed_rows_lost" "$write_rto_seconds" "$rto_budget_seconds" "$rejoin_seconds" "$restart_policy_services"
