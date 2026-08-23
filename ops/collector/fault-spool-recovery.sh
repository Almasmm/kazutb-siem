#!/usr/bin/env bash
set -Eeuo pipefail

required_ack="I_UNDERSTAND_API_WILL_STOP"
if [[ "${KCSP_COLLECTOR_FAULT_ACK:-}" != "$required_ack" ]]; then
  echo "Set KCSP_COLLECTOR_FAULT_ACK=$required_ack to run this disruptive local test" >&2
  exit 2
fi

base_url="${KCSP_BASE_URL:-http://127.0.0.1:8080}"
case "$base_url" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *)
    echo "Collector fault acceptance is restricted to a loopback KCSP URL" >&2
    exit 2
    ;;
esac

for command in docker curl; do
  command -v "$command" >/dev/null || {
    echo "$command is required" >&2
    exit 2
  }
done

api_container="$(docker ps -a --filter label=com.docker.compose.service=api --format '{{.Names}}' | head -n 1)"
collector_container="$(docker ps -a --filter label=com.docker.compose.service=collector --format '{{.Names}}' | head -n 1)"
if [[ -z "$api_container" || -z "$collector_container" ]]; then
  echo "Running Compose API and collector containers are required" >&2
  exit 1
fi

restore_api() {
  docker start "$api_container" >/dev/null 2>&1 || true
}
trap restore_api EXIT INT TERM

canary="KCSP-XDR-SPOOL-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
payload="CEF:0|KCSP Test|Campus Firewall|1.0|xdr-spool|$canary|8|src=10.77.1.16 dst=198.51.100.78 spt=55124 dpt=443 act=blocked"

docker stop "$api_container" >/dev/null
printf '%s' "$payload" | docker exec -i "$collector_container" nc -u -w 1 127.0.0.1 5514
sleep 2

offline_health="$(docker exec "$collector_container" wget -qO- http://127.0.0.1:8081/health/ready)"
if ! grep -Eq '"status":"ready"' <<<"$offline_health" || ! grep -Eq '"queue_depth":[1-9][0-9]*' <<<"$offline_health"; then
  echo "Collector did not remain ready with a durable offline event: $offline_health" >&2
  exit 1
fi
queued="$(sed -nE 's/.*"queue_depth":([0-9]+).*/\1/p' <<<"$offline_health")"

docker start "$api_container" >/dev/null
deadline=$((SECONDS + 30))
until curl --fail --silent --show-error "$base_url/health/ready" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "API did not recover within 30 seconds" >&2
    exit 1
  fi
  sleep 0.5
done

deadline=$((SECONDS + 30))
until curl --fail --silent --show-error \
  -H 'Authorization: Bearer kcsp-demo-l2' \
  -H 'X-KCSP-Tenant-ID: university-kulazhanov' \
  "$base_url/api/v1/events?limit=200" | grep -Fq "$canary"; do
  if (( SECONDS >= deadline )); then
    echo "Spooled collector canary did not reach Events within 30 seconds" >&2
    exit 1
  fi
  sleep 0.5
done

deadline=$((SECONDS + 15))
while :; do
  drained_health="$(docker exec "$collector_container" wget -qO- http://127.0.0.1:8081/health/ready)"
  if grep -Eq '"queue_depth":0' <<<"$drained_health"; then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "Collector spool did not drain within 15 seconds: $drained_health" >&2
    exit 1
  fi
  sleep 0.5
done

printf '{"schema":"kcsp.collector-fault/v1","status":"ok","queued":%s,"drained":0,"canary":"%s"}\n' "$queued" "$canary"
