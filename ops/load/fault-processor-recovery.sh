#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${KCSP_FAULT_ACK:-}" != "I_UNDERSTAND_PROCESSOR_WILL_STOP" ]]; then
  echo "Set KCSP_FAULT_ACK=I_UNDERSTAND_PROCESSOR_WILL_STOP for an approved non-production test." >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
project="${KCSP_COMPOSE_PROJECT_NAME:-kcsp}"
api="${KCSP_FAULT_API_URL:-http://127.0.0.1:8080}"
tenant="${KCSP_TENANT_ID:-university-kulazhanov}"
collector_token="${KCSP_COLLECTOR_TOKEN:-kcsp-demo-collector}"
analyst_token="${KCSP_ANALYST_TOKEN:-kcsp-demo-l2}"
recovery_slo="${KCSP_RECOVERY_SLO_SECONDS:-60}"
results="${KCSP_LOAD_RESULTS:-$root/.artifacts/load}"

if [[ "$api" != http://127.0.0.1:* && "$api" != http://localhost:* ]]; then
  echo "Fault injection is restricted to a loopback Compose deployment." >&2
  exit 1
fi
for command in curl docker jq; do
  command -v "$command" >/dev/null || {
    echo "$command is required" >&2
    exit 1
  }
done

mapfile -t processors < <(
  docker ps -q \
    --filter "label=com.docker.compose.project=$project" \
    --filter "label=com.docker.compose.service=processor" \
    --filter status=running
)
if [[ "${#processors[@]}" -eq 0 ]]; then
  echo "No running Compose processor containers were found." >&2
  exit 1
fi

mkdir -p "$results"
run_id="processor-fault-$(date -u +%Y%m%dT%H%M%SZ)"
restarted=false
cleanup() {
  if [[ "$restarted" != "true" ]]; then
    docker start "${processors[@]}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker stop --time 20 "${processors[@]}" >/dev/null

KCSP_LOAD_PROFILE=fault \
KCSP_LOAD_DURATION="${KCSP_FAULT_DURATION:-15s}" \
KCSP_INGEST_RATE="${KCSP_FAULT_RATE:-20}" \
KCSP_SKIP_VISIBILITY=true \
KCSP_RUN_ID="$run_id" \
KCSP_LOAD_RESULTS="$results" \
KCSP_TENANT_ID="$tenant" \
KCSP_COLLECTOR_TOKEN="$collector_token" \
KCSP_ANALYST_TOKEN="$analyst_token" \
bash "$root/ops/load/run.sh"

sentinel="${run_id}-drain-sentinel"
payload="$(jq -nc \
  --arg event_id "$sentinel" \
  --arg event_time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    event_id: $event_id,
    event_time: $event_time,
    category: "network_activity",
    activity_name: "Processor recovery drain sentinel",
    source: {vendor: "KCSP", product: "FaultHarness", type: "synthetic"},
    device: {hostname: "processor-fault-probe", criticality: 1}
  }')"
status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  -X POST "$api/api/v1/ingest/events" \
  -H "Authorization: Bearer $collector_token" \
  -H "X-KCSP-Tenant-ID: $tenant" \
  -H "X-KCSP-Event-Format: ocsf-json-v1" \
  -H "Content-Type: application/json" \
  --data "$payload")"
if [[ "$status" != "202" ]]; then
  echo "API did not accept the drain sentinel while processor was stopped: HTTP $status" >&2
  exit 1
fi

recovery_started="$(date +%s)"
docker start "${processors[@]}" >/dev/null
restarted=true
visible=false
while (( $(date +%s) - recovery_started <= recovery_slo )); do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    "$api/api/v1/events/$sentinel" \
    -H "Authorization: Bearer $analyst_token" \
    -H "X-KCSP-Tenant-ID: $tenant" || true)"
  if [[ "$status" == "200" ]]; then
    visible=true
    break
  fi
  sleep 1
done
if [[ "$visible" != "true" ]]; then
  echo "Processor did not drain through sentinel within ${recovery_slo}s." >&2
  exit 1
fi

recovery_seconds="$(( $(date +%s) - recovery_started ))"
summary="$results/kcsp-fault-summary.json"
accepted="$(jq -r '.metrics.events_accepted.values.count // 0' "$summary")"
report="$results/kcsp-processor-recovery.json"
jq -n \
  --arg run_id "$run_id" \
  --arg sentinel "$sentinel" \
  --argjson stopped_processors "${#processors[@]}" \
  --argjson accepted_events "$accepted" \
  --argjson recovery_seconds "$recovery_seconds" \
  --argjson recovery_slo_seconds "$recovery_slo" \
  '{
    schema: "kcsp.fault-acceptance/v1",
    status: "ok",
    run_id: $run_id,
    stopped_processors: $stopped_processors,
    accepted_events: $accepted_events,
    drain_sentinel: $sentinel,
    recovery_seconds: $recovery_seconds,
    recovery_slo_seconds: $recovery_slo_seconds
  }' | tee "$report"
