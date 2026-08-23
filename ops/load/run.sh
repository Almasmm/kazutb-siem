#!/usr/bin/env sh
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
profile="${KCSP_LOAD_PROFILE:-smoke}"
results="${KCSP_LOAD_RESULTS:-$root/.artifacts/load}"
network="${KCSP_LOAD_DOCKER_NETWORK:-kcsp_default}"
image="${KCSP_K6_IMAGE:-grafana/k6:2.1.0@sha256:65c920dc067d5e2e00befbf982af6ad6ad0117034e8b1c65817c7975c52d4669}"

case "$profile" in
  smoke|sustained|spike|capacity10k|fault) ;;
  *)
    echo "KCSP_LOAD_PROFILE must be smoke, sustained, spike, capacity10k, or fault" >&2
    exit 1
    ;;
esac

mkdir -p "$results"
export KCSP_LOAD_PROFILE="$profile"
export KCSP_BASE_URL="${KCSP_BASE_URL:-http://api:8080}"
export KCSP_TENANT_ID="${KCSP_TENANT_ID:-university-kulazhanov}"
export KCSP_COLLECTOR_TOKEN="${KCSP_COLLECTOR_TOKEN:-kcsp-demo-collector}"
export KCSP_ANALYST_TOKEN="${KCSP_ANALYST_TOKEN:-kcsp-demo-l2}"
export KCSP_ALLOW_DEMO_CREDENTIALS="${KCSP_ALLOW_DEMO_CREDENTIALS:-true}"
export KCSP_RUN_ID="${KCSP_RUN_ID:-kcsp-$profile-$(date -u +%Y%m%dT%H%M%SZ)}"
export KCSP_SUMMARY_PATH="/results/kcsp-$profile-summary.json"

docker run --rm \
  --network "$network" \
  --user "$(id -u):$(id -g)" \
  -v "$root/test/load/k6:/scripts:ro" \
  -v "$results:/results" \
  -e KCSP_BASE_URL \
  -e KCSP_TENANT_ID \
  -e KCSP_COLLECTOR_TOKEN \
  -e KCSP_ANALYST_TOKEN \
  -e KCSP_ALLOW_DEMO_CREDENTIALS \
  -e KCSP_LOAD_PROFILE \
  -e KCSP_LOAD_DURATION \
  -e KCSP_INGEST_RATE \
  -e KCSP_READ_VUS \
  -e KCSP_ASSET_CARDINALITY \
  -e KCSP_INGEST_P95_MS \
  -e KCSP_INGEST_P99_MS \
  -e KCSP_READ_P95_MS \
  -e KCSP_READ_P99_MS \
  -e KCSP_PIPELINE_VISIBILITY_SLO_MS \
  -e KCSP_PIPELINE_VISIBILITY_TIMEOUT_MS \
  -e KCSP_SKIP_VISIBILITY \
  -e KCSP_RUN_ID \
  -e KCSP_SUMMARY_PATH \
  "$image" run /scripts/kcsp.js
