#!/usr/bin/env sh
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${KCSP_K6_IMAGE:-grafana/k6:2.1.0@sha256:65c920dc067d5e2e00befbf982af6ad6ad0117034e8b1c65817c7975c52d4669}"

docker run --rm \
  -v "$root/test/load/k6:/scripts:ro" \
  "$image" inspect /scripts/kcsp.js >/dev/null

if KCSP_LOAD_PROFILE=invalid bash "$root/ops/load/run.sh" >/dev/null 2>&1; then
  echo "load runner accepted an invalid profile" >&2
  exit 1
fi
if KCSP_FAULT_ACK=missing bash "$root/ops/load/fault-processor-recovery.sh" >/dev/null 2>&1; then
  echo "fault runner accepted a missing safety acknowledgement" >&2
  exit 1
fi

printf '%s\n' '{"status":"ok","test":"kcsp-load-contract"}'
