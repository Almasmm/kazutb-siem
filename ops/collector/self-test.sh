#!/usr/bin/env bash
set -Eeuo pipefail

script="${1:-ops/collector/fault-spool-recovery.sh}"
if KCSP_COLLECTOR_FAULT_ACK='' KCSP_BASE_URL=http://127.0.0.1:8080 bash "$script" >/dev/null 2>&1; then
  echo "Collector fault script accepted a missing safety acknowledgement" >&2
  exit 1
fi
if KCSP_COLLECTOR_FAULT_ACK=I_UNDERSTAND_API_WILL_STOP KCSP_BASE_URL=https://soc.example.edu bash "$script" >/dev/null 2>&1; then
  echo "Collector fault script accepted a non-loopback target" >&2
  exit 1
fi
printf '%s\n' '{"status":"ok","test":"kcsp-collector-fault-guards"}'
