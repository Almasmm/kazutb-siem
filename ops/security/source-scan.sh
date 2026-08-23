#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)

# shellcheck disable=SC1091
. "$SCRIPT_DIR/toolchain.env"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "$1" >&2
    exit 1
  fi
}

require_command git
require_command go
require_command npm

cd "$ROOT_DIR"

printf '%s\n' '==> Secret scan: complete Git history'
go run "$KCSP_GITLEAKS_MODULE" git \
  --no-banner \
  --redact \
  --verbose \
  --log-opts="--all" \
  .

printf '%s\n' '==> SAST: Go security rules'
go run "$KCSP_GOSEC_MODULE" \
  -quiet \
  -exclude-generated \
  -exclude-dir=.artifacts \
  -exclude-dir=.tools \
  -exclude-dir=node_modules \
  -severity medium \
  -confidence medium \
  ./...

printf '%s\n' '==> SCA: reachable Go vulnerabilities'
go run "$KCSP_GOVULNCHECK_MODULE" ./...

printf '%s\n' '==> SCA: frontend dependency vulnerabilities'
(
  cd "$ROOT_DIR/apps/web"
  npm audit --audit-level=high
)
