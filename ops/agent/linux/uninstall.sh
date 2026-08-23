#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./uninstall.sh [--purge]

The default preserves /etc/kcsp/agent.env, enrolled credentials and the queue.
Use --purge only when the endpoint is being permanently decommissioned.
EOF
}

fail() {
  printf 'uninstall: %s\n' "$*" >&2
  exit 1
}

PURGE=false
while (($# > 0)); do
  case "$1" in
    --purge) PURGE=true; shift ;;
    --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "root privileges are required"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required"

systemctl disable --now kcsp-agent.service >/dev/null 2>&1 || true
rm -f -- /etc/systemd/system/kcsp-agent.service /opt/kcsp/agent/kcsp-agent
rmdir -- /opt/kcsp/agent /opt/kcsp 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed kcsp-agent.service >/dev/null 2>&1 || true

if [[ "$PURGE" == true ]]; then
  rm -f -- /etc/kcsp/agent.env
  rmdir -- /etc/kcsp 2>/dev/null || true
  rm -rf -- /var/lib/kcsp-agent
  if id kcsp-agent >/dev/null 2>&1; then
    userdel kcsp-agent
  fi
  if getent group kcsp-agent >/dev/null 2>&1; then
    groupdel kcsp-agent
  fi
fi

printf '{"status":"ok","purged":%s}\n' "$PURGE"
