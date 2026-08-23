#!/bin/sh
set -eu

umask 077
config="${PATRONI_CONFIG_FILE:-/tmp/patroni.yml}"
chmod 0700 /var/lib/postgresql/data
/usr/local/bin/kcsp-render-patroni
exec /opt/patroni/bin/patroni "$config"
