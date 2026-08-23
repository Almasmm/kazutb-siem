#!/bin/sh
set -eu

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

export KCSP_PATRONI_NAME=patroni-1
export KCSP_PATRONI_SCOPE=kcsp-ha
export KCSP_PATRONI_ETCD3_HOSTS=etcd-1:2379,etcd-2:2379,etcd-3:2379
export KCSP_HA_POSTGRES_PASSWORD=self-test-superuser-password
export KCSP_HA_REPLICATION_PASSWORD=self-test-replication-password
export KCSP_HA_REWIND_PASSWORD=self-test-rewind-password
export PATRONI_CONFIG_FILE="$root/patroni.yml"

/usr/local/bin/kcsp-render-patroni
/opt/patroni/bin/python3 - "$PATRONI_CONFIG_FILE" <<'PY'
import os
import stat
import sys
import yaml

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    config = yaml.safe_load(source)
assert config["bootstrap"]["dcs"]["synchronous_mode"] is True
assert config["bootstrap"]["dcs"]["synchronous_mode_strict"] is True
assert config["bootstrap"]["dcs"]["failsafe_mode"] is False
assert len(config["etcd3"]["hosts"].split(",")) == 3
assert config["postgresql"]["bin_dir"] == "/usr/local/bin"
assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
PY

echo '{"status":"ok","test":"kcsp-patroni-self-test"}'
