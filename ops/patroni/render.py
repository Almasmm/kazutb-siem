#!/opt/patroni/bin/python3
import os
import pathlib
import re
import tempfile

import yaml


IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")
HOST = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}:[0-9]{1,5}$")


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"{name} is required")
    if "\n" in value or "\r" in value:
        raise SystemExit(f"{name} must not contain line breaks")
    return value


def identifier(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default or "")
    if not IDENTIFIER.fullmatch(value):
        raise SystemExit(f"{name} is not a safe identifier")
    return value


def secret(name: str) -> str:
    value = required(name)
    if len(value.encode()) < 24:
        raise SystemExit(f"{name} must contain at least 24 bytes")
    return value


def integer(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise SystemExit(f"{name} must be an integer") from error
    if value < minimum or value > maximum:
        raise SystemExit(f"{name} must be between {minimum} and {maximum}")
    return value


def main() -> None:
    node = identifier("KCSP_PATRONI_NAME")
    scope = identifier("KCSP_PATRONI_SCOPE", "kcsp-ha")
    database = identifier("KCSP_HA_DATABASE", "kcsp")
    superuser = identifier("KCSP_HA_SUPERUSER", "kcsp")
    replication_user = identifier("KCSP_HA_REPLICATION_USER", "kcsp_replicator")
    rewind_user = identifier("KCSP_HA_REWIND_USER", "kcsp_rewind")
    superuser_password = secret("KCSP_HA_POSTGRES_PASSWORD")
    replication_password = secret("KCSP_HA_REPLICATION_PASSWORD")
    rewind_password = secret("KCSP_HA_REWIND_PASSWORD")
    data_dir = os.environ.get("KCSP_PATRONI_DATA_DIR", "/var/lib/postgresql/data")
    if not pathlib.PurePosixPath(data_dir).is_absolute():
        raise SystemExit("KCSP_PATRONI_DATA_DIR must be absolute")

    hosts = [item.strip() for item in required("KCSP_PATRONI_ETCD3_HOSTS").split(",")]
    if len(hosts) != 3 or len(set(hosts)) != 3 or any(not HOST.fullmatch(item) for item in hosts):
        raise SystemExit("KCSP_PATRONI_ETCD3_HOSTS must contain three unique host:port voters")

    ttl = integer("KCSP_PATRONI_TTL_SECONDS", 30, 20, 120)
    loop_wait = integer("KCSP_PATRONI_LOOP_WAIT_SECONDS", 5, 1, 30)
    retry_timeout = integer("KCSP_PATRONI_RETRY_TIMEOUT_SECONDS", 10, 3, 30)
    if loop_wait + (2 * retry_timeout) > ttl:
        raise SystemExit("Patroni timing violates loop_wait + 2*retry_timeout <= ttl")

    maximum_lag = integer("KCSP_PATRONI_MAXIMUM_LAG_BYTES", 1048576, 0, 1073741824)
    synchronous_nodes = integer("KCSP_PATRONI_SYNCHRONOUS_NODES", 1, 1, 2)
    hba = [
        "local all all trust",
        f"host replication {replication_user} 0.0.0.0/0 scram-sha-256",
        f"host all {superuser} 0.0.0.0/0 scram-sha-256",
        f"host all {rewind_user} 0.0.0.0/0 scram-sha-256",
    ]
    parameters = {
        "hot_standby": "on",
        "hot_standby_feedback": "on",
        "max_connections": 300,
        "max_replication_slots": 10,
        "max_wal_senders": 10,
        "password_encryption": "scram-sha-256",
        "synchronous_commit": "remote_apply",
        "wal_keep_size": "512MB",
        "wal_level": "replica",
        "wal_log_hints": "on",
    }
    config = {
        "scope": scope,
        "namespace": "/kcsp/",
        "name": node,
        "restapi": {
            "listen": "0.0.0.0:8008",
            "connect_address": f"{node}:8008",
        },
        "etcd3": {"hosts": ",".join(hosts)},
        "bootstrap": {
            "dcs": {
                "ttl": ttl,
                "loop_wait": loop_wait,
                "retry_timeout": retry_timeout,
                "maximum_lag_on_failover": maximum_lag,
                "maximum_lag_on_syncnode": maximum_lag,
                "check_timeline": True,
                "failsafe_mode": False,
                "synchronous_mode": True,
                "synchronous_mode_strict": True,
                "synchronous_node_count": synchronous_nodes,
                "postgresql": {
                    "use_pg_rewind": True,
                    "use_slots": True,
                    "parameters": parameters,
                },
            },
            "initdb": [{"encoding": "UTF8"}, "data-checksums"],
            "pg_hba": hba,
            "post_init": "/usr/local/bin/kcsp-patroni-post-init",
        },
        "postgresql": {
            "listen": "0.0.0.0:5432",
            "connect_address": f"{node}:5432",
            "data_dir": data_dir,
            "bin_dir": "/usr/local/bin",
            "pgpass": "/tmp/pgpass",
            "authentication": {
                "superuser": {"username": superuser, "password": superuser_password},
                "replication": {"username": replication_user, "password": replication_password},
                "rewind": {"username": rewind_user, "password": rewind_password},
            },
            "parameters": parameters,
            "pg_hba": hba,
            "create_replica_methods": ["basebackup"],
            "basebackup": {"checkpoint": "fast"},
        },
        "watchdog": {
            "mode": os.environ.get("KCSP_PATRONI_WATCHDOG_MODE", "automatic"),
            "device": "/dev/watchdog",
            "safety_margin": 5,
        },
        "tags": {
            "clonefrom": False,
            "nofailover": False,
            "noloadbalance": False,
            "nosync": False,
        },
        "kcsp": {"database": database},
    }

    destination = pathlib.Path(os.environ.get("PATRONI_CONFIG_FILE", "/tmp/patroni.yml"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=destination.parent, delete=False
    ) as temporary:
        yaml.safe_dump(config, temporary, default_flow_style=False, sort_keys=False)
        temp_name = temporary.name
    os.chmod(temp_name, 0o600)
    os.replace(temp_name, destination)


if __name__ == "__main__":
    main()
