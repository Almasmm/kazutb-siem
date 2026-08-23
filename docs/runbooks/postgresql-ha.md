# PostgreSQL Small-HA and fencing runbook

## Topology

The `ha` profile is isolated from the default development database:

- three PostgreSQL 17 nodes managed by Patroni 4.1.5;
- three independent etcd 3.5.21 voting members;
- one synchronous standby required with `synchronous_mode_strict`;
- HAProxy 3.2 write routing through Patroni `/primary`;
- HAProxy read routing through Patroni `/replica`;
- separate internal data and DCS networks;
- dedicated persistent volume for every database and DCS member;
- data checksums, replication slots, `pg_rewind`, SCRAM credentials and timeline
  validation;
- read-only container root filesystems and all Linux capabilities dropped for
  Patroni and HAProxy.

The profile does not reuse or overwrite `kcsp-postgres-data`.

## Start

Set three independent local secrets:

```powershell
$env:KCSP_HA_POSTGRES_PASSWORD = '<at least 24 random bytes>'
$env:KCSP_HA_REPLICATION_PASSWORD = '<different random value>'
$env:KCSP_HA_REWIND_PASSWORD = '<different random value>'
```

The normal Compose secrets are still required while parsing the complete model.
Start the HA control plane:

```powershell
docker compose --profile ha up -d --build --wait `
  etcd-1 etcd-2 etcd-3 patroni-1 patroni-2 patroni-3 postgres-ha
```

Endpoints:

- write endpoint: `127.0.0.1:5434`;
- read-only replica endpoint: `127.0.0.1:5435`;
- HAProxy health/Prometheus endpoint: `127.0.0.1:8404`.

Applications must use the write endpoint for migrations and SOC mutations.
Read-only reporting can use the replica endpoint only when bounded replica lag
is acceptable.

## Acceptance and DCS partition drill

Run:

```bash
sh ops/ha/acceptance.sh
```

The drill:

1. Finds the elected leader through Patroni REST state.
2. Writes a committed probe row through HAProxy.
3. Requires at least one synchronous standby.
4. Disconnects only the leader's DCS network while leaving its client/data
   network connected.
5. Requires the former leader to lose `/primary` eligibility.
6. Requires a different member to acquire leadership through the two-member
   etcd quorum.
7. Writes another row through the unchanged HAProxy endpoint.
8. Verifies both committed rows.
9. Reconnects the former leader and requires it to return as a replica.

This is a stronger test than stopping a container because the former leader
remains reachable by clients while it loses consensus. Successful demotion is
the software-fencing invariant that prevents dual-primary writes.

## Production boundary

`watchdog.mode=automatic` allows the local profile to run without a host
watchdog. Production bare-metal nodes must expose a tested watchdog and set
`watchdog.mode=required`, or provide equivalent STONITH/fencing.

The local DCS network uses plaintext etcd because it is internal and intended
only for the Small-HA proof profile. Production requires mutual TLS for etcd,
certificate rotation, separate hosts/failure domains, odd voter count,
anti-affinity, monitoring and a tested loss-of-quorum procedure.

Before application cutover, restore or migrate KCSP data into the HA cluster,
run schema migrations through the write endpoint, switch
`KCSP_DATABASE_URL`, verify tenant isolation and audit continuity, and execute
the failover drill again. PostgreSQL HA does not make Kafka, ClickHouse, MinIO
or the application workers highly available; those remain separate gates.
