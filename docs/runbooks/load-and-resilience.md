# Load and resilience acceptance runbook

## Purpose

Measure KCSP ingest acceptance, SOC read latency, asynchronous pipeline
visibility, dropped work, and processor backlog recovery with reproducible
evidence.

These tests produce synthetic security events. Run them only in an approved
non-production environment or in a dedicated production performance tenant
with explicit change approval and retention rules.

## Toolchain

The repository pins Grafana k6 `v2.1.0` by OCI digest. The load script sends
events through the production queue endpoint:

```text
collector bearer -> API -> Kafka -> processor -> parser/detection ->
PostgreSQL/ClickHouse -> tenant-scoped analyst read
```

Direct test-only ingest is not used.

## Profiles

| Profile | Default shape | Purpose |
| --- | --- | --- |
| `smoke` | 5 EPS and 2 readers for 15 seconds | deployment preflight |
| `sustained` | 250 EPS and 10 readers for 15 minutes | stable capacity |
| `spike` | ramp to 4x configured EPS | burst and recovery behavior |
| `capacity10k` | 250 EPS, 10 readers, and 10,000 deterministic hosts for 40 seconds | high-cardinality end-to-end gate |
| `fault` | 20 EPS for 15 seconds, ingest only | processor outage harness |

The sustained and spike defaults are test objectives, not certified platform
capacity. Increase them only after the prior level passes with resource,
Kafka-lag, ClickHouse, PostgreSQL, and host telemetry captured.

## Default SLO gates

- Ingest HTTP error rate below 1 percent.
- Ingest acceptance p95 below 250 ms and p99 below 750 ms.
- SOC read error rate below 1 percent.
- SOC read p95 below 500 ms and p99 below 1500 ms.
- Zero dropped arrival-rate iterations.
- The setup event visible through `/api/v1/events/{id}` within 30 seconds.
- Processor outage backlog drained through a final sentinel within 60 seconds.

Override thresholds with `KCSP_INGEST_P95_MS`, `KCSP_INGEST_P99_MS`,
`KCSP_READ_P95_MS`, `KCSP_READ_P99_MS`,
`KCSP_PIPELINE_VISIBILITY_SLO_MS`, and `KCSP_RECOVERY_SLO_SECONDS`. Loosening a
threshold requires a documented capacity decision; it is not a way to turn a
failed acceptance green.

## Local smoke on Windows

Start the normal stack first, then run:

```powershell
.\ops\load\run.ps1 -Profile smoke
```

The PowerShell runner uses the internal Docker DNS name `api`, does not print
tokens, and writes the full k6 summary under `.artifacts/load`.

The committed `kcsp-demo-*` credentials are valid only for the local demo
authenticator. For OIDC or service-auth environments, set short-lived values in
the process environment:

```powershell
$env:KCSP_COLLECTOR_TOKEN = "<short-lived collector token>"
$env:KCSP_ANALYST_TOKEN = "<short-lived analyst token>"
$env:KCSP_TENANT_ID = "<performance test tenant>"
$env:KCSP_ALLOW_DEMO_CREDENTIALS = "false"
.\ops\load\run.ps1 -Profile sustained
```

Do not place tokens in command arguments, values files, Git, or result bundles.

## 10,000-host high-cardinality gate

The `capacity10k` profile emits exactly 10,000 deterministic hostnames and
requires zero dropped iterations. HTTP acceptance alone is not a pass. After
the k6 run, verify the normalized event count and exact hostname cardinality in
ClickHouse using the same run ID:

```powershell
$env:KCSP_RUN_ID = "kcsp-capacity10k-<approved-run-id>"
.\ops\load\run.ps1 -Profile capacity10k
$password = Read-Host "ClickHouse password" -AsSecureString
.\ops\load\verify-capacity10k.ps1 -RunId $env:KCSP_RUN_ID -ClickHousePassword $password
```

The verifier polls only within a bounded drain window and writes a secret-free
acceptance report under `.artifacts/load`. PASS requires exactly 10,000
normalized events, exactly 10,000 unique non-empty hostnames, at least 10,001
k6 acceptances including setup, and zero dropped iterations. A longer drain
timeout must be approved and documented rather than used to hide insufficient
processor throughput.

## Linux runner

```sh
KCSP_LOAD_PROFILE=smoke \
KCSP_LOAD_RESULTS=/secure/test-results/kcsp \
bash ops/load/run.sh
```

Useful controlled overrides:

```sh
KCSP_LOAD_PROFILE=sustained \
KCSP_LOAD_DURATION=30m \
KCSP_INGEST_RATE=500 \
KCSP_READ_VUS=20 \
bash ops/load/run.sh
```

The runner exits non-zero when any threshold fails.

## Processor recovery fault

This test intentionally stops every running Compose `processor` container. It
is restricted to a loopback API and requires an explicit acknowledgement:

```sh
KCSP_FAULT_ACK=I_UNDERSTAND_PROCESSOR_WILL_STOP \
KCSP_FAULT_RATE=20 \
KCSP_FAULT_DURATION=15s \
KCSP_RECOVERY_SLO_SECONDS=60 \
bash ops/load/fault-processor-recovery.sh
```

The script:

1. Finds processor containers by Compose project and service labels.
2. Stops them with a grace period.
3. Proves the API continues accepting events into Kafka.
4. Queues a final drain sentinel behind the load.
5. Restarts every stopped processor through a cleanup-safe path.
6. Waits until the sentinel is visible through the authenticated read API.
7. Writes `kcsp-processor-recovery.json`.

An interrupt or failed assertion still triggers processor restart. Confirm
service health after any fault test.

## Evidence

Retain:

- k6 full summary JSON and concise console summary;
- exact Git revision and k6 image digest;
- profile, duration, arrival rate, VUs, and threshold overrides;
- application, Kafka, PostgreSQL, ClickHouse, and host metrics;
- processor recovery report;
- alerts fired during the test;
- topology and resource limits;
- change approval and operator names.

Do not retain bearer tokens or real event payloads in the result bundle.

## Interpretation

- Accepted EPS measures API-to-Kafka admission, not completed detection.
- Pipeline visibility measures one sentinel and must be evaluated together
  with Kafka lag and processor throughput.
- Zero HTTP errors with dropped iterations means the generator could not
  sustain the requested rate; the run fails by design.
- A passing laptop smoke profile is not a university production capacity
  certificate.
- Capacity is certified only for the exact topology, resource allocation,
  retention state, ruleset, event mix, and software digests tested.
