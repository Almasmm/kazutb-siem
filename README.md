# KCSP — Kulazhanov Cyber Security Platform

KCSP V0.1 is an executable SIEM/SOC vertical slice derived from the university master specification. It proves one complete analyst workflow:

```text
HTTP security event
  → tenant-bound canonical event
  → detection finding
  → explainable risk score
  → deduplicated alert
  → analyst-created incident
  → lifecycle + tamper-evident audit chain
```

This repository is a product foundation, not a production SIEM claim. The default `embedded-dev` profile is deliberately self-contained and synchronous so that the domain model, API, UI, security boundaries, and tests can be exercised before Kafka, ClickHouse, PostgreSQL, OIDC, and durable workers are introduced.

## Run it

With Docker Desktop running:

```bash
docker compose up --build
```

Open <http://localhost:3000>. The API is available at <http://localhost:8080> and is preloaded with a safe synthetic dataset.

For local development without containers:

```bash
go run ./cmd/api
npm --prefix apps/web install
npm --prefix apps/web run dev
```

Then open <http://localhost:5173>. Vite proxies `/api` to the API on port `8080`.

The development console uses the synthetic `kcsp-demo-l2` bearer identity and tenant `university-kulazhanov`. These credentials are hard-coded for this local profile only and must never be enabled in a deployed environment.

## Verify the vertical slice

Run all backend tests and the production frontend build:

```bash
go test -race ./...
npm --prefix apps/web run build
```

Send the positive Sysmon fixture with the ingest-only service credential:

```powershell
$headers = @{
  Authorization = 'Bearer kcsp-demo-collector'
  'X-KCSP-Tenant-ID' = 'university-kulazhanov'
}
Invoke-RestMethod `
  -Method Post `
  -Uri 'http://localhost:8080/api/v1/events' `
  -Headers $headers `
  -ContentType 'application/json' `
  -InFile '.\test\testdata\sysmon\powershell_positive.json'
```

The response contains separate `event`, `findings`, and `alerts` objects. Repeating the same `event_id` returns the original event with `duplicate: true` and creates no duplicate finding or alert.

## What V0.1 includes

- OCSF-compatible typed event envelope with original and ingest timestamps, parser lineage, raw SHA-256, and tenant context.
- Stateless suspicious PowerShell detection plus a five-failures-in-five-minutes authentication threshold.
- Explainable, deterministic risk factors and MITRE ATT&CK metadata.
- Alert grouping, assignment, triage, SLA metadata, optimistic concurrency, and manual promotion to an incident.
- Validated incident state machine from `NEW` through `CLOSED`; closure requires a disposition and reason.
- Fine-grained demo permissions, source/analyst credential separation, server-controlled tenant binding, and negative tenant tests.
- Per-tenant append-oriented SHA-256 audit chain with a verification endpoint.
- React/TypeScript SOC Console in Russian, Kazakh, and English.
- OpenAPI and AsyncAPI contracts, Sigma source content, architecture/security decisions, fixtures, and automated tests.

## Explicitly out of scope for this profile

- Durable queues, replay, DLQ, backpressure, and crash recovery.
- PostgreSQL RLS, ClickHouse analytics, Kafka streaming, S3 raw/evidence storage, and Valkey state.
- Production OIDC/MFA, mTLS collectors, secret rotation, rate limiting, HA/DR, and air-gapped packaging.
- Full Sigma compiler, CQL engine, Parser Studio, Cases/Evidence, SOAR, Threat Intelligence, UEBA, AI SOC, licensing, and MSSP operations.
- Any published EPS, latency, availability, or retention guarantee.

Those capabilities remain required by the master specification. Their intended boundaries and the next production milestone are described in [the vertical-slice architecture](docs/architecture/vertical-slice.md) and [ADR-0001](docs/adr/0001-modular-monolith.md).

## Repository map

```text
apps/web/             React/TypeScript analyst console
cmd/api/              KCSP API entry point
internal/core/        canonical domain objects
internal/pipeline/    normalization, detection, risk, alert aggregation
internal/soc/         alert triage and incident lifecycle
internal/store/       embedded development adapter and audit chain
internal/httpapi/     REST transport, RBAC, tenant enforcement, security headers
content/sigma/        detection-as-code source content
api/                  OpenAPI and AsyncAPI contracts
docs/                 architecture, ADR, threat model, and runbook
test/testdata/         positive and negative telemetry fixtures
```

## Design principles carried into the code

1. `Event`, `Finding`, `Alert`, and `Incident` are distinct lifecycle objects.
2. Tenant context is assigned by authenticated server context, never trusted from event payloads.
3. Detection does not automatically equal incident; the analyst controls escalation.
4. Risk decisions expose their contributing factors.
5. Optimistic versions protect mutable SOC objects from silent lost updates.
6. The Response Plane remains outside the ingest/API process; no privileged SOAR action exists in V0.1.
7. The embedded adapter is replaceable and is never presented as the production 10k-EPS architecture.

See the [local development runbook](docs/runbooks/local-development.md) for API credentials, health checks, reset behavior, and current operational limits.

