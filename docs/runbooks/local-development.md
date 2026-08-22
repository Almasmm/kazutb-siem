# Local development runbook

KCSP V0.1 is the `embedded-dev` profile: synchronous Go pipeline, in-memory state,
public demo credentials, and synthetic seed data. Restarting replaces current state
with the seed baseline. Never submit real university telemetry.

## Addresses and credentials

| Mode | Web | API |
|---|---|---|
| Compose | `http://127.0.0.1:3000` | `http://127.0.0.1:8080` |
| Native | `http://127.0.0.1:5173` | `http://127.0.0.1:8080` |

All business requests require `X-KCSP-Tenant-ID: university-kulazhanov` and a token:

| Token | Use |
|---|---|
| `kcsp-demo-collector` | ingest only |
| `kcsp-demo-l1` | read, Alert triage, Incident create |
| `kcsp-demo-l2` | read, Alert/Incident management, Audit |
| `kcsp-demo-auditor` | Audit and SOC read-only |
| `kcsp-demo-admin` | embedded administrator |

These are public fixtures, not secrets.

## Start

Compose:

```powershell
docker compose up --build
```

Or use two native terminals:

```powershell
go run ./cmd/api
```

```powershell
npm --prefix apps/web install
npm --prefix apps/web run dev
```

Verify health and authenticated overview:

```powershell
$kcspApi = 'http://127.0.0.1:8080'
$tenant = 'university-kulazhanov'
$l2Headers = @{
    Authorization = 'Bearer kcsp-demo-l2'
    'X-KCSP-Tenant-ID' = $tenant
}

Invoke-RestMethod "$kcspApi/health/live"
Invoke-RestMethod "$kcspApi/health/ready"
$overview = Invoke-RestMethod "$kcspApi/api/v1/overview" -Headers $l2Headers
$overview.platform
```

Expected profile: `embedded-dev`. Health is unversioned; business resources use
`/api/v1`.

## Exercise Event -> Incident

### Ingest the positive fixture

```powershell
$collectorHeaders = @{
    Authorization = 'Bearer kcsp-demo-collector'
    'X-KCSP-Tenant-ID' = $tenant
}

$result = Invoke-RestMethod `
    -Method Post `
    -Uri "$kcspApi/api/v1/events" `
    -Headers $collectorHeaders `
    -ContentType 'application/json' `
    -InFile '.\test\testdata\sysmon\powershell_positive.json'

$result | ConvertTo-Json -Depth 12
```

Expected HTTP 201 and:

- `duplicate: false`;
- `event.event_id` equals `fixture-sysmon-positive-001`;
- one PowerShell `finding` and one `alert`;
- server-set tenant/ingest time/raw hash and default collector/schema/parser lineage;
- Finding risk-factor sum equals its capped `risk_score` and includes T1059.001.

The endpoint accepts a canonical Event directly. It is not a raw Sysmon parser.

### Verify the negative fixture

```powershell
$negative = Invoke-RestMethod `
    -Method Post `
    -Uri "$kcspApi/api/v1/events" `
    -Headers $collectorHeaders `
    -ContentType 'application/json' `
    -InFile '.\test\testdata\sysmon\powershell_negative.json'

$negative | ConvertTo-Json -Depth 10
```

Expected: Event created, `findings` and `alerts` empty.

### Verify idempotency

Post the positive fixture again. Expected HTTP 200, `duplicate: true`, original Event,
and empty Findings/Alerts. Tenant counts must not increase for the duplicate.

### Read the created Alert

```powershell
$alertId = $result.alerts[0].alert_id
$alertResponse = Invoke-WebRequest `
    -Uri "$kcspApi/api/v1/alerts/$alertId" `
    -Headers $l2Headers
$alert = $alertResponse.Content | ConvertFrom-Json
$alertResponse.Headers.ETag
```

### Acknowledge the Alert

```powershell
$alertPatch = @{
    status = 'ACKNOWLEDGED'
    assignee = 'dev-analyst'
    comment = 'Synthetic V0.1 triage'
    version = $alert.version
} | ConvertTo-Json

$alert = Invoke-RestMethod `
    -Method Patch `
    -Uri "$kcspApi/api/v1/alerts/$alertId" `
    -Headers $l2Headers `
    -ContentType 'application/json' `
    -Body $alertPatch
```

Repeat that body with the old version: expected HTTP 412 and no accepted mutation.

### Create and progress an Incident

```powershell
$incidentBody = @{
    title = 'Synthetic encoded PowerShell investigation'
    summary = 'Local V0.1 contract exercise'
    assignee = 'dev-analyst'
    alert_ids = @($alertId)
} | ConvertTo-Json -Depth 5

$incident = Invoke-RestMethod `
    -Method Post `
    -Uri "$kcspApi/api/v1/incidents" `
    -Headers $l2Headers `
    -ContentType 'application/json' `
    -Body $incidentBody

$incidentPatch = @{
    status = 'TRIAGE'
    comment = 'Telemetry lineage reviewed'
    version = $incident.version
} | ConvertTo-Json

$incident = Invoke-RestMethod `
    -Method Patch `
    -Uri "$kcspApi/api/v1/incidents/$($incident.incident_id)" `
    -Headers $l2Headers `
    -ContentType 'application/json' `
    -Body $incidentPatch

$incident | ConvertTo-Json -Depth 12
```

The Incident must derive Alert/Finding/Event ids, MITRE, entity, severity, and risk;
timeline must show create and transition. Repeating POST with exactly the same Alert set
returns the existing Incident with HTTP 200.

## Verify authorization and audit

No token must return 401. The collector token reading Alerts must return 403. A non-admin
token with `X-KCSP-Tenant-ID: another-tenant` must return 403.

Inspect the volatile audit chain:

```powershell
$audit = Invoke-RestMethod "$kcspApi/api/v1/audit?limit=100" -Headers $l2Headers
$audit.chain_valid
$audit.items | Select-Object action,resource_type,resource_id,previous_hash,hash
```

Expected `chain_valid: true`, with each non-first entry referencing its predecessor.
This chain is in memory, unkeyed, recomputable, and not WORM or forensic evidence.

## Test and validate

```powershell
go test -race ./...
npm --prefix apps/web run typecheck
npm --prefix apps/web run test
npm --prefix apps/web run build
```

Optional contract checks when approved tooling/network access is available:

```powershell
npx --yes @redocly/cli lint api/openapi/kcsp-v0.1.yaml
npx --yes @asyncapi/cli@4.1.1 validate api/asyncapi/kcsp-v0.1.yaml
```

The AsyncAPI file is future-only. Successful validation does not mean Kafka or domain
notifications run in V0.1.

## Reset and stop

Restarting the API/Compose stack discards current memory and loads the synthetic seed
again; counts return to seed baseline, not zero. This is reset, not backup/restore.

Stop Compose without deleting future developer volumes:

```powershell
docker compose down
```

## Troubleshooting and safety

- If 401: check exact Bearer token spelling.
- If 403: check both permission and tenant header.
- If 412: GET the resource again and use its current `version`/ETag.
- If 409: inspect `allowed_transitions` on the Incident.
- If objects disappear: the API restarted; this is expected.
- If port 8080 is busy, stop the conflicting local process; do not expose V0.1 publicly.
- Do not add real credentials, connect collectors, disable browser security, or bind to
  a public interface to make this profile appear production-like.
