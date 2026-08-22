# KCSP V0.1 vertical slice

Status: executable development baseline  
Runtime profile: `embedded-dev`  
Production readiness: **no**

## Proven outcome

V0.1 implements one complete SIEM/SOC path:

```text
tenant-bound canonical Event
  -> normalization/defaulting
  -> stateless or five-in-five-minute threshold detection
  -> immutable Finding
  -> explainable risk score
  -> deduplicated Alert
  -> analyst-created Incident
  -> lifecycle timeline and per-tenant SHA-256 audit chain
```

The API pipeline is one Go process and executes synchronously against an in-memory
store. A React console consumes that API and supports Russian, Kazakh, and English.
Compose publishes the web console on loopback port 3000 and the API on loopback port
8080. This is a behaviorally useful slice, not a miniature production SIEM.

Normative contracts:

- [OpenAPI V0.1](../../api/openapi/kcsp-v0.1.yaml) describes executable HTTP behavior.
- [AsyncAPI V0.1](../../api/asyncapi/kcsp-v0.1.yaml) is a non-executable design target
  for a future Kafka port.

## Executable scope

V0.1 contains:

- a Go API process with synchronous application/domain calls;
- a tenant-aware in-memory repository;
- hard-coded demonstration Bearer principals, fine-grained permissions, and tenant
  membership checks using the required `X-KCSP-Tenant-ID` header;
- direct canonical Event ingest; the endpoint is not a raw Sysmon/CEF parser;
- server-controlled tenant and ingest time, raw SHA-256 provenance, and default
  collector/schema/parser metadata;
- stateless suspicious PowerShell detection (`KCSP-WIN-PS-001`);
- five authentication failures from one source within five minutes
  (`KCSP-AUTH-THRESHOLD-001`);
- deterministic risk factors, Finding creation, and 15-minute Alert aggregation;
- Alert assignment/triage with optimistic versions and SLA metadata;
- manual Incident creation, lifecycle validation, timeline, derived lineage, and SLA;
- per-tenant append-oriented SHA-256 linked AuditEntries with in-memory verification;
- synthetic seed data and positive/negative canonical-event fixtures;
- a React SOC console with RU/KK/EN dictionaries.

The demo Bearer values are public test fixtures embedded in the application. They are
not secrets and are not equivalent to OIDC, MFA, or production identity assurance.

## Runtime shape

```text
Browser/script
    |
    | Bearer demo token + required tenant header
    v
HTTP transport / permission and tenant checks
    |
    +-------------------+-------------------+
    |                   |                   |
Ingest canonical    Triage Alert       Manage Incident
Event                   |                   |
    |                    +---------+---------+
    v                              |
Normalize/default                 SOC service
    |                              |
Detect -> Finding -> Risk -> Alert |
    |                              |
    +---------------+--------------+
                    v
           tenant-keyed Memory adapter
         Events / Findings / Alerts / Incidents
              Rules / linked AuditEntries
```

There is no external message bus and no in-process notification abstraction in the
executable slice. The HTTP call invokes pipeline and repository code directly.

## Tenant and authorization boundary

Every versioned business endpoint requires both:

1. `Authorization: Bearer <demo-token>`; and
2. `X-KCSP-Tenant-ID: university-kulazhanov`.

The authenticator maps a token to a Principal, permission set, and allowed tenant set.
The server checks the operation permission and tenant membership before invoking the
handler. During ingest the server overwrites any decoded Event `tenant_id` with this
authorized context. Storage reads and writes are tenant-keyed.

| Demo principal | Intended V0.1 use |
|---|---|
| `kcsp-demo-collector` | canonical Event ingest only |
| `kcsp-demo-l1` | read SIEM/SOC data, triage Alerts, create Incidents |
| `kcsp-demo-l2` | L1 capabilities plus Incident updates and Audit reads |
| `kcsp-demo-auditor` | overview, Alert/Incident, and Audit reads |
| `kcsp-demo-admin` | all embedded permissions and all tenants |

This matrix is executable negative-test coverage, but static tokens in browser source
provide no production confidentiality or identity proof.

## Event processing semantics

`POST /api/v1/events` accepts a `CanonicalEvent`-shaped JSON document. At minimum the
domain requires `category` and `source.type`; repository fixtures provide an explicit
`event_id` for deterministic idempotency.

For a new event the pipeline:

1. takes tenant only from the authenticated server context;
2. generates a missing Event id and event time, and always sets current ingest time;
3. supplies development collector, OCSF-compatible schema, and embedded parser defaults;
4. serializes a small canonical subset when raw message is absent;
5. computes `raw.hash` from the raw message and supplies an `embedded://` reference;
6. stores the immutable Event under the authorized tenant;
7. evaluates both embedded detection paths;
8. stores each Finding, sums/caps its named risk factors, and creates or aggregates an
   Alert using rule plus primary entity as the deduplication key;
9. appends a linked AuditEntry for Alert creation/update; and
10. returns Event, Findings, Alerts, and `duplicate: false` with HTTP 201.

If the same tenant already contains `event_id`, the endpoint returns the stored Event,
empty Findings/Alerts, `duplicate: true`, and HTTP 200. Idempotency is process-local and
disappears with the in-memory state.

No asset/identity directory lookup occurs. Risk context such as device criticality and
privileged-user status comes directly from the canonical Event submitted by the caller
or from synthetic seed content. Trust policy for that enrichment is future work.

## Domain boundaries

### Event

An Event is an immutable normalized telemetry fact. It separates event time from
ingest time and records source, canonical security fields, raw provenance, and parser
metadata. No Event update/delete endpoint exists.

### Finding

A Finding is an immutable rule match referencing one Event and one exact Rule version.
It contains matched fields, MITRE techniques, confidence, and an explainable risk
breakdown. V0.1 exposes only the tenant-filtered Finding collection.

### Alert

An Alert is an analyst triage aggregate over Findings/Events for a rule and entity.
States are `NEW`, `ACKNOWLEDGED`, `IN_PROGRESS`, and `CLOSED`. Closing requires a
disposition. GET/PATCH responses expose an integer version and ETag. A stale expected
version returns HTTP 412; an illegal transition returns HTTP 409.

### Incident

An Incident is explicitly created from at least one existing Alert. Severity, maximum
risk, Finding/Event ids, entities, and MITRE techniques are derived from those Alerts.
The same normalized Alert set is idempotent. The lifecycle is:

```text
NEW -> TRIAGE -> INVESTIGATION -> CONTAINMENT -> ERADICATION -> RECOVERY -> CLOSED
                         |              |                         ^
                         +-----------> RECOVERY ------------------+
```

The implementation also permits the documented early close transitions from TRIAGE
or INVESTIGATION. Closing requires disposition and reason. Accepted state, assignment,
and comment changes append timeline and Audit entries.

### DetectionRule

The two rules are embedded and read-only. V0.1 has no rule mutation/detail endpoint,
general Sigma compiler, correlation DSL, or historical executor. The Sigma source file
documents the PowerShell rule; the Go executor is the executable subset.

### AuditEntry

Each tenant has an ordered in-memory audit list. An entry includes `previous_hash` and
an unkeyed SHA-256 over selected canonical fields and metadata. `GET /api/v1/audit`
returns `chain_valid` after recomputation. This detects accidental in-memory chain
corruption but is volatile, recomputable by a writer, not HMAC-signed, and not WORM or
forensic evidence.

## Executable HTTP surface

| Resource | Operations |
|---|---|
| Session | `GET /api/v1/session` |
| Overview | `GET /api/v1/overview` |
| Events | `GET/POST /api/v1/events`, `GET /api/v1/events/{eventID}` |
| Findings | `GET /api/v1/findings` |
| Alerts | `GET /api/v1/alerts`, `GET/PATCH /api/v1/alerts/{alertID}` |
| Incidents | `GET/POST /api/v1/incidents`, `GET/PATCH /api/v1/incidents/{incidentID}` |
| Rules | `GET /api/v1/rules` |
| Audit | `GET /api/v1/audit` |
| Health | `GET /health/live`, `GET /health/ready` |
| Metrics | `GET /metrics` (development exposition only) |
| Demo lifecycle | `POST /api/v1/demo/reset` (platform-admin fixture only) |

List responses contain `items` and `total`; limits default to 100 and cap at 500. The
embedded search parameters are bounded substring/equality filters, not CQL.

## Current ports and production intent

| Boundary | Executable `embedded-dev` | Intended production adapter/status |
|---|---|---|
| Identity and tenant | demo Bearer Principal + tenant membership/header | OIDC claims and trusted source binding; not implemented |
| Pipeline repository | Go interfaces implemented by Memory | split ClickHouse telemetry and PostgreSQL control adapters; not implemented |
| Event stream | direct synchronous calls; no port implementation | Kafka contract in AsyncAPI; not implemented |
| Raw event | inline message/hash/reference in Memory | protected S3-compatible archive; not implemented |
| Audit | volatile per-tenant unkeyed SHA-256 chain | transactional durable append/WORM or signed anchor; undecided |

Domain/application code must not import Kafka, ClickHouse, PostgreSQL, or OIDC SDK
types. Adding a named interface does not prove its security, delivery, transaction, or
performance properties.

## Acceptance requirements

V0.1 acceptance requires automated tests plus the local runbook to show:

1. API health succeeds and authorized overview reports `platform.profile:
   embedded-dev`.
2. Missing/unknown Bearer token returns 401, a token without the operation permission
   returns 403, and a valid non-platform token requesting another tenant returns 403.
3. The collector token posts the positive canonical fixture and receives HTTP 201 with
   one Event, one PowerShell Finding, and one Alert as separate objects.
4. Stored Event tenant equals the server-authorized tenant regardless of a payload
   tenant value; ingest time, raw hash/reference, and default lineage are server-set.
5. Finding references the exact Event/Rule version, maps T1059.001, and its risk factor
   sum (capped 0..100) equals the reported risk score.
6. The negative PowerShell fixture returns an Event with empty Findings and Alerts.
7. Repeating the same Event id returns HTTP 200 with `duplicate: true`, the original
   Event, empty Findings/Alerts, and unchanged aggregate counts.
8. Exactly the fifth authentication failure from one source within five minutes
   creates the threshold Finding/Alert and includes T1110; earlier observations do not.
9. Finding and Rule collection endpoints expose both rule paths; unsupported Finding
   or Rule detail routes are not part of the contract.
10. Alert PATCH uses body `version` or `If-Match`, enforces valid transitions and close
    disposition, returns an updated ETag, and returns 412 for a stale version.
11. Incident POST derives lineage/risk from existing Alerts; repeating the same Alert
    set returns the existing Incident with HTTP 200.
12. Incident PATCH enforces allowed transitions, closure fields, timeline creation,
    ETag/version behavior, HTTP 409 for illegal transitions, and HTTP 412 when stale.
13. Alert detection/triage and Incident create/update append tenant-scoped AuditEntries;
    `chain_valid` remains true and each non-first entry links to its predecessor hash.
14. Backend tests pass with the race detector, frontend typecheck/tests/build pass, and
    the RU/KK/EN locale dictionaries expose the same keys.
15. Restart/reset returns the profile to its synthetic seed baseline; it is documented
    as data replacement, not persistence or recovery.

No quarantine/parser-error flow, external/in-process notification, enrichment lookup,
EPS, latency, availability, durability, replay, or recovery claim is part of V0.1
acceptance.

## Explicit exclusions

V0.1 does **not** provide:

- production OIDC/SAML, MFA, secret credentials, token rotation, or production RBAC;
- TLS/mTLS, collector identity, rate limiting, or untrusted-network deployment;
- raw Sysmon/XML/CEF/LEEF parsing, WEF, Syslog, endpoint agents, parser quarantine/DLQ,
  parser version management, or Parser Studio;
- durable queue, Kafka transport, notification delivery, replay, backpressure, or
  cross-process ordering;
- ClickHouse/PostgreSQL/S3/Valkey, migrations, backup/restore, HA, failover, or DR;
- trusted CMDB/identity enrichment, Threat Intelligence, IOC matching, UEBA, or entity graph;
- full OCSF validation, CQL, arbitrary Sigma compilation, temporal/sequence detection,
  or durable correlation state;
- Cases, Evidence/custody, reports, SOAR, privileged response, AI SOC, licensing, MSSP,
  air-gap packaging, or supported sizing.

Review [the threat model](../security/threat-model.md) before changing network exposure
or using any non-synthetic data. The structural rationale is in
[ADR-0001](../adr/0001-modular-monolith.md).
