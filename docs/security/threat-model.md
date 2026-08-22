# Threat model: KCSP V0.1 `embedded-dev`

Status: development threat model  
Production authorization: **denied**

## Security statement

V0.1 uses hard-coded demonstration Bearer tokens, permission checks, required tenant
membership, a synchronous Go pipeline, and tenant-keyed in-memory state. These controls
make authorization behavior testable; they do not make the profile safe for real
telemetry. Tokens are public fixtures, HTTP state is volatile, and there is no OIDC,
MFA, TLS, secret rotation, durable audit, or storage isolation.

Run only on loopback with synthetic data. Kafka, ClickHouse, PostgreSQL, and OIDC are
future designs, not compensating controls available to this runtime.

## Assets and trust boundaries

Assets are canonical Event integrity/provenance, Finding/Rule lineage, explainable risk,
Alert/Incident lifecycle state, tenant separation, and audit history.

```text
Browser/script
  | Boundary A: HTTP + public demo Bearer + tenant header
  v
AuthN / permission / tenant-membership middleware
  | Boundary B: caller canonical fields -> server-owned tenant/time/hash/defaults
  v
Synchronous pipeline and SOC aggregates
  | Boundary C: domain calls -> tenant-keyed in-memory repository
  v
Events / Findings / Alerts / Incidents / linked AuditEntries
```

Boundary A is useful only on loopback. CORS is a browser policy, not an authentication
boundary. Boundary B receives attacker-controlled canonical fields, including claimed
privilege and asset criticality; V0.1 has no trusted enrichment lookup. Boundary C is a
code seam, not process or storage isolation.

## Threats and current controls

| ID | Threat | Executable V0.1 control | Residual risk |
|---|---|---|---|
| TM-01 | Missing/forged identity | Exact demo-token lookup; missing/unknown token returns 401 | Tokens are public and replayable; no identity proof |
| TM-02 | Excess privilege | Per-route permissions distinguish collector/L1/L2/auditor/admin | Static mapping; no MFA, lifecycle, expiry, or revocation |
| TM-03 | Cross-tenant access | Required tenant header checked against Principal membership; repository keyed by tenant | Only demo tenant coverage; admin is platform scoped; no DB/RLS test |
| TM-04 | Payload selects tenant | Ingest overwrites decoded `tenant_id` from authorized context | Input decoder tolerates extra canonical fields; contract clients must omit tenant |
| TM-05 | Duplicate creates repeated detections | Event id is tenant-local idempotency key | Dedup disappears on restart; caller controls Event id |
| TM-06 | Stale SOC write | Body version or ETag; stale version returns 412 | Missing version is tolerated by implementation; contract clients must always send one |
| TM-07 | Invalid lifecycle/mass assignment | Aggregate transition/closure checks; mutation decoders reject unknown fields | Canonical ingest is intentionally broader than mutation DTOs |
| TM-08 | Repudiation/audit modification | Actor/request id recorded; per-tenant `previous_hash`/SHA-256 chain is recomputed | Volatile, unkeyed, recomputable by a writer, no WORM/anchor |
| TM-09 | Raw telemetry disclosure | Permission/tenant checks, no-store header, no request-body logging | Authorized demo token can read inline raw synthetic message |
| TM-10 | Memory/CPU exhaustion | 1 MiB write-body limit, server timeouts, list cap 500, loopback publishing | No rate limit/quota; maps and threshold state grow until restart |
| TM-11 | Detection/risk spoofing | Findings/scores are server-generated | Caller supplies `is_privileged` and `criticality`; no trusted CMDB/identity source |
| TM-12 | Privileged response execution | No SOAR/action/shell/file/network callback endpoint exists | Future Response Plane needs a separate threat model |
| TM-13 | Browser abuse | Narrow local CORS allowlist, security headers, Compose/native loopback defaults | Local malware/process can call API and knows demo tokens |
| TM-14 | Stream/storage assumptions | Docs label all future adapters unimplemented | Direct calls do not test delivery, replay, transactions, or isolation |

## Mandatory V0.1 requirements

1. API and Compose host publishing default to `127.0.0.1`; do not recommend public bind.
2. Overview visibly reports `platform.profile: embedded-dev`.
3. Every `/api/v1` business operation requires Bearer authentication, its exact
   permission, and an allowed non-empty `X-KCSP-Tenant-ID`.
4. Event tenant, ingest time, raw hash, and generated defaults are server-owned.
5. Event idempotency is tenant-local; Event/Finding have no mutation/delete routes.
6. Alert/Incident contract clients send current version/ETag; stale writes return 412.
7. Invalid lifecycle returns 409; closure fields are enforced.
8. SOC mutations append actor/request-aware AuditEntries; Audit API reports chain validity.
9. Documentation calls the audit chain volatile, unkeyed, non-WORM, and non-forensic.
10. Write bodies are capped; list limits cap at 500; normal logs do not include bodies.
11. Only documented local UI origins receive CORS headers; wildcard CORS is forbidden.
12. No Event content can trigger filesystem, shell, identity, endpoint, or firewall action.
13. Fixtures contain only synthetic data; no real credentials, staff/student data, or logs.
14. AsyncAPI is labelled future-only; no message delivery/replay claim is permitted.

## Required security tests

- no token -> 401; unknown token -> 401;
- insufficient permission -> 403; unauthorized tenant -> 403;
- collector can ingest but cannot read Events/Alerts;
- L1 cannot update an Incident; L2 can;
- payload tenant cannot override server tenant;
- duplicate Event cannot create another Finding/Alert;
- stale Alert/Incident version -> 412 without accepted mutation;
- illegal transition -> 409; incomplete closure -> 422;
- Event/Finding/Rule mutation and privileged-action routes do not exist;
- audit chain remains valid across detection, triage, and Incident operations;
- oversized/invalid JSON is bounded and errors do not echo the full raw body;
- backend race tests and dependency/secret scans run in CI when configured.

## Production blockers

Before production, replace demo tokens with OIDC/MFA and scoped service identities;
test tenant isolation at API/query/cache/stream/storage layers; add TLS/mTLS, secret
rotation, rate limits/quotas, trusted enrichment policy, and durable storage. Kafka
requires authentication/authorization, partition isolation, schema compatibility,
at-least-once/idempotency, backpressure, quarantine, replay, and poison-message tests.
ClickHouse/PostgreSQL require least privilege, parameterized access, migrations,
retention, encryption, backup/restore, RLS/isolation, and failure tests. Audit requires
durable append semantics and an external signed/WORM anchor. Release gating also needs
SBOM, SAST/SCA/secret/container/IaC scans, artifact signing, threat-model review,
benchmark, restore/failure drills, and penetration testing.
