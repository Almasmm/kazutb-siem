# ADR-0001: Modular monolith with replaceable infrastructure ports

- Status: Accepted
- Date: 2026-08-17
- Scope: V0.1 `embedded-dev`

## Context

The first increment must prove Event -> Finding -> Alert -> Incident behavior without
first solving distributed deployment. The target product still requires independently
scalable ingest/storage workers and production identity later.

## Decision

Implement the V0.1 API pipeline as one Go modular monolith:

- synchronous application calls;
- tenant-keyed in-memory repositories;
- direct canonical Event input;
- embedded detection/risk executors;
- Alert and Incident aggregate services;
- hard-coded demo Bearer principals with permission and tenant-membership checks;
- volatile per-tenant SHA-256 linked AuditEntries;
- no executable message bus or notification publisher.

The React web console is a separate static client/development process, not a backend
service boundary.

Pipeline and SOC application code depend on repository interfaces owned by those
modules. Domain code does not import Kafka, ClickHouse, PostgreSQL, or OIDC SDKs. The
future Kafka boundary is documented in AsyncAPI but is not yet an implemented port.

| Boundary | V0.1 adapter | Production intent |
|---|---|---|
| Identity/tenant | demo Bearer Principal + required tenant header/membership | OIDC and trusted source binding |
| Security telemetry | tenant-keyed Memory repository | ClickHouse |
| Control state | tenant-keyed Memory repository | PostgreSQL |
| Stream | direct calls; none | Kafka |
| Raw content | inline Memory value/hash/reference | S3-compatible archive |

Names in the final column are direction, not accepted functionality.

## Module rules

1. HTTP handlers translate transport input/errors and call application services.
2. Event and Finding are immutable and remain distinct from Alert and Incident.
3. Tenant is derived from authenticated server context and overwrites payload tenant.
4. Alert/Incident mutation goes through aggregate transition rules.
5. Contract clients provide the current body version or ETag; stale state returns 412.
6. Accepted SOC mutations append audit in the same application operation.
7. IDs and clocks remain testable without infrastructure SDK types.
8. HTTP and future stream contracts are versioned independently from Go structs.
9. Demo security behavior must remain visibly `embedded-dev` and cannot be promoted as
   OIDC/MFA or production tenant isolation.
10. The unkeyed volatile audit chain cannot be described as WORM, signed, or forensic.

## Consequences

Positive:

- the complete behavior runs and tests without external infrastructure;
- domain/RBAC/tenant/lifecycle tests are fast and deterministic;
- measured needs can drive later deployment boundaries;
- production storage/identity adapters have explicit seams.

Negative:

- process restart loses events, correlation state, SOC state, and audit history;
- static demo tokens are public and provide no production identity assurance;
- direct calls conceal broker/database failure, retry, ordering, and transaction modes;
- repository interfaces alone do not prove ClickHouse/PostgreSQL suitability;
- Kafka is only a design contract, so no delivery/replay claim exists;
- migrating state requires new schemas, integration tests, and operational runbooks.

## Alternatives rejected

**Microservices first:** adds network, deployment, compatibility, and partial-failure
work before service boundaries are supported by evidence.

**Infrastructure first:** a Kafka/ClickHouse/PostgreSQL/OIDC stack would demonstrate
plumbing, not the required analyst outcome.

**Unstructured CRUD monolith:** sharing generic records across Event, Finding, Alert,
and Incident would erase lifecycle invariants and make future extraction harder.

## Extraction criteria

A module becomes separately deployed only with measured need for independent scale,
security/failure isolation, availability, or release lifecycle. Extraction requires a
new ADR, owned/versioned contract, authentication/authorization model, observability,
failure semantics, migration plan, and integration/load tests.

Separate decisions are required for Kafka partitioning/delivery/outbox, ClickHouse
schemas/retention, PostgreSQL transactions/RLS, OIDC claims, and durable audit anchoring.
