# KCSP tenant isolation

KCSP treats a tenant identifier as security-sensitive input, not as a display
name. The same canonical identifier crosses OIDC, HTTP, Kafka, PostgreSQL,
ClickHouse, and object-storage boundaries.

## Identity invariant

Tenant IDs are lowercase DNS-label-like values containing only `a-z`, `0-9`,
and internal hyphens. They are at most 63 bytes and must start and end with an
alphanumeric character. Display names remain unrestricted metadata and must
never be used as storage prefixes or authorization keys.

OIDC tokens carry memberships in `kcsp_tenants` or `tenant_id`. KCSP rejects
the complete token if any supplied membership is malformed. It does not drop a
bad membership and continue with the remaining claims. Platform-scoped
principals can select any existing tenant, but they cannot bypass canonical ID
validation.

## Request invariant

Every protected API request has exactly one `X-KCSP-Tenant-ID` header. Missing,
duplicated, proxy-merged, mixed-case, path-like, or otherwise malformed values
fail closed through the normal tenant-denied response. The trusted tenant is
stored in request context after authentication; payload tenant fields never
override it.

## Data invariant

Application queries and object identities use `(tenant_id, object_id)` keys.
Collectors are tenant-bound identities, parsers receive the trusted envelope
tenant, and asynchronous messages retain that tenant through detection, risk,
alert, incident, evidence, SOAR, UEBA, and AI SOC processing.

Before publishing, API authenticates the raw Kafka envelope with HMAC-SHA-256.
The signature binds tenant, collector, event and message identities, timestamps,
format, schema, content type, and payload SHA-256. Processor verifies both the
signature and payload hash before ClickHouse raw persistence. Unsigned or
modified records are quarantined in DLQ at the `envelope` stage.

Database owner credentials still represent a platform-wide trust boundary.
They must be limited to KCSP services and rotated through the deployment secret
store. Direct analyst access to PostgreSQL, ClickHouse, Kafka, or MinIO is not a
supported tenancy boundary.

## Acceptance gates

- Auth tests reject malformed OIDC memberships, including path-like values.
- HTTP tests reject duplicate and proxy-merged tenant headers.
- Pipeline tests prove that payload tenant fields cannot replace the trusted
  tenant.
- Store and service tests use same-ID and cross-tenant lookups for events,
  alerts, incidents, evidence, hunts, threat intelligence, SOAR, and UEBA.
- A deployment acceptance run must use two real OIDC tenant identities before
  onboarding an additional organization. Execute the fail-closed gate in
  [OIDC two-tenant isolation acceptance](../runbooks/oidc-tenant-acceptance.md)
  and retain its secret-free report with the release evidence.
