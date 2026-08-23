# OIDC Authorization Trust Policy

KCSP validates the token signature, issuer, audience, expiry, MFA assurance and
tenant membership before it evaluates authorization. The canonical KCSP role
matrix is the default and authoritative permission source.

## Role mapping

Map university IdP groups to the configured roles claim. Use only documented
KCSP roles such as `soc_l1`, `soc_l2`, `soc_manager`, `tenant_admin`,
`detection_engineer`, `threat_hunter`, `auditor` and narrowly scoped service
roles. Unknown roles grant no permissions.

Tenant-scoped identities must carry at least one canonical membership in the
configured tenant claim. Platform and MSSP roles are exceptional cross-tenant
identities and require separate assignment, MFA and change approval.

## Direct permission claims

Direct grants from the configured permission claim and permission-like OAuth
scopes are disabled by default. This prevents a permissive IdP client or scope
mapping from silently bypassing the reviewed role matrix.

Enable them only with an explicit deployment decision:

```yaml
config:
  auth:
    oidc:
      allowDirectPermissions: true
```

When enabled, KCSP accepts only permission names already present in its
canonical permission catalog and applies normal permission implications. The
IdP client, group/scope mappings and token samples must be retained as security
change evidence. Never enable direct grants merely to work around a missing or
incorrect role mapping.
