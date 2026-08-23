# OIDC two-tenant isolation acceptance

## Purpose

Run this gate before onboarding an additional organization or promoting an IAM
change. It uses two real production OIDC identities to prove that each identity
can read its own KCSP tenant and cannot select the other tenant.

Unit tests and decoded JWT claims are preflight evidence only. KCSP returns PASS
only after the deployed API validates both token signatures, issuer, audience,
expiry, MFA assurance, RBAC, and tenant membership.

## Preconditions

- Use two distinct human test identities from the production OIDC issuer.
- Assign both identities the same approved SOC read role and require MFA.
- Give identity A membership only in tenant A and identity B only in tenant B.
- Ensure every default acceptance endpoint is licensed and enabled.
- Run from an approved administration host with trusted DNS and CA roots.

Do not use platform administrators, MSSP cross-tenant roles, demo tokens, shared
accounts, or tokens carrying both tenant memberships. Those identities are
expected to fail this isolation gate.

## Run

The binary is included in the signed KCSP platform image. Tokens are accepted
only from environment variables so they never appear in command arguments.

```sh
export KCSP_BASE_URL=https://soc.example.edu
export KCSP_TENANT_A=faculty-a
export KCSP_TENANT_B=faculty-b
export KCSP_OIDC_TOKEN_A='<short-lived OIDC token for identity A>'
export KCSP_OIDC_TOKEN_B='<short-lived OIDC token for identity B>'

kcsp-tenant-acceptance \
  -report /secure/acceptance/kcsp-oidc-tenant-isolation.json

unset KCSP_OIDC_TOKEN_A KCSP_OIDC_TOKEN_B
```

If KCSP uses a custom tenant claim, set `KCSP_OIDC_TENANT_CLAIM` to the same
claim configured on the API. Never use `-allow-loopback-http` outside a local
automated test.

The default gate checks overview, events, alerts, incidents, and cases. An
approved deployment may set `KCSP_ACCEPTANCE_ENDPOINTS` to another
comma-separated set of protected `/api/v1/` GET paths, but it must retain at
least one data-plane endpoint.

## PASS contract

For both identities, the tool requires:

- a structurally valid, unexpired JWT from the same HTTPS issuer;
- a distinct `sub` and exactly one expected canonical tenant membership;
- HTTP 200 from every protected endpoint for the identity's own tenant;
- HTTP 403 with `tenant_denied` for the other tenant;
- HTTP 403 with `tenant_denied` when the tenant header is missing;
- HTTP 403 with `tenant_denied` when duplicate tenant headers are sent.

Redirects are rejected to prevent bearer-token forwarding. Remote plaintext
HTTP is rejected. The JSON report contains no tokens, subjects, response bodies,
or claims and is written with owner-only permissions where supported.

Retain the report with the release digest, IdP configuration revision, operator
identity, change approval, and timestamp. This gate validates application-level
tenant authorization; it does not authorize direct analyst access to KCSP data
stores.
