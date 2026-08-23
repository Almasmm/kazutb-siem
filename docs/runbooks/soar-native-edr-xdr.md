# Native EDR/XDR connectors

KCSP supports provider-native response actions for Microsoft Defender for Endpoint and CrowdStrike Falcon while retaining `EDR_XDR_REST` with provider `GENERIC` for existing integrations.

## Security contract

- Native providers require `OAUTH2_CLIENT_CREDENTIALS`; static bearer tokens are rejected.
- KCSP stores only an `env://`, `vault://`, or `k8s://` secret reference. The resolved JSON credential document is never persisted or returned by the API.
- Provider origins are allowlisted. Microsoft Defender uses `https://api.security.microsoft.com`; Falcon supports its documented commercial and government API clouds.
- OAuth tokens are cached in worker memory only and expire before the provider token lifetime.
- Redirects, loopback/link-local destinations, plaintext HTTP, oversized responses, and provider endpoints with custom paths or ports are rejected.
- Existing SOAR allowlists, server-side risk classification, approval policy, durable rate limits, retries, action ledger, and immutable audit remain authoritative.

## Microsoft Defender for Endpoint

Create an Entra application with application permissions `Machine.Isolate` and `Machine.Read.All`, grant tenant admin consent, and bind this secret document:

```json
{"tenant_id":"00000000-0000-0000-0000-000000000000","client_id":"11111111-1111-1111-1111-111111111111","client_secret":"resolved-only-at-runtime"}
```

Configure:

- Kind: `EDR_XDR_REST`
- Provider: `MICROSOFT_DEFENDER_ENDPOINT`
- Endpoint: `https://api.security.microsoft.com`
- Auth: `OAUTH2_CLIENT_CREDENTIALS`
- Actions: `endpoint.isolate`, `endpoint.release`

KCSP calls the provider isolate/unisolate endpoint, captures the returned `MachineAction` ID, and reads `/api/machineactions/{id}` before recording verification.

## CrowdStrike Falcon

Create an API client with `Hosts: READ` and `Hosts: WRITE`, then bind:

```json
{"client_id":"falcon-client-id","client_secret":"resolved-only-at-runtime","member_cid":"optional-32-character-member-cid"}
```

Configure the Falcon cloud origin assigned to the tenant, provider `CROWDSTRIKE_FALCON`, and auth `OAUTH2_CLIENT_CREDENTIALS`. KCSP maps isolate/release to `contain`/`lift_containment`, records the Falcon trace ID, and reads host details to verify containment state.

## Acceptance

1. Register the connector with a non-production provider tenant.
2. Run **Test connection** and confirm OAuth plus provider API health succeeds.
3. Execute an approved playbook against a designated test endpoint.
4. Confirm the action ledger contains provider, endpoint ID, action/trace ID, provider status, and `VERIFIED` or `ACKNOWLEDGED`.
5. Confirm the endpoint state in the provider console before enabling the connector for production playbooks.
