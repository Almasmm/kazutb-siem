# Native SOAR ITSM connectors

KCSP supports provider-aware ServiceNow and Jira Cloud ticket actions through the `ITSM_REST` connector kind. The legacy `GENERIC` provider remains available for existing webhook-style integrations.

## Security contract

- Use an HTTPS base URL without credentials, query parameters, or fragments.
- Bind credentials through `secret_ref`; KCSP never stores the credential value in connector settings.
- Use `BASIC` with `username:password` or `email:api_token`, `BEARER`, or `API_KEY` according to the provider deployment.
- Run **Test connection** before enabling a connector for LIVE playbooks.
- Keep the connector action allowlist and per-minute limit as narrow as possible.

Every native write is followed by a provider GET for the same ticket. A successful action is recorded in the durable SOAR action ledger with the external ticket ID/key and `verification_status=VERIFIED`. If a provider acknowledges a write but the read-after-write check fails, KCSP marks the action failed without automatically repeating the potentially non-idempotent write.

## ServiceNow

Use the instance base URL, for example `https://university.service-now.com`, and set `settings.provider` to `SERVICENOW`. KCSP uses the Incident Table API:

- `kcsp.ticket.create`: `POST /api/now/table/incident`
- `kcsp.ticket.update`: `PATCH /api/now/table/incident/{sys_id}`
- `kcsp.ticket.comment`: writes `work_notes` through the same PATCH endpoint
- `kcsp.ticket.close`: writes state `7`, close code, and close notes through PATCH

Update, comment, and close requests must supply the 32-character ServiceNow `sys_id` as `ticket_id`. Supported fields are intentionally allowlisted: title/summary, description/details, category, subcategory, assignment group, impact, and urgency.

## Jira Cloud

Use the site base URL, for example `https://university.atlassian.net`, set `settings.provider` to `JIRA`, and configure:

- `project_key`: required project key, such as `SOC`
- `issue_type`: issue type name, default `Task`
- `close_transition_id`: required when `kcsp.ticket.close` is allowed

KCSP uses Jira REST API v3 issue, comment, and transition resources. Description and comment text is encoded as Atlassian Document Format. Update, comment, and close requests accept `ticket_key` or a numeric `ticket_id`.

## Action parameters

| Action | Required parameters | Optional parameters |
| --- | --- | --- |
| `kcsp.ticket.create` | `title` or `summary` | `description`, `priority`, provider-specific allowlisted fields |
| `kcsp.ticket.update` | `ticket_id` or `ticket_key`, plus at least one supported field | `title`, `description`, `priority`, `labels` |
| `kcsp.ticket.comment` | `ticket_id` or `ticket_key`, `comment` | none |
| `kcsp.ticket.close` | `ticket_id` or `ticket_key` | `reason` |

Provider response bodies are limited to 64 KiB, action payloads to 1 MiB, redirects are rejected, TLS 1.2 or newer is required, and the default transport rejects loopback, link-local, multicast, and unspecified destinations.
