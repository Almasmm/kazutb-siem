# Native Slack and Microsoft Teams notifications

KCSP supports native provider contracts in `NOTIFICATION_REST` connectors while retaining `GENERIC`, `SLACK`, and `TEAMS` legacy proxy modes.

## Slack Web API

Configure provider `SLACK_WEB_API`, endpoint `https://slack.com`, Bearer authentication, and a Slack conversation ID such as `C0123456789` in `settings.channel`. Bind the bot token through `secret_ref`.

KCSP calls `POST /api/chat.postMessage` with a deterministic `client_msg_id`, captures the returned timestamp, and verifies it through `GET /api/conversations.history` with `latest`, `inclusive`, and `limit=1`. Connection tests call `GET /api/auth.test`.

The Slack app needs the least-privilege scopes required to post to and read history from the selected conversation. Keep the connector allowlist restricted to `kcsp.notification.send`.

## Microsoft Teams Graph

Configure provider `TEAMS_GRAPH`, endpoint `https://graph.microsoft.com`, Bearer authentication, `settings.team_id`, and `settings.channel_id`. The access token is resolved from `secret_ref` and is never persisted.

KCSP sends a text message through:

`POST /v1.0/teams/{team-id}/channels/{channel-id}/messages`

It then verifies the returned message ID through:

`GET /v1.0/teams/{team-id}/channels/{channel-id}/messages/{message-id}`

Connection tests read the configured channel. Grant only the delegated or resource-specific permissions required for the selected team and channel. Microsoft Graph's standard channel send API is intended for messages people read, not bulk log transport; KCSP uses it only for actionable SOC notifications.

## Shared controls

- HTTPS and TLS 1.2 or newer
- secret binding with no credential material in connector settings
- provider-specific health checks
- connector timeout, retry policy, rate limit, and action allowlist
- 64 KiB response bound and safe error classification
- immutable SOAR action ledger with external message ID and `VERIFIED` status
- no automatic replay after a provider acknowledged a write but verification failed
