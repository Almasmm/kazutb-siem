# MISP and OpenCTI provider feeds

KCSP can pull indicators from MISP and OpenCTI into the same normalized threat intelligence domain used by STIX import, event matching, and retrosearch.

## Register a feed

Open **Threat intelligence**, select **New feed**, and configure:

- provider: `MISP` or `OPENCTI`
- provider base URL over HTTPS
- refresh interval from 60 to 604800 seconds
- default confidence and feed tags
- `auth_reference` using `env://`, `vault://`, or `k8s://`

The credential value is never persisted. The built-in runtime resolves `env://KCSP_TI_FEED_SECRET_*`; Vault and Kubernetes references remain in `CREDENTIALS_REQUIRED` until the corresponding secret provider is enabled in the deployment.

## Provider contracts

MISP uses `POST /attributes/restSearch` with bounded JSON pagination and `GET /servers/getVersion` for health. The MISP API key is sent in the `Authorization` header.

OpenCTI uses fixed GraphQL queries over `POST /graphql`, Relay cursors, and Bearer authentication. KCSP parses provider STIX patterns through its existing STIX 2.1 parser rather than maintaining a second IOC normalizer.

## Scheduling and failure handling

Every API replica may run the feed scheduler. PostgreSQL leases with `FOR UPDATE SKIP LOCKED` ensure that one worker owns a feed at a time. Each run persists:

- sync and health status
- opaque provider cursor
- last and next sync timestamps
- imported, deduplicated, and rejected counts
- safe error class and detail

Provider failures are retried up to three times for network, HTTP 429, and HTTP 5xx responses. Failed runs are rescheduled according to the feed interval and recorded in the immutable audit chain. Redirects, embedded URL credentials, oversized responses, TLS below 1.2, and loopback/link-local destinations are rejected.

Use **Test connection** after binding a secret, then **Sync now** to queue an immediate run. A feed without available credentials remains explicitly `CREDENTIALS_REQUIRED`; KCSP does not substitute a fake provider.
