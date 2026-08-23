# KCSP Helm chart

This chart deploys the stateless KCSP application plane:

- API
- Kafka event processor
- SOAR worker
- governed AI worker
- web SOC console

PostgreSQL, ClickHouse, Kafka, MinIO, the OIDC provider, ingress controller,
certificate management, and the Prometheus Operator are external dependencies.
Keeping stateful systems outside the application chart prevents accidental
single-node data stores from being presented as a production topology.

## Security model

- Runtime credentials are read only from an existing Kubernetes Secret.
- The chart never renders a `Secret` resource or accepts secret values.
- Service account token mounting is disabled.
- Containers run as non-root with `RuntimeDefault` seccomp, a read-only root
  filesystem, no Linux capabilities, and no privilege escalation.
- NetworkPolicy is default-deny. External egress is fail-closed until exact
  CIDRs or in-cluster data-plane peers are configured.
- Web traffic reaches the API through a release-aware internal Service.
- Public OIDC and tenant settings are mounted through runtime `config.js`, so
  one immutable web image digest can be promoted across environments.
- PodDisruptionBudgets, rolling updates, topology spread, probes, and optional
  HPA resources are included.

## Required Secret

`secrets.existingSecret` must contain:

| Key | Used by |
| --- | --- |
| `database-url` | API, processor, SOAR, AI |
| `clickhouse-url` | API, processor, AI |
| `kafka-envelope-hmac-key` | API, processor; minimum 32 bytes |
| `collector-oauth-client-id` | Network collector, when enabled |
| `collector-oauth-client-secret` | Network collector, when enabled |
| `minio-access-key` | API |
| `minio-secret-key` | API |
| `ai-local-api-key` | AI, optional |
| `ai-cloud-api-key` | AI, optional |

SOAR connector credentials can be supplied through
`secrets.connectorExistingSecret`. Its keys must already be valid KCSP
environment names such as `KCSP_CONNECTOR_SECRET_ITSM`.

The network collector is opt-in. Enable `workloads.collector.enabled`, set its
OIDC token endpoint and client credentials, restrict
`config.networkCollector.service.loadBalancerSourceRanges`, and choose UDP,
TCP, or mTLS listeners. Its durable spool uses an existing PVC or a
chart-managed RWO claim.

Do not commit a Secret manifest or plaintext values file. Use an external
secret operator, a hardware-backed secret manager, or a controlled bootstrap
process.

## Render locally

```sh
helm lint --strict deploy/helm/kcsp
helm template kcsp deploy/helm/kcsp \
  --namespace kcsp \
  --set secrets.existingSecret=kcsp-runtime
```

Run the repository contract test:

```sh
sh ops/helm/self-test.sh
```

## Production configuration

Before installation:

1. Replace all image tags with immutable digests.
2. Configure the university OIDC issuer and client ID.
3. Configure Kafka and MinIO endpoints.
4. Add exact data-plane and identity-provider CIDRs to
   `networkPolicy.externalEgressCidrs`, or define `dataPlanePeers`.
5. Configure an ingress hostname and TLS Secret.
6. Enable ServiceMonitor only when its CRD is installed.
7. Confirm backups and restore drills for all external stateful systems.

See `docs/runbooks/kubernetes-deployment.md` for the operational procedure.
