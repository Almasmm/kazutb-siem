# Kubernetes deployment runbook

## Purpose

Deploy the KCSP stateless application plane to a production Kubernetes cluster
without embedding development-grade stateful services or plaintext secrets.

This runbook covers the API, event processor, SOAR worker, AI worker, and web
SOC console. PostgreSQL HA, ClickHouse, Kafka, MinIO, OIDC, DNS, ingress, TLS,
monitoring, and backup systems must already be available.

## Production boundary

The Helm chart is an application deployment contract, not a Kubernetes
distribution and not a database operator. Use supported operators or dedicated
external clusters for stateful dependencies. The local Compose Patroni profile
proves fencing behavior but is not installed by this chart.

The chart does not claim production readiness by itself. University acceptance
still requires capacity tests, failure injection, security review, data
retention approval, restore evidence, and operator training.

## Prerequisites

- Kubernetes 1.29 or newer with at least three worker nodes across failure
  domains.
- A CNI that enforces `networking.k8s.io/v1` NetworkPolicy.
- A default StorageClass for platform operators that need persistent storage.
- An ingress controller and a valid TLS certificate for the SOC hostname.
- PostgreSQL with a write endpoint, TLS, backups, and tested failover.
- ClickHouse, Kafka, and MinIO production clusters with TLS and authentication.
- An OIDC issuer reachable by both browsers and KCSP API pods.
- Immutable KCSP images in a registry accessible by the cluster.
- A Prometheus Operator only if ServiceMonitor is enabled.

## Namespace hardening

Create a dedicated namespace and enforce the restricted Pod Security Standard:

```sh
kubectl create namespace kcsp
kubectl label namespace kcsp \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

If private images are used, create a registry pull Secret through the approved
secret-management process and reference it in `imagePullSecrets`.

## Runtime secrets

Prefer External Secrets, Secrets Store CSI, or another university-approved
secret manager. The chart deliberately does not render Kubernetes Secret
objects.

The runtime Secret must contain these keys:

```text
database-url
clickhouse-url
kafka-envelope-hmac-key
minio-access-key
minio-secret-key
ai-local-api-key
ai-cloud-api-key
```

`kafka-envelope-hmac-key` must contain at least 32 bytes. API signs every raw
envelope and processor verifies it before persistence. Drain the raw topic
before rotating this key; API and processor must switch to the new value in one
controlled rollout so records signed with the previous key are not quarantined.

The AI keys may be absent when the corresponding provider is disabled. URLs
must enforce TLS and contain production credentials sourced from the secret
manager. Never place their values in Helm arguments, Git, CI logs, or shell
history.

SOAR connector credentials belong in a separate Secret whose keys are exact
environment variable names, for example `KCSP_CONNECTOR_SECRET_ITSM`. Set its
name in `secrets.connectorExistingSecret`.

For an internal PKI, create a ConfigMap containing the complete system CA
bundle plus the university roots, then set `trustBundle.existingConfigMap`.
The mounted file replaces the image CA bundle, so it must be complete.

## Values preparation

Create a protected values file outside the repository. It must contain only
non-secret configuration:

```yaml
images:
  api:
    repository: registry.example.edu/kcsp/api
    tag: "0.1.0"
    digest: "sha256:REPLACE_WITH_VERIFIED_DIGEST"

secrets:
  existingSecret: kcsp-runtime

config:
  auth:
    mode: oidc
    oidc:
      issuerURL: https://identity.example.edu/realms/kcsp
      clientID: kcsp
      rolesClaim: roles
      permissionClaim: permissions
      tenantClaim: tenant_id

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: soc.example.edu
      path: /
      pathType: Prefix
  tls:
    - secretName: kcsp-soc-tls
      hosts:
        - soc.example.edu

networkPolicy:
  externalEgressCidrs:
    - 10.20.30.10/32
    - 10.20.40.0/24
```

Set a verified digest for every image, not only the API. Restrict egress CIDRs
to PostgreSQL, ClickHouse, Kafka, MinIO, OIDC, and approved AI or connector
destinations. If a dependency runs inside Kubernetes, use `dataPlanePeers`
with namespace and pod selectors instead.

## Preflight

Run the chart contract test:

```sh
docker run --rm \
  -v "$PWD:/src" \
  -w /src \
  --entrypoint /bin/sh \
  alpine/helm:3.17.3 \
  ops/helm/self-test.sh
```

Render the exact production release and review it:

```sh
helm lint --strict deploy/helm/kcsp -f /secure/kcsp-values.yaml
helm template kcsp deploy/helm/kcsp \
  --namespace kcsp \
  -f /secure/kcsp-values.yaml > /secure/kcsp-rendered.yaml
```

Confirm that the render contains no `kind: Secret`, every image uses a digest,
and NetworkPolicy egress is restricted to approved destinations.

## Install or upgrade

```sh
helm upgrade --install kcsp deploy/helm/kcsp \
  --namespace kcsp \
  --atomic \
  --timeout 10m \
  --history-max 10 \
  -f /secure/kcsp-values.yaml
```

The `--atomic` flag rolls back failed upgrades. It does not replace database
backup, migration review, or application-level rollback planning.

## Acceptance checks

```sh
kubectl -n kcsp get deployments,pods,services,pdb,networkpolicy
kubectl -n kcsp rollout status deployment/kcsp-api --timeout=5m
kubectl -n kcsp rollout status deployment/kcsp-processor --timeout=5m
kubectl -n kcsp rollout status deployment/kcsp-soar-worker --timeout=5m
kubectl -n kcsp rollout status deployment/kcsp-ai-worker --timeout=5m
kubectl -n kcsp rollout status deployment/kcsp-web --timeout=5m
kubectl -n kcsp get events --sort-by=.lastTimestamp
```

Validate through the TLS hostname:

```sh
curl --fail --silent --show-error https://soc.example.edu/healthz
curl --fail --silent --show-error https://soc.example.edu/api/health/ready
```

Then verify:

- OIDC login and tenant-scoped authorization.
- Collector ingestion through the approved gateway.
- Kafka processing and ClickHouse event search.
- Alert-to-incident creation.
- Evidence upload and retrieval.
- SOAR approval and execution audit.
- Prometheus targets and alert delivery.
- A controlled pod eviction while PDB and topology spread are active.

## Rollback

List revisions and roll back only after checking schema compatibility:

```sh
helm history kcsp --namespace kcsp
helm rollback kcsp REVISION --namespace kcsp --wait --timeout 10m
```

If a release changed a database schema incompatibly, application rollback must
follow the reviewed database recovery plan. Do not improvise destructive SQL.

## Failure handling

- If pods remain Pending, inspect quotas, topology constraints, taints, and
  resource requests.
- If probes fail, check external dependency reachability and NetworkPolicy
  CIDRs before restarting pods.
- If OIDC fails, verify issuer TLS trust, audience/client ID, and clock sync.
- If workers are live but not progressing, inspect Kafka lag, database leases,
  and downstream availability.
- If an external stateful dependency fails, follow its dedicated failover or
  restore runbook. Reinstalling this chart does not recover data.

Record manifests, image digests, test output, alerts, timelines, and approvals
as deployment evidence in the change record.
