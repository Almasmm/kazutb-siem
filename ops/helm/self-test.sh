#!/bin/sh
set -eu

chart="${1:-deploy/helm/kcsp}"
rendered="$(mktemp)"
extended="$(mktemp)"
trap 'rm -f "$rendered" "$extended"' EXIT

helm lint --strict "$chart"
helm template kcsp "$chart" \
    --namespace kcsp \
    --set-string secrets.existingSecret=kcsp-ci-runtime >"$rendered"

deployments="$(grep -c '^kind: Deployment$' "$rendered")"
if [ "$deployments" -ne 5 ]; then
    echo "expected 5 Deployments, rendered $deployments" >&2
    exit 1
fi
if grep -q '^kind: Secret$' "$rendered"; then
    echo "chart must not render plaintext Secret resources" >&2
    exit 1
fi
grep -q 'automountServiceAccountToken: false' "$rendered"
grep -q 'runAsNonRoot: true' "$rendered"
grep -q 'readOnlyRootFilesystem: true' "$rendered"
grep -q 'type: RuntimeDefault' "$rendered"
grep -q '^kind: NetworkPolicy$' "$rendered"
grep -q '^kind: PodDisruptionBudget$' "$rendered"
grep -q 'proxy_pass http://kcsp-api:8080;' "$rendered"

helm template kcsp "$chart" \
    --namespace kcsp \
    --api-versions monitoring.coreos.com/v1 \
    --set-string secrets.existingSecret=kcsp-ci-runtime \
    --set ingress.enabled=true \
    --set-string ingress.hosts[0].host=soc.kaztbu.kz \
    --set-string ingress.hosts[0].path=/ \
    --set-string ingress.hosts[0].pathType=Prefix \
    --set workloads.api.autoscaling.enabled=true \
    --set networkPolicy.monitoring.enabled=true \
    --set-string networkPolicy.externalEgressCidrs[0]=10.20.30.10/32 \
    --set-string trustBundle.existingConfigMap=kcsp-ca-bundle \
    --set-string secrets.connectorExistingSecret=kcsp-connectors \
    --set observability.serviceMonitor.enabled=true >"$extended"
grep -q '^kind: Ingress$' "$extended"
grep -q '^kind: HorizontalPodAutoscaler$' "$extended"
grep -q '^kind: ServiceMonitor$' "$extended"
grep -q 'name: kcsp-connectors' "$extended"
grep -q 'name: trust-bundle' "$extended"

if helm template kcsp "$chart" \
    --namespace kcsp \
    --set-string secrets.existingSecret= >/dev/null 2>&1; then
    echo "values schema accepted an empty runtime Secret name" >&2
    exit 1
fi

printf '%s\n' '{"status":"ok","test":"kcsp-helm-self-test","deployments":5}'
