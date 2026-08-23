# KCSP network collector

The KCSP network collector terminates device telemetry outside the API control
plane and forwards it through the same authenticated ingest endpoint used by
agents. It accepts RFC 5424/RFC 3164 Syslog, CEF, LEEF, Suricata EVE JSON, and
Zeek JSON over newline-delimited UDP or TCP. TLS mode requires mutual TLS.

## Production identity

Create a dedicated OIDC confidential client with the collector role and one
canonical `tenant_id` membership. Store its client ID and secret under the
Helm runtime Secret keys `collector-oauth-client-id` and
`collector-oauth-client-secret`. The collector uses the client-credentials
grant and refreshes access tokens before expiry. Do not provision analyst
permissions to this client.

## Listener policy

- Prefer mTLS TCP on port 6514 where devices support RFC 5425.
- Enable plain TCP or UDP only on a segmented management network.
- Restrict the LoadBalancer with `loadBalancerSourceRanges` and matching
  NetworkPolicy CIDRs.
- Keep UDP/TCP disabled when there is no approved source range.
- Register the OIDC subject in the KCSP collector registry before sending data.

## Durable spool

The collector writes every accepted message to `/var/lib/kcsp-collector` before
forwarding. Kubernetes uses an RWO PVC and `Recreate` deployment strategy so two
pods never mount and replay the same spool. Readiness stays healthy during a
temporary API outage while disk buffering remains available. If the configured
spool limit is reached, TCP listeners receive backpressure and the process
reports an error rather than silently acknowledging an unpersisted message.

## Acceptance

1. Send one canary per enabled protocol.
2. Confirm collector readiness and a zero/decreasing queue depth.
3. Confirm each canary in Events under the expected tenant and parser ID.
4. Deny the collector subject access to a second tenant and verify HTTP `403`.
5. Stop the API, send canaries, restart API, and verify ordered spool drain.

For a local Compose deployment, the last step is automated and guarded:

```bash
KCSP_COLLECTOR_FAULT_ACK=I_UNDERSTAND_API_WILL_STOP \
  bash ops/collector/fault-spool-recovery.sh
```

The script refuses non-loopback targets and restores the API through an exit
trap even when an assertion fails.
