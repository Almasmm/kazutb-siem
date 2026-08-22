# KCSP Windows lightweight agent

The agent reads the `Microsoft-Windows-Sysmon/Operational` channel with the
Windows-native `wevtutil` interface and forwards original event XML to the KCSP
ingest gateway. It does not normalize or run detections on the endpoint.

## Delivery guarantees

- Every event is fsynced to the local queue before its Event Log checkpoint is advanced.
- Queue files remain until KCSP returns a matching `202 QUEUED` receipt.
- A stable ID derived from computer and EventRecordID makes replay idempotent.
- The original `SystemTime` is sent as the event timestamp and retained through OCSF normalization.
- When the configured queue limit is reached, the checkpoint is retained so collection can resume without silently dropping events.

## Security configuration

Use a short-lived OIDC service token with only `siem.events.ingest`, plus a
client certificate issued to the registered collector identity. The agent
reloads the certificate and key for every new TLS handshake, allowing rotation
without restarting the process. Plain HTTP is rejected unless
`KCSP_AGENT_ALLOW_INSECURE_HTTP=true` is explicitly set for local development.

Required environment variables:

```text
KCSP_AGENT_SERVER_URL=https://soc.example.edu
KCSP_AGENT_TENANT_ID=university-kulazhanov
KCSP_AGENT_ACCESS_TOKEN=<collector-scoped token>
KCSP_AGENT_CA_FILE=C:\ProgramData\KCSP\pki\ca.pem
KCSP_AGENT_CERT_FILE=C:\ProgramData\KCSP\pki\agent.pem
KCSP_AGENT_KEY_FILE=C:\ProgramData\KCSP\pki\agent-key.pem
KCSP_AGENT_STATE_DIR=C:\ProgramData\KCSP\agent
```

Build the Windows binary from the repository root:

```powershell
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -o kcsp-agent.exe ./cmd/agent
```

Run it under a dedicated low-privilege Windows service account that has read
access to the Sysmon operational channel and write access only to its state
directory. Service installation and certificate enrollment are separate
deployment-plane operations; no long-lived secret should be embedded in the
binary or command line.
