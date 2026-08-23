# KCSP Windows lightweight agent rollout

KCSP Agent 0.5 runs as a native Windows service named `KCSPAgent`. It reads the
Sysmon, Security, System, PowerShell, and Defender channels with Windows-native
interfaces and forwards original XML to the on-premise KCSP data plane. Parsing,
OCSF normalization, detection, risk, alerting, and incident creation stay on the
server; the endpoint remains a bounded collection and delivery component.

## Delivery guarantees

- Every event is fsynced to the local queue before its Event Log checkpoint is advanced.
- Queue files remain until KCSP returns a matching `202 QUEUED` receipt.
- A stable ID derived from computer and EventRecordID makes replay idempotent.
- The original `SystemTime` is sent as the event timestamp and retained through OCSF normalization.
- When the configured queue limit is reached, the checkpoint is retained so collection can resume without silently dropping events.

## Security and service model

- The service uses the virtual account `NT SERVICE\KCSPAgent`, not LocalSystem.
- The account is added to the built-in Event Log Readers group and receives
  `Modify` only on `C:\ProgramData\KCSP\agent`.
- A short-lived bootstrap token is passed only to the installer process. The
  installer runs `KCSP_AGENT_ENROLL_ONLY=true`, deletes a token file, and never
  writes the bootstrap token to the service registry or command line.
- The resulting opaque machine credential is stored in the private state
  directory and rotates automatically before expiry.
- HTTPS is mandatory outside an explicitly selected local lab. A campus CA can
  be packaged separately and copied into the protected state directory.
- Production installation should require a valid Authenticode signature and a
  SHA-256 value from the release manifest.
- JSON service logs rotate at 10 MiB with five local backups.

## Build a deployment package

From the repository root, cross-compile the binary and build a versioned ZIP:

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags '-s -w -X main.agentVersion=0.5.0' -o .artifacts\kcsp-agent.exe .\cmd\agent
.\ops\agent\windows\Build-KCSPWindowsPackage.ps1 `
  -Version 0.5.0 `
  -OutputDirectory .artifacts\windows `
  -PrebuiltBinary .artifacts\kcsp-agent.exe
```

For production, pass `-SigningCertificateThumbprint` to the package builder.
Distribute the ZIP and its out-of-band release digest through the university's
software distribution system. The package manifest protects every included
file; Authenticode establishes publisher identity.

## Prepare Sysmon offline

KCSP does not download or redistribute Sysmon. Obtain `Sysmon64.exe` through the
approved Microsoft software channel, transfer it through the university's
artifact process, and run:

```powershell
.\Install-KCSPSysmon.ps1 `
  -SysmonExecutable C:\Staging\Sysmon64.exe `
  -ExpectedSha256 '<approved Microsoft artifact digest>'
```

The script rejects a binary without a valid Microsoft Authenticode signature.
The included baseline intentionally collects process and network activity and
must first be measured in the lab; tune high-volume exclusions before broad
deployment without removing credential-access and persistence coverage.

## Install or upgrade the agent

Create one short-lived enrollment token per rollout wave. Never place it in a
GPO, shared script, command line, ticket, or inventory CSV. A deployment system
may create a local one-use file whose ACL grants only SYSTEM and Administrators;
the installer validates broad ACLs and deletes the file after the attempt.

```powershell
.\Install-KCSPAgent.ps1 `
  -ServerUrl https://soc.kaztbu.kz `
  -TenantId university-kulazhanov `
  -EnrollmentTokenFile C:\Windows\Temp\kcsp-enroll.token `
  -RequireAuthenticodeSignature `
  -NonInteractive
```

An upgrade preserves identity, credential, queue, and checkpoints. A fresh
non-interactive install fails closed when no bootstrap token is supplied.

## Generate a 2000+ host rollout plan

Prepare an inventory using `inventory.example.csv`, then generate deterministic
canary and bounded waves:

```powershell
.\New-KCSPRolloutPlan.ps1 `
  -InventoryPath .\campus-inventory.csv `
  -OutputDirectory .\rollout `
  -CanarySize 25 `
  -WaveSize 250
```

Critical or Tier-0 systems are ordered after standard endpoints. Recommended
holds and gates are:

1. Lab: 5 representative machines for 48 hours.
2. Canary: 25 non-critical machines for 48 hours.
3. Faculty/administrative waves: at most 250 machines with a 24-hour hold.
4. Server and critical infrastructure waves only after endpoint gates remain green.
5. Abort a wave if enrollment success is below 99%, online collectors below 98%, event latency p95 exceeds 60 seconds, queue growth is sustained, credential exposure is detected, or endpoint resource budgets are exceeded.

Issue each wave token with `max_uses` equal to the exact wave count and the
shortest operational TTL. Revoke it immediately after the wave, even when its
use count is not exhausted.

## Per-host acceptance

Run the acceptance probe after installation:

```powershell
.\Test-KCSPAgent.ps1 -ExpectedSha256 '<manifest binary digest>'
```

It returns non-zero on failed service, account, ACL, credential, Sysmon channel,
or KCSP reachability checks and writes a secret-free JSON report under the state
directory. Aggregate those reports in the deployment system before releasing
the next wave. In KCSP, confirm the collector is `ONLINE`, source identity is the
expected hostname, Sysmon test activity reaches ClickHouse, and the associated
detection creates an alert and incident.

## Live Windows/Sysmon pipeline acceptance

After the host-level probe is green, create a short-lived KCSP service account
with exactly `siem.events.read`, `siem.findings.read`, and `soc.alerts.read`.
Run the live gate from an elevated prompt on a representative university host:

```powershell
$token = Read-Host 'KCSP acceptance service token' -AsSecureString
.\Test-KCSPEndToEnd.ps1 `
  -ServerUrl https://soc.kaztbu.kz `
  -TenantId university-kulazhanov `
  -AccessToken $token `
  -ExpectedCollectorId $env:COMPUTERNAME
```

The gate starts a harmless local PowerShell process with a unique marker and
suspicious command-line indicators, then proves the server-side chain
`Sysmon event -> OCSF event -> KCSP-WIN-PS-001 finding -> alert`. It fails when
source identity or tenant binding is missing, the expected detection is absent,
or end-to-end latency exceeds the configured SLA. Its JSON report contains only
record identifiers and timings. Revoke the temporary service account after the
acceptance window.

## Rollback

Stop a rollout wave first and revoke its unused enrollment token. To remove the
binary while preserving queued telemetry and identity for diagnosis:

```powershell
.\Uninstall-KCSPAgent.ps1 -Confirm:$false
```

Use `-PurgeState` only after evidence and queue retention decisions are approved.
That switch permanently removes the machine credential, checkpoints, and local
queue, so reinstallation requires a new enrollment token.

## Runtime environment reference

Required environment variables:

```text
KCSP_AGENT_SERVER_URL=https://soc.example.edu
KCSP_AGENT_TENANT_ID=university-kulazhanov
KCSP_AGENT_ENROLLMENT_TOKEN=<first-run-only token>
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

The installer writes only non-secret runtime settings to the service-specific
`Environment` registry value. Do not configure a long-lived access token there.
