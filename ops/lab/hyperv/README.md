# KCSP Hyper-V cyber range

An automated Windows lab on the developer host, so agent changes can be built,
deployed, broken, recovered and verified without a second person copying files
to a physical PC.

Hyper-V only. Do not install VirtualBox: Docker Desktop and WSL already use the
Windows hypervisor platform, and a second hypervisor conflicts with it.

## What you provide, once

1. An official Windows ISO in `C:\Hyper-V\KCSP-LAB\ISOs` (Windows 11 Enterprise
   Evaluation is fine).
2. One elevated PowerShell session. Hyper-V, NAT, the firewall rule and the
   portproxy all require an administrator token.

Everything after that is automatic.

The automation is pinned to the development-only tenant `kcsp-lab` and uses
the tenant-scoped `kcsp-lab-admin` credential. Configuration loading and every
API call fail closed if another tenant (especially `university-kulazhanov`) is
supplied. The API creates `kcsp-lab` idempotently only when
`KCSP_LAB_BOOTSTRAP=true` in a `development` or `test` profile; production
rejects that setting.

```powershell
# from an elevated PowerShell, at the repository root
.\ops\lab\hyperv\Bootstrap-KCSPLab.ps1
```

That verifies Hyper-V, creates the isolated lab network and ingress, starts the
KCSP stack, builds the golden Windows image, clones the endpoints, installs
Sysmon, builds the agent from the current working tree, installs and enrolls it,
and runs the end-to-end acceptance.

## Daily loop

```powershell
.\ops\lab\hyperv\Get-KCSPLabStatus.ps1      # one-screen operational view
.\ops\lab\hyperv\Invoke-KCSPDevGate.ps1     # unit tests + build + deploy + E2E
.\ops\lab\hyperv\Invoke-KCSPLabTests.ps1    # end-to-end acceptance only
.\ops\lab\hyperv\Invoke-KCSPChaosTests.ps1  # network and server outage recovery
.\ops\lab\hyperv\Upgrade-KCSPAgents.ps1     # rebuild and upgrade in place
.\ops\lab\hyperv\Reset-KCSPLab.ps1          # restore a checkpoint and retest
```

Before any of that, and any time something looks wrong:

```powershell
.\ops\lab\hyperv\Test-KCSPLabPreflight.ps1  # runs unelevated; says what is blocking
```

Preflight separates "the tooling is broken" from "the host is not ready yet".

## How it avoids manual copying

Guests are driven over **PowerShell Direct** (`Invoke-Command -VMName`), which
rides the VMBus. No RDP, no network share, no open ports, no login. The agent
package moves with `Copy-VMFile`, falling back to a streamed PowerShell Direct
session when the Guest Service Interface is unavailable. Enrollment tokens are
issued through the KCSP API and consumed immediately, so no secret is ever typed
or stored on a guest.

Windows is installed once. The image is applied straight into a VHDX with DISM
rather than run through Windows Setup, so no setup screen is ever touched, and
each endpoint is a differencing disk over that base.

## Layout

| Path | Contents |
| --- | --- |
| `C:\Hyper-V\KCSP-LAB\Base` | golden VHDX |
| `C:\Hyper-V\KCSP-LAB\VMs` | per-endpoint differencing disks |
| `C:\Hyper-V\KCSP-LAB\ISOs` | Windows ISO you supply |
| `C:\Hyper-V\KCSP-LAB\Logs` | orchestration logs |
| `.lab\config.psd1` | your settings (gitignored) |
| `.lab\secrets\` | lab administrator credential (gitignored) |
| `.artifacts\lab-results\` | run reports (gitignored) |

Nothing under `C:\Hyper-V` is in the repository, and no credential is ever
committed or logged.

## Network

An internal switch `KCSP-LAB` with the host at `192.168.250.1` and endpoints at
`192.168.250.101+`. The KCSP API stays bound to `127.0.0.1`; a portproxy
publishes it at `192.168.250.1:18080`, and the firewall rule is scoped to the
lab subnet only. PostgreSQL, Kafka, ClickHouse, MinIO, Valkey and the Docker API
are never exposed to guests.

The lab is deliberately isolated from the university LAN.

## Safety

`Destroy-KCSPLab.ps1` requires `-ConfirmDestroy` and refuses to touch anything
whose name does not carry the lab prefix. Disks are only deleted from under the
lab VM directory. Docker volumes, KCSP data and the physical pilot endpoint
`kaztbu` are never in scope.

Destroy and reset operations also load the pinned tenant configuration before
doing any work. They have no caller-selectable database tenant and cannot reset
or delete `university-kulazhanov`, its collector, or its backlog.

The physical pilot is for milestone acceptance. Day-to-day regression belongs
here.

## Scaling

`-Count` controls how many endpoints exist; the default is 1 and the naming and
addressing are computed, not hardcoded.

```powershell
.\ops\lab\hyperv\Bootstrap-KCSPLab.ps1 -Count 4
.\ops\lab\hyperv\New-KCSPWindowsVM.ps1 -Count 4 -StartIndex 2
```
