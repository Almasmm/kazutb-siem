#requires -Version 5.1
<#
    .SYNOPSIS
    Brings up the whole KCSP cyber range with one command.

    .DESCRIPTION
    Runs the full path: verify Hyper-V, create the isolated lab network and
    ingress, start the KCSP stack, build the golden Windows image, clone the
    endpoints, install Sysmon, build and install the agent from current source,
    enroll it, and confirm the first events are flowing.

    The only manual prerequisites are an official Windows ISO placed in
    <LabRoot>\ISOs and running this once from an elevated PowerShell.

    .EXAMPLE
    .\Bootstrap-KCSPLab.ps1
    .\Bootstrap-KCSPLab.ps1 -Count 4
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [int] $Count,
    [switch] $SkipStack,
    [switch] $SkipTests,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('bootstrap-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
if (-not $Count) { $Count = [int] $config.DefaultCount }

Write-KCSPLabLog "KCSP lab bootstrap - prefix $($config.Prefix), $Count endpoint(s)" -Level STEP
Write-KCSPLabLog "Config: $($config.ConfigPath)" -Level INFO
Write-KCSPLabLog "Lab root: $($paths.Root)" -Level INFO

# ------------------------------------------------------------ 1. prerequisites
if (-not (Test-KCSPLabElevated)) {
    Write-KCSPLabLog 'ELEVATION_REQUIRED' -Level ERROR
    throw 'ELEVATION_REQUIRED: Hyper-V, NAT, firewall and portproxy all need an elevated session. Re-run this from PowerShell started with "Run as Administrator".'
}

$hyperV = Get-KCSPLabHyperVStatus
Write-KCSPLabLog "Hyper-V: feature=$($hyperV.FeatureEnabled) vmms=$($hyperV.VmmsRunning) host=$($hyperV.HostReachable)" -Level INFO
if ($hyperV.FeatureEnabled -ne $true) {
    Write-KCSPLabLog 'Hyper-V is not enabled - enabling now' -Level STEP
    $needsReboot = Enable-KCSPLabHyperV
    if ($needsReboot) {
        Write-KCSPLabLog 'REBOOT_REQUIRED_FOR_HYPERV' -Level ERROR
        Write-KCSPLabLog 'Restart Windows, then run this script again. Nothing else has been changed.' -Level ERROR
        throw 'REBOOT_REQUIRED_FOR_HYPERV'
    }
}
if (-not $hyperV.HostReachable) {
    $retry = Get-KCSPLabHyperVStatus
    if (-not $retry.HostReachable) { throw "Hyper-V is enabled but not reachable: $($retry.Detail)" }
}

# ---------------------------------------------------------------- 2. lab plumbing
Initialize-KCSPLabNetwork -Config $config | Out-Null
$ingress = Set-KCSPLabIngress -Config $config
Write-KCSPLabLog "Lab ingress ready: $ingress" -Level PASS

# ------------------------------------------------------------------ 3. KCSP stack
if (-not $SkipStack) {
    Write-KCSPLabLog 'Starting the KCSP stack' -Level STEP
    Push-Location $config.RepoRoot
    try {
        & docker compose up -d | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "docker compose up failed ($LASTEXITCODE)" }
    } finally { Pop-Location }

    $ready = $false
    $deadline = (Get-Date).AddSeconds(420)
    while ((Get-Date) -lt $deadline) {
        try {
            $health = Invoke-RestMethod "http://127.0.0.1:$($config.ApiPort)/health/ready" -TimeoutSec 5
            if ($health.status -eq 'ready') { $ready = $true; break }
        } catch { }
        Start-Sleep -Seconds 5
    }
    if (-not $ready) { throw 'KCSP API did not become ready.' }
    Write-KCSPLabLog 'KCSP API ready' -Level PASS
}

# --------------------------------------------------------------- 4. golden image
$baseDisk = Join-Path $paths.Base "$($config.Prefix)-WIN-BASE.vhdx"
if ((Test-Path -LiteralPath $baseDisk) -and -not $Force) {
    Write-KCSPLabLog "Golden image already present" -Level INFO
} else {
    $isoPresent = $config.IsoPath -and (Test-Path -LiteralPath $config.IsoPath)
    if (-not $isoPresent) {
        $isoPresent = @(Get-ChildItem -LiteralPath $paths.ISOs -Filter *.iso -ErrorAction SilentlyContinue).Count -gt 0
    }
    if (-not $isoPresent) {
        Write-KCSPLabLog 'WINDOWS_ISO_REQUIRED' -Level ERROR
        Write-KCSPLabLog "Place an official Windows ISO in: $($paths.ISOs)" -Level ERROR
        Write-KCSPLabLog 'Everything after that step is automatic. Re-run this script once the ISO is in place.' -Level ERROR
        throw "WINDOWS_ISO_REQUIRED: expected an official Windows ISO in $($paths.ISOs)"
    }
    Write-KCSPLabLog 'Building the golden Windows image (one-time, several minutes)' -Level STEP
    & (Join-Path $PSScriptRoot 'New-KCSPWindowsBase.ps1') -ConfigPath $ConfigPath -Force:$Force | Out-Null
}

# ----------------------------------------------------------------- 5. endpoints
Write-KCSPLabLog "Creating $Count endpoint(s)" -Level STEP
& (Join-Path $PSScriptRoot 'New-KCSPWindowsVM.ps1') -ConfigPath $ConfigPath -Count $Count -Force:$Force | Out-Null

$credential = Get-KCSPLabCredential -Config $config
foreach ($vm in Get-KCSPLabVMs -Config $config) {
    Write-KCSPLabLog "Waiting for $($vm.Name) to finish first boot (Windows OOBE runs unattended)" -Level INFO
    Wait-KCSPLabGuest -VMName $vm.Name -Credential $credential -TimeoutSeconds 2400 | Out-Null
    # Snapshot the clean OS before anything is installed on top of it.
    if (-not (Get-VMSnapshot -VMName $vm.Name -Name 'CLEAN_WINDOWS' -ErrorAction SilentlyContinue)) {
        Checkpoint-VM -Name $vm.Name -SnapshotName 'CLEAN_WINDOWS'
        Write-KCSPLabLog "$($vm.Name) checkpoint CLEAN_WINDOWS created" -Level INFO
    }
}

# -------------------------------------------------- 6. Sysmon + agent + enrollment
Write-KCSPLabLog 'Installing Sysmon and the KCSP agent' -Level STEP
$deployed = & (Join-Path $PSScriptRoot 'Deploy-KCSPAgent.ps1') -ConfigPath $ConfigPath
foreach ($item in @($deployed)) {
    Write-KCSPLabLog "$($item.VM): service=$($item.Service) collector=$($item.CollectorId) version=$($item.Version)" -Level PASS
}

# --------------------------------------------------------------------- 7. verify
if (-not $SkipTests) {
    Write-KCSPLabLog 'Running end-to-end acceptance' -Level STEP
    & (Join-Path $PSScriptRoot 'Invoke-KCSPLabTests.ps1') -ConfigPath $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw 'End-to-end acceptance failed - see the report for the failing check.' }
}

Write-KCSPLabLog 'Lab bootstrap complete' -Level PASS
Write-KCSPLabLog "Status:  .\ops\lab\hyperv\Get-KCSPLabStatus.ps1" -Level INFO
Write-KCSPLabLog "Retest:  .\ops\lab\hyperv\Invoke-KCSPLabTests.ps1" -Level INFO
