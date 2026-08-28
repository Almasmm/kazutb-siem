#requires -Version 5.1
<#
    .SYNOPSIS
    The developer gate: unit tests, build, deploy to the lab, and prove it works.

    .DESCRIPTION
    One command to run after changing the agent or the data plane. It runs the
    portable test suites first (fast, no VM), then the Windows acceptance in the
    Hyper-V lab. A non-zero exit means the change is not ready to push.

    The Hyper-V half is skipped automatically when the lab is not available, so
    the same command still gives useful signal on a machine without the range -
    but it reports the skip rather than pretending the gate was green.

    .EXAMPLE
    .\Invoke-KCSPDevGate.ps1
    .\Invoke-KCSPDevGate.ps1 -IncludeChaos -IncludeUpgrade
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $SkipUnit,
    [switch] $SkipLab,
    [switch] $IncludeChaos,
    [switch] $IncludeUpgrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
$resultsRoot = Join-Path $config.RepoRoot '.artifacts\lab-results'
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('devgate-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))

$report = New-KCSPLabReport -Name 'KCSP developer gate'
$repo = $config.RepoRoot

function Invoke-Gate {
    param([string] $Name, [scriptblock] $Body, [switch] $Optional)
    $start = Get-Date
    try {
        & $Body
        $ok = ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE)
        $seconds = ((Get-Date) - $start).TotalSeconds
        Add-KCSPLabCheck -Report $report -Name $Name -Status $(if ($ok) { 'PASS' } else { 'FAIL' }) `
            -Detail $(if ($ok) { 'ok' } else { "exit code $LASTEXITCODE" }) -DurationSeconds $seconds
        return $ok
    } catch {
        $seconds = ((Get-Date) - $start).TotalSeconds
        Add-KCSPLabCheck -Report $report -Name $Name -Status $(if ($Optional) { 'SKIP' } else { 'FAIL' }) `
            -Detail $_.Exception.Message -DurationSeconds $seconds
        return [bool] $Optional
    }
}

# --------------------------------------------------------------- portable suites
if (-not $SkipUnit) {
    $go = (Get-Command go -ErrorAction SilentlyContinue).Source
    if (-not $go) {
        $local = Join-Path $repo '.tools\go\bin\go.exe'
        if (Test-Path -LiteralPath $local) { $go = $local }
    }
    if ($go) {
        Invoke-Gate 'go.vet' { Push-Location $repo; try { & $go vet ./... } finally { Pop-Location } } | Out-Null
        Invoke-Gate 'go.test' { Push-Location $repo; try { & $go test ./... -count=1 } finally { Pop-Location } } | Out-Null
    } else {
        Add-KCSPLabCheck -Report $report -Name 'go.test' -Status 'SKIP' -Detail 'no Go toolchain on PATH or in .tools\go'
    }

    Invoke-Gate 'web.test' { & npm --prefix (Join-Path $repo 'apps\web') run test --if-present } | Out-Null
    Invoke-Gate 'web.build' { & npm --prefix (Join-Path $repo 'apps\web') run build } | Out-Null
}

# ---------------------------------------------------------- Windows acceptance
$labAvailable = $false
if (-not $SkipLab) {
    if (-not (Test-KCSPLabElevated)) {
        Add-KCSPLabCheck -Report $report -Name 'lab.available' -Status 'SKIP' -Detail 'ELEVATION_REQUIRED for the Hyper-V half'
    } else {
        try {
            Get-VMHost -ErrorAction Stop | Out-Null
            $labAvailable = @(Get-KCSPLabVMs -Config $config).Count -gt 0
            Add-KCSPLabCheck -Report $report -Name 'lab.available' -Status $(if ($labAvailable) { 'PASS' } else { 'SKIP' }) `
                -Detail $(if ($labAvailable) { 'lab endpoints present' } else { 'no lab endpoints - run Bootstrap-KCSPLab.ps1' })
        } catch {
            Add-KCSPLabCheck -Report $report -Name 'lab.available' -Status 'SKIP' -Detail 'Hyper-V not reachable'
        }
    }
}

if ($labAvailable) {
    Invoke-Gate 'lab.deploy' { & (Join-Path $PSScriptRoot 'Deploy-KCSPAgent.ps1') -ConfigPath $ConfigPath | Out-Null } | Out-Null
    Invoke-Gate 'lab.e2e' { & (Join-Path $PSScriptRoot 'Invoke-KCSPLabTests.ps1') -ConfigPath $ConfigPath -IncludeDetection } | Out-Null
    if ($IncludeUpgrade) {
        Invoke-Gate 'lab.upgrade' { & (Join-Path $PSScriptRoot 'Upgrade-KCSPAgents.ps1') -ConfigPath $ConfigPath -SkipBuild } | Out-Null
    }
    if ($IncludeChaos) {
        Invoke-Gate 'lab.chaos' { & (Join-Path $PSScriptRoot 'Invoke-KCSPChaosTests.ps1') -ConfigPath $ConfigPath } | Out-Null
    }
}

$saved = Save-KCSPLabReport -Report $report -OutputRoot $resultsRoot
Write-KCSPLabLog "DEV GATE $($saved.Result) - $($saved.Passed) passed, $($saved.Failed) failed, $($saved.Skipped) skipped" `
    -Level $(if ($saved.Result -eq 'PASS') { 'PASS' } else { 'FAIL' })
Write-KCSPLabLog "Report: $($saved.Directory)" -Level INFO
$saved
if ($saved.Failed -gt 0) { exit 1 }
