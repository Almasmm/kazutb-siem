#requires -Version 5.1
<#
    .SYNOPSIS
    One-screen operational view of the lab.

    .DESCRIPTION
    Shows the KCSP stack, every lab endpoint, its agent, source health, queue
    depth and the result of the last recorded end-to-end run. Read-only: it
    changes nothing and is safe to run at any time, elevated or not (Hyper-V
    rows are reported as unavailable without elevation).

    .EXAMPLE
    .\Get-KCSPLabStatus.ps1
    .\Get-KCSPLabStatus.ps1 -AsJson
#>
[CmdletBinding()]
param([string] $ConfigPath, [switch] $AsJson)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$rows = New-Object System.Collections.Generic.List[object]

function Add-Row {
    param([string] $Component, [string] $State, [string] $Detail = '')
    $rows.Add([pscustomobject]@{ component = $Component; state = $State; detail = $Detail })
}

# --------------------------------------------------------------- KCSP services
try {
    $ready = Invoke-RestMethod "http://127.0.0.1:$($config.ApiPort)/health/ready" -TimeoutSec 5
    Add-Row 'KCSP API' $(if ($ready.status -eq 'ready') { 'HEALTHY' } else { 'DEGRADED' }) "profile=$($ready.profile)"
} catch {
    Add-Row 'KCSP API' 'DOWN' $_.Exception.Message
}

Push-Location $config.RepoRoot
try {
    $compose = & docker compose ps --format '{{.Service}}|{{.Status}}' 2>$null
    foreach ($line in @($compose)) {
        if (-not $line) { continue }
        $parts = $line -split '\|', 2
        if ($parts.Count -lt 2) { continue }
        if ($parts[0] -in 'postgres', 'kafka', 'clickhouse', 'minio', 'valkey', 'processor') {
            Add-Row $parts[0] $(if ($parts[1] -like '*healthy*') { 'HEALTHY' } elseif ($parts[1] -like 'Up*') { 'UP' } else { 'DOWN' }) $parts[1]
        }
    }
} catch { } finally { Pop-Location }

# ------------------------------------------------------------------- endpoints
$hyperVAvailable = $true
try { Get-VMHost -ErrorAction Stop | Out-Null } catch { $hyperVAvailable = $false }

if (-not $hyperVAvailable) {
    Add-Row 'Hyper-V' 'UNAVAILABLE' $(if (Test-KCSPLabElevated) { 'Hyper-V not reachable' } else { 'run elevated to see VM state' })
} else {
    $vms = Get-KCSPLabVMs -Config $config
    if (-not $vms) { Add-Row 'Lab endpoints' 'NONE' 'run Bootstrap-KCSPLab.ps1' }
    foreach ($vm in $vms) {
        Add-Row $vm.Name "$($vm.State)" "uptime=$($vm.Uptime)"
    }
}

# --------------------------------------------------------------- agents in KCSP
try {
    $collectors = Invoke-KCSPApi -Config $config -Path '/api/v1/collectors'
    $labCollectors = @($collectors.items | Where-Object { $_.name -like "$($config.Prefix)-*" })
    if (-not $labCollectors) { Add-Row 'Lab agents' 'NONE' 'no lab collector has enrolled yet' }
    foreach ($collector in $labCollectors) {
        $operational = $collector.operational
        $state = if ($operational) { $operational.overall } else { $collector.health }
        Add-Row "KCSPAgent $($collector.version) @ $($collector.name)" $state "last_seen=$($collector.last_seen_at)"
        if ($operational) {
            Add-Row "  queue @ $($collector.name)" $(if ($operational.queue_depth -eq 0) { 'HEALTHY' } elseif ($operational.backlog_draining) { 'DRAINING' } else { 'BACKLOG' }) `
                "depth=$($operational.queue_depth) delivery=$($operational.delivery_rate_eps) evt/s"
        }
        foreach ($source in @($collector.health_metadata.source_health)) {
            Add-Row "  $($source.channel)" $source.state "checkpoint=$($source.checkpoint) read=$($source.events_read)"
        }
    }
} catch {
    Add-Row 'Lab agents' 'UNKNOWN' $_.Exception.Message
}

# ------------------------------------------------------------- last E2E result
$resultsRoot = Join-Path $config.RepoRoot '.artifacts\lab-results'
if (Test-Path -LiteralPath $resultsRoot) {
    $latest = Get-ChildItem -LiteralPath $resultsRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($latest) {
        $reportPath = Join-Path $latest.FullName 'report.json'
        if (Test-Path -LiteralPath $reportPath) {
            $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
            Add-Row 'Last E2E' $report.result "$($report.name) - $($report.duration_seconds)s at $($report.started_at)"
        }
    }
} else {
    Add-Row 'Last E2E' 'NEVER' 'no lab run recorded yet'
}

if ($AsJson) {
    $rows | ConvertTo-Json -Depth 4
} else {
    $rows | Format-Table -AutoSize @{ n = 'COMPONENT'; e = { $_.component }; width = 46 },
                                   @{ n = 'STATE'; e = { $_.state }; width = 12 },
                                   @{ n = 'DETAIL'; e = { $_.detail } }
}
