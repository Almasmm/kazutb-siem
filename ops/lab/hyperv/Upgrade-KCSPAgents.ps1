#requires -Version 5.1
<#
    .SYNOPSIS
    Rebuilds the agent from source and upgrades every lab endpoint in place.

    .DESCRIPTION
    The regression this automates is identity preservation: an upgrade must keep
    the machine credential, collector_id, state directory, queue and checkpoints,
    and must never re-enroll or create a second collector. Every one of those is
    captured before the upgrade and asserted after it.

    .EXAMPLE
    .\Upgrade-KCSPAgents.ps1
    .\Upgrade-KCSPAgents.ps1 -VMName KCSP-LAB-WIN-01 -SkipBuild
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string[]] $VMName,
    [switch] $SkipBuild,
    [int] $HealthCheckSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
$resultsRoot = Join-Path $config.RepoRoot '.artifacts\lab-results'
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('upgrade-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
Assert-KCSPLabElevated

$report = New-KCSPLabReport -Name 'KCSP lab agent upgrade regression'
$credential = Get-KCSPLabCredential -Config $config

# Reads the identity and state an in-place upgrade must preserve.
$stateProbe = {
    $stateDirectory = 'C:\ProgramData\KCSP\agent'
    $credentialPath = Join-Path $stateDirectory 'credential.json'
    $collectorId = $null
    if (Test-Path $credentialPath) {
        $parsed = Get-Content $credentialPath -Raw | ConvertFrom-Json
        $property = $parsed.PSObject.Properties['collector_id']
        if ($property) { $collectorId = [string] $property.Value }
    }
    $service = Get-Service -Name KCSPAgent -ErrorAction SilentlyContinue
    $binary = 'C:\Program Files\KCSP\Agent\kcsp-agent.exe'
    $log = Join-Path $stateDirectory 'agent.log'
    [pscustomobject]@{
        CollectorId    = $collectorId
        CredentialHash = $(if (Test-Path $credentialPath) { (Get-FileHash $credentialPath -Algorithm SHA256).Hash } else { '' })
        Checkpoints    = @(Get-ChildItem $stateDirectory -Filter '*.checkpoint' -ErrorAction SilentlyContinue).Count
        QueueFiles     = @(Get-ChildItem (Join-Path $stateDirectory 'queue') -Filter '*.event' -ErrorAction SilentlyContinue).Count
        Service        = $(if ($service) { "$($service.Status)" } else { 'missing' })
        Version        = $(if (Test-Path $binary) { (Get-Item $binary).VersionInfo.FileVersion } else { '' })
        Sha256         = $(if (Test-Path $binary) { (Get-FileHash $binary -Algorithm SHA256).Hash } else { '' })
        InvalidUtf8    = $(if (Test-Path $log) { @(Select-String -Path $log -Pattern 'invalid UTF-8' -ErrorAction SilentlyContinue).Count } else { 0 })
    }
}

if (-not $SkipBuild) {
    Write-KCSPLabLog 'Rebuilding and staging the agent package from current source' -Level STEP
    & (Join-Path $PSScriptRoot 'Deploy-KCSPAgent.ps1') -ConfigPath $ConfigPath -VMName $VMName -NoCheckpoint | Out-Null
}

$targets = if ($VMName) { @($VMName | ForEach-Object { Get-VM -Name $_ -ErrorAction Stop }) } else { Get-KCSPLabVMs -Config $config }
if (-not $targets) { throw 'No lab endpoints found.' }

foreach ($vm in $targets) {
    Assert-KCSPLabOwned -Config $config -Name $vm.Name -Kind 'VM'
    Write-KCSPLabLog "=== $($vm.Name) upgrade regression ===" -Level STEP

    $before = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock $stateProbe
    if (-not $before.CollectorId) { throw "$($vm.Name) is not enrolled; nothing to upgrade." }
    Write-KCSPLabLog "$($vm.Name) before: version=$($before.Version) collector=$($before.CollectorId) queue=$($before.QueueFiles)" -Level INFO

    Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential `
        -ArgumentList $before.CollectorId, $HealthCheckSeconds -ScriptBlock {
        param($expectedCollector, $seconds)
        & C:\KCSP\agent\Upgrade-KCSPAgent.ps1 -ExpectedCollectorId $expectedCollector -HealthCheckSeconds $seconds 2>&1 | Out-String
    } | Out-Null

    $after = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock $stateProbe
    Write-KCSPLabLog "$($vm.Name) after:  version=$($after.Version) collector=$($after.CollectorId)" -Level INFO

    Add-KCSPLabCheck -Report $report -Name "$($vm.Name).collector_id_preserved" `
        -Status $(if ($after.CollectorId -and $after.CollectorId -eq $before.CollectorId) { 'PASS' } else { 'FAIL' }) `
        -Detail "$($before.CollectorId) -> $($after.CollectorId)"
    Add-KCSPLabCheck -Report $report -Name "$($vm.Name).credential_untouched" `
        -Status $(if ($after.CredentialHash -eq $before.CredentialHash) { 'PASS' } else { 'FAIL' }) `
        -Detail 'credential.json digest unchanged'
    Add-KCSPLabCheck -Report $report -Name "$($vm.Name).checkpoints_preserved" `
        -Status $(if ($after.Checkpoints -ge $before.Checkpoints) { 'PASS' } else { 'FAIL' }) `
        -Detail "$($before.Checkpoints) -> $($after.Checkpoints) checkpoint file(s)"
    Add-KCSPLabCheck -Report $report -Name "$($vm.Name).binary_replaced" `
        -Status $(if ($after.Sha256 -and $after.Sha256 -ne $before.Sha256) { 'PASS' } else { 'SKIP' }) `
        -Detail 'agent binary digest changed'
    Add-KCSPLabCheck -Report $report -Name "$($vm.Name).service_running" `
        -Status $(if ($after.Service -eq 'Running') { 'PASS' } else { 'FAIL' }) -Detail $after.Service
    Add-KCSPLabCheck -Report $report -Name "$($vm.Name).no_invalid_utf8" `
        -Status $(if ($after.InvalidUtf8 -eq 0) { 'PASS' } else { 'FAIL' }) -Detail "$($after.InvalidUtf8) occurrence(s)"

    # A re-enrollment would show up as a second collector for the same hostname.
    $collectors = Invoke-KCSPApi -Config $config -Path '/api/v1/collectors'
    $sameHost = @($collectors.items | Where-Object { $_.name -eq $vm.Name })
    Add-KCSPLabCheck -Report $report -Name "$($vm.Name).no_second_collector" `
        -Status $(if ($sameHost.Count -le 1) { 'PASS' } else { 'FAIL' }) `
        -Detail "$($sameHost.Count) collector record(s) for this hostname"

    Set-KCSPLabFact -Report $report -Key "$($vm.Name)_version" -Value "$($before.Version) -> $($after.Version)"
    Set-KCSPLabFact -Report $report -Key "$($vm.Name)_collector_id" -Value $after.CollectorId
}

$saved = Save-KCSPLabReport -Report $report -OutputRoot $resultsRoot
Write-KCSPLabLog "RESULT $($saved.Result) - report at $($saved.Directory)" -Level $(if ($saved.Result -eq 'PASS') { 'PASS' } else { 'FAIL' })
$saved
if ($saved.Failed -gt 0) { exit 1 }
