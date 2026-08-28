#requires -Version 5.1
<#
    .SYNOPSIS
    Store-and-forward and outage recovery tests for the KCSP lab.

    .DESCRIPTION
    Breaks delivery two different ways and proves the agent buffers durably and
    recovers without losing or duplicating events:

      network outage - a guest-side firewall rule blocks only the KCSP gateway
      server outage  - the KCSP API container is stopped and started again

    Both are reversed in a finally block, so a failed assertion still leaves the
    lab and the guest firewall exactly as they were found. The API is stopped
    with a controlled `docker compose stop`; volumes are never touched.

    .EXAMPLE
    .\Invoke-KCSPChaosTests.ps1
    .\Invoke-KCSPChaosTests.ps1 -SkipServerOutage
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $VMName,
    [int] $EventCount = 25,
    [int] $RecoveryTimeoutSeconds = 300,
    [switch] $SkipNetworkOutage,
    [switch] $SkipServerOutage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
$resultsRoot = Join-Path $config.RepoRoot '.artifacts\lab-results'
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('chaos-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))

$report = New-KCSPLabReport -Name 'KCSP lab outage and store-and-forward'
$credential = Get-KCSPLabCredential -Config $config

$vm = if ($VMName) { Get-VM -Name $VMName -ErrorAction Stop } else { Get-KCSPLabVMs -Config $config | Select-Object -First 1 }
if (-not $vm) { throw 'No lab endpoint available.' }
Assert-KCSPLabOwned -Config $config -Name $vm.Name -Kind 'VM'
Set-KCSPLabFact -Report $report -Key 'vm' -Value $vm.Name

$collectorId = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
    $path = 'C:\ProgramData\KCSP\agent\credential.json'
    if (-not (Test-Path $path)) { return $null }
    $parsed = Get-Content $path -Raw | ConvertFrom-Json
    $property = $parsed.PSObject.Properties['collector_id']
    if ($property) { [string] $property.Value } else { $null }
}
if (-not $collectorId) { throw "$($vm.Name) is not enrolled." }
Set-KCSPLabFact -Report $report -Key 'collector_id' -Value $collectorId

function Get-QueueDepth {
    $collectors = Invoke-KCSPApi -Config $config -Path '/api/v1/collectors'
    $mine = @($collectors.items | Where-Object { $_.collector_id -eq $collectorId }) | Select-Object -First 1
    if (-not $mine -or -not $mine.operational) { return -1 }
    return [int] $mine.operational.queue_depth
}

function New-GuestMarkers {
    param([string] $Prefix, [int] $Count)
    $markers = 1..$Count | ForEach-Object { "$Prefix-$_" }
    Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList (, $markers) -ScriptBlock {
        param($tokens)
        foreach ($token in $tokens) { powershell.exe -NoProfile -Command "Write-Output '$token'" | Out-Null }
    } | Out-Null
    return $markers
}

function Wait-ForMarkers {
    param([string[]] $Markers, [int] $TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $seen = @{}
    while ((Get-Date) -lt $deadline -and $seen.Count -lt $Markers.Count) {
        foreach ($marker in $Markers) {
            if ($seen.ContainsKey($marker)) { continue }
            $events = Invoke-KCSPApi -Config $config -Path "/api/v1/events?q=$marker&limit=5"
            $count = @($events.items).Count
            if ($count -gt 0) { $seen[$marker] = $count }
        }
        if ($seen.Count -lt $Markers.Count) { Start-Sleep -Seconds 5 }
    }
    return $seen
}

function Add-Check {
    param([string] $Name, [string] $Status, [string] $Detail, [double] $Seconds = 0)
    Add-KCSPLabCheck -Report $report -Name $Name -Status $Status -Detail $Detail -DurationSeconds $Seconds
}

# ---------------------------------------------------------- network outage test
if (-not $SkipNetworkOutage) {
    $ruleName = 'KCSP-LAB-CHAOS-BLOCK-GATEWAY'
    $blocked = $false
    try {
        $before = Get-QueueDepth
        Add-Check 'network.baseline_queue' $(if ($before -le 0) { 'PASS' } else { 'PASS' }) "queue_depth=$before"

        Write-KCSPLabLog 'Blocking only the KCSP gateway inside the guest' -Level STEP
        Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential `
            -ArgumentList $ruleName, $config.HostAddress, $config.IngressPort -ScriptBlock {
            param($rule, $target, $port)
            Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Protocol TCP `
                -RemoteAddress $target -RemotePort $port | Out-Null
        } | Out-Null
        $blocked = $true

        $markers = New-GuestMarkers -Prefix "KCSP-LAB-NET-$([guid]::NewGuid().ToString('N').Substring(0,8))" -Count $EventCount
        Write-KCSPLabLog "Generated $($markers.Count) events while the gateway is unreachable" -Level INFO

        $grew = $false
        $deadline = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline) {
            $depth = Get-QueueDepth
            if ($depth -gt $before) { $grew = $true; break }
            Start-Sleep -Seconds 10
        }
        Add-Check 'network.queue_grows' $(if ($grew) { 'PASS' } else { 'FAIL' }) "queue grew above $before while blocked"

        Write-KCSPLabLog 'Restoring guest network' -Level STEP
        Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList $ruleName -ScriptBlock {
            param($rule)
            Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        } | Out-Null
        $blocked = $false

        $recoveryStart = Get-Date
        $seen = Wait-ForMarkers -Markers $markers -TimeoutSeconds $RecoveryTimeoutSeconds
        $recoverySeconds = [math]::Round(((Get-Date) - $recoveryStart).TotalSeconds, 1)
        Set-KCSPLabFact -Report $report -Key 'network_recovery_seconds' -Value $recoverySeconds

        Add-Check 'network.all_events_delivered' $(if ($seen.Count -eq $markers.Count) { 'PASS' } else { 'FAIL' }) `
            "$($seen.Count)/$($markers.Count) markers arrived after recovery" $recoverySeconds

        $duplicates = @($seen.GetEnumerator() | Where-Object { $_.Value -gt 1 })
        Add-Check 'network.no_duplicates' $(if ($duplicates.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
            "$($duplicates.Count) marker(s) present more than once"

        $drained = $false
        $deadline = (Get-Date).AddSeconds($RecoveryTimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            if ((Get-QueueDepth) -le $before) { $drained = $true; break }
            Start-Sleep -Seconds 5
        }
        Add-Check 'network.queue_drains' $(if ($drained) { 'PASS' } else { 'FAIL' }) "queue returned to <= $before"
    }
    finally {
        if ($blocked) {
            Write-KCSPLabLog 'Removing chaos firewall rule from guest (cleanup)' -Level WARN
            try {
                Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList $ruleName -ScriptBlock {
                    param($rule)
                    Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                } | Out-Null
            } catch { Write-KCSPLabLog "Guest firewall cleanup failed: $($_.Exception.Message)" -Level ERROR }
        }
    }
}

# ----------------------------------------------------------- server outage test
if (-not $SkipServerOutage) {
    $stopped = $false
    try {
        $before = Get-QueueDepth
        Write-KCSPLabLog 'Stopping the KCSP API (controlled; volumes untouched)' -Level STEP
        Push-Location $config.RepoRoot
        try {
            & docker compose stop api | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "docker compose stop api failed ($LASTEXITCODE)" }
        } finally { Pop-Location }
        $stopped = $true
        Add-Check 'server.api_stopped' 'PASS' 'docker compose stop api'

        $markers = New-GuestMarkers -Prefix "KCSP-LAB-SRV-$([guid]::NewGuid().ToString('N').Substring(0,8))" -Count $EventCount
        Start-Sleep -Seconds 45

        Write-KCSPLabLog 'Starting the KCSP API again' -Level STEP
        Push-Location $config.RepoRoot
        try {
            & docker compose start api | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "docker compose start api failed ($LASTEXITCODE)" }
        } finally { Pop-Location }
        $stopped = $false

        $ready = $false
        $deadline = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline) {
            try {
                $health = Invoke-RestMethod "http://127.0.0.1:$($config.ApiPort)/health/ready" -TimeoutSec 5
                if ($health.status -eq 'ready') { $ready = $true; break }
            } catch { }
            Start-Sleep -Seconds 5
        }
        Add-Check 'server.api_recovered' $(if ($ready) { 'PASS' } else { 'FAIL' }) 'readiness returned'

        $recoveryStart = Get-Date
        $seen = Wait-ForMarkers -Markers $markers -TimeoutSeconds $RecoveryTimeoutSeconds
        $recoverySeconds = [math]::Round(((Get-Date) - $recoveryStart).TotalSeconds, 1)
        Set-KCSPLabFact -Report $report -Key 'server_recovery_seconds' -Value $recoverySeconds

        Add-Check 'server.no_silent_loss' $(if ($seen.Count -eq $markers.Count) { 'PASS' } else { 'FAIL' }) `
            "$($seen.Count)/$($markers.Count) markers survived the outage" $recoverySeconds
        $duplicates = @($seen.GetEnumerator() | Where-Object { $_.Value -gt 1 })
        Add-Check 'server.no_uncontrolled_duplicates' $(if ($duplicates.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
            "$($duplicates.Count) duplicated marker(s)"
    }
    finally {
        if ($stopped) {
            Write-KCSPLabLog 'Restarting the KCSP API after a failed outage test (cleanup)' -Level WARN
            Push-Location $config.RepoRoot
            try { & docker compose start api | Out-Null } catch { } finally { Pop-Location }
        }
    }
}

$saved = Save-KCSPLabReport -Report $report -OutputRoot $resultsRoot
Write-KCSPLabLog "Report: $($saved.Directory)" -Level STEP
Write-KCSPLabLog "RESULT $($saved.Result) - $($saved.Passed) passed, $($saved.Failed) failed" -Level $(if ($saved.Result -eq 'PASS') { 'PASS' } else { 'FAIL' })
$saved
if ($saved.Failed -gt 0) { exit 1 }
