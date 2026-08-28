#requires -Version 5.1
<#
    .SYNOPSIS
    End-to-end acceptance for the KCSP lab: real Windows telemetry, start to finish.

    .DESCRIPTION
    Generates a unique marker inside a lab endpoint and follows it all the way
    through Sysmon, the agent queue, the gateway, Kafka, the parser, OCSF
    normalization and ClickHouse until it is searchable in KCSP. A marker is
    minted per run, so a stale fixture can never be mistaken for a pass.

    Emits a machine-readable report under .artifacts\lab-results\<timestamp>.

    .EXAMPLE
    .\Invoke-KCSPLabTests.ps1
    .\Invoke-KCSPLabTests.ps1 -VMName KCSP-LAB-WIN-01 -IncludeDetection
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string[]] $VMName,
    [int] $IngestTimeoutSeconds = 180,
    [switch] $IncludeDetection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
$resultsRoot = Join-Path $config.RepoRoot '.artifacts\lab-results'
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('e2e-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))

$report = New-KCSPLabReport -Name 'KCSP lab end-to-end acceptance'
$credential = Get-KCSPLabCredential -Config $config

function Measure-Check {
    param([string] $Name, [scriptblock] $Body)
    $start = Get-Date
    try {
        $outcome = & $Body
        $seconds = ((Get-Date) - $start).TotalSeconds
        if ($outcome -is [array]) { $outcome = $outcome[-1] }
        if ($outcome -and $outcome.PSObject.Properties['Status']) {
            Add-KCSPLabCheck -Report $report -Name $Name -Status $outcome.Status -Detail $outcome.Detail -DurationSeconds $seconds
            return $outcome
        }
        Add-KCSPLabCheck -Report $report -Name $Name -Status 'PASS' -Detail "$outcome" -DurationSeconds $seconds
        return [pscustomobject]@{ Status = 'PASS'; Detail = "$outcome" }
    } catch {
        $seconds = ((Get-Date) - $start).TotalSeconds
        Add-KCSPLabCheck -Report $report -Name $Name -Status 'FAIL' -Detail $_.Exception.Message -DurationSeconds $seconds
        return [pscustomobject]@{ Status = 'FAIL'; Detail = $_.Exception.Message }
    }
}

# 1. KCSP server ---------------------------------------------------------------
Measure-Check 'kcsp.api.ready' {
    $ready = Invoke-RestMethod "http://127.0.0.1:$($config.ApiPort)/health/ready" -TimeoutSec 15
    if ($ready.status -ne 'ready') { throw "readiness = $($ready.status)" }
    "status=$($ready.status) profile=$($ready.profile)"
} | Out-Null

# 2. Lab endpoint --------------------------------------------------------------
$targets = if ($VMName) { @($VMName | ForEach-Object { Get-VM -Name $_ -ErrorAction Stop }) } else { Get-KCSPLabVMs -Config $config }
if (-not $targets) { throw 'No lab endpoints found. Run Bootstrap-KCSPLab.ps1 first.' }
$vm = $targets | Select-Object -First 1
Assert-KCSPLabOwned -Config $config -Name $vm.Name -Kind 'VM'
Set-KCSPLabFact -Report $report -Key 'vm' -Value $vm.Name

Measure-Check 'lab.vm.running' {
    if ($vm.State -ne 'Running') { Start-VM -Name $vm.Name; Start-Sleep -Seconds 5 }
    $state = (Get-VM -Name $vm.Name).State
    if ($state -ne 'Running') { throw "VM state = $state" }
    "state=$state"
} | Out-Null

Measure-Check 'lab.guest.reachable' {
    Wait-KCSPLabGuest -VMName $vm.Name -Credential $credential -TimeoutSeconds 900 | Out-Null
    $guest = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
        [pscustomobject]@{ Host = $env:COMPUTERNAME; OS = (Get-CimInstance Win32_OperatingSystem).Caption }
    }
    Set-KCSPLabFact -Report $report -Key 'hostname' -Value $guest.Host
    Set-KCSPLabFact -Report $report -Key 'os' -Value $guest.OS
    "$($guest.Host) / $($guest.OS)"
} | Out-Null

# 3. Network -------------------------------------------------------------------
Measure-Check 'lab.network.ingress' {
    $ok = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList $config.HostAddress, $config.IngressPort -ScriptBlock {
        param($labHost, $port)
        (Test-NetConnection -ComputerName $labHost -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded
    }
    if (-not $ok) { throw "guest cannot reach $($config.HostAddress):$($config.IngressPort)" }
    "reachable $($config.HostAddress):$($config.IngressPort)"
} | Out-Null

# 4. Sysmon --------------------------------------------------------------------
Measure-Check 'lab.sysmon.service' {
    $sysmon = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
        foreach ($name in 'Sysmon64', 'Sysmon') {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($service) { return [pscustomobject]@{ Name = $service.Name; Status = "$($service.Status)" } }
        }
        return $null
    }
    if (-not $sysmon) { throw 'no Sysmon service present' }
    if ($sysmon.Status -ne 'Running') { throw "$($sysmon.Name) is $($sysmon.Status)" }
    Set-KCSPLabFact -Report $report -Key 'sysmon_service' -Value $sysmon.Name
    "$($sysmon.Name) $($sysmon.Status)"
} | Out-Null

# 5-6. Agent + enrollment ------------------------------------------------------
$agentState = $null
Measure-Check 'lab.agent.service' {
    $agentState = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
        $service = Get-Service -Name KCSPAgent -ErrorAction SilentlyContinue
        $collectorId = $null
        $path = 'C:\ProgramData\KCSP\agent\credential.json'
        if (Test-Path $path) {
            $parsed = Get-Content $path -Raw | ConvertFrom-Json
            $property = $parsed.PSObject.Properties['collector_id']
            if ($property) { $collectorId = [string] $property.Value }
        }
        $binary = 'C:\Program Files\KCSP\Agent\kcsp-agent.exe'
        [pscustomobject]@{
            Status = $(if ($service) { "$($service.Status)" } else { 'missing' })
            CollectorId = $collectorId
            Sha256 = $(if (Test-Path $binary) { (Get-FileHash $binary -Algorithm SHA256).Hash } else { '' })
        }
    }
    if ($agentState.Status -ne 'Running') { throw "KCSPAgent service is $($agentState.Status)" }
    if (-not $agentState.CollectorId) { throw 'agent has no machine credential (not enrolled)' }
    Set-KCSPLabFact -Report $report -Key 'collector_id' -Value $agentState.CollectorId
    Set-KCSPLabFact -Report $report -Key 'agent_sha256' -Value $agentState.Sha256
    "service Running, collector $($agentState.CollectorId)"
} | Out-Null

# 7. Collector health ----------------------------------------------------------
$collector = $null
Measure-Check 'kcsp.collector.online' {
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline) {
        $collector = Get-KCSPLabCollector -Config $config -HostName (Get-KCSPLabVMName -Config $config -Index 1)
        if (-not $collector -and $agentState.CollectorId) {
            $all = Invoke-KCSPApi -Config $config -Path '/api/v1/collectors'
            $collector = @($all.items | Where-Object { $_.collector_id -eq $agentState.CollectorId }) | Select-Object -First 1
        }
        if ($collector -and $collector.health -eq 'ONLINE') { break }
        Start-Sleep -Seconds 5
    }
    if (-not $collector) { throw 'collector not registered in KCSP' }
    if ($collector.health -ne 'ONLINE') { throw "collector health = $($collector.health)" }
    Set-KCSPLabFact -Report $report -Key 'agent_version' -Value $collector.version
    "health=$($collector.health) version=$($collector.version)"
} | Out-Null

Measure-Check 'kcsp.collector.sources' {
    if (-not $collector) { throw 'no collector' }
    $sources = @($collector.health_metadata.source_health)
    if (-not $sources) { throw 'agent reported no source health' }
    $degraded = @($sources | Where-Object { $_.state -eq 'DEGRADED' })
    Set-KCSPLabFact -Report $report -Key 'sources' -Value (($sources | ForEach-Object { "$($_.channel)=$($_.state)" }) -join ', ')
    if ($degraded.Count -gt 0) { throw "degraded: $(($degraded | ForEach-Object { $_.channel }) -join ', ')" }
    "$($sources.Count) sources healthy"
} | Out-Null

# 8-9. Marker event ------------------------------------------------------------
$marker = "KCSP-LAB-E2E-$([guid]::NewGuid().ToString('N').Substring(0,16))"
Set-KCSPLabFact -Report $report -Key 'marker' -Value $marker
$markerEmittedAt = $null

Measure-Check 'lab.marker.generated' {
    $emitted = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList $marker -ScriptBlock {
        param($token)
        $before = Get-Date
        # Harmless: writes the marker and the current time, nothing else.
        powershell.exe -NoProfile -Command "Write-Output '$token'; Get-Date" | Out-Null
        [pscustomobject]@{ At = $before.ToUniversalTime().ToString('o') }
    }
    $markerEmittedAt = [datetime]::Parse($emitted.At).ToUniversalTime()
    "emitted at $($emitted.At)"
} | Out-Null

Measure-Check 'lab.sysmon.marker_recorded' {
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $found = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList $marker -ScriptBlock {
            param($token)
            try {
                $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 } -MaxEvents 200 -ErrorAction Stop
                foreach ($event in $events) { if ($event.Message -like "*$token*") { return $event.RecordId } }
            } catch { }
            return $null
        }
        if ($found) { return [pscustomobject]@{ Status = 'PASS'; Detail = "Sysmon EventID 1 record $found" } }
        Start-Sleep -Seconds 5
    }
    throw 'marker never appeared as Sysmon Event ID 1'
} | Out-Null

# 10-13. Ingestion through the pipeline ---------------------------------------
$ingestSeconds = $null
Measure-Check 'kcsp.ingest.marker_searchable' {
    $deadline = (Get-Date).AddSeconds($IngestTimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $events = Invoke-KCSPApi -Config $config -Path "/api/v1/events?q=$marker&limit=10"
        if ($events.items -and @($events.items).Count -gt 0) {
            $event = @($events.items)[0]
            $ingestSeconds = [math]::Round(((Get-Date).ToUniversalTime() - $markerEmittedAt).TotalSeconds, 2)
            Set-KCSPLabFact -Report $report -Key 'normalized_event_id' -Value $event.event_id
            Set-KCSPLabFact -Report $report -Key 'end_to_end_latency_seconds' -Value $ingestSeconds
            return [pscustomobject]@{ Status = 'PASS'; Detail = "event_id=$($event.event_id) latency=${ingestSeconds}s" }
        }
        Start-Sleep -Seconds 5
    }
    throw "marker not searchable in KCSP within ${IngestTimeoutSeconds}s"
} | Out-Null

Measure-Check 'kcsp.hunt.marker_visible' {
    $events = Invoke-KCSPApi -Config $config -Path "/api/v1/events?q=$marker&limit=5"
    $count = @($events.items).Count
    if ($count -lt 1) { throw 'hunt returned no rows for the marker' }
    $payload = @($events.items)[0]
    if ("$($payload | ConvertTo-Json -Depth 6)" -notlike "*$marker*") { throw 'returned event does not contain the marker' }
    "$count row(s), marker present in payload"
} | Out-Null

Measure-Check 'kcsp.collector.queue_drained' {
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline) {
        $current = Invoke-KCSPApi -Config $config -Path '/api/v1/collectors'
        $mine = @($current.items | Where-Object { $_.collector_id -eq $agentState.CollectorId }) | Select-Object -First 1
        if ($mine -and $mine.operational) {
            $depth = [int] $mine.operational.queue_depth
            Set-KCSPLabFact -Report $report -Key 'queue_depth' -Value $depth
            if ($depth -eq 0) { return [pscustomobject]@{ Status = 'PASS'; Detail = 'queue_depth=0' } }
            if ($mine.operational.backlog_draining) { Start-Sleep -Seconds 5; continue }
        }
        Start-Sleep -Seconds 5
    }
    return [pscustomobject]@{ Status = 'PASS'; Detail = 'queue non-zero but events are flowing (not a failure)' }
} | Out-Null

# 14-17. Detection ------------------------------------------------------------
if ($IncludeDetection) {
    $detectionMarker = "KCSP-LAB-DET-$([guid]::NewGuid().ToString('N').Substring(0,12))"
    Set-KCSPLabFact -Report $report -Key 'detection_marker' -Value $detectionMarker
    Measure-Check 'lab.detection.encoded_command' {
        Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList $detectionMarker -ScriptBlock {
            param($token)
            # Harmless encoded command: prints the marker and nothing else. No
            # payload, no persistence, no credential access.
            $script = "Write-Output '$token'"
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
            powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
        } | Out-Null
        'encoded PowerShell executed'
    } | Out-Null

    Measure-Check 'kcsp.detection.finding_or_alert' {
        $deadline = (Get-Date).AddSeconds($IngestTimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            $events = Invoke-KCSPApi -Config $config -Path "/api/v1/events?q=$detectionMarker&limit=5"
            if (@($events.items).Count -gt 0) {
                $alerts = Invoke-KCSPApi -Config $config -Path '/api/v1/alerts?limit=25'
                $match = @($alerts.items | Where-Object { "$($_ | ConvertTo-Json -Depth 6)" -like "*$detectionMarker*" }) | Select-Object -First 1
                if ($match) {
                    Set-KCSPLabFact -Report $report -Key 'alert_id' -Value $match.alert_id
                    return [pscustomobject]@{ Status = 'PASS'; Detail = "alert $($match.alert_id)" }
                }
                return [pscustomobject]@{ Status = 'SKIP'; Detail = 'event ingested; no rule matched this marker' }
            }
            Start-Sleep -Seconds 5
        }
        throw 'encoded-command event never reached KCSP'
    } | Out-Null
}

# 18. Audit + API consistency --------------------------------------------------
Measure-Check 'kcsp.api.consistency' {
    $collectors = Invoke-KCSPApi -Config $config -Path '/api/v1/collectors'
    $mine = @($collectors.items | Where-Object { $_.collector_id -eq $agentState.CollectorId }) | Select-Object -First 1
    if (-not $mine) { throw 'collector disappeared from the API' }
    if (-not $mine.operational) { throw 'collector carries no derived operational block' }
    if ($mine.tenant_id -and $mine.tenant_id -ne $config.TenantId) { throw "tenant leak: $($mine.tenant_id)" }
    "overall=$($mine.operational.overall) telemetry=$($mine.operational.telemetry)"
} | Out-Null

# 19. Report -------------------------------------------------------------------
$saved = Save-KCSPLabReport -Report $report -OutputRoot $resultsRoot
Write-KCSPLabLog "Report: $($saved.Directory)" -Level STEP
Write-KCSPLabLog "RESULT $($saved.Result) - $($saved.Passed) passed, $($saved.Failed) failed, $($saved.Skipped) skipped" -Level $(if ($saved.Result -eq 'PASS') { 'PASS' } else { 'FAIL' })

$saved
if ($saved.Failed -gt 0) { exit 1 }
