#requires -Version 5.1
[CmdletBinding()]
param(
    [string] $SubscriptionId = 'KCSP-Baseline',
    [ValidateRange(0, 2147483647)] [int] $MinimumForwardedEvents = 0,
    [string] $ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$results = New-Object Collections.Generic.List[object]
function Add-Result {
    param([string] $Check, [ValidateSet('PASS', 'WARN', 'FAIL')] [string] $Status, [string] $Detail)
    $results.Add([pscustomobject]@{ check = $Check; status = $Status; detail = $Detail })
}

$wec = Get-Service -Name Wecsvc -ErrorAction SilentlyContinue
Add-Result 'wec.service' $(if ($wec -and $wec.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) $(if ($wec) { $wec.Status.ToString() } else { 'not installed' })
$subscription = & wecutil.exe gs $SubscriptionId 2>&1
Add-Result 'wec.subscription' $(if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'FAIL' }) (($subscription | Select-Object -First 8) -join ' ')
$runtime = & wecutil.exe gr $SubscriptionId 2>&1
Add-Result 'wec.runtime' $(if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'FAIL' }) (($runtime | Select-Object -First 12) -join ' ')
try {
    $log = Get-WinEvent -ListLog ForwardedEvents -ErrorAction Stop
    $eventStatus = if (-not $log.IsEnabled) { 'FAIL' } elseif ($log.RecordCount -lt $MinimumForwardedEvents) { 'FAIL' } elseif ($log.RecordCount -eq 0) { 'WARN' } else { 'PASS' }
    Add-Result 'wec.forwarded_events' $eventStatus "enabled=$($log.IsEnabled) records=$($log.RecordCount) maximum_bytes=$($log.MaximumSizeInBytes)"
}
catch {
    Add-Result 'wec.forwarded_events' 'FAIL' $_.Exception.Message
}
$service = Get-Service -Name KCSPAgent -ErrorAction SilentlyContinue
if ($service) {
    $environment = @((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\KCSPAgent' -Name Environment -ErrorAction SilentlyContinue).Environment)
    $channels = $environment | Where-Object { $_ -like 'KCSP_AGENT_WINDOWS_CHANNELS=*' } | Select-Object -First 1
    Add-Result 'kcsp.agent' $(if ($service.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) $service.Status.ToString()
    Add-Result 'kcsp.forwarded_events_channel' $(if ($channels -and $channels.Split('=', 2)[1].Split(';') -contains 'ForwardedEvents') { 'PASS' } else { 'FAIL' }) ([string] $channels)
}
else {
    Add-Result 'kcsp.agent' 'FAIL' 'KCSPAgent is not installed on the WEC host.'
}
$failed = @($results | Where-Object { $_.status -eq 'FAIL' }).Count
$report = [ordered]@{
    schema = 'kcsp.wef.acceptance/v1'
    generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    computer = $env:COMPUTERNAME
    subscription_id = $SubscriptionId
    passed = ($failed -eq 0)
    failures = $failed
    results = $results
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $env:ProgramData ("KCSP\wef\acceptance-{0}.json" -f [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
}
$reportDirectory = Split-Path -Parent $ReportPath
New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
$json = $report | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText($ReportPath, $json, (New-Object Text.UTF8Encoding($false)))
$json
if ($failed -gt 0) { exit 1 }
