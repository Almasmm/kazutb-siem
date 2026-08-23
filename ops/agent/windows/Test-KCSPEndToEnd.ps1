#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ServerUrl,
    [Parameter(Mandatory = $true)] [string] $TenantId,
    [securestring] $AccessToken,
    [string] $AccessTokenFile,
    [ValidateRange(30, 900)] [int] $TimeoutSeconds = 180,
    [ValidateRange(10, 600)] [int] $MaximumPipelineLatencySeconds = 120,
    [string] $ExpectedCollectorId,
    [string] $ReportPath = (Join-Path $env:ProgramData ("KCSP\agent\e2e-{0}.json" -f [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$results = New-Object Collections.Generic.List[object]
$plainToken = $null
$startedAt = [DateTimeOffset]::UtcNow
$marker = "KCSP-E2E-$([Guid]::NewGuid().ToString('N'))"
$eventRecord = $null
$findingRecord = $null
$alertRecord = $null

function Add-Result {
    param([string] $Check, [ValidateSet('PASS', 'WARN', 'FAIL')] [string] $Status, [string] $Detail)
    $results.Add([pscustomobject]@{ check = $Check; status = $Status; detail = $Detail })
}

function ConvertFrom-KCSPSecureString {
    param([Parameter(Mandatory = $true)] [securestring] $Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Read-SecureTokenFile {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if ($resolved.StartsWith('\\')) { throw 'Access token file must be local, not a UNC path.' }
    $broadSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    $acl = Get-Acl -LiteralPath $resolved
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $broadSids -contains $rule.IdentityReference.Value) {
            throw "Access token file grants access to broad principal $($rule.IdentityReference.Value)."
        }
    }
    return (Get-Content -LiteralPath $resolved -Raw).Trim()
}

function Invoke-KCSPGet {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return Invoke-RestMethod -Method Get -Uri "$($script:apiRoot)$Path" -Headers $script:headers -TimeoutSec 15
}

function Wait-KCSPRecord {
    param([Parameter(Mandatory = $true)] [scriptblock] $Probe)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $value = & $Probe
        if ($null -ne $value) { return $value }
        Start-Sleep -Seconds 3
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $null
}

try {
    $server = $null
    if (-not [Uri]::TryCreate($ServerUrl.TrimEnd('/'), [UriKind]::Absolute, [ref] $server) -or $server.Scheme -ne 'https' -or -not [string]::IsNullOrWhiteSpace($server.UserInfo)) {
        throw 'ServerUrl must be an absolute HTTPS URL without user information.'
    }
    if ($TenantId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') { throw 'TenantId is invalid.' }
    if ($AccessTokenFile) { $plainToken = Read-SecureTokenFile -Path $AccessTokenFile }
    elseif ($null -ne $AccessToken) { $plainToken = ConvertFrom-KCSPSecureString -Value $AccessToken }
    else { $plainToken = ConvertFrom-KCSPSecureString -Value (Read-Host 'KCSP scoped service account token' -AsSecureString) }
    if ($plainToken -notmatch '^kcsp_sat_' -or $plainToken.Length -gt 512 -or $plainToken.Contains("`n") -or $plainToken.Contains("`r")) {
        throw 'A valid kcsp_sat_ service account token is required.'
    }
    $script:apiRoot = $server.AbsoluteUri.TrimEnd('/') + '/api/v1'
    $script:headers = @{ Authorization = "Bearer $plainToken"; 'X-KCSP-Tenant-ID' = $TenantId; 'X-KCSP-Access-Reason' = "windows-e2e:$marker" }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $agent = Get-Service -Name KCSPAgent -ErrorAction SilentlyContinue
    Add-Result 'endpoint.agent_running' $(if ($agent -and $agent.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) $(if ($agent) { $agent.Status.ToString() } else { 'not installed' })
    $sysmon = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
    Add-Result 'endpoint.sysmon_running' $(if ($sysmon -and $sysmon.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) $(if ($sysmon) { $sysmon.Status.ToString() } else { 'not installed' })
    if (-not $agent -or $agent.Status -ne 'Running' -or -not $sysmon -or $sysmon.Status -ne 'Running') {
        throw 'KCSP Agent and Sysmon must both be running before the live probe.'
    }

    $probe = "Write-Output '$marker'; [Convert]::FromBase64String('UwBPAEMA') | Out-Null # EncodedCommand"
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $probe) -Wait -PassThru -WindowStyle Hidden
    Add-Result 'endpoint.probe_executed' $(if ($process.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }) "pid=$($process.Id) marker=$marker exit_code=$($process.ExitCode)"

    $encodedMarker = [Uri]::EscapeDataString($marker)
    $eventRecord = Wait-KCSPRecord -Probe {
        $page = Invoke-KCSPGet -Path "/events?q=$encodedMarker&limit=100"
        $matches = @($page.items | Where-Object { $_.process.command_line -like "*$marker*" -or $_.raw.message -like "*$marker*" } | Select-Object -First 1)
        if ($matches.Count -gt 0) { return $matches[0] }
        return $null
    }
    if (-not $eventRecord) { throw "Timed out waiting for the Sysmon event for marker $marker." }
    $isSysmon = [string]$eventRecord.source.product -match 'Sysmon'
    $hasIdentity = -not [string]::IsNullOrWhiteSpace([string]$eventRecord.source_id) -and -not [string]::IsNullOrWhiteSpace([string]$eventRecord.collector_id)
    $collectorMatches = [string]::IsNullOrWhiteSpace($ExpectedCollectorId) -or $eventRecord.collector_id -eq $ExpectedCollectorId
    Add-Result 'pipeline.event_received' 'PASS' "event_id=$($eventRecord.event_id) collector_id=$($eventRecord.collector_id)"
    Add-Result 'pipeline.sysmon_source' $(if ($isSysmon) { 'PASS' } else { 'FAIL' }) "vendor=$($eventRecord.source.vendor) product=$($eventRecord.source.product) source_id=$($eventRecord.source_id)"
    Add-Result 'pipeline.source_identity' $(if ($hasIdentity -and $collectorMatches) { 'PASS' } else { 'FAIL' }) "source_id=$($eventRecord.source_id) collector_id=$($eventRecord.collector_id) expected=$ExpectedCollectorId"
    Add-Result 'pipeline.tenant_binding' $(if ($eventRecord.tenant_id -eq $TenantId) { 'PASS' } else { 'FAIL' }) "tenant_id=$($eventRecord.tenant_id)"

    $findingRecord = Wait-KCSPRecord -Probe {
        $page = Invoke-KCSPGet -Path "/findings?event_id=$([Uri]::EscapeDataString([string]$eventRecord.event_id))&limit=100"
        $matches = @($page.items | Where-Object { $_.rule.id -eq 'KCSP-WIN-PS-001' } | Select-Object -First 1)
        if ($matches.Count -gt 0) { return $matches[0] }
        return $null
    }
    if (-not $findingRecord) { throw "Timed out waiting for finding KCSP-WIN-PS-001 for event $($eventRecord.event_id)." }
    Add-Result 'pipeline.finding_created' 'PASS' "finding_id=$($findingRecord.finding_id) rule=$($findingRecord.rule.id) risk=$($findingRecord.risk_score)"

    $alertRecord = Wait-KCSPRecord -Probe {
        $page = Invoke-KCSPGet -Path '/alerts?limit=500'
        $matches = @($page.items | Where-Object { $_.rule.id -eq 'KCSP-WIN-PS-001' -and @($_.event_ids) -contains $eventRecord.event_id } | Select-Object -First 1)
        if ($matches.Count -gt 0) { return $matches[0] }
        return $null
    }
    if (-not $alertRecord) { throw "Timed out waiting for alert KCSP-WIN-PS-001 for event $($eventRecord.event_id)." }
    $latency = ([DateTimeOffset]::Parse([string]$alertRecord.created_at) - $startedAt).TotalSeconds
    Add-Result 'pipeline.alert_created' 'PASS' "alert_id=$($alertRecord.alert_id) severity=$($alertRecord.severity) risk=$($alertRecord.risk_score)"
    Add-Result 'pipeline.latency_sla' $(if ($latency -le $MaximumPipelineLatencySeconds) { 'PASS' } else { 'FAIL' }) "seconds=$([Math]::Round($latency, 3)) maximum=$MaximumPipelineLatencySeconds"
}
catch {
    Add-Result 'acceptance.execution' 'FAIL' $_.Exception.Message
}
finally {
    $plainToken = $null
    $script:headers = $null
    $failed = @($results | Where-Object { $_.status -eq 'FAIL' }).Count
    $report = [ordered]@{
        schema = 'kcsp.windows-sysmon-e2e/v1'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        started_at = $startedAt.ToString('o')
        computer = $env:COMPUTERNAME
        tenant_id = $TenantId
        marker = $marker
        passed = ($failed -eq 0)
        failures = $failed
        event_id = $(if ($eventRecord) { $eventRecord.event_id } else { $null })
        finding_id = $(if ($findingRecord) { $findingRecord.finding_id } else { $null })
        alert_id = $(if ($alertRecord) { $alertRecord.alert_id } else { $null })
        results = $results
    }
    $directory = Split-Path -Parent $ReportPath
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $json = $report | ConvertTo-Json -Depth 7
    [IO.File]::WriteAllText($ReportPath, $json, (New-Object Text.UTF8Encoding($false)))
    $json
}
if (@($results | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { exit 1 }
