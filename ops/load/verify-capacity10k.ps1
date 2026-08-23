#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $RunId,
    [string] $TenantId = 'university-kulazhanov',
    [ValidateRange(1, 10000000)] [int] $ExpectedAssets = 10000,
    [string] $SummaryPath = (Join-Path $PSScriptRoot '..\..\.artifacts\load\kcsp-capacity10k-summary.json'),
    [string] $ClickHouseUrl = 'http://127.0.0.1:8123',
    [string] $ClickHouseDatabase = 'kcsp',
    [string] $ClickHouseUser = 'kcsp',
    [securestring] $ClickHousePassword,
    [ValidateRange(10, 900)] [int] $DrainTimeoutSeconds = 180,
    [string] $ReportPath = (Join-Path $PSScriptRoot '..\..\.artifacts\load\kcsp-capacity10k-acceptance.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$plainPassword = $null

function ConvertFrom-KCSPSecureString {
    param([Parameter(Mandatory = $true)] [securestring] $Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$') { throw 'RunId is invalid.' }
if ($TenantId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') { throw 'TenantId is invalid.' }
$endpoint = $null
if (-not [Uri]::TryCreate($ClickHouseUrl.TrimEnd('/'), [UriKind]::Absolute, [ref] $endpoint)) { throw 'ClickHouseUrl is invalid.' }
$isLoopbackHTTP = $endpoint.Scheme -eq 'http' -and @('127.0.0.1', 'localhost', '::1') -contains $endpoint.Host
if ($endpoint.Scheme -ne 'https' -and -not $isLoopbackHTTP) { throw 'ClickHouse verification requires HTTPS or a loopback HTTP endpoint.' }
if (-not (Test-Path -LiteralPath $SummaryPath -PathType Leaf)) { throw "k6 summary not found: $SummaryPath" }
$summary = Get-Content -LiteralPath $SummaryPath -Raw | ConvertFrom-Json
$accepted = [int64]($summary.metrics.events_accepted.values.count)
$dropped = [int64]($summary.metrics.dropped_iterations.values.count)
if ($accepted -lt $ExpectedAssets + 1) { throw "k6 accepted only $accepted events; expected at least $($ExpectedAssets + 1) including setup." }
if ($dropped -ne 0) { throw "k6 dropped $dropped iterations." }

if ($null -ne $ClickHousePassword) { $plainPassword = ConvertFrom-KCSPSecureString -Value $ClickHousePassword }
elseif ($env:KCSP_CLICKHOUSE_PASSWORD) { $plainPassword = $env:KCSP_CLICKHOUSE_PASSWORD }
else { throw 'ClickHousePassword or KCSP_CLICKHOUSE_PASSWORD is required.' }

$headers = @{ 'X-ClickHouse-User' = $ClickHouseUser; 'X-ClickHouse-Key' = $plainPassword }
$query = @"
SELECT count() AS events, uniqExact(device_hostname) AS assets, countIf(device_hostname = '') AS missing_hostnames
FROM normalized_events FINAL
WHERE tenant_id = '$TenantId' AND startsWith(event_id, '$RunId-ingest-')
FORMAT JSON
"@
$started = [DateTimeOffset]::UtcNow
$deadline = $started.AddSeconds($DrainTimeoutSeconds)
$events = 0L
$assets = 0L
$missing = 0L
try {
    do {
        $response = Invoke-RestMethod -Method Post -Uri "$($endpoint.AbsoluteUri.TrimEnd('/'))/?database=$([Uri]::EscapeDataString($ClickHouseDatabase))" -Headers $headers -ContentType 'text/plain' -Body $query -TimeoutSec 20
        $row = @($response.data)[0]
        $events = [int64]$row.events
        $assets = [int64]$row.assets
        $missing = [int64]$row.missing_hostnames
        if ($events -ge $ExpectedAssets -and $assets -ge $ExpectedAssets) { break }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
}
finally {
    $plainPassword = $null
    $headers = $null
}
$drainSeconds = ([DateTimeOffset]::UtcNow - $started).TotalSeconds
$passed = $events -eq $ExpectedAssets -and $assets -eq $ExpectedAssets -and $missing -eq 0
$report = [ordered]@{
    schema = 'kcsp.capacity10k-acceptance/v1'
    generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    run_id = $RunId
    tenant_id = $TenantId
    passed = $passed
    k6_events_accepted = $accepted
    dropped_iterations = $dropped
    normalized_events = $events
    unique_assets = $assets
    missing_hostnames = $missing
    drain_seconds = [Math]::Round($drainSeconds, 3)
    expected_assets = $ExpectedAssets
}
$reportDirectory = Split-Path -Parent $ReportPath
New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
$json = $report | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($ReportPath, $json, (New-Object Text.UTF8Encoding($false)))
$json
if (-not $passed) { exit 1 }
