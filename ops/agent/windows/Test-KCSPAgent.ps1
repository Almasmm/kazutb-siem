#requires -Version 5.1
[CmdletBinding()]
param(
    [string] $ExpectedSha256,
    [string] $ReportPath,
    [switch] $SkipServerProbe,
    [switch] $SkipSysmon
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'KCSPAgent'
$stateDirectory = Join-Path $env:ProgramData 'KCSP\agent'
$results = New-Object Collections.Generic.List[object]

function Add-Result {
    param([string] $Check, [ValidateSet('PASS', 'WARN', 'FAIL')] [string] $Status, [string] $Detail)
    $results.Add([pscustomobject]@{ check = $Check; status = $Status; detail = $Detail })
}

try {
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
    Add-Result 'service.running' $(if ($service.State -eq 'Running') { 'PASS' } else { 'FAIL' }) "state=$($service.State) start_mode=$($service.StartMode) account=$($service.StartName)"
    Add-Result 'service.account' $(if ($service.StartName -eq 'NT SERVICE\KCSPAgent') { 'PASS' } else { 'FAIL' }) $service.StartName
    $binaryPath = $service.PathName.Trim('"')
    if (Test-Path -LiteralPath $binaryPath -PathType Leaf) {
        $hash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash
        Add-Result 'binary.present' 'PASS' "sha256=$hash"
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
            Add-Result 'binary.integrity' $(if ($hash -eq $ExpectedSha256.Trim()) { 'PASS' } else { 'FAIL' }) 'Compared with rollout manifest.'
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $binaryPath
        Add-Result 'binary.authenticode' $(if ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid) { 'PASS' } else { 'WARN' }) $signature.Status.ToString()
    }
    else {
        Add-Result 'binary.present' 'FAIL' $binaryPath
    }
}
catch {
    Add-Result 'service.running' 'FAIL' $_.Exception.Message
}

$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$serviceEnvironment = @((Get-ItemProperty -Path $serviceRegistryPath -Name Environment -ErrorAction SilentlyContinue).Environment)
if ($serviceEnvironment | Where-Object { $_ -like 'KCSP_AGENT_ENROLLMENT_TOKEN=*' }) {
    Add-Result 'credential.bootstrap_not_persisted' 'FAIL' 'Enrollment token exists in service environment.'
}
else {
    Add-Result 'credential.bootstrap_not_persisted' 'PASS' 'No enrollment token in service environment.'
}

$credentialPath = Join-Path $stateDirectory 'credential.json'
try {
    $credential = Get-Content -LiteralPath $credentialPath -Raw | ConvertFrom-Json
    $expires = [DateTimeOffset]::Parse($credential.expires_at)
    $valid = $credential.access_token -like 'kcsp_agent_*' -and $expires -gt [DateTimeOffset]::UtcNow
    Add-Result 'credential.valid' $(if ($valid) { 'PASS' } else { 'FAIL' }) "collector_id=$($credential.collector_id) expires_at=$($expires.ToString('o'))"
}
catch {
    Add-Result 'credential.valid' 'FAIL' $_.Exception.Message
}

try {
    $acl = Get-Acl -LiteralPath $stateDirectory
    $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    $unsafe = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $broad -contains $_.IdentityReference.Value
    })
    Add-Result 'state.acl' $(if ($unsafe.Count -eq 0) { 'PASS' } else { 'FAIL' }) "broad_allow_rules=$($unsafe.Count)"
}
catch {
    Add-Result 'state.acl' 'FAIL' $_.Exception.Message
}

if (-not $SkipSysmon) {
    $sysmonService = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    Add-Result 'sysmon.service' $(if ($sysmonService -and $sysmonService.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) $(if ($sysmonService) { $sysmonService.Status.ToString() } else { 'not installed' })
    try {
        $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        Add-Result 'sysmon.channel' $(if ($log.IsEnabled) { 'PASS' } else { 'FAIL' }) "enabled=$($log.IsEnabled) records=$($log.RecordCount)"
    }
    catch {
        Add-Result 'sysmon.channel' 'FAIL' $_.Exception.Message
    }
}

$channelSetting = $serviceEnvironment | Where-Object { $_ -like 'KCSP_AGENT_WINDOWS_CHANNELS=*' } | Select-Object -First 1
$configuredChannels = if ($channelSetting) {
    @($channelSetting.Substring('KCSP_AGENT_WINDOWS_CHANNELS='.Length).Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}
else {
    @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Windows Defender/Operational')
}
foreach ($channel in $configuredChannels) {
    try {
        $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
        Add-Result "eventlog.$channel" $(if ($log.IsEnabled) { 'PASS' } else { 'WARN' }) "enabled=$($log.IsEnabled)"
    }
    catch {
        Add-Result "eventlog.$channel" 'WARN' $_.Exception.Message
    }
}

if (-not $SkipServerProbe) {
    $serverSetting = $serviceEnvironment | Where-Object { $_ -like 'KCSP_AGENT_SERVER_URL=*' } | Select-Object -First 1
    if ($serverSetting) {
        $serverUrl = $serverSetting.Substring('KCSP_AGENT_SERVER_URL='.Length).TrimEnd('/')
        try {
            $health = Invoke-RestMethod -Method Get -Uri "$serverUrl/health/live" -TimeoutSec 15
            Add-Result 'server.reachable' 'PASS' "status=$($health.status)"
        }
        catch {
            Add-Result 'server.reachable' 'FAIL' $_.Exception.Message
        }
    }
    else {
        Add-Result 'server.reachable' 'FAIL' 'KCSP_AGENT_SERVER_URL is missing from service environment.'
    }
}

$failed = @($results | Where-Object { $_.status -eq 'FAIL' }).Count
$report = [ordered]@{
    schema = 'kcsp.windows-agent.acceptance/v1'
    generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    computer = $env:COMPUTERNAME
    passed = ($failed -eq 0)
    failures = $failed
    results = $results
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $stateDirectory ("acceptance-{0}.json" -f [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
}
$reportJson = $report | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText($ReportPath, $reportJson, (New-Object Text.UTF8Encoding($false)))
$reportJson
if ($failed -gt 0) {
    exit 1
}
