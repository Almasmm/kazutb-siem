#requires -Version 5.1
<#
    .SYNOPSIS
    Upgrades an installed KCSP agent in place, preserving its enrolled identity.

    .DESCRIPTION
    Replaces the agent binary without re-enrolling. The machine credential,
    collector_id, state directory, queued events, checkpoints and service
    configuration are all preserved, so the endpoint keeps its existing
    collector record instead of registering a second asset.

    The upgrade fails closed: the replacement binary must match the digest in
    the package manifest, an existing machine credential must be present, and
    the previous binary is restored if the upgraded service does not come up.

    .EXAMPLE
    .\Upgrade-KCSPAgent.ps1 -ExpectedCollectorId agt_70e3bbd15031e64b333fa27e
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $BinaryPath = (Join-Path $PSScriptRoot 'kcsp-agent.exe'),
    [string] $ExpectedSha256,
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'KCSP\Agent'),
    [string] $StateDirectory = (Join-Path $env:ProgramData 'KCSP\agent'),
    # Initial cursor applied to channels that have no checkpoint yet. FROM_NOW
    # stops a newly working channel from replaying the retained journal.
    [ValidateSet('FROM_NOW', 'LAST_1_HOUR', 'LAST_24_HOURS', 'FROM_BEGINNING')]
    [string] $InitialCursor = 'FROM_NOW',
    [string] $ExpectedCollectorId,
    [int] $HealthCheckSeconds = 60,
    [switch] $RequireAuthenticodeSignature
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serviceName = 'KCSPAgent'
$targetBinary = Join-Path $InstallDirectory 'kcsp-agent.exe'
$logPath = Join-Path $StateDirectory 'agent.log'
$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"

function Get-KCSPJsonProperty {
    <#
        .SYNOPSIS
        Reads an optional property from parsed JSON without tripping StrictMode.

        .DESCRIPTION
        Under Set-StrictMode -Version Latest, dotting a property that a JSON
        document does not contain raises PropertyNotFoundException. Agent state
        files carry optional fields, so absence must read as $null rather than
        abort the upgrade.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $InputObject,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if (-not $property) { return $null }
    $value = [string] $property.Value
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    return $value.Trim()
}

function Read-KCSPJsonObject {
    <#
        .SYNOPSIS
        Parses a JSON state file, failing closed on malformed content.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Description
    )
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "$Description at $Path is empty."
    }
    try {
        $parsed = $raw | ConvertFrom-Json
    }
    catch {
        throw "$Description at $Path is not valid JSON: $($_.Exception.Message)"
    }
    if ($null -eq $parsed -or -not ($parsed -is [psobject])) {
        throw "$Description at $Path is not a JSON object."
    }
    return $parsed
}

function Resolve-KCSPAgentIdentity {
    <#
        .SYNOPSIS
        Resolves the persisted identity that an in-place upgrade must preserve.

        .DESCRIPTION
        collector_id is the required identity and lives in credential.json.
        agent_id is written to a separate identity.json by the agent and is
        never part of credential.json, so it is read from its own file and is
        optional: an endpoint whose identity file is absent is still valid and
        must upgrade without re-enrollment. agent_id is never derived from
        collector_id, because that would invent an identity rather than read one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $StateDirectory,
        [string] $ExpectedCollectorId
    )
    Set-StrictMode -Version Latest

    $credentialFile = Join-Path $StateDirectory 'credential.json'
    $identityFile = Join-Path $StateDirectory 'identity.json'

    # An upgrade must never mint a new identity. Without an existing credential
    # this would silently become a fresh enrollment and duplicate the collector.
    if (-not (Test-Path -LiteralPath $credentialFile -PathType Leaf)) {
        throw "No machine credential at $credentialFile. Refusing to upgrade, because that would require re-enrollment."
    }
    $credential = Read-KCSPJsonObject -Path $credentialFile -Description 'Machine credential'
    $collectorId = Get-KCSPJsonProperty -InputObject $credential -Name 'collector_id'
    if (-not $collectorId) {
        throw "Existing credential at $credentialFile does not carry a collector_id."
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedCollectorId) -and $collectorId -ne $ExpectedCollectorId) {
        throw "Installed collector_id is $collectorId, expected $ExpectedCollectorId."
    }

    $agentId = $null
    if (Test-Path -LiteralPath $identityFile -PathType Leaf) {
        $identity = Read-KCSPJsonObject -Path $identityFile -Description 'Agent identity'
        $agentId = Get-KCSPJsonProperty -InputObject $identity -Name 'agent_id'
    }

    return [pscustomobject]@{
        CollectorId    = $collectorId
        AgentId        = $agentId
        CredentialPath = $credentialFile
        IdentityPath   = $identityFile
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'KCSP agent upgrade requires an elevated Administrator session.'
    }
}

function Resolve-ExpectedHash {
    param([string] $ExplicitHash)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitHash)) {
        return $ExplicitHash.Trim().ToUpperInvariant()
    }
    $manifestPath = Join-Path $PSScriptRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'ExpectedSha256 or a package manifest.json is required; upgrade fails closed without an integrity value.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $entry = @($manifest.files | Where-Object { $_.path -eq 'kcsp-agent.exe' })
    if ($entry.Count -ne 1 -or [string]::IsNullOrWhiteSpace($entry[0].sha256)) {
        throw 'Package manifest does not contain exactly one kcsp-agent.exe digest.'
    }
    return $entry[0].sha256.ToUpperInvariant()
}

Assert-Administrator

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Replacement agent binary not found: $BinaryPath"
}
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Service '$serviceName' is not installed. Use Install-KCSPAgent.ps1 for a first-time installation."
}
$identityBefore = Resolve-KCSPAgentIdentity -StateDirectory $StateDirectory -ExpectedCollectorId $ExpectedCollectorId
$collectorId = $identityBefore.CollectorId
$agentId = $identityBefore.AgentId

$expectedHash = Resolve-ExpectedHash -ExplicitHash $ExpectedSha256
$actualHash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actualHash -ne $expectedHash) {
    throw "Replacement binary SHA-256 mismatch: expected $expectedHash, got $actualHash."
}
$signature = Get-AuthenticodeSignature -LiteralPath $BinaryPath
if ($RequireAuthenticodeSignature -and $signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
    throw "Replacement binary Authenticode signature is not valid: $($signature.Status)."
}

$previousVersion = $null
if (Test-Path -LiteralPath $targetBinary -PathType Leaf) {
    $previousVersion = (Get-Item -LiteralPath $targetBinary).VersionInfo.FileVersion
}
if (-not $PSCmdlet.ShouldProcess($serviceName, "Replace agent binary and restart")) {
    return
}

# Mark the log so the health check only reads lines produced after the upgrade.
$logOffsetBefore = 0
if (Test-Path -LiteralPath $logPath -PathType Leaf) {
    $logOffsetBefore = (Get-Item -LiteralPath $logPath).Length
}

if ($service.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
    (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
}

$backupBinary = "$targetBinary.previous"
if (Test-Path -LiteralPath $targetBinary -PathType Leaf) {
    Copy-Item -LiteralPath $targetBinary -Destination $backupBinary -Force
}

$rollback = $false
try {
    Copy-Item -LiteralPath $BinaryPath -Destination $targetBinary -Force

    # Preserve the existing service environment and only add the cursor mode.
    $existing = @(Get-ItemProperty -Path $serviceRegistryPath -Name Environment -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Environment -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        $preserved = @($existing | Where-Object { $_ -notlike 'KCSP_AGENT_INITIAL_CURSOR=*' })
        $preserved += "KCSP_AGENT_INITIAL_CURSOR=$InitialCursor"
        if ($preserved | Where-Object { $_ -like 'KCSP_AGENT_ENROLLMENT_TOKEN=*' }) {
            throw 'Refusing to keep a one-time enrollment token in service configuration.'
        }
        New-ItemProperty -Path $serviceRegistryPath -Name Environment -PropertyType MultiString -Value $preserved -Force | Out-Null
    }

    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
}
catch {
    $rollback = $true
    $failure = $_.Exception.Message
}

if ($rollback) {
    if (Test-Path -LiteralPath $backupBinary -PathType Leaf) {
        Copy-Item -LiteralPath $backupBinary -Destination $targetBinary -Force
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    }
    throw "Upgrade failed and the previous binary was restored: $failure"
}

# Health check: the service must stay up and the new log must be free of the
# decode failure this release fixes.
$deadline = (Get-Date).AddSeconds([Math]::Max(5, $HealthCheckSeconds))
$decodeErrors = 0
$sourceFailures = 0
$newLogText = ''
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5
    if ((Get-Service -Name $serviceName).Status -ne 'Running') {
        throw 'KCSP agent service did not stay running after the upgrade.'
    }
    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        $stream = [IO.File]::Open($logPath, 'Open', 'Read', 'ReadWrite')
        try {
            if ($stream.Length -ge $logOffsetBefore) { [void] $stream.Seek($logOffsetBefore, 'Begin') }
            $reader = New-Object IO.StreamReader($stream)
            $newLogText = $reader.ReadToEnd()
        }
        finally {
            $stream.Dispose()
        }
        $decodeErrors = ([regex]::Matches($newLogText, 'invalid UTF-8')).Count
        $sourceFailures = ([regex]::Matches($newLogText, 'telemetry source read failed')).Count
        if ($decodeErrors -gt 0) {
            throw "Upgraded agent still reports $decodeErrors 'invalid UTF-8' decode failures."
        }
    }
}

$identityAfter = Resolve-KCSPAgentIdentity -StateDirectory $StateDirectory
if ($identityAfter.CollectorId -ne $collectorId) {
    throw "collector_id changed during upgrade: $collectorId -> $($identityAfter.CollectorId)."
}
if (Test-Path -LiteralPath $backupBinary -PathType Leaf) {
    Remove-Item -LiteralPath $backupBinary -Force
}

[pscustomobject]@{
    service                = $serviceName
    status                 = (Get-Service -Name $serviceName).Status.ToString()
    previous_version       = $previousVersion
    binary_sha256          = $actualHash
    authenticode           = $signature.Status.ToString()
    collector_id           = $collectorId
    agent_id               = $agentId
    credential_preserved   = $true
    state_directory        = $StateDirectory
    initial_cursor         = $InitialCursor
    invalid_utf8_errors    = $decodeErrors
    source_read_failures   = $sourceFailures
    health_window_seconds  = $HealthCheckSeconds
}
