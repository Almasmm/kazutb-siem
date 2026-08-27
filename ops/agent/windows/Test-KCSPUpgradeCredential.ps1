#requires -Version 5.1
<#
    .SYNOPSIS
    Verifies the identity contract of Upgrade-KCSPAgent.ps1.

    .DESCRIPTION
    Regression cover for the pilot defect: the upgrade read agent_id from
    credential.json under Set-StrictMode -Version Latest and aborted with
    PropertyNotFoundException. agent_id is not part of credential.json in any
    agent version - the Go agent writes it to a separate identity.json - so the
    upgrade must treat it as optional and resolve it from its own file.

    The resolver is lifted out of the upgrade script with the PowerShell parser
    so the script stays self-contained, then exercised against real state
    directories on disk with StrictMode enabled, exactly as it runs in
    production.
#>
[CmdletBinding()]
param(
    [string] $UpgradeScriptPath = (Join-Path $PSScriptRoot 'Upgrade-KCSPAgent.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = 0
function Add-Result {
    param([string] $Name, [string] $Status, [string] $Detail = '')
    if ($Status -ne 'PASS') { $script:Failures++ }
    [pscustomobject]@{ check = $Name; status = $Status; detail = $Detail }
}

if (-not (Test-Path -LiteralPath $UpgradeScriptPath -PathType Leaf)) {
    throw "Upgrade script not found: $UpgradeScriptPath"
}

$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($UpgradeScriptPath, [ref] $null, [ref] $parseErrors)
if ($parseErrors -and $parseErrors.Count -gt 0) {
    throw "Upgrade script failed to parse: $($parseErrors[0].Message)"
}
$wanted = 'Get-KCSPJsonProperty', 'Read-KCSPJsonObject', 'Resolve-KCSPAgentIdentity'
$definitions = @()
foreach ($name in $wanted) {
    $function = $ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name },
        $true) | Select-Object -First 1
    if (-not $function) {
        throw "Upgrade-KCSPAgent.ps1 no longer defines $name."
    }
    $definitions += $function.Extent.Text
}

# StrictMode is enabled in the harness exactly as the upgrade script enables it,
# so a missing-property regression fails here the same way it failed on the host.
$resolver = [scriptblock]::Create(@"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
$($definitions -join "`n`n")
Resolve-KCSPAgentIdentity @args
"@)

$results = New-Object System.Collections.Generic.List[object]
$root = Join-Path ([IO.Path]::GetTempPath()) ("kcsp-upgrade-credential-{0}" -f [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -Force | Out-Null

function New-StateDirectory {
    # Credential/Identity are [object] so that $null means "do not create the
    # file" while '' means "create it empty"; a [string] param would coerce
    # $null to '' and silently write an empty file.
    param([string] $Name, [object] $Credential = $null, [object] $Identity = $null)
    $directory = Join-Path $root $Name
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    if ($null -ne $Credential) {
        [IO.File]::WriteAllText((Join-Path $directory 'credential.json'), [string] $Credential, (New-Object Text.UTF8Encoding($false)))
    }
    if ($null -ne $Identity) {
        [IO.File]::WriteAllText((Join-Path $directory 'identity.json'), [string] $Identity, (New-Object Text.UTF8Encoding($false)))
    }
    return $directory
}

$pilotCollector = 'agt_70e3bbd15031e64b333fa27e'
$currentCredential = @"
{"access_token":"kcsp_agent_example","token_type":"Bearer","expires_at":"2027-01-01T00:00:00Z","collector_id":"$pilotCollector"}
"@
# The real pilot host: a credential with no agent_id property at all.
$legacyCredential = @"
{"access_token":"kcsp_agent_example","token_type":"Bearer","expires_at":"2027-01-01T00:00:00Z","collector_id":"$pilotCollector"}
"@
$identityFile = @"
{"agent_id":"$pilotCollector","created_at":"2026-08-20T09:00:00Z"}
"@

try {
    # 1. Credential plus an identity file carrying agent_id.
    $directory = New-StateDirectory -Name 'current' -Credential $currentCredential -Identity $identityFile
    try {
        $resolved = & $resolver -StateDirectory $directory -ExpectedCollectorId $pilotCollector
        if ($resolved.CollectorId -eq $pilotCollector -and $resolved.AgentId -eq $pilotCollector) {
            $results.Add((Add-Result 'credential.with-agent-id' 'PASS' "collector_id=$($resolved.CollectorId) agent_id=$($resolved.AgentId)"))
        }
        else {
            $results.Add((Add-Result 'credential.with-agent-id' 'FAIL' "collector_id=$($resolved.CollectorId) agent_id=$($resolved.AgentId)"))
        }
    }
    catch {
        $results.Add((Add-Result 'credential.with-agent-id' 'FAIL' "threw: $($_.Exception.Message)"))
    }

    # 2. Legacy: collector_id present, no agent_id anywhere. This is the exact
    #    shape on kaztbu and must upgrade without re-enrollment.
    $legacyDirectory = New-StateDirectory -Name 'legacy' -Credential $legacyCredential -Identity $null
    try {
        $resolved = & $resolver -StateDirectory $legacyDirectory -ExpectedCollectorId $pilotCollector
        if ($resolved.CollectorId -eq $pilotCollector -and $null -eq $resolved.AgentId) {
            $results.Add((Add-Result 'credential.legacy-without-agent-id' 'PASS' "collector_id=$($resolved.CollectorId) agent_id=<null>"))
        }
        else {
            $results.Add((Add-Result 'credential.legacy-without-agent-id' 'FAIL' "collector_id=$($resolved.CollectorId) agent_id=$($resolved.AgentId)"))
        }
    }
    catch {
        $results.Add((Add-Result 'credential.legacy-without-agent-id' 'FAIL' "threw: $($_.Exception.Message)"))
    }

    # agent_id must never be invented from collector_id.
    try {
        $resolved = & $resolver -StateDirectory $legacyDirectory
        if ($null -eq $resolved.AgentId) {
            $results.Add((Add-Result 'credential.agent-id-not-substituted' 'PASS' 'agent_id stays null rather than copying collector_id'))
        }
        else {
            $results.Add((Add-Result 'credential.agent-id-not-substituted' 'FAIL' "agent_id was invented as $($resolved.AgentId)"))
        }
    }
    catch {
        $results.Add((Add-Result 'credential.agent-id-not-substituted' 'FAIL' "threw: $($_.Exception.Message)"))
    }

    # 3-6. Fail-closed conditions.
    $failClosed = @(
        @{ Name = 'failclosed.no-collector-id'; Credential = '{"access_token":"kcsp_agent_example","token_type":"Bearer"}'; Identity = $null; Expected = $pilotCollector },
        @{ Name = 'failclosed.blank-collector-id'; Credential = '{"collector_id":"   "}'; Identity = $null; Expected = '' },
        @{ Name = 'failclosed.malformed-credential'; Credential = '{ this is not json'; Identity = $null; Expected = '' },
        @{ Name = 'failclosed.empty-credential'; Credential = ''; Identity = $null; Expected = '' },
        @{ Name = 'failclosed.malformed-identity'; Credential = $legacyCredential; Identity = '<<<not json>>>'; Expected = '' }
    )
    foreach ($case in $failClosed) {
        $directory = New-StateDirectory -Name $case.Name -Credential $case.Credential -Identity $case.Identity
        try {
            [void] (& $resolver -StateDirectory $directory -ExpectedCollectorId $case.Expected)
            $results.Add((Add-Result $case.Name 'FAIL' 'expected a terminating error'))
        }
        catch {
            $results.Add((Add-Result $case.Name 'PASS' 'refused'))
        }
    }

    # 4. Wrong ExpectedCollectorId.
    try {
        [void] (& $resolver -StateDirectory $legacyDirectory -ExpectedCollectorId 'agt_someone_else')
        $results.Add((Add-Result 'failclosed.wrong-expected-collector' 'FAIL' 'expected a terminating error'))
    }
    catch {
        $results.Add((Add-Result 'failclosed.wrong-expected-collector' 'PASS' 'refused a mismatched collector_id'))
    }

    # 5. credential.json missing entirely.
    $emptyDirectory = New-StateDirectory -Name 'missing' -Credential $null -Identity $null
    try {
        [void] (& $resolver -StateDirectory $emptyDirectory)
        $results.Add((Add-Result 'failclosed.credential-missing' 'FAIL' 'expected a terminating error'))
    }
    catch {
        $detail = if ($_.Exception.Message -match 're-enrollment') { 'refused and named re-enrollment as the reason' } else { 'refused' }
        $results.Add((Add-Result 'failclosed.credential-missing' 'PASS' $detail))
    }

    # 7/8. The resolver must not mutate the state directory it inspects.
    $before = Get-ChildItem -LiteralPath $legacyDirectory -Recurse -Force | ForEach-Object {
        "{0}|{1}|{2}" -f $_.Name, $_.Length, $_.LastWriteTimeUtc.Ticks
    } | Sort-Object
    $credentialTextBefore = Get-Content -LiteralPath (Join-Path $legacyDirectory 'credential.json') -Raw
    [void] (& $resolver -StateDirectory $legacyDirectory -ExpectedCollectorId $pilotCollector)
    $after = Get-ChildItem -LiteralPath $legacyDirectory -Recurse -Force | ForEach-Object {
        "{0}|{1}|{2}" -f $_.Name, $_.Length, $_.LastWriteTimeUtc.Ticks
    } | Sort-Object
    $credentialTextAfter = Get-Content -LiteralPath (Join-Path $legacyDirectory 'credential.json') -Raw
    if ((Compare-Object $before $after) -or $credentialTextBefore -ne $credentialTextAfter) {
        $results.Add((Add-Result 'identity.state-directory-unchanged' 'FAIL' 'the resolver modified the state directory'))
    }
    else {
        $results.Add((Add-Result 'identity.state-directory-unchanged' 'PASS' 'credential.json and state directory untouched'))
    }
    if (Test-Path -LiteralPath (Join-Path $legacyDirectory 'identity.json')) {
        $results.Add((Add-Result 'identity.no-identity-file-created' 'FAIL' 'resolver created identity.json'))
    }
    else {
        $results.Add((Add-Result 'identity.no-identity-file-created' 'PASS' 'missing identity.json was not fabricated'))
    }

    # 9/10. Static contract: the upgrade path must never enroll or mint identity.
    $scriptText = Get-Content -LiteralPath $UpgradeScriptPath -Raw
    if ($scriptText -match 'KCSP_AGENT_ENROLLMENT_TOKEN\s*=\s*[^*]' -and $scriptText -notmatch "notlike 'KCSP_AGENT_ENROLLMENT_TOKEN") {
        $results.Add((Add-Result 'upgrade.no-enrollment-token' 'FAIL' 'upgrade sets an enrollment token'))
    }
    else {
        $results.Add((Add-Result 'upgrade.no-enrollment-token' 'PASS' 'no enrollment token is ever set'))
    }
    if ($scriptText -match 'KCSP_AGENT_ENROLL_ONLY' -or $scriptText -match 'agent-enrollment') {
        $results.Add((Add-Result 'upgrade.no-second-collector' 'FAIL' 'upgrade can trigger enrollment'))
    }
    else {
        $results.Add((Add-Result 'upgrade.no-second-collector' 'PASS' 'upgrade never runs enrollment, so no second collector'))
    }
    if ($scriptText -match 'Remove-Item[^\r\n]*\$StateDirectory' -or $scriptText -match 'Set-Content[^\r\n]*credential\.json') {
        $results.Add((Add-Result 'upgrade.state-directory-preserved' 'FAIL' 'upgrade writes to or removes the state directory'))
    }
    else {
        $results.Add((Add-Result 'upgrade.state-directory-preserved' 'PASS' 'upgrade never writes credential.json or removes the state directory'))
    }
    # The original defect: a bare property dot on credential JSON.
    if ($scriptText -match '\$credential(Before|After)\.agent_id') {
        $results.Add((Add-Result 'upgrade.no-strictmode-property-dot' 'FAIL' 'agent_id is still read directly off credential.json'))
    }
    else {
        $results.Add((Add-Result 'upgrade.no-strictmode-property-dot' 'PASS' 'optional fields are read through Get-KCSPJsonProperty'))
    }
}
finally {
    $expectedRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedRoot = [IO.Path]::GetFullPath($root)
    if ($resolvedRoot.StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}

$results
if ($script:Failures -gt 0) {
    throw "$($script:Failures) upgrade credential check(s) failed."
}
Write-Verbose 'All upgrade credential checks passed.'
