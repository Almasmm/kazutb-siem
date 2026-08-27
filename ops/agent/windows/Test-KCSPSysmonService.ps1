#requires -Version 5.1
<#
    .SYNOPSIS
    Verifies Sysmon service detection in Install-KCSPSysmon.ps1.

    .DESCRIPTION
    Regression cover for the pilot defect: the installer resolved the service
    with a single Get-Service call naming both 'Sysmon64' and 'Sysmon'. On a
    real host only one of those exists, and with -ErrorAction Stop the absent
    name threw ("Cannot find any service with service name 'Sysmon'") after the
    installation had already succeeded.

    The resolver is lifted out of the installer with the PowerShell parser so
    the installer stays a self-contained script, then exercised against a mocked
    Get-Service for each real-world naming variant.
#>
[CmdletBinding()]
param(
    [string] $InstallerPath = (Join-Path $PSScriptRoot 'Install-KCSPSysmon.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = 0
function Add-Result {
    param([string] $Name, [string] $Status, [string] $Detail = '')
    if ($Status -ne 'PASS') { $script:Failures++ }
    [pscustomobject]@{ check = $Name; status = $Status; detail = $Detail }
}

if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    throw "Installer not found: $InstallerPath"
}

# Extract the resolver function definition from the installer source.
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref] $tokens, [ref] $errors)
if ($errors -and $errors.Count -gt 0) {
    throw "Installer failed to parse: $($errors[0].Message)"
}
$function = $ast.FindAll(
    { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Resolve-KCSPSysmonService' },
    $true) | Select-Object -First 1
if (-not $function) {
    throw 'Install-KCSPSysmon.ps1 no longer defines Resolve-KCSPSysmonService.'
}

$results = New-Object System.Collections.Generic.List[object]

# The installer must never resolve the service with one multi-name, -ErrorAction
# Stop call, which is what produced the reported failure.
$installerText = Get-Content -LiteralPath $InstallerPath -Raw
if ($installerText -match "Get-Service\s+-Name\s+'Sysmon64'\s*,\s*'Sysmon'\s+-ErrorAction\s+Stop") {
    $results.Add((Add-Result 'installer.no-multi-name-stop' 'FAIL' 'installer still requires both service names to exist'))
}
else {
    $results.Add((Add-Result 'installer.no-multi-name-stop' 'PASS' 'resolver probes each candidate individually'))
}

foreach ($scenario in @(
        @{ Name = 'sysmon64-only'; Present = @('Sysmon64'); Expected = 'Sysmon64' },
        @{ Name = 'sysmon32-only'; Present = @('Sysmon'); Expected = 'Sysmon' },
        @{ Name = 'both-present'; Present = @('Sysmon64', 'Sysmon'); Expected = 'Sysmon64' },
        @{ Name = 'none-present'; Present = @(); Expected = $null }
    )) {

    # Fresh scope per scenario so the mock cannot leak between cases.
    $scriptBlock = [scriptblock]::Create(@"
param(`$Present)
function Get-Service {
    param([string[]] `$Name, [string] `$ErrorAction)
    foreach (`$candidate in `$Name) {
        if (`$Present -contains `$candidate) {
            return [pscustomobject]@{ Name = `$candidate; Status = 'Running' }
        }
    }
    return `$null
}
$($function.Extent.Text)
Resolve-KCSPSysmonService @args
"@)

    $resolved = $null
    $threw = $false
    try {
        $resolved = & $scriptBlock $scenario.Present
    }
    catch {
        $threw = $true
        $message = $_.Exception.Message
    }

    if ($null -eq $scenario.Expected) {
        # Without -Require an absent service resolves to $null rather than throwing.
        if (-not $threw -and $null -eq $resolved) {
            $results.Add((Add-Result "resolve.$($scenario.Name)" 'PASS' 'returned null without throwing'))
        }
        else {
            $results.Add((Add-Result "resolve.$($scenario.Name)" 'FAIL' "threw=$threw resolved=$resolved"))
        }
    }
    elseif (-not $threw -and $resolved -and $resolved.Name -eq $scenario.Expected) {
        $results.Add((Add-Result "resolve.$($scenario.Name)" 'PASS' "resolved $($resolved.Name)"))
    }
    else {
        $detail = if ($threw) { "threw: $message" } else { "resolved=$($resolved.Name)" }
        $results.Add((Add-Result "resolve.$($scenario.Name)" 'FAIL' $detail))
    }
}

# -Require must fail loudly, and only when no variant exists at all.
$requireBlock = [scriptblock]::Create(@"
param(`$Present)
function Get-Service {
    param([string[]] `$Name, [string] `$ErrorAction)
    foreach (`$candidate in `$Name) {
        if (`$Present -contains `$candidate) {
            return [pscustomobject]@{ Name = `$candidate; Status = 'Running' }
        }
    }
    return `$null
}
$($function.Extent.Text)
Resolve-KCSPSysmonService -Require
"@)

try {
    $resolved = & $requireBlock @('Sysmon64')
    if ($resolved.Name -eq 'Sysmon64') {
        $results.Add((Add-Result 'require.sysmon64-only' 'PASS' 'Sysmon64 satisfies -Require without Sysmon present'))
    }
    else {
        $results.Add((Add-Result 'require.sysmon64-only' 'FAIL' "resolved=$($resolved.Name)"))
    }
}
catch {
    $results.Add((Add-Result 'require.sysmon64-only' 'FAIL' "threw: $($_.Exception.Message)"))
}

try {
    [void] (& $requireBlock @())
    $results.Add((Add-Result 'require.none-present' 'FAIL' 'expected a terminating error when no service exists'))
}
catch {
    $results.Add((Add-Result 'require.none-present' 'PASS' 'threw when no Sysmon service exists'))
}

$results
if ($script:Failures -gt 0) {
    throw "$($script:Failures) Sysmon service detection check(s) failed."
}
Write-Verbose 'All Sysmon service detection checks passed.'
