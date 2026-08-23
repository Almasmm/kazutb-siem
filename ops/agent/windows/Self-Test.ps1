#requires -Version 5.1
[CmdletBinding()]
param([string] $PrebuiltBinary)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scripts = Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File
foreach ($script in $scripts) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref] $tokens, [ref] $parseErrors) | Out-Null
    if ($parseErrors.Count -gt 0) {
        throw "PowerShell parser errors in $($script.Name): $($parseErrors -join '; ')"
    }
}
[xml] $sysmon = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'sysmon-kcsp.xml') -Raw
if ($sysmon.DocumentElement.Name -ne 'Sysmon') {
    throw 'Sysmon baseline XML is invalid.'
}
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("kcsp-windows-self-test-{0}" -f [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    $inventoryPath = Join-Path $temporaryRoot 'inventory.csv'
    $inventory = for ($index = 1; $index -le 2001; $index++) {
        [pscustomobject]@{ Hostname = 'campus-{0:D4}' -f $index; Site = 'main'; Criticality = $(if ($index -gt 1950) { 'critical' } else { 'standard' }) }
    }
    $inventory | Export-Csv -LiteralPath $inventoryPath -NoTypeInformation -Encoding UTF8
    $rolloutDirectory = Join-Path $temporaryRoot 'rollout'
    & (Join-Path $PSScriptRoot 'New-KCSPRolloutPlan.ps1') -InventoryPath $inventoryPath -OutputDirectory $rolloutDirectory -CanarySize 25 -WaveSize 250 | Out-Null
    $plan = @(Import-Csv -LiteralPath (Join-Path $rolloutDirectory 'rollout-plan.csv'))
    if ($plan.Count -ne 2001 -or @($plan | Select-Object -ExpandProperty Hostname -Unique).Count -ne 2001) {
        throw 'Rollout plan lost or duplicated hosts.'
    }
    if (@($plan | Where-Object { $_.rollout_wave -eq 'canary' }).Count -ne 25) {
        throw 'Rollout canary size contract failed.'
    }
    foreach ($group in @($plan | Where-Object { $_.rollout_wave -ne 'canary' } | Group-Object rollout_wave)) {
        if ($group.Count -gt 250) { throw "Rollout wave $($group.Name) exceeds 250 hosts." }
    }
    if (-not [string]::IsNullOrWhiteSpace($PrebuiltBinary)) {
        $packageDirectory = Join-Path $temporaryRoot 'package'
        $package = & (Join-Path $PSScriptRoot 'Build-KCSPWindowsPackage.ps1') -Version '0.5.0-test' -OutputDirectory $packageDirectory -PrebuiltBinary $PrebuiltBinary
        if (-not (Test-Path -LiteralPath $package.archive -PathType Leaf) -or (Get-FileHash -LiteralPath $package.archive -Algorithm SHA256).Hash -ne $package.sha256) {
            throw 'Windows package archive integrity contract failed.'
        }
        $expandedPackage = Join-Path $temporaryRoot 'expanded-package'
        Expand-Archive -LiteralPath $package.archive -DestinationPath $expandedPackage
        $manifestPath = Join-Path $expandedPackage 'manifest.json'
        $manifestDigest = ((Get-Content -LiteralPath (Join-Path $expandedPackage 'manifest.sha256') -Raw).Trim() -split '\s+')[0]
        if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -ne $manifestDigest) {
            throw 'Windows package manifest digest contract failed.'
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        foreach ($entry in $manifest.files) {
            $packagedFile = Join-Path $expandedPackage $entry.path
            if (-not (Test-Path -LiteralPath $packagedFile -PathType Leaf) -or (Get-FileHash -LiteralPath $packagedFile -Algorithm SHA256).Hash -ne $entry.sha256) {
                throw "Windows package file digest failed: $($entry.path)"
            }
        }
        if (@($manifest.files | Where-Object { $_.path -eq 'kcsp-agent.exe' }).Count -ne 1) {
            throw 'Windows package does not contain exactly one agent binary.'
        }
    }
    [pscustomobject]@{ status = 'ok'; scripts = $scripts.Count; rollout_hosts = $plan.Count; maximum_wave = 250; package_tested = (-not [string]::IsNullOrWhiteSpace($PrebuiltBinary)) } | ConvertTo-Json -Compress
}
finally {
    $expectedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    if ($resolvedTemporaryRoot.StartsWith($expectedTempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTemporaryRoot)) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
