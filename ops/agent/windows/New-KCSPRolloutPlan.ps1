#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $InventoryPath,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [ValidateRange(1, 100)] [int] $CanarySize = 25,
    [ValidateRange(1, 500)] [int] $WaveSize = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inventory = @(Import-Csv -LiteralPath $InventoryPath)
if ($inventory.Count -eq 0 -or -not ($inventory[0].PSObject.Properties.Name -contains 'Hostname')) {
    throw 'Inventory must contain at least one row and a Hostname column.'
}
$seen = @{}
$prepared = foreach ($row in $inventory) {
    $hostname = ([string] $row.Hostname).Trim()
    if ($hostname -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,253}$') {
        throw "Invalid hostname in inventory: $hostname"
    }
    $key = $hostname.ToLowerInvariant()
    if ($seen.ContainsKey($key)) {
        throw "Duplicate hostname in inventory: $hostname"
    }
    $seen[$key] = $true
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
    $criticality = if ($row.PSObject.Properties.Name -contains 'Criticality') { ([string] $row.Criticality).Trim().ToLowerInvariant() } else { '' }
    [pscustomobject]@{ row = $row; hash = $digest; critical = ($criticality -in @('critical', 'tier-0', 'tier0')) }
}
$ordered = @($prepared | Sort-Object @{ Expression = 'critical'; Ascending = $true }, @{ Expression = 'hash'; Ascending = $true })
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$records = for ($index = 0; $index -lt $ordered.Count; $index++) {
    $wave = if ($index -lt [Math]::Min($CanarySize, $ordered.Count)) { 'canary' } else { 'wave-{0:D3}' -f ([int] [Math]::Floor(($index - $CanarySize) / $WaveSize) + 1) }
    $record = [ordered]@{}
    foreach ($property in $ordered[$index].row.PSObject.Properties) {
        $record[$property.Name] = $property.Value
    }
    $record.rollout_wave = $wave
    $record.rollout_sequence = $index + 1
    [pscustomobject] $record
}
$planPath = Join-Path $OutputDirectory 'rollout-plan.csv'
$records | Export-Csv -LiteralPath $planPath -NoTypeInformation -Encoding UTF8
$groups = @($records | Group-Object rollout_wave | Sort-Object Name | ForEach-Object { [pscustomobject]@{ wave = $_.Name; hosts = $_.Count } })
$summary = [ordered]@{
    schema = 'kcsp.windows-agent.rollout/v1'
    generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    total_hosts = $records.Count
    canary_size = @($records | Where-Object { $_.rollout_wave -eq 'canary' }).Count
    maximum_wave_size = $WaveSize
    waves = $groups
}
$summaryPath = Join-Path $OutputDirectory 'rollout-summary.json'
[IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
[pscustomobject]@{ plan = $planPath; summary = $summaryPath; total_hosts = $records.Count; waves = $groups.Count }
