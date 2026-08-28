#requires -Version 5.1
<#
    .SYNOPSIS
    Stops lab endpoints, and optionally the KCSP stack. Never removes volumes.
#>
[CmdletBinding()]
param([string] $ConfigPath, [switch] $IncludeStack, [switch] $TurnOff)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('stop-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
Assert-KCSPLabElevated

foreach ($vm in Get-KCSPLabVMs -Config $config) {
    Assert-KCSPLabOwned -Config $config -Name $vm.Name -Kind 'VM'
    if ($vm.State -eq 'Off') { continue }
    if ($TurnOff) { Stop-VM -Name $vm.Name -TurnOff -Force } else { Stop-VM -Name $vm.Name -Force }
    Write-KCSPLabLog "$($vm.Name) stopped" -Level INFO
}

if ($IncludeStack) {
    # Controlled stop only. Volumes and data are never removed.
    Push-Location $config.RepoRoot
    try { & docker compose stop | Out-Null } finally { Pop-Location }
    Write-KCSPLabLog 'KCSP stack stopped (volumes preserved)' -Level INFO
}
Write-KCSPLabLog 'Lab stopped' -Level PASS
