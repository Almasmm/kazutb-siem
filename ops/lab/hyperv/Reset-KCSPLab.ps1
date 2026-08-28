#requires -Version 5.1
<#
    .SYNOPSIS
    Restores lab endpoints to a named checkpoint so a test can be repeated.

    .DESCRIPTION
    Restoring beats reinstalling: a broken endpoint returns to a known state in
    seconds. Ad-hoc checkpoints beyond the configured named ones are trimmed so
    the differencing chain cannot grow without bound.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $ConfigPath,
    [ValidateSet('CLEAN_WINDOWS', 'SYSMON_INSTALLED', 'KCSP_AGENT_INSTALLED')]
    [string] $Checkpoint = 'KCSP_AGENT_INSTALLED',
    [string[]] $VMName,
    [switch] $PruneOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('reset-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
Assert-KCSPLabElevated

$targets = if ($VMName) { @($VMName | ForEach-Object { Get-VM -Name $_ -ErrorAction Stop }) } else { Get-KCSPLabVMs -Config $config }
foreach ($vm in $targets) {
    Assert-KCSPLabOwned -Config $config -Name $vm.Name -Kind 'VM'

    if (-not $PruneOnly) {
        $snapshot = Get-VMSnapshot -VMName $vm.Name -Name $Checkpoint -ErrorAction SilentlyContinue
        if (-not $snapshot) {
            Write-KCSPLabLog "$($vm.Name) has no checkpoint '$Checkpoint' - skipping" -Level WARN
        } elseif ($PSCmdlet.ShouldProcess($vm.Name, "Restore checkpoint $Checkpoint")) {
            Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
            Write-KCSPLabLog "$($vm.Name) restored to $Checkpoint" -Level PASS
            if ((Get-VM -Name $vm.Name).State -ne 'Running') { Start-VM -Name $vm.Name }
        }
    }

    # Trim ad-hoc checkpoints, keeping the named provisioning ones.
    $named = @($config.Checkpoints)
    $adhoc = @(Get-VMSnapshot -VMName $vm.Name | Where-Object { $named -notcontains $_.Name } | Sort-Object CreationTime -Descending)
    if ($adhoc.Count -gt $config.MaxAdHocCheckpoints) {
        foreach ($old in $adhoc[$config.MaxAdHocCheckpoints..($adhoc.Count - 1)]) {
            if ($PSCmdlet.ShouldProcess("$($vm.Name)/$($old.Name)", 'Remove ad-hoc checkpoint')) {
                Remove-VMSnapshot -VMSnapshot $old -Confirm:$false
                Write-KCSPLabLog "$($vm.Name) pruned checkpoint $($old.Name)" -Level INFO
            }
        }
    }
}
