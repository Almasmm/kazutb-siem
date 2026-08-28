#requires -Version 5.1
<#
    .SYNOPSIS
    Removes lab resources. Guarded so it can only ever touch the lab.

    .DESCRIPTION
    Every VM, disk, switch and NAT this removes must carry the configured lab
    prefix. Docker volumes, the KCSP stack data, unrelated Hyper-V VMs and the
    physical pilot endpoint are never in scope and are never touched.

    Requires -ConfirmDestroy; without it the script only reports what it would
    remove.

    .EXAMPLE
    .\Destroy-KCSPLab.ps1                       # dry run
    .\Destroy-KCSPLab.ps1 -ConfirmDestroy
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $ConfirmDestroy,
    [switch] $KeepBaseImage,
    [switch] $KeepNetwork
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('destroy-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
Assert-KCSPLabElevated

if (-not $ConfirmDestroy) {
    Write-KCSPLabLog 'DRY RUN - pass -ConfirmDestroy to actually remove anything' -Level WARN
}

$plan = New-Object System.Collections.Generic.List[string]
foreach ($vm in Get-KCSPLabVMs -Config $config) { $plan.Add("VM        $($vm.Name)") }
if (-not $KeepNetwork) {
    if (Get-VMSwitch -Name $config.Prefix -ErrorAction SilentlyContinue) { $plan.Add("Switch    $($config.Prefix)") }
    if (Get-NetNat -Name "$($config.Prefix)-NAT" -ErrorAction SilentlyContinue) { $plan.Add("NAT       $($config.Prefix)-NAT") }
    $plan.Add("Ingress   $($config.HostAddress):$($config.IngressPort)")
}
if (-not $KeepBaseImage) {
    $baseDisk = Join-Path $paths.Base "$($config.Prefix)-WIN-BASE.vhdx"
    if (Test-Path -LiteralPath $baseDisk) { $plan.Add("Base disk $baseDisk") }
}
if ($plan.Count -eq 0) { Write-KCSPLabLog 'Nothing to remove.' -Level INFO; return }
foreach ($line in $plan) { Write-KCSPLabLog "would remove: $line" -Level INFO }
if (-not $ConfirmDestroy) { return }

foreach ($vm in Get-KCSPLabVMs -Config $config) {
    # Guard again immediately before the destructive call.
    Assert-KCSPLabOwned -Config $config -Name $vm.Name -Kind 'VM'
    $disks = @(Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path)
    if ($vm.State -ne 'Off') { Stop-VM -Name $vm.Name -TurnOff -Force }
    Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue | Remove-VMSnapshot -Confirm:$false -ErrorAction SilentlyContinue
    Remove-VM -Name $vm.Name -Force
    Write-KCSPLabLog "removed VM $($vm.Name)" -Level WARN
    foreach ($disk in $disks) {
        # Only disks that live under the lab VM directory are ever deleted.
        if ($disk -and $disk.StartsWith($paths.VMs, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $disk)) {
            Remove-Item -LiteralPath $disk -Force
            Write-KCSPLabLog "removed disk $disk" -Level WARN
        }
    }
    $directory = Join-Path $paths.VMs $vm.Name
    if ((Test-Path -LiteralPath $directory) -and $directory.StartsWith($paths.VMs, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not $KeepNetwork) {
    Remove-KCSPLabIngress -Config $config
    Get-NetNat -Name "$($config.Prefix)-NAT" -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue
    Get-VMSwitch -Name $config.Prefix -ErrorAction SilentlyContinue | Remove-VMSwitch -Force -ErrorAction SilentlyContinue
    Write-KCSPLabLog 'removed lab network' -Level WARN
}
if (-not $KeepBaseImage) {
    $baseDisk = Join-Path $paths.Base "$($config.Prefix)-WIN-BASE.vhdx"
    if (Test-Path -LiteralPath $baseDisk) {
        Remove-Item -LiteralPath $baseDisk -Force
        Write-KCSPLabLog 'removed base image' -Level WARN
    }
}
Write-KCSPLabLog 'Lab destroyed. Docker volumes, KCSP data and the physical pilot were not touched.' -Level PASS
