#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'KCSP\Agent'),
    [string] $StateDirectory = (Join-Path $env:ProgramData 'KCSP\agent'),
    [switch] $PurgeState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'KCSPAgent'
$serviceAccount = 'NT SERVICE\KCSPAgent'

function Assert-ExpectedDirectory {
    param([string] $Path, [string] $Root)
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $fullPath.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove path outside expected root: $fullPath"
    }
    return $fullPath
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to delete KCSPAgent service.'
    }
}
$eventLogReaders = Get-LocalGroup -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue
if ($eventLogReaders) {
    Remove-LocalGroupMember -Group $eventLogReaders -Member $serviceAccount -ErrorAction SilentlyContinue
}
$safeInstallDirectory = Assert-ExpectedDirectory -Path $InstallDirectory -Root $env:ProgramFiles
if ((Test-Path -LiteralPath $safeInstallDirectory) -and $PSCmdlet.ShouldProcess($safeInstallDirectory, 'Remove KCSP agent binaries')) {
    Remove-Item -LiteralPath $safeInstallDirectory -Recurse -Force
}
if ($PurgeState) {
    $safeStateDirectory = Assert-ExpectedDirectory -Path $StateDirectory -Root $env:ProgramData
    if ((Test-Path -LiteralPath $safeStateDirectory) -and $PSCmdlet.ShouldProcess($safeStateDirectory, 'Permanently remove KCSP credentials, queue and checkpoints')) {
        Remove-Item -LiteralPath $safeStateDirectory -Recurse -Force
    }
}
[pscustomobject]@{ service = $serviceName; removed = $true; state_preserved = (-not $PurgeState) }
