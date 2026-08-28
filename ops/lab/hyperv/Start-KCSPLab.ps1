#requires -Version 5.1
<#
    .SYNOPSIS
    Starts the lab: KCSP stack, network, ingress and every lab endpoint.
#>
[CmdletBinding()]
param([string] $ConfigPath, [switch] $SkipStack)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('start-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
Assert-KCSPLabElevated

if (-not $SkipStack) {
    Write-KCSPLabLog 'Starting the KCSP stack' -Level STEP
    Push-Location $config.RepoRoot
    try {
        & docker compose up -d | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "docker compose up failed ($LASTEXITCODE)" }
    } finally { Pop-Location }

    $deadline = (Get-Date).AddSeconds(300)
    while ((Get-Date) -lt $deadline) {
        try {
            $ready = Invoke-RestMethod "http://127.0.0.1:$($config.ApiPort)/health/ready" -TimeoutSec 5
            if ($ready.status -eq 'ready') { Write-KCSPLabLog "KCSP API ready ($($ready.profile))" -Level PASS; break }
        } catch { }
        Start-Sleep -Seconds 5
    }
}

Initialize-KCSPLabNetwork -Config $config | Out-Null
$ingress = Set-KCSPLabIngress -Config $config
Write-KCSPLabLog "Lab ingress: $ingress" -Level INFO

foreach ($vm in Get-KCSPLabVMs -Config $config) {
    Assert-KCSPLabOwned -Config $config -Name $vm.Name -Kind 'VM'
    if ($vm.State -ne 'Running') {
        Start-VM -Name $vm.Name
        Write-KCSPLabLog "$($vm.Name) started" -Level INFO
    } else {
        Write-KCSPLabLog "$($vm.Name) already running" -Level INFO
    }
}
Write-KCSPLabLog 'Lab started' -Level PASS
