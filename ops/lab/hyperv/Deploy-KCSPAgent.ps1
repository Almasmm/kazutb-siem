#requires -Version 5.1
<#
    .SYNOPSIS
    Builds the KCSP agent from current source and installs it into lab endpoints.

    .DESCRIPTION
    The whole path runs from this host with no second operator: build the agent
    from the working tree, package it, copy it into each guest over the VMBus,
    install Sysmon, issue a single-use enrollment token through the KCSP API,
    and install the agent so it enrolls itself.

    Nothing is copied by hand and no guest ever needs RDP or a network share.

    .EXAMPLE
    .\Deploy-KCSPAgent.ps1
    .\Deploy-KCSPAgent.ps1 -VMName KCSP-LAB-WIN-01 -SkipSysmon
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $ConfigPath,
    [string[]] $VMName,
    [switch] $SkipBuild,
    [switch] $SkipSysmon,
    [switch] $NoCheckpoint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('deploy-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
Assert-KCSPLabElevated

$credential = Get-KCSPLabCredential -Config $config
$repo = $config.RepoRoot

# --------------------------------------------------------------- build + package
$packageRoot = Join-Path $paths.Artifacts 'windows-agent'
if (-not $SkipBuild) {
    Write-KCSPLabLog 'Building the Windows agent from the current working tree' -Level STEP
    $goTool = Resolve-KCSPLabGoToolchain -RepoRoot $repo -Environment @{
        GOOS='windows'; GOARCH='amd64'; CGO_ENABLED='0'
    }
    Write-KCSPLabLog "Go toolchain: $($goTool.Kind) $($goTool.Executable)" -Level INFO

    # Version comes from source, never from a hardcoded number.
    $mainGo = Get-Content -LiteralPath (Join-Path $repo 'cmd\agent\main.go') -Raw
    if ($mainGo -notmatch 'agentVersion\s*=\s*"([^"]+)"') { throw 'Could not read agentVersion from cmd/agent/main.go.' }
    $version = $Matches[1]
    Write-KCSPLabLog "Agent version from source: $version" -Level INFO

    $binary = Join-Path $paths.Artifacts 'kcsp-agent.exe'
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    try {
        Push-Location $repo
        $goArguments = @($goTool.PrefixArguments) + @(
            'build', '-trimpath', '-ldflags', "-s -w -X main.agentVersion=$version", '-o', $binary, './cmd/agent'
        )
        & $goTool.Executable @goArguments
        if ($LASTEXITCODE -ne 0) { throw "Agent build failed with exit code $LASTEXITCODE." }
    } finally {
        Pop-Location
        Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $packageRoot) { Remove-Item -LiteralPath $packageRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
    $built = & (Join-Path $repo 'ops\agent\windows\Build-KCSPWindowsPackage.ps1') `
        -Version $version -OutputDirectory $packageRoot -PrebuiltBinary $binary
    Expand-Archive -Path $built.archive -DestinationPath $packageRoot -Force
    Write-KCSPLabLog "Package built: $(Split-Path -Leaf $built.archive)" -Level INFO
}
$agentExe = Join-Path $packageRoot 'kcsp-agent.exe'
if (-not (Test-Path -LiteralPath $agentExe)) { throw "Agent package not found in $packageRoot. Run without -SkipBuild." }
$agentHash = (Get-FileHash -LiteralPath $agentExe -Algorithm SHA256).Hash
$agentVersion = (Get-Item -LiteralPath $agentExe).VersionInfo.FileVersion
Write-KCSPLabLog "Agent SHA-256 $agentHash" -Level INFO

# ------------------------------------------------------------------- endpoints
$targets = if ($VMName) { @($VMName | ForEach-Object { Get-VM -Name $_ -ErrorAction Stop }) } else { Get-KCSPLabVMs -Config $config }
if (-not $targets) { throw 'No lab endpoints found. Run New-KCSPWindowsVM.ps1 first.' }

$ingress = "http://$($config.HostAddress):$($config.IngressPort)"
$results = New-Object System.Collections.Generic.List[object]

foreach ($vm in $targets) {
    Assert-KCSPLabOwned -Config $config -Name $vm.Name -Kind 'VM'
    Write-KCSPLabLog "=== $($vm.Name) ===" -Level STEP
    if ($vm.State -ne 'Running') { Start-VM -Name $vm.Name; Write-KCSPLabLog "$($vm.Name) starting" -Level INFO }
    Wait-KCSPLabGuest -VMName $vm.Name -Credential $credential -TimeoutSeconds 1800 | Out-Null

    # Static lab address, applied by the guest itself.
    Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
        if (Test-Path C:\KCSP\Set-LabNetwork.ps1) {
            powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\KCSP\Set-LabNetwork.ps1 | Out-Null
        }
    } | Out-Null

    $reachable = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList $config.HostAddress, $config.IngressPort -ScriptBlock {
        param($labHost, $port)
        try { (Test-NetConnection -ComputerName $labHost -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded } catch { $false }
    }
    Write-KCSPLabLog "$($vm.Name) -> KCSP ingress reachable: $reachable" -Level $(if ($reachable) { 'INFO' } else { 'WARN' })

    # ------------------------------------------------------------------ Sysmon
    if (-not $SkipSysmon) {
        $sysmonState = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ArgumentList $config.SysmonUrl -ScriptBlock {
            param($url)
            $existing = foreach ($name in 'Sysmon64', 'Sysmon') {
                $service = Get-Service -Name $name -ErrorAction SilentlyContinue
                if ($service) { $service; break }
            }
            if ($existing) { return "already-installed:$($existing.Name):$($existing.Status)" }
            New-Item -ItemType Directory -Path C:\KCSP\sysmon -Force | Out-Null
            $zip = 'C:\KCSP\sysmon\Sysmon.zip'
            if (-not (Test-Path C:\KCSP\sysmon\Sysmon64.exe)) {
                if (-not (Test-Path $zip)) {
                    try {
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 180
                    } catch { return "download-failed:$($_.Exception.Message)" }
                }
                try { Expand-Archive -Path $zip -DestinationPath C:\KCSP\sysmon -Force } catch { return "extract-failed:$($_.Exception.Message)" }
            }
            if (-not (Test-Path C:\KCSP\sysmon\Sysmon64.exe)) { return 'binary-missing' }
            & C:\KCSP\sysmon\Sysmon64.exe -accepteula -i 2>&1 | Out-Null
            Start-Sleep -Seconds 5
            $service = foreach ($name in 'Sysmon64', 'Sysmon') {
                $candidate = Get-Service -Name $name -ErrorAction SilentlyContinue
                if ($candidate) { $candidate; break }
            }
            if ($service) { return "installed:$($service.Name):$($service.Status)" }
            return 'install-failed'
        }
        Write-KCSPLabLog "$($vm.Name) Sysmon: $sysmonState" -Level $(if ("$sysmonState" -like '*Running*') { 'INFO' } else { 'WARN' })
    }

    # ----------------------------------------------------------- copy package
    Write-KCSPLabLog "$($vm.Name) copying agent package over the VMBus" -Level INFO
    Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
        New-Item -ItemType Directory -Path C:\KCSP\agent -Force | Out-Null
    } | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $packageRoot -File | Where-Object { $_.Extension -in '.exe', '.ps1', '.json', '.xml' }) {
        Copy-KCSPLabFileToGuest -VMName $vm.Name -Credential $credential -Source $file.FullName -Destination "C:\KCSP\agent\$($file.Name)" | Out-Null
    }

    $guestHash = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
        (Get-FileHash -LiteralPath 'C:\KCSP\agent\kcsp-agent.exe' -Algorithm SHA256).Hash
    }
    if ($guestHash -ne $agentHash) { throw "$($vm.Name): agent transferred with a different digest ($guestHash != $agentHash)." }
    Write-KCSPLabLog "$($vm.Name) package verified in guest" -Level INFO

    # ------------------------------------------------------------- enrollment
    $alreadyEnrolled = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
        Test-Path 'C:\ProgramData\KCSP\agent\credential.json'
    }
    if ($alreadyEnrolled) {
        Write-KCSPLabLog "$($vm.Name) already enrolled - upgrading in place instead" -Level INFO
        $upgrade = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
            & C:\KCSP\agent\Upgrade-KCSPAgent.ps1 -HealthCheckSeconds 20 2>&1 | Out-String
        }
        Write-KCSPLabLog "$($vm.Name) upgrade output captured" -Level INFO
    } else {
        $issued = New-KCSPLabEnrollmentToken -Config $config -Label $vm.Name
        Write-KCSPLabLog "$($vm.Name) enrollment token issued ($($issued.token.token_id))" -Level INFO
        $install = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential `
            -ArgumentList $ingress, $config.TenantId, $issued.enrollment_token, $agentHash -ScriptBlock {
            param($serverUrl, $tenant, $token, $expectedHash)
            $secure = ConvertTo-SecureString -String $token -AsPlainText -Force
            & C:\KCSP\agent\Install-KCSPAgent.ps1 -ServerUrl $serverUrl -TenantId $tenant `
                -EnrollmentToken $secure -ExpectedSha256 $expectedHash -AllowInsecureHttp -NonInteractive 2>&1 | Out-String
        }
        # The one-time token is consumed by enrollment; nothing is persisted.
        Write-KCSPLabLog "$($vm.Name) install completed" -Level INFO
    }

    $state = Invoke-KCSPLabGuest -VMName $vm.Name -Credential $credential -ScriptBlock {
        $service = Get-Service -Name KCSPAgent -ErrorAction SilentlyContinue
        $credentialPath = 'C:\ProgramData\KCSP\agent\credential.json'
        $collectorId = $null
        if (Test-Path $credentialPath) {
            $parsed = Get-Content $credentialPath -Raw | ConvertFrom-Json
            $property = $parsed.PSObject.Properties['collector_id']
            if ($property) { $collectorId = [string] $property.Value }
        }
        [pscustomobject]@{
            Service = $(if ($service) { $service.Status.ToString() } else { 'missing' })
            CollectorId = $collectorId
            Hostname = $env:COMPUTERNAME
        }
    }
    Write-KCSPLabLog "$($vm.Name) service=$($state.Service) collector=$($state.CollectorId)" -Level PASS

    if (-not $NoCheckpoint -and $state.CollectorId) {
        $name = 'KCSP_AGENT_INSTALLED'
        Get-VMSnapshot -VMName $vm.Name -Name $name -ErrorAction SilentlyContinue | Remove-VMSnapshot -Confirm:$false -ErrorAction SilentlyContinue
        Checkpoint-VM -Name $vm.Name -SnapshotName $name
        Write-KCSPLabLog "$($vm.Name) checkpoint $name created" -Level INFO
    }

    $results.Add([pscustomobject]@{
        VM = $vm.Name; Hostname = $state.Hostname; Service = $state.Service
        CollectorId = $state.CollectorId; AgentSha256 = $agentHash; Version = $agentVersion
    })
}

$results
