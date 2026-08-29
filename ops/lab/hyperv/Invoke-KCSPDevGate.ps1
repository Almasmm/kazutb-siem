#requires -Version 5.1
<#
    .SYNOPSIS
    The developer gate: unit tests, build, deploy to the lab, and prove it works.

    .DESCRIPTION
    One command to run after changing the agent or the data plane. It runs the
    portable test suites first (fast, no VM), then the Windows acceptance in the
    Hyper-V lab. A non-zero exit means the change is not ready to push.

    The Hyper-V half is skipped automatically when the lab is not available, so
    the same command still gives useful signal on a machine without the range -
    but it reports the skip rather than pretending the gate was green.

    .EXAMPLE
    .\Invoke-KCSPDevGate.ps1
    .\Invoke-KCSPDevGate.ps1 -IncludeChaos -IncludeUpgrade
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $SkipUnit,
    [switch] $SkipLab,
    [switch] $IncludeChaos,
    [switch] $IncludeUpgrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
$resultsRoot = Join-Path $config.RepoRoot '.artifacts\lab-results'
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('devgate-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))

$report = New-KCSPLabReport -Name 'KCSP developer gate'
$repo = $config.RepoRoot
$reportDirectory = Join-Path $resultsRoot $report.StartedAt.ToString('yyyyMMdd-HHmmss')
$commandLogRoot = Join-Path $reportDirectory 'command-logs'
New-Item -ItemType Directory -Path $commandLogRoot -Force | Out-Null

function Invoke-Gate {
    param([string] $Name, [scriptblock] $Body, [switch] $Optional)
    $start = Get-Date
    try {
        # Never inherit an exit code from an earlier external command. Lab
        # stages either throw or explicitly set LASTEXITCODE in this scope.
        $global:LASTEXITCODE = $null
        & $Body
        $ok = ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE)
        $seconds = ((Get-Date) - $start).TotalSeconds
        Add-KCSPLabCheck -Report $report -Name $Name -Status $(if ($ok) { 'PASS' } else { 'FAIL' }) `
            -Detail $(if ($ok) { 'ok' } else { "exit code $LASTEXITCODE" }) -DurationSeconds $seconds
        return $ok
    } catch {
        $seconds = ((Get-Date) - $start).TotalSeconds
        Add-KCSPLabCheck -Report $report -Name $Name -Status $(if ($Optional) { 'SKIP' } else { 'FAIL' }) `
            -Detail $_.Exception.Message -DurationSeconds $seconds
        return [bool] $Optional
    }
}

function Resolve-KCSPApplication {
    param([Parameter(Mandatory)] [string] $Name)
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { return $null }
    $pathProperty = $command.PSObject.Properties['Path']
    if ($pathProperty -and (Test-Path -LiteralPath $pathProperty.Value -PathType Leaf)) { return [string] $pathProperty.Value }
    $sourceProperty = $command.PSObject.Properties['Source']
    if ($sourceProperty -and (Test-Path -LiteralPath $sourceProperty.Value -PathType Leaf)) { return [string] $sourceProperty.Value }
    return $null
}

function Resolve-KCSPGoToolchain {
    $normal = Resolve-KCSPApplication -Name 'go'
    if ($normal) { return [pscustomobject]@{ Kind='native'; Executable=$normal; PrefixArguments=@() } }

    $localCandidates = @(
        (Join-Path $repo '.tools\go\bin\go.exe'),
        (Join-Path $repo '.tools\go\bin\go')
    )
    foreach ($candidate in $localCandidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [pscustomobject]@{ Kind='repository-local'; Executable=$candidate; PrefixArguments=@() }
        }
    }

    $docker = Resolve-KCSPApplication -Name 'docker'
    if ($docker) {
        & $docker version --format '{{.Server.Version}}' *> $null
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{
                Kind='docker'; Executable=$docker
                PrefixArguments=@('run','--rm','--mount',"type=bind,source=$repo,target=/src",'-w','/src','golang:1.25','go')
            }
        }
    }
    throw 'TOOLCHAIN_MISSING: no Go application on PATH, repository-local Go, or reachable Docker Go toolchain.'
}

function Resolve-KCSPRaceToolchain {
    param([Parameter(Mandatory)] $Primary)
    if ($Primary.Kind -eq 'docker') { return $Primary }
    $docker = Resolve-KCSPApplication -Name 'docker'
    if ($docker) {
        & $docker version --format '{{.Server.Version}}' *> $null
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{
                Kind='docker-race'; Executable=$docker
                PrefixArguments=@('run','--rm','--mount',"type=bind,source=$repo,target=/src",'-w','/src','golang:1.25','go')
            }
        }
    }
    return $Primary
}

function Format-KCSPCommandLine {
    param([string] $Executable, [string[]] $Arguments)
    $formatted = @($Executable) + @($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    })
    return ($formatted -join ' ')
}

function Invoke-GateCommand {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Executable,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter(Mandatory)] [string] $WorkingDirectory
    )
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        Add-KCSPLabCheck -Report $report -Name $Name -Status 'FAIL' -Detail "TOOLCHAIN_MISSING: $Executable"
        return $false
    }
    $safeName = $Name -replace '[^A-Za-z0-9_.-]', '_'
    $stdoutPath = Join-Path $commandLogRoot "$safeName.stdout.log"
    $stderrPath = Join-Path $commandLogRoot "$safeName.stderr.log"
    $commandLine = Format-KCSPCommandLine -Executable $Executable -Arguments $Arguments
    $started = Get-Date
    $exitCode = -1
    try {
        Push-Location $WorkingDirectory
        try {
            $global:LASTEXITCODE = 0
            & $Executable @Arguments 1> $stdoutPath 2> $stderrPath
            $exitCode = [int] $LASTEXITCODE
        } finally { Pop-Location }
    } catch {
        [IO.File]::AppendAllText($stderrPath, $_.Exception.ToString() + [Environment]::NewLine)
    }
    $seconds = ((Get-Date) - $started).TotalSeconds
    if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath | Write-Host }
    if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath | Write-Host }
    $report.Facts["command.$Name"] = [ordered]@{
        executable=$Executable; command=$commandLine; exit_code=$exitCode
        stdout=$stdoutPath; stderr=$stderrPath; duration_seconds=[math]::Round($seconds,3)
    }
    $ok = $exitCode -eq 0
    Add-KCSPLabCheck -Report $report -Name $Name -Status $(if ($ok) { 'PASS' } else { 'FAIL' }) `
        -Detail "exit_code=$exitCode executable=$Executable stdout=$stdoutPath stderr=$stderrPath" -DurationSeconds $seconds
    return $ok
}

# --------------------------------------------------------------- portable suites
if (-not $SkipUnit) {
    try {
        $goTool = Resolve-KCSPGoToolchain
        $report.Facts['go.toolchain'] = [ordered]@{ kind=$goTool.Kind; executable=$goTool.Executable }
        Invoke-GateCommand 'portable.go.vet' $goTool.Executable (@($goTool.PrefixArguments) + @('vet','./...')) $repo | Out-Null
        Invoke-GateCommand 'portable.go.test' $goTool.Executable (@($goTool.PrefixArguments) + @('test','./...','-count=1')) $repo | Out-Null
        $raceTool = Resolve-KCSPRaceToolchain -Primary $goTool
        Invoke-GateCommand 'portable.go.race' $raceTool.Executable (@($raceTool.PrefixArguments) + @('test','-race','./...','-count=1')) $repo | Out-Null

        $agentOutput = Join-Path $commandLogRoot 'kcsp-agent.exe'
        Invoke-GateCommand 'windows.agent.build' $goTool.Executable (@($goTool.PrefixArguments) + @('build','-trimpath','-o',$agentOutput,'./cmd/agent')) $repo | Out-Null
    } catch {
        Add-KCSPLabCheck -Report $report -Name 'portable.go.toolchain' -Status 'FAIL' -Detail $_.Exception.Message
    }

    $windowsPowerShell = Resolve-KCSPApplication -Name 'powershell.exe'
    if ($windowsPowerShell) {
        $pesterCommand = "Invoke-Pester -Path '$((Join-Path $PSScriptRoot 'KCSPLab.Network.Tests.ps1').Replace("'", "''"))' -EnableExit"
        Invoke-GateCommand 'windows.powershell.test' $windowsPowerShell @('-NoProfile','-Command',$pesterCommand) $repo | Out-Null
    } else {
        Add-KCSPLabCheck -Report $report -Name 'windows.powershell.test' -Status 'FAIL' -Detail 'TOOLCHAIN_MISSING: powershell.exe'
    }

    $npm = Resolve-KCSPApplication -Name 'npm'
    if ($npm) {
        Invoke-GateCommand 'portable.web.test' $npm @('--prefix',(Join-Path $repo 'apps\web'),'run','test','--if-present') $repo | Out-Null
        Invoke-GateCommand 'portable.web.build' $npm @('--prefix',(Join-Path $repo 'apps\web'),'run','build') $repo | Out-Null
    } else {
        Add-KCSPLabCheck -Report $report -Name 'portable.web.toolchain' -Status 'FAIL' -Detail 'TOOLCHAIN_MISSING: npm application not found'
    }
}

# ---------------------------------------------------------- Windows acceptance
$labAvailable = $false
if (-not $SkipLab) {
    if (-not (Test-KCSPLabElevated)) {
        Add-KCSPLabCheck -Report $report -Name 'lab.available' -Status 'SKIP' -Detail 'ELEVATION_REQUIRED for the Hyper-V half'
    } else {
        try {
            Get-VMHost -ErrorAction Stop | Out-Null
            $labAvailable = @(Get-KCSPLabVMs -Config $config).Count -gt 0
            Add-KCSPLabCheck -Report $report -Name 'lab.available' -Status $(if ($labAvailable) { 'PASS' } else { 'SKIP' }) `
                -Detail $(if ($labAvailable) { 'lab endpoints present' } else { 'no lab endpoints - run Bootstrap-KCSPLab.ps1' })
        } catch {
            Add-KCSPLabCheck -Report $report -Name 'lab.available' -Status 'SKIP' -Detail 'Hyper-V not reachable'
        }
    }
}

if ($labAvailable) {
    Invoke-Gate 'lab.deploy' { & (Join-Path $PSScriptRoot 'Deploy-KCSPAgent.ps1') -ConfigPath $ConfigPath | Out-Null } | Out-Null
    Invoke-Gate 'lab.e2e' { & (Join-Path $PSScriptRoot 'Invoke-KCSPLabTests.ps1') -ConfigPath $ConfigPath -IncludeDetection } | Out-Null
    if ($IncludeUpgrade) {
        Invoke-Gate 'lab.upgrade' { & (Join-Path $PSScriptRoot 'Upgrade-KCSPAgents.ps1') -ConfigPath $ConfigPath -SkipBuild } | Out-Null
    }
    if ($IncludeChaos) {
        Invoke-Gate 'lab.chaos' { & (Join-Path $PSScriptRoot 'Invoke-KCSPChaosTests.ps1') -ConfigPath $ConfigPath } | Out-Null
    }
}

$saved = Save-KCSPLabReport -Report $report -OutputRoot $resultsRoot
Write-KCSPLabLog "DEV GATE $($saved.Result) - $($saved.Passed) passed, $($saved.Failed) failed, $($saved.Skipped) skipped" `
    -Level $(if ($saved.Result -eq 'PASS') { 'PASS' } else { 'FAIL' })
Write-KCSPLabLog "Report: $($saved.Directory)" -Level INFO
$saved
if ($saved.Failed -gt 0) { exit 1 }
