#requires -Version 5.1
<#
    .SYNOPSIS
    Validates the lab tooling and reports exactly what is blocking a real run.

    .DESCRIPTION
    Runs without elevation and without Hyper-V. It parses every lab script,
    loads the module, exercises the pure logic (naming, ownership guards,
    reporting) against real temp files, and then reports host readiness:
    elevation, Hyper-V, Windows ISO, disk and KCSP API.

    This is the check to run first; it distinguishes "the tooling is broken"
    from "the host is not ready yet".

    .EXAMPLE
    .\Test-KCSPLabPreflight.ps1
#>
[CmdletBinding()]
param([string] $ConfigPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:Failures = 0
$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([string] $Check, [string] $Status, [string] $Detail = '')
    if ($Status -eq 'FAIL') { $script:Failures++ }
    $results.Add([pscustomobject]@{ check = $Check; status = $Status; detail = $Detail })
}

# ------------------------------------------------------------ 1. every script parses
$scripts = Get-ChildItem -LiteralPath $PSScriptRoot -Filter *.ps1 | Sort-Object Name
$scripts += Get-ChildItem -LiteralPath $PSScriptRoot -Filter *.psm1
foreach ($file in $scripts) {
    $errors = $null
    [void] [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref] $null, [ref] $errors)
    if ($errors -and $errors.Count -gt 0) {
        Add-Result "parse.$($file.Name)" 'FAIL' $errors[0].Message
    } else {
        Add-Result "parse.$($file.Name)" 'PASS' ''
    }
}

# --------------------------------------------------------------- 2. module surface
try {
    Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force -ErrorAction Stop
    $required = @(
        'Get-KCSPLabConfig', 'Get-KCSPLabPaths', 'Write-KCSPLabLog', 'Test-KCSPLabElevated',
        'Resolve-KCSPLabApplication', 'Resolve-KCSPLabGoToolchain',
        'Assert-KCSPLabElevated', 'Get-KCSPLabHyperVStatus', 'Get-KCSPLabCredential',
        'Get-KCSPLabVMName', 'Get-KCSPLabVMAddress', 'Assert-KCSPLabOwned', 'Get-KCSPLabVMs',
        'ConvertTo-KCSPLabObjectArray', 'Get-KCSPLabBaseDependencies', 'Get-KCSPLabBaseImageState', 'Ensure-KCSPLabBaseImage',
        'Assert-KCSPLabBaseImageRemovalSafe', 'Remove-KCSPLabInvalidBaseImage', 'Test-KCSPLabBaseImage',
        'Ensure-KCSPLabNetwork', 'Initialize-KCSPLabNetwork', 'Set-KCSPLabIngress', 'Wait-KCSPLabGuest', 'Invoke-KCSPLabGuest',
        'Copy-KCSPLabFileToGuest', 'Invoke-KCSPApi', 'New-KCSPLabReport', 'Add-KCSPLabCheck', 'Save-KCSPLabReport'
    )
    $missing = @($required | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
    if ($missing.Count -gt 0) { Add-Result 'module.exports' 'FAIL' "missing: $($missing -join ', ')" }
    else { Add-Result 'module.exports' 'PASS' "$($required.Count) functions exported" }
} catch {
    Add-Result 'module.exports' 'FAIL' $_.Exception.Message
    $results | Format-Table -AutoSize
    throw
}

# ------------------------------------------------------------------ 3. config
$config = $null
try {
    $config = Get-KCSPLabConfig -ConfigPath $ConfigPath
    Add-Result 'config.load' 'PASS' "prefix=$($config.Prefix) from $(Split-Path -Leaf $config.ConfigPath)"
} catch {
    Add-Result 'config.load' 'FAIL' $_.Exception.Message
}

if ($config) {
    # Naming must be deterministic and per-endpoint distinct.
    $names = 1..4 | ForEach-Object { Get-KCSPLabVMName -Config $config -Index $_ }
    $addresses = 1..4 | ForEach-Object { Get-KCSPLabVMAddress -Config $config -Index $_ }
    $uniqueNames = @($names | Select-Object -Unique).Count
    $uniqueAddresses = @($addresses | Select-Object -Unique).Count
    Add-Result 'naming.unique_per_endpoint' $(if ($uniqueNames -eq 4 -and $uniqueAddresses -eq 4) { 'PASS' } else { 'FAIL' }) `
        "$($names -join ', ') / $($addresses -join ', ')"
    Add-Result 'naming.scales_beyond_four' $(if ((Get-KCSPLabVMName -Config $config -Index 12) -eq "$($config.Prefix)-WIN-12") { 'PASS' } else { 'FAIL' }) `
        'endpoint count is not hardcoded'

    # The ownership guard is what keeps destructive operations off other VMs.
    try {
        Assert-KCSPLabOwned -Config $config -Name "$($config.Prefix)-WIN-01" -Kind 'VM'
        Add-Result 'guard.allows_lab_resource' 'PASS' ''
    } catch { Add-Result 'guard.allows_lab_resource' 'FAIL' $_.Exception.Message }
    foreach ($foreign in @('kaztbu', 'Ubuntu-Dev', '', 'KCSP')) {
        $refused = $false
        try { Assert-KCSPLabOwned -Config $config -Name $foreign -Kind 'VM' } catch { $refused = $true }
        $label = if ($foreign) { $foreign } else { '<empty>' }
        Add-Result "guard.refuses.$label" $(if ($refused) { 'PASS' } else { 'FAIL' }) 'non-lab resource must be refused'
    }

    # Reporting must produce the machine-readable artifacts a run depends on.
    try {
        $temp = Join-Path ([IO.Path]::GetTempPath()) ("kcsp-lab-preflight-{0}" -f [guid]::NewGuid().ToString('N'))
        $report = New-KCSPLabReport -Name 'preflight self-test'
        Add-KCSPLabCheck -Report $report -Name 'sample.pass' -Status 'PASS' -Detail 'ok' -DurationSeconds 0.1 | Out-Null
        Add-KCSPLabCheck -Report $report -Name 'sample.fail' -Status 'FAIL' -Detail 'expected' -DurationSeconds 0.2 | Out-Null
        Set-KCSPLabFact -Report $report -Key 'marker' -Value 'KCSP-LAB-PREFLIGHT'
        $saved = Save-KCSPLabReport -Report $report -OutputRoot $temp
        $hasJson = Test-Path (Join-Path $saved.Directory 'report.json')
        $hasMd = Test-Path (Join-Path $saved.Directory 'report.md')
        $hasTimings = Test-Path (Join-Path $saved.Directory 'timings.json')
        $parsed = Get-Content (Join-Path $saved.Directory 'report.json') -Raw | ConvertFrom-Json
        $correct = $hasJson -and $hasMd -and $hasTimings -and $parsed.result -eq 'FAIL' -and $parsed.passed -eq 1 -and $parsed.failed -eq 1
        Add-Result 'report.artifacts' $(if ($correct) { 'PASS' } else { 'FAIL' }) 'report.json + report.md + timings.json, failure propagates to result'
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    } catch { Add-Result 'report.artifacts' 'FAIL' $_.Exception.Message }

    # Unattend template must carry every placeholder the builders substitute.
    $templatePath = Join-Path $PSScriptRoot 'unattend.template.xml'
    if (Test-Path -LiteralPath $templatePath) {
        $template = Get-Content -LiteralPath $templatePath -Raw
        $placeholders = @('{{COMPUTERNAME}}', '{{TIMEZONE}}', '{{LOCALE}}', '{{ADMINUSER}}', '{{ADMINPASSWORD}}')
        $absent = @($placeholders | Where-Object { $template -notlike "*$_*" })
        Add-Result 'unattend.placeholders' $(if ($absent.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
            $(if ($absent.Count -eq 0) { 'all present' } else { "missing: $($absent -join ', ')" })
        try { [xml] $template | Out-Null; Add-Result 'unattend.valid_xml' 'PASS' '' }
        catch { Add-Result 'unattend.valid_xml' 'FAIL' $_.Exception.Message }
    } else {
        Add-Result 'unattend.placeholders' 'FAIL' 'unattend.template.xml missing'
    }

    # Secrets must be gitignored.
    Push-Location $config.RepoRoot
    try {
        & git check-ignore -q '.lab/secrets/lab-admin.json' 2>$null
        Add-Result 'secrets.gitignored' $(if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'FAIL' }) '.lab is ignored'
        & git check-ignore -q '.artifacts/lab-results/x/report.json' 2>$null
        Add-Result 'results.gitignored' $(if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'FAIL' }) '.artifacts is ignored'
    } finally { Pop-Location }
}

# ------------------------------------------------------------- 4. host readiness
$elevated = Test-KCSPLabElevated
Add-Result 'host.elevated' $(if ($elevated) { 'PASS' } else { 'BLOCKED' }) `
    $(if ($elevated) { 'running as Administrator' } else { 'ELEVATION_REQUIRED - Hyper-V, NAT, firewall and portproxy all need it' })

$hyperV = Get-KCSPLabHyperVStatus
Add-Result 'host.hyperv_service' $(if ($hyperV.VmmsRunning) { 'PASS' } else { 'BLOCKED' }) "vmms running=$($hyperV.VmmsRunning)"
Add-Result 'host.hyperv_usable' $(if ($hyperV.HostReachable) { 'PASS' } else { 'BLOCKED' }) `
    $(if ($hyperV.HostReachable) { 'Get-VMHost reachable' } else { 'Hyper-V cmdlets unavailable in this session' })

if ($config) {
    $isoDirectory = Join-Path $config.LabRoot 'ISOs'
    $isos = @()
    if (Test-Path -LiteralPath $isoDirectory) { $isos = @(Get-ChildItem -LiteralPath $isoDirectory -Filter *.iso -ErrorAction SilentlyContinue) }
    Add-Result 'host.windows_iso' $(if ($isos.Count -gt 0) { 'PASS' } else { 'BLOCKED' }) `
        $(if ($isos.Count -gt 0) { "$($isos.Count) ISO(s) present" } else { "WINDOWS_ISO_REQUIRED - expected in $isoDirectory" })

    $drive = Get-PSDrive -Name ($config.LabRoot.Substring(0, 1)) -ErrorAction SilentlyContinue
    if ($drive -and $drive.Free) {
        $freeGB = [math]::Round($drive.Free / 1GB, 1)
        Add-Result 'host.disk_space' $(if ($freeGB -gt 80) { 'PASS' } else { 'WARN' }) "$freeGB GB free on $($drive.Name):"
    }

    try {
        $ready = Invoke-RestMethod "http://127.0.0.1:$($config.ApiPort)/health/ready" -TimeoutSec 5
        Add-Result 'host.kcsp_api' $(if ($ready.status -eq 'ready') { 'PASS' } else { 'WARN' }) "status=$($ready.status)"
    } catch { Add-Result 'host.kcsp_api' 'WARN' 'KCSP API not responding (Bootstrap will start it)' }
}

$results | Format-Table -AutoSize @{ n = 'CHECK'; e = { $_.check }; width = 40 }, @{ n = 'STATUS'; e = { $_.status }; width = 8 }, @{ n = 'DETAIL'; e = { $_.detail } }

$blocked = @($results | Where-Object { $_.status -eq 'BLOCKED' })
Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "TOOLING: $($script:Failures) check(s) FAILED - the lab scripts need fixing." -ForegroundColor Red
} else {
    Write-Host 'TOOLING: OK - every lab script parses and the logic self-tests pass.' -ForegroundColor Green
}
if ($blocked.Count -gt 0) {
    Write-Host "HOST: blocked on -> $(($blocked | ForEach-Object { $_.check }) -join ', ')" -ForegroundColor Yellow
} else {
    Write-Host 'HOST: ready - Bootstrap-KCSPLab.ps1 can run.' -ForegroundColor Green
}
if ($script:Failures -gt 0) { exit 1 }
