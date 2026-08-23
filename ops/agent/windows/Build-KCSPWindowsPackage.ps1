#requires -Version 5.1
[CmdletBinding()]
param(
    [string] $Version = '0.5.0',
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [string] $PrebuiltBinary,
    [string] $SigningCertificateThumbprint,
    [string] $TimestampServer = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$') {
    throw 'Version must be a semantic version without a leading v.'
}
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("kcsp-windows-package-{0}" -f [Guid]::NewGuid().ToString('N'))
$stage = Join-Path $temporaryRoot ("kcsp-agent-{0}-windows-amd64" -f $Version)
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    $binary = Join-Path $stage 'kcsp-agent.exe'
    if (-not [string]::IsNullOrWhiteSpace($PrebuiltBinary)) {
        Copy-Item -LiteralPath $PrebuiltBinary -Destination $binary
    }
    else {
        $oldGOOS = $env:GOOS
        $oldGOARCH = $env:GOARCH
        $oldCGO = $env:CGO_ENABLED
        try {
            $env:GOOS = 'windows'
            $env:GOARCH = 'amd64'
            $env:CGO_ENABLED = '0'
            Push-Location $repoRoot
            & go test ./cmd/agent
            if ($LASTEXITCODE -ne 0) { throw 'Windows agent tests failed.' }
            & go build -trimpath -ldflags "-s -w -X main.agentVersion=$Version" -o $binary ./cmd/agent
            if ($LASTEXITCODE -ne 0) { throw 'Windows agent build failed.' }
        }
        finally {
            Pop-Location
            $env:GOOS = $oldGOOS
            $env:GOARCH = $oldGOARCH
            $env:CGO_ENABLED = $oldCGO
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        $certificate = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $SigningCertificateThumbprint } | Select-Object -First 1
        if (-not $certificate) { throw 'Authenticode signing certificate was not found.' }
        $signed = Set-AuthenticodeSignature -FilePath $binary -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer
        if ($signed.Status -ne [Management.Automation.SignatureStatus]::Valid) { throw "Authenticode signing failed: $($signed.Status)" }
    }
    foreach ($name in @('Install-KCSPAgent.ps1', 'Uninstall-KCSPAgent.ps1', 'Install-KCSPSysmon.ps1', 'Test-KCSPAgent.ps1', 'New-KCSPRolloutPlan.ps1', 'sysmon-kcsp.xml')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage $name)
    }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs\windows-agent.md') -Destination (Join-Path $stage 'README.md')
    $files = @(Get-ChildItem -LiteralPath $stage -File | Sort-Object Name | ForEach-Object {
        [ordered]@{ path = $_.Name; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash; bytes = $_.Length }
    })
    $manifest = [ordered]@{
        schema = 'kcsp.windows-agent.package/v1'
        version = $Version
        platform = 'windows'
        architecture = 'amd64'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        files = $files
    }
    $manifestPath = Join-Path $stage 'manifest.json'
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText((Join-Path $stage 'manifest.sha256'), "$manifestHash  manifest.json`n", (New-Object Text.UTF8Encoding($false)))
    $archivePath = Join-Path $OutputDirectory ("kcsp-agent-{0}-windows-amd64.zip" -f $Version)
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archivePath -CompressionLevel Optimal -Force
    [pscustomobject]@{ archive = $archivePath; sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash; version = $Version; files = $files.Count }
}
finally {
    $expectedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    if ($resolvedTemporaryRoot.StartsWith($expectedTempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTemporaryRoot)) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
