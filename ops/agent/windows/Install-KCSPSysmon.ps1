#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $SysmonExecutable,
    [string] $ConfigurationPath = (Join-Path $PSScriptRoot 'sysmon-kcsp.xml'),
    [string] $ExpectedSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Sysmon installation requires an elevated Administrator session.'
}
if (-not (Test-Path -LiteralPath $SysmonExecutable -PathType Leaf) -or -not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
    throw 'A local Sysmon executable and KCSP configuration file are required.'
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
    $actualHash = (Get-FileHash -LiteralPath $SysmonExecutable -Algorithm SHA256).Hash
    if ($actualHash -ne $ExpectedSha256.Trim()) {
        throw 'Sysmon executable SHA-256 mismatch.'
    }
}
$signature = Get-AuthenticodeSignature -LiteralPath $SysmonExecutable
if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
    throw "Sysmon executable must carry a valid Microsoft Authenticode signature; status=$($signature.Status)."
}
[xml] $configuration = Get-Content -LiteralPath $ConfigurationPath -Raw
if ($configuration.DocumentElement.Name -ne 'Sysmon') {
    throw 'Sysmon configuration root element is invalid.'
}
$configDirectory = Join-Path $env:ProgramData 'KCSP\sysmon'
New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null
$installedConfiguration = Join-Path $configDirectory 'sysmon-kcsp.xml'
Copy-Item -LiteralPath $ConfigurationPath -Destination $installedConfiguration -Force
$service = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($service) {
    & $SysmonExecutable -accepteula -c $installedConfiguration | Out-Null
}
else {
    & $SysmonExecutable -accepteula -i $installedConfiguration | Out-Null
}
if ($LASTEXITCODE -ne 0) {
    throw "Sysmon configuration failed with exit code $LASTEXITCODE."
}
& wevtutil.exe sl 'Microsoft-Windows-Sysmon/Operational' /e:true
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to enable the Sysmon operational channel.'
}
$service = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction Stop | Select-Object -First 1
$service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
[pscustomobject]@{ service = $service.Name; status = $service.Status.ToString(); config = $installedConfiguration; signer = $signature.SignerCertificate.Subject }
