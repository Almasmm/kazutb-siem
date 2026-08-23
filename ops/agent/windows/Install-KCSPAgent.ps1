#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)] [string] $ServerUrl,
    [Parameter(Mandatory = $true)] [string] $TenantId,
    [string] $BinaryPath = (Join-Path $PSScriptRoot 'kcsp-agent.exe'),
    [string] $ExpectedSha256,
    [securestring] $EnrollmentToken,
    [string] $EnrollmentTokenFile,
    [string] $CAFile,
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'KCSP\Agent'),
    [string] $StateDirectory = (Join-Path $env:ProgramData 'KCSP\agent'),
    [string[]] $WindowsChannels = @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Windows Defender/Operational'),
    [switch] $RequireAuthenticodeSignature,
    [switch] $AllowInsecureHttp,
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'KCSPAgent'
$serviceAccount = 'NT SERVICE\KCSPAgent'
$targetBinary = Join-Path $InstallDirectory 'kcsp-agent.exe'
$credentialPath = Join-Path $StateDirectory 'credential.json'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'KCSP agent installation requires an elevated Administrator session.'
    }
}

function Invoke-SC {
    param([Parameter(Mandatory = $true)] [string[]] $Arguments)
    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe $($Arguments -join ' ') failed: $($output -join ' ')"
    }
}

function Resolve-ExpectedHash {
    param([string] $ExplicitHash)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitHash)) {
        return $ExplicitHash.Trim().ToUpperInvariant()
    }
    $manifestPath = Join-Path $PSScriptRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'ExpectedSha256 or a package manifest.json is required; installation fails closed without an integrity value.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $entry = @($manifest.files | Where-Object { $_.path -eq 'kcsp-agent.exe' })
    if ($entry.Count -ne 1 -or [string]::IsNullOrWhiteSpace($entry[0].sha256)) {
        throw 'Package manifest does not contain exactly one kcsp-agent.exe digest.'
    }
    return $entry[0].sha256.ToUpperInvariant()
}

function Assert-SecureTokenFile {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if ($resolved.StartsWith('\\')) {
        throw 'Enrollment token file must be local, not a UNC path.'
    }
    $acl = Get-Acl -LiteralPath $resolved
    $broadSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $broadSids -contains $rule.IdentityReference.Value) {
            throw "Enrollment token file grants access to broad principal $($rule.IdentityReference.Value)."
        }
    }
    return $resolved
}

function ConvertFrom-KCSPSecureString {
    param([Parameter(Mandatory = $true)] [securestring] $Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Set-PrivateDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [Security.AccessControl.FileSystemRights] $ServiceRights
    )
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @(
        (New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), 'FullControl', $inheritance, $propagation, $allow)),
        (New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')), 'FullControl', $inheritance, $propagation, $allow)),
        (New-Object Security.AccessControl.FileSystemAccessRule($serviceAccount, $ServiceRights, $inheritance, $propagation, $allow))
    )) {
        [void] $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-ProcessEnvironment {
    param([hashtable] $Values, [hashtable] $Original)
    foreach ($name in $Values.Keys) {
        $Original[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, [string] $Values[$name], 'Process')
    }
}

function Restore-ProcessEnvironment {
    param([hashtable] $Original)
    foreach ($name in $Original.Keys) {
        [Environment]::SetEnvironmentVariable($name, $Original[$name], 'Process')
    }
}

Assert-Administrator
$uri = $null
if (-not [Uri]::TryCreate($ServerUrl.TrimEnd('/'), [UriKind]::Absolute, [ref] $uri) -or @('http', 'https') -notcontains $uri.Scheme) {
    throw 'ServerUrl must be an absolute HTTP(S) URL.'
}
if ($uri.Scheme -ne 'https' -and -not $AllowInsecureHttp) {
    throw 'KCSP agent installation requires HTTPS unless AllowInsecureHttp is explicitly selected for a local lab.'
}
if ($TenantId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') {
    throw 'TenantId is invalid.'
}
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Agent binary not found: $BinaryPath"
}
$expectedHash = Resolve-ExpectedHash -ExplicitHash $ExpectedSha256
$actualHash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actualHash -ne $expectedHash) {
    throw "Agent binary SHA-256 mismatch: expected $expectedHash, got $actualHash."
}
$signature = Get-AuthenticodeSignature -LiteralPath $BinaryPath
if ($RequireAuthenticodeSignature -and $signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
    throw "Agent binary Authenticode signature is not valid: $($signature.Status)."
}

$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
    $existingService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
Copy-Item -LiteralPath $BinaryPath -Destination $targetBinary -Force

if (-not $existingService) {
    Invoke-SC -Arguments @('create', $serviceName, 'binPath=', "`"$targetBinary`"", 'start=', 'delayed-auto', 'obj=', $serviceAccount, 'DisplayName=', 'KCSP Lightweight Security Agent')
}
else {
    Invoke-SC -Arguments @('config', $serviceName, 'binPath=', "`"$targetBinary`"", 'start=', 'delayed-auto', 'obj=', $serviceAccount, 'DisplayName=', 'KCSP Lightweight Security Agent')
}
Invoke-SC -Arguments @('description', $serviceName, 'Collects approved Windows and Sysmon telemetry for the on-premise KCSP SOC platform.')
Invoke-SC -Arguments @('sidtype', $serviceName, 'unrestricted')
Invoke-SC -Arguments @('failure', $serviceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/60000')
Invoke-SC -Arguments @('failureflag', $serviceName, '1')

$eventLogReaders = Get-LocalGroup -SID 'S-1-5-32-573'
if (-not (Get-LocalGroupMember -Group $eventLogReaders -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $serviceAccount })) {
    Add-LocalGroupMember -Group $eventLogReaders -Member $serviceAccount
}
Set-PrivateDirectoryAcl -Path $InstallDirectory -ServiceRights ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
Set-PrivateDirectoryAcl -Path $StateDirectory -ServiceRights ([Security.AccessControl.FileSystemRights]::Modify)

$installedCAFile = $null
if (-not [string]::IsNullOrWhiteSpace($CAFile)) {
    if (-not (Test-Path -LiteralPath $CAFile -PathType Leaf)) {
        throw "CA file not found: $CAFile"
    }
    $pkiDirectory = Join-Path $StateDirectory 'pki'
    New-Item -ItemType Directory -Path $pkiDirectory -Force | Out-Null
    $installedCAFile = Join-Path $pkiDirectory 'ca.pem'
    Copy-Item -LiteralPath $CAFile -Destination $installedCAFile -Force
}

if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
    $plainToken = $null
    $tokenFileToDelete = $null
    try {
        if (-not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile)) {
            $tokenFileToDelete = Assert-SecureTokenFile -Path $EnrollmentTokenFile
            $plainToken = (Get-Content -LiteralPath $tokenFileToDelete -Raw).Trim()
        }
        elseif ($null -ne $EnrollmentToken) {
            $plainToken = ConvertFrom-KCSPSecureString -Value $EnrollmentToken
        }
        elseif (-not $NonInteractive) {
            $plainToken = ConvertFrom-KCSPSecureString -Value (Read-Host 'One-time KCSP enrollment token' -AsSecureString)
        }
        else {
            throw 'A fresh non-interactive install requires EnrollmentTokenFile or EnrollmentToken.'
        }
        if ($plainToken -notmatch '^kcsp_enroll_' -or $plainToken.Length -gt 512) {
            throw 'Enrollment token has an invalid format.'
        }
        $bootstrapEnvironment = @{
            KCSP_AGENT_SERVER_URL = $uri.AbsoluteUri.TrimEnd('/')
            KCSP_AGENT_TENANT_ID = $TenantId
            KCSP_AGENT_STATE_DIR = $StateDirectory
            KCSP_AGENT_ENROLLMENT_TOKEN = $plainToken
            KCSP_AGENT_ENROLL_ONLY = 'true'
            KCSP_AGENT_ALLOW_INSECURE_HTTP = $(if ($AllowInsecureHttp) { 'true' } else { 'false' })
        }
        if ($installedCAFile) {
            $bootstrapEnvironment.KCSP_AGENT_CA_FILE = $installedCAFile
        }
        $originalEnvironment = @{}
        Set-ProcessEnvironment -Values $bootstrapEnvironment -Original $originalEnvironment
        try {
            $process = Start-Process -FilePath $targetBinary -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
                throw "Agent enrollment failed with exit code $($process.ExitCode)."
            }
        }
        finally {
            Restore-ProcessEnvironment -Original $originalEnvironment
        }
    }
    finally {
        $plainToken = $null
        if ($tokenFileToDelete -and (Test-Path -LiteralPath $tokenFileToDelete -PathType Leaf)) {
            Remove-Item -LiteralPath $tokenFileToDelete -Force
        }
    }
}

$serviceEnvironment = @(
    "KCSP_AGENT_SERVER_URL=$($uri.AbsoluteUri.TrimEnd('/'))",
    "KCSP_AGENT_TENANT_ID=$TenantId",
    "KCSP_AGENT_STATE_DIR=$StateDirectory",
    'KCSP_AGENT_SOURCE=auto',
    "KCSP_AGENT_WINDOWS_CHANNELS=$($WindowsChannels -join ';')",
    "KCSP_AGENT_LOG_FILE=$(Join-Path $StateDirectory 'agent.log')",
    'KCSP_AGENT_LOG_MAX_BYTES=10485760',
    'KCSP_AGENT_LOG_BACKUPS=5',
    "KCSP_AGENT_ALLOW_INSECURE_HTTP=$(if ($AllowInsecureHttp) { 'true' } else { 'false' })"
)
if ($installedCAFile) {
    $serviceEnvironment += "KCSP_AGENT_CA_FILE=$installedCAFile"
}
if ($serviceEnvironment | Where-Object { $_ -like 'KCSP_AGENT_ENROLLMENT_TOKEN=*' }) {
    throw 'Refusing to persist the one-time enrollment token in service configuration.'
}
$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
New-ItemProperty -Path $serviceRegistryPath -Name Environment -PropertyType MultiString -Value $serviceEnvironment -Force | Out-Null
New-ItemProperty -Path $serviceRegistryPath -Name DelayedAutoStart -PropertyType DWord -Value 1 -Force | Out-Null

Start-Service -Name $serviceName
$service = Get-Service -Name $serviceName
$service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
[pscustomobject]@{
    service = $serviceName
    status = $service.Status.ToString()
    binary_sha256 = $actualHash
    authenticode = $signature.Status.ToString()
    state_directory = $StateDirectory
    enrollment_token_persisted = $false
}
