#requires -Version 5.1
<#
    KCSP Hyper-V cyber range - shared orchestration module.

    Every lab resource is named with the configured prefix (default KCSP-LAB)
    so destructive operations can be constrained to lab-owned objects and can
    never touch unrelated VMs, the Docker KCSP volumes, or the physical pilot
    endpoint.
#>

Set-StrictMode -Version Latest

$script:LabLogPath = $null
$script:LabTenantId = 'kcsp-lab'
$script:ForbiddenTenantId = 'university-kulazhanov'

# ---------------------------------------------------------------- configuration

function Get-KCSPLabRoot {
    <#  Repository root, derived from this module's location. #>
    [CmdletBinding()] param()
    return [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
}

function Resolve-KCSPLabApplication {
    <# Resolve only a real executable/application and remain safe under
       Set-StrictMode when Get-Command returns null. #>
    [CmdletBinding()] param([Parameter(Mandatory)] [string] $Name)
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { return $null }
    foreach ($propertyName in 'Path', 'Source') {
        $property = $command.PSObject.Properties[$propertyName]
        if ($property -and (Test-Path -LiteralPath $property.Value -PathType Leaf)) {
            return [string] $property.Value
        }
    }
    return $null
}

function Resolve-KCSPLabGoToolchain {
    <# PATH, repository-local Go, then the approved pinned Docker toolchain. #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)] [string] $RepoRoot,
        [hashtable] $Environment
    )
    $normal = Resolve-KCSPLabApplication -Name 'go'
    if ($normal) { return [pscustomobject]@{ Kind='native'; Executable=$normal; PrefixArguments=@() } }

    foreach ($candidate in @(
        (Join-Path $RepoRoot '.tools\go\bin\go.exe'),
        (Join-Path $RepoRoot '.tools\go\bin\go')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [pscustomobject]@{ Kind='repository-local'; Executable=$candidate; PrefixArguments=@() }
        }
    }

    $docker = Resolve-KCSPLabApplication -Name 'docker'
    if ($docker) {
        & $docker version --format '{{.Server.Version}}' *> $null
        if ($LASTEXITCODE -eq 0) {
            $prefix = @('run','--rm')
            if ($Environment) {
                foreach ($key in @($Environment.Keys | Sort-Object)) {
                    $prefix += @('-e', "${key}=$($Environment[$key])")
                }
            }
            $prefix += @('--mount', "type=bind,source=$RepoRoot,target=/src", '-w', '/src', 'golang:1.25', 'go')
            return [pscustomobject]@{ Kind='docker'; Executable=$docker; PrefixArguments=$prefix }
        }
    }
    throw 'TOOLCHAIN_MISSING: no Go application on PATH, repository-local Go, or reachable Docker Go toolchain.'
}

function Get-KCSPLabConfig {
    <#
        .SYNOPSIS
        Loads lab configuration, preferring the operator's private copy.

        .DESCRIPTION
        .lab\config.psd1 is gitignored and holds the real settings. When it is
        absent the committed config.example.psd1 supplies defaults, so the lab
        is runnable from a clean clone without first editing anything.
    #>
    [CmdletBinding()] param([string] $ConfigPath)

    $root = Get-KCSPLabRoot
    $candidates = @()
    if ($ConfigPath) { $candidates += $ConfigPath }
    $candidates += (Join-Path $root '.lab\config.psd1')
    $candidates += (Join-Path $PSScriptRoot 'config.example.psd1')

    $resolved = $null
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { $resolved = $candidate; break }
    }
    if (-not $resolved) { throw "No lab configuration found. Expected one of: $($candidates -join ', ')" }

    $config = Import-PowerShellDataFile -LiteralPath $resolved
    $config.ConfigPath = $resolved
    $config.RepoRoot = $root
    $config.LabStateRoot = Join-Path $root '.lab'
    $config.SecretsRoot = Join-Path $config.LabStateRoot 'secrets'
    $config.ApiCredentialPath = Join-Path $config.SecretsRoot 'lab-api-credential.json'
    if (-not $config.ContainsKey('Prefix') -or -not $config.Prefix) { $config.Prefix = 'KCSP-LAB' }
    Assert-KCSPLabTenant -Config $config
    return $config
}

function Assert-KCSPLabTenant {
    <# Hard fail before any lab action can address the university tenant. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    $tenantId = if ($Config.ContainsKey('TenantId')) { [string] $Config.TenantId } else { '' }
    if ($tenantId -eq $script:ForbiddenTenantId) {
        throw "TENANT_SAFETY_GUARD: Hyper-V automation must never use '$script:ForbiddenTenantId'."
    }
    if ($tenantId -ne $script:LabTenantId) {
        throw "TENANT_SAFETY_GUARD: Hyper-V automation is pinned to '$script:LabTenantId'; got '$tenantId'."
    }
    $profile = if ($Config.ContainsKey('Profile')) { ([string] $Config.Profile).ToLowerInvariant() } else { '' }
    if ($profile -notin 'development', 'test') {
        throw "TENANT_SAFETY_GUARD: Hyper-V lab credential bootstrap is forbidden for profile '$profile'."
    }
}

function Get-KCSPLabPaths {
    <#  Resolves and creates the on-disk layout. VHDX and ISO content never
        live inside the repository. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)

    $base = $Config.LabRoot
    $paths = [ordered]@{
        Root      = $base
        Base      = Join-Path $base 'Base'
        VMs       = Join-Path $base 'VMs'
        ISOs      = Join-Path $base 'ISOs'
        Exports   = Join-Path $base 'Exports'
        Logs      = Join-Path $base 'Logs'
        Artifacts = Join-Path $base 'Artifacts'
    }
    foreach ($key in @($paths.Keys)) {
        if (-not (Test-Path -LiteralPath $paths[$key])) {
            New-Item -ItemType Directory -Path $paths[$key] -Force | Out-Null
        }
    }
    return $paths
}

# ---------------------------------------------------------------------- logging

function Start-KCSPLabLog {
    [CmdletBinding()] param([Parameter(Mandatory)] [string] $Path)
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $script:LabLogPath = $Path
}

function Write-KCSPLabLog {
    <#  Console plus log file. Secrets must never be passed to this function. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'STEP', 'PASS', 'FAIL')] [string] $Level = 'INFO'
    )
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$stamp] [$Level] $Message"
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'FAIL'  { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'PASS'  { Write-Host $line -ForegroundColor Green }
        'STEP'  { Write-Host $line -ForegroundColor Cyan }
        default { Write-Host $line }
    }
    if ($script:LabLogPath) {
        try { Add-Content -LiteralPath $script:LabLogPath -Value $line -Encoding UTF8 } catch { }
    }
}

# ------------------------------------------------------------------ environment

function Test-KCSPLabElevated {
    [CmdletBinding()] param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-KCSPLabElevated {
    <#  Hyper-V, NetNat, firewall and portproxy all require an elevated token.
        Failing early with a precise message beats a partial lab. #>
    [CmdletBinding()] param()
    if (-not (Test-KCSPLabElevated)) {
        throw 'ELEVATION_REQUIRED: run this script from an elevated PowerShell session (Run as Administrator).'
    }
}

function Get-KCSPLabHyperVStatus {
    <#  Reports Hyper-V readiness without throwing, so preflight can run
        unelevated and still say something useful. #>
    [CmdletBinding()] param()
    $status = [ordered]@{
        Elevated       = Test-KCSPLabElevated
        VmmsRunning    = $false
        FeatureEnabled = $null
        HostReachable  = $false
        RebootRequired = $false
        Detail         = ''
    }
    $service = Get-Service vmms -ErrorAction SilentlyContinue
    if ($service) { $status.VmmsRunning = ($service.Status -eq 'Running') }

    if ($status.Elevated) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
            $status.FeatureEnabled = ($feature.State -eq 'Enabled')
            $status.RebootRequired = ($feature.RestartNeeded -eq $true)
        } catch { $status.Detail = $_.Exception.Message }
    }
    try {
        Get-VMHost -ErrorAction Stop | Out-Null
        $status.HostReachable = $true
    } catch {
        if (-not $status.Detail) { $status.Detail = $_.Exception.Message }
    }
    return [pscustomobject] $status
}

function Enable-KCSPLabHyperV {
    <#  Enables the Hyper-V feature set. Returns $true when a reboot is needed. #>
    [CmdletBinding(SupportsShouldProcess = $true)] param()
    Assert-KCSPLabElevated
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
    if ($feature.State -eq 'Enabled') { return $false }
    if (-not $PSCmdlet.ShouldProcess('Microsoft-Hyper-V-All', 'Enable Windows optional feature')) { return $false }
    $result = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
    return [bool] $result.RestartNeeded
}

# --------------------------------------------------------------------- secrets

function Get-KCSPLabSecretStore {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    if (-not (Test-Path -LiteralPath $Config.SecretsRoot)) {
        New-Item -ItemType Directory -Path $Config.SecretsRoot -Force | Out-Null
    }
    return $Config.SecretsRoot
}

function New-KCSPLabPassword {
    <#  Cryptographically strong lab password. Lab credentials are unique to the
        range and never reused from production. #>
    [CmdletBinding()] param([int] $Length = 24)
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^*-_=+'
    $bytes = New-Object byte[] ($Length * 2)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        [void] $builder.Append($alphabet[$bytes[$i] % $alphabet.Length])
    }
    # Guarantee the complexity classes Windows requires for a local account.
    return 'Kc1!' + $builder.ToString()
}

function New-KCSPLabApiToken {
    [CmdletBinding()] param()
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return 'kcsp_lab_' + [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Get-KCSPLabTenantCredential {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    Assert-KCSPLabTenant -Config $Config
    $path = [string] $Config.ApiCredentialPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "LAB_CREDENTIAL_MISSING: run Bootstrap-KCSPLab.ps1 to initialize the development/test credential."
    }
    $saved = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    foreach ($property in 'tenant_id','principal','access_token') {
        if (-not $saved.PSObject.Properties[$property] -or [string]::IsNullOrWhiteSpace([string] $saved.$property)) {
            throw "LAB_CREDENTIAL_INVALID: missing $property."
        }
    }
    if ($saved.tenant_id -ne $script:LabTenantId -or $saved.principal -ne 'svc-kcsp-lab-admin' -or
        [string] $saved.access_token -notmatch '^kcsp_lab_[A-Za-z0-9_-]{40,}$') {
        throw 'LAB_CREDENTIAL_INVALID: tenant, principal or token format mismatch.'
    }
    return [pscustomobject]@{ TenantId=$saved.tenant_id; Principal=$saved.principal; AccessToken=$saved.access_token; Path=$path }
}

function Ensure-KCSPLabTenantCredential {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config, [switch] $Rotate)
    Assert-KCSPLabTenant -Config $Config
    Get-KCSPLabSecretStore -Config $Config | Out-Null
    if (-not $Rotate -and (Test-Path -LiteralPath $Config.ApiCredentialPath -PathType Leaf)) {
        $existing = Get-KCSPLabTenantCredential -Config $Config
        Write-KCSPLabLog 'EXISTS tenant-scoped lab API credential (secret redacted)' -Level INFO
        return $existing
    }
    $token = New-KCSPLabApiToken
    $payload = [ordered]@{ tenant_id=$script:LabTenantId; principal='svc-kcsp-lab-admin'; access_token=$token; created_at=(Get-Date).ToUniversalTime().ToString('o') }
    $temporary = "$($Config.ApiCredentialPath).$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporary, ($payload | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    Protect-KCSPLabFile -Path $temporary
    Move-Item -LiteralPath $temporary -Destination $Config.ApiCredentialPath -Force -ErrorAction Stop
    Protect-KCSPLabFile -Path $Config.ApiCredentialPath
    Write-KCSPLabLog "CREATE tenant-scoped lab API credential for $script:LabTenantId (secret redacted)" -Level INFO
    return Get-KCSPLabTenantCredential -Config $Config
}

function Get-KCSPLabCredential {
    <#
        .SYNOPSIS
        Returns the lab administrator credential, creating it on first use.

        .DESCRIPTION
        The password is generated locally, stored only under .lab\secrets
        (gitignored, ACL-restricted) and never written to logs or reports.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)

    $store = Get-KCSPLabSecretStore -Config $Config
    $file = Join-Path $store 'lab-admin.json'
    if (Test-Path -LiteralPath $file -PathType Leaf) {
        $saved = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        $secure = ConvertTo-SecureString -String $saved.password -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential($saved.username, $secure)
    }
    $username = $Config.AdminUser
    $password = New-KCSPLabPassword
    $payload = [ordered]@{ username = $username; password = $password; created_at = (Get-Date).ToUniversalTime().ToString('o') }
    [IO.File]::WriteAllText($file, ($payload | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    Protect-KCSPLabFile -Path $file
    $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($username, $secure)
}

function Protect-KCSPLabFile {
    <#  Restricts a secret file to SYSTEM, Administrators and the current user. #>
    [CmdletBinding()] param([Parameter(Mandatory)] [string] $Path)
    try {
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')))
        }
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    } catch {
        throw "SECRET_ACL_FAILED for $(Split-Path -Leaf $Path): $($_.Exception.Message)"
    }
}

function ConvertFrom-KCSPLabSecureString {
    [CmdletBinding()] param([Parameter(Mandatory)] [securestring] $Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

# --------------------------------------------------------------------- naming

function Get-KCSPLabVMName {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [int] $Index)
    return '{0}-WIN-{1:d2}' -f $Config.Prefix, $Index
}

function Get-KCSPLabVMAddress {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [int] $Index)
    return '{0}{1}' -f $Config.GuestAddressPrefix, (100 + $Index)
}

function Assert-KCSPLabOwned {
    <#
        .SYNOPSIS
        Guards destructive operations to lab-owned resources only.

        .DESCRIPTION
        Every VM, switch and disk the lab manages carries the configured prefix.
        Anything without it belongs to somebody else - an unrelated Hyper-V VM,
        or the operator's own work - and must never be touched.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [string] $Kind = 'resource'
    )
    if ([string]::IsNullOrWhiteSpace($Name) -or -not $Name.StartsWith($Config.Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate on $Kind '$Name': it is not owned by the lab (prefix '$($Config.Prefix)')."
    }
}

function Get-KCSPLabVMs {
    <#  Every lab VM, and only lab VMs. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    $pattern = "$($Config.Prefix)-WIN-*"
    return @(Get-VM -Name $pattern -ErrorAction SilentlyContinue)
}

function Test-KCSPLabPathEqual {
    [CmdletBinding()] param([string] $Left, [string] $Right)
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
    try {
        return [IO.Path]::GetFullPath($Left).TrimEnd('\') -eq [IO.Path]::GetFullPath($Right).TrimEnd('\')
    } catch { return $false }
}

function ConvertTo-KCSPLabObjectArray {
    <# PowerShell 5.1 and 7.x both throw ArgumentException when @() wraps a
       Generic.List[object]. Copy explicitly and emit the array as one object
       so 0/1/N inputs always retain the System.Object[] contract. #>
    [CmdletBinding()] param([AllowNull()] [System.Collections.IEnumerable] $InputCollection)
    $buffer = New-Object System.Collections.Generic.List[object]
    if ($null -ne $InputCollection) {
        foreach ($item in $InputCollection) { $buffer.Add($item) }
    }
    [object[]] $result = [object[]]::new($buffer.Count)
    $buffer.CopyTo($result)
    Write-Output -NoEnumerate $result
}

function Get-KCSPLabBaseDependencies {
    <# Walk each attached lab VM disk through every AVHDX/VHDX parent. This is
       the authoritative guard before a base can ever be replaced. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [string] $BasePath)
    $dependencies = New-Object System.Collections.Generic.List[object]
    foreach ($vm in @(Get-KCSPLabVMs -Config $Config)) {
        Assert-KCSPLabOwned -Config $Config -Name $vm.Name -Kind 'VM'
        $runtimeProof = @(Get-VMSnapshot -VMName $vm.Name -Name 'CLEAN_WINDOWS' -ErrorAction SilentlyContinue).Count -gt 0
        foreach ($drive in @(Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction Stop)) {
            $leaf = [string] $drive.Path
            $leafVhd = Get-VHD -Path $leaf -ErrorAction Stop
            $current = $leaf
            $chain = New-Object System.Collections.Generic.List[string]
            $visited = @{}
            while (-not [string]::IsNullOrWhiteSpace($current) -and -not $visited.ContainsKey($current.ToLowerInvariant())) {
                $visited[$current.ToLowerInvariant()] = $true
                $chain.Add($current)
                if (Test-KCSPLabPathEqual -Left $current -Right $BasePath) {
                    $dependencies.Add([pscustomobject]@{
                        VMName=$vm.Name; VMState=[string] $vm.State; DiskPath=$leaf; ChildPath=$leaf
                        ParentPath=[string] $leafVhd.ParentPath; DiskType=[string] $leafVhd.VhdType
                        Attached=[bool] $leafVhd.Attached; OwnedByLab=$true
                        Chain=@($chain); CleanWindowsCheckpoint=$runtimeProof
                    })
                    break
                }
                try { $current = [string] (Get-VHD -Path $current -ErrorAction Stop).ParentPath }
                catch {
                    Write-KCSPLabLog "VHD chain inspection failed for $current`: $($_.Exception.Message)" -Level WARN
                    break
                }
            }
        }
    }

    # Also protect offline/orphaned child disks beneath the lab VM root. They
    # may not currently be attached to a VM but still make the parent immutable.
    $paths = Get-KCSPLabPaths -Config $Config
    $knownLeaves = @{}
    foreach ($dependency in $dependencies) { $knownLeaves[([string] $dependency.DiskPath).ToLowerInvariant()] = $true }
    $diskFiles = @(Get-ChildItem -LiteralPath $paths.VMs -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.vhdx', '.avhdx' })
    foreach ($file in $diskFiles) {
        if ($knownLeaves.ContainsKey($file.FullName.ToLowerInvariant()) -or
            (Test-KCSPLabPathEqual -Left $file.FullName -Right $BasePath)) { continue }
        $current = $file.FullName
        try { $leafVhd = Get-VHD -Path $file.FullName -ErrorAction Stop } catch { continue }
        $chain = New-Object System.Collections.Generic.List[string]
        $visited = @{}
        while (-not [string]::IsNullOrWhiteSpace($current) -and -not $visited.ContainsKey($current.ToLowerInvariant())) {
            $visited[$current.ToLowerInvariant()] = $true
            $chain.Add($current)
            if (Test-KCSPLabPathEqual -Left $current -Right $BasePath) {
                $dependencies.Add([pscustomobject]@{
                    VMName='unattached-lab-disk'; VMState='Detached'; DiskPath=$file.FullName; ChildPath=$file.FullName
                    ParentPath=[string] $leafVhd.ParentPath; DiskType=[string] $leafVhd.VhdType
                    Attached=[bool] $leafVhd.Attached; OwnedByLab=$true
                    Chain=@($chain); CleanWindowsCheckpoint=$false
                })
                break
            }
            try { $current = [string] (Get-VHD -Path $current -ErrorAction Stop).ParentPath } catch { break }
        }
    }
    $result = ConvertTo-KCSPLabObjectArray -InputCollection $dependencies
    Write-Output -NoEnumerate $result
}

function Test-KCSPLabOfflineWindowsImage {
    <# Marker-loss recovery for an unattached base: mount read-only and prove
       both the Windows registry hive and UEFI BCD exist. #>
    [CmdletBinding()] param([Parameter(Mandatory)] [string] $BasePath)
    $mounted = $false
    try {
        $vhd = Get-VHD -Path $BasePath -ErrorAction Stop
        if ($vhd.Attached) { return $false }
        $disk = Mount-VHD -Path $BasePath -ReadOnly -PassThru -ErrorAction Stop | Get-Disk -ErrorAction Stop
        $mounted = $true
        $volumes = @($disk | Get-Partition -ErrorAction Stop | Get-Volume -ErrorAction SilentlyContinue)
        $windows = $volumes | Where-Object { $_.FileSystemLabel -eq 'Windows' -and $_.Path } | Select-Object -First 1
        $system = $volumes | Where-Object { $_.FileSystemLabel -eq 'System' -and $_.Path } | Select-Object -First 1
        return $windows -and $system -and
            (Test-Path -LiteralPath (Join-Path $windows.Path 'Windows\System32\Config\SYSTEM') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $system.Path 'EFI\Microsoft\Boot\BCD') -PathType Leaf)
    } catch {
        Write-KCSPLabLog "Offline base validation failed: $($_.Exception.Message)" -Level WARN
        return $false
    } finally {
        if ($mounted) { Dismount-VHD -Path $BasePath -ErrorAction SilentlyContinue }
    }
}

function Get-KCSPLabBaseImageState {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    $paths = Get-KCSPLabPaths -Config $Config
    $basePath = Join-Path $paths.Base "$($Config.Prefix)-WIN-BASE.vhdx"
    $readyPath = "$basePath.ready.json"
    if (-not (Test-Path -LiteralPath $basePath -PathType Leaf)) {
        return [pscustomobject]@{ BasePath=$basePath; ReadyPath=$readyPath; Exists=$false; Valid=$false; MarkerValid=$false; VHDValid=$false; Attached=$false; OfflineValid=$false; Dependencies=@(); RuntimeProof=$false; Reason='missing' }
    }

    $markerValid = $false
    if (Test-Path -LiteralPath $readyPath -PathType Leaf) {
        try {
            $marker = Get-Content -LiteralPath $readyPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $markerValid = $marker.status -eq 'ready' -and (Test-KCSPLabPathEqual -Left $marker.base_image -Right $basePath)
        } catch { Write-KCSPLabLog "Golden image marker is unreadable: $($_.Exception.Message)" -Level WARN }
    }

    $vhd = $null
    try { $vhd = Get-VHD -Path $basePath -ErrorAction Stop } catch {
        return [pscustomobject]@{ BasePath=$basePath; ReadyPath=$readyPath; Exists=$true; Valid=$false; MarkerValid=$markerValid; VHDValid=$false; Attached=$false; OfflineValid=$false; Dependencies=@(); RuntimeProof=$false; Reason=$_.Exception.Message }
    }
    $vhdValid = [string] $vhd.VhdType -eq 'Dynamic' -and
        [string] $vhd.VhdFormat -eq 'VHDX' -and
        [int64] $vhd.Size -eq [int64] $Config.VMDiskSizeBytes
    [object[]] $dependencies = Get-KCSPLabBaseDependencies -Config $Config -BasePath $basePath
    $runtimeProof = @($dependencies | Where-Object { $_.CleanWindowsCheckpoint }).Count -gt 0
    $offlineValid = $false
    if ($vhdValid -and -not $markerValid -and -not $runtimeProof -and -not $vhd.Attached) {
        $offlineValid = Test-KCSPLabOfflineWindowsImage -BasePath $basePath
    }
    $valid = $vhdValid -and ($markerValid -or $runtimeProof -or $offlineValid)
    $reason = if (-not $vhdValid) { 'VHD metadata mismatch' } elseif ($markerValid) { 'ready marker' } elseif ($runtimeProof) { 'CLEAN_WINDOWS dependent VM proof' } elseif ($offlineValid) { 'offline Windows+UEFI proof' } else { 'no readiness proof' }
    return [pscustomobject]@{
        BasePath=$basePath; ReadyPath=$readyPath; Exists=$true; Valid=$valid; MarkerValid=$markerValid
        VHDValid=$vhdValid; Attached=[bool] $vhd.Attached; OfflineValid=$offlineValid
        Dependencies=$dependencies; RuntimeProof=$runtimeProof; Reason=$reason
    }
}

function Repair-KCSPLabBaseImageMetadata {
    [CmdletBinding()] param([Parameter(Mandatory)] $State)
    if (-not $State.Valid -or -not $State.VHDValid) { throw 'BASE_METADATA_REPAIR_REFUSED: base validity has not been proven.' }
    $proof = if ($State.RuntimeProof) { 'CLEAN_WINDOWS dependent VM proof' } elseif ($State.OfflineValid) { 'offline Windows+UEFI proof' } else { 'ready marker' }
    $marker = [ordered]@{ status='ready'; base_image=$State.BasePath; validation_proof=$proof; repaired_at=(Get-Date).ToUniversalTime().ToString('o') }
    $temporary = "$($State.ReadyPath).$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporary, ($marker | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $State.ReadyPath -Force -ErrorAction Stop
    Write-KCSPLabLog "METADATA_REPAIRED golden image marker ($proof)" -Level INFO
}

function Ensure-KCSPLabBaseImage {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    $state = Get-KCSPLabBaseImageState -Config $Config
    if ($state.Exists) { Write-KCSPLabLog "EXISTS golden image $($state.BasePath)" -Level INFO }
    if ($state.Valid -and -not $state.MarkerValid) {
        Repair-KCSPLabBaseImageMetadata -State $state
        $state = Get-KCSPLabBaseImageState -Config $Config
    }
    if ($state.Valid) {
        Write-KCSPLabLog "VERIFIED golden image ($($state.Reason), dependencies=$(@($state.Dependencies).Count), attached=$($state.Attached))" -Level PASS
        foreach ($dependency in @($state.Dependencies)) {
            $displayChain = @($dependency.Chain)
            [array]::Reverse($displayChain)
            Write-KCSPLabLog "VERIFIED VHD dependency: $($displayChain -join ' -> ') -> $($dependency.VMName)" -Level INFO
        }
    }
    return $state
}

function Test-KCSPLabBaseImage {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    return [bool] (Get-KCSPLabBaseImageState -Config $Config).Valid
}

function Assert-KCSPLabBaseImageRemovalSafe {
    [CmdletBinding()] param([Parameter(Mandatory)] $State)
    if (@($State.Dependencies).Count -gt 0) {
        $owners = @($State.Dependencies | ForEach-Object { "$($_.VMName):$($_.DiskPath)" }) -join '; '
        Write-KCSPLabLog "BLOCKED_BY_DEPENDENCY base removal forbidden: $owners" -Level ERROR
        throw "BASE_REMOVE_FORBIDDEN: dependent child disks exist: $owners"
    }
}

function Remove-KCSPLabInvalidBaseImage {
    <# One guarded attempt only. The READY marker is removed after the VHDX,
       so a file lock cannot destroy the last valid metadata proof. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $State)
    Assert-KCSPLabBaseImageRemovalSafe -State $State
    if ($State.Attached) {
        Write-KCSPLabLog 'REPAIR detaching dependency-free lab base image' -Level WARN
        Dismount-VHD -Path $State.BasePath -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $State.BasePath -PathType Leaf) {
        Write-KCSPLabLog 'REPAIR removing dependency-free invalid lab base image' -Level WARN
        try { Remove-Item -LiteralPath $State.BasePath -Force -ErrorAction Stop }
        catch {
            Write-KCSPLabLog "FAILED base removal (no retry): $($_.Exception.Message)" -Level ERROR
            throw
        }
    }
    if (Test-Path -LiteralPath $State.ReadyPath -PathType Leaf) {
        Remove-Item -LiteralPath $State.ReadyPath -Force -ErrorAction Stop
    }
}

# --------------------------------------------------------------------- network

function Get-KCSPLabHostAdapter {
    <# Resolve the management vNIC using Hyper-V ownership plus the Windows
       network inventory. The exact alias is preferred, while InterfaceGuid
       and Hyper-V adapter metadata cover delayed/localised enumeration. #>
    [CmdletBinding()] param([Parameter(Mandatory)] [string] $SwitchName)

    $management = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue |
        Where-Object { $_.SwitchName -eq $SwitchName })
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)
    $exactAlias = "vEthernet ($SwitchName)"
    $adapter = @($adapters | Where-Object {
        $_.Name -eq $exactAlias -and $_.InterfaceDescription -like 'Hyper-V Virtual Ethernet Adapter*'
    }) | Select-Object -First 1
    if ($adapter) { return $adapter }

    foreach ($virtualAdapter in $management) {
        $identities = @([string] $virtualAdapter.DeviceId, [string] $virtualAdapter.Id) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($candidate in $adapters) {
            $guid = [string] $candidate.InterfaceGuid
            if (-not [string]::IsNullOrWhiteSpace($guid) -and
                $candidate.InterfaceDescription -like 'Hyper-V Virtual Ethernet Adapter*' -and
                @($identities | Where-Object { $_ -match [regex]::Escape($guid.Trim('{}')) }).Count -gt 0) {
                return $candidate
            }
        }
    }
    return $null
}

function Wait-KCSPLabHostAdapter {
    [CmdletBinding()] param(
        [Parameter(Mandatory)] [string] $SwitchName,
        [int] $TimeoutSeconds = 60,
        [int] $PollMilliseconds = 1000
    )
    $started = Get-Date
    $deadline = $started.AddSeconds($TimeoutSeconds)
    do {
        $adapter = Get-KCSPLabHostAdapter -SwitchName $SwitchName
        if ($adapter) {
            return [pscustomobject]@{ Adapter = $adapter; WaitedSeconds = ((Get-Date) - $started).TotalSeconds }
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    } while ((Get-Date) -lt $deadline)
    return $null
}

function Write-KCSPLabNetworkDiagnostics {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config, [string] $Reason)
    $switchName = [string] $Config.Prefix
    $switches = @(Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $switchName })
    $management = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue |
        Where-Object { $_.SwitchName -eq $switchName -or $_.Name -eq $switchName })
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "vEthernet ($switchName)" -or $_.Name -eq $switchName })
    $nats = @(Get-NetNat -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "$($switchName)-NAT" -or $_.InternalIPInterfaceAddressPrefix -eq $Config.Subnet })
    Write-KCSPLabLog "FAILED network reconciliation: $Reason; switches=$($switches.Count) management_vnics=$($management.Count) net_adapters=$($adapters.Count) nats=$($nats.Count)" -Level ERROR
    foreach ($item in $switches) {
        Write-KCSPLabLog "DIAGNOSTIC switch name=$($item.Name) type=$($item.SwitchType) id=$($item.Id)" -Level ERROR
    }
    foreach ($item in $management) {
        Write-KCSPLabLog "DIAGNOSTIC management_vnic name=$($item.Name) switch=$($item.SwitchName) id=$($item.Id)" -Level ERROR
    }
    foreach ($item in $adapters) {
        Write-KCSPLabLog "DIAGNOSTIC host_adapter name=$($item.Name) status=$($item.Status) ifIndex=$($item.ifIndex) guid=$($item.InterfaceGuid)" -Level ERROR
    }
    foreach ($item in $nats) {
        Write-KCSPLabLog "DIAGNOSTIC nat name=$($item.Name) prefix=$($item.InternalIPInterfaceAddressPrefix) active=$($item.Active)" -Level ERROR
    }
}

function Ensure-KCSPLabNetwork {
    <#
        .SYNOPSIS
        Ensures the isolated lab switch, host address and NAT.

        .DESCRIPTION
        An Internal switch keeps lab traffic off the university LAN. The host
        end of the switch holds the gateway address; NAT is optional and only
        gives guests outbound internet for Windows Update.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)] param(
        [Parameter(Mandatory)] $Config,
        [int] $AdapterTimeoutSeconds = 60,
        [int] $PollMilliseconds = 1000
    )
    Assert-KCSPLabElevated

    $switchName = "$($Config.Prefix)"
    Assert-KCSPLabOwned -Config $Config -Name $switchName -Kind 'VMSwitch'
    $existing = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
    if ($existing -and [string] $existing.SwitchType -ne 'Internal') {
        Write-KCSPLabNetworkDiagnostics -Config $Config -Reason "owned switch has type $($existing.SwitchType), expected Internal"
        throw "NETWORK_OWNERSHIP_CONFLICT: switch '$switchName' exists but is not Internal."
    }

    $adapterResult = $null
    if ($existing) {
        Write-KCSPLabLog "EXISTS internal switch $switchName" -Level INFO
        $adapterResult = Wait-KCSPLabHostAdapter -SwitchName $switchName -TimeoutSeconds $AdapterTimeoutSeconds -PollMilliseconds $PollMilliseconds
        if (-not $adapterResult) {
            # A switch object without its management vNIC is an owned partial
            # state. Remove only that exact switch through Hyper-V, wait for
            # Windows cleanup, and recreate it through supported cmdlets.
            Write-KCSPLabLog "REPAIR partial switch ${switchName}: management vNIC did not appear" -Level WARN
            if ($PSCmdlet.ShouldProcess($switchName, 'Remove broken lab-owned switch')) {
                Remove-VMSwitch -Name $switchName -Force -ErrorAction Stop
                $cleanupDeadline = (Get-Date).AddSeconds(30)
                do {
                    $remaining = Get-KCSPLabHostAdapter -SwitchName $switchName
                    if (-not $remaining) { break }
                    Start-Sleep -Milliseconds $PollMilliseconds
                } while ((Get-Date) -lt $cleanupDeadline)
                if (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue) {
                    Write-KCSPLabNetworkDiagnostics -Config $Config -Reason 'broken switch remained after supported removal'
                    throw "NETWORK_REPAIR_FAILED: switch '$switchName' remained after Remove-VMSwitch."
                }
                $existing = $null
            }
        }
    }

    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($switchName, 'Create internal VM switch')) {
            $created = $false
            for ($attempt = 1; $attempt -le 2 -and -not $created; $attempt++) {
                try {
                    New-VMSwitch -Name $switchName -SwitchType Internal -ErrorAction Stop | Out-Null
                    $verifiedSwitch = Get-VMSwitch -Name $switchName -ErrorAction Stop
                    if ([string] $verifiedSwitch.SwitchType -ne 'Internal') {
                        throw "created switch has type $($verifiedSwitch.SwitchType)"
                    }
                    $created = $true
                    $existing = $verifiedSwitch
                    Write-KCSPLabLog "CREATE internal switch $switchName verified (attempt $attempt)" -Level INFO
                } catch {
                    $message = $_.Exception.Message
                    Write-KCSPLabLog "FAILED create internal switch $switchName (attempt $attempt): $message" -Level WARN
                    # 0x800700B7 may be a concurrent/partially materialised
                    # switch. Re-inspect truth and allow Windows bounded time to
                    # publish or clean the owned miniport before one retry.
                    $recovered = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
                    if ($recovered -and [string] $recovered.SwitchType -eq 'Internal') {
                        $existing = $recovered
                        $created = $true
                        Write-KCSPLabLog "REPAIRED switch $switchName materialised after create error" -Level INFO
                        break
                    }
                    if ($attempt -lt 2) {
                        Start-Sleep -Seconds 5
                        continue
                    }
                    Write-KCSPLabNetworkDiagnostics -Config $Config -Reason $message
                    throw
                }
            }
        }
    }

    if (-not $adapterResult) {
        $adapterResult = Wait-KCSPLabHostAdapter -SwitchName $switchName -TimeoutSeconds $AdapterTimeoutSeconds -PollMilliseconds $PollMilliseconds
    }
    if (-not $adapterResult -or -not $adapterResult.Adapter) {
        Write-KCSPLabNetworkDiagnostics -Config $Config -Reason "host adapter timeout after ${AdapterTimeoutSeconds}s"
        throw "NETWORK_ADAPTER_TIMEOUT: host adapter for switch '$switchName' did not appear within ${AdapterTimeoutSeconds}s."
    }
    $adapter = $adapterResult.Adapter
    Write-KCSPLabLog ("VERIFIED host adapter {0} (ifIndex={1}, waited={2:N1}s)" -f $adapter.Name, $adapter.ifIndex, $adapterResult.WaitedSeconds) -Level INFO

    $hostAddress = $Config.HostAddress
    $prefixLength = $Config.PrefixLength
    $foreignAddress = @(Get-NetIPAddress -IPAddress $hostAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -ne $adapter.ifIndex })
    if ($foreignAddress.Count -gt 0) {
        Write-KCSPLabNetworkDiagnostics -Config $Config -Reason "$hostAddress is assigned outside the lab adapter"
        throw "NETWORK_OWNERSHIP_CONFLICT: $hostAddress is already assigned to a non-lab interface."
    }
    $current = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $hostAddress }
    if (-not $current) {
        if ($PSCmdlet.ShouldProcess($hostAddress, 'Assign lab gateway address')) {
            # Clear any stale address on this adapter before assigning ours.
            Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $hostAddress -PrefixLength $prefixLength -ErrorAction Stop | Out-Null
            Write-KCSPLabLog "CREATE host IPv4 $hostAddress/$prefixLength on lab adapter" -Level INFO
        }
    } elseif ([int] $current.PrefixLength -ne $prefixLength) {
        throw "NETWORK_CONFIG_CONFLICT: $hostAddress has prefix length $($current.PrefixLength), expected $prefixLength."
    }
    $verifiedAddress = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $hostAddress -AddressFamily IPv4 -ErrorAction Stop
    Write-KCSPLabLog "VERIFIED host IPv4 $($verifiedAddress.IPAddress)/$($verifiedAddress.PrefixLength)" -Level INFO

    if ($Config.EnableNat) {
        $natName = "$($Config.Prefix)-NAT"
        Assert-KCSPLabOwned -Config $Config -Name $natName -Kind 'NAT'
        $foreignNat = @(Get-NetNat -ErrorAction SilentlyContinue | Where-Object {
            $_.InternalIPInterfaceAddressPrefix -eq $Config.Subnet -and $_.Name -ne $natName
        })
        if ($foreignNat.Count -gt 0) {
            throw "NETWORK_OWNERSHIP_CONFLICT: subnet $($Config.Subnet) belongs to NAT '$($foreignNat[0].Name)'."
        }
        $nat = Get-NetNat -Name $natName -ErrorAction SilentlyContinue
        if ($nat -and $nat.InternalIPInterfaceAddressPrefix -ne $Config.Subnet) {
            throw "NETWORK_CONFIG_CONFLICT: NAT '$natName' uses $($nat.InternalIPInterfaceAddressPrefix), expected $($Config.Subnet)."
        } elseif (-not $nat) {
            if ($PSCmdlet.ShouldProcess($natName, 'Create lab NAT')) {
                New-NetNat -Name $natName -InternalIPInterfaceAddressPrefix $Config.Subnet -ErrorAction Stop | Out-Null
                Write-KCSPLabLog "CREATE NAT $natName for $($Config.Subnet)" -Level INFO
            }
        } else {
            Write-KCSPLabLog "EXISTS NAT $natName for $($Config.Subnet)" -Level INFO
        }
        $verifiedNat = Get-NetNat -Name $natName -ErrorAction Stop
        if ($verifiedNat.InternalIPInterfaceAddressPrefix -ne $Config.Subnet) { throw "NETWORK_NAT_VERIFY_FAILED: $natName" }
        Write-KCSPLabLog "VERIFIED NAT $natName for $($verifiedNat.InternalIPInterfaceAddressPrefix)" -Level INFO
    }
    return $switchName
}

function Initialize-KCSPLabNetwork {
    <# Backward-compatible entrypoint; all behavior is ensure/reconcile. #>
    [CmdletBinding(SupportsShouldProcess = $true)] param([Parameter(Mandatory)] $Config)
    return Ensure-KCSPLabNetwork -Config $Config
}

function Set-KCSPLabIngress {
    <#
        .SYNOPSIS
        Publishes the KCSP API to the lab subnet only.

        .DESCRIPTION
        The API listens on 127.0.0.1 so guests cannot reach it directly. A
        portproxy on the lab gateway address forwards to it, and the firewall
        rule is scoped to the lab subnet - never Any, and never the university
        LAN. No datastore port is ever published.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)] param([Parameter(Mandatory)] $Config)
    Assert-KCSPLabElevated

    $listen = $Config.HostAddress
    $listenPort = $Config.IngressPort
    $target = '127.0.0.1'
    $targetPort = $Config.ApiPort

    $existing = & netsh interface portproxy show v4tov4 2>$null | Out-String
    if ($existing -notmatch [regex]::Escape($listen) -or $existing -notmatch "\b$listenPort\b") {
        if ($PSCmdlet.ShouldProcess("$listen`:$listenPort", "Forward to $target`:$targetPort")) {
            & netsh interface portproxy add v4tov4 listenaddress=$listen listenport=$listenPort connectaddress=$target connectport=$targetPort protocol=tcp | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "PORTPROXY_CREATE_FAILED: exit code $LASTEXITCODE" }
            Write-KCSPLabLog "Portproxy $listen`:$listenPort -> $target`:$targetPort" -Level INFO
        }
    } else {
        Write-KCSPLabLog "Portproxy for $listen`:$listenPort already present" -Level INFO
    }

    $ruleName = "$($Config.Prefix) - ingress"
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    $ruleValid = $false
    if ($rule) {
        $portFilter = $rule | Get-NetFirewallPortFilter
        $addressFilter = $rule | Get-NetFirewallAddressFilter
        $ruleValid = $rule.Enabled -eq 'True' -and $rule.Action -eq 'Allow' -and
            $portFilter.Protocol -eq 'TCP' -and [string] $portFilter.LocalPort -eq [string] $listenPort -and
            @($addressFilter.RemoteAddress) -contains $Config.Subnet
    }
    if ($rule -and -not $ruleValid) {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
        $rule = $null
        Write-KCSPLabLog 'REPAIR removed mismatched lab-owned ingress firewall rule' -Level WARN
    }
    if (-not $rule) {
        if ($PSCmdlet.ShouldProcess($ruleName, 'Create lab-scoped inbound rule')) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP `
                -LocalPort $listenPort -RemoteAddress $Config.Subnet -Profile Any | Out-Null
            Write-KCSPLabLog "Firewall allows $($Config.Subnet) to TCP $listenPort" -Level INFO
        }
    }
    return "http://$listen`:$listenPort"
}

function Test-KCSPLabTcpPort {
    [CmdletBinding()] param([Parameter(Mandatory)] [string] $Address, [Parameter(Mandatory)] [int] $Port, [int] $TimeoutMilliseconds=2000)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) { return $false }
        $client.EndConnect($pending)
        return $client.Connected
    } catch { return $false } finally { $client.Dispose() }
}

function Ensure-KCSPLabIngressReady {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    Assert-KCSPLabElevated
    $listen = [string] $Config.HostAddress; $port = [int] $Config.IngressPort
    $target = '127.0.0.1'; $targetPort = [int] $Config.ApiPort
    for ($attempt=1; $attempt -le 2; $attempt++) {
        if (Test-KCSPLabTcpPort -Address $listen -Port $port) {
            try {
                $health = Invoke-RestMethod "http://$listen`:$port/health/ready" -TimeoutSec 5 -ErrorAction Stop
                if ($health.status -eq 'ready') {
                    Write-KCSPLabLog "VERIFIED host ingress $listen`:$port -> $target`:$targetPort" -Level PASS
                    return "http://$listen`:$port"
                }
            } catch { }
        }
        Write-KCSPLabLog "REPAIR refreshing exact KCSP-LAB portproxy (attempt $attempt)" -Level WARN
        & netsh interface portproxy delete v4tov4 listenaddress=$listen listenport=$port protocol=tcp 2>$null | Out-Null
        & netsh interface portproxy add v4tov4 listenaddress=$listen listenport=$port connectaddress=$target connectport=$targetPort protocol=tcp | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "PORTPROXY_REPAIR_FAILED: exit code $LASTEXITCODE" }
        Start-Sleep -Seconds 2
    }
    throw "HOST_INGRESS_UNREACHABLE: $listen`:$port does not proxy the ready API at $target`:$targetPort."
}

function Remove-KCSPLabIngress {
    [CmdletBinding(SupportsShouldProcess = $true)] param([Parameter(Mandatory)] $Config)
    Assert-KCSPLabElevated
    if ($PSCmdlet.ShouldProcess('lab ingress', 'Remove portproxy and firewall rule')) {
        & netsh interface portproxy delete v4tov4 listenaddress=$($Config.HostAddress) listenport=$($Config.IngressPort) 2>$null | Out-Null
        Get-NetFirewallRule -DisplayName "$($Config.Prefix) - ingress" -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
}

# ----------------------------------------------------------------- guest access

function Wait-KCSPLabGuest {
    <#
        .SYNOPSIS
        Waits until PowerShell Direct answers inside the guest.

        .DESCRIPTION
        PowerShell Direct needs no network, no RDP and no open ports; it rides
        the VMBus. This is what removes the manual-copy dependency entirely.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [pscredential] $Credential,
        [int] $TimeoutSeconds = 1800
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    while ((Get-Date) -lt $deadline) {
        $attempt++
        try {
            $result = Invoke-Command -VMName $VMName -Credential $Credential -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
            if ($result) {
                Write-KCSPLabLog "$VMName reachable over PowerShell Direct as $result (attempt $attempt)" -Level INFO
                return $true
            }
        } catch {
            Start-Sleep -Seconds 10
        }
    }
    throw "Timed out after ${TimeoutSeconds}s waiting for PowerShell Direct on $VMName."
}

function Invoke-KCSPLabGuest {
    <#  Runs a script block inside a lab guest over PowerShell Direct. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [pscredential] $Credential,
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [object[]] $ArgumentList = @()
    )
    return Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
}

function Ensure-KCSPLabGuestNetwork {
    [CmdletBinding()] param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [pscredential] $Credential,
        [Parameter(Mandatory)] [string] $Address
    )
    Assert-KCSPLabOwned -Config $Config -Name $VMName -Kind 'VM'
    $hostNic = Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop | Where-Object { $_.SwitchName -eq $Config.Prefix } | Select-Object -First 1
    if (-not $hostNic) { throw "GUEST_NETWORK_INVALID: $VMName has no adapter on $($Config.Prefix)." }
    $mac = ([string] $hostNic.MacAddress).ToUpperInvariant()
    $dns = if ($Config.ContainsKey('GuestDnsServers')) { @($Config.GuestDnsServers) } else { @('1.1.1.1','8.8.8.8') }
    $state = Invoke-KCSPLabGuest -VMName $VMName -Credential $Credential -ArgumentList $mac,$Address,[int]$Config.PrefixLength,[string]$Config.HostAddress,$dns -ScriptBlock {
        param($expectedMac,$expectedAddress,$prefixLength,$gateway,$dnsServers)
        $ErrorActionPreference = 'Stop'
        $normalize = { param($value) ([string]$value).Replace(':','').Replace('-','').ToUpperInvariant() }
        $adapter = Get-NetAdapter | Where-Object { (& $normalize $_.MacAddress) -eq (& $normalize $expectedMac) } | Select-Object -First 1
        if (-not $adapter) { throw "Hyper-V guest adapter with MAC $expectedMac was not found." }
        if ($adapter.Status -ne 'Up') { Enable-NetAdapter -InterfaceIndex $adapter.ifIndex -Confirm:$false; Start-Sleep -Seconds 2 }
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -ne $expectedAddress -or $_.PrefixLength -ne $prefixLength } | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
        $current = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -eq $expectedAddress -and $_.PrefixLength -eq $prefixLength }
        if (-not $current) { New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $expectedAddress -PrefixLength $prefixLength -ErrorAction Stop | Out-Null }
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -ne $gateway } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        if (-not (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq $gateway })) {
            New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop $gateway -RouteMetric 10 -ErrorAction Stop | Out-Null
        }
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsServers -ErrorAction Stop
        [pscustomobject]@{ Hostname=$env:COMPUTERNAME; InterfaceAlias=$adapter.Name; InterfaceIndex=$adapter.ifIndex; MacAddress=$adapter.MacAddress; IPv4=$expectedAddress; PrefixLength=$prefixLength; Gateway=$gateway; DNS=@($dnsServers) }
    }
    Write-KCSPLabLog "$VMName VERIFIED guest network: $($state.IPv4)/$($state.PrefixLength) gateway=$($state.Gateway) adapter=$($state.InterfaceAlias)" -Level PASS
    return $state
}

function Test-KCSPLabGuestIngress {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config,[Parameter(Mandatory)][string]$VMName,[Parameter(Mandatory)][pscredential]$Credential)
    $result = Invoke-KCSPLabGuest -VMName $VMName -Credential $Credential -ArgumentList $Config.HostAddress,[int]$Config.IngressPort -ScriptBlock {
        param($hostAddress,$port)
        $tcp = (Test-NetConnection -ComputerName $hostAddress -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded
        $status = $null
        if ($tcp) { try { $status=(Invoke-RestMethod "http://$hostAddress`:$port/health/ready" -TimeoutSec 10 -ErrorAction Stop).status } catch { } }
        [pscustomobject]@{ Tcp=$tcp; Health=$status }
    }
    if (-not $result.Tcp -or $result.Health -ne 'ready') { throw "GUEST_INGRESS_UNREACHABLE: $VMName cannot reach ready API at $($Config.HostAddress):$($Config.IngressPort)." }
    Write-KCSPLabLog "$VMName VERIFIED guest ingress TCP=True health=ready" -Level PASS
    return $result
}

function Copy-KCSPLabFileToGuest {
    <#
        .SYNOPSIS
        Copies a host file into a guest without any network share.

        .DESCRIPTION
        Copy-VMFile is preferred; it needs the Guest Service Interface. When
        that is unavailable the file is streamed over a PowerShell Direct
        session instead, so deployment still works on a locked-down guest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [pscredential] $Credential,
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Destination
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Source file not found: $Source" }

    $service = Get-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
    if ($service -and -not $service.Enabled) {
        Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $service = Get-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
    }
    if ($service -and $service.Enabled) {
        try {
            Copy-VMFile -Name $VMName -SourcePath $Source -DestinationPath $Destination -CreateFullPath -FileSource Host -Force -ErrorAction Stop
            return $Destination
        } catch {
            Write-KCSPLabLog "Copy-VMFile failed ($($_.Exception.Message)); streaming over PowerShell Direct" -Level WARN
        }
    }

    # Fallback: stream the file in chunks through the VMBus session.
    $session = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
    try {
        Invoke-Command -Session $session -ScriptBlock {
            param($path)
            $dir = Split-Path -Parent $path
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        } -ArgumentList $Destination
        $stream = [IO.File]::OpenRead($Source)
        try {
            $buffer = New-Object byte[] (1MB)
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $chunk = if ($read -eq $buffer.Length) { $buffer } else { $buffer[0..($read - 1)] }
                $encoded = [Convert]::ToBase64String($chunk)
                Invoke-Command -Session $session -ScriptBlock {
                    param($path, $data)
                    $bytes = [Convert]::FromBase64String($data)
                    $fs = [IO.File]::Open($path, 'Append', 'Write')
                    try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
                } -ArgumentList $Destination, $encoded
            }
        } finally { $stream.Dispose() }
    } finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
    return $Destination
}

# ------------------------------------------------------------------ KCSP API

function Invoke-KCSPLabApi {
    <# Central fail-closed REST helper. It loads the ACL-protected lab bearer,
       applies tenant scope, parses problem responses and never logs secrets. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string] $Path,
        [string] $Method = 'GET',
        $Body,
        [int] $TimeoutSeconds = 30,
        [string] $TenantId,
        [string] $Bearer,
        [switch] $NoBearer
    )
    Assert-KCSPLabTenant -Config $Config
    if (-not $TenantId) { $TenantId = $Config.TenantId }
    if (-not $NoBearer -and -not $Bearer) { $Bearer = (Get-KCSPLabTenantCredential -Config $Config).AccessToken }
    $headers = @{
        'X-KCSP-Tenant-ID'   = $TenantId
        'Content-Type'       = 'application/json'
        'X-Request-ID'       = "lab_$([guid]::NewGuid().ToString('N'))"
    }
    if (-not $NoBearer) { $headers.Authorization = "Bearer $Bearer" }
    $uri = "http://127.0.0.1:$($Config.ApiPort)$Path"
    $parameters = @{ Uri=$uri; Headers=$headers; Method=$Method; TimeoutSec=$TimeoutSeconds; ErrorAction='Stop' }
    if ($null -ne $Body) { $parameters.Body = ($Body | ConvertTo-Json -Depth 8) }
    try {
        $response = Invoke-RestMethod @parameters
        if ($null -eq $response) { throw 'KCSP_LAB_API_CONTRACT_INVALID: empty response.' }
        return $response
    } catch {
        $caught = $_
        if ($caught.Exception.Message -like 'KCSP_LAB_API_CONTRACT_INVALID:*') { throw }
        $status = 0; $problemCode = 'request_failed'; $trace = ''
        $responseProperty = $caught.Exception.PSObject.Properties['Response']
        $errorResponse = if ($responseProperty) { $responseProperty.Value } else { $null }
        if ($errorResponse) {
            try { $status = [int] $errorResponse.StatusCode } catch { }
            try {
                $problemText = ''
                if ($errorResponse.PSObject.Methods['GetResponseStream']) {
                    $stream = $errorResponse.GetResponseStream()
                    $reader = New-Object IO.StreamReader($stream)
                    try { $problemText = $reader.ReadToEnd() } finally { $reader.Dispose() }
                } elseif ($errorResponse.PSObject.Properties['Content'] -and $errorResponse.Content) {
                    $problemText = $errorResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                }
                if (-not $problemText -and $caught.ErrorDetails -and $caught.ErrorDetails.Message) {
                    $problemText = [string] $caught.ErrorDetails.Message
                }
                if ($problemText) {
                    $problem = $problemText | ConvertFrom-Json
                    if ($problem.PSObject.Properties['code']) { $problemCode = [string] $problem.code }
                    if ($problem.PSObject.Properties['trace_id']) { $trace = [string] $problem.trace_id }
                }
            } catch { }
        }
        throw "KCSP_LAB_API_ERROR status=$status code=$problemCode trace_id=$trace method=$Method path=$Path"
    }
}

function Invoke-KCSPApi {
    <# Compatibility wrapper for existing scripts. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [string] $Path, [string] $Method='GET', $Body, [int] $TimeoutSeconds=30)
    return Invoke-KCSPLabApi -Config $Config -Path $Path -Method $Method -Body $Body -TimeoutSeconds $TimeoutSeconds
}

function Test-KCSPLabApiAuthorization {
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    $credential = Get-KCSPLabTenantCredential -Config $Config
    Invoke-KCSPLabApi -Config $Config -Path '/api/v1/collectors' | Out-Null
    $session = Invoke-KCSPLabApi -Config $Config -Path '/api/v1/session'
    $principalProperty = $session.PSObject.Properties['principal']
    $tenantProperty = $session.PSObject.Properties['tenant']
    $permissionsProperty = $session.PSObject.Properties['permissions']
    $runtimePrincipal = if ($principalProperty) { $principalProperty.Value } else { $null }
    $runtimeTenant = if ($tenantProperty) { $tenantProperty.Value } else { $null }
    if ($null -eq $runtimePrincipal -or $null -eq $runtimeTenant -or $null -eq $permissionsProperty -or
        -not $runtimePrincipal.PSObject.Properties['id'] -or -not $runtimePrincipal.PSObject.Properties['role'] -or
        -not $runtimeTenant.PSObject.Properties['id'] -or
        [string] $runtimePrincipal.id -ne 'svc-kcsp-lab-admin' -or [string] $runtimePrincipal.role -ne 'Lab Automation' -or
        [string] $runtimeTenant.id -ne $script:LabTenantId) {
        throw 'LAB_AUTH_PRINCIPAL_INVALID: runtime identity is not the tenant-scoped Lab Automation principal.'
    }
    $expectedPermissions = @(
        'platform.session.read','platform.overview.read','platform.collectors.read','platform.collectors.manage','platform.audit.read',
        'siem.events.read','siem.findings.read','siem.hunt.read','siem.hunt.execute','detection.rules.read','siem.rules.read',
        'soc.alerts.read','soc.alerts.manage','soc.incidents.read','soc.incidents.create','soc.incidents.manage',
        'soc.cases.read','soc.cases.manage','soc.evidence.read'
    )
    $actualPermissions = @($permissionsProperty.Value)
    $unexpectedPermissions = @($actualPermissions | Where-Object { $_ -notin $expectedPermissions })
    $missingPermissions = @($expectedPermissions | Where-Object { $_ -notin $actualPermissions })
    if ($unexpectedPermissions.Count -gt 0 -or $missingPermissions.Count -gt 0) {
        throw "LAB_AUTH_PRINCIPAL_INVALID: runtime permission allowlist mismatch (unexpected=$($unexpectedPermissions -join ','); missing=$($missingPermissions -join ','))."
    }

    $crossTokenBody = @{ label='KCSP-LAB-AUTH-CROSS-TENANT-DENY'; collector_type='lightweight-agent'; capabilities=@('windows_eventlog'); expires_in_seconds=300; max_uses=1 }
    $checks = @(
        @{ Name='cross-events'; Path='/api/v1/events?limit=1'; Method='GET'; Tenant=$script:ForbiddenTenantId; Expected=403; Code='tenant_denied' },
        @{ Name='cross-collectors'; Path='/api/v1/collectors'; Method='GET'; Tenant=$script:ForbiddenTenantId; Expected=403; Code='tenant_denied' },
        @{ Name='cross-incidents'; Path='/api/v1/incidents?limit=1'; Method='GET'; Tenant=$script:ForbiddenTenantId; Expected=403; Code='tenant_denied' },
        @{ Name='cross-evidence'; Path='/api/v1/evidence?limit=1'; Method='GET'; Tenant=$script:ForbiddenTenantId; Expected=403; Code='tenant_denied' },
        @{ Name='cross-enrollment'; Path='/api/v1/agent-enrollment/tokens'; Method='POST'; Tenant=$script:ForbiddenTenantId; Body=$crossTokenBody; Expected=403; Code='tenant_denied' },
        @{ Name='no-bearer'; Path='/api/v1/collectors'; Method='GET'; NoBearer=$true; Expected=401; Code='authentication_required' },
        @{ Name='wrong-bearer'; Path='/api/v1/collectors'; Method='GET'; Bearer='invalid-lab-credential-value'; Expected=401; Code='authentication_required' },
        @{ Name='platform-privileged'; Path='/api/v1/admin/tenants?limit=1'; Method='GET'; Expected=403; Code='permission_denied' }
    )
    foreach ($check in $checks) {
        $denied = $false
        try {
            $parameters = @{ Config=$Config; Path=$check.Path; Method=$check.Method }
            if ($check.ContainsKey('Tenant')) { $parameters.TenantId = $check.Tenant }
            if ($check.ContainsKey('Body')) { $parameters.Body = $check.Body }
            if ($check.ContainsKey('Bearer')) { $parameters.Bearer = $check.Bearer }
            if ($check.ContainsKey('NoBearer')) { $parameters.NoBearer = [switch] $check.NoBearer }
            Invoke-KCSPLabApi @parameters | Out-Null
        } catch {
            $message = $_.Exception.Message
            $denied = $message -match "status=$($check.Expected)\b" -and $message -match "code=$([regex]::Escape($check.Code))\b"
        }
        if (-not $denied) { throw "LAB_AUTH_ISOLATION_FAILED: $($check.Name) did not return $($check.Expected) $($check.Code)." }
    }

    $probeTokenId = $null
    try {
        $probe = New-KCSPLabEnrollmentToken -Config $Config -Label 'KCSP-LAB-AUTH-PROBE'
        $probeTokenId = [string] $probe.token.token_id
    } finally {
        if ($probeTokenId) {
            Invoke-KCSPLabApi -Config $Config -Path "/api/v1/agent-enrollment/tokens/$probeTokenId/revoke" -Method POST | Out-Null
        }
    }
    Write-KCSPLabLog 'VERIFIED lab auth: principal=Lab Automation own=200 cross=403 none=401 wrong=401 platform=403 enrollment=create+revoke' -Level PASS
    return [pscustomobject]@{ Allowed=200; CrossTenant=403; NoBearer=401; WrongBearer=401; PlatformPrivileged=403; Enrollment='created+revoked'; Principal=$credential.Principal; Role=$runtimePrincipal.role }
}

function Get-KCSPLabCollector {
    <#  Finds the collector a lab VM enrolled as, by hostname. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [string] $HostName)
    $collectors = Invoke-KCSPApi -Config $Config -Path '/api/v1/collectors'
    return @($collectors.items | Where-Object { $_.name -eq $HostName -or $_.name -eq $HostName.ToUpper() }) | Select-Object -First 1
}

function New-KCSPLabEnrollmentToken {
    <#  Issues a short-lived single-use enrollment token for one endpoint. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [string] $Label)
    $body = @{
        label = $Label
        collector_type = 'lightweight-agent'
        capabilities = @('sysmon')
        expires_in_seconds = 3600
        max_uses = 1
    }
    $issued = Invoke-KCSPLabApi -Config $Config -Path '/api/v1/agent-enrollment/tokens' -Method POST -Body $body
    $tokenProperty = $issued.PSObject.Properties['token']
    $tokenMetadata = if ($tokenProperty) { $tokenProperty.Value } else { $null }
    if (-not $issued.PSObject.Properties['enrollment_token'] -or
        [string]::IsNullOrWhiteSpace([string] $issued.enrollment_token) -or
        $null -eq $tokenMetadata -or -not $tokenMetadata.PSObject.Properties['token_id'] -or
        -not $tokenMetadata.PSObject.Properties['expires_at'] -or -not $tokenMetadata.PSObject.Properties['max_uses']) {
        throw 'ENROLLMENT_TOKEN_CONTRACT_INVALID: required enrollment_token/token_id/expires_at/max_uses fields are missing.'
    }
    $expiresAt = [DateTimeOffset]::MinValue
    $expiryValid = [DateTimeOffset]::TryParse([string] $tokenMetadata.expires_at, [ref] $expiresAt)
    $now = [DateTimeOffset]::UtcNow
    if ([string]::IsNullOrWhiteSpace([string] $tokenMetadata.token_id) -or
        [int] $tokenMetadata.max_uses -ne 1 -or -not $expiryValid -or
        $expiresAt -le $now -or $expiresAt -gt $now.AddHours(2)) {
        throw 'ENROLLMENT_TOKEN_CONTRACT_INVALID: token must be one-use and expire within the requested finite TTL.'
    }
    return $issued
}

# ------------------------------------------------------------------- reporting

function New-KCSPLabReport {
    [CmdletBinding()] param([Parameter(Mandatory)] [string] $Name)
    return [pscustomobject]@{
        Name      = $Name
        StartedAt = (Get-Date).ToUniversalTime()
        Checks    = New-Object System.Collections.Generic.List[object]
        Facts     = [ordered]@{}
    }
}

function Add-KCSPLabCheck {
    <#  Records one PASS/FAIL/SKIP check. Detail must never contain secrets. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Report,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('PASS', 'FAIL', 'SKIP')] [string] $Status,
        [string] $Detail = '',
        [double] $DurationSeconds = 0
    )
    $Report.Checks.Add([pscustomobject]@{
        check = $Name; status = $Status; detail = $Detail
        duration_seconds = [math]::Round($DurationSeconds, 3)
        at = (Get-Date).ToUniversalTime().ToString('o')
    })
    $level = switch ($Status) { 'PASS' { 'PASS' } 'FAIL' { 'FAIL' } default { 'WARN' } }
    Write-KCSPLabLog ("{0,-42} {1}{2}" -f $Name, $Status, $(if ($Detail) { "  ($Detail)" } else { '' })) -Level $level
}

function Set-KCSPLabFact {
    [CmdletBinding()] param([Parameter(Mandatory)] $Report, [Parameter(Mandatory)] [string] $Key, $Value)
    $Report.Facts[$Key] = $Value
}

function Save-KCSPLabReport {
    <#  Writes report.json and report.md, returning the output directory. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Report, [Parameter(Mandatory)] [string] $OutputRoot)

    $stamp = $Report.StartedAt.ToString('yyyyMMdd-HHmmss')
    $directory = Join-Path $OutputRoot $stamp
    New-Item -ItemType Directory -Path (Join-Path $directory 'logs') -Force | Out-Null

    $failed = @($Report.Checks | Where-Object { $_.status -eq 'FAIL' }).Count
    $passed = @($Report.Checks | Where-Object { $_.status -eq 'PASS' }).Count
    $skipped = @($Report.Checks | Where-Object { $_.status -eq 'SKIP' }).Count
    $finishedAt = (Get-Date).ToUniversalTime()

    $payload = [ordered]@{
        name = $Report.Name
        started_at = $Report.StartedAt.ToString('o')
        finished_at = $finishedAt.ToString('o')
        duration_seconds = [math]::Round(($finishedAt - $Report.StartedAt).TotalSeconds, 2)
        result = $(if ($failed -gt 0) { 'FAIL' } else { 'PASS' })
        passed = $passed; failed = $failed; skipped = $skipped
        facts = $Report.Facts
        # Materialised to a plain array: ConvertTo-Json cannot serialise a
        # List[object] nested inside an ordered dictionary.
        checks = $Report.Checks.ToArray()
    }
    [IO.File]::WriteAllText((Join-Path $directory 'report.json'),
        ($payload | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))

    $markdown = New-Object System.Text.StringBuilder
    [void] $markdown.AppendLine("# $($Report.Name)")
    [void] $markdown.AppendLine()
    [void] $markdown.AppendLine("**Result:** $($payload.result) - $passed passed, $failed failed, $skipped skipped in $($payload.duration_seconds)s")
    [void] $markdown.AppendLine()
    if ($Report.Facts.Count -gt 0) {
        [void] $markdown.AppendLine('## Facts')
        [void] $markdown.AppendLine()
        [void] $markdown.AppendLine('| Fact | Value |')
        [void] $markdown.AppendLine('| --- | --- |')
        foreach ($key in $Report.Facts.Keys) {
            [void] $markdown.AppendLine("| $key | $($Report.Facts[$key]) |")
        }
        [void] $markdown.AppendLine()
    }
    [void] $markdown.AppendLine('## Checks')
    [void] $markdown.AppendLine()
    [void] $markdown.AppendLine('| Check | Status | Detail | Seconds |')
    [void] $markdown.AppendLine('| --- | --- | --- | --- |')
    foreach ($check in $Report.Checks) {
        [void] $markdown.AppendLine("| $($check.check) | $($check.status) | $($check.detail) | $($check.duration_seconds) |")
    }
    [IO.File]::WriteAllText((Join-Path $directory 'report.md'),
        $markdown.ToString(), (New-Object Text.UTF8Encoding($false)))

    $timings = [object[]] ($Report.Checks | Select-Object check, duration_seconds)
    [IO.File]::WriteAllText((Join-Path $directory 'timings.json'),
        ($timings | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))

    if ($script:LabLogPath -and (Test-Path -LiteralPath $script:LabLogPath)) {
        Copy-Item -LiteralPath $script:LabLogPath -Destination (Join-Path $directory 'logs\lab.log') -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{ Directory = $directory; Result = $payload.result; Passed = $passed; Failed = $failed; Skipped = $skipped }
}

Export-ModuleMember -Function *-KCSPLab*, *-KCSPApi, Invoke-KCSPApi, ConvertFrom-KCSPLabSecureString
