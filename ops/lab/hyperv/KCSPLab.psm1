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
    if (-not $Config.ContainsKey('ApiToken') -or [string] $Config.ApiToken -ne 'kcsp-lab-admin') {
        throw "TENANT_SAFETY_GUARD: Hyper-V automation requires the tenant-scoped kcsp-lab credential."
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
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        Write-KCSPLabLog "Could not tighten ACL on $(Split-Path -Leaf $Path): $($_.Exception.Message)" -Level WARN
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

function Test-KCSPLabBaseImage {
    <# A VHDX is reusable only after image application, boot-file creation and
       clean dismount completed. The marker records that completed transaction;
       Get-VHD supplies current Hyper-V truth rather than trusting the marker. #>
    [CmdletBinding()] param([Parameter(Mandatory)] $Config)
    $paths = Get-KCSPLabPaths -Config $Config
    $basePath = Join-Path $paths.Base "$($Config.Prefix)-WIN-BASE.vhdx"
    $readyPath = "$basePath.ready.json"
    if (-not (Test-Path -LiteralPath $basePath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $readyPath -PathType Leaf)) { return $false }
    try {
        $marker = Get-Content -LiteralPath $readyPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $vhd = Get-VHD -Path $basePath -ErrorAction Stop
        return $marker.status -eq 'ready' -and
            $marker.base_image -eq $basePath -and
            $vhd.VhdType -eq 'Dynamic' -and
            [int64] $vhd.Size -eq [int64] $Config.VMDiskSizeBytes -and
            -not $vhd.Attached
    } catch {
        Write-KCSPLabLog "Base image validation failed: $($_.Exception.Message)" -Level WARN
        return $false
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
    $wanted = "$listen{0,-1}" -f ''
    if ($existing -notmatch [regex]::Escape($listen) -or $existing -notmatch "\b$listenPort\b") {
        if ($PSCmdlet.ShouldProcess("$listen`:$listenPort", "Forward to $target`:$targetPort")) {
            & netsh interface portproxy add v4tov4 listenaddress=$listen listenport=$listenPort connectaddress=$target connectport=$targetPort | Out-Null
            Write-KCSPLabLog "Portproxy $listen`:$listenPort -> $target`:$targetPort" -Level INFO
        }
    } else {
        Write-KCSPLabLog "Portproxy for $listen`:$listenPort already present" -Level INFO
    }

    $ruleName = "$($Config.Prefix) - ingress"
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $rule) {
        if ($PSCmdlet.ShouldProcess($ruleName, 'Create lab-scoped inbound rule')) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP `
                -LocalPort $listenPort -RemoteAddress $Config.Subnet -Profile Any | Out-Null
            Write-KCSPLabLog "Firewall allows $($Config.Subnet) to TCP $listenPort" -Level INFO
        }
    }
    return "http://$listen`:$listenPort"
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

function Invoke-KCSPApi {
    <#  REST helper against the KCSP API with tenant scoping. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string] $Path,
        [string] $Method = 'GET',
        $Body,
        [int] $TimeoutSeconds = 30
    )
    Assert-KCSPLabTenant -Config $Config
    $headers = @{
        Authorization        = "Bearer $($Config.ApiToken)"
        'X-KCSP-Tenant-ID'   = $Config.TenantId
        'Content-Type'       = 'application/json'
    }
    $uri = "http://127.0.0.1:$($Config.ApiPort)$Path"
    $parameters = @{ Uri = $uri; Headers = $headers; Method = $Method; TimeoutSec = $TimeoutSeconds }
    if ($null -ne $Body) { $parameters.Body = ($Body | ConvertTo-Json -Depth 8) }
    return Invoke-RestMethod @parameters
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
    $issued = Invoke-KCSPApi -Config $Config -Path '/api/v1/agent-enrollment/tokens' -Method POST -Body $body
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
