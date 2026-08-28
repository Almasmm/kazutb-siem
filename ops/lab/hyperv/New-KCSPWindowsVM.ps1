#requires -Version 5.1
<#
    .SYNOPSIS
    Creates N lab Windows endpoints from the golden image.

    .DESCRIPTION
    Each endpoint gets its own differencing disk over the shared base VHDX, so
    cloning costs seconds and megabytes rather than a full Windows install. The
    guest's computer name and static lab address are injected offline into its
    own answer file before first boot, which is what keeps hostnames, agent IDs
    and collector identities distinct per endpoint.

    .EXAMPLE
    .\New-KCSPWindowsVM.ps1 -Count 1
    .\New-KCSPWindowsVM.ps1 -Count 4 -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $ConfigPath,
    [ValidateRange(1, 32)] [int] $Count,
    [int] $StartIndex = 1,
    [switch] $Force,
    [switch] $NoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('vm-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
Assert-KCSPLabElevated

if (-not $Count) { $Count = [int] $config.DefaultCount }
$basePath = Join-Path $paths.Base "$($config.Prefix)-WIN-BASE.vhdx"
if (-not (Test-Path -LiteralPath $basePath -PathType Leaf)) {
    throw "Golden image not found: $basePath. Run New-KCSPWindowsBase.ps1 first."
}

$switchName = Initialize-KCSPLabNetwork -Config $config
$credential = Get-KCSPLabCredential -Config $config
$template = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'unattend.template.xml') -Raw
$created = New-Object System.Collections.Generic.List[object]

for ($offset = 0; $offset -lt $Count; $offset++) {
    $index = $StartIndex + $offset
    $vmName = Get-KCSPLabVMName -Config $config -Index $index
    $address = Get-KCSPLabVMAddress -Config $config -Index $index
    Assert-KCSPLabOwned -Config $config -Name $vmName -Kind 'VM'

    $existing = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Write-KCSPLabLog "$vmName already exists - skipping (use -Force to recreate)" -Level INFO
        $created.Add([pscustomobject]@{ Name = $vmName; Address = $address; Created = $false })
        continue
    }
    if ($existing -and $Force) {
        if ($PSCmdlet.ShouldProcess($vmName, 'Remove existing lab VM')) {
            Write-KCSPLabLog "Removing existing $vmName" -Level WARN
            if ($existing.State -ne 'Off') { Stop-VM -Name $vmName -TurnOff -Force }
            $disks = @(Get-VMHardDiskDrive -VMName $vmName | Select-Object -ExpandProperty Path)
            Remove-VM -Name $vmName -Force
            foreach ($disk in $disks) {
                # Only ever delete disks that live under the lab VM directory.
                if ($disk -and $disk.StartsWith($paths.VMs, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $disk)) {
                    Remove-Item -LiteralPath $disk -Force
                }
            }
        }
    }

    if (-not $PSCmdlet.ShouldProcess($vmName, 'Create lab endpoint')) { continue }

    $vmDirectory = Join-Path $paths.VMs $vmName
    New-Item -ItemType Directory -Path $vmDirectory -Force | Out-Null
    $diskPath = Join-Path $vmDirectory "$vmName.vhdx"

    # Differencing disk keeps each endpoint tiny and the base image immutable.
    New-VHD -Path $diskPath -ParentPath $basePath -Differencing | Out-Null
    Write-KCSPLabLog "$vmName differencing disk created over the golden image" -Level INFO

    # Personalise the guest offline: computer name and static lab address.
    $mounted = Mount-VHD -Path $diskPath -PassThru
    try {
        $volume = $mounted | Get-Disk | Get-Partition | Get-Volume |
            Where-Object { $_.FileSystemLabel -eq 'Windows' -and $_.DriveLetter } | Select-Object -First 1
        if (-not $volume) { throw "Could not locate the Windows volume inside $diskPath." }
        $guestRoot = "$($volume.DriveLetter):"

        $plainPassword = ConvertFrom-KCSPLabSecureString -Value $credential.Password
        $answer = $template.
            Replace('{{COMPUTERNAME}}', $vmName).
            Replace('{{TIMEZONE}}', $config.TimeZone).
            Replace('{{LOCALE}}', $config.Locale).
            Replace('{{ADMINUSER}}', $credential.UserName).
            Replace('{{ADMINPASSWORD}}', [Security.SecurityElement]::Escape($plainPassword))
        $plainPassword = $null
        New-Item -ItemType Directory -Path "$guestRoot\Windows\Panther" -Force | Out-Null
        [IO.File]::WriteAllText("$guestRoot\Windows\Panther\unattend.xml", $answer, (New-Object Text.UTF8Encoding($false)))
        $answer = $null

        # Static addressing script, applied by the guest on first boot. The lab
        # runs no DHCP, so each endpoint configures its own address.
        New-Item -ItemType Directory -Path "$guestRoot\KCSP" -Force | Out-Null
        $network = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$adapter = Get-NetAdapter | Where-Object { `$_.Status -eq 'Up' } | Select-Object -First 1
if (`$adapter) {
    Get-NetIPAddress -InterfaceIndex `$adapter.ifIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:`$false
    Remove-NetRoute -InterfaceIndex `$adapter.ifIndex -Confirm:`$false
    New-NetIPAddress -InterfaceIndex `$adapter.ifIndex -IPAddress '$address' -PrefixLength $($config.PrefixLength) -DefaultGateway '$($config.HostAddress)'
    Set-DnsClientServerAddress -InterfaceIndex `$adapter.ifIndex -ServerAddresses '1.1.1.1','8.8.8.8'
}
Set-Content -Path C:\KCSP\network-configured.txt -Value '$address'
"@
        [IO.File]::WriteAllText("$guestRoot\KCSP\Set-LabNetwork.ps1", $network, (New-Object Text.UTF8Encoding($false)))
        Write-KCSPLabLog "$vmName personalised (hostname + $address)" -Level INFO
    }
    finally {
        Dismount-VHD -Path $diskPath -ErrorAction SilentlyContinue
    }

    $vm = New-VM -Name $vmName -Generation $config.VMGeneration -MemoryStartupBytes $config.VMMemoryStartupBytes `
        -VHDPath $diskPath -SwitchName $switchName -Path $paths.VMs
    Set-VMProcessor -VMName $vmName -Count $config.VMProcessorCount
    if ($config.VMDynamicMemory) {
        Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $true `
            -MinimumBytes $config.VMMemoryMinimumBytes -StartupBytes $config.VMMemoryStartupBytes -MaximumBytes $config.VMMemoryMaximumBytes
    }
    Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false -CheckpointType Standard
    # Guest Service Interface carries Copy-VMFile; without it deployment falls
    # back to streaming over PowerShell Direct.
    Enable-VMIntegrationService -VMName $vmName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue

    # Windows 11 expects a TPM and Secure Boot.
    try {
        Set-VMFirmware -VMName $vmName -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
        $owner = Get-HgsGuardian -Name 'UntrustedGuardian' -ErrorAction SilentlyContinue
        if (-not $owner) { $owner = New-HgsGuardian -Name 'UntrustedGuardian' -GenerateCertificates }
        $protector = New-HgsKeyProtector -Owner $owner -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $vmName -KeyProtector $protector.RawData
        Enable-VMTPM -VMName $vmName
        Write-KCSPLabLog "$vmName vTPM and Secure Boot enabled" -Level INFO
    } catch {
        Write-KCSPLabLog "$vmName TPM/Secure Boot setup skipped: $($_.Exception.Message)" -Level WARN
    }

    if (-not $NoStart) {
        Start-VM -Name $vmName
        Write-KCSPLabLog "$vmName started" -Level STEP
    }
    $created.Add([pscustomobject]@{ Name = $vmName; Address = $address; Disk = $diskPath; Created = $true })
}

Write-KCSPLabLog "Endpoints ready: $(($created | ForEach-Object { $_.Name }) -join ', ')" -Level PASS
$created
