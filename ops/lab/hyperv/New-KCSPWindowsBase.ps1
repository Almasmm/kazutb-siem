#requires -Version 5.1
<#
    .SYNOPSIS
    Builds the KCSP lab golden Windows image from an official ISO.

    .DESCRIPTION
    Applies the Windows image straight into a VHDX with DISM instead of running
    Windows Setup, so nothing is ever typed at a setup screen. The answer file
    is written into \Windows\Panther, which Windows processes on first boot to
    create the lab administrator and finish OOBE unattended.

    The result is one base VHDX that every endpoint is cloned from, so Windows
    is installed once no matter how many endpoints the lab runs.

    .EXAMPLE
    .\New-KCSPWindowsBase.ps1
    .\New-KCSPWindowsBase.ps1 -IsoPath D:\iso\Win11_Eval.iso -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $ConfigPath,
    [string] $IsoPath,
    [string] $WindowsEdition,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KCSPLab.psm1') -Force

$config = Get-KCSPLabConfig -ConfigPath $ConfigPath
$paths = Get-KCSPLabPaths -Config $config
Start-KCSPLabLog -Path (Join-Path $paths.Logs ('base-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
Assert-KCSPLabElevated

$basePath = Join-Path $paths.Base "$($config.Prefix)-WIN-BASE.vhdx"
if ((Test-Path -LiteralPath $basePath) -and -not $Force) {
    Write-KCSPLabLog "Base image already present: $basePath (use -Force to rebuild)" -Level INFO
    return [pscustomobject]@{ BaseImage = $basePath; Rebuilt = $false }
}

# ------------------------------------------------------------------ locate ISO
if (-not $IsoPath) { $IsoPath = $config.IsoPath }
if (-not $IsoPath) {
    $candidate = Get-ChildItem -LiteralPath $paths.ISOs -Filter *.iso -ErrorAction SilentlyContinue |
        Sort-Object Length -Descending | Select-Object -First 1
    if ($candidate) { $IsoPath = $candidate.FullName }
}
if (-not $IsoPath -or -not (Test-Path -LiteralPath $IsoPath -PathType Leaf)) {
    Write-KCSPLabLog 'WINDOWS_ISO_REQUIRED' -Level ERROR
    Write-KCSPLabLog "Place an official Windows ISO in $($paths.ISOs) and re-run." -Level ERROR
    throw "WINDOWS_ISO_REQUIRED: expected an official Windows ISO in $($paths.ISOs)"
}
Write-KCSPLabLog "Using Windows ISO: $IsoPath" -Level STEP

$mounted = $null
$vhdMounted = $false
$imagePath = $null
try {
    # ------------------------------------------------------------- mount ISO
    $before = (Get-Volume).DriveLetter
    $mounted = Mount-DiskImage -ImagePath $IsoPath -PassThru
    Start-Sleep -Seconds 2
    $driveLetter = ($mounted | Get-Volume).DriveLetter
    if (-not $driveLetter) {
        $after = (Get-Volume).DriveLetter
        $driveLetter = (Compare-Object $before $after | Where-Object { $_.SideIndicator -eq '=>' }).InputObject | Select-Object -First 1
    }
    if (-not $driveLetter) { throw 'Could not determine the mounted ISO drive letter.' }
    $isoRoot = "${driveLetter}:"
    Write-KCSPLabLog "ISO mounted at $isoRoot" -Level INFO

    $wim = Join-Path $isoRoot 'sources\install.wim'
    $esd = Join-Path $isoRoot 'sources\install.esd'
    if (Test-Path -LiteralPath $wim) { $imagePath = $wim }
    elseif (Test-Path -LiteralPath $esd) { $imagePath = $esd }
    else { throw "Neither sources\install.wim nor sources\install.esd found on $isoRoot. Is this a Windows installation ISO?" }
    Write-KCSPLabLog "Windows image: $imagePath" -Level INFO

    # --------------------------------------------------------- choose edition
    $editions = Get-WindowsImage -ImagePath $imagePath
    Write-KCSPLabLog ("Editions available: " + (($editions | ForEach-Object { "$($_.ImageIndex)=$($_.ImageName)" }) -join '; ')) -Level INFO
    if (-not $WindowsEdition) { $WindowsEdition = $config.WindowsEdition }
    $selected = $editions | Where-Object { $_.ImageName -eq $WindowsEdition } | Select-Object -First 1
    if (-not $selected) {
        $selected = $editions | Where-Object { $_.ImageName -like '*Enterprise*' } | Select-Object -First 1
    }
    if (-not $selected) { $selected = $editions | Select-Object -First 1 }
    Write-KCSPLabLog "Selected edition: $($selected.ImageName) (index $($selected.ImageIndex))" -Level STEP

    # ------------------------------------------------------------ create VHDX
    if (Test-Path -LiteralPath $basePath) {
        Write-KCSPLabLog "Removing previous base image" -Level WARN
        Remove-Item -LiteralPath $basePath -Force
    }
    if (-not $PSCmdlet.ShouldProcess($basePath, 'Create and populate base VHDX')) { return }

    # Dynamic disk: the file grows with real content instead of reserving 64 GB.
    New-VHD -Path $basePath -SizeBytes $config.VMDiskSizeBytes -Dynamic | Out-Null
    Write-KCSPLabLog "Created dynamic VHDX ($([math]::Round($config.VMDiskSizeBytes/1GB)) GB max)" -Level INFO

    $disk = Mount-VHD -Path $basePath -PassThru | Get-Disk
    $vhdMounted = $true
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -Confirm:$false | Out-Null

    # Gen2 UEFI layout: EFI system partition, MSR, then Windows.
    $efi = New-Partition -DiskNumber $disk.Number -Size 512MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    $efi | Format-Volume -FileSystem FAT32 -NewFileSystemLabel 'System' -Confirm:$false | Out-Null
    $efiLetter = (Get-Partition -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber | Get-Volume).DriveLetter
    if (-not $efiLetter) {
        $efi | Set-Partition -NewDriveLetter 'S'
        $efiLetter = 'S'
    }
    New-Partition -DiskNumber $disk.Number -Size 128MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
    $windows = New-Partition -DiskNumber $disk.Number -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
    $windows | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false | Out-Null
    $windows | Set-Partition -NewDriveLetter 'W'
    Write-KCSPLabLog "Partitioned base VHDX (EFI=${efiLetter}: Windows=W:)" -Level INFO

    # ------------------------------------------------------- apply the image
    Write-KCSPLabLog "Applying Windows image - this takes several minutes" -Level STEP
    $applyStart = Get-Date
    Expand-WindowsImage -ImagePath $imagePath -Index $selected.ImageIndex -ApplyPath 'W:\' | Out-Null
    Write-KCSPLabLog "Image applied in $([math]::Round(((Get-Date) - $applyStart).TotalMinutes,1)) min" -Level INFO

    # ------------------------------------------------------------- answer file
    $credential = Get-KCSPLabCredential -Config $config
    $plainPassword = ConvertFrom-KCSPLabSecureString -Value $credential.Password
    $template = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'unattend.template.xml') -Raw
    $answer = $template.
        Replace('{{COMPUTERNAME}}', "$($config.Prefix)-BASE").
        Replace('{{TIMEZONE}}', $config.TimeZone).
        Replace('{{LOCALE}}', $config.Locale).
        Replace('{{ADMINUSER}}', $credential.UserName).
        Replace('{{ADMINPASSWORD}}', [Security.SecurityElement]::Escape($plainPassword))
    $plainPassword = $null

    New-Item -ItemType Directory -Path 'W:\Windows\Panther' -Force | Out-Null
    [IO.File]::WriteAllText('W:\Windows\Panther\unattend.xml', $answer, (New-Object Text.UTF8Encoding($false)))
    $answer = $null
    Write-KCSPLabLog 'Answer file staged in \Windows\Panther' -Level INFO

    # Stage a marker so first-boot completion is detectable from the host.
    New-Item -ItemType Directory -Path 'W:\KCSP' -Force | Out-Null

    # --------------------------------------------------------------- bootable
    & bcdboot W:\Windows /s "${efiLetter}:" /f UEFI | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "bcdboot failed with exit code $LASTEXITCODE." }
    Write-KCSPLabLog 'Boot files written (UEFI)' -Level INFO
}
finally {
    if ($vhdMounted) {
        try { Dismount-VHD -Path $basePath -ErrorAction Stop } catch { Write-KCSPLabLog "Dismount-VHD: $($_.Exception.Message)" -Level WARN }
    }
    if ($mounted) {
        try { Dismount-DiskImage -ImagePath $IsoPath | Out-Null } catch { }
    }
}

$size = (Get-Item -LiteralPath $basePath).Length
Write-KCSPLabLog "Golden image ready: $basePath ($([math]::Round($size/1GB,1)) GB on disk)" -Level PASS
[pscustomobject]@{
    BaseImage = $basePath
    Edition   = $selected.ImageName
    Source    = $IsoPath
    SizeBytes = $size
    Rebuilt   = $true
}
