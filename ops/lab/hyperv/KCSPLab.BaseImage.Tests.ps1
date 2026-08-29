#requires -Version 5.1

$modulePath = Join-Path $PSScriptRoot 'KCSPLab.psm1'
Import-Module $modulePath -Force
Set-StrictMode -Version Latest

function New-TestBaseState {
    param(
        [bool] $Valid = $true,
        [bool] $MarkerValid = $true,
        [bool] $Attached = $false,
        [object[]] $Dependencies = @(),
        [bool] $RuntimeProof = $false,
        [bool] $OfflineValid = $false
    )
    [pscustomobject]@{
        BasePath='C:\Hyper-V\KCSP-LAB\Base\KCSP-LAB-WIN-BASE.vhdx'
        ReadyPath='C:\Hyper-V\KCSP-LAB\Base\KCSP-LAB-WIN-BASE.vhdx.ready.json'
        Exists=$true; Valid=$Valid; MarkerValid=$MarkerValid; VHDValid=$true
        Attached=$Attached; Dependencies=$Dependencies; RuntimeProof=$RuntimeProof
        OfflineValid=$OfflineValid; Reason='test proof'
    }
}

Describe 'KCSP golden image lifecycle' {
    BeforeEach {
        Mock Write-KCSPLabLog {} -ModuleName KCSPLab
        Mock Repair-KCSPLabBaseImageMetadata {} -ModuleName KCSPLab
    }

    It 'verifies a valid base without VM dependencies' {
        $state = New-TestBaseState
        $global:KCSPTestBaseState = $state
        Mock Get-KCSPLabBaseImageState { $global:KCSPTestBaseState } -ModuleName KCSPLab

        (Ensure-KCSPLabBaseImage -Config @{}).Valid | Should Be $true
        Assert-MockCalled Repair-KCSPLabBaseImageMetadata -Times 0 -Exactly -ModuleName KCSPLab -Scope It
        Remove-Variable KCSPTestBaseState -Scope Global -ErrorAction SilentlyContinue
    }

    It 'verifies a valid attached base with a child and never permits deletion' {
        $dependency = [pscustomobject]@{ VMName='KCSP-LAB-WIN-01'; DiskPath='C:\Hyper-V\KCSP-LAB\VMs\KCSP-LAB-WIN-01\disk.vhdx'; Chain=@('child.vhdx','base.vhdx'); CleanWindowsCheckpoint=$true }
        $state = New-TestBaseState -Attached $true -Dependencies @($dependency) -RuntimeProof $true
        $global:KCSPTestBaseState = $state
        Mock Get-KCSPLabBaseImageState { $global:KCSPTestBaseState } -ModuleName KCSPLab

        (Ensure-KCSPLabBaseImage -Config @{}).Valid | Should Be $true
        { Assert-KCSPLabBaseImageRemovalSafe -State $state } | Should Throw
        Remove-Variable KCSPTestBaseState -Scope Global -ErrorAction SilentlyContinue
    }

    It 'reconstructs a missing READY marker from booted child runtime proof' {
        $dependency = [pscustomobject]@{ VMName='KCSP-LAB-WIN-01'; DiskPath='child.vhdx'; Chain=@('child.vhdx','base.vhdx'); CleanWindowsCheckpoint=$true }
        $missing = New-TestBaseState -MarkerValid $false -Attached $true -Dependencies @($dependency) -RuntimeProof $true
        $repaired = New-TestBaseState -Attached $true -Dependencies @($dependency) -RuntimeProof $true
        $global:KCSPTestMissingBaseState = $missing
        $global:KCSPTestRepairedBaseState = $repaired
        $global:KCSPBaseStateCalls = 0
        Mock Get-KCSPLabBaseImageState {
            $global:KCSPBaseStateCalls++
            if ($global:KCSPBaseStateCalls -eq 1) { return $global:KCSPTestMissingBaseState }
            return $global:KCSPTestRepairedBaseState
        } -ModuleName KCSPLab

        (Ensure-KCSPLabBaseImage -Config @{}).Valid | Should Be $true
        Assert-MockCalled Repair-KCSPLabBaseImageMetadata -Times 1 -Exactly -ModuleName KCSPLab -Scope It
        Remove-Variable KCSPBaseStateCalls,KCSPTestMissingBaseState,KCSPTestRepairedBaseState -Scope Global -ErrorAction SilentlyContinue
    }

    It 'allows guarded replacement of an invalid dependency-free base' {
        $state = New-TestBaseState -Valid $false
        { Assert-KCSPLabBaseImageRemovalSafe -State $state } | Should Not Throw
    }

    It 'fails closed for an invalid base with children instead of deleting the parent' {
        $dependency = [pscustomobject]@{ VMName='KCSP-LAB-WIN-01'; DiskPath='child.vhdx'; Chain=@('child.vhdx','base.vhdx'); CleanWindowsCheckpoint=$false }
        $state = New-TestBaseState -Valid $false -Attached $true -Dependencies @($dependency)
        Mock Remove-Item {} -ModuleName KCSPLab

        { Remove-KCSPLabInvalidBaseImage -State $state } | Should Throw
        Assert-MockCalled Remove-Item -Times 0 -Exactly -ModuleName KCSPLab -Scope It
    }

    It 'does not retry a locked base and preserves its READY marker' {
        $state = New-TestBaseState -Valid $false
        Mock Test-Path { $true } -ModuleName KCSPLab
        Mock Remove-Item { throw 'file is being used by another process' } -ModuleName KCSPLab

        { Remove-KCSPLabInvalidBaseImage -State $state } | Should Throw
        Assert-MockCalled Remove-Item -ParameterFilter { $LiteralPath -eq $state.BasePath } -Times 1 -Exactly -ModuleName KCSPLab -Scope It
        Assert-MockCalled Remove-Item -ParameterFilter { $LiteralPath -eq $state.ReadyPath } -Times 0 -Exactly -ModuleName KCSPLab -Scope It
    }

    It 'preserves the existing CLEAN_WINDOWS checkpoint by using it only as proof' {
        $dependency = [pscustomobject]@{ VMName='KCSP-LAB-WIN-01'; DiskPath='child.vhdx'; Chain=@('child.vhdx','base.vhdx'); CleanWindowsCheckpoint=$true }
        $state = New-TestBaseState -Dependencies @($dependency) -RuntimeProof $true
        $global:KCSPTestBaseState = $state
        Mock Get-KCSPLabBaseImageState { $global:KCSPTestBaseState } -ModuleName KCSPLab
        Mock Remove-VMSnapshot {} -ModuleName KCSPLab

        Ensure-KCSPLabBaseImage -Config @{} | Out-Null
        Assert-MockCalled Remove-VMSnapshot -Times 0 -Exactly -ModuleName KCSPLab -Scope It
        Remove-Variable KCSPTestBaseState -Scope Global -ErrorAction SilentlyContinue
    }
}

Describe 'KCSP dependency collection contract' {
    BeforeEach {
        $global:KCSPDependencyTestVMs = @()
        Mock Get-KCSPLabVMs { $global:KCSPDependencyTestVMs } -ModuleName KCSPLab
        Mock Assert-KCSPLabOwned {} -ModuleName KCSPLab
        Mock Get-VMSnapshot { [pscustomobject]@{ Name='CLEAN_WINDOWS' } } -ModuleName KCSPLab
        Mock Get-VMHardDiskDrive {
            param($VMName)
            [pscustomobject]@{ Path="C:\Hyper-V\KCSP-LAB\VMs\$VMName\$VMName.vhdx" }
        } -ModuleName KCSPLab
        Mock Get-VHD {
            param($Path)
            if ($Path -like '*WIN-BASE.vhdx') {
                return [pscustomobject]@{ Path=$Path; ParentPath=''; VhdType='Dynamic'; Attached=$true }
            }
            return [pscustomobject]@{ Path=$Path; ParentPath='C:\Hyper-V\KCSP-LAB\Base\KCSP-LAB-WIN-BASE.vhdx'; VhdType='Differencing'; Attached=$true }
        } -ModuleName KCSPLab
        Mock Get-KCSPLabPaths { @{ VMs='C:\Hyper-V\KCSP-LAB\VMs' } } -ModuleName KCSPLab
        Mock Get-ChildItem { @() } -ModuleName KCSPLab
    }

    It 'returns System.Object[] for 0, 1 and multiple List[object] dependencies' {
        foreach ($count in 0, 1, 3) {
            $source = New-Object System.Collections.Generic.List[object]
            for ($index = 0; $index -lt $count; $index++) {
                $source.Add([pscustomobject]@{ VMName="KCSP-LAB-WIN-$index"; ChildPath="child-$index.vhdx" })
            }
            $result = ConvertTo-KCSPLabObjectArray -InputCollection $source
            $null -eq $result | Should Be $false
            $result.GetType().FullName | Should Be 'System.Object[]'
            $result.Count | Should Be $count
        }
    }

    It 'returns System.Object[] for 0, 1 and multiple List[PSObject] dependencies' {
        foreach ($count in 0, 1, 3) {
            $source = New-Object System.Collections.Generic.List[psobject]
            for ($index = 0; $index -lt $count; $index++) {
                $source.Add([pscustomobject]@{ VMName="KCSP-LAB-WIN-$index"; ChildPath="child-$index.vhdx" })
            }
            $result = ConvertTo-KCSPLabObjectArray -InputCollection $source
            $null -eq $result | Should Be $false
            $result.GetType().FullName | Should Be 'System.Object[]'
            $result.Count | Should Be $count
        }
    }

    It 'does not contain the failing generic List wrapping return pattern' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should Not Match 'return\s+@\(\$dependencies\)'
    }

    It 'keeps the Get-KCSPLabBaseDependencies return type stable for 0, 1 and N real-contract objects' {
        $base = 'C:\Hyper-V\KCSP-LAB\Base\KCSP-LAB-WIN-BASE.vhdx'
        foreach ($count in 0, 1, 3) {
            $global:KCSPDependencyTestVMs = @(for ($index=1; $index -le $count; $index++) {
                [pscustomobject]@{ Name="KCSP-LAB-WIN-0$index"; State='Running' }
            })
            $result = Get-KCSPLabBaseDependencies -Config @{ Prefix='KCSP-LAB' } -BasePath $base
            $result.GetType().FullName | Should Be 'System.Object[]'
            $result.Count | Should Be $count
            foreach ($dependency in $result) {
                $names = @($dependency.PSObject.Properties.Name)
                ($names -contains 'VMName') | Should Be $true
                ($names -contains 'ChildPath') | Should Be $true
                ($names -contains 'ParentPath') | Should Be $true
                ($names -contains 'DiskType') | Should Be $true
                ($names -contains 'Attached') | Should Be $true
                ($names -contains 'OwnedByLab') | Should Be $true
            }
        }
        Remove-Variable KCSPDependencyTestVMs -Scope Global -ErrorAction SilentlyContinue
    }
}
