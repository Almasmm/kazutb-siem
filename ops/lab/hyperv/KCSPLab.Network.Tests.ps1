#requires -Version 5.1

$modulePath = Join-Path $PSScriptRoot 'KCSPLab.psm1'
Import-Module $modulePath -Force

Describe 'KCSP lab network reconciliation' {
        BeforeEach {
            Mock Assert-KCSPLabElevated {} -ModuleName KCSPLab
            Mock Test-KCSPLabElevated { $true } -ModuleName KCSPLab
            Mock Assert-KCSPLabOwned {} -ModuleName KCSPLab
            Mock Get-VMNetworkAdapter { @([pscustomobject]@{ Name = 'KCSP-LAB'; SwitchName = 'KCSP-LAB'; DeviceId = ''; Id = '' }) } -ModuleName KCSPLab
            Mock Start-Sleep {} -ModuleName KCSPLab
            Mock New-NetIPAddress { [pscustomobject]@{ InterfaceIndex = 250; IPAddress = '192.168.250.1'; PrefixLength = 24 } } -ModuleName KCSPLab
            Mock Remove-NetIPAddress {} -ModuleName KCSPLab
            Mock New-NetNat { [pscustomobject]@{ Name = 'KCSP-LAB-NAT'; InternalIPInterfaceAddressPrefix = '192.168.250.0/24' } } -ModuleName KCSPLab
            Mock Remove-VMSwitch {} -ModuleName KCSPLab
            Mock Write-KCSPLabLog {} -ModuleName KCSPLab
        }

        It 'preserves and verifies an existing desired switch and NAT' {
            $testConfig = @{ Prefix='KCSP-LAB'; HostAddress='192.168.250.1'; PrefixLength=24; Subnet='192.168.250.0/24'; EnableNat=$true }
            Mock Get-VMSwitch { [pscustomobject]@{ Name = 'KCSP-LAB'; SwitchType = 'Internal' } } -ModuleName KCSPLab
            Mock Get-NetAdapter { @([pscustomobject]@{ Name='vEthernet (KCSP-LAB)'; InterfaceDescription='Hyper-V Virtual Ethernet Adapter'; InterfaceGuid=[guid]::NewGuid(); ifIndex=250 }) } -ModuleName KCSPLab
            Mock Get-NetIPAddress { @([pscustomobject]@{ InterfaceIndex=250; IPAddress='192.168.250.1'; PrefixLength=24 }) } -ModuleName KCSPLab
            Mock Get-NetNat { @([pscustomobject]@{ Name='KCSP-LAB-NAT'; InternalIPInterfaceAddressPrefix='192.168.250.0/24' }) } -ModuleName KCSPLab
            Mock New-VMSwitch { throw 'must not create a duplicate switch' } -ModuleName KCSPLab

            Ensure-KCSPLabNetwork -Config $testConfig -AdapterTimeoutSeconds 1 -PollMilliseconds 1 | Should Be 'KCSP-LAB'

            Assert-MockCalled New-VMSwitch -Times 0 -Exactly -ModuleName KCSPLab -Scope It
            Assert-MockCalled Remove-VMSwitch -Times 0 -Exactly -ModuleName KCSPLab -Scope It
            Assert-MockCalled New-NetNat -Times 0 -Exactly -ModuleName KCSPLab -Scope It
        }

        It 'repairs an owned switch object whose management adapter is missing' {
            $testConfig = @{ Prefix='KCSP-LAB'; HostAddress='192.168.250.1'; PrefixLength=24; Subnet='192.168.250.0/24'; EnableNat=$true }
            $global:KCSPTestSwitchPresent = $true
            $global:KCSPTestAdapterPresent = $false
            Mock Get-VMSwitch {
                if ($global:KCSPTestSwitchPresent) { return [pscustomobject]@{ Name='KCSP-LAB'; SwitchType='Internal' } }
                return $null
            } -ModuleName KCSPLab
            Mock Get-NetAdapter {
                if ($global:KCSPTestAdapterPresent) { return @([pscustomobject]@{ Name='vEthernet (KCSP-LAB)'; InterfaceDescription='Hyper-V Virtual Ethernet Adapter'; InterfaceGuid=[guid]::NewGuid(); ifIndex=250 }) }
                return @()
            } -ModuleName KCSPLab
            Mock Get-NetIPAddress { @([pscustomobject]@{ InterfaceIndex=250; IPAddress='192.168.250.1'; PrefixLength=24 }) } -ModuleName KCSPLab
            Mock Get-NetNat { @([pscustomobject]@{ Name='KCSP-LAB-NAT'; InternalIPInterfaceAddressPrefix='192.168.250.0/24' }) } -ModuleName KCSPLab
            Mock Remove-VMSwitch { $global:KCSPTestSwitchPresent = $false } -ModuleName KCSPLab
            Mock New-VMSwitch {
                $global:KCSPTestSwitchPresent = $true
                $global:KCSPTestAdapterPresent = $true
                return [pscustomobject]@{ Name='KCSP-LAB'; SwitchType='Internal' }
            } -ModuleName KCSPLab

            Ensure-KCSPLabNetwork -Config $testConfig -AdapterTimeoutSeconds 0 -PollMilliseconds 1 | Should Be 'KCSP-LAB'

            Assert-MockCalled Remove-VMSwitch -Times 1 -Exactly -ModuleName KCSPLab -Scope It
            Assert-MockCalled New-VMSwitch -Times 1 -Exactly -ModuleName KCSPLab -Scope It
            Assert-MockCalled Write-KCSPLabLog -ParameterFilter { $Message -like 'REPAIR partial switch*' } -Times 1 -ModuleName KCSPLab -Scope It
            Assert-MockCalled Write-KCSPLabLog -ParameterFilter { $Message -like 'CREATE internal switch*verified*' } -Times 1 -ModuleName KCSPLab -Scope It
            Remove-Variable KCSPTestSwitchPresent,KCSPTestAdapterPresent -Scope Global -ErrorAction SilentlyContinue
        }

        It 'fails closed and never logs CREATE when New-VMSwitch throws 0x800700B7' {
            $testConfig = @{ Prefix='KCSP-LAB'; HostAddress='192.168.250.1'; PrefixLength=24; Subnet='192.168.250.0/24'; EnableNat=$true }
            Mock Get-VMSwitch { $null } -ModuleName KCSPLab
            Mock Get-VMNetworkAdapter { @() } -ModuleName KCSPLab
            Mock Get-NetAdapter { @() } -ModuleName KCSPLab
            Mock Get-NetIPAddress { @() } -ModuleName KCSPLab
            Mock Get-NetNat { @() } -ModuleName KCSPLab
            Mock New-VMSwitch { throw '0x800700B7 Cannot create a file when that file already exists' } -ModuleName KCSPLab

            { Ensure-KCSPLabNetwork -Config $testConfig -AdapterTimeoutSeconds 0 -PollMilliseconds 1 } | Should Throw

            Assert-MockCalled New-VMSwitch -Times 2 -Exactly -ModuleName KCSPLab -Scope It
            Assert-MockCalled Write-KCSPLabLog -ParameterFilter { $Message -like 'CREATE internal switch*' } -Times 0 -ModuleName KCSPLab -Scope It
            Assert-MockCalled Write-KCSPLabLog -ParameterFilter { $Message -like 'FAILED create internal switch*0x800700B7*' } -Times 2 -ModuleName KCSPLab -Scope It
        }

        It 're-inspects desired state when 0x800700B7 materialises the switch concurrently' {
            $testConfig = @{ Prefix='KCSP-LAB'; HostAddress='192.168.250.1'; PrefixLength=24; Subnet='192.168.250.0/24'; EnableNat=$true }
            $global:KCSPTestConcurrentSwitch = $false
            Mock Get-VMSwitch {
                if ($global:KCSPTestConcurrentSwitch) { return [pscustomobject]@{ Name='KCSP-LAB'; SwitchType='Internal' } }
                return $null
            } -ModuleName KCSPLab
            Mock Get-NetAdapter {
                if ($global:KCSPTestConcurrentSwitch) { return @([pscustomobject]@{ Name='vEthernet (KCSP-LAB)'; InterfaceDescription='Hyper-V Virtual Ethernet Adapter'; InterfaceGuid=[guid]::NewGuid(); ifIndex=250 }) }
                return @()
            } -ModuleName KCSPLab
            Mock Get-NetIPAddress { @([pscustomobject]@{ InterfaceIndex=250; IPAddress='192.168.250.1'; PrefixLength=24 }) } -ModuleName KCSPLab
            Mock Get-NetNat { @([pscustomobject]@{ Name='KCSP-LAB-NAT'; InternalIPInterfaceAddressPrefix='192.168.250.0/24' }) } -ModuleName KCSPLab
            Mock New-VMSwitch {
                $global:KCSPTestConcurrentSwitch = $true
                throw '0x800700B7 Cannot create a file when that file already exists'
            } -ModuleName KCSPLab

            Ensure-KCSPLabNetwork -Config $testConfig -AdapterTimeoutSeconds 1 -PollMilliseconds 1 | Should Be 'KCSP-LAB'

            Assert-MockCalled New-VMSwitch -Times 1 -Exactly -ModuleName KCSPLab -Scope It
            Assert-MockCalled Write-KCSPLabLog -ParameterFilter { $Message -like 'CREATE internal switch*' } -Times 0 -ModuleName KCSPLab -Scope It
            Assert-MockCalled Write-KCSPLabLog -ParameterFilter { $Message -like 'REPAIRED switch*materialised*' } -Times 1 -ModuleName KCSPLab -Scope It
            Remove-Variable KCSPTestConcurrentSwitch -Scope Global -ErrorAction SilentlyContinue
        }
}
