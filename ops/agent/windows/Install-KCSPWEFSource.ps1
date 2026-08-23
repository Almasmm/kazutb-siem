#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)] [string] $CollectorFqdn,
    [ValidateSet('http', 'https')] [string] $Transport = 'http',
    [ValidateRange(10, 86400)] [int] $RefreshSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'KCSP WEF source configuration requires an elevated Administrator session.'
}
if ($CollectorFqdn -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{1,253}$' -or $CollectorFqdn.Contains('..')) {
    throw 'CollectorFqdn is invalid.'
}
$port = if ($Transport -eq 'https') { 5986 } else { 5985 }
$manager = "Server=$Transport`://$CollectorFqdn`:$port/wsman/SubscriptionManager/WEC,Refresh=$RefreshSeconds"
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Configure WEF source for $CollectorFqdn")) {
    return
}
Set-Service -Name WinRM -StartupType Automatic
if ((Get-Service -Name WinRM).Status -ne 'Running') {
    Start-Service -Name WinRM
}
& winrm.exe quickconfig -quiet | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'winrm quickconfig failed.'
}
$eventLogReaders = Get-LocalGroup -SID 'S-1-5-32-573'
$networkService = New-Object Security.Principal.SecurityIdentifier('S-1-5-20')
$networkServiceAccount = $networkService.Translate([Security.Principal.NTAccount]).Value
if (-not (Get-LocalGroupMember -Group $eventLogReaders -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $networkService })) {
    Add-LocalGroupMember -Group $eventLogReaders -Member $networkServiceAccount
}
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
New-Item -Path $policyPath -Force | Out-Null
New-ItemProperty -Path $policyPath -Name '1' -PropertyType String -Value $manager -Force | Out-Null
Restart-Service -Name WinRM -Force
[pscustomobject]@{
    schema = 'kcsp.wef.source/v1'
    collector = $CollectorFqdn
    subscription_manager = $manager
    winrm_status = (Get-Service -Name WinRM).Status.ToString()
    event_log_reader = $networkServiceAccount
    deployment = 'Pilot/local policy; use the same settings in domain GPO for fleet rollout.'
}
