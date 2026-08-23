#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $SubscriptionId = 'KCSP-Baseline',
    [string] $SubscriptionTemplate = (Join-Path $PSScriptRoot 'wef-kcsp-subscription.xml'),
    [ValidateSet('http', 'https')] [string] $Transport = 'http',
    [string] $CollectorFqdn = ([Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName),
    [ValidateRange(10, 86400)] [int] $RefreshSeconds = 60,
    [ValidateRange(1, 5000)] [int] $MaximumItems = 50,
    [ValidateRange(1000, 3600000)] [int] $MaximumLatencyMilliseconds = 30000,
    [ValidateRange(1000, 3600000)] [int] $HeartbeatMilliseconds = 60000,
    [ValidateRange(67108864, 68719476736)] [Int64] $ForwardedEventsMaximumBytes = 4294967296,
    [string] $AllowedSourceDomainComputers = 'O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)',
    [switch] $ReadExistingEvents,
    [switch] $ReplaceExisting,
    [bool] $ConfigureKCSPAgent = $true,
    [string] $StateDirectory = (Join-Path $env:ProgramData 'KCSP\wef')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'KCSP WEF collector configuration requires an elevated Administrator session.'
    }
}

function Invoke-Native {
    param([Parameter(Mandatory = $true)] [string] $FilePath, [Parameter(Mandatory = $true)] [string[]] $Arguments)
    $output = & $FilePath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed: $($output -join ' ')"
    }
    return @($output)
}

function Set-PrivateDirectoryAcl {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', $inheritance, $propagation, $allow)
        [void] $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-KCSPAgentForwardedEventsChannel {
    $serviceName = 'KCSPAgent'
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        return $false
    }
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    $environment = @((Get-ItemProperty -Path $registryPath -Name Environment -ErrorAction Stop).Environment)
    $channelPrefix = 'KCSP_AGENT_WINDOWS_CHANNELS='
    $channelSetting = $environment | Where-Object { $_ -like "$channelPrefix*" } | Select-Object -First 1
    $channels = New-Object Collections.Generic.List[string]
    if ($channelSetting) {
        foreach ($channel in $channelSetting.Substring($channelPrefix.Length).Split(';')) {
            if (-not [string]::IsNullOrWhiteSpace($channel) -and -not $channels.Contains($channel.Trim())) {
                $channels.Add($channel.Trim())
            }
        }
    }
    else {
        foreach ($channel in @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Windows Defender/Operational')) {
            $channels.Add($channel)
        }
    }
    if (-not $channels.Contains('ForwardedEvents')) {
        $channels.Add('ForwardedEvents')
    }
    $replacement = "$channelPrefix$($channels -join ';')"
    $updated = @($environment | Where-Object { $_ -notlike "$channelPrefix*" }) + $replacement
    New-ItemProperty -Path $registryPath -Name Environment -PropertyType MultiString -Value $updated -Force | Out-Null
    if ($service.Status -eq 'Running') {
        Restart-Service -Name $serviceName -Force
        (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    return $true
}

Assert-Administrator
if ($SubscriptionId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$') {
    throw 'SubscriptionId is invalid.'
}
if ($CollectorFqdn -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{1,253}$' -or $CollectorFqdn.Contains('..')) {
    throw 'CollectorFqdn is invalid.'
}
if (-not (Test-Path -LiteralPath $SubscriptionTemplate -PathType Leaf)) {
    throw "WEF subscription template not found: $SubscriptionTemplate"
}
try {
    [void] (ConvertFrom-SddlString -Sddl $AllowedSourceDomainComputers)
}
catch {
    throw "AllowedSourceDomainComputers is not valid SDDL: $($_.Exception.Message)"
}
if ($Transport -eq 'https') {
    $listeners = Invoke-Native -FilePath 'winrm.exe' -Arguments @('enumerate', 'winrm/config/listener')
    if (-not ($listeners -match 'Transport\s*=\s*HTTPS')) {
        throw 'HTTPS transport requires a preconfigured WinRM HTTPS listener and trusted machine certificate.'
    }
}

if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Configure WEF subscription $SubscriptionId")) {
    return
}
New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
Set-PrivateDirectoryAcl -Path $StateDirectory
[xml] $subscription = Get-Content -LiteralPath $SubscriptionTemplate -Raw
$namespace = New-Object Xml.XmlNamespaceManager($subscription.NameTable)
$namespace.AddNamespace('s', 'http://schemas.microsoft.com/2006/03/windows/events/subscription')
$values = @{
    'SubscriptionId' = $SubscriptionId
    'TransportName' = $Transport
    'ReadExistingEvents' = $(if ($ReadExistingEvents) { 'true' } else { 'false' })
    'AllowedSourceDomainComputers' = $AllowedSourceDomainComputers
}
foreach ($name in $values.Keys) {
    $node = $subscription.SelectSingleNode("/s:Subscription/s:$name", $namespace)
    if (-not $node) { throw "Subscription template is missing $name." }
    $node.InnerText = [string] $values[$name]
}
$subscription.SelectSingleNode('/s:Subscription/s:Delivery/s:Batching/s:MaxItems', $namespace).InnerText = [string] $MaximumItems
$subscription.SelectSingleNode('/s:Subscription/s:Delivery/s:Batching/s:MaxLatencyTime', $namespace).InnerText = [string] $MaximumLatencyMilliseconds
$subscription.SelectSingleNode('/s:Subscription/s:Delivery/s:PushSettings/s:Heartbeat', $namespace).SetAttribute('Interval', [string] $HeartbeatMilliseconds)
$subscriptionPath = Join-Path $StateDirectory "$SubscriptionId.xml"
$settings = New-Object Xml.XmlWriterSettings
$settings.Encoding = New-Object Text.UTF8Encoding($false)
$settings.Indent = $true
$writer = [Xml.XmlWriter]::Create($subscriptionPath, $settings)
try { $subscription.Save($writer) } finally { $writer.Dispose() }

[void] (Invoke-Native -FilePath 'wecutil.exe' -Arguments @('qc', '/q'))
[void] (Invoke-Native -FilePath 'wevtutil.exe' -Arguments @('sl', 'ForwardedEvents', '/e:true', "/ms:$ForwardedEventsMaximumBytes", '/rt:false'))
& wecutil.exe gs $SubscriptionId *> $null
$exists = $LASTEXITCODE -eq 0
if ($exists -and -not $ReplaceExisting) {
    throw "WEF subscription $SubscriptionId already exists; use ReplaceExisting to replace it explicitly."
}
if ($exists) {
    [void] (Invoke-Native -FilePath 'wecutil.exe' -Arguments @('ds', $SubscriptionId))
}
[void] (Invoke-Native -FilePath 'wecutil.exe' -Arguments @('cs', $subscriptionPath))
$agentConfigured = $false
if ($ConfigureKCSPAgent) {
    $agentConfigured = Set-KCSPAgentForwardedEventsChannel
}
$port = if ($Transport -eq 'https') { 5986 } else { 5985 }
$subscriptionManager = "Server=$Transport`://$CollectorFqdn`:$port/wsman/SubscriptionManager/WEC,Refresh=$RefreshSeconds"
[pscustomobject]@{
    schema = 'kcsp.wef.collector/v1'
    subscription_id = $SubscriptionId
    transport = $Transport
    subscription_manager_gpo_value = $subscriptionManager
    allowed_source_sddl = $AllowedSourceDomainComputers
    forwarded_events_maximum_bytes = $ForwardedEventsMaximumBytes
    kcsp_agent_configured = $agentConfigured
    source_gpo_requirements = @('WinRM service: Automatic', 'Event Log Readers: NETWORK SERVICE', 'Event Forwarding/SubscriptionManager: value above')
}
