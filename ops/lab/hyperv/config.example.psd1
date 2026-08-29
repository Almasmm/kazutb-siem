@{
    # Copy to .lab\config.psd1 (gitignored) to override anything below.
    # The defaults here are runnable as-is on a clean clone.

    # Every lab resource is named with this prefix. Destructive operations
    # refuse to touch anything that does not carry it.
    Prefix = 'KCSP-LAB'

    # On-disk layout. Deliberately outside the repository: VHDX and ISO content
    # must never be committed.
    LabRoot = 'C:\Hyper-V\KCSP-LAB'

    # Isolated lab network. Guests reach the KCSP API through HostAddress only;
    # this subnet is not the university LAN.
    Subnet             = '192.168.250.0/24'
    HostAddress        = '192.168.250.1'
    PrefixLength       = 24
    GuestAddressPrefix = '192.168.250.'
    GuestDnsServers     = @('1.1.1.1', '8.8.8.8')
    # NAT gives guests outbound internet (Windows Update, Sysmon download).
    EnableNat = $true

    # KCSP API on the host, and the lab-facing ingress port.
    ApiPort     = 8080
    IngressPort = 18080

    # Lab tenant, kept separate from the university pilot tenant so lab events
    # never mix with real pilot telemetry.
    TenantId = 'kcsp-lab'
    Profile = 'development'

    # Guest VM sizing.
    VMGeneration   = 2
    VMProcessorCount = 2
    VMMemoryStartupBytes = 4GB
    VMMemoryMinimumBytes = 2GB
    VMMemoryMaximumBytes = 6GB
    VMDynamicMemory = $true
    VMDiskSizeBytes = 64GB

    # Local administrator created inside every guest. The password is generated
    # on first use and stored only in .lab\secrets (gitignored).
    AdminUser = 'kcspadmin'

    # Windows image. Placed here by the operator once; everything after is
    # automatic. WindowsEdition matches an image name inside install.wim.
    IsoPath        = ''
    WindowsEdition = 'Windows 11 Enterprise Evaluation'

    # Guest locale/timezone.
    Locale   = 'en-US'
    TimeZone = 'Central Asia Standard Time'

    # Sysmon. When SysmonUrl is set and NAT is on, the guest downloads it;
    # otherwise drop Sysmon64.exe in <LabRoot>\Artifacts.
    SysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'

    # Default endpoint count for Bootstrap. Extended runs pass -Count 4.
    DefaultCount = 1

    # Checkpoint names created during provisioning.
    Checkpoints = @('CLEAN_WINDOWS', 'SYSMON_INSTALLED', 'KCSP_AGENT_INSTALLED')
    # Keep at most this many ad-hoc checkpoints per VM beyond the named ones.
    MaxAdHocCheckpoints = 3
}
