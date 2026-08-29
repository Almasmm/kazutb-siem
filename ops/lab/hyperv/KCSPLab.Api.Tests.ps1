#requires -Version 5.1

$modulePath = Join-Path $PSScriptRoot 'KCSPLab.psm1'
Import-Module $modulePath -Force
Set-StrictMode -Version Latest

function New-TestLabApiConfig {
    param([string] $Root = 'C:\test-kcsp-lab', [string] $Profile = 'development')
    @{
        TenantId='kcsp-lab'; Profile=$Profile; ApiPort=8080; HostAddress='192.168.250.1'; IngressPort=18080
        Prefix='KCSP-LAB'; SecretsRoot=(Join-Path $Root 'secrets'); ApiCredentialPath=(Join-Path $Root 'secrets\lab-api-credential.json')
    }
}

function Get-TestLabPermissions {
    @(
        'platform.session.read','platform.overview.read','platform.collectors.read','platform.collectors.manage','platform.audit.read',
        'siem.events.read','siem.findings.read','siem.hunt.read','siem.hunt.execute','detection.rules.read','siem.rules.read',
        'soc.alerts.read','soc.alerts.manage','soc.incidents.read','soc.incidents.create','soc.incidents.manage',
        'soc.cases.read','soc.cases.manage','soc.evidence.read'
    )
}

Describe 'KCSP lab API authentication' {
    BeforeEach {
        $global:KCSPTestLabPermissions = Get-TestLabPermissions
        Mock Get-KCSPLabTenantCredential { [pscustomobject]@{ AccessToken='kcsp_lab_test_token_value_that_is_long_enough_123456'; Principal='svc-kcsp-lab-admin' } } -ModuleName KCSPLab
    }
    AfterEach { Remove-Variable KCSPTestLabPermissions -Scope Global -ErrorAction SilentlyContinue }

    It 'turns a transport or HTTP error into one controlled lab API failure' {
        Mock Invoke-RestMethod { throw [InvalidOperationException]::new('simulated request failure') } -ModuleName KCSPLab
        $message = $null
        try { Invoke-KCSPLabApi -Config (New-TestLabApiConfig) -Path '/api/v1/collectors' | Out-Null } catch { $message=$_.Exception.Message }
        $message | Should Match '^KCSP_LAB_API_ERROR status=0 code=request_failed'
        $message | Should Not Match 'PropertyNotFound'
    }

    It 'applies the lab bearer and tenant header centrally' {
        $global:KCSPCapturedHeaders = $null
        Mock Invoke-RestMethod { param($Headers) $global:KCSPCapturedHeaders=$Headers; [pscustomobject]@{ items=@(); total=0 } } -ModuleName KCSPLab
        Invoke-KCSPLabApi -Config (New-TestLabApiConfig) -Path '/api/v1/collectors' | Out-Null
        $global:KCSPCapturedHeaders.Authorization | Should Be 'Bearer kcsp_lab_test_token_value_that_is_long_enough_123456'
        $global:KCSPCapturedHeaders['X-KCSP-Tenant-ID'] | Should Be 'kcsp-lab'
        Remove-Variable KCSPCapturedHeaders -Scope Global -ErrorAction SilentlyContinue
    }

    It 'does not cascade into token property access after an API error' {
        Mock Invoke-KCSPLabApi { throw 'KCSP_LAB_API_ERROR status=401 code=authentication_required' } -ModuleName KCSPLab
        $message=$null
        try { New-KCSPLabEnrollmentToken -Config (New-TestLabApiConfig) -Label 'KCSP-LAB-WIN-01' | Out-Null } catch { $message=$_.Exception.Message }
        $message | Should Match 'status=401'
        $message | Should Not Match 'property.*token'
    }

    It 'fails with an explicit contract error when enrollment token is missing' {
        Mock Invoke-KCSPLabApi { [pscustomobject]@{ token=[pscustomobject]@{ token_id='enr_test'; expires_at=(Get-Date).ToUniversalTime().AddHours(1).ToString('o'); max_uses=1 } } } -ModuleName KCSPLab
        { New-KCSPLabEnrollmentToken -Config (New-TestLabApiConfig) -Label 'KCSP-LAB-WIN-01' } | Should Throw 'ENROLLMENT_TOKEN_CONTRACT_INVALID: required enrollment_token/token_id/expires_at/max_uses fields are missing.'
    }

    It 'accepts the complete one-time enrollment response contract' {
        Mock Invoke-KCSPLabApi { [pscustomobject]@{ enrollment_token='kcsp_enroll_test.secret'; token=[pscustomobject]@{ token_id='enr_test'; expires_at=(Get-Date).ToUniversalTime().AddHours(1).ToString('o'); max_uses=1 } } } -ModuleName KCSPLab
        $issued=New-KCSPLabEnrollmentToken -Config (New-TestLabApiConfig) -Label 'KCSP-LAB-WIN-01'
        $issued.token.token_id | Should Be 'enr_test'
    }

    It 'rejects a reusable or non-finite enrollment token contract' {
        Mock Invoke-KCSPLabApi { [pscustomobject]@{ enrollment_token='kcsp_enroll_test.secret'; token=[pscustomobject]@{ token_id='enr_test'; expires_at=(Get-Date).ToUniversalTime().AddHours(1).ToString('o'); max_uses=2 } } } -ModuleName KCSPLab
        { New-KCSPLabEnrollmentToken -Config (New-TestLabApiConfig) -Label 'KCSP-LAB-WIN-01' } | Should Throw 'ENROLLMENT_TOKEN_CONTRACT_INVALID: token must be one-use and expire within the requested finite TTL.'
    }

    It 'rejects an expired enrollment token contract' {
        Mock Invoke-KCSPLabApi { [pscustomobject]@{ enrollment_token='kcsp_enroll_test.secret'; token=[pscustomobject]@{ token_id='enr_test'; expires_at=(Get-Date).ToUniversalTime().AddMinutes(-1).ToString('o'); max_uses=1 } } } -ModuleName KCSPLab
        { New-KCSPLabEnrollmentToken -Config (New-TestLabApiConfig) -Label 'KCSP-LAB-WIN-01' } | Should Throw 'ENROLLMENT_TOKEN_CONTRACT_INVALID: token must be one-use and expire within the requested finite TTL.'
    }

    It 'uses a stable registered platform endpoint and verifies the complete authorization matrix' {
        Mock Invoke-KCSPLabApi {
            param($Config,$Path,$Method,$Body,$TenantId,$Bearer,$NoBearer)
            if ($Path -eq '/api/v1/session') {
                return [pscustomobject]@{
                    principal=[pscustomobject]@{ id='svc-kcsp-lab-admin'; role='Lab Automation' }
                    tenant=[pscustomobject]@{ id='kcsp-lab'; name='KCSP Hyper-V Lab' }
                    permissions=$global:KCSPTestLabPermissions
                }
            }
            if ($NoBearer -or $Bearer -eq 'invalid-lab-credential-value') { throw 'KCSP_LAB_API_ERROR status=401 code=authentication_required' }
            if ($TenantId -eq 'university-kulazhanov') { throw 'KCSP_LAB_API_ERROR status=403 code=tenant_denied' }
            if ($Path -eq '/api/v1/admin/tenants?limit=1') { throw 'KCSP_LAB_API_ERROR status=403 code=permission_denied' }
            if ($Path -eq '/api/v1/agent-enrollment/tokens' -and $Method -eq 'POST') {
                return [pscustomobject]@{ enrollment_token='kcsp_enroll_test.secret'; token=[pscustomobject]@{ token_id='enr_probe'; expires_at=(Get-Date).ToUniversalTime().AddHours(1).ToString('o'); max_uses=1 } }
            }
            return [pscustomobject]@{ status='ok'; items=@(); total=0 }
        } -ModuleName KCSPLab

        $result=Test-KCSPLabApiAuthorization -Config (New-TestLabApiConfig)
        $result.PlatformPrivileged | Should Be 403
        $result.Role | Should Be 'Lab Automation'
        $result.Enrollment | Should Be 'created+revoked'
        Assert-MockCalled Invoke-KCSPLabApi -Times 1 -Exactly -ModuleName KCSPLab -ParameterFilter {
            $Path -eq '/api/v1/admin/tenants?limit=1' -and $Method -eq 'GET'
        }
    }

    It 'does not accept a 404 from an unregistered endpoint as platform denial' {
        Mock Invoke-KCSPLabApi {
            param($Config,$Path,$Method,$Body,$TenantId,$Bearer,$NoBearer)
            if ($Path -eq '/api/v1/session') {
                return [pscustomobject]@{
                    principal=[pscustomobject]@{ id='svc-kcsp-lab-admin'; role='Lab Automation' }
                    tenant=[pscustomobject]@{ id='kcsp-lab'; name='KCSP Hyper-V Lab' }
                    permissions=$global:KCSPTestLabPermissions
                }
            }
            if ($NoBearer -or $Bearer -eq 'invalid-lab-credential-value') { throw 'KCSP_LAB_API_ERROR status=401 code=authentication_required' }
            if ($TenantId -eq 'university-kulazhanov') { throw 'KCSP_LAB_API_ERROR status=403 code=tenant_denied' }
            if ($Path -eq '/api/v1/admin/tenants?limit=1') { throw 'KCSP_LAB_API_ERROR status=404 code=request_failed' }
            return [pscustomobject]@{ status='ok'; items=@(); total=0 }
        } -ModuleName KCSPLab
        { Test-KCSPLabApiAuthorization -Config (New-TestLabApiConfig) } | Should Throw 'LAB_AUTH_ISOLATION_FAILED: platform-privileged did not return 403 permission_denied.'
    }
}

Describe 'KCSP lab credential lifecycle' {
    BeforeEach { Mock Protect-KCSPLabFile {} -ModuleName KCSPLab }

    It 'reuses one generated credential and applies ACL protection across bootstrap runs' {
        $root=Join-Path ([IO.Path]::GetTempPath()) ("kcsp-lab-api-test-"+[guid]::NewGuid().ToString('N'))
        $config=New-TestLabApiConfig -Root $root
        try {
            $first=Ensure-KCSPLabTenantCredential -Config $config
            $second=Ensure-KCSPLabTenantCredential -Config $config
            $first.AccessToken | Should Be $second.AccessToken
            $first.AccessToken | Should Match '^kcsp_lab_[A-Za-z0-9_-]{40,}$'
            Test-Path -LiteralPath $config.ApiCredentialPath | Should Be $true
            Assert-MockCalled Protect-KCSPLabFile -Times 2 -Exactly -ModuleName KCSPLab -Scope It
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'prohibits credential bootstrap in production' {
        { Ensure-KCSPLabTenantCredential -Config (New-TestLabApiConfig -Profile 'production') } | Should Throw
    }

    It 'rotates the secret without changing tenant or principal metadata' {
        $root=Join-Path ([IO.Path]::GetTempPath()) ("kcsp-lab-api-rotate-test-"+[guid]::NewGuid().ToString('N'))
        $config=New-TestLabApiConfig -Root $root
        try {
            $first=Ensure-KCSPLabTenantCredential -Config $config
            $second=Ensure-KCSPLabTenantCredential -Config $config -Rotate
            $second.AccessToken | Should Not Be $first.AccessToken
            $second.TenantId | Should Be 'kcsp-lab'
            $second.Principal | Should Be 'svc-kcsp-lab-admin'
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'KCSP guest ingress contract' {
    It 'fails closed when guest TCP or health readiness is false' {
        Mock Assert-KCSPLabTenant {} -ModuleName KCSPLab
        Mock Invoke-KCSPLabGuest { [pscustomobject]@{ Tcp=$false; Health=$null } } -ModuleName KCSPLab
        { Test-KCSPLabGuestIngress -Config (New-TestLabApiConfig) -VMName 'KCSP-LAB-WIN-01' -Credential ([pscredential]::Empty) } | Should Throw
    }

    It 'passes only when guest TCP and health endpoint are ready' {
        Mock Invoke-KCSPLabGuest { [pscustomobject]@{ Tcp=$true; Health='ready' } } -ModuleName KCSPLab
        Mock Write-KCSPLabLog {} -ModuleName KCSPLab
        (Test-KCSPLabGuestIngress -Config (New-TestLabApiConfig) -VMName 'KCSP-LAB-WIN-01' -Credential ([pscredential]::Empty)).Health | Should Be 'ready'
    }
}
