<#
    Offline checks for the 1.2.0 hardening: the neutral staging OU, Kerberos armoring and silo
    enforcement, two-way silo reconciliation, and the attack path checks of the audit. Active
    Directory and Group Policy are mocked; what is under test is the decision logic.
#>

$ErrorActionPreference = 'Stop'
$script:Failures = 0

# Runs a script in a child PowerShell and returns its exit code. Windows PowerShell 5.1 turns
# anything the child writes to stderr into a terminating error once ErrorActionPreference is
# 'Stop', so the preference is relaxed for the call; the exit code is what is being tested.
function Invoke-ChildScript {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass @Arguments *> $null }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

function Assert-That {
    param([string]$What, [bool]$Condition, [string]$Detail)
    if ($Condition) { Write-Host "  PASS  $What" -ForegroundColor Green }
    else { Write-Host "  FAIL  $What $Detail" -ForegroundColor Red; $script:Failures++ }
}

$source = Get-Content -Raw $PSScriptRoot/../ADTierKit.ps1
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($f in $functions) { . ([scriptblock]::Create($f.Extent.Text)) }

# Every directory command fails loudly unless a mock below replaces it - see TestIsolation.ps1.
. (Join-Path $PSScriptRoot 'TestIsolation.ps1')

# --- state ---------------------------------------------------------------------------------------
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$script:PrincipalCache = @{}
$domainDn = 'DC=lab,DC=example,DC=com'
$domainSid = 'S-1-5-21-1-2-3'
$script:TierContext = [pscustomobject]@{
    DomainDn            = $domainDn
    DomainFqdn          = 'lab.example.com'
    DomainSid           = $domainSid
    RootOuDn            = "OU=Tiering,$domainDn"
    StagingOuDn         = "OU=Staging,OU=Tiering,$domainDn"
    DomainControllersDn = "OU=Domain Controllers,$domainDn"
    AdminSdHolderDn     = "CN=AdminSDHolder,CN=System,$domainDn"
    PoliciesDn          = "CN=Policies,CN=System,$domainDn"
    Server              = 'dc01'
    TierNames           = @('Tier-0', 'Tier-1', 'Tier-2')
}
function Get-TierContext { return $script:TierContext }
function Get-TierAdParameter { @{ Server = 'dc01' } }
function Write-TierLog { param($Message, $Level) }
function Reset-Actions { $script:TierActions.Clear() }
function Get-Actions { param($ObjectType) @($script:TierActions | Where-Object { $_.ObjectType -eq $ObjectType }) }

function Get-ShippedConfiguration {
    $c = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
    $c = Expand-TierRoleDefinition -Configuration $c
    return (Expand-TierStagingDefinition -Configuration $c)
}

# =================================================================================================
Write-Host "`nNeutral staging OU"
# =================================================================================================

$config = Get-ShippedConfiguration
$top = $config.tiers[0]

$deny = $top.groups | Where-Object { $_.name -eq 'DL-Staging-DenyLogon' }
$join = $top.groups | Where-Object { $_.name -eq 'DL-Staging-Join' }
$roleGroups = @($config.tiers | ForEach-Object { $_.groups } | Where-Object scope -eq 'Global' | ForEach-Object name)
Assert-That 'staging deny group generated in the top tier group OU' ($deny -and $deny.targetOu -eq 'Tier-0/Groups')
Assert-That 'deny group holds every role group of every tier' (@($roleGroups | Where-Object { @($deny.members) -notcontains $_ }).Count -eq 0) "missing: $(@($roleGroups | Where-Object { @($deny.members) -notcontains $_ }) -join ', ')"
Assert-That 'generated role groups are covered too' (@($deny.members) -contains 'G-T1-GPO-Admins' -and @($deny.members) -contains 'G-T0-DNS-Admins')
Assert-That 'join group generated' ($join -and $join.targetOu -eq 'Tier-0/Groups' -and -not $join.members)

$quarantine = $top.gpos | Where-Object { $_.name -eq 'Staging-Quarantine' }
Assert-That 'quarantine GPO targets the staging OU' ($quarantine -and $quarantine.targetOu -eq '$Staging')
Assert-That 'quarantine GPO denies interactive logon to the staging deny group' (@($quarantine.userRights.SeDenyInteractiveLogonRight) -contains 'DL-Staging-DenyLogon')
Assert-That 'quarantine GPO adds nobody to local Administrators' (-not $quarantine.restrictedGroups)

$stagingAces = @($top.delegations | Where-Object { $_.targetOu -eq '$Staging' })
Assert-That 'join group gets the domain join set only' (@($stagingAces | Where-Object principal -eq 'DL-Staging-Join').Count -eq 5)
Assert-That 'join group gets no unscoped right' (@($stagingAces | Where-Object { $_.principal -eq 'DL-Staging-Join' -and -not $_.objectType }).Count -eq 0)
Assert-That 'top tier admins manage the staging OU' (@($stagingAces | Where-Object principal -eq 'G-T0-Admins').Count -eq 2)
Assert-That 'no lower tier holds a right on the staging OU' (@($stagingAces | Where-Object { $_.principal -match 'T1|T2' }).Count -eq 0)
Assert-That 'staging LAPS policy readable by the top tier only' (@($config.windowsLaps.delegations | Where-Object { $_.targetOu -eq '$Staging' -and $_.readGroup -eq 'G-T0-Admins' -and $_.gpoName -eq 'Staging-LAPS' }).Count -eq 1)

$before = ($config | ConvertTo-Json -Depth 30)
$config = Expand-TierStagingDefinition -Configuration $config
Assert-That 'expansion is idempotent' (($config | ConvertTo-Json -Depth 30) -eq $before)

$off = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
$off.staging.enabled = $false
$off = Expand-TierStagingDefinition -Configuration $off
Assert-That 'disabled staging generates nothing' (@($off.tiers[0].groups | Where-Object name -like 'DL-Staging-*').Count -eq 0)

Assert-That '$Staging resolves below the model root' ((Resolve-TierOuDn -Reference '$Staging') -eq "OU=Staging,OU=Tiering,$domainDn")
$loaded = Import-TierConfiguration -Path $PSScriptRoot/../config/tiermodel.json
Assert-That 'shipped configuration loads without duplicate names' ($null -ne $loaded)

$gen = New-TierModelConfiguration
Assert-That 'generator enables the neutral staging OU' ($gen.staging.enabled -and $gen.options.redirectComputersTo -eq '$Staging')
Assert-That 'generator follows the naming pattern' ($gen.staging.denyLogonGroup -eq 'DL-Staging-DenyLogon' -and $gen.staging.gpoName -eq 'Staging-Quarantine')
$genOff = New-TierModelConfiguration -NeutralStaging $false
Assert-That 'without it new computers go to the workplace staging OU' ($genOff.options.redirectComputersTo -eq 'Tier-2/Staging')

# =================================================================================================
Write-Host "`nKerberos armoring"
# =================================================================================================

$settings = Get-TierArmoringSetting
$dcBaseline = $gen.tiers[0].gpos | Where-Object { $_.targetOu -eq '$DomainControllers' }
Assert-That 'generator: DC baseline enables KDC armoring' (@($dcBaseline.registrySettings | Where-Object { $_.key -eq $settings.Kdc.Key -and $_.valueName -eq 'EnableCbacAndArmor' -and $_.value -eq 1 }).Count -eq 1)
Assert-That 'generator: KDC level is Supported, not Fail' (@($dcBaseline.registrySettings | Where-Object { $_.valueName -eq 'CbacAndArmorLevel' }).value -eq 1)
Assert-That 'generator: every tier GPO enables client armoring' (@($gen.tiers | ForEach-Object { $_.gpos } | Where-Object { -not @($_.registrySettings | Where-Object { $_.key -eq $settings.Client.Key }) }).Count -eq 0)

$script:LiveValues = @{}
function Get-GPRegistryValue { param($Name, $Key, $ValueName, $Domain, $Server) $v = $script:LiveValues["$Name|$ValueName|$Key"]; if ($null -eq $v) { throw 'not found' }; [pscustomobject]@{ Value = $v } }

$problems = @(Test-TierKerberosArmoring -Configuration $config)
Assert-That 'configured but not deployed is reported' ($problems.Count -gt 0 -and ($problems -join ' ') -match 'not deployed')

foreach ($tier in $config.tiers) {
    foreach ($gpo in $tier.gpos) {
        foreach ($setting in @($gpo.registrySettings)) {
            if ($setting.valueName -eq 'EnableCbacAndArmor') { $script:LiveValues["$($gpo.name)|$($setting.valueName)|$($setting.key)"] = 1 }
        }
    }
}
$problems = @(Test-TierKerberosArmoring -Configuration $config)
Assert-That 'configured and deployed passes' ($problems.Count -eq 0) ($problems -join '; ')

$bare = Get-ShippedConfiguration
foreach ($gpo in $bare.tiers[0].gpos) { $gpo.registrySettings = @($gpo.registrySettings | Where-Object { $_.key -ne $settings.Kdc.Key }) }
$problems = @(Test-TierKerberosArmoring -Configuration $bare)
Assert-That 'missing KDC armoring is reported' (($problems -join ' ') -match 'KDC support')

# =================================================================================================
Write-Host "`nSilo enforcement and reconciliation"
# =================================================================================================

$siloDnBase = 'CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=example'
$script:Policy = $null
$script:Silo = $null
$script:SiloState = @{}
$script:Calls = [System.Collections.Generic.List[string]]::new()
$script:GroupMembers = @{}

function Reset-Silo {
    param([bool]$Enforced = $false)
    $script:Policy = [pscustomobject]@{ Name = 'Tier-0-AuthPolicy'; DistinguishedName = "CN=Tier-0-AuthPolicy,$siloDnBase"; Enforce = $Enforced; UserTGTLifetimeMins = 240 }
    $script:Silo = [pscustomobject]@{ Name = 'Tier-0-Silo'; DistinguishedName = "CN=Tier-0-Silo,$siloDnBase"; Enforce = $Enforced }
    $script:Calls.Clear()
    Reset-Actions
}

function Get-ADAuthenticationPolicy { $script:Policy }
function Get-ADAuthenticationPolicySilo { param($Filter) if ($Filter -match 'Tier-1') { [pscustomobject]@{ Name = 'Tier-1-Silo'; DistinguishedName = "CN=Tier-1-Silo,$siloDnBase"; Enforce = $false } } else { $script:Silo } }
function Set-ADAuthenticationPolicy { param($Identity, $Enforce, $UserTGTLifetimeMins, $Server) $script:Calls.Add("policy Enforce=$Enforce") }
function Set-ADAuthenticationPolicySilo { param($Identity, $Enforce, $Server) $script:Calls.Add("silo Enforce=$Enforce") }
function Get-ADGroup { param($LDAPFilter) if ($LDAPFilter -match 'sAMAccountName=([^)]+)') { [pscustomobject]@{ DistinguishedName = "CN=$($Matches[1])" } } }
function Get-ADGroupMember { param($Identity) @($script:GroupMembers[$Identity] | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ objectClass = 'user'; distinguishedName = $_ } }) }
function Get-ADUser { param($Identity) [pscustomobject]@{ DistinguishedName = $Identity; SamAccountName = (($Identity -split ',')[0] -replace '^CN=') } }
function Get-ADComputer { }
function Get-ADObject {
    param($Identity, $LDAPFilter, $Properties)
    if ($LDAPFilter -match 'msDS-AssignedAuthNPolicySilo=CN=([^,\\]+)') {
        $name = $Matches[1]
        return @($script:SiloState.Keys | Where-Object { $script:SiloState[$_] -like "CN=$name,*" } |
                ForEach-Object { [pscustomobject]@{ DistinguishedName = $_; sAMAccountName = (($_ -split ',')[0] -replace '^CN=') } })
    }
    [pscustomobject]@{ 'msDS-AssignedAuthNPolicySilo' = $script:SiloState[$Identity] }
}
function Grant-ADAuthenticationPolicySiloAccess { }
function Revoke-ADAuthenticationPolicySiloAccess { }
function Set-ADAccountAuthenticationPolicySilo { param($Identity, $AuthenticationPolicySilo) $script:Calls.Add("assign $Identity"); $script:SiloState[$Identity] = "CN=$AuthenticationPolicySilo,$siloDnBase" }
function Set-ADObject { param($Identity, $Clear) $script:Calls.Add("clear $Identity"); $script:SiloState.Remove($Identity) }

$adminDn = "CN=adm-t0-alice,OU=Accounts,OU=Tier-0,OU=Tiering,$domainDn"
$leaverDn = "CN=adm-t0-bob,OU=Accounts,OU=Tier-0,OU=Tiering,$domainDn"
$script:GroupMembers['CN=G-T0-Admins'] = @($adminDn)

$siloConfig = Get-ShippedConfiguration
$siloConfig.authenticationPolicySilos = @($siloConfig.authenticationPolicySilos[0])
$siloConfig.options.authenticationPolicyEnforcement = 'Enforce'

# Enforcement requested, armoring not deployed: withheld.
function Test-TierKerberosArmoring { @('no GPO reaching the Domain Controllers OU enables KDC support') }
Reset-Silo
New-TierAuthenticationSilo -Configuration $siloConfig -Confirm:$false
Assert-That 'enforcement is withheld without armoring' (@($script:Calls | Where-Object { $_ -match 'Enforce=True' }).Count -eq 0)
Assert-That 'the withheld enforcement is a High failure' (@(Get-Actions 'KerberosArmoring' | Where-Object { $_.Result -eq 'Failed' -and $_.Severity -eq 'High' }).Count -eq 1)
Assert-That 'withholding does not downgrade anything' (@($script:Calls | Where-Object { $_ -match 'Enforce=False' }).Count -eq 0)
Assert-That 'members are still assigned' ($script:Calls -contains "assign $adminDn")

Reset-Silo
New-TierAuthenticationSilo -Configuration $siloConfig -Force -Confirm:$false
Assert-That '-Force enforces anyway' ($script:Calls -contains 'policy Enforce=True' -and $script:Calls -contains 'silo Enforce=True')

# Armoring in place: an existing audit-mode silo is switched to enforce.
function Test-TierKerberosArmoring { @() }
Reset-Silo
New-TierAuthenticationSilo -Configuration $siloConfig -AuditOnly -Confirm:$false
Assert-That 'audit reports the enforcement drift' (@(Get-Actions 'AuthenticationPolicy' | Where-Object Result -eq 'Drift').Count -eq 1 -and @(Get-Actions 'AuthenticationPolicySilo' | Where-Object Result -eq 'Drift').Count -eq 1)
Assert-That 'audit changes nothing' ($script:Calls.Count -eq 0)

Reset-Silo
New-TierAuthenticationSilo -Configuration $siloConfig -Confirm:$false
Assert-That 'an existing policy is switched to enforce' ($script:Calls -contains 'policy Enforce=True')
Assert-That 'an existing silo is switched to enforce' ($script:Calls -contains 'silo Enforce=True')

Reset-Silo -Enforced $true
$siloConfig.options.authenticationPolicyEnforcement = 'Audit'
New-TierAuthenticationSilo -Configuration $siloConfig -Confirm:$false
Assert-That 'configuration back to Audit converges back' ($script:Calls -contains 'policy Enforce=False' -and $script:Calls -contains 'silo Enforce=False')

# Reconciliation: bob was a Tier 0 admin and has left the group.
$script:SiloState[$leaverDn] = "CN=Tier-0-Silo,$siloDnBase"
Reset-Silo
New-TierAuthenticationSilo -Configuration $siloConfig -Confirm:$false
$stale = @(Get-Actions 'SiloReconcile')
Assert-That 'a member that left is reported' ($stale.Count -eq 1 -and $stale[0].Target -eq 'adm-t0-bob' -and $stale[0].Result -eq 'Drift')
Assert-That 'report mode removes nothing' ($script:Calls -notcontains "clear $leaverDn")

$siloConfig.options.authenticationPolicySiloReconcile = 'Enforce'
Reset-Silo
New-TierAuthenticationSilo -Configuration $siloConfig -Confirm:$false
Assert-That 'enforce mode removes it' ($script:Calls -contains "clear $leaverDn")
Assert-That 'current members are left alone' ($script:Calls -notcontains "clear $adminDn")

# Conflict: alice is in both the Tier 0 and the Tier 1 role group.
$conflictConfig = Get-ShippedConfiguration
$script:GroupMembers['CN=G-T1-Admins'] = @($adminDn)
$script:SiloState.Clear()
Reset-Silo
New-TierAuthenticationSilo -Configuration $conflictConfig -Confirm:$false
Assert-That 'an account in two silos is a conflict' (@(Get-Actions 'SiloConflict' | Where-Object { $_.Target -eq $adminDn -and $_.Severity -eq 'High' }).Count -eq 1)
Assert-That 'a conflicting account is not assigned anywhere' ($script:Calls -notcontains "assign $adminDn")
$script:GroupMembers.Remove('CN=G-T1-Admins')

# =================================================================================================
Write-Host "`nAttack path rules"
# =================================================================================================

$memberGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
$certGuid = 'bf967a7f-0de6-11d0-a285-00aa003049e2'        # userCertificate
$dcsyncGuid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$applyGpoGuid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'

Assert-That 'GenericAll is dangerous' ((Get-TierAceRisk -Rights 0xF01FF -ObjectType $null) -eq 'GenericAll')
Assert-That 'WriteDacl is dangerous' ((Get-TierAceRisk -Rights 0x40000 -ObjectType $null) -eq 'WriteDacl')
Assert-That 'GenericWrite is dangerous' ((Get-TierAceRisk -Rights 0x20028 -ObjectType $null) -eq 'GenericWrite')
Assert-That 'write to all properties is dangerous' ((Get-TierAceRisk -Rights 0x20 -ObjectType $null) -match 'all properties')
Assert-That 'write to member is dangerous' ((Get-TierAceRisk -Rights 0x20 -ObjectType $memberGuid) -match 'member')
Assert-That 'write to userCertificate is not' ($null -eq (Get-TierAceRisk -Rights 0x20 -ObjectType $certGuid))
Assert-That 'DCSync right is dangerous' ((Get-TierAceRisk -Rights 0x100 -ObjectType $dcsyncGuid) -match 'DCSync')
Assert-That 'Apply Group Policy is not' ($null -eq (Get-TierAceRisk -Rights 0x100 -ObjectType $applyGpoGuid))
Assert-That 'generic read is not' ($null -eq (Get-TierAceRisk -Rights 0x20094 -ObjectType $null))
Assert-That 'a deny entry is not' ($null -eq (Get-TierAceRisk -Rights 0xF01FF -ObjectType $null -AccessControlType 'Deny'))

# =================================================================================================
Write-Host "`nAttack path audit"
# =================================================================================================

class FakeAce {
    [object]$IdentityReference; [long]$ActiveDirectoryRights; [string]$AccessControlType; [guid]$ObjectType; [bool]$IsInherited
    FakeAce([string]$sid, [long]$rights, [string]$objectType, [bool]$inherited) {
        $this.IdentityReference = [pscustomobject]@{ Value = $sid }
        $this.ActiveDirectoryRights = $rights
        $this.AccessControlType = 'Allow'
        $this.ObjectType = if ($objectType) { [guid]$objectType } else { [guid]::Empty }
        $this.IsInherited = $inherited
    }
}
class FakeSd {
    [string]$Owner; [object[]]$Aces
    FakeSd([string]$owner, [object[]]$aces) { $this.Owner = $owner; $this.Aces = $aces }
    [object] GetOwner([type]$t) { return [pscustomobject]@{ Value = $this.Owner } }
    [object[]] GetAccessRules([bool]$explicit, [bool]$inherited, [type]$t) {
        return @($this.Aces | Where-Object { ($explicit -and -not $_.IsInherited) -or ($inherited -and $_.IsInherited) })
    }
}
function New-FakeObject { param($Dn, $Owner, [object[]]$Aces = @()) [pscustomobject]@{ DistinguishedName = $Dn; nTSecurityDescriptor = [FakeSd]::new($Owner, $Aces) } }

$da = "$domainSid-512"; $dcs = "$domainSid-516"
$exchange = "$domainSid-1500"; $helpdesk = "$domainSid-1600"; $t1Admins = "$domainSid-1101"; $t0Admins = "$domainSid-1001"
$foreignEa = 'S-1-5-21-9-9-9-519'
$tier0Dn = "OU=Tier-0,OU=Tiering,$domainDn"
$gpoId = '31b2f340-016d-11d2-945f-00c04fb984f9'

$script:Objects = @{
    $domainDn                               = New-FakeObject $domainDn $da @(
        [FakeAce]::new($dcs, 0x100, $dcsyncGuid, $false),              # Domain Controllers - trusted
        [FakeAce]::new($foreignEa, 0xF01FF, $null, $false),            # Enterprise Admins of the root - trusted
        [FakeAce]::new($exchange, 0x40000, $null, $false),             # Exchange Windows Permissions - WriteDacl
        [FakeAce]::new($helpdesk, 0x100, $dcsyncGuid, $false))         # a helpdesk group with DCSync
    "CN=AdminSDHolder,CN=System,$domainDn"  = New-FakeObject "CN=AdminSDHolder,CN=System,$domainDn" $da @([FakeAce]::new('S-1-5-32-561', 0x20, 'bf967a7f-0de6-11d0-a285-00aa003049e2', $false))
    "CN=Policies,CN=System,$domainDn"       = New-FakeObject "CN=Policies,CN=System,$domainDn" $da @()
    "OU=Domain Controllers,$domainDn"       = New-FakeObject "OU=Domain Controllers,$domainDn" $da @([FakeAce]::new($exchange, 0xF01FF, $null, $true))
    "OU=Tiering,$domainDn"                  = New-FakeObject "OU=Tiering,$domainDn" $da @()
    "CN={$($gpoId.ToUpper())},CN=Policies,CN=System,$domainDn" = New-FakeObject 'gpo' $da @([FakeAce]::new($helpdesk, 0x20, $null, $false))
}
$script:Subtree = @{
    $tier0Dn                          = @(
        (New-FakeObject "CN=PKI01,OU=Servers,$tier0Dn" $da @([FakeAce]::new($t1Admins, 0xF01FF, $null, $false))),
        (New-FakeObject "CN=adm-t0-alice,OU=Accounts,$tier0Dn" $t1Admins @()),
        (New-FakeObject "CN=G-T0-Admins,OU=Groups,$tier0Dn" $da @([FakeAce]::new($t0Admins, 0xF01FF, $null, $false))))
    "OU=Domain Controllers,$domainDn" = @((New-FakeObject "CN=DC01,OU=Domain Controllers,$domainDn" $da @([FakeAce]::new($exchange, 0xF01FF, $null, $true))))
}

function Get-ADObject {
    param($Identity, $SearchBase, $LDAPFilter, $Properties, $ResultSetSize, $SearchScope)
    if ($SearchBase) { return $script:Subtree[$SearchBase] }
    if ($script:Objects.ContainsKey($Identity)) { return $script:Objects[$Identity] }
    throw "not found: $Identity"
}
function Get-ADOrganizationalUnit { @() }
function Get-GPInheritance { param($Target) [pscustomobject]@{ InheritedGpoLinks = @([pscustomobject]@{ GpoId = [guid]$gpoId; DisplayName = 'Default Domain Policy' }) } }
function Get-ADComputer { param($LDAPFilter, $SearchBase) if ($SearchBase -eq $tier0Dn) { [pscustomobject]@{ DistinguishedName = "CN=ADFS01,OU=Servers,$tier0Dn" } } }
function Get-ADUser {
    param($Identity, $LDAPFilter, $SearchBase, $Properties)
    if ($Identity) { return [pscustomobject]@{ PasswordLastSet = (Get-Date).AddDays(-900); SID = "$domainSid-502" } }
    if ($LDAPFilter -match 'KeyCredential') { return @() }
    if ($LDAPFilter -match 'adminCount') {
        return @(
            [pscustomobject]@{ DistinguishedName = "CN=krbtgt,CN=Users,$domainDn"; SID = "$domainSid-502"; servicePrincipalName = @('kadmin/changepw') },
            [pscustomobject]@{ DistinguishedName = "CN=svc-sql,CN=Users,$domainDn"; SID = "$domainSid-2001"; servicePrincipalName = @('MSSQLSvc/sql01') })
    }
    return @()
}
$sidNames = @{ 'G-T0-Admins' = $t0Admins }
function Resolve-TierPrincipal { param($Reference, [switch]$AllowMissing) if ($sidNames.ContainsKey($Reference)) { [pscustomobject]@{ Name = $Reference; SID = $sidNames[$Reference] } } else { [pscustomobject]@{ Name = $Reference; SID = $Reference } } }

Reset-Actions
Test-TierAttackPath -Configuration (Get-ShippedConfiguration)
$findings = @($script:TierActions | Where-Object { $_.Phase -eq 'AttackPath' -and $_.Result -eq 'Drift' })
$has = { param($type, $pattern) @($findings | Where-Object { $_.ObjectType -eq $type -and "$($_.Target) $($_.Detail)" -match $pattern }).Count -gt 0 }

Assert-That 'WriteDacl on the domain head is found' (& $has 'DangerousAce' "$exchange.*WriteDacl")
Assert-That 'DCSync by a non-DC is found' (& $has 'DangerousAce' "$helpdesk.*DCSync")
Assert-That 'DCSync by Domain Controllers is not' (-not (& $has 'DangerousAce' "$dcs"))
Assert-That 'Enterprise Admins of the forest root are trusted' (-not (& $has 'DangerousAce' "$foreignEa"))
Assert-That 'scoped default writes on AdminSDHolder are not findings' (-not (& $has 'DangerousAce' 'S-1-5-32-561'))
Assert-That 'inherited entries below the head are not reported twice' (-not (& $has 'DangerousAce' 'Domain Controllers.*S-1-5-21-1-2-3-1500'))
Assert-That 'a Tier 1 group with full control on a Tier 0 server is High' (@($findings | Where-Object { $_.ObjectType -eq 'TopTierAce' -and $_.Target -match 'PKI01' -and $_.Severity -eq 'High' }).Count -eq 1)
Assert-That 'a Tier 0 account owned by Tier 1 is found' (& $has 'TopTierAce' 'adm-t0-alice.*Owned by')
Assert-That 'the top tier itself is trusted' (-not (& $has 'TopTierAce' 'G-T0-Admins'))
Assert-That 'inherited entries on DC objects are skipped' (-not (& $has 'TopTierAce' 'DC01'))
Assert-That 'an editable GPO applying to Tier 0 is found' (& $has 'TopTierGpo' "Default Domain Policy.*$helpdesk")
Assert-That 'RBCD on a Tier 0 server is found' (& $has 'Rbcd' 'ADFS01')
Assert-That 'a privileged account with an SPN is found' (& $has 'Kerberoastable' 'svc-sql')
Assert-That 'krbtgt itself is not Kerberoastable' (-not (& $has 'Kerberoastable' 'krbtgt'))
Assert-That 'an old krbtgt password is found' (& $has 'Krbtgt' '900 days')

$disabled = Get-ShippedConfiguration
$disabled.attackPathChecks.enabled = $false
Reset-Actions
Test-TierAttackPath -Configuration $disabled
Assert-That 'the checks can be switched off' ($script:TierActions.Count -eq 0)

# =================================================================================================
Write-Host "`nConfiguration migration"
# =================================================================================================

$legacy = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
$legacy.PSObject.Properties.Remove('staging')
$legacy.PSObject.Properties.Remove('attackPathChecks')
$legacy.options.PSObject.Properties.Remove('authenticationPolicySiloReconcile')
$legacy.options.redirectComputersTo = 'Tier-2/Staging'
foreach ($tier in $legacy.tiers) {
    foreach ($gpo in $tier.gpos) { $gpo.registrySettings = @($gpo.registrySettings | Where-Object { $_.valueName -notin 'EnableCbacAndArmor', 'CbacAndArmorLevel' }) }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) "adtierkit-hardening-$PID"
New-Item -Path $work -ItemType Directory -Force | Out-Null
$legacyPath = Join-Path $work 'tiermodel.json'
$legacy | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $legacyPath -Encoding UTF8

$updater = Join-Path $PSScriptRoot '../Update-TierConfiguration.ps1'
$exit = Invoke-ChildScript -Arguments @('-File', $updater, '-Path', $legacyPath, '-SkipRoles')
Assert-That 'updater succeeds' ($exit -eq 0) "exit code $exit"

$migrated = Get-Content -Raw $legacyPath | ConvertFrom-Json
$migratedDc = $migrated.tiers[0].gpos | Where-Object { $_.targetOu -eq '$DomainControllers' }
Assert-That 'KDC armoring added to the DC baseline' (@($migratedDc.registrySettings | Where-Object { $_.valueName -eq 'CbacAndArmorLevel' }).Count -eq 1)
Assert-That 'client armoring added to every tier GPO' (@($migrated.tiers | ForEach-Object { $_.gpos } | Where-Object { -not @($_.registrySettings | Where-Object { $_.key -eq $settings.Client.Key }) }).Count -eq 0)
Assert-That 'reconcile mode added as Report' ($migrated.options.authenticationPolicySiloReconcile -eq 'Report')
Assert-That 'attack path checks added' ($migrated.attackPathChecks.enabled -eq $true)
Assert-That 'staging added, but disabled' ($migrated.staging -and $migrated.staging.enabled -eq $false -and $migrated.staging.groupOu -eq 'Tier-0/Groups')
Assert-That 'redirect target left alone' ($migrated.options.redirectComputersTo -eq 'Tier-2/Staging')

$before = Get-Content -Raw $legacyPath
$null = Invoke-ChildScript -Arguments @('-File', $updater, '-Path', $legacyPath, '-SkipRoles')
Assert-That 'a second run changes nothing' ((Get-Content -Raw $legacyPath) -eq $before)

Remove-Item -LiteralPath $work -Recurse -Force

# -------------------------------------------------------------------------------------------------
Write-Host ''
if ($script:Failures -eq 0) {
    Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
}
Write-Host "$script:Failures check(s) failed." -ForegroundColor Red
exit 1
