<#
    Offline checks for the 1.3.0 security review fixes: objects squatted under a configured name are
    not adopted, LDAP filter values are escaped, the principal name fallback only accepts one
    security principal, the privileged group guards work on the real SID, the isolation check no
    longer trusts CN=Users, the attack path rules know AddSelf and WriteAccountRestrictions, and the
    wizard no longer deploys with -Force. Active Directory is mocked; the decision logic is tested.
#>

$ErrorActionPreference = 'Stop'
$script:Failures = 0

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
$script:TierDeclaredNames = $null
$script:TierAdoptionCache = @{}
$domainDn = 'DC=lab,DC=example,DC=com'
$domainSid = 'S-1-5-21-1-2-3'

$configuration = [pscustomobject]@{
    tiers     = @(
        [pscustomobject]@{
            id = 0; name = 'Tier-0'
            groups = @([pscustomobject]@{ name = 'G-T0-Admins'; scope = 'Global'; targetOu = 'Groups' })
            adminAccounts = @([pscustomobject]@{ samAccountName = 'adm-t0-template'; targetOu = 'Accounts'; memberOf = @('G-T0-Admins') })
            gpos = @()
        }
        [pscustomobject]@{
            id = 2; name = 'Tier-2'
            groups = @([pscustomobject]@{ name = 'G-T2-Admins'; scope = 'Global'; targetOu = 'Groups' })
            adminAccounts = @()
            gpos = @()
        }
    )
    ownership = [pscustomobject]@{ owner = '512'; acceptableOwners = @() }
    staging   = [pscustomobject]@{ enabled = $true; joinGroup = 'DL-Staging-Join' }
    options   = [pscustomobject]@{ createAdminAccounts = $true }
}

$script:TierContext = [pscustomobject]@{
    DomainDn            = $domainDn
    DomainSid           = $domainSid
    DomainFqdn          = 'lab.example.com'
    RootOuDn            = "OU=Tiering,$domainDn"
    DomainControllersDn = "OU=Domain Controllers,$domainDn"
    Server              = 'dc01'
    TierNames           = @('Tier-0', 'Tier-2')
    Configuration       = $configuration
}
function Get-TierContext { return $script:TierContext }
function Write-TierLog { param($Message, $Level) }
function Reset-State {
    $script:TierActions.Clear()
    $script:PrincipalCache = @{}
    $script:TierDeclaredNames = $null
    $script:TierAdoptionCache = @{}
}

# A security descriptor stand-in: SecurityIdentifier cannot be constructed off Windows.
function New-Descriptor {
    param([string]$OwnerSid)
    $sd = [pscustomobject]@{ OwnerSid = $OwnerSid }
    $sd | Add-Member -MemberType ScriptMethod -Name GetOwner -Value { param($type) [pscustomobject]@{ Value = $this.OwnerSid } }
    return $sd
}

# The directory: objects by sAMAccountName, with their owner.
$script:Objects = @{}
$script:LastFilter = $null
function Add-DirectoryObject {
    param([string]$Sam, [string]$Dn, [string]$OwnerSid, [string]$Sid, [string]$Name)
    if (-not $Name) { $Name = $Sam }
    $script:Objects[$Sam] = [pscustomobject]@{
        Name = $Name; sAMAccountName = $Sam; DistinguishedName = $Dn
        objectSid = [pscustomobject]@{ Value = $Sid }; SID = [pscustomobject]@{ Value = $Sid }
        nTSecurityDescriptor = (New-Descriptor -OwnerSid $OwnerSid)
    }
}

function Get-ADObject {
    param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $ErrorAction, $SearchBase)
    if ($Identity) {
        $hit = @($script:Objects.Values | Where-Object { $_.DistinguishedName -eq $Identity }) | Select-Object -First 1
        if (-not $hit) { throw 'not found' }
        return $hit
    }
    if ($Filter) {
        $script:LastFilter = $Filter
        if ($Filter -match "^sAMAccountName -eq '(.*)'$") {
            $name = $Matches[1].Replace("''", "'")
            if ($script:Objects.ContainsKey($name)) { return $script:Objects[$name] }
            return $null
        }
        if ($Filter -match "^name -eq '(.*)'$") {
            $name = $Matches[1].Replace("''", "'")
            return @($script:ByName[$name])
        }
    }
    return $null
}
function Get-ADGroup {
    param($LDAPFilter, $Properties, $Server, $ErrorAction)
    $script:LastFilter = $LDAPFilter
    if ($LDAPFilter -match '^\(sAMAccountName=(.*)\)$') {
        $name = $Matches[1]
        if ($script:Objects.ContainsKey($name)) { return $script:Objects[$name] }
    }
    return $null
}
$script:ByName = @{}

# =================================================================================================
Write-Host "`nLDAP filter values are escaped"
# =================================================================================================

Assert-That 'parentheses and asterisk are escaped' ((ConvertTo-TierLdapFilterValue -Value 'a*(b)') -eq 'a\2a\28b\29')
Assert-That 'backslash is escaped first' ((ConvertTo-TierLdapFilterValue -Value 'a\b') -eq 'a\5cb')
Assert-That 'null is an empty value, not a binding error' ((ConvertTo-TierLdapFilterValue -Value $null) -eq '')

Reset-State
Add-DirectoryObject -Sam 'DnsAdmins' -Dn "CN=DnsAdmins,CN=Users,$domainDn" -OwnerSid "$domainSid-512" -Sid "$domainSid-1101"
$null = Get-TierPrivilegedGroupReference -Entry ([pscustomobject]@{ name = 'Dns*)(objectClass=*' })
Assert-That 'a privileged group name cannot widen the filter' ($script:LastFilter -eq '(sAMAccountName=Dns\2a\29\28objectClass=\2a)') $script:LastFilter

# =================================================================================================
Write-Host "`nPrincipal resolution"
# =================================================================================================

Reset-State
$null = Resolve-TierPrincipal -Reference "it's" -AllowMissing
Assert-That 'a quote in a name is doubled in the -Filter string' ($script:LastFilter -eq "name -eq 'it''s'") $script:LastFilter

Reset-State
$script:ByName['Helpdesk'] = @(
    [pscustomobject]@{ Name = 'Helpdesk'; DistinguishedName = "CN=Helpdesk,OU=A,$domainDn"; objectSid = [pscustomobject]@{ Value = "$domainSid-2001" } }
    [pscustomobject]@{ Name = 'Helpdesk'; DistinguishedName = "CN=Helpdesk,OU=B,$domainDn"; objectSid = [pscustomobject]@{ Value = "$domainSid-2002" } }
)
$threw = $false
try { $null = Resolve-TierPrincipal -Reference 'Helpdesk' } catch { $threw = $_.Exception.Message -match 'ambiguous' }
Assert-That 'two security principals with the same name are refused' $threw

Reset-State
$script:ByName['Printer'] = @([pscustomobject]@{ Name = 'Printer'; DistinguishedName = "CN=Printer,OU=A,$domainDn"; objectSid = $null })
Assert-That 'an object without a SID (a contact) is not a principal' ($null -eq (Resolve-TierPrincipal -Reference 'Printer' -AllowMissing))

# =================================================================================================
Write-Host "`nSquatted objects are not adopted"
# =================================================================================================

$t2AdminSid = "$domainSid-3001"

Reset-State
$script:Objects = @{}
Add-DirectoryObject -Sam 'G-T0-Admins' -Dn "CN=G-T0-Admins,OU=Groups,OU=Tier-2,OU=Tiering,$domainDn" -OwnerSid $t2AdminSid -Sid "$domainSid-4001"
Assert-That 'a configured group owned by a Tier 2 admin does not resolve' ($null -eq (Resolve-TierPrincipal -Reference 'G-T0-Admins' -AllowMissing))
$finding = @($script:TierActions | Where-Object { $_.ObjectType -eq 'ForeignObject' })
Assert-That 'the refusal is a High finding' ($finding.Count -eq 1 -and $finding[0].Severity -eq 'High')

Reset-State
$threw = $false
try { $null = Resolve-TierPrincipal -Reference 'G-T0-Admins' } catch { $threw = $_.Exception.Message -match 'not adopted' }
Assert-That 'without AllowMissing the refusal is an error' $threw

Reset-State
$script:Objects = @{}
Add-DirectoryObject -Sam 'G-T0-Admins' -Dn "CN=G-T0-Admins,OU=Groups,OU=Tier-0,OU=Tiering,$domainDn" -OwnerSid "$domainSid-512" -Sid "$domainSid-4001"
Assert-That 'the same group owned by Domain Admins resolves' ((Resolve-TierPrincipal -Reference 'G-T0-Admins').SID -eq "$domainSid-4001")

Reset-State
$script:Objects = @{}
Add-DirectoryObject -Sam 'G-T0-Admins' -Dn "CN=G-T0-Admins,OU=Groups,OU=Tier-0,OU=Tiering,$domainDn" -OwnerSid 'S-1-5-21-9-9-9-519' -Sid "$domainSid-4001"
Assert-That 'Enterprise Admins of the forest root are an acceptable owner' ($null -ne (Resolve-TierPrincipal -Reference 'G-T0-Admins' -AllowMissing))

Reset-State
$script:Objects = @{}
Add-DirectoryObject -Sam 'Helpdesk-Team' -Dn "CN=Helpdesk-Team,OU=Groups,OU=Tier-2,OU=Tiering,$domainDn" -OwnerSid $t2AdminSid -Sid "$domainSid-4002"
Assert-That 'a name the configuration does not declare is not checked' ($null -ne (Resolve-TierPrincipal -Reference 'Helpdesk-Team' -AllowMissing))

Reset-State
$configuration.ownership.acceptableOwners = @($t2AdminSid)
$script:Objects = @{}
Add-DirectoryObject -Sam 'G-T0-Admins' -Dn "CN=G-T0-Admins,OU=Groups,OU=Tier-0,OU=Tiering,$domainDn" -OwnerSid $t2AdminSid -Sid "$domainSid-4001"
Assert-That 'an owner listed in ownership.acceptableOwners is accepted' ($null -ne (Resolve-TierPrincipal -Reference 'G-T0-Admins' -AllowMissing))
$configuration.ownership.acceptableOwners = @()

# --- the group stage does not move a squatted group ----------------------------------------------
Reset-State
$script:Objects = @{}
Add-DirectoryObject -Sam 'G-T0-Admins' -Dn "CN=G-T0-Admins,OU=Groups,OU=Tier-2,OU=Tiering,$domainDn" -OwnerSid $t2AdminSid -Sid "$domainSid-4001"
Add-DirectoryObject -Sam 'G-T2-Admins' -Dn "CN=G-T2-Admins,OU=Groups,OU=Tier-2,OU=Tiering,$domainDn" -OwnerSid "$domainSid-512" -Sid "$domainSid-4003"
$script:Moves = [System.Collections.Generic.List[object]]::new()
function Move-ADObject { param($Identity, $TargetPath) $script:Moves.Add([pscustomobject]@{ Identity = $Identity; Target = $TargetPath }) }
function New-ADGroup { throw 'nothing should be created' }
New-TierGroupSet -Configuration $configuration -Confirm:$false
Assert-That 'the squatted top tier group is not moved into the top tier' (@($script:Moves | Where-Object { $_.Identity -like 'CN=G-T0-Admins,*' }).Count -eq 0)
Assert-That 'the group stage reports it' (@($script:TierActions | Where-Object { $_.ObjectType -eq 'ForeignObject' -and $_.Target -eq 'G-T0-Admins' }).Count -eq 1)
Assert-That 'a legitimate group is still handled' (@($script:TierActions | Where-Object { $_.Phase -eq 'Group' -and $_.Target -eq 'G-T2-Admins' -and $_.Result -eq 'Compliant' }).Count -eq 1)

# --- the account stage does not add a squatted account to the role group --------------------------
Reset-State
$script:Objects = @{}
Add-DirectoryObject -Sam 'adm-t0-template' -Dn "CN=adm-t0-template,OU=Accounts,OU=Tier-2,OU=Tiering,$domainDn" -OwnerSid $t2AdminSid -Sid "$domainSid-5001"
$script:Added = [System.Collections.Generic.List[object]]::new()
function Get-ADUser { param($LDAPFilter, $Identity, $Properties, $Server, $ErrorAction) if ($LDAPFilter -match 'adm-t0-template') { return $script:Objects['adm-t0-template'] } }
function Add-ADGroupMember { param($Identity, $Members) $script:Added.Add("$Identity <- $Members") }
function Set-TierAdminAccountHygiene { param($Configuration, [switch]$AuditOnly) }
New-TierAdminAccountSet -Configuration $configuration -CredentialDirectory ([System.IO.Path]::GetTempPath()) -Confirm:$false
Assert-That 'the squatted account is not added to the top tier role group' ($script:Added.Count -eq 0) ($script:Added -join '; ')
Assert-That 'the account stage reports it' (@($script:TierActions | Where-Object { $_.ObjectType -eq 'ForeignObject' -and $_.Target -eq 'adm-t0-template' }).Count -eq 1)

# =================================================================================================
Write-Host "`nAttack path rules"
# =================================================================================================

Assert-That 'Self on member is AddSelf' ((Get-TierAceRisk -Rights 0x8 -ObjectType 'bf9679c0-0de6-11d0-a285-00aa003049e2') -match 'Self-Membership')
Assert-That 'a write to Account Restrictions is RBCD' ((Get-TierAceRisk -Rights 0x20 -ObjectType '4c164200-20c0-11d0-a768-00aa006e0529') -match 'RBCD')
Assert-That 'a write to msDS-GroupMSAMembership is dangerous' ((Get-TierAceRisk -Rights 0x20 -ObjectType '888eedd6-ce04-df40-b462-b8a50e41ba38') -match 'GroupMSAMembership')
Assert-That 'Get-Changes-In-Filtered-Set is reported' ((Get-TierAceRisk -Rights 0x100 -ObjectType '89e95b76-444d-4c62-991a-0facbeda640c') -match 'DCSync')
Assert-That 'Validated-SPN alone is not a finding' ($null -eq (Get-TierAceRisk -Rights 0x8 -ObjectType 'f3a64788-5306-11d1-a9c5-0000f80367c1'))

# --- the staging join group is not trusted like Tier 0 -------------------------------------------
Reset-State
$configuration.tiers[0].groups = @(
    [pscustomobject]@{ name = 'G-T0-Admins'; scope = 'Global' }
    [pscustomobject]@{ name = 'DL-Staging-Join'; scope = 'DomainLocal' }
)
$script:Objects = @{}
Add-DirectoryObject -Sam 'G-T0-Admins' -Dn "CN=G-T0-Admins,OU=Groups,OU=Tier-0,OU=Tiering,$domainDn" -OwnerSid "$domainSid-512" -Sid "$domainSid-4001"
Add-DirectoryObject -Sam 'DL-Staging-Join' -Dn "CN=DL-Staging-Join,OU=Groups,OU=Tier-0,OU=Tiering,$domainDn" -OwnerSid "$domainSid-512" -Sid "$domainSid-4009"
$trusted = Get-TierTrustedSid -Configuration $configuration
Assert-That 'the top tier admin group is trusted' ($trusted.ContainsKey("$domainSid-4001"))
Assert-That 'the staging join group is not' (-not $trusted.ContainsKey("$domainSid-4009"))

# =================================================================================================
Write-Host "`nPrivileged groups and isolation"
# =================================================================================================

function Get-TierWellKnownGroup {
    param($Sid, $Properties)
    $full = if ($Sid -match '^S-1-') { $Sid } else { "$domainSid-$Sid" }
    [pscustomobject]@{ Name = "Group $Sid"; DistinguishedName = "CN=Group $Sid,CN=Users,$domainDn"; SID = [pscustomobject]@{ Value = $full } }
}
$script:Removed = [System.Collections.Generic.List[string]]::new()
function Remove-ADGroupMember { param($Identity, $Members) $script:Removed.Add($Members) }
function Get-ADGroupMember {
    param($Identity)
    @([pscustomobject]@{ name = 'svc-old'; distinguishedName = "CN=svc-old,CN=Users,$domainDn"; SID = [pscustomobject]@{ Value = "$domainSid-7001" } })
}

Reset-State
$privileged = [pscustomobject]@{ mode = 'Enforce'; groups = @([pscustomobject]@{ sid = "$domainSid-512"; allowedMembers = @() }) }
Set-TierPrivilegedGroupMembership -Configuration ([pscustomobject]@{ privilegedGroups = $privileged }) -Confirm:$false
Assert-That 'Domain Admins addressed by its full SID is never emptied' ($script:Removed.Count -eq 0)

Reset-State
$privileged = [pscustomobject]@{ mode = 'Enforce'; groups = @([pscustomobject]@{ sid = 'S-1-5-32-544'; allowedMembers = @() }) }
Set-TierPrivilegedGroupMembership -Configuration ([pscustomobject]@{ privilegedGroups = $privileged }) -Confirm:$false
Assert-That 'the built-in Administrators group is never emptied either' ($script:Removed.Count -eq 0)

Reset-State
$script:Removed.Clear()
$privileged = [pscustomobject]@{ mode = 'Enforce'; groups = @([pscustomobject]@{ sid = 'S-1-5-32-548'; allowedMembers = @() }) }
Set-TierPrivilegedGroupMembership -Configuration ([pscustomobject]@{ privilegedGroups = $privileged }) -Confirm:$false
Assert-That 'Account Operators may still be emptied' ($script:Removed.Count -eq 1)

# --- CN=Users is no longer a free pass ------------------------------------------------------------
Reset-State
$configuration.tiers[0].groups = @([pscustomobject]@{ name = 'G-T0-Admins'; scope = 'Global' })
function Get-ADGroupMember {
    param($Identity)
    if ($Identity -notlike 'CN=Group 512,*') { return @() }
    @(
        [pscustomobject]@{ name = 'Administrator'; distinguishedName = "CN=Administrator,CN=Users,$domainDn"; SID = [pscustomobject]@{ Value = "$domainSid-500" } }
        [pscustomobject]@{ name = 'helpdesk.joe'; distinguishedName = "CN=helpdesk.joe,CN=Users,$domainDn"; SID = [pscustomobject]@{ Value = "$domainSid-8001" } }
        [pscustomobject]@{ name = 'adm-t0-anna'; distinguishedName = "CN=adm-t0-anna,OU=Accounts,OU=Tier-0,OU=Tiering,$domainDn"; SID = [pscustomobject]@{ Value = "$domainSid-8002" } }
    )
}
function Get-ADComputer { param($Filter, $LDAPFilter, $SearchBase, $Properties, $Server, $ErrorAction) @() }
function Get-ADUser { param($Filter, $LDAPFilter, $SearchBase, $Properties, $Server, $ErrorAction) @() }
Test-TierModelIsolation -Configuration $configuration
$daFinding = @($script:TierActions | Where-Object { $_.ObjectType -eq 'PrivilegedGroup' -and $_.Target -eq 'Group 512' }) | Select-Object -First 1
Assert-That 'a user in CN=Users inside Domain Admins is reported' ($daFinding.Result -eq 'Drift' -and $daFinding.Detail -match 'helpdesk\.joe')
Assert-That 'the built-in Administrator is not' ($daFinding.Detail -notmatch 'Administrator')
Assert-That 'a top tier account is not' ($daFinding.Detail -notmatch 'adm-t0-anna')

# =================================================================================================
Write-Host "`nWizard and SYSVOL"
# =================================================================================================

$wizard = @($functions | Where-Object { $_.Name -eq 'Start-TierModelWizard' })[0].Extent.Text
Assert-That 'the wizard never deploys with -Force' ($wizard -notmatch 'Invoke-TierModelDeployment[^\r\n]*-Force')
Assert-That 'the wizard no longer names Deploy-TierModel.ps1' ($wizard -notmatch 'Deploy-TierModel\.ps1')

$context = @($functions | Where-Object { $_.Name -eq 'Initialize-TierContext' })[0].Extent.Text
Assert-That 'SYSVOL is written on the targeted domain controller' ($context -match 'SysvolPolicyPath\s*=\s*"\\\\\$\(if \(\$Server\)')

# -------------------------------------------------------------------------------------------------
Write-Host ''
if ($script:Failures -eq 0) {
    Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
}
Write-Host "$script:Failures check(s) failed." -ForegroundColor Red
exit 1
