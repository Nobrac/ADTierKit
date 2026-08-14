<#
    Offline check of the role expansion and the new OU reference tokens.
    Runs without Active Directory: the script is dot-sourced with its parameter block bypassed,
    a fake tier context is injected, and only the pure functions are exercised.
#>

$ErrorActionPreference = 'Stop'
$script:Failures = 0

function Assert-That {
    param([string]$What, [bool]$Condition, [string]$Detail)
    if ($Condition) { Write-Host "  PASS  $What" -ForegroundColor Green }
    else { Write-Host "  FAIL  $What $Detail" -ForegroundColor Red; $script:Failures++ }
}

# --- load the functions without executing the script body ---------------------------------------
$source = Get-Content -Raw $PSScriptRoot/../ADTierKit.ps1
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($f in $functions) { . ([scriptblock]::Create($f.Extent.Text)) }
Write-Host "Loaded $($functions.Count) functions`n"

# Write-TierLog needs the module-scope log state; a stub keeps the output readable.
function Write-TierLog { param($Message, $Level) }
$script:TierActions = [System.Collections.Generic.List[object]]::new()

# --- fake context --------------------------------------------------------------------------------
$domainDn = 'DC=lab,DC=example,DC=com'
$script:TierContext = [pscustomobject]@{
    DomainDn            = $domainDn
    RootOuDn            = "OU=Tiering,$domainDn"
    DomainControllersDn = "OU=Domain Controllers,$domainDn"
    SystemContainerDn   = "CN=System,$domainDn"
    MicrosoftDnsDn      = "CN=MicrosoftDNS,CN=System,$domainDn"
    DomainDnsZonesDn    = "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDn"
    ForestDnsZonesDn    = "CN=MicrosoftDNS,DC=ForestDnsZones,$domainDn"
    PoliciesDn          = "CN=Policies,CN=System,$domainDn"
    AdminSdHolderDn     = "CN=AdminSDHolder,CN=System,$domainDn"
    TierNames           = @('Tier-0', 'Tier-1', 'Tier-2')
}
function Get-TierContext { return $script:TierContext }

Write-Host 'OU reference tokens' -ForegroundColor Cyan
Assert-That '$MicrosoftDns'      ((Resolve-TierOuDn -Reference '$MicrosoftDns') -eq "CN=MicrosoftDNS,CN=System,$domainDn")
Assert-That '$PoliciesContainer' ((Resolve-TierOuDn -Reference '$PoliciesContainer') -eq "CN=Policies,CN=System,$domainDn")
Assert-That '$AdminSDHolder'     ((Resolve-TierOuDn -Reference '$AdminSDHolder') -eq "CN=AdminSDHolder,CN=System,$domainDn")
Assert-That '$DomainDnsZones'    ((Resolve-TierOuDn -Reference '$DomainDnsZones') -eq "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDn")
Assert-That '$DnsZone:<zone>'    ((Resolve-TierOuDn -Reference '$DnsZone:apps.example.com') -eq "DC=apps.example.com,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDn")
Assert-That 'existing tokens still work' ((Resolve-TierOuDn -Reference 'Servers' -TierName 'Tier-1') -eq "OU=Servers,OU=Tier-1,OU=Tiering,$domainDn")
Assert-That 'verbatim DN passes through' ((Resolve-TierOuDn -Reference "CN=Foo,$domainDn") -eq "CN=Foo,$domainDn")

# --- role expansion --------------------------------------------------------------------------------
Write-Host "`nRole expansion" -ForegroundColor Cyan
$config = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
$before = @{
    Groups      = @($config.tiers | ForEach-Object { $_.groups }).Count
    Accounts    = @($config.tiers | ForEach-Object { $_.adminAccounts }).Count
    Delegations = @($config.tiers | ForEach-Object { $_.delegations }).Count
}
$config = Expand-TierRoleDefinition -Configuration $config

$t0 = $config.tiers | Where-Object id -eq 0
$t1 = $config.tiers | Where-Object id -eq 1
$t2 = $config.tiers | Where-Object id -eq 2

Assert-That 'DNS role group created in Tier 0' (@($t0.groups | Where-Object name -eq 'G-T0-DNS-Admins').Count -eq 1)
Assert-That 'GPO role group created in Tier 0' (@($t0.groups | Where-Object name -eq 'G-T0-GPO-Admins').Count -eq 1)
Assert-That 'GPO-Link role group created in Tier 1' (@($t1.groups | Where-Object name -eq 'G-T1-GPO-Admins').Count -eq 1)
Assert-That 'GPO-Link role group created in Tier 2' (@($t2.groups | Where-Object name -eq 'G-T2-GPO-Admins').Count -eq 1)
Assert-That 'disabled role produced nothing' (@($t1.groups | Where-Object name -eq 'G-T1-DNS-Operators').Count -eq 0)

$t1Deny = ($t1.groups | Where-Object name -eq 'DL-T1-DenyLogon').members
$t2Deny = ($t2.groups | Where-Object name -eq 'DL-T2-DenyLogon').members
$t0Deny = ($t0.groups | Where-Object name -eq 'DL-T0-DenyLogon').members
Assert-That 'T0 DNS role denied on Tier 1' ($t1Deny -contains 'G-T0-DNS-Admins') "-> $($t1Deny -join ', ')"
Assert-That 'T0 DNS role denied on Tier 2' ($t2Deny -contains 'G-T0-DNS-Admins')
Assert-That 'T1 GPO role denied on Tier 0' ($t0Deny -contains 'G-T1-GPO-Admins')
Assert-That 'T1 GPO role denied on Tier 2' ($t2Deny -contains 'G-T1-GPO-Admins')
Assert-That 'role group NOT denied in its own tier' ($t0Deny -notcontains 'G-T0-DNS-Admins')

$silo0 = $config.authenticationPolicySilos | Where-Object name -eq 'Tier-0-Silo'
$silo1 = $config.authenticationPolicySilos | Where-Object name -eq 'Tier-1-Silo'
Assert-That 'T0 roles joined the Tier 0 silo' ($silo0.memberGroups -contains 'G-T0-DNS-Admins' -and $silo0.memberGroups -contains 'G-T0-GPO-Admins')
Assert-That 'T1 role joined the Tier 1 silo' ($silo1.memberGroups -contains 'G-T1-GPO-Admins')

Assert-That 'template account created' (@($t0.adminAccounts | Where-Object samAccountName -eq 'adm-t0-dns-template').Count -eq 1)
$template = $t0.adminAccounts | Where-Object samAccountName -eq 'adm-t0-dns-template'
Assert-That 'template account is in its role group' ($template.memberOf -contains 'G-T0-DNS-Admins')

$dnsAce = @($t0.delegations | Where-Object { $_.principal -eq 'G-T0-DNS-Admins' })
Assert-That 'DNS delegations attached to Tier 0' ($dnsAce.Count -eq 3) "-> $($dnsAce.Count)"
Assert-That 'DNS zone ACE targets the DNS server object' (@($dnsAce | Where-Object targetOu -eq '$MicrosoftDns').Count -eq 1)

$linkAce = @($t1.delegations | Where-Object { $_.principal -eq 'G-T1-GPO-Admins' -and $_.objectType -eq 'gPLink' })
Assert-That 'gPLink ACE created for Tier 1' ($linkAce.Count -eq 1)
Assert-That 'gPLink ACE is writable' ($linkAce[0].rights -eq 'ReadProperty, WriteProperty')
$optionsAce = @($t1.delegations | Where-Object { $_.principal -eq 'G-T1-GPO-Admins' -and $_.objectType -eq 'gPOptions' })
Assert-That 'gPOptions ACE is read only' ($optionsAce.Count -eq 1 -and $optionsAce[0].rights -eq 'ReadProperty')
Assert-That 'no principal can write gPOptions' (@($config.tiers | ForEach-Object { $_.delegations } | Where-Object { $_.objectType -eq 'gPOptions' -and $_.rights -match 'WriteProperty' }).Count -eq 0)

Assert-That 'tier 2 delegations were not contaminated by tier 1' (@($t2.delegations | Where-Object principal -eq 'G-T1-GPO-Admins').Count -eq 0)

$dnsAdmins = $config.privilegedGroups.groups | Where-Object { $_.name -eq 'DnsAdmins' }
Assert-That 'DnsAdmins added to the privileged group watch list' ($null -ne $dnsAdmins)
Assert-That 'DnsAdmins allows only the role group' ($dnsAdmins.allowedMembers -contains 'G-T0-DNS-Admins' -and @($dnsAdmins.allowedMembers).Count -eq 1)
$gpco = $config.privilegedGroups.groups | Where-Object { $_.sid -eq '520' }
Assert-That 'Group Policy Creator Owners added by SID' ($null -ne $gpco -and $gpco.allowedMembers -contains 'G-T0-GPO-Admins')

Write-Host "`nBuilt-in nesting entries" -ForegroundColor Cyan
$nestDns = @($config.builtInNesting | Where-Object { $_.group.name -eq 'DnsAdmins' })
Assert-That 'DnsAdmins nesting entry generated' ($nestDns.Count -eq 1)
Assert-That 'DnsAdmins nesting names the role group' ($nestDns[0].members -contains 'G-T0-DNS-Admins')
$nestGpco = @($config.builtInNesting | Where-Object { $_.group.sid -eq '520' })
Assert-That 'Group Policy Creator Owners nesting entry generated' ($nestGpco.Count -eq 1 -and $nestGpco[0].members -contains 'G-T0-GPO-Admins')

# The invariant that stops the two stages fighting: everything nested must also be declared.
$mismatch = foreach ($entry in @($config.builtInNesting)) {
    $key = if ($entry.group.sid) { $entry.group.sid } else { $entry.group.name }
    $declared = @($config.privilegedGroups.groups | Where-Object { $_.sid -eq $key -or $_.name -eq $key }) | Select-Object -First 1
    foreach ($m in $entry.members) { if ($declared -and $declared.allowedMembers -notcontains $m) { "$key <- $m" } }
}
Assert-That 'every nested member is also declared in privilegedGroups' (@($mismatch).Count -eq 0) "-> $($mismatch -join ', ')"

# --- idempotency of the expansion itself ---------------------------------------------------------
Write-Host "`nIdempotency" -ForegroundColor Cyan
$again = Expand-TierRoleDefinition -Configuration $config
$t0b = $again.tiers | Where-Object id -eq 0
Assert-That 'second expansion adds no group' (@($t0b.groups | Where-Object name -eq 'G-T0-DNS-Admins').Count -eq 1)
Assert-That 'second expansion adds no account' (@($t0b.adminAccounts | Where-Object samAccountName -eq 'adm-t0-dns-template').Count -eq 1)
$deny1b = ($again.tiers | Where-Object id -eq 1).groups | Where-Object name -eq 'DL-T1-DenyLogon'
Assert-That 'second expansion adds no duplicate deny member' (@($deny1b.members | Where-Object { $_ -eq 'G-T0-DNS-Admins' }).Count -eq 1)
$silo0b = $again.authenticationPolicySilos | Where-Object name -eq 'Tier-0-Silo'
Assert-That 'second expansion adds no duplicate silo member' (@($silo0b.memberGroups | Where-Object { $_ -eq 'G-T0-DNS-Admins' }).Count -eq 1)
$dnsAdminsB = $again.privilegedGroups.groups | Where-Object { $_.name -eq 'DnsAdmins' }
Assert-That 'second expansion adds no duplicate privileged entry' (@($again.privilegedGroups.groups | Where-Object { $_.name -eq 'DnsAdmins' }).Count -eq 1)
Assert-That 'second expansion adds no duplicate nesting entry' (@($again.builtInNesting | Where-Object { $_.group.name -eq 'DnsAdmins' }).Count -eq 1)
$nestB = @($again.builtInNesting | Where-Object { $_.group.name -eq 'DnsAdmins' })[0]
Assert-That 'second expansion adds no duplicate nesting member' (@($nestB.members | Where-Object { $_ -eq 'G-T0-DNS-Admins' }).Count -eq 1)

# --- fallback behaviour ----------------------------------------------------------------------------
Write-Host "`nFallbacks" -ForegroundColor Cyan
$legacy = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
foreach ($t in $legacy.tiers) {
    $t.PSObject.Properties.Remove('token')
    $t.PSObject.Properties.Remove('denyLogonGroup')
}
$legacy = Expand-TierRoleDefinition -Configuration $legacy
$l0 = $legacy.tiers | Where-Object id -eq 0
Assert-That 'token falls back to T<id>' (@($l0.groups | Where-Object name -eq 'G-T0-DNS-Admins').Count -eq 1)
$l1Deny = ($legacy.tiers | Where-Object id -eq 1).groups | Where-Object name -eq 'DL-T1-DenyLogon'
Assert-That 'deny group found by name pattern' ($l1Deny.members -contains 'G-T0-DNS-Admins')

Write-Host "`nLower tier refusal" -ForegroundColor Cyan
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$evil = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
$evil.roles = @([pscustomobject]@{
        name                   = 'Rogue'
        tiers                  = @(2)
        roleGroup              = 'G-{TOKEN}-Rogue'
        privilegedGroupNesting = @([pscustomobject]@{ name = 'DnsAdmins' })
    })
$evil = Expand-TierRoleDefinition -Configuration $evil
$t2rogue = ($evil.tiers | Where-Object id -eq 2)
Assert-That 'the role group is still created' (@($t2rogue.groups | Where-Object name -eq 'G-T2-Rogue').Count -eq 1)
Assert-That 'no nesting entry for a lower tier role' (@($evil.builtInNesting | Where-Object { $_.members -contains 'G-T2-Rogue' }).Count -eq 0)
Assert-That 'not silently declared as allowed either' (@($evil.privilegedGroups.groups | Where-Object { $_.allowedMembers -contains 'G-T2-Rogue' }).Count -eq 0)
$refusal = @($script:TierActions | Where-Object { $_.ObjectType -eq 'PrivilegedGroup' -and $_.Result -eq 'Failed' })
Assert-That 'the refusal is a High finding' ($refusal.Count -eq 1 -and $refusal[0].Severity -eq 'High')

Write-Host ''
if ($script:Failures -eq 0) { Write-Host 'All checks passed.' -ForegroundColor Green; exit 0 }
Write-Host "$script:Failures check(s) failed." -ForegroundColor Red
exit 1
