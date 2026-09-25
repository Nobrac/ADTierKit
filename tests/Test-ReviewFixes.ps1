<#
    Offline checks for the 1.2.0 review fixes. Active Directory is mocked; what is under test is
    the decision logic: who ends up in a silo, what the generator writes, where groups are
    expected to live, and that the configuration migration produces the shipped configuration.
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
$script:TierContext = [pscustomobject]@{
    DomainDn            = $domainDn
    DomainSid           = 'S-1-5-21-1-2-3'
    RootOuDn            = "OU=Tiering,$domainDn"
    DomainControllersDn = "OU=Domain Controllers,$domainDn"
    Server              = 'dc01'
    TierNames           = @('Tier-0', 'Tier-1', 'Tier-2')
}
function Get-TierContext { return $script:TierContext }
function Write-TierLog { param($Message, $Level) }
function Reset-Actions { $script:TierActions.Clear() }
function Get-Actions { param($ObjectType) @($script:TierActions | Where-Object { $_.ObjectType -eq $ObjectType }) }

$shipped = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json

# =================================================================================================
Write-Host "`nSilo exclusion"
# =================================================================================================

$breakGlassDn = "CN=adm-t0-breakglass,OU=Accounts,OU=Tier-0,OU=Tiering,$domainDn"
$templateDn = "CN=adm-t0-template,OU=Accounts,OU=Tier-0,OU=Tiering,$domainDn"
$script:SiloState = @{}
$script:Assigned = [System.Collections.Generic.List[string]]::new()
$script:Cleared = [System.Collections.Generic.List[string]]::new()

# In the state the shipped configuration asks for, so the convergence has nothing to change.
function Get-ADAuthenticationPolicy { [pscustomobject]@{ Name = 'policy'; Enforce = $false; UserTGTLifetimeMins = 240 } }
function Get-ADAuthenticationPolicySilo { [pscustomobject]@{ Name = 'silo'; Enforce = $false } }
function Set-ADAuthenticationPolicy { throw 'the silo convergence should have had nothing to change' }
function Set-ADAuthenticationPolicySilo { throw 'the silo convergence should have had nothing to change' }
function Get-ADGroup { param($LDAPFilter) [pscustomobject]@{ DistinguishedName = "CN=group,$domainDn" } }
function Get-ADGroupMember {
    # Both role groups report both accounts, so de-duplication is exercised as well.
    @(
        [pscustomobject]@{ objectClass = 'user'; distinguishedName = $breakGlassDn },
        [pscustomobject]@{ objectClass = 'user'; distinguishedName = $templateDn }
    )
}
function Get-ADUser { param($Identity) [pscustomobject]@{ DistinguishedName = $Identity; SamAccountName = (($Identity -split ',')[0] -replace '^CN=') } }
function Get-ADComputer { }
function Get-ADObject { param($Identity, $Properties) [pscustomobject]@{ 'msDS-AssignedAuthNPolicySilo' = $script:SiloState[$Identity] } }
function Grant-ADAuthenticationPolicySiloAccess { }
function Revoke-ADAuthenticationPolicySiloAccess { }
function Set-ADAccountAuthenticationPolicySilo { param($Identity, $AuthenticationPolicySilo) $script:Assigned.Add($Identity); $script:SiloState[$Identity] = "CN=$AuthenticationPolicySilo,CN=Silos" }
function Set-ADObject { param($Identity, $Clear, $Server) $script:Cleared.Add($Identity); $script:SiloState[$Identity] = $null }

$silo = $shipped.authenticationPolicySilos[0]

Assert-That 'excludeFromSilo accounts are collected' ((Get-TierSiloExclusion -Configuration $shipped) -contains 'adm-t0-breakglass')

Reset-Actions
New-TierSingleAuthenticationSilo -Configuration $shipped -SiloDefinition $silo -Confirm:$false
Assert-That 'break-glass account is not assigned' ($script:Assigned -notcontains $breakGlassDn)
Assert-That 'template account is assigned' ($script:Assigned -contains $templateDn)
Assert-That 'each account is assigned once only' (@($script:Assigned | Where-Object { $_ -eq $templateDn }).Count -eq 1)

# A deployment made before the fix: the break-glass account is already in the silo.
$script:SiloState[$breakGlassDn] = "CN=$($silo.name),CN=AuthN Silos"
Reset-Actions
New-TierSingleAuthenticationSilo -Configuration $shipped -SiloDefinition $silo -AuditOnly -Confirm:$false
# @() because Windows PowerShell 5.1 gives a single [pscustomobject] no .Count.
$exclusion = @(Get-Actions 'SiloExclusion')
Assert-That 'audit reports an assigned break-glass account' ($exclusion.Count -eq 1 -and $exclusion[0].Result -eq 'Drift' -and $exclusion[0].Severity -eq 'High')
Assert-That 'audit does not change anything' ($script:Cleared.Count -eq 0)

Reset-Actions
New-TierSingleAuthenticationSilo -Configuration $shipped -SiloDefinition $silo -Confirm:$false
Assert-That 'deploy removes the break-glass account from the silo' ($script:Cleared -contains $breakGlassDn)
Assert-That 'the removal is reported' ((Get-Actions 'SiloExclusion')[0].Result -eq 'Updated')

# Audit now looks at the members as well.
$script:SiloState[$templateDn] = $null
Reset-Actions
New-TierSingleAuthenticationSilo -Configuration $shipped -SiloDefinition $silo -AuditOnly -Confirm:$false
$missing = @(Get-Actions 'SiloMember' | Where-Object Result -eq 'Missing')
Assert-That 'audit reports an unassigned silo member' ($missing.Count -eq 1 -and $missing[0].Target -eq 'adm-t0-template')

# =================================================================================================
Write-Host "`nGenerator defaults"
# =================================================================================================

$gen = New-TierModelConfiguration
$t0 = $gen.tiers[0]; $t1 = $gen.tiers[1]; $t2 = $gen.tiers[2]

$operatorOnServiceAccounts = @($gen.tiers | ForEach-Object { $_.delegations } | Where-Object { $_.principal -like '*-Operators' -and $_.targetOu -eq 'Service-Accounts' })
Assert-That 'no operator delegation on the service account OU' ($operatorOnServiceAccounts.Count -eq 0)
Assert-That 'no unscoped ExtendedRight anywhere' (@($gen.tiers | ForEach-Object { $_.delegations } | Where-Object { $_.rights -match 'ExtendedRight' -and -not $_.objectType -and $_.inheritance -ne 'Descendents' }).Count -eq 0)

$deny1 = $t1.groups | Where-Object { $_.name -eq $t1.denyLogonGroup }
$deny2 = $t2.groups | Where-Object { $_.name -eq $t2.denyLogonGroup }
$deny0 = $t0.groups | Where-Object { $_.name -eq $t0.denyLogonGroup }
Assert-That 'Tier 1 deny group lives in the top tier' ($deny1.targetOu -eq 'Tier-0/Groups')
Assert-That 'Tier 2 deny group lives in the top tier' ($deny2.targetOu -eq 'Tier-0/Groups')
Assert-That 'Tier 0 deny group stays in its own group OU' ($deny0.targetOu -eq 'Groups')
Assert-That 'Tier 2 exception group lives in the top tier' ($t2.gpos[0].exceptionGroupOu -eq 'Tier-0/Groups')

$gpOptionsDeny = { param($tier) @($tier.delegations | Where-Object { $_.type -eq 'Deny' -and $_.objectType -eq 'gPOptions' }) }
Assert-That 'Tier 1 admins are denied gPOptions' (@(& $gpOptionsDeny $t1).Count -eq 1)
Assert-That 'Tier 2 admins are denied gPOptions' (@(& $gpOptionsDeny $t2).Count -eq 1)
Assert-That 'Tier 0 admins keep gPOptions' (@(& $gpOptionsDeny $t0).Count -eq 0)

$allow = New-TierModelConfiguration -LogonRightsMode AllowList
Assert-That 'allow list keeps Users on workstations' ($allow.tiers[2].gpos[0].allowedUserRights.SeInteractiveLogonRight -contains 'S-1-5-32-545')
Assert-That 'allow list names only Administrators on servers' (@($allow.tiers[1].gpos[0].allowedUserRights.SeInteractiveLogonRight) -join ',' -eq 'S-1-5-32-544')

$net = New-TierModelConfiguration -DenyNetworkLogonAcrossTiers
$dcBaseline = $net.tiers[0].gpos | Where-Object { $_.targetOu -eq '$DomainControllers' }
Assert-That 'DC baseline never denies network logon to a tier group' (@($dcBaseline.userRights.SeDenyNetworkLogonRight | Where-Object { $_ -notlike 'S-1-*' }).Count -eq 0)
Assert-That 'tier GPOs still deny network logon when asked to' ($net.tiers[1].gpos[0].userRights.SeDenyNetworkLogonRight -contains $net.tiers[1].denyLogonGroup)

# =================================================================================================
Write-Host "`nShipped configuration"
# =================================================================================================

foreach ($tier in @($shipped.tiers | Select-Object -Skip 1)) {
    $denyGroup = $tier.groups | Where-Object { $_.name -eq $tier.denyLogonGroup }
    Assert-That "$($tier.name) deny group is in Tier-0/Groups" ($denyGroup.targetOu -eq 'Tier-0/Groups')
    Assert-That "$($tier.name) exception group is in Tier-0/Groups" (@($tier.gpos | Where-Object { $_.exceptionGroup -and $_.exceptionGroupOu -ne 'Tier-0/Groups' }).Count -eq 0)
    Assert-That "$($tier.name) admins are denied gPOptions" (@(& $gpOptionsDeny $tier).Count -eq 1)
}
Assert-That 'no operator delegation on Service-Accounts' (@($shipped.tiers | ForEach-Object { $_.delegations } | Where-Object { $_.targetOu -eq 'Service-Accounts' }).Count -eq 0)

# =================================================================================================
Write-Host "`nGroup placement"
# =================================================================================================

$script:Moves = [System.Collections.Generic.List[object]]::new()
function Get-TierAdParameter { @{ Server = 'dc01' } }
function Move-ADObject { param($Identity, $TargetPath, $Server) $script:Moves.Add([pscustomobject]@{ Identity = $Identity; Target = $TargetPath }) }

$target = "OU=Groups,OU=Tier-0,OU=Tiering,$domainDn"
Assert-That 'group in place is compliant' ((Move-TierObjectToOu -DistinguishedName "CN=DL-T2-DenyLogon,$target" -TargetOuDn $target -Confirm:$false) -eq 'Compliant')
Assert-That 'comparison ignores case' ((Move-TierObjectToOu -DistinguishedName "CN=DL-T2-DenyLogon,$($target.ToLower())" -TargetOuDn $target -Confirm:$false) -eq 'Compliant')
Assert-That 'an escaped comma is not a separator' ((Move-TierObjectToOu -DistinguishedName "CN=Deny\, legacy,$target" -TargetOuDn $target -Confirm:$false) -eq 'Compliant')
$legacyDn = "CN=DL-T2-DenyLogon,OU=Groups,OU=Tier-2,OU=Tiering,$domainDn"
Assert-That 'misplaced group is drift in audit' ((Move-TierObjectToOu -DistinguishedName $legacyDn -TargetOuDn $target -AuditOnly -Confirm:$false) -eq 'Drift')
Assert-That 'audit does not move anything' ($script:Moves.Count -eq 0)
Assert-That 'misplaced group is moved on deploy' ((Move-TierObjectToOu -DistinguishedName $legacyDn -TargetOuDn $target -Confirm:$false) -eq 'Updated' -and $script:Moves[0].Target -eq $target)
Assert-That 'plan mode does not move anything' ((Move-TierObjectToOu -DistinguishedName $legacyDn -TargetOuDn $target -WhatIf) -eq 'Planned' -and $script:Moves.Count -eq 1)

# =================================================================================================
Write-Host "`nStage isolation"
# =================================================================================================

Reset-Actions
$after = $false
Invoke-TierStage -Name 'GPO' -ScriptBlock { throw 'New-GPO: access denied' }
$after = $true
$stageFailure = @(Get-Actions 'Stage')
Assert-That 'a failing stage does not end the run' $after
Assert-That 'the failure is recorded' ($stageFailure.Count -eq 1 -and $stageFailure[0].Result -eq 'Failed' -and $stageFailure[0].Phase -eq 'GPO')

# =================================================================================================
Write-Host "`nPrivileged group membership"
# =================================================================================================

function Get-TierPrivilegedGroupReference { [pscustomobject]@{ Name = 'Domain Admins'; DistinguishedName = "CN=Domain Admins,CN=Users,$domainDn" } }
function Resolve-TierPrincipal { param($Reference, [switch]$AllowMissing) [pscustomobject]@{ Name = $Reference; SID = 'S-1-5-21-1-2-3-1100'; DistinguishedName = "CN=$Reference,$domainDn" } }
function Get-ADGroupMember { throw 'An unspecified error has occurred' }

Reset-Actions
$privileged = [pscustomobject]@{ mode = 'Report'; groups = @([pscustomobject]@{ sid = '512'; allowedMembers = @('G-T0-Admins') }) }
Set-TierPrivilegedGroupMembership -Configuration ([pscustomobject]@{ privilegedGroups = $privileged }) -AuditOnly -Confirm:$false
$groupActions = Get-Actions 'PrivilegedGroup'
Assert-That 'unreadable membership is not reported compliant' (@($groupActions | Where-Object Result -eq 'Compliant').Count -eq 0)
Assert-That 'unreadable membership is a High failure' (@($groupActions | Where-Object { $_.Result -eq 'Failed' -and $_.Severity -eq 'High' }).Count -eq 1)

# =================================================================================================
Write-Host "`nConfiguration migration"
# =================================================================================================

# Rebuild a 1.1.0 style configuration from the shipped one, run the updater on it, and expect the
# shipped configuration back.
$legacy = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
foreach ($tier in @($legacy.tiers)) {
    $isTop = $tier.id -eq $legacy.tiers[0].id
    $tier.delegations = @($tier.delegations | Where-Object { -not ($_.type -eq 'Deny' -and $_.objectType -eq 'gPOptions') })
    if ($tier.name -ne 'Tier-2') {
        $tier.delegations = @($tier.delegations) + [pscustomobject]@{
            principal = "G-$($tier.token)-Operators"; targetOu = 'Service-Accounts'; rights = 'ReadProperty, ExtendedRight'
            objectType = $null; inheritance = 'All'; type = 'Allow'; comment = 'Read gMSA password blobs'
        }
    }
    if (-not $isTop) {
        ($tier.groups | Where-Object { $_.name -eq $tier.denyLogonGroup }).targetOu = 'Groups'
        foreach ($gpo in @($tier.gpos | Where-Object exceptionGroup)) { $gpo.exceptionGroupOu = 'Groups' }
    }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) "adtierkit-migration-$PID"
New-Item -Path $work -ItemType Directory -Force | Out-Null
$legacyPath = Join-Path $work 'tiermodel.json'
$legacy | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $legacyPath -Encoding UTF8

$updater = Join-Path $PSScriptRoot '../Update-TierConfiguration.ps1'
$exit = Invoke-ChildScript -Arguments @('-File', $updater, '-Path', $legacyPath, '-SkipRoles')
Assert-That 'updater succeeds' ($exit -eq 0) "exit code $exit"

$migrated = Get-Content -Raw $legacyPath | ConvertFrom-Json
foreach ($tier in @($migrated.tiers)) {
    $isTop = $tier.id -eq $migrated.tiers[0].id
    Assert-That "$($tier.name): unscoped operator ACE removed" (@($tier.delegations | Where-Object { $_.rights -eq 'ReadProperty, ExtendedRight' -and -not $_.objectType }).Count -eq 0)
    if ($isTop) {
        Assert-That "$($tier.name): top tier gets no gPOptions deny" (@(& $gpOptionsDeny $tier).Count -eq 0)
        continue
    }
    Assert-That "$($tier.name): deny group moved to the top tier" (($tier.groups | Where-Object { $_.name -eq $tier.denyLogonGroup }).targetOu -eq 'Tier-0/Groups')
    Assert-That "$($tier.name): exception group moved to the top tier" (@($tier.gpos | Where-Object { $_.exceptionGroup -and $_.exceptionGroupOu -ne 'Tier-0/Groups' }).Count -eq 0)
    Assert-That "$($tier.name): gPOptions deny added" (@(& $gpOptionsDeny $tier).Count -eq 1)
}

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
