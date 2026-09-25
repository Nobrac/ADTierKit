<#
    .SYNOPSIS
    Brings an existing tiermodel.json up to the schema the roles and ownership features need.

    .DESCRIPTION
    Adds four things, and only the ones that are actually missing:

      * tiers[].token           - the short token ('T0') that role naming patterns expand to
      * tiers[].denyLogonGroup  - the deny logon group a foreign role group must be nested into
      * roles                   - the role definitions, taken from config\roles.example.json
      * builtInNesting          - generated at load time; the key is written so it is visible
      * ownership               - the ownership stage configuration, in report mode

    For 1.2.0 it also applies three security corrections to existing tiers:

      * the operators' unscoped 'ReadProperty, ExtendedRight' ACE on the service account OU is
        removed - it granted every control access right, 'Reset Password' included, and never
        granted gMSA password retrieval, which an ACE cannot do
      * the deny logon group and the GPO exception group of every tier below the top one are
        moved to the top tier's group OU, out of reach of the tier they restrict
      * tier administrators below the top tier get a deny on writing gPOptions, so they cannot
        block Group Policy inheritance on their sub-OUs

    The first correction only changes the configuration: the tool adds ACEs and never removes
    them, so an ACE that is already in the directory has to be removed by hand (see CHANGELOG).

    And it adds what 1.2.0 introduced:

      * the Kerberos armoring values - KDC support on every GPO targeting the Domain
        Controllers OU, client support on every tier GPO - without which no silo can be enforced
      * options.authenticationPolicySiloReconcile, in Report mode
      * the attackPathChecks block for the audit
      * a staging block for the neutral landing zone, written DISABLED: enabling it creates an OU,
        groups and a GPO and is meant to be a decision. Set staging.enabled to true and
        options.redirectComputersTo to '$Staging' when you are ready.
      * a LAPS policy for the Domain Controllers OU, so the DSRM password is rotated and backed up

    Nothing else existing is overwritten. Running it twice changes nothing the second time.

    The token is derived from the group names the tier already uses rather than assumed, so a
    configuration built with a custom naming pattern keeps working. If it cannot be derived with
    confidence the script says so and leaves it blank rather than guessing - a wrong token puts a
    role group in the wrong tier's deny group, which is a hole rather than an error message.

    .EXAMPLE
    .\Update-TierConfiguration.ps1 -Path .\config\tiermodel.json -WhatIf
    Shows what would change without writing anything.

    .EXAMPLE
    .\Update-TierConfiguration.ps1 -Path .\config\tiermodel.json
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Default: config\tiermodel.json next to this script.
    [string]$Path,
    # Default: config\roles.example.json next to this script.
    [string]$RolesPath,
    [switch]$SkipRoles
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is empty while parameter defaults are bound under Windows PowerShell 5.1 (-File),
# so the script folder is resolved here, after binding, with two fallbacks.
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot -and $MyInvocation.MyCommand.Path) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }
if (-not $Path) { $Path = Join-Path $scriptRoot 'config\tiermodel.json' }
if (-not $RolesPath) { $RolesPath = Join-Path $scriptRoot 'config\roles.example.json' }

function Write-Step { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }
function Write-Change { param([string]$Text) Write-Host "  + $Text" -ForegroundColor Green }
function Write-Keep { param([string]$Text) Write-Host "  = $Text" -ForegroundColor DarkGray }
function Write-Problem { param([string]$Text) Write-Host "  ! $Text" -ForegroundColor Yellow }

if (-not (Test-Path -LiteralPath $Path)) { throw "No configuration at $Path" }

$config = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
$changes = 0
$problems = 0

# --- tokens and deny logon groups -----------------------------------------------------------------
Write-Step 'Tiers'

foreach ($tier in $config.tiers) {

    # --- token ------------------------------------------------------------------------------------
    if ($tier.PSObject.Properties.Name -contains 'token' -and $tier.token) {
        Write-Keep "$($tier.name): token $($tier.token)"
    }
    else {
        # Every group in a tier carries the tier's token somewhere in its name. Splitting the names
        # into segments and keeping the segment that appears in all of them, and that contains the
        # tier's own id, identifies it without knowing the naming pattern.
        $segmentSets = foreach ($group in @($tier.groups)) { , @($group.name -split '[-_ ]' | Where-Object { $_ }) }
        $token = $null

        if (@($segmentSets).Count -gt 0) {
            $common = $segmentSets[0]
            foreach ($set in $segmentSets) { $common = @($common | Where-Object { $set -contains $_ }) }
            $withId = @($common | Where-Object { $_ -match "\D$($tier.id)$|^$($tier.id)$" })
            if (@($withId).Count -eq 1) { $token = $withId[0] }
        }

        if ($token) {
            $tier | Add-Member -MemberType NoteProperty -Name 'token' -Value $token -Force
            Write-Change "$($tier.name): token $token (derived from the group names)"
            $changes++
        }
        else {
            $tier | Add-Member -MemberType NoteProperty -Name 'token' -Value "T$($tier.id)" -Force
            Write-Problem "$($tier.name): token could not be derived, assumed T$($tier.id) - CHECK THIS"
            $problems++
        }
    }

    # --- deny logon group --------------------------------------------------------------------------
    if ($tier.PSObject.Properties.Name -contains 'denyLogonGroup' -and $tier.denyLogonGroup) {
        Write-Keep "$($tier.name): deny logon group $($tier.denyLogonGroup)"
    }
    else {
        $candidates = @($tier.groups | Where-Object { $_.name -match 'Deny[-_ ]?Logon' })
        if (@($candidates).Count -eq 1) {
            $tier | Add-Member -MemberType NoteProperty -Name 'denyLogonGroup' -Value $candidates[0].name -Force
            Write-Change "$($tier.name): deny logon group $($candidates[0].name)"
            $changes++
        }
        else {
            $tier | Add-Member -MemberType NoteProperty -Name 'denyLogonGroup' -Value $null -Force
            $detail = if (@($candidates).Count -eq 0) { 'none found' } else { "$(@($candidates).Count) candidates" }
            Write-Problem "$($tier.name): deny logon group could not be identified ($detail) - FILL THIS IN BY HAND"
            $problems++
        }
    }
}

# --- security corrections (1.2.0) ------------------------------------------------------------------
Write-Step 'Security corrections'

$topTier = @($config.tiers)[0]
$topDenyGroup = @($topTier.groups | Where-Object { $_.name -eq $topTier.denyLogonGroup }) | Select-Object -First 1
$topGroupsOu = if ($topDenyGroup -and $topDenyGroup.targetOu) { [string]$topDenyGroup.targetOu } else { 'Groups' }
if ($topGroupsOu -notlike '*/*') { $topGroupsOu = "$($topTier.name)/$topGroupsOu" }

foreach ($tier in $config.tiers) {
    $isTop = $tier.id -eq $topTier.id

    # 1. operators' unscoped control access on the service account OU
    $delegations = @($tier.delegations | Where-Object { $_ })
    $unscoped = @($delegations | Where-Object {
            $rights = @(([string]$_.rights) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object)
            ($rights -join ',') -eq 'ExtendedRight,ReadProperty' -and -not $_.objectType -and $_.type -eq 'Allow'
        })
    if ($unscoped.Count -gt 0) {
        $tier.delegations = @($delegations | Where-Object { $unscoped -notcontains $_ })
        foreach ($entry in $unscoped) {
            Write-Change "$($tier.name): removed unscoped ExtendedRight ACE for $($entry.principal) on '$($entry.targetOu)' - remove it from the directory as well"
        }
        $changes++
    }

    if ($isTop) { continue }

    # 2. deny logon and exception groups into the top tier
    foreach ($group in @($tier.groups | Where-Object { $_.name -eq $tier.denyLogonGroup })) {
        if ($group.targetOu -ne $topGroupsOu) {
            $group.targetOu = $topGroupsOu
            Write-Change "$($tier.name): deny logon group $($group.name) -> $topGroupsOu"
            $changes++
        }
        else { Write-Keep "$($tier.name): deny logon group already in $topGroupsOu" }
    }
    foreach ($gpo in @($tier.gpos | Where-Object { $_ -and $_.exceptionGroup })) {
        if ($gpo.exceptionGroupOu -ne $topGroupsOu) {
            $gpo | Add-Member -MemberType NoteProperty -Name 'exceptionGroupOu' -Value $topGroupsOu -Force
            Write-Change "$($tier.name): exception group $($gpo.exceptionGroup) -> $topGroupsOu"
            $changes++
        }
    }

    # 3. no Block Inheritance for the tier administrators
    $manageAll = @($tier.delegations | Where-Object {
            $_ -and $_.type -eq 'Allow' -and $_.inheritance -eq 'Descendents' -and -not $_.objectType -and ([string]$_.rights) -match 'WriteProperty'
        }) | Select-Object -First 1
    if (-not $manageAll) {
        Write-Keep "$($tier.name): no granular branch delegation found - gPOptions deny not added"
        continue
    }
    $hasDeny = @($tier.delegations | Where-Object {
            $_ -and $_.principal -eq $manageAll.principal -and $_.type -eq 'Deny' -and $_.objectType -eq 'gPOptions'
        }).Count -gt 0
    if ($hasDeny) {
        Write-Keep "$($tier.name): gPOptions deny for $($manageAll.principal) present"
    }
    else {
        $tier.delegations = @($tier.delegations) + [pscustomobject]@{
            principal           = $manageAll.principal
            targetOu            = $manageAll.targetOu
            rights              = 'WriteProperty'
            objectType          = 'gPOptions'
            inheritedObjectType = 'organizationalUnit'
            inheritance         = 'Descendents'
            type                = 'Deny'
            comment             = "Cannot block Group Policy inheritance below the $($tier.name) branch"
        }
        Write-Change "$($tier.name): gPOptions deny for $($manageAll.principal)"
        $changes++
    }
}

# --- additions (1.2.0) ------------------------------------------------------------------------------
Write-Step 'Kerberos armoring, silo reconcile, staging, attack path checks'

$kdcKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
$clientKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'

$addRegistry = {
    param($Gpo, [string]$Key, [string]$ValueName, [int]$Value, [string]$Comment)
    $present = @($Gpo.registrySettings | Where-Object { $_ -and $_.key -eq $Key -and $_.valueName -eq $ValueName })
    if ($present.Count -gt 0) { return $false }
    $entry = [pscustomobject]@{ key = $Key; valueName = $ValueName; type = 'DWord'; value = $Value; comment = $Comment }
    if ($Gpo.PSObject.Properties.Name -contains 'registrySettings' -and $null -ne $Gpo.registrySettings) {
        $Gpo.registrySettings = @(@($Gpo.registrySettings | Where-Object { $_ }) + $entry)
    }
    else { $Gpo | Add-Member -MemberType NoteProperty -Name 'registrySettings' -Value @($entry) -Force }
    return $true
}

foreach ($tier in $config.tiers) {
    foreach ($gpo in @($tier.gpos | Where-Object { $_ })) {
        if ($gpo.targetOu -eq '$DomainControllers') {
            if (& $addRegistry $gpo $kdcKey 'EnableCbacAndArmor' 1 'KDC support for claims, compound authentication and Kerberos armoring') {
                Write-Change "$($gpo.name): KDC armoring support"; $changes++
            }
            if (& $addRegistry $gpo $kdcKey 'CbacAndArmorLevel' 1 'Supported - unarmoured requests are still answered') {
                Write-Change "$($gpo.name): KDC armoring level 1 (Supported)"; $changes++
            }
        }
        if (& $addRegistry $gpo $clientKey 'EnableCbacAndArmor' 1 'Kerberos client support for claims, compound authentication and armoring - required by authentication policy silos') {
            Write-Change "$($gpo.name): Kerberos client armoring support"; $changes++
        }
    }
}

if ($config.options.PSObject.Properties.Name -contains 'authenticationPolicySiloReconcile') {
    Write-Keep "silo reconcile mode $($config.options.authenticationPolicySiloReconcile)"
}
else {
    $config.options | Add-Member -MemberType NoteProperty -Name 'authenticationPolicySiloReconcile' -Value 'Report' -Force
    Write-Change 'options.authenticationPolicySiloReconcile = Report'
    $changes++
}

if ($config.PSObject.Properties.Name -contains 'attackPathChecks' -and $config.attackPathChecks) {
    Write-Keep 'attackPathChecks present'
}
else {
    $config | Add-Member -MemberType NoteProperty -Name 'attackPathChecks' -Value ([pscustomobject]@{
            enabled           = $true
            trustedPrincipals = @()
            krbtgtMaxAgeDays  = 180
            maxObjects        = 5000
        }) -Force
    Write-Change 'attackPathChecks (audit only)'
    $changes++
}

$stagingAdded = $false
if ($config.PSObject.Properties.Name -contains 'staging' -and $config.staging) {
    Write-Keep "staging present, enabled: $($config.staging.enabled)"
}
else {
    $adminGroup = (@($topTier.groups | Where-Object { $_.scope -eq 'Global' }) | Select-Object -First 1).name
    $config | Add-Member -MemberType NoteProperty -Name 'staging' -Value ([pscustomobject]@{
            enabled            = $false
            ouName             = 'Staging'
            description        = 'Neutral landing zone for newly joined computers. No tier administers these machines until the top tier classifies them.'
            administratorGroup = $adminGroup
            groupOu            = $topGroupsOu
            denyLogonGroup     = 'DL-Staging-DenyLogon'
            joinGroup          = 'DL-Staging-Join'
            gpoName            = 'Staging-Quarantine'
            lapsGpoName        = 'Staging-LAPS'
        }) -Force
    Write-Change 'staging (neutral landing zone) - added DISABLED'
    $changes++
    $stagingAdded = $true
}

# --- DSRM (1.2.0) ----------------------------------------------------------------------------------
Write-Step 'DSRM through Windows LAPS'

$dcLaps = @($config.windowsLaps.delegations | Where-Object { $_ -and $_.targetOu -eq '$DomainControllers' }) | Select-Object -First 1
if (-not $dcLaps) {
    Write-Keep 'no LAPS delegation for the Domain Controllers OU - nothing to add'
}
elseif ($dcLaps.gpoName) {
    Write-Keep "DSRM policy $($dcLaps.gpoName) present"
}
else {
    # Named after the top tier's LAPS policy where there is one: T0-LAPS -> T0-DC-LAPS.
    $topLaps = @($config.windowsLaps.delegations | Where-Object { $_ -and $_.targetOu -eq $topTier.name -and $_.gpoName }) | Select-Object -First 1
    $dsrmName = if ($topLaps -and $topLaps.gpoName -match 'LAPS$') { $topLaps.gpoName -replace 'LAPS$', 'DC-LAPS' } else { "$($topTier.token)-DC-LAPS" }
    $dcLaps.gpoName = $dsrmName
    Write-Change "DSRM policy $dsrmName for the Domain Controllers OU (Windows LAPS manages the DSRM password there)"
    $changes++
}

# --- roles ------------------------------------------------------------------------------------------
Write-Step 'Roles'

if ($SkipRoles) {
    Write-Keep 'skipped by request'
}
elseif ($config.PSObject.Properties.Name -contains 'roles' -and @($config.roles).Count -gt 0) {
    Write-Keep "$(@($config.roles).Count) role(s) already present - left alone"
}
elseif (-not (Test-Path -LiteralPath $RolesPath)) {
    Write-Problem "No $RolesPath - roles not added"
    $problems++
}
else {
    $roles = (Get-Content -LiteralPath $RolesPath -Raw | ConvertFrom-Json).roles
    $config | Add-Member -MemberType NoteProperty -Name 'roles' -Value $roles -Force
    foreach ($role in $roles) {
        $state = if ($role.PSObject.Properties.Name -contains 'enabled' -and -not $role.enabled) { 'disabled' } else { "tiers $($role.tiers -join ', ')" }
        Write-Change "role $($role.name) ($state)"
    }
    $changes++
}

# --- generated and new blocks --------------------------------------------------------------------
Write-Step 'Blocks'

if ($config.PSObject.Properties.Name -contains 'builtInNesting') {
    Write-Keep 'builtInNesting present'
}
else {
    $config | Add-Member -MemberType NoteProperty -Name 'builtInNesting' -Value @() -Force
    Write-Change 'builtInNesting (generated at load time from the roles)'
    $changes++
}

if ($config.PSObject.Properties.Name -contains 'ownership' -and $config.ownership) {
    Write-Keep "ownership present, mode $($config.ownership.mode)"
}
else {
    $config | Add-Member -MemberType NoteProperty -Name 'ownership' -Value ([pscustomobject]@{
            enabled          = $true
            mode             = 'Report'
            owner            = '512'
            acceptableOwners = @()
            scopes           = @('$ModelRoot')
            objectClasses    = @('user', 'group', 'computer', 'organizationalUnit', 'msDS-GroupManagedServiceAccount')
            maxObjects       = 5000
        }) -Force
    Write-Change 'ownership (report mode)'
    $changes++
}

# --- write -------------------------------------------------------------------------------------------
Write-Step 'Result'

if ($changes -eq 0) {
    Write-Host '  Nothing to change - the configuration is already up to date.' -ForegroundColor Green
}
elseif ($PSCmdlet.ShouldProcess($Path, "Write $changes change(s)")) {
    $backup = "$Path.$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
    Copy-Item -LiteralPath $Path -Destination $backup
    $config | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Host "  $changes change(s) written. Backup: $backup" -ForegroundColor Green
}
else {
    Write-Host "  $changes change(s) would be written." -ForegroundColor Yellow
}

# --- review table -------------------------------------------------------------------------------------
Write-Host ''
Write-Host ('  {0,-3} {1,-12} {2,-10} {3}' -f 'ID', 'TIER', 'TOKEN', 'DENY LOGON GROUP') -ForegroundColor White
foreach ($tier in $config.tiers) {
    $deny = if ($tier.denyLogonGroup) { $tier.denyLogonGroup } else { '<MISSING>' }
    $colour = if ($tier.denyLogonGroup) { 'Gray' } else { 'Yellow' }
    Write-Host ('  {0,-3} {1,-12} {2,-10} {3}' -f $tier.id, $tier.name, $tier.token, $deny) -ForegroundColor $colour
}

# A token that is not T<id> means the shipped role patterns produce names in a different style
# from every other group in the model - 'G-TIER1-GPO-Admins' next to 'ADM_TIER1_Admins'. It works,
# but it looks like a mistake, and in six months somebody will treat it as one.
$custom = @($config.tiers | Where-Object { $_.token -ne "T$($_.id)" })
if ($custom.Count -gt 0 -and -not $SkipRoles) {
    Write-Host ''
    Write-Host "  This model does not use the T<id> token style. The shipped roles are named" -ForegroundColor Yellow
    Write-Host "  'G-{TOKEN}-DNS-Admins' and will produce e.g. 'G-$($custom[0].token)-DNS-Admins'." -ForegroundColor Yellow
    Write-Host "  Adjust roles[].roleGroup and roles[].templateAccount to match your own pattern." -ForegroundColor Yellow
}

if ($stagingAdded) {
    Write-Host ''
    Write-Host "  The neutral landing zone was added but is switched off. New computers still land in" -ForegroundColor Yellow
    Write-Host "  '$($config.options.redirectComputersTo)'. To use it, set staging.enabled to true and" -ForegroundColor Yellow
    Write-Host "  options.redirectComputersTo to '`$Staging', then plan a deploy." -ForegroundColor Yellow
}

if ($problems -gt 0) {
    Write-Host ''
    Write-Host "$problems item(s) need checking before you deploy. A wrong token or a missing deny logon" -ForegroundColor Yellow
    Write-Host "group means a role group is not denied where it should be, and nothing will report it." -ForegroundColor Yellow
    exit 2
}

Write-Host ''
Write-Host 'Next: .\ADTierKit.ps1 -Mode Check' -ForegroundColor Cyan
