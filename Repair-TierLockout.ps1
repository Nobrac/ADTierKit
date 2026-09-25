<#
    .SYNOPSIS
    Recovers a domain controller from an ADTierKit logon lockout.

    .DESCRIPTION
    Undoes the situation in three steps, each verified before and after:

      1. Removes the built-in Administrator (RID 500) from every tier role group. That membership
         is what put the account into a deny group in the first place, because each tier's deny
         group holds the role groups of the other tiers.

      2. Restores the default holders of "Allow log on locally" on a domain controller. An
         emergency repair with secedit typically narrows this right to Administrators only, which
         silently drops Account, Server, Print and Backup Operators and Enterprise Domain
         Controllers.

      3. Re-checks the deny groups of the GPOs that reach this domain controller (the Domain
         Controllers OU, or wherever this machine sits) for critical identities - the account
         running this script, RID 500, and the members of Domain Admins - and reports whether
         re-enabling the tier GPOs would be safe. The deny groups of the other tiers are not
         checked: they contain the top tier role group by design, so every Domain Admin shows up
         in them, and a check that fires on every correctly configured domain can never pass.

    The GPO links stay disabled unless -EnableGpoLinks is passed. Re-enabling them is the one
    irreversible-feeling step, so it is a deliberate act and only runs when step 3 came back clean.

    Run this on the domain controller, elevated, as a member of Domain Admins.

    .PARAMETER ConfigurationPath
    The ADTierKit configuration. Used to learn the tier role group and deny group names.

    .PARAMETER SkipUserRightsRestore
    Leaves the local user rights alone. Use this if you deliberately want the hardened
    Administrators-only setting rather than the Windows default.

    .PARAMETER EnableGpoLinks
    Re-enables the tier GPO links, but only if no lockout risk remains.

    .EXAMPLE
    .\Repair-TierLockout.ps1 -WhatIf

    Shows what would be changed without touching anything.

    .EXAMPLE
    .\Repair-TierLockout.ps1

    Removes the memberships and restores the user rights. Leaves the GPO links disabled.

    .EXAMPLE
    .\Repair-TierLockout.ps1 -EnableGpoLinks

    The same, and re-enables the tier GPOs if the lockout check is clean.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Default: config\tiermodel.json next to this script.
    [string]$ConfigurationPath,
    [switch]$SkipUserRightsRestore,
    [switch]$EnableGpoLinks
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is empty while parameter defaults are bound under Windows PowerShell 5.1 (-File),
# so the script folder is resolved here, after binding, with two fallbacks.
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot -and $MyInvocation.MyCommand.Path) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }
if (-not $ConfigurationPath) { $ConfigurationPath = Join-Path $scriptRoot 'config\tiermodel.json' }

function Write-Step {
    param([string]$Text, [string]$Level = 'Info')
    $colour = switch ($Level) {
        'Good' { 'Green' }
        'Warn' { 'Yellow' }
        'Bad' { 'Red' }
        'Head' { 'Cyan' }
        default { 'Gray' }
    }
    $prefix = switch ($Level) {
        'Good' { '  [+] ' }
        'Warn' { '  [!] ' }
        'Bad' { '  [x] ' }
        'Head' { '' }
        default { '  [i] ' }
    }
    if ($Level -eq 'Head') { Write-Host '' }
    Write-Host "$prefix$Text" -ForegroundColor $colour
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction SilentlyContinue

Write-Step '=== ADTierKit lockout recovery ===' -Level Head

# ---------------------------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------------------------
$domain = Get-ADDomain
$domainSid = $domain.DomainSID.Value
$administrator = Get-ADUser -Identity "$domainSid-500" -Properties MemberOf

Write-Step "Domain: $($domain.DNSRoot)"
Write-Step "Built-in Administrator: $($administrator.SamAccountName)"

if (-not (Test-Path -LiteralPath $ConfigurationPath)) {
    throw "Configuration not found: $ConfigurationPath. Pass -ConfigurationPath explicitly."
}
$config = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json
Write-Step "Configuration: $ConfigurationPath"

# Every group the configuration defines, split into role groups and deny groups.
$roleGroupNames = [System.Collections.Generic.List[string]]::new()
$denyGroupNames = [System.Collections.Generic.List[string]]::new()

foreach ($tier in $config.tiers) {
    foreach ($group in $tier.groups) {
        if ($group.scope -eq 'Global') { $roleGroupNames.Add($group.name) }
    }
    foreach ($gpo in @($tier.gpos)) {
        foreach ($right in ($gpo.userRights.PSObject.Properties.Name | Where-Object { $_ -like 'SeDeny*Logon*' })) {
            foreach ($reference in @($gpo.userRights.$right)) {
                if ($reference -notlike 'S-1-*' -and $denyGroupNames -notcontains $reference) {
                    $denyGroupNames.Add($reference)
                }
            }
        }
    }
}

Write-Step "Tier role groups: $($roleGroupNames -join ', ')"
Write-Step "Deny groups: $($denyGroupNames -join ', ')"

$links = @()
# The configuration calls this key 'rootOu'. Guessing the name once produced 'OU=,DC=...',
# which ADSI rejects with 0x80005000 - so it is read defensively and verified.
$rootOuName = $config.domain.rootOu
if ([string]::IsNullOrWhiteSpace($rootOuName)) {
    throw "The configuration has no domain.rootOu value - cannot determine the tier model root."
}
$rootDn = "OU=$rootOuName,$($domain.DistinguishedName)"
foreach ($tier in $config.tiers) {
    foreach ($gpo in @($tier.gpos)) {
        $target = if ($gpo.targetOu -eq '$DomainControllers') { $domain.DomainControllersContainer }
        elseif ($gpo.targetOu -eq '$ModelRoot') { $rootDn }
        elseif ([string]::IsNullOrWhiteSpace($gpo.targetOu)) { "OU=$($tier.name),$rootDn" }
        elseif ($gpo.targetOu -match '^(OU|CN|DC)=') { $gpo.targetOu }
        elseif ($gpo.targetOu -like '*/*') {
            $segments = @($gpo.targetOu.Split('/') | Where-Object { $_ })
            [array]::Reverse($segments)
            (($segments | ForEach-Object { "OU=$_" }) -join ',') + ",$rootDn"
        }
        else { "OU=$($gpo.targetOu),OU=$($tier.name),$rootDn" }
        $exists = $null -ne (Get-ADObject -Filter "distinguishedName -eq '$target'" -ErrorAction SilentlyContinue)

        # Deny groups of this GPO - needed for the lockout re-check below.
        $gpoDenyGroups = @()
        foreach ($right in ($gpo.userRights.PSObject.Properties.Name | Where-Object { $_ -like 'SeDeny*Logon*' })) {
            $gpoDenyGroups += @($gpo.userRights.$right | Where-Object { $_ -and $_ -notlike 'S-1-*' })
        }

        $links += [pscustomobject]@{
            Name       = $gpo.name
            Target     = $target
            Exists     = $exists
            DenyGroups = @($gpoDenyGroups | Sort-Object -Unique)
        }
    }
}

# The machines whose logon has to survive: the Domain Controllers OU and this computer.
$protectedTargets = @($domain.DomainControllersContainer)
try { $protectedTargets += (Get-ADComputer -Identity $env:COMPUTERNAME -ErrorAction Stop).DistinguishedName }
catch { Write-Step 'This machine was not found in the directory - only the Domain Controllers OU is considered' -Level Warn }

$reachingLinks = @($links | Where-Object {
        $linkTarget = $_.Target
        @($protectedTargets | Where-Object { $_ -eq $linkTarget -or $_ -like "*,$linkTarget" }).Count -gt 0
    })

# ---------------------------------------------------------------------------------------------
# 1. Remove the built-in Administrator from the tier role groups
# ---------------------------------------------------------------------------------------------
Write-Step '--- Step 1: tier role group membership ---' -Level Head

$removed = 0
foreach ($groupName in $roleGroupNames) {
    $group = Get-ADGroup -LDAPFilter "(sAMAccountName=$groupName)" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $group) {
        Write-Step "$groupName does not exist - skipped"
        continue
    }

    $members = @(Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue)
    if ($members.SID.Value -notcontains $administrator.SID.Value) {
        Write-Step "$groupName does not contain the Administrator"
        continue
    }

    if ($PSCmdlet.ShouldProcess($groupName, "Remove $($administrator.SamAccountName)")) {
        Remove-ADGroupMember -Identity $group.DistinguishedName -Members $administrator.DistinguishedName -Confirm:$false
        Write-Step "$groupName : Administrator removed" -Level Good
        $removed++
    }
}

if ($removed -eq 0) {
    Write-Step 'No role group memberships had to be removed'
}

# ---------------------------------------------------------------------------------------------
# 2. Restore the default logon rights on this domain controller
# ---------------------------------------------------------------------------------------------
Write-Step '--- Step 2: local user rights ---' -Level Head

if ($SkipUserRightsRestore) {
    Write-Step 'Skipped on request - the current (hardened) setting is kept'
}
elseif (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore the default logon rights')) {
    Write-Step 'Would restore the default holders of the interactive logon rights'
}
else {
    # secedit only changes the local database. A tier GPO that still applies here writes its deny
    # entries back at the next policy refresh - on a domain controller within five minutes.
    if (Get-Command Get-GPInheritance -ErrorAction SilentlyContinue) {
        foreach ($link in ($reachingLinks | Where-Object Exists)) {
            try {
                $inheritance = Get-GPInheritance -Target $link.Target -Domain $domain.DNSRoot -ErrorAction Stop
                $live = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $link.Name -and $_.Enabled }
                if ($live) {
                    Write-Step "$($link.Name) is still linked and enabled on $($link.Target) - disable the link first, or the next policy refresh undoes this step" -Level Warn
                }
            }
            catch { Write-Step "Link state of $($link.Name) could not be read - $($_.Exception.Message)" -Level Warn }
        }
    }

    # The Windows default on a domain controller. Administrators plus the four operator groups
    # and Enterprise Domain Controllers for interactive logon; Administrators for remote.
    # The deny entries are cleared: the tier model re-applies them once the GPOs are back on.
    $template = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-548,*S-1-5-32-549,*S-1-5-32-550,*S-1-5-32-551,*S-1-5-9
SeRemoteInteractiveLogonRight = *S-1-5-32-544
SeDenyInteractiveLogonRight =
SeDenyRemoteInteractiveLogonRight =
SeDenyBatchLogonRight =
SeDenyServiceLogonRight =
'@

    $workDir = Join-Path $env:TEMP 'ADTierKit-Repair'
    if (-not (Test-Path -LiteralPath $workDir)) { New-Item -Path $workDir -ItemType Directory -Force | Out-Null }
    $infPath = Join-Path $workDir 'restore.inf'
    $dbPath = Join-Path $workDir 'restore.sdb'
    $logPath = Join-Path $workDir 'restore.log'

    $template | Set-Content -LiteralPath $infPath -Encoding Unicode
    & secedit.exe /configure /db $dbPath /cfg $infPath /areas USER_RIGHTS /log $logPath /quiet

    if ($LASTEXITCODE -eq 0) {
        Write-Step 'Default logon rights restored' -Level Good
    }
    else {
        Write-Step "secedit returned exit code $LASTEXITCODE - see $logPath" -Level Warn
    }

    # Show the result so the outcome is visible rather than assumed.
    $checkPath = Join-Path $workDir 'check.txt'
    & secedit.exe /export /areas USER_RIGHTS /cfg $checkPath /quiet
    Select-String -Path $checkPath -Pattern 'InteractiveLogonRight' | ForEach-Object {
        Write-Step "  $($_.Line.Trim())"
    }
}

# ---------------------------------------------------------------------------------------------
# 3. Re-check for remaining lockout risk
# ---------------------------------------------------------------------------------------------
Write-Step '--- Step 3: lockout re-check ---' -Level Head

$critical = @{}
try {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $critical[$me.User.Value] = "the account running this script ($($me.Name))"
}
catch { }
$critical["$domainSid-500"] = 'the built-in Administrator'

$domainAdmins = Get-ADGroup -Identity "$domainSid-512" -ErrorAction SilentlyContinue
if ($domainAdmins) {
    foreach ($member in @(Get-ADGroupMember -Identity $domainAdmins.DistinguishedName -Recursive -ErrorAction SilentlyContinue)) {
        if (-not $critical.ContainsKey($member.SID.Value)) {
            $critical[$member.SID.Value] = "$($member.name), a member of $($domainAdmins.Name)"
        }
    }
}

$reachingDenyGroups = @($reachingLinks | ForEach-Object { $_.DenyGroups } | Where-Object { $_ } | Sort-Object -Unique)
Write-Step "GPOs reaching this machine: $(if ($reachingLinks) { ($reachingLinks.Name -join ', ') } else { 'none' })"

$problems = [System.Collections.Generic.List[string]]::new()
foreach ($groupName in $reachingDenyGroups) {
    $group = Get-ADGroup -LDAPFilter "(sAMAccountName=$groupName)" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $group) { continue }

    foreach ($member in @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction SilentlyContinue)) {
        if ($critical.ContainsKey($member.SID.Value)) {
            $problems.Add("$groupName (denied on this machine) still contains $($critical[$member.SID.Value])")
        }
    }
}

if ($problems.Count -eq 0) {
    Write-Step 'No critical account is in any deny group - re-enabling the tier GPOs is safe' -Level Good
}
else {
    foreach ($problem in $problems) { Write-Step $problem -Level Bad }
    Write-Step 'Resolve these before re-enabling the tier GPOs' -Level Warn
}

# ---------------------------------------------------------------------------------------------
# 4. Optionally re-enable the GPO links
# ---------------------------------------------------------------------------------------------
Write-Step '--- Step 4: GPO links ---' -Level Head

if (-not $EnableGpoLinks) {
    Write-Step 'Links left disabled. Re-run with -EnableGpoLinks once you are ready:'
    foreach ($link in $links) {
        $mark = if ($link.Exists) { '' } else { '   (target missing)' }
        Write-Step "  $($link.Name) -> $($link.Target)$mark"
    }
}
elseif ($problems.Count -gt 0) {
    Write-Step 'Refusing to re-enable the links while a lockout risk remains' -Level Bad
}
else {
    foreach ($link in $links) {
        if (-not $link.Exists) {
            Write-Step "$($link.Name) : target $($link.Target) does not exist - skipped" -Level Warn
            continue
        }
        if ($PSCmdlet.ShouldProcess($link.Name, "Enable link on $($link.Target)")) {
            try {
                Set-GPLink -Name $link.Name -Target $link.Target -LinkEnabled Yes -Domain $domain.DNSRoot | Out-Null
                Write-Step "$($link.Name) -> enabled" -Level Good
            }
            catch {
                Write-Step "$($link.Name) : $($_.Exception.Message)" -Level Warn
            }
        }
    }
    Write-Step 'Run gpupdate /force and verify a logon BEFORE closing your current session' -Level Warn
}

Write-Step '=== Done ===' -Level Head
Write-Step 'Keep this session open until you have confirmed a fresh logon works.' -Level Warn
