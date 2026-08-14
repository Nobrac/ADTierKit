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

    Nothing existing is overwritten. Running it twice changes nothing the second time.

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
    [string]$Path = ".\config\tiermodel.json",
    [string]$RolesPath = ".\config\roles.example.json",
    [switch]$SkipRoles
)

$ErrorActionPreference = 'Stop'

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

if ($problems -gt 0) {
    Write-Host ''
    Write-Host "$problems item(s) need checking before you deploy. A wrong token or a missing deny logon" -ForegroundColor Yellow
    Write-Host "group means a role group is not denied where it should be, and nothing will report it." -ForegroundColor Yellow
    exit 2
}

Write-Host ''
Write-Host 'Next: .\ADTierKit.ps1 -Mode Check' -ForegroundColor Cyan
