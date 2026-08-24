<#
    .SYNOPSIS
    ADTierKit - deployment and auditing of an Active Directory administrative tier model.

    .DESCRIPTION
    Single file tool. Everything except the configuration data lives in this script.

    Modes:
      Wizard   asks for the naming convention, previews the result, writes the configuration
               file and optionally starts the deployment. This is the default.
      Deploy   applies an existing configuration file. Idempotent, supports -WhatIf.
      Audit    read only drift and hygiene report.
      Sync     re-runs only the membership stages: group nesting and authentication silo
               assignment. Safe to schedule; touches no structure, delegation or policy.
      Check    prerequisite check only.
      InstallTask  registers a daily scheduled task that runs Sync as SYSTEM.

    The configuration itself stays in a separate JSON file on purpose: it is data, it is what
    you review, diff and keep under version control, and both Deploy and Audit read from it.

    .PARAMETER Mode
    Wizard (default), Deploy, Audit or Check.

    .PARAMETER ConfigurationPath
    Path to the JSON configuration. Defaults to .\config\tiermodel.json next to this script.

    .PARAMETER Stage
    Deploy mode only. Restricts the run to individual stages for a staged rollout.

    .PARAMETER Server
    Target domain controller. Defaults to the PDC emulator of the domain.

    .PARAMETER UseDefaults
    Wizard mode only. Accepts every default without prompting.

    .PARAMETER Apply
    Deploy mode only. Without it the run only plans and reports; nothing is written.

    .PARAMETER Force
    Continues even if the prerequisite check reports findings, and skips the safety questions.

    .NOTES
    Version:  1.1.0
    License:  MIT
    Requires: Windows PowerShell 5.1, ActiveDirectory and GroupPolicy modules, Domain Admin.

    Tested against a Windows Server 2025 domain at functional level Windows2025Domain. Written
    for Windows PowerShell 5.1 specifically - it is what ships on a domain controller, and it is
    stricter than PowerShell 7 in places that matter (empty collections bound to typed
    parameters, for one).

    .EXAMPLE
    .\ADTierKit.ps1

    Runs the interactive rollout wizard.

    .EXAMPLE
    .\ADTierKit.ps1 -Mode Deploy

    Plans the deployment against the existing configuration. Writes nothing, produces a full
    plan report. This is what Deploy does unless -Apply is given.

    .EXAMPLE
    .\ADTierKit.ps1 -Mode Deploy -Apply -Stage OU,Group,Nesting,Account,Delegation -Force

    Deploys the structural part only, leaving Group Policy and the silo for a later window.

    .EXAMPLE
    .\ADTierKit.ps1 -Mode Audit

    Read only drift report.

    .EXAMPLE
    .\ADTierKit.ps1 -Mode InstallTask

    Registers a daily task so that servers moved into a tier later still end up in the silo.

    .NOTES
    Requires PowerShell 5.1+, the ActiveDirectory and GroupPolicy modules, an elevated session
    and Domain Admins membership. Always run -Mode Deploy -WhatIf before applying anything.

    .PARAMETER NoEventLog
    Suppresses writing the run result to the Windows Application event log.

    Exit codes: 0 success, 1 deployment failures, 2 audit found drift, 3 prerequisites failed,
    4 audit found high severity findings.
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Wizard', 'Deploy', 'Audit', 'Sync', 'Check', 'InstallTask')]
    [string]$Mode = 'Wizard',

    [string]$ConfigurationPath,

    [ValidateSet('RecycleBin', 'OU', 'Domain', 'Group', 'Nesting', 'Account', 'Delegation', 'Ownership', 'PrivilegedGroups', 'Auditing', 'GPO', 'Laps', 'KDS', 'Silo')]
    [string[]]$Stage = @('RecycleBin', 'OU', 'Domain', 'Group', 'Nesting', 'Account', 'Delegation', 'Ownership', 'PrivilegedGroups', 'Auditing', 'GPO', 'Laps', 'KDS', 'Silo'),

    [string]$Server,

    [string]$LogDirectory,

    [string]$ReportDirectory,

    [string]$CredentialDirectory,

    [switch]$Apply,

    [switch]$UseDefaults,

    [switch]$SkipPrerequisiteCheck,

    [switch]$NoEventLog,

    [switch]$Force
)

# ---------------------------------------------------------------------------------------------
# Where the script lives.
#
# $PSScriptRoot is not reliably populated while parameter defaults are being bound - under a
# scheduled task it comes out empty, and Join-Path then throws before a single line has been
# logged, which is exactly as opaque as it sounds. Resolving it here, after binding, with two
# fallbacks: the invocation path, and finally the current directory.
# ---------------------------------------------------------------------------------------------
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot -and $MyInvocation.MyCommand.Path) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }

if (-not $ConfigurationPath) { $ConfigurationPath = Join-Path $scriptRoot 'config\tiermodel.json' }
if (-not $LogDirectory) { $LogDirectory = Join-Path $scriptRoot 'Logs' }
if (-not $ReportDirectory) { $ReportDirectory = Join-Path $scriptRoot 'Reports' }
if (-not $CredentialDirectory) { $CredentialDirectory = Join-Path $scriptRoot 'Credentials' }

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop


####################################################################################################
#region Core
#  Logging, configuration loading, runtime context and name resolution.
####################################################################################################

$script:TierKitVersion = '1.1.0'
$script:TierLogFile = $null
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$script:TierContext = $null
$script:SchemaGuidCache = @{}
# Resolved once per run: the schemaIDGUIDs of every msLAPS-* attribute.
$script:LapsAttributeGuids = $null
$script:PrincipalCache = @{}

function Initialize-TierLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogDirectory
    )

    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        # The log has to exist even in a dry run - it is how the dry run is read afterwards.
        New-Item -Path $LogDirectory -ItemType Directory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:TierLogFile = Join-Path $LogDirectory "ADTierKit-$stamp.log"
    $script:TierActions.Clear()

    # The version goes in the first line of every log and report. A support question that starts
    # with a pasted log should not also need a question about which build produced it.
    Write-TierLog -Message "ADTierKit $script:TierKitVersion - log started $(Get-Date -Format o)" -Level Info
    return $script:TierLogFile
}

function Write-TierLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Skip', 'Plan', 'Header')]
        [string]$Level = 'Info'
    )

    $line = '{0} [{1,-7}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.ToUpper(), $Message

    switch ($Level) {
        'Header'  { Write-Host ''; Write-Host "=== $Message ===" -ForegroundColor Cyan }
        'Success' { Write-Host "  [+] $Message" -ForegroundColor Green }
        'Skip'    { Write-Host "  [=] $Message" -ForegroundColor DarkGray }
        'Plan'    { Write-Host "  [~] $Message" -ForegroundColor Yellow }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Host "  [!] $Message" -ForegroundColor Red }
        default   { Write-Host "  [i] $Message" -ForegroundColor Gray }
    }

    if ($script:TierLogFile) {
        Add-Content -LiteralPath $script:TierLogFile -Value $line -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }
}

function Get-TierSeverity {
    <#
        .SYNOPSIS
        Classifies a finding so that a report can be triaged instead of read line by line.

        .DESCRIPTION
        High     something is broken or an attack path is open right now
        Medium   a control the tier model depends on is missing or has drifted
        Low      structural object missing, no immediate security impact
        Info     everything that went as planned
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory)][string]$Result
    )

    # Object types that represent a live attack path rather than a missing object.
    $criticalTypes = @('PrivilegedGroup', 'UnconstrainedDelegation', 'Ace', 'SecurityTemplate', 'AuthenticationPolicySilo')
    # Phases whose absence disables an enforced control.
    $controlPhases = @('Delegation', 'GPO', 'Silo', 'Isolation')

    switch ($Result) {
        'Failed' { return 'High' }
        'Drift' {
            if ($criticalTypes -contains $ObjectType) { return 'High' }
            return 'Medium'
        }
        'Missing' {
            if ($criticalTypes -contains $ObjectType) { return 'High' }
            if ($controlPhases -contains $Phase) { return 'Medium' }
            return 'Low'
        }
        default { return 'Info' }
    }
}

function Add-TierAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][ValidateSet('Created', 'Updated', 'Compliant', 'Planned', 'Failed', 'Missing', 'Drift')][string]$Result,
        [string]$Detail,
        [ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity
    )

    if (-not $Severity) {
        $Severity = Get-TierSeverity -Phase $Phase -ObjectType $ObjectType -Result $Result
    }

    $script:TierActions.Add([pscustomobject]@{
            Timestamp  = (Get-Date).ToString('o')
            Phase      = $Phase
            ObjectType = $ObjectType
            Target     = $Target
            Result     = $Result
            Severity   = $Severity
            Detail     = $Detail
        })
}

function Get-TierActionLog {
    [CmdletBinding()]
    param()
    return $script:TierActions.ToArray()
}

function Add-TierConfigurationItem {
    <#
        .SYNOPSIS
        Appends items to an array property of a configuration object, creating it if absent.

        .DESCRIPTION
        ConvertFrom-Json produces fixed size arrays, so an in place += is not possible; the
        property has to be reassigned. A tier that never declared the property at all - a tier
        with no delegations, say - needs the property added instead.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Property,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Item
    )

    if ($Item.Count -eq 0) { return }

    if ($Object.PSObject.Properties.Name -contains $Property -and $null -ne $Object.$Property) {
        $Object.$Property = @(@($Object.$Property | Where-Object { $null -ne $_ }) + $Item)
    }
    else {
        $Object | Add-Member -MemberType NoteProperty -Name $Property -Value ([object[]]$Item) -Force
    }
}

function Copy-TierConfigurationObject {
    <#
        .SYNOPSIS
        Deep copies a configuration fragment so a role template can be expanded per tier without
        the second tier inheriting the first tier's substitutions.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$InputObject)
    return ($InputObject | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json)
}

function Get-TierToken {
    <#
        .SYNOPSIS
        Returns the short token of a tier ('T0'), used to expand role naming patterns.

        .DESCRIPTION
        The wizard writes the token it derived from the naming pattern into the tier. A
        configuration written before roles existed does not have one, so the conventional
        T<id> is assumed - which is what the shipped naming patterns produce.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Tier)

    if ($Tier.PSObject.Properties.Name -contains 'token' -and $Tier.token) { return [string]$Tier.token }
    return "T$($Tier.id)"
}

function Get-TierDenyLogonGroupName {
    <#
        .SYNOPSIS
        Finds the deny logon group of a tier.

        .DESCRIPTION
        Every role group has to be nested into the deny logon group of every *other* tier, or the
        role silently becomes a hole in the tier boundary. Which group that is depends on the
        naming pattern chosen in the wizard, so it is either declared explicitly on the tier or
        recognised by name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Tier)

    if ($Tier.PSObject.Properties.Name -contains 'denyLogonGroup' -and $Tier.denyLogonGroup) {
        return [string]$Tier.denyLogonGroup
    }

    $candidates = @($Tier.groups | Where-Object { $_.name -match 'Deny[-_ ]?Logon' })
    if ($candidates.Count -eq 1) { return [string]$candidates[0].name }
    return $null
}

function Get-TierSiloDefinition {
    <#
        .SYNOPSIS
        Finds the authentication policy silo belonging to a tier, if one is configured.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][object]$Tier
    )

    $silos = @($Configuration.authenticationPolicySilos | Where-Object { $_ })
    if (-not $silos) { return $null }

    if ($Tier.PSObject.Properties.Name -contains 'siloName' -and $Tier.siloName) {
        return ($silos | Where-Object { $_.name -eq $Tier.siloName } | Select-Object -First 1)
    }
    return ($silos | Where-Object { $_.name -like "$($Tier.name)*" } | Select-Object -First 1)
}

function Expand-TierRoleDefinition {
    <#
        .SYNOPSIS
        Expands the 'roles' block into the groups, accounts, delegations, deny nesting and silo
        membership that a role consists of.

        .DESCRIPTION
        A role is not one object. A DNS administration role is a global group, a disabled template
        account, a set of ACEs, a membership in the deny logon group of every other tier, and a
        membership in the tier's authentication silo. Four of those five are easy to forget when
        adding a role group by hand - and forgetting the deny nesting means the new group can log
        on to every tier, which is exactly the boundary the model exists to draw.

        Expansion therefore produces all of them from one declaration, and produces nothing at all
        if the declaration is incomplete. Everything it generates is ordinary configuration, so
        the deploy, audit and sync stages need no knowledge of roles whatsoever.

        Expansion is idempotent against a configuration that already contains the generated names,
        so a role can be added to a configuration the wizard wrote earlier.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration)

    if (-not ($Configuration.PSObject.Properties.Name -contains 'roles')) { return $Configuration }
    $roles = @($Configuration.roles | Where-Object { $_ })
    if (-not $roles) { return $Configuration }

    $generated = 0

    foreach ($role in $roles) {
        if ($role.PSObject.Properties.Name -contains 'enabled' -and -not $role.enabled) {
            Write-TierLog -Message "Role '$($role.name)' is disabled in the configuration - skipped" -Level Skip
            continue
        }
        if (-not $role.name) { throw 'A role in the configuration has no name.' }
        if (-not $role.roleGroup) { throw "Role '$($role.name)' has no roleGroup pattern." }

        # .Count, not -not: a role that applies to tier 0 alone declares @(0), which unrolls to a
        # single 0 and is falsy. Every Tier 0 role in the shipped configuration would have thrown.
        $roleTiers = @($role.tiers)
        if ($roleTiers.Count -eq 0) { throw "Role '$($role.name)' does not declare which tiers it applies to." }

        foreach ($tier in $Configuration.tiers) {
            if ($roleTiers -notcontains $tier.id) { continue }

            $token = Get-TierToken -Tier $tier
            $tokens = @{
                ID      = $tier.id
                TIER    = $tier.name
                TOKEN   = $token
                TOKENLC = $token.ToLowerInvariant()
                ROLE    = $role.name
                ROLELC  = $role.name.ToLowerInvariant()
            }

            $groupName = Expand-TierName -Pattern $role.roleGroup -Tokens $tokens

            # --- the role group -------------------------------------------------------------
            if (@($tier.groups | Where-Object { $_.name -eq $groupName })) {
                Write-TierLog -Message "Role group $groupName already declared in $($tier.name) - expansion skipped" -Level Skip
            }
            else {
                $description = if ($role.description) { Expand-TierName -Pattern $role.description -Tokens $tokens }
                else { "$($role.name) administration role for $($tier.name)." }

                $groupOu = if ($role.roleGroupOu) { $role.roleGroupOu } else { 'Groups' }
                Add-TierConfigurationItem -Object $tier -Property 'groups' -Item @([pscustomobject]@{
                        name        = $groupName
                        scope       = 'Global'
                        targetOu    = $groupOu
                        description = $description
                    })
                $generated++
            }

            # --- deny logon nesting in every other tier -------------------------------------
            # The default is on. A role that is exempt has to say so explicitly, because the
            # failure mode of forgetting is silent and the failure mode of over-denying is loud.
            $nest = $true
            if ($role.PSObject.Properties.Name -contains 'nestIntoForeignDenyGroups' -and $null -ne $role.nestIntoForeignDenyGroups) {
                $nest = [bool]$role.nestIntoForeignDenyGroups
            }

            if ($nest) {
                foreach ($other in $Configuration.tiers) {
                    if ($other.id -eq $tier.id) { continue }
                    $denyGroupName = Get-TierDenyLogonGroupName -Tier $other
                    if (-not $denyGroupName) {
                        Write-TierLog -Message "No deny logon group found for $($other.name) - $groupName is NOT denied there. Declare 'denyLogonGroup' on the tier." -Level Warning
                        continue
                    }
                    $denyGroup = @($other.groups | Where-Object { $_.name -eq $denyGroupName }) | Select-Object -First 1
                    if (-not $denyGroup) { continue }
                    if (@($denyGroup.members) -contains $groupName) { continue }
                    Add-TierConfigurationItem -Object $denyGroup -Property 'members' -Item @($groupName)
                }
            }
            else {
                Write-TierLog -Message "Role $groupName is exempt from cross-tier deny nesting by configuration" -Level Warning
            }

            # --- silo membership ------------------------------------------------------------
            $silo = $null
            $wantSilo = $true
            if ($role.PSObject.Properties.Name -contains 'siloMember' -and $null -ne $role.siloMember) {
                $wantSilo = [bool]$role.siloMember
            }
            if ($wantSilo) {
                $silo = Get-TierSiloDefinition -Configuration $Configuration -Tier $tier
                if ($silo -and (@($silo.memberGroups) -notcontains $groupName)) {
                    Add-TierConfigurationItem -Object $silo -Property 'memberGroups' -Item @($groupName)
                }
            }

            # --- template account -----------------------------------------------------------
            if ($role.templateAccount) {
                $accountName = Expand-TierName -Pattern $role.templateAccount -Tokens $tokens
                if (-not @($tier.adminAccounts | Where-Object { $_.samAccountName -eq $accountName })) {
                    Add-TierConfigurationItem -Object $tier -Property 'adminAccounts' -Item @([pscustomobject]@{
                            samAccountName = $accountName
                            displayName    = "$($tier.name) $($role.name) Admin Template"
                            targetOu       = 'Accounts'
                            memberOf       = @($groupName)
                            description    = "Template account - copy this object when onboarding a $($role.name) administrator for $($tier.name)."
                        })
                    $generated++
                }
            }

            # --- delegations ----------------------------------------------------------------
            foreach ($delegation in @($role.delegations | Where-Object { $_ })) {
                $copy = Copy-TierConfigurationObject -InputObject $delegation

                # A role delegation normally targets its own role group; naming it explicitly
                # stays possible for the rare ACE that has to name something else.
                if (-not ($copy.PSObject.Properties.Name -contains 'principal') -or -not $copy.principal) {
                    $copy | Add-Member -MemberType NoteProperty -Name 'principal' -Value $groupName -Force
                }
                else {
                    $copy.principal = Expand-TierName -Pattern $copy.principal -Tokens $tokens
                }

                foreach ($field in 'targetOu', 'comment') {
                    if ($copy.PSObject.Properties.Name -contains $field -and $copy.$field) {
                        $copy.$field = Expand-TierName -Pattern $copy.$field -Tokens $tokens
                    }
                }
                if (-not ($copy.PSObject.Properties.Name -contains 'inheritedObjectType')) {
                    $copy | Add-Member -MemberType NoteProperty -Name 'inheritedObjectType' -Value $null -Force
                }

                Add-TierConfigurationItem -Object $tier -Property 'delegations' -Item @($copy)
                $generated++
            }

            # --- built-in group nesting -----------------------------------------------------
            # DnsAdmins and Group Policy Creator Owners already hold the permissions the role
            # needs. Nesting into them and keeping the built-in group otherwise empty is the
            # documented way to hold those permissions without handing anyone the group itself.
            #
            # Two things are generated per entry, and they are not the same thing: a declaration
            # in privilegedGroups, which is what watches the group for undeclared members, and an
            # entry in builtInNesting, which is what actually performs the nesting. Without the
            # second one the role holds no permissions at all until somebody switches
            # privilegedGroups to Enforce, because report mode reports an absent member rather
            # than adding it.
            foreach ($builtIn in @($role.privilegedGroupNesting | Where-Object { $_ })) {
                $reference = if ($builtIn -is [string]) { [pscustomobject]@{ name = $builtIn } } else { $builtIn }
                $key = if ($reference.PSObject.Properties.Name -contains 'sid' -and $reference.sid) { $reference.sid } else { $reference.name }

                # A built-in group of this kind is Tier 0 by capability whatever its RID says:
                # DnsAdmins members can load a DLL into a service running as SYSTEM on a domain
                # controller. Nesting a lower tier role into one would hand that tier the control
                # plane, which is the boundary this whole model exists to draw - so it is refused
                # rather than warned about.
                if ($tier.id -ne @($Configuration.tiers)[0].id) {
                    Write-TierLog -Message "Role '$($role.name)' in $($tier.name) declares nesting into the privileged built-in group '$key' - refused. Only the top tier may hold it." -Level Error
                    Add-TierAction -Phase 'Role' -ObjectType 'PrivilegedGroup' -Target "$groupName -> $key" -Result 'Failed' `
                        -Detail 'A role below the top tier may not be nested into a privileged built-in group' -Severity 'High'
                    continue
                }

                if ($Configuration.privilegedGroups) {
                    $entry = @($Configuration.privilegedGroups.groups | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'sid' -and $_.sid -eq $key) -or
                            ($_.PSObject.Properties.Name -contains 'name' -and $_.name -eq $key)
                        }) | Select-Object -First 1

                    if ($entry) {
                        if (@($entry.allowedMembers) -notcontains $groupName) {
                            Add-TierConfigurationItem -Object $entry -Property 'allowedMembers' -Item @($groupName)
                        }
                    }
                    else {
                        $new = [pscustomobject]@{
                            sid            = if ($reference.PSObject.Properties.Name -contains 'sid') { $reference.sid } else { $null }
                            name           = if ($reference.PSObject.Properties.Name -contains 'name') { $reference.name } else { $null }
                            allowedMembers = @($groupName)
                            comment        = "Holds the permissions of the $($role.name) role - members are nested, never added directly."
                        }
                        Add-TierConfigurationItem -Object $Configuration.privilegedGroups -Property 'groups' -Item @($new)
                    }
                }

                $existingNesting = @($Configuration.builtInNesting | Where-Object {
                        $_ -and (
                            ($_.group.PSObject.Properties.Name -contains 'sid' -and $_.group.sid -eq $key) -or
                            ($_.group.PSObject.Properties.Name -contains 'name' -and $_.group.name -eq $key)
                        )
                    }) | Select-Object -First 1

                if ($existingNesting) {
                    if (@($existingNesting.members) -notcontains $groupName) {
                        Add-TierConfigurationItem -Object $existingNesting -Property 'members' -Item @($groupName)
                    }
                }
                else {
                    Add-TierConfigurationItem -Object $Configuration -Property 'builtInNesting' -Item @([pscustomobject]@{
                            group   = $reference
                            members = @($groupName)
                            comment = "Grants the $($role.name) role the permissions this built-in group already holds."
                        })
                }
                $generated++
            }
        }
    }

    if ($generated -gt 0) {
        Write-TierLog -Message "Role expansion produced $generated additional configuration object(s)" -Level Info
    }
    return $Configuration
}

function Import-TierConfiguration {
    <#
        .SYNOPSIS
        Loads and validates the JSON tier model configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Configuration file not found: $Path"
    }

    try {
        $config = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "Configuration file is not valid JSON: $($_.Exception.Message)"
    }

    foreach ($required in 'schemaVersion', 'domain', 'options', 'tiers') {
        if (-not $config.PSObject.Properties.Name.Contains($required)) {
            throw "Configuration is missing the mandatory property '$required'."
        }
    }

    if ($config.tiers.Count -eq 0) {
        throw 'Configuration contains no tiers.'
    }

    # Roles expand into ordinary groups, accounts, delegations, deny nesting and silo membership
    # before anything else looks at the configuration, so every existing stage keeps working
    # unchanged and the duplicate check below covers generated names too.
    $config = Expand-TierRoleDefinition -Configuration $config

    $names = @{}
    foreach ($tier in $config.tiers) {
        foreach ($group in @($tier.groups)) {
            if ($names.ContainsKey($group.name)) {
                throw "Duplicate group name in configuration: $($group.name)"
            }
            $names[$group.name] = $tier.name
        }
    }

    Write-TierLog -Message "Configuration loaded: $($config.metadata.name) (revision $($config.metadata.revision))" -Level Info
    return $config
}

function Initialize-TierContext {
    <#
        .SYNOPSIS
        Builds the runtime context (domain info, base DNs) from the configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [string]$Server
    )

    $adParams = @{}
    if ($Server) { $adParams['Server'] = $Server }

    if ($Configuration.domain.fqdn) {
        $domain = Get-ADDomain -Identity $Configuration.domain.fqdn @adParams
    }
    else {
        $domain = Get-ADDomain @adParams
    }

    $rootOuName = $Configuration.domain.rootOu
    $rootDn = "OU=$rootOuName,$($domain.DistinguishedName)"

    # The forest root domain naming context, needed for the ForestDnsZones partition. Deriving it
    # from the forest FQDN avoids a second directory round trip and is correct for every domain
    # whose DN follows its DNS name - which, outside of renamed domains, is all of them.
    $forestDn = ($domain.Forest -split '\.' | ForEach-Object { "DC=$_" }) -join ','

    $systemDn = "CN=System,$($domain.DistinguishedName)"

    $script:TierContext = [pscustomobject]@{
        Domain           = $domain
        DomainDn         = $domain.DistinguishedName
        DomainFqdn       = $domain.DNSRoot
        DomainNetBios    = $domain.NetBIOSName
        DomainSid        = $domain.DomainSID.Value
        Server           = if ($Server) { $Server } else { $domain.PDCEmulator }
        RootOuName       = $rootOuName
        RootOuDn         = $rootDn
        DomainControllersDn = $domain.DomainControllersContainer
        # Containers outside the tier model that delegation still has to reach. They are built
        # here rather than in the configuration because none of them can be named portably: every
        # one carries the domain DN, and two of them live in application partitions.
        SystemContainerDn   = $systemDn
        MicrosoftDnsDn      = "CN=MicrosoftDNS,$systemDn"
        DomainDnsZonesDn    = "CN=MicrosoftDNS,DC=DomainDnsZones,$($domain.DistinguishedName)"
        ForestDnsZonesDn    = "CN=MicrosoftDNS,DC=ForestDnsZones,$forestDn"
        PoliciesDn          = "CN=Policies,$systemDn"
        AdminSdHolderDn     = "CN=AdminSDHolder,$systemDn"
        SysvolPolicyPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
        Configuration    = $Configuration
        # Lets a bare tier name be resolved as an OU reference without a tier context.
        TierNames        = @($Configuration.tiers | ForEach-Object { $_.name })
    }

    Write-TierLog -Message "Target domain: $($domain.DNSRoot) ($($domain.DistinguishedName))" -Level Info
    Write-TierLog -Message "Directory server: $($script:TierContext.Server)" -Level Info
    Write-TierLog -Message "Tier model root: $rootDn" -Level Info

    return $script:TierContext
}

function Get-TierContext {
    [CmdletBinding()]
    param()
    if (-not $script:TierContext) { throw 'Tier context is not initialised. Call Initialize-TierContext first.' }
    return $script:TierContext
}

function Get-TierAdParameter {
    <#
        .SYNOPSIS
        Returns the common splatting hashtable (-Server) for ActiveDirectory cmdlets.
    #>
    [CmdletBinding()]
    param()
    $ctx = Get-TierContext
    return @{ Server = $ctx.Server }
}

function Resolve-TierOuDn {
    <#
        .SYNOPSIS
        Resolves a configuration OU reference to a distinguished name.

        .DESCRIPTION
        Accepted forms:
          ''                    -> the tier root OU
          'Servers'             -> a child OU of the given tier
          'Tier-1/Servers'      -> an explicit tier path below the model root
          '$DomainRoot'         -> the domain naming context
          '$DomainControllers'  -> the Domain Controllers container
          '$SystemContainer'    -> CN=System,<domain>
          '$MicrosoftDns'       -> CN=MicrosoftDNS,CN=System,<domain>  (DNS server object)
          '$DomainDnsZones'     -> the domain DNS application partition
          '$ForestDnsZones'     -> the forest DNS application partition
          '$PoliciesContainer'  -> CN=Policies,CN=System,<domain>      (group policy objects)
          '$AdminSDHolder'      -> CN=AdminSDHolder,CN=System,<domain>
          '$DnsZone:contoso.com'-> that zone inside the domain DNS partition
          'OU=X,DC=...'         -> passed through unchanged
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][AllowNull()][string]$Reference,
        [string]$TierName
    )

    $ctx = Get-TierContext

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        if (-not $TierName) { return $ctx.RootOuDn }
        return "OU=$TierName,$($ctx.RootOuDn)"
    }

    switch ($Reference) {
        '$DomainRoot' { return $ctx.DomainDn }
        '$DomainControllers' { return $ctx.DomainControllersDn }
        '$ModelRoot' { return $ctx.RootOuDn }
        '$SystemContainer' { return $ctx.SystemContainerDn }
        '$MicrosoftDns' { return $ctx.MicrosoftDnsDn }
        '$DomainDnsZones' { return $ctx.DomainDnsZonesDn }
        '$ForestDnsZones' { return $ctx.ForestDnsZonesDn }
        '$PoliciesContainer' { return $ctx.PoliciesDn }
        '$AdminSDHolder' { return $ctx.AdminSdHolderDn }
    }

    # A single zone, for record level delegation. Zones created since Windows Server 2003 live in
    # the application partition; a zone predating it sits under CN=MicrosoftDNS,CN=System instead,
    # in which case the full DN has to be written out in the configuration.
    if ($Reference -match '^\$DnsZone:(.+)$') {
        $zoneName = $Matches[1].Trim()
        if (-not $zoneName) { throw 'OU reference "$DnsZone:" is missing the zone name.' }
        return "DC=$zoneName,$($ctx.DomainDnsZonesDn)"
    }

    if ($Reference -match '^(OU|CN|DC)=') { return $Reference }

    $segments = $Reference.Split('/') | Where-Object { $_ }

    if ($segments.Count -gt 1) {
        # Explicit path, e.g. Tier-1/Servers -> OU=Servers,OU=Tier-1,<root>
        $reversed = [System.Collections.Generic.List[string]]::new()
        for ($i = $segments.Count - 1; $i -ge 0; $i--) { $reversed.Add("OU=$($segments[$i])") }
        return ($reversed -join ',') + ",$($ctx.RootOuDn)"
    }

    if (-not $TierName) {
        # A bare tier name is a valid reference on its own - the LAPS and auditing sections use
        # it because they are not iterated per tier and have no tier context to pass.
        if ($ctx.TierNames -contains $Reference) { return "OU=$Reference,$($ctx.RootOuDn)" }
        throw "OU reference '$Reference' is relative but no tier context was supplied."
    }
    return "OU=$Reference,OU=$TierName,$($ctx.RootOuDn)"
}

function Resolve-TierPrincipal {
    <#
        .SYNOPSIS
        Resolves a principal reference (group name, sAMAccountName or SID string) to an AD object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Reference,
        [switch]$AllowMissing
    )

    if ($script:PrincipalCache.ContainsKey($Reference)) { return $script:PrincipalCache[$Reference] }

    $ad = Get-TierAdParameter

    try {
        if ($Reference -match '^S-1-') {
            # By LDAP filter, not -Identity: Get-ADObject binds -Identity to a distinguished name
            # or a GUID and rejects a SID outright, which surfaces as an unresolvable principal
            # several frames later rather than as an error anyone can act on.
            $obj = $null
            try {
                $obj = Get-ADObject -LDAPFilter "(objectSid=$Reference)" -Properties objectSid, sAMAccountName @ad -ErrorAction Stop |
                    Select-Object -First 1
            }
            catch { $obj = $null }
            if (-not $obj) {
                # Well-known SIDs (e.g. S-1-5-113 Local account) have no directory object.
                return [pscustomobject]@{
                    Name              = $Reference
                    SID               = $Reference
                    DistinguishedName = $null
                    IsWellKnown       = $true
                }
            }
            $resolved = [pscustomobject]@{
                Name              = $obj.Name
                SID               = $obj.objectSid.Value
                DistinguishedName = $obj.DistinguishedName
                IsWellKnown       = $false
            }
            $script:PrincipalCache[$Reference] = $resolved
            return $resolved
        }

        $obj = Get-ADObject -Filter "sAMAccountName -eq '$Reference'" -Properties objectSid, sAMAccountName @ad -ErrorAction Stop |
            Select-Object -First 1

        if (-not $obj) {
            $obj = Get-ADObject -Filter "name -eq '$Reference'" -Properties objectSid, sAMAccountName @ad -ErrorAction Stop |
                Select-Object -First 1
        }

        if (-not $obj) {
            if ($AllowMissing) { return $null }
            throw "Principal '$Reference' was not found in $($ad.Server)."
        }

        $resolved = [pscustomobject]@{
            Name              = $obj.Name
            SID               = $obj.objectSid.Value
            DistinguishedName = $obj.DistinguishedName
            IsWellKnown       = $false
        }
        $script:PrincipalCache[$Reference] = $resolved
        return $resolved
    }
    catch {
        if ($AllowMissing) { return $null }
        throw
    }
}

function New-TierSecurityIdentifier {
    <#
        .SYNOPSIS
        Builds a SecurityIdentifier from a SID string.

        .DESCRIPTION
        One line, wrapped in a function on purpose. Owner assignment is the one part of this tool
        whose logic cannot be exercised outside Windows - the SecurityIdentifier constructor is
        not implemented on other platforms - and routing every construction through one seam lets
        the offline tests reach the code around it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Sid)
    return [System.Security.Principal.SecurityIdentifier]::new($Sid)
}

function Resolve-TierPrincipalReference {
    <#
        .SYNOPSIS
        Resolves a principal reference that may also be a bare domain relative identifier.

        .DESCRIPTION
        The privileged group block addresses groups by RID ('512' for Domain Admins), because
        their names are localised. Anywhere a configuration names a principal that is likely to be
        one of those built-in groups - the owner of an object, for instance - the same shorthand
        has to work, and Resolve-TierPrincipal on its own would go looking for a group whose
        sAMAccountName is literally '512'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Reference,
        [switch]$AllowMissing
    )

    if ($Reference -match '^\d+$') {
        # No -Properties here: only the name, SID and DN are used below, and an empty property
        # set is not a valid argument to Get-ADGroup on Windows PowerShell 5.1.
        $group = Get-TierWellKnownGroup -Sid $Reference
        if (-not $group) {
            if ($AllowMissing) { return $null }
            throw "No group with RID $Reference exists in this domain."
        }
        return [pscustomobject]@{
            Name              = $group.Name
            SID               = $group.SID.Value
            DistinguishedName = $group.DistinguishedName
            IsWellKnown       = $false
        }
    }

    return (Resolve-TierPrincipal -Reference $Reference -AllowMissing:$AllowMissing)
}

function Clear-TierPrincipalCache {
    <#
        .SYNOPSIS
        Drops the resolved principal cache. Called between deployment stages so that objects
        created earlier in the same run are picked up.
    #>
    [CmdletBinding()]
    param()
    $script:PrincipalCache = @{}
}

function Get-TierSchemaGuid {
    <#
        .SYNOPSIS
        Returns the schemaIDGUID of a class/attribute or the rightsGuid of an extended right.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    if ($script:SchemaGuidCache.ContainsKey($Name)) { return $script:SchemaGuidCache[$Name] }

    $ad = Get-TierAdParameter
    $rootDse = Get-ADRootDSE @ad

    $entry = Get-ADObject -SearchBase $rootDse.schemaNamingContext -LDAPFilter "(lDAPDisplayName=$Name)" -Properties schemaIDGUID @ad -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($entry) {
        $guid = [guid]$entry.schemaIDGUID
        $script:SchemaGuidCache[$Name] = $guid
        return $guid
    }

    # Extended rights and property sets both live in CN=Extended-Rights, but they are not named
    # consistently: control access rights use hyphens throughout (User-Force-Change-Password),
    # while property sets carry a displayName with spaces (Account Restrictions). Trying both
    # spellings against both attributes is cheaper than maintaining a lookup table.
    $candidates = [System.Collections.Generic.List[string]]::new()
    $candidates.Add($Name)
    # The extra parentheses matter: inside a method call the comma of -replace would otherwise
    # be read as an argument separator, turning Add() into a two-argument call that does not exist.
    if ($Name -match '-') { $candidates.Add(($Name -replace '-', ' ')) }
    if ($Name -match ' ') { $candidates.Add(($Name -replace ' ', '-')) }

    $filter = '(|' + (($candidates | Sort-Object -Unique | ForEach-Object { "(displayName=$_)(cn=$_)" }) -join '') + ')'

    $extended = Get-ADObject -SearchBase "CN=Extended-Rights,$($rootDse.configurationNamingContext)" -LDAPFilter $filter -Properties rightsGuid @ad -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($extended) {
        $guid = [guid]$extended.rightsGuid
        $script:SchemaGuidCache[$Name] = $guid
        return $guid
    }

    # A raw GUID in the configuration is passed through unchanged - the escape hatch for anything
    # this resolver cannot find by name.
    $parsed = [guid]::Empty
    if ([guid]::TryParse($Name, [ref]$parsed)) {
        $script:SchemaGuidCache[$Name] = $parsed
        return $parsed
    }

    throw "Unable to resolve schema or extended-right GUID for '$Name'. Tried lDAPDisplayName in the schema and displayName/cn in CN=Extended-Rights (also with hyphens and spaces exchanged). A raw GUID can be used instead."
}

function Get-TierWellKnownGroup {
    <#
        .SYNOPSIS
        Resolves a built-in or well-known group by SID instead of by name.

        .DESCRIPTION
        Built-in group names are localised (Administrators / Administratoren / Administrateurs),
        so every lookup of a privileged group has to go through the SID.

        .PARAMETER Sid
        Either a complete SID ('S-1-5-32-544') or a domain relative identifier ('512').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Sid,
        [string[]]$Properties = @('member')
    )

    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $full = if ($Sid -match '^S-1-') { $Sid } else { "$($ctx.DomainSid)-$Sid" }

    # An empty collection is a reasonable way to say 'no extra attributes', and Get-ADGroup rejects
    # it - on Windows PowerShell 5.1 the binding fails at the call site, several frames away from
    # the cmdlet that actually objects. Normalising it here keeps that from being anybody's
    # problem twice.
    if (-not $Properties -or @($Properties).Count -eq 0) { $Properties = @('objectSid') }

    try { return Get-ADGroup -Identity $full -Properties $Properties @ad -ErrorAction Stop }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { return $null }
}

function Get-TierPrivilegedGroupReference {
    <#
        .SYNOPSIS
        Resolves a privileged group entry that is addressed either by SID or by name.

        .DESCRIPTION
        Everything privileged in this tool is addressed by SID, because built-in group names are
        localised. Two groups cannot be: DnsAdmins and DnsUpdateProxy are created by the DNS
        server role, not by the operating system, and receive an ordinary RID above 1000 that
        differs between domains. They are also not localised, which is what makes the name lookup
        safe here and nowhere else.

        DnsAdmins is worth the exception. It is not covered by AdminSDHolder and carries no
        adminCount, so nothing flags it as privileged - but its members can load a DLL into the
        DNS service, which runs as SYSTEM on a domain controller. It is Tier 0 in everything but
        Microsoft's classification of it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Entry,
        [string[]]$Properties = @('member')
    )

    if ($Entry.PSObject.Properties.Name -contains 'sid' -and $Entry.sid) {
        return Get-TierWellKnownGroup -Sid $Entry.sid -Properties $Properties
    }

    if (-not ($Entry.PSObject.Properties.Name -contains 'name') -or -not $Entry.name) {
        throw 'A privileged group entry declares neither a sid nor a name.'
    }

    $ad = Get-TierAdParameter
    return (Get-ADGroup -LDAPFilter "(sAMAccountName=$($Entry.name))" -Properties $Properties @ad -ErrorAction SilentlyContinue |
        Select-Object -First 1)
}

function ConvertTo-TierSidString {
    <#
        .SYNOPSIS
        Formats a SID for use inside a GptTmpl.inf security template.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Sid)
    return "*$Sid"
}

#endregion Core

####################################################################################################
#region Prompts
#  Console helpers for the wizard. Every prompt shows an example and a default.
####################################################################################################

$script:TierUseDefaults = $false

function Set-TierPromptMode {
    [CmdletBinding()]
    param([switch]$UseDefaults)
    $script:TierUseDefaults = [bool]$UseDefaults
}

function Write-TierPromptHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Description
    )

    Write-Host ''
    Write-Host ('-' * 72) -ForegroundColor DarkCyan
    Write-Host " $Title" -ForegroundColor Cyan
    if ($Description) { Write-Host " $Description" -ForegroundColor DarkGray }
    Write-Host ('-' * 72) -ForegroundColor DarkCyan
}

function Show-TierQuestion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Question,
        [string]$Example,
        [string]$Default,
        [string]$Hint
    )

    Write-Host ''
    Write-Host "  $Question" -ForegroundColor White
    if ($Hint) { Write-Host "    $Hint" -ForegroundColor DarkGray }
    if ($Example) { Write-Host "    Example : $Example" -ForegroundColor DarkYellow }
    if ($Default) { Write-Host "    Default : $Default" -ForegroundColor DarkGreen }
}

function Read-TierText {
    <#
        .SYNOPSIS
        Asks for a free text value with example, default and optional validation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Question,
        [Parameter(Mandatory)][string]$Example,
        [Parameter(Mandatory)][string]$Default,
        [string]$Hint,
        [string]$ValidationPattern,
        [string]$ValidationMessage = 'The value contains characters that are not allowed here.',
        [int]$MaxLength
    )

    while ($true) {
        Show-TierQuestion -Question $Question -Example $Example -Default $Default -Hint $Hint

        if ($script:TierUseDefaults) {
            Write-Host "  > $Default (default accepted)" -ForegroundColor DarkGray
            return $Default
        }

        $answer = Read-Host '  >'
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
        $answer = $answer.Trim()

        if ($MaxLength -and $answer.Length -gt $MaxLength) {
            Write-Host "    Too long - the maximum is $MaxLength characters." -ForegroundColor Red
            continue
        }

        if ($ValidationPattern -and $answer -notmatch $ValidationPattern) {
            Write-Host "    $ValidationMessage" -ForegroundColor Red
            continue
        }

        return $answer
    }
}

function Read-TierPattern {
    <#
        .SYNOPSIS
        Asks for a naming pattern and shows how it resolves before accepting it.

        .PARAMETER SampleTokens
        Hashtable of placeholder values used to render the preview, e.g. @{ ID = '0'; TOKEN = 'T0' }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Question,
        [Parameter(Mandatory)][string]$Default,
        [Parameter(Mandatory)][hashtable]$SampleTokens,
        [string]$Hint,
        [int]$MaxLength,
        [string]$ValidationPattern = '^[A-Za-z0-9 _\-\.\{\}]+$',
        [string]$ValidationMessage = 'Only letters, digits, space, dot, hyphen, underscore and placeholders in braces are allowed.'
    )

    $placeholders = ($SampleTokens.Keys | Sort-Object | ForEach-Object { "{$_}" }) -join ', '
    $exampleHint = if ($Hint) { $Hint } else { "Available placeholders: $placeholders" }

    while ($true) {
        $exampleValue = '{0}  ->  {1}' -f $Default, (Expand-TierName -Pattern $Default -Tokens $SampleTokens)

        $answer = Read-TierText -Question $Question -Example $exampleValue -Default $Default `
            -Hint $exampleHint -ValidationPattern $ValidationPattern -ValidationMessage $ValidationMessage

        $resolved = Expand-TierName -Pattern $answer -Tokens $SampleTokens

        if ($resolved -match '[\{\}]') {
            Write-Host "    Unknown placeholder in '$answer'. Allowed: $placeholders" -ForegroundColor Red
            continue
        }

        if ($MaxLength -and $resolved.Length -gt $MaxLength) {
            Write-Host "    '$resolved' is $($resolved.Length) characters - the maximum is $MaxLength." -ForegroundColor Red
            continue
        }

        Write-Host "    Resolves to: $resolved" -ForegroundColor Green
        return $answer
    }
}

function Read-TierBoolean {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Question,
        [Parameter(Mandatory)][string]$Example,
        [Parameter(Mandatory)][bool]$Default,
        [string]$Hint
    )

    $defaultText = if ($Default) { 'yes' } else { 'no' }

    while ($true) {
        Show-TierQuestion -Question "$Question [yes/no]" -Example $Example -Default $defaultText -Hint $Hint

        if ($script:TierUseDefaults) {
            Write-Host "  > $defaultText (default accepted)" -ForegroundColor DarkGray
            return $Default
        }

        $answer = Read-Host '  >'
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }

        switch -Regex ($answer.Trim().ToLower()) {
            '^(y|yes|j|ja|true|1)$' { return $true }
            '^(n|no|nein|false|0)$' { return $false }
            default { Write-Host '    Please answer yes or no.' -ForegroundColor Red }
        }
    }
}

function Read-TierChoice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Question,
        [Parameter(Mandatory)][string[]]$Options,
        [Parameter(Mandatory)][string]$Default,
        [string[]]$OptionDescriptions,
        [string]$Hint
    )

    while ($true) {
        Write-Host ''
        Write-Host "  $Question" -ForegroundColor White
        if ($Hint) { Write-Host "    $Hint" -ForegroundColor DarkGray }

        for ($i = 0; $i -lt $Options.Count; $i++) {
            $description = if ($OptionDescriptions -and $i -lt $OptionDescriptions.Count) { " - $($OptionDescriptions[$i])" } else { '' }
            Write-Host ("    [{0}] {1}{2}" -f ($i + 1), $Options[$i], $description) -ForegroundColor DarkYellow
        }
        Write-Host "    Default : $Default" -ForegroundColor DarkGreen

        if ($script:TierUseDefaults) {
            Write-Host "  > $Default (default accepted)" -ForegroundColor DarkGray
            return $Default
        }

        $answer = Read-Host '  >'
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        $answer = $answer.Trim()

        if ($answer -match '^\d+$') {
            $index = [int]$answer - 1
            if ($index -ge 0 -and $index -lt $Options.Count) { return $Options[$index] }
        }

        $match = $Options | Where-Object { $_ -eq $answer } | Select-Object -First 1
        if ($match) { return $match }

        Write-Host '    Please pick one of the listed options.' -ForegroundColor Red
    }
}

function Expand-TierName {
    <#
        .SYNOPSIS
        Replaces {PLACEHOLDER} tokens in a naming pattern.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][hashtable]$Tokens
    )

    $result = $Pattern
    foreach ($key in $Tokens.Keys) {
        $result = $result -replace ('\{' + [regex]::Escape($key) + '\}'), [string]$Tokens[$key]
    }
    return $result
}

#endregion Prompts

####################################################################################################
#region ACL
#  Idempotent management of Active Directory access control entries.
####################################################################################################

function Get-TierAccessRuleGuid {
    [CmdletBinding()]
    param([AllowNull()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return [guid]::Empty }
    return (Get-TierSchemaGuid -Name $Name)
}

function Test-TierAccessRule {
    <#
        .SYNOPSIS
        Returns $true when an equivalent ACE already exists on the security descriptor.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.ActiveDirectorySecurity]$SecurityDescriptor,
        [Parameter(Mandatory)][System.DirectoryServices.ActiveDirectoryAccessRule]$Rule
    )

    $existing = $SecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

    foreach ($ace in $existing) {
        if ($ace.IdentityReference.Value -ne $Rule.IdentityReference.Value) { continue }
        if ($ace.AccessControlType -ne $Rule.AccessControlType) { continue }
        if ($ace.ObjectType -ne $Rule.ObjectType) { continue }
        if ($ace.InheritedObjectType -ne $Rule.InheritedObjectType) { continue }
        if ($ace.InheritanceType -ne $Rule.InheritanceType) { continue }

        # The existing ACE must contain at least the requested rights.
        if (($ace.ActiveDirectoryRights -band $Rule.ActiveDirectoryRights) -eq $Rule.ActiveDirectoryRights) {
            return $true
        }
    }

    return $false
}

function Set-TierAccessRule {
    <#
        .SYNOPSIS
        Adds an access control entry to an AD object unless an equivalent entry exists.

        .OUTPUTS
        'Created', 'Compliant' or 'Planned'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$TargetDn,
        [Parameter(Mandatory)][string]$PrincipalSid,
        [Parameter(Mandatory)][string]$Rights,
        [ValidateSet('Allow', 'Deny')][string]$AccessType = 'Allow',
        [AllowNull()][string]$ObjectType,
        [AllowNull()][string]$InheritedObjectType,
        [ValidateSet('None', 'All', 'Descendents', 'SelfAndChildren', 'Children')][string]$Inheritance = 'All',
        [switch]$AuditOnly
    )

    $ad = Get-TierAdParameter

    $identity = [System.Security.Principal.SecurityIdentifier]::new($PrincipalSid)
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
    $type = [System.Security.AccessControl.AccessControlType]$AccessType
    $objGuid = Get-TierAccessRuleGuid -Name $ObjectType
    $inhGuid = Get-TierAccessRuleGuid -Name $InheritedObjectType
    $inhType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Inheritance

    $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $identity, $adRights, $type, $objGuid, $inhType, $inhGuid)

    # In a dry run the target object usually does not exist yet: report the ACE as planned
    # instead of failing on the read. Outside a dry run a missing target is a real error.
    $object = $null
    try { $object = Get-ADObject -Identity $TargetDn -Properties nTSecurityDescriptor @ad -ErrorAction Stop }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        if ($AuditOnly) { return 'Missing' }
        if ($WhatIfPreference) { return 'Planned' }
        throw
    }
    $sd = $object.nTSecurityDescriptor

    if (Test-TierAccessRule -SecurityDescriptor $sd -Rule $rule) {
        return 'Compliant'
    }

    if ($AuditOnly) { return 'Missing' }

    if ($PSCmdlet.ShouldProcess($TargetDn, "Grant $AccessType '$Rights' to SID $PrincipalSid")) {
        $sd.AddAccessRule($rule)
        Set-ADObject -Identity $TargetDn -Replace @{ nTSecurityDescriptor = $sd } @ad -ErrorAction Stop
        return 'Created'
    }

    return 'Planned'
}

function Set-TierAuditRule {
    <#
        .SYNOPSIS
        Adds a system access control entry (audit rule) to an AD object.

        .DESCRIPTION
        Delegation decides who may change the tier model. Auditing decides whether anyone finds
        out that it happened. Without a SACL on the model root, an attacker who acquires the
        rights to rewrite a delegation leaves no directory service change events behind.

        The SACL is reached through the AD: provider because the security descriptor returned by
        Get-ADObject does not include the audit portion.

        .OUTPUTS
        'Created', 'Compliant', 'Missing' or 'Planned'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$TargetDn,
        [Parameter(Mandatory)][string]$PrincipalSid,
        [Parameter(Mandatory)][string]$Rights,
        [ValidateSet('Success', 'Failure', 'None')][string]$AuditFlags = 'Success',
        [AllowNull()][string]$ObjectType,
        [AllowNull()][string]$InheritedObjectType,
        [ValidateSet('None', 'All', 'Descendents', 'SelfAndChildren', 'Children')][string]$Inheritance = 'All',
        [switch]$AuditOnly
    )

    $identity = [System.Security.Principal.SecurityIdentifier]::new($PrincipalSid)
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
    $flags = [System.Security.AccessControl.AuditFlags]$AuditFlags
    $objGuid = Get-TierAccessRuleGuid -Name $ObjectType
    $inhGuid = Get-TierAccessRuleGuid -Name $InheritedObjectType
    $inhType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Inheritance

    $rule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
        $identity, $adRights, $flags, $objGuid, $inhType, $inhGuid)

    $path = "AD:\$TargetDn"

    if (-not (Test-Path -LiteralPath $path)) {
        if ($AuditOnly) { return 'Missing' }
        if ($WhatIfPreference) { return 'Planned' }
        throw "Target object $TargetDn does not exist"
    }

    $sd = Get-Acl -Path $path -Audit -ErrorAction Stop

    foreach ($ace in $sd.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        if ($ace.IdentityReference.Value -ne $rule.IdentityReference.Value) { continue }
        if ($ace.ObjectType -ne $rule.ObjectType) { continue }
        if ($ace.InheritedObjectType -ne $rule.InheritedObjectType) { continue }
        if ($ace.InheritanceType -ne $rule.InheritanceType) { continue }
        if (($ace.AuditFlags -band $rule.AuditFlags) -ne $rule.AuditFlags) { continue }
        if (($ace.ActiveDirectoryRights -band $rule.ActiveDirectoryRights) -eq $rule.ActiveDirectoryRights) {
            return 'Compliant'
        }
    }

    if ($AuditOnly) { return 'Missing' }

    if ($PSCmdlet.ShouldProcess($TargetDn, "Audit $AuditFlags '$Rights' for SID $PrincipalSid")) {
        $sd.AddAuditRule($rule)
        Set-Acl -Path $path -AclObject $sd -ErrorAction Stop
        return 'Created'
    }

    return 'Planned'
}

function Disable-TierAclInheritance {
    <#
        .SYNOPSIS
        Blocks ACL inheritance on an OU and optionally keeps the inherited ACEs as explicit ones.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$TargetDn,
        [switch]$PreserveInherited
    )

    $ad = Get-TierAdParameter
    $object = $null
    try { $object = Get-ADObject -Identity $TargetDn -Properties nTSecurityDescriptor @ad -ErrorAction Stop }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        if ($WhatIfPreference) { return 'Planned' }
        throw
    }
    $sd = $object.nTSecurityDescriptor

    if ($sd.AreAccessRulesProtected) { return 'Compliant' }

    if ($PSCmdlet.ShouldProcess($TargetDn, 'Block ACL inheritance')) {
        $sd.SetAccessRuleProtection($true, [bool]$PreserveInherited)
        Set-ADObject -Identity $TargetDn -Replace @{ nTSecurityDescriptor = $sd } @ad -ErrorAction Stop
        return 'Updated'
    }

    return 'Planned'
}

#endregion ACL

####################################################################################################
#region GPO
#  GPO creation, security template (GptTmpl.inf), CSE registration, version bump, links.
####################################################################################################

$script:SecurityCse = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
$script:SecurityTool = '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'

function New-TierGpoIfMissing {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Comment,
        [switch]$AuditOnly
    )

    $ctx = Get-TierContext
    $existing = Get-GPO -Name $Name -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction SilentlyContinue

    if ($existing) {
        return [pscustomobject]@{ Gpo = $existing; Result = 'Compliant' }
    }

    if ($AuditOnly) {
        return [pscustomobject]@{ Gpo = $null; Result = 'Missing' }
    }

    if ($PSCmdlet.ShouldProcess($Name, 'Create Group Policy Object')) {
        $gpo = New-GPO -Name $Name -Comment $Comment -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop
        return [pscustomobject]@{ Gpo = $gpo; Result = 'Created' }
    }

    return [pscustomobject]@{ Gpo = $null; Result = 'Planned' }
}

function Get-TierGpoSysvolPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$GpoId)

    $ctx = Get-TierContext
    return Join-Path $ctx.SysvolPolicyPath ("{" + $GpoId.ToString().ToUpper() + "}")
}

function ConvertTo-TierSecurityTemplate {
    <#
        .SYNOPSIS
        Builds the content of a GptTmpl.inf from user rights and restricted group definitions.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$UserRights = @{},
        [hashtable]$RestrictedGroups = @{},
        [ValidateSet('MemberOf', 'Replace')][string]$RestrictedGroupsMode = 'MemberOf'
    )

    # Section order follows what secedit itself writes: Unicode, Version, then the payload.
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('[Unicode]')
    [void]$sb.AppendLine('Unicode=yes')
    [void]$sb.AppendLine('[Version]')
    [void]$sb.AppendLine('signature="$CHICAGO$"')
    [void]$sb.AppendLine('Revision=1')

    if ($UserRights.Count -gt 0) {
        [void]$sb.AppendLine('[Privilege Rights]')
        foreach ($right in ($UserRights.Keys | Sort-Object)) {
            $sids = @($UserRights[$right]) | Where-Object { $_ } | Sort-Object -Unique

            # 'SeSomeRight = ' with nothing after it does not mean 'leave alone' - it means
            # 'nobody holds this right'. Writing that line for a right whose principals failed to
            # resolve would silently strip it from everyone, including the administrators.
            if ($sids.Count -eq 0) { continue }

            $value = ($sids | ForEach-Object { ConvertTo-TierSidString -Sid $_ }) -join ','
            [void]$sb.AppendLine("$right = $value")
        }
    }

    if ($RestrictedGroups.Count -gt 0) {
        [void]$sb.AppendLine('[Group Membership]')

        if ($RestrictedGroupsMode -eq 'Replace') {
            # Strict: the listed members become the ONLY members of the target group.
            # Everything else, including Domain Admins, is removed on every policy refresh.
            foreach ($groupSid in ($RestrictedGroups.Keys | Sort-Object)) {
                $members = @($RestrictedGroups[$groupSid]) | Where-Object { $_ } | Sort-Object -Unique
                $memberValue = ($members | ForEach-Object { ConvertTo-TierSidString -Sid $_ }) -join ','
                $key = ConvertTo-TierSidString -Sid $groupSid
                [void]$sb.AppendLine("$key" + '__Memberof =')
                [void]$sb.AppendLine("$key" + "__Members = $memberValue")
            }
        }
        else {
            # Additive: each access group is declared a member of the target group.
            # Existing members are left untouched, which cannot lock anyone out.
            #
            # Both lines per entry are required - this is exactly what GPMC itself writes:
            #   <accessGroup>__Memberof = <targetGroup>
            #   <accessGroup>__Members  =
            # Omitting the empty __Members line makes the entry unreliable to parse.
            $memberOf = @{}
            foreach ($groupSid in $RestrictedGroups.Keys) {
                foreach ($member in (@($RestrictedGroups[$groupSid]) | Where-Object { $_ })) {
                    if (-not $memberOf.ContainsKey($member)) { $memberOf[$member] = [System.Collections.Generic.List[string]]::new() }
                    if ($memberOf[$member] -notcontains $groupSid) { $memberOf[$member].Add($groupSid) }
                }
            }

            foreach ($member in ($memberOf.Keys | Sort-Object)) {
                $key = ConvertTo-TierSidString -Sid $member
                $targets = ($memberOf[$member] | Sort-Object | ForEach-Object { ConvertTo-TierSidString -Sid $_ }) -join ','
                [void]$sb.AppendLine("$key" + "__Memberof = $targets")
                [void]$sb.AppendLine("$key" + '__Members =')
            }
        }
    }

    return $sb.ToString()
}

function Set-TierGpoSecurityTemplate {
    <#
        .SYNOPSIS
        Writes the security template into SYSVOL and refreshes the GPO metadata.

        .OUTPUTS
        'Created', 'Updated', 'Compliant', 'Missing' or 'Planned'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [hashtable]$UserRights = @{},
        [hashtable]$RestrictedGroups = @{},
        [ValidateSet('MemberOf', 'Replace')][string]$RestrictedGroupsMode = 'MemberOf',
        [switch]$AuditOnly
    )

    if ($UserRights.Count -eq 0 -and $RestrictedGroups.Count -eq 0) { return 'Compliant' }

    $gpoPath = Get-TierGpoSysvolPath -GpoId $GpoId
    $secEditDir = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\SecEdit'
    $tmplPath = Join-Path $secEditDir 'GptTmpl.inf'

    $desired = ConvertTo-TierSecurityTemplate -UserRights $UserRights -RestrictedGroups $RestrictedGroups -RestrictedGroupsMode $RestrictedGroupsMode

    $current = $null
    if (Test-Path -LiteralPath $tmplPath) {
        $current = [System.IO.File]::ReadAllText($tmplPath)
    }

    $normalize = { param($t) if ($null -eq $t) { '' } else { ($t -replace "`r`n", "`n").Trim() } }

    if ((& $normalize $current) -eq (& $normalize $desired)) {
        return 'Compliant'
    }

    if ($AuditOnly) {
        if ($current) { return 'Drift' } else { return 'Missing' }
    }

    if (-not $PSCmdlet.ShouldProcess("GPO $GpoId", 'Write security template (user rights / restricted groups)')) {
        return 'Planned'
    }

    if (-not (Test-Path -LiteralPath $secEditDir)) {
        New-Item -Path $secEditDir -ItemType Directory -Force | Out-Null
    }

    if ($current) {
        $backup = "$tmplPath.bak-$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item -LiteralPath $tmplPath -Destination $backup -Force
        Write-TierLog -Message "Existing security template backed up to $backup" -Level Info
    }

    # GptTmpl.inf must be UTF-16 LE.
    [System.IO.File]::WriteAllText($tmplPath, $desired, [System.Text.Encoding]::Unicode)

    Add-TierGpoClientSideExtension -GpoId $GpoId | Out-Null
    Update-TierGpoVersion -GpoId $GpoId | Out-Null

    if ($current) { return 'Updated' } else { return 'Created' }
}

function Add-TierGpoClientSideExtension {
    <#
        .SYNOPSIS
        Ensures the security CSE is registered in gPCMachineExtensionNames.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][guid]$GpoId)

    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $gpoDn = "CN={$($GpoId.ToString().ToUpper())},CN=Policies,CN=System,$($ctx.DomainDn)"

    $obj = Get-ADObject -Identity $gpoDn -Properties gPCMachineExtensionNames @ad -ErrorAction Stop
    $currentValue = [string]$obj.gPCMachineExtensionNames

    $blocks = [System.Collections.Generic.List[string]]::new()
    if ($currentValue) {
        foreach ($match in [regex]::Matches($currentValue, '\[[^\]]+\]')) {
            $blocks.Add($match.Value)
        }
    }

    if ($blocks -notcontains "[$script:SecurityCse$script:SecurityTool]") {
        $existingSecurity = @($blocks | Where-Object { $_.StartsWith("[$script:SecurityCse") }) | Select-Object -First 1
        if ($existingSecurity) {
            # CSE already present with other tool GUIDs - append ours inside the block.
            $index = $blocks.IndexOf($existingSecurity)
            if ($existingSecurity -notlike "*$script:SecurityTool*") {
                $blocks[$index] = $existingSecurity.TrimEnd(']') + $script:SecurityTool + ']'
            }
        }
        else {
            $blocks.Add("[$script:SecurityCse$script:SecurityTool]")
        }
    }
    else {
        return 'Compliant'
    }

    $newValue = ($blocks | Sort-Object) -join ''

    if ($PSCmdlet.ShouldProcess($gpoDn, 'Register security client side extension')) {
        # -Replace fails when the attribute has never been set, which is the case for a freshly
        # created GPO, so the empty case has to use -Add.
        if ([string]::IsNullOrEmpty($currentValue)) {
            Set-ADObject -Identity $gpoDn -Add @{ gPCMachineExtensionNames = $newValue } @ad -ErrorAction Stop
        }
        else {
            Set-ADObject -Identity $gpoDn -Replace @{ gPCMachineExtensionNames = $newValue } @ad -ErrorAction Stop
        }
        return 'Updated'
    }

    return 'Planned'
}

function Update-TierGpoVersion {
    <#
        .SYNOPSIS
        Increments the machine part of the GPO version in AD and in GPT.INI.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][guid]$GpoId)

    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $gpoDn = "CN={$($GpoId.ToString().ToUpper())},CN=Policies,CN=System,$($ctx.DomainDn)"

    $obj = Get-ADObject -Identity $gpoDn -Properties versionNumber @ad -ErrorAction Stop
    $version = [int]$obj.versionNumber
    $userVersion = ($version -shr 16) -band 0xFFFF
    $machineVersion = $version -band 0xFFFF
    $newVersion = (($userVersion -shl 16) -bor (($machineVersion + 1) -band 0xFFFF))

    if (-not $PSCmdlet.ShouldProcess($gpoDn, "Bump GPO version to $newVersion")) { return 'Planned' }

    Set-ADObject -Identity $gpoDn -Replace @{ versionNumber = $newVersion } @ad -ErrorAction Stop

    $gptIni = Join-Path (Get-TierGpoSysvolPath -GpoId $GpoId) 'GPT.INI'
    if (Test-Path -LiteralPath $gptIni) {
        $content = Get-Content -LiteralPath $gptIni
        if ($content -match '^Version=') {
            $content = $content -replace '^Version=.*', "Version=$newVersion"
        }
        else {
            $content += "Version=$newVersion"
        }
        Set-Content -LiteralPath $gptIni -Value $content -Encoding ASCII
    }
    else {
        Set-Content -LiteralPath $gptIni -Value @('[General]', "Version=$newVersion") -Encoding ASCII
    }

    return 'Updated'
}

function Set-TierGpoRegistrySetting {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)]$Value,
        [switch]$AuditOnly
    )

    $ctx = Get-TierContext

    $current = Get-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction SilentlyContinue

    if ($current -and "$($current.Value)" -eq "$Value") { return 'Compliant' }
    if ($AuditOnly) {
        if ($current) { return 'Drift' } else { return 'Missing' }
    }

    if ($PSCmdlet.ShouldProcess("$GpoName : $Key\$ValueName", "Set registry value to $Value")) {
        Set-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName -Type $Type -Value $Value `
            -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop | Out-Null
        if ($current) { return 'Updated' } else { return 'Created' }
    }

    return 'Planned'
}

function Set-TierDirectoryOwner {
    <#
        .SYNOPSIS
        Writes the owner of a directory object and confirms that it took.

        .DESCRIPTION
        Owner assignment does not go through Set-ADObject. Replacing nTSecurityDescriptor there
        writes the DACL and drops the owner portion without raising anything - the call succeeds,
        the owner is unchanged, and any code that trusts the return value reports a correction
        that never happened. The owner sits behind its own security mask, and the cmdlet does not
        set it.

        Set-Acl on the AD provider does. The DirectoryEntry route that would set the mask by hand
        was measured against a Server 2025 domain controller and does not work from Windows
        PowerShell 5.1 - DirectoryEntryConfiguration comes back null even after the entry is
        bound, so the mask can never be set and the owner is left untouched.

        The write is read back afterwards, always. A write the directory accepts without applying
        is the failure mode this function exists for, and it must not be possible to report a
        correction without having looked.

        .OUTPUTS
        $true when the owner is confirmed changed. Throws when the write did not take effect.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dn,
        [Parameter(Mandatory)][string]$OwnerSid
    )

    $ctx = Get-TierContext
    $sid = New-TierSecurityIdentifier -Sid $OwnerSid

    # The write has to land on the same domain controller the rest of the run reads from. The AD:
    # drive is bound to whichever server the session picked, so when -Server names a different
    # one, a temporary drive is used instead: otherwise the write goes to one DC, the read-back
    # queries another, and replication latency turns into a failure that is not one.
    $drive = $null
    $prefix = 'AD:'
    if ($ctx.Server) {
        $name = "TierOwner$PID"
        try {
            $drive = New-PSDrive -Name $name -PSProvider ActiveDirectory -Server $ctx.Server -Root '//RootDSE/' -Scope Script -ErrorAction Stop
            $prefix = "${name}:"
        }
        catch {
            Write-TierLog -Message "Could not bind a directory drive to $($ctx.Server) - falling back to the session default for the owner write" -Level Warning
        }
    }

    try {
        $acl = Get-Acl -Path "$prefix$Dn" -ErrorAction Stop
        $acl.SetOwner($sid)
        Set-Acl -Path "$prefix$Dn" -AclObject $acl -ErrorAction Stop
    }
    finally {
        if ($drive) { Remove-PSDrive -Name $drive.Name -Force -ErrorAction SilentlyContinue }
    }

    if (Test-TierObjectOwner -Dn $Dn -OwnerSid $OwnerSid) { return $true }

    throw "The owner of $Dn is unchanged after the write - the directory accepted the change without applying it."
}

function Test-TierObjectOwner {
    <#
        .SYNOPSIS
        Reads back the owner of an object and reports whether it matches.

        .DESCRIPTION
        Separate from the write on purpose. A write that the directory accepts without applying
        is the failure this code exists to catch, so the check has to be a real round trip to the
        directory rather than the return value of the call that just claimed to have done it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dn,
        [Parameter(Mandatory)][string]$OwnerSid
    )

    $ad = Get-TierAdParameter
    try {
        $object = Get-ADObject -Identity $Dn -Properties nTSecurityDescriptor @ad -ErrorAction Stop
        $owner = $object.nTSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier])
        return ($owner -and $owner.Value -eq $OwnerSid)
    }
    catch {
        return $false
    }
}

function Set-TierGpoOwner {
    <#
        .SYNOPSIS
        Ensures a policy object is owned by the declared principal rather than by whoever created
        it.

        .OUTPUTS
        'Created', 'Compliant', 'Missing' or 'Planned'

        .DESCRIPTION
        An owner holds WRITE_DAC implicitly, whatever the DACL says. A policy created by a
        delegated administrator is therefore permanently re-permissionable by that administrator,
        which quietly undoes any granular delegation placed on it afterwards. Objects created by a
        member of Domain Admins get Domain Admins as owner; everything else gets its creator, so
        this only has work to do where delegation is actually in use.

        The SYSVOL side of the same problem is not addressed here - the file system ACL of the
        policy folder has its own owner, and changing it needs SeRestorePrivilege on the share.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$GpoDn,
        [Parameter(Mandatory)][string]$OwnerSid,
        [switch]$AuditOnly
    )

    $ad = Get-TierAdParameter

    $object = $null
    try { $object = Get-ADObject -Identity $GpoDn -Properties nTSecurityDescriptor @ad -ErrorAction Stop }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        if ($AuditOnly) { return 'Missing' }
        if ($WhatIfPreference) { return 'Planned' }
        throw
    }

    $sd = $object.nTSecurityDescriptor
    $current = $sd.GetOwner([System.Security.Principal.SecurityIdentifier])
    if ($current -and $current.Value -eq $OwnerSid) { return 'Compliant' }

    if ($AuditOnly) { return 'Missing' }

    if ($PSCmdlet.ShouldProcess($GpoDn, "Set owner to SID $OwnerSid")) {
        Set-TierDirectoryOwner -Dn $GpoDn -OwnerSid $OwnerSid | Out-Null
        return 'Created'
    }

    return 'Planned'
}

function Set-TierGpoDelegation {
    <#
        .SYNOPSIS
        Applies the per-GPO permission delegation declared in the configuration.

        .DESCRIPTION
        Editing rights are granted through the GroupPolicy module rather than by writing ACEs,
        because a policy object carries permissions in two places - the directory object and the
        SYSVOL folder - and Set-GPPermission keeps both consistent.

        'GpoEdit' is as granular as this gets, and it is not granular enough: it maps to write
        access on all properties, which includes displayName and gPCWQLFilter. A delegate can
        therefore rename the policy and change its WMI filter, and changing the filter changes
        which machines the policy applies to. The narrower alternative - write access to
        versionNumber and the two extension name attributes only - is refused by the GPMC, which
        will not open a policy it cannot fully write. Auditing displayName and gPCWQLFilter is the
        available mitigation; see the auditing section of the configuration.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Gpo,
        [Parameter(Mandatory)][object]$Delegation,
        [switch]$AuditOnly
    )

    $results = [System.Collections.Generic.List[object]]::new()

    $levels = [ordered]@{
        editors = 'GpoEdit'
        readers = 'GpoRead'
    }

    foreach ($field in $levels.Keys) {
        if (-not ($Delegation.PSObject.Properties.Name -contains $field)) { continue }

        foreach ($reference in @($Delegation.$field | Where-Object { $_ })) {
            $principal = Resolve-TierPrincipal -Reference $reference -AllowMissing
            if (-not $principal) {
                $results.Add([pscustomobject]@{ Target = "$reference on $($Gpo.DisplayName)"; Result = if ($WhatIfPreference) { 'Planned' } else { 'Missing' } })
                continue
            }

            $wanted = $levels[$field]
            $current = $null
            try {
                $current = Get-GPPermission -Guid $Gpo.Id -TargetName $principal.Name -TargetType Group -ErrorAction SilentlyContinue
            }
            catch {
                # Get-GPPermission throws rather than returning nothing when the trustee holds no
                # permission at all, which is the normal case on first deployment.
                $current = $null
            }

            # GpoEditDeleteModifySecurity is a superset of GpoEdit; treating it as drift would
            # fight with a deliberate grant made outside the tool.
            $satisfied = $current -and (
                $current.Permission -eq $wanted -or
                ($wanted -eq 'GpoEdit' -and $current.Permission -eq 'GpoEditDeleteModifySecurity') -or
                ($wanted -eq 'GpoRead' -and $current.Permission -in @('GpoEdit', 'GpoApply', 'GpoEditDeleteModifySecurity'))
            )

            if ($satisfied) {
                $results.Add([pscustomobject]@{ Target = "$reference $wanted on $($Gpo.DisplayName)"; Result = 'Compliant' })
                continue
            }

            if ($AuditOnly) {
                $results.Add([pscustomobject]@{ Target = "$reference $wanted on $($Gpo.DisplayName)"; Result = 'Missing' })
                continue
            }

            if ($PSCmdlet.ShouldProcess($Gpo.DisplayName, "Grant $wanted to $reference")) {
                try {
                    Set-GPPermission -Guid $Gpo.Id -TargetName $principal.Name -TargetType Group -PermissionLevel $wanted -ErrorAction Stop | Out-Null
                    $results.Add([pscustomobject]@{ Target = "$reference $wanted on $($Gpo.DisplayName)"; Result = 'Created' })
                }
                catch {
                    $results.Add([pscustomobject]@{ Target = "$reference $wanted on $($Gpo.DisplayName)"; Result = 'Failed'; Detail = $_.Exception.Message })
                }
            }
            else {
                $results.Add([pscustomobject]@{ Target = "$reference $wanted on $($Gpo.DisplayName)"; Result = 'Planned' })
            }
        }
    }

    return $results
}

function Set-TierGpoLink {
    <#
        .SYNOPSIS
        Creates or converges a GPO link, including whether it is enabled.

        .DESCRIPTION
        The enabled state is part of the declared configuration, not something the tool decides.
        Without that, disabling a link by hand - which is exactly what you do during a lockout or
        a staged rollout - would be silently reverted by the next deployment, and the intent
        behind the change would live nowhere but in the directory.

        Set linkEnabled to false on a GPO to keep it linked but inactive.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$TargetDn,
        [switch]$Enforced,
        [bool]$LinkEnabled = $true,
        [switch]$AuditOnly
    )

    $ctx = Get-TierContext
    $enforcedValue = if ($Enforced) { 'Yes' } else { 'No' }
    $enabledValue = if ($LinkEnabled) { 'Yes' } else { 'No' }

    $inheritance = Get-GPInheritance -Target $TargetDn -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop
    $link = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }

    if ($link) {
        $needsUpdate = ($link.Enforced -ne [bool]$Enforced) -or ($link.Enabled -ne $LinkEnabled)
        if (-not $needsUpdate) { return 'Compliant' }
        if ($AuditOnly) { return 'Drift' }

        if ($PSCmdlet.ShouldProcess("$GpoName -> $TargetDn", "Update GPO link (enabled=$enabledValue, enforced=$enforcedValue)")) {
            Set-GPLink -Name $GpoName -Target $TargetDn -LinkEnabled $enabledValue -Enforced $enforcedValue `
                -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop | Out-Null
            return 'Updated'
        }
        return 'Planned'
    }

    if ($AuditOnly) { return 'Missing' }

    if ($PSCmdlet.ShouldProcess("$GpoName -> $TargetDn", "Link GPO (enabled=$enabledValue, enforced=$enforcedValue)")) {
        New-GPLink -Name $GpoName -Target $TargetDn -LinkEnabled $enabledValue -Enforced $enforcedValue `
            -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop | Out-Null
        return 'Created'
    }

    return 'Planned'
}

#endregion GPO

####################################################################################################
#region ConfigurationGenerator
#  Builds a complete configuration document from naming patterns.
####################################################################################################

function New-TierModelConfiguration {
    <#
        .SYNOPSIS
        Generates a tier model configuration from naming patterns.

        .DESCRIPTION
        All name patterns support the following placeholders:

          {ID}       tier number, e.g. 0
          {TIER}     resolved tier name, e.g. Tier-0
          {TOKEN}    short tier token, e.g. T0
          {TOKENLC}  short tier token in lower case, e.g. t0
          {ROLE}     role word, e.g. Admins        (role group pattern only)
          {RESOURCE} resource word, e.g. DenyLogon (access group pattern only)
          {PURPOSE}  purpose word, e.g. template   (account and GPO patterns only)

        .EXAMPLE
        New-TierModelConfiguration -RootOu 'Tiering' -RoleGroupPattern 'G-{TOKEN}-{ROLE}' |
            ConvertTo-Json -Depth 10 | Set-Content .\config\tiermodel.json
    #>
    [CmdletBinding()]
    param(
        [string]$ModelName = 'Administrative Tier Model',
        [ValidateRange(2, 4)][int]$TierCount = 3,

        [string]$DomainFqdn,
        [string]$RootOu = 'Tiering',

        [string]$TierNamePattern = 'Tier-{ID}',
        [string]$TierTokenPattern = 'T{ID}',

        [string]$AccountsOuName = 'Accounts',
        [string]$GroupsOuName = 'Groups',
        [string]$ServersOuName = 'Servers',
        [string]$DevicesOuName = 'Devices',
        [string]$ServiceAccountsOuName = 'Service-Accounts',
        [string]$StagingOuName = 'Staging',

        [string]$RoleGroupPattern = 'G-{TOKEN}-{ROLE}',
        [string]$AccessGroupPattern = 'DL-{TOKEN}-{RESOURCE}',
        [string]$AdminAccountPattern = 'adm-{TOKENLC}-{PURPOSE}',
        [string]$GpoPattern = '{TOKEN}-{PURPOSE}',
        [string]$GpoExceptionGroupPattern = 'DL-{TOKEN}-Exempt-{PURPOSE}',
        [string]$LapsGpoPattern = '{TOKEN}-LAPS',
        [string]$SiloNamePattern = '{TIER}-Silo',
        [string]$SiloPolicyNamePattern = '{TIER}-AuthPolicy',

        [string]$AdminRoleName = 'Admins',
        [string]$OperatorRoleName = 'Operators',
        [string]$LocalAdminsResourceName = 'LocalAdmins',
        [string]$RemoteDesktopResourceName = 'RemoteDesktop',
        [string]$DenyLogonResourceName = 'DenyLogon',

        [ValidateSet('Deny', 'AllowList')][string]$LogonRightsMode = 'Deny',

        [ValidateSet('Granular', 'FullControl')][string]$DelegationModel = 'Granular',

        [switch]$DenyNetworkLogonAcrossTiers,

        [bool]$EnableAuditing = $true,

        [ValidateSet('Report', 'Enforce')][string]$PrivilegedGroupMode = 'Report',

        [hashtable]$Options
    )

    $defaultOptions = [ordered]@{
        protectOusFromAccidentalDeletion   = $true
        blockInheritanceOnTierRoots        = $false
        blockGpoInheritanceOnTierRoots      = $true
        createAdminAccounts                = $true
        adminAccountsDisabledOnCreation    = $true
        adminAccountsSensitiveNoDelegation = $true
        addTier0AdminsToProtectedUsers     = $true
        enableAdRecycleBin                 = $true
        machineAccountQuota                = 0
        redirectComputersTo                = $null
        redirectUsersTo                    = $null
        enableSiteLinkNotification         = $true
        deployWindowsLaps                  = $true
        createKdsRootKey                   = $true
        kdsRootKeyEffectiveImmediately     = $false
        createGpos                         = $true
        restrictedGroupsMode               = 'MemberOf'
        linkGpos                           = $true
        enforceGpoLinks                    = $true
        createAuthenticationPolicySilo     = $true
        authenticationPolicyEnforcement    = 'Audit'
        tier0TgtLifetimeMinutes            = 240
    }

    if ($Options) {
        foreach ($key in $Options.Keys) { $defaultOptions[$key] = $Options[$key] }
    }

    $tierDescriptions = @(
        'Control plane: domain controllers, AD, PKI, identity and directory synchronisation infrastructure.',
        'Server and application plane: member servers, business applications, databases.',
        'Workstation and end user plane: clients, helpdesk, standard users.',
        'Additional plane: define the scope for this tier before using it.'
    )

    # ---- resolve names for every tier ---------------------------------------------------
    $tierMeta = @()
    for ($id = 0; $id -lt $TierCount; $id++) {
        $base = @{ ID = $id }
        $tierName = Expand-TierName -Pattern $TierNamePattern -Tokens $base
        $token = Expand-TierName -Pattern $TierTokenPattern -Tokens $base

        $tokens = @{
            ID      = $id
            TIER    = $tierName
            TOKEN   = $token
            TOKENLC = $token.ToLower()
        }

        $tierMeta += [pscustomobject]@{
            Id          = $id
            Name        = $tierName
            Token       = $token
            Tokens      = $tokens
            IsTop       = ($id -eq 0)
            IsWorkplace = ($id -eq $TierCount - 1)
            Admins      = (Expand-TierName -Pattern $RoleGroupPattern -Tokens ($tokens + @{ ROLE = $AdminRoleName }))
            Operators   = (Expand-TierName -Pattern $RoleGroupPattern -Tokens ($tokens + @{ ROLE = $OperatorRoleName }))
            LocalAdmins = (Expand-TierName -Pattern $AccessGroupPattern -Tokens ($tokens + @{ RESOURCE = $LocalAdminsResourceName }))
            RemoteDesk  = (Expand-TierName -Pattern $AccessGroupPattern -Tokens ($tokens + @{ RESOURCE = $RemoteDesktopResourceName }))
            DenyLogon   = (Expand-TierName -Pattern $AccessGroupPattern -Tokens ($tokens + @{ RESOURCE = $DenyLogonResourceName }))
        }
    }

    # ---- build the tier definitions -----------------------------------------------------
    $tiers = @()
    foreach ($meta in $tierMeta) {

        $ous = [System.Collections.Generic.List[object]]::new()
        $ous.Add([ordered]@{ name = $AccountsOuName; description = "$($meta.Name) administrative user accounts" })
        $ous.Add([ordered]@{ name = $GroupsOuName; description = "$($meta.Name) role and access groups" })
        if (-not $meta.IsWorkplace) {
            $serverNote = if ($meta.IsTop) { "$($meta.Name) servers. Domain controllers stay in OU=Domain Controllers." } else { "$($meta.Name) member servers" }
            $ous.Add([ordered]@{ name = $ServersOuName; description = $serverNote })
        }
        $deviceNote = if ($meta.IsTop) { 'Privileged access workstations used to administer this tier' } elseif ($meta.IsWorkplace) { 'End user workstations' } else { 'Administrative workstations and jump hosts for this tier' }
        $ous.Add([ordered]@{ name = $DevicesOuName; description = $deviceNote })
        $ous.Add([ordered]@{ name = $ServiceAccountsOuName; description = "$($meta.Name) service accounts, gMSA and dMSA" })
        $ous.Add([ordered]@{ name = $StagingOuName; description = "Landing zone for newly joined $($meta.Name) systems before they are moved into the tier" })

        # deny-logon group holds the admin and operator groups of every other tier
        $denyMembers = @()
        foreach ($other in $tierMeta) {
            if ($other.Id -eq $meta.Id) { continue }
            $denyMembers += $other.Admins
            $denyMembers += $other.Operators
        }

        $groups = @(
            [ordered]@{ name = $meta.Admins; scope = 'Global'; targetOu = $GroupsOuName; description = "$($meta.Name) administrators (role group)"; members = @() }
            [ordered]@{ name = $meta.Operators; scope = 'Global'; targetOu = $GroupsOuName; description = "$($meta.Name) operators without directory write permissions"; members = @() }
            [ordered]@{ name = $meta.LocalAdmins; scope = 'DomainLocal'; targetOu = $GroupsOuName; description = "Nested into the local Administrators group of $($meta.Name) systems"; members = @($meta.Admins) }
            [ordered]@{ name = $meta.RemoteDesk; scope = 'DomainLocal'; targetOu = $GroupsOuName; description = "Nested into the local Remote Desktop Users group of $($meta.Name) systems"; members = @($meta.Admins, $meta.Operators) }
            [ordered]@{ name = $meta.DenyLogon; scope = 'DomainLocal'; targetOu = $GroupsOuName; description = "Principals that must never authenticate to a $($meta.Name) system"; members = $denyMembers }
        )

        $accounts = @()
        if ($meta.IsTop) {
            $accounts += [ordered]@{
                samAccountName = (Expand-TierName -Pattern $AdminAccountPattern -Tokens ($meta.Tokens + @{ PURPOSE = 'breakglass' }))
                displayName    = "$($meta.Name) Break Glass Account"
                targetOu       = $AccountsOuName
                memberOf       = @($meta.Admins)
                description    = 'Emergency access account. Store the credential offline and alert on every use.'
                excludeFromSilo = $true
            }
        }
        $accounts += [ordered]@{
            samAccountName = (Expand-TierName -Pattern $AdminAccountPattern -Tokens ($meta.Tokens + @{ PURPOSE = 'template' }))
            displayName    = "$($meta.Name) Admin Template"
            targetOu       = $AccountsOuName
            memberOf       = @($meta.Admins)
            description    = "Template account - copy this object when onboarding a $($meta.Name) administrator."
        }

        foreach ($account in $accounts) {
            if ($account.samAccountName.Length -gt 20) {
                throw "The account name '$($account.samAccountName)' is $($account.samAccountName.Length) characters. sAMAccountName is limited to 20 - shorten the account naming pattern."
            }
            # Characters Active Directory rejects in a sAMAccountName.
            if ($account.samAccountName -match '[/\\\[\]:;|=,+*?<>@"]') {
                throw "The account name '$($account.samAccountName)' contains a character Active Directory does not accept in a sAMAccountName. Forbidden: / \ [ ] : ; | = , + * ? < > @ and double quotes."
            }
        }

        if ($DelegationModel -eq 'FullControl') {
            $delegations = @(
                [ordered]@{ principal = $meta.Admins; targetOu = ''; rights = 'GenericAll'; objectType = $null; inheritedObjectType = $null; inheritance = 'All'; type = 'Allow'; comment = "Full control over the $($meta.Name) branch" }
            )
        }
        else {
            # Granular: everything a tier administrator needs to run the branch, minus WriteDacl
            # and WriteOwner. Without those two an administrator cannot rewrite the delegation
            # that constrains them, which is the difference between a boundary and a suggestion.
            $delegations = @()
            foreach ($class in 'user', 'group', 'computer', 'organizationalUnit', 'contact', 'msDS-GroupManagedServiceAccount') {
                $delegations += [ordered]@{ principal = $meta.Admins; targetOu = ''; rights = 'CreateChild, DeleteChild'; objectType = $class; inheritedObjectType = $null; inheritance = 'All'; type = 'Allow'; comment = "Create and delete $class objects in the $($meta.Name) branch" }
            }
            $delegations += [ordered]@{ principal = $meta.Admins; targetOu = ''; rights = 'ReadProperty, WriteProperty, Delete, DeleteTree, ExtendedRight, Self'; objectType = $null; inheritedObjectType = $null; inheritance = 'Descendents'; type = 'Allow'; comment = "Manage every object below the $($meta.Name) branch - permissions on the branch itself stay out of reach" }
        }
        $computerOu = if ($meta.IsWorkplace) { $DevicesOuName } else { $ServersOuName }

        # Creating and deleting computer objects is not enough to actually join a machine.
        # A domain join also resets the computer account password and writes the DNS host name,
        # the service principal names and the account restrictions on the object. Without these
        # four entries an operator can pre-stage a computer but the join itself fails.
        $delegations += [ordered]@{ principal = $meta.Operators; targetOu = $computerOu; rights = 'CreateChild, DeleteChild'; objectType = 'computer'; inheritedObjectType = $null; inheritance = 'All'; type = 'Allow'; comment = "Create and delete $($meta.Name) computer objects" }
        $delegations += [ordered]@{ principal = $meta.Operators; targetOu = $computerOu; rights = 'ExtendedRight'; objectType = 'User-Force-Change-Password'; inheritedObjectType = 'computer'; inheritance = 'Descendents'; type = 'Allow'; comment = 'Reset the computer account password - required to join or rejoin' }
        $delegations += [ordered]@{ principal = $meta.Operators; targetOu = $computerOu; rights = 'Self'; objectType = 'Validated-DNS-Host-Name'; inheritedObjectType = 'computer'; inheritance = 'Descendents'; type = 'Allow'; comment = 'Validated write of the DNS host name' }
        $delegations += [ordered]@{ principal = $meta.Operators; targetOu = $computerOu; rights = 'Self'; objectType = 'Validated-SPN'; inheritedObjectType = 'computer'; inheritance = 'Descendents'; type = 'Allow'; comment = 'Validated write of the service principal names' }
        $delegations += [ordered]@{ principal = $meta.Operators; targetOu = $computerOu; rights = 'ReadProperty, WriteProperty'; objectType = 'Account-Restrictions'; inheritedObjectType = 'computer'; inheritance = 'Descendents'; type = 'Allow'; comment = 'Account restrictions property set - required to enable the joined account' }
        $delegations += [ordered]@{ principal = $meta.Operators; targetOu = $ServiceAccountsOuName; rights = 'ReadProperty, ExtendedRight'; objectType = $null; inheritance = 'All'; type = 'Allow'; comment = 'Read managed service account password blobs' }

        # Network logon is deliberately NOT denied to the other tiers by default.
        # Interactive, remote interactive, batch and service logon are what actually leak
        # credentials onto a machine; blocking network logon additionally breaks remote
        # management, agents and file access in ways that are hard to attribute afterwards.
        # S-1-5-113 is "Local account" and S-1-5-32-546 is "Guests" - both are safe to deny.
        $networkDeny = @('S-1-5-113', 'S-1-5-32-546')
        if ($DenyNetworkLogonAcrossTiers) { $networkDeny = @($meta.DenyLogon) + $networkDeny }

        # Allow lists are absolute. Authenticated Users has to stay in the network logon right or
        # nothing on the machine reaches a file share, and the built-in Administrators group is the
        # target of the restricted groups entry above, so it carries the tier's access group.
        $allowedRights = $null
        if ($LogonRightsMode -eq 'AllowList') {
            $allowedRights = [ordered]@{
                SeInteractiveLogonRight       = @('S-1-5-32-544')
                SeRemoteInteractiveLogonRight = @('S-1-5-32-544', 'S-1-5-32-555')
                SeNetworkLogonRight           = @('S-1-5-32-544', 'S-1-5-11')
            }
            # SeServiceLogonRight and SeBatchLogonRight are deliberately absent: an allow list on
            # those stops every domain service account that is not named in it. Add them by hand
            # once you know which accounts run services on the machines in this tier.
        }

        # Safety net for the domain controller baseline.
        #
        # A template that writes only Deny entries relies on the Allow side being held elsewhere.
        # On a domain controller the interactive and remote interactive rights are not necessarily
        # defined by any GPO - they can be held implicitly from the promotion defaults, and an
        # implicit right is not something a Deny-only policy can be reasoned about safely.
        # Writing the Allow side explicitly means the administrators group is always named as a
        # holder, so applying this GPO can never leave the controller without an administrative
        # logon path. This is the one place where the allow-list risk is smaller than the
        # deny-only risk.
        $baselineAllowRights = [ordered]@{
            SeInteractiveLogonRight       = @('S-1-5-32-544', $meta.Admins)
            SeRemoteInteractiveLogonRight = @('S-1-5-32-544', $meta.Admins)
        }

        $denyRights = [ordered]@{
            SeDenyInteractiveLogonRight       = @($meta.DenyLogon)
            SeDenyRemoteInteractiveLogonRight = @($meta.DenyLogon)
            SeDenyNetworkLogonRight           = $networkDeny
            SeDenyBatchLogonRight             = @($meta.DenyLogon)
            SeDenyServiceLogonRight           = @($meta.DenyLogon)
        }

        $registrySettings = @(
            [ordered]@{ key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; valueName = 'LocalAccountTokenFilterPolicy'; type = 'DWord'; value = 0; comment = 'Keep UAC remote restrictions for local accounts' }
            [ordered]@{ key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; valueName = '\\*\SYSVOL'; type = 'String'; value = 'RequireMutualAuthentication=1, RequireIntegrity=1'; comment = 'UNC hardened path - protects policy retrieval against spoofing' }
            [ordered]@{ key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; valueName = '\\*\NETLOGON'; type = 'String'; value = 'RequireMutualAuthentication=1, RequireIntegrity=1'; comment = 'UNC hardened path - protects logon script retrieval against spoofing' }
        )
        if ($meta.IsTop) {
            $registrySettings += [ordered]@{ key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; valueName = 'RunAsPPL'; type = 'DWord'; value = 1; comment = 'Run LSA as a protected process' }
        }

        $gpos = @(
            [ordered]@{
                name             = (Expand-TierName -Pattern $GpoPattern -Tokens ($meta.Tokens + @{ PURPOSE = 'Logon-Restrictions' }))
                targetOu         = ''
                comment          = "Blocks principals of all other tiers from authenticating to $($meta.Name) systems."
                userRights       = $denyRights
                restrictedGroups = [ordered]@{
                    'S-1-5-32-544' = @($meta.LocalAdmins)
                    'S-1-5-32-555' = @($meta.RemoteDesk)
                }
                allowedUserRights = $allowedRights
                linkEnabled      = $true
                registrySettings = $registrySettings
                exceptionGroup   = (Expand-TierName -Pattern $GpoExceptionGroupPattern -Tokens ($meta.Tokens + @{ PURPOSE = 'Logon' }))
                exceptionGroupOu = $GroupsOuName
            }
        )

        if ($meta.IsTop) {
            $gpos += [ordered]@{
                name             = (Expand-TierName -Pattern $GpoPattern -Tokens ($meta.Tokens + @{ PURPOSE = 'DomainController-Baseline' }))
                targetOu         = '$DomainControllers'
                comment          = 'Applies the tier logon restrictions to the Domain Controllers OU, and names the administrative holders of the logon rights explicitly so the controller can never be left without a logon path.'
                userRights        = $denyRights
                allowedUserRights = $baselineAllowRights
                linkEnabled       = $true
                restrictedGroups  = [ordered]@{}
                registrySettings  = @()
            }
        }

        $description = if ($meta.Id -lt $tierDescriptions.Count) { $tierDescriptions[$meta.Id] } else { $tierDescriptions[-1] }

        $tiers += [ordered]@{
            id                  = $meta.Id
            name                = $meta.Name
            # The token and the deny logon group are written out because role expansion needs
            # both and neither can be derived from the tier name once a custom naming pattern is
            # in play. Guessing them would put a role group in the wrong deny group, which is a
            # hole rather than an error message.
            token               = $meta.Token
            denyLogonGroup      = $meta.DenyLogon
            description         = $description
            organizationalUnits = $ous.ToArray()
            groups              = $groups
            adminAccounts       = $accounts
            delegations         = $delegations
            gpos                = $gpos
        }
    }

    $top = $tierMeta[0]

    # Machines joined without an explicit target land in the workplace tier staging OU, where
    # they at least receive a tier GPO instead of sitting in CN=Computers without any policy.
    $workplace = $tierMeta[-1]
    if ($null -eq $defaultOptions['redirectComputersTo']) {
        $defaultOptions['redirectComputersTo'] = "$($workplace.Name)/$StagingOuName"
    }
    elseif ([string]::IsNullOrWhiteSpace([string]$defaultOptions['redirectComputersTo'])) {
        $defaultOptions['redirectComputersTo'] = $null
    }

    # One silo per administrative plane. The workplace tier is left out on purpose: pinning
    # every end user workstation into a silo is a different project with a different risk profile.
    $silos = @()
    foreach ($meta in $tierMeta) {
        if ($meta.IsWorkplace) { continue }

        $computerOus = @("$($meta.Name)/$DevicesOuName", "$($meta.Name)/$ServersOuName")

        $silos += [ordered]@{
            name                     = (Expand-TierName -Pattern $SiloNamePattern -Tokens $meta.Tokens)
            policyName               = (Expand-TierName -Pattern $SiloPolicyNamePattern -Tokens $meta.Tokens)
            description              = "Restricts $($meta.Name) accounts to $($meta.Name) systems using Kerberos armouring."
            memberGroups             = @($meta.Admins, $meta.Operators)
            memberComputerOus        = $computerOus
            includeDomainControllers = [bool]$meta.IsTop
        }
    }

    # Built-in groups that must not hold anything outside the top tier. Addressed by SID:
    # 512 Domain Admins, 519 Enterprise Admins, 518 Schema Admins, 526 Key Admins,
    # S-1-5-32-544 Administrators, -548 Account Operators, -549 Server Operators,
    # -550 Print Operators, -551 Backup Operators.
    $privileged = @(
        [ordered]@{ sid = '512'; allowedMembers = @($top.Admins); comment = 'Domain Admins - top tier administrators only' }
        [ordered]@{ sid = '519'; allowedMembers = @(); comment = 'Enterprise Admins - empty outside change windows' }
        [ordered]@{ sid = '518'; allowedMembers = @(); comment = 'Schema Admins - empty outside change windows' }
        [ordered]@{ sid = '526'; allowedMembers = @(); comment = 'Key Admins' }
        [ordered]@{ sid = 'S-1-5-32-548'; allowedMembers = @(); comment = 'Account Operators - no legitimate use in a tier model' }
        [ordered]@{ sid = 'S-1-5-32-549'; allowedMembers = @(); comment = 'Server Operators - grants logon to domain controllers' }
        [ordered]@{ sid = 'S-1-5-32-550'; allowedMembers = @(); comment = 'Print Operators - can load drivers on domain controllers' }
        [ordered]@{ sid = 'S-1-5-32-551'; allowedMembers = @(); comment = 'Backup Operators - can read the whole directory database' }
    )

    # Windows LAPS, one delegation and one policy GPO per tier. The domain controller OU is a
    # special case: its DSRM decryptor is fixed to Domain Admins by design, so no decryptor group
    # and no policy GPO is configured for it here.
    $lapsDelegations = @(
        [ordered]@{
            targetOu               = '$DomainControllers'
            computerSelfPermission = $true
            readGroup              = $top.Admins
            resetGroup             = $top.Admins
            decryptorGroup         = $null
            gpoName                = $null
            comment                = 'Domain controllers store the DSRM password; its decryptor is always Domain Admins.'
        }
    )
    foreach ($meta in $tierMeta) {
        $lapsDelegations += [ordered]@{
            targetOu               = $meta.Name
            computerSelfPermission = $true
            readGroup              = $meta.Admins
            resetGroup             = $meta.Admins
            decryptorGroup         = $meta.Admins
            gpoName                = (Expand-TierName -Pattern $LapsGpoPattern -Tokens $meta.Tokens)
            comment                = "Local administrator passwords of $($meta.Name) machines are readable only by $($meta.Admins)."
        }
    }

    $configuration = [ordered]@{
        schemaVersion = '1.0'
        metadata      = [ordered]@{
            name        = $ModelName
            description = "Generated tier model with $TierCount tiers."
            revision    = 1
            generatedOn = (Get-Date).ToString('yyyy-MM-dd')
        }
        domain        = [ordered]@{
            fqdn              = $DomainFqdn
            rootOu            = $RootOu
            rootOuDescription = 'Root of the administrative tier model. Managed declaratively - do not edit by hand.'
        }
        options       = $defaultOptions
        tiers         = $tiers
        # Roles expand into groups, template accounts, delegations, cross-tier deny nesting and
        # silo membership at load time. The wizard writes the key empty rather than omitting it,
        # because a key that is present in the file is one somebody will read the comment on.
        # config/roles.example.json holds ready-made DNS and Group Policy roles.
        roles         = @()
        # Generated by role expansion at load time. Present and empty so that a hand-written entry
        # has somewhere obvious to go: it nests a group into a built-in group such as DnsAdmins,
        # additively, and never removes anything.
        builtInNesting = @()
        # An owner holds WRITE_DAC implicitly, so an object owned by a delegated administrator is
        # one whose permissions that administrator can rewrite. Report mode by default: the first
        # run after a rollout finds nothing, and what it finds later is worth reading before it is
        # corrected automatically.
        ownership     = [ordered]@{
            enabled          = $true
            mode             = 'Report'
            owner            = '512'
            acceptableOwners = @()
            scopes           = @('$ModelRoot')
            objectClasses    = @('user', 'group', 'computer', 'organizationalUnit', 'msDS-GroupManagedServiceAccount')
            maxObjects       = 5000
        }
        windowsLaps = [ordered]@{
            enabled      = [bool]$defaultOptions['deployWindowsLaps']
            updateSchema = $true
            policy       = [ordered]@{
                backupDirectory                     = 2
                passwordAgeDays                     = 30
                passwordLength                      = 24
                passwordComplexity                  = 4
                administratorAccountName            = $null
                passwordExpirationProtectionEnabled = 1
                adEncryptedPasswordHistorySize      = 12
                postAuthenticationActions           = 3
                postAuthenticationResetDelay        = 8
            }
            delegations  = $lapsDelegations
        }
        privilegedGroups = [ordered]@{
            mode   = $PrivilegedGroupMode
            groups = $privileged
        }
        auditing      = [ordered]@{
            enabled = $EnableAuditing
            rules   = @(
                # Read rights are deliberately absent: auditing them buries the interesting
                # events in noise. Delete and DeleteTree matter because an object can be removed
                # without touching its parent.
                [ordered]@{ principal = 'S-1-1-0'; targetOu = '$ModelRoot'; rights = 'CreateChild, DeleteChild, Delete, DeleteTree, WriteProperty, Self, WriteDacl, WriteOwner, ExtendedRight'; flags = 'Success'; objectType = $null; inheritance = 'All'; comment = 'Record every change to the tier model structure and its delegation' }
                [ordered]@{ principal = 'S-1-1-0'; targetOu = '$DomainControllers'; rights = 'CreateChild, DeleteChild, Delete, DeleteTree, WriteProperty, Self, WriteDacl, WriteOwner, ExtendedRight'; flags = 'Success'; objectType = $null; inheritance = 'All'; comment = 'Record every change to domain controller objects' }
            )
        }
        authenticationPolicySilos = $silos
    }

    return $configuration
}

function Save-TierModelConfiguration {
    <#
        .SYNOPSIS
        Writes a configuration object to disk as JSON, backing up an existing file.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Configuration,
        [Parameter(Mandatory)][string]$Path
    )

    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    if (Test-Path -LiteralPath $Path) {
        $backup = "$Path.bak-$(Get-Date -Format 'yyyyMMddHHmmss')"
        if ($PSCmdlet.ShouldProcess($Path, "Back up existing configuration to $backup")) {
            Copy-Item -LiteralPath $Path -Destination $backup -Force
        }
    }

    if ($PSCmdlet.ShouldProcess($Path, 'Write configuration')) {
        $Configuration | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
    }

    return $Path
}

#endregion ConfigurationGenerator

####################################################################################################
#region DeploymentStages
#  Prerequisites, OUs, groups, nesting, accounts, delegation, GPOs, KDS, silo.
####################################################################################################

function Test-TierModelPrerequisite {
    <#
        .SYNOPSIS
        Validates that the current host and account can deploy the tier model.

        .OUTPUTS
        [pscustomobject] with Passed (bool) and Findings (array)
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipPrivilegeCheck
    )

    Write-TierLog -Message 'Prerequisite check' -Level Header
    $findings = [System.Collections.Generic.List[object]]::new()

    $add = {
        param($Name, $Ok, $Detail)
        $findings.Add([pscustomobject]@{ Check = $Name; Passed = [bool]$Ok; Detail = $Detail })
        if ($Ok) { Write-TierLog -Message "$Name - $Detail" -Level Success }
        else { Write-TierLog -Message "$Name - $Detail" -Level Error }
    }

    & $add 'PowerShell version' ($PSVersionTable.PSVersion.Major -ge 5) "Running PowerShell $($PSVersionTable.PSVersion)"

    foreach ($moduleName in 'ActiveDirectory', 'GroupPolicy') {
        $module = Get-Module -ListAvailable -Name $moduleName | Select-Object -First 1
        & $add "Module $moduleName" ([bool]$module) $(if ($module) { "Version $($module.Version)" } else { 'Not installed - install RSAT AD DS and GPMC tools' })
    }

    if (-not $SkipPrivilegeCheck) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        & $add 'Elevation' $elevated $(if ($elevated) { 'Session is elevated' } else { 'Run the console as administrator' })

        # Group names are localised, so the token is checked against the well known relative
        # identifiers instead: 512 Domain Admins, 519 Enterprise Admins, 518 Schema Admins.
        $tokenSids = @()
        if ($identity.Groups) { $tokenSids = @($identity.Groups | ForEach-Object { $_.Value }) }
        $privilegedRids = @('-512', '-519', '-518')
        $matched = @($tokenSids | Where-Object { $sid = $_; ($privilegedRids | Where-Object { $sid.EndsWith($_) }) })

        $isPrivileged = $matched.Count -gt 0
        & $add 'Privileged group membership' $isPrivileged $(if ($isPrivileged) { "Token carries $($matched -join ', ')" } else { 'Token carries no Domain, Enterprise or Schema Admins SID - deployment will most likely fail' })
    }

    try {
        $ctx = Get-TierContext
        & $add 'Directory connectivity' $true "Connected to $($ctx.Server)"

        $dfl = $ctx.Domain.DomainMode
        $siloCapable = $dfl -notin @('Windows2000Domain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain', 'Windows2012Domain')
        & $add 'Domain functional level' $true "$dfl$(if (-not $siloCapable) { ' - Authentication Policy Silos require 2012 R2 or higher' })"

        $sysvolOk = Test-Path -LiteralPath $ctx.SysvolPolicyPath
        & $add 'SYSVOL access' $sysvolOk $ctx.SysvolPolicyPath

        # Enterprise Admins, Schema Admins and forest wide settings live in the root domain.
        # Running against a child domain is legitimate, but half the top tier is elsewhere.
        $isChild = $ctx.Domain.DNSRoot -ne $ctx.Domain.Forest
        & $add 'Domain position in the forest' $true $(if ($isChild) {
                "$($ctx.Domain.DNSRoot) is a child of $($ctx.Domain.Forest) - Enterprise and Schema Admins live in the root domain and are not covered by this run"
            }
            else { "$($ctx.Domain.DNSRoot) is the forest root domain" })
    }
    catch {
        & $add 'Directory connectivity' $false $_.Exception.Message
    }

    $passed = -not ($findings | Where-Object { -not $_.Passed })
    return [pscustomobject]@{ Passed = [bool]$passed; Findings = $findings.ToArray() }
}

function New-TierOuStructure {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    Write-TierLog -Message 'Organizational unit structure' -Level Header
    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $protect = [bool]$Configuration.options.protectOusFromAccidentalDeletion

    $targets = [System.Collections.Generic.List[object]]::new()
    $targets.Add([pscustomobject]@{ Name = $ctx.RootOuName; Path = $ctx.DomainDn; Description = $Configuration.domain.rootOuDescription })

    foreach ($tier in $Configuration.tiers) {
        $targets.Add([pscustomobject]@{ Name = $tier.name; Path = $ctx.RootOuDn; Description = $tier.description })
        foreach ($ou in @($tier.organizationalUnits)) {
            $targets.Add([pscustomobject]@{ Name = $ou.name; Path = "OU=$($tier.name),$($ctx.RootOuDn)"; Description = $ou.description })
        }
    }

    foreach ($target in $targets) {
        $dn = "OU=$($target.Name),$($target.Path)"
        # Get-AD* -Identity throws on a missing object even under SilentlyContinue - the
        # documented way to probe for existence is a try/catch around -ErrorAction Stop.
        $existing = $null
        try { $existing = Get-ADOrganizationalUnit -Identity $dn @ad -ErrorAction Stop }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $existing = $null }

        if ($existing) {
            Write-TierLog -Message "OU exists: $dn" -Level Skip
            Add-TierAction -Phase 'OU' -ObjectType 'OrganizationalUnit' -Target $dn -Result 'Compliant'
            continue
        }

        if ($AuditOnly) {
            Write-TierLog -Message "OU missing: $dn" -Level Warning
            Add-TierAction -Phase 'OU' -ObjectType 'OrganizationalUnit' -Target $dn -Result 'Missing'
            continue
        }

        if ($PSCmdlet.ShouldProcess($dn, 'Create organizational unit')) {
            try {
                New-ADOrganizationalUnit -Name $target.Name -Path $target.Path -Description $target.Description `
                    -ProtectedFromAccidentalDeletion $protect @ad -ErrorAction Stop
                Write-TierLog -Message "OU created: $dn" -Level Success
                Add-TierAction -Phase 'OU' -ObjectType 'OrganizationalUnit' -Target $dn -Result 'Created'
            }
            catch {
                Write-TierLog -Message "Failed to create $dn - $($_.Exception.Message)" -Level Error
                Add-TierAction -Phase 'OU' -ObjectType 'OrganizationalUnit' -Target $dn -Result 'Failed' -Detail $_.Exception.Message
            }
        }
        else {
            Add-TierAction -Phase 'OU' -ObjectType 'OrganizationalUnit' -Target $dn -Result 'Planned'
        }
    }

    # Blocking GPO inheritance is separate from blocking ACL inheritance. Without it every
    # policy linked at the domain root - the Default Domain Policy, anything legacy - also
    # lands on the tier systems, which defeats the point of a tier specific baseline.
    if ($Configuration.options.blockGpoInheritanceOnTierRoots) {
        $ctxLocal = Get-TierContext
        foreach ($tier in $Configuration.tiers) {
            $dn = "OU=$($tier.name),$($ctxLocal.RootOuDn)"

            if (-not (Test-Path -LiteralPath "AD:\$dn")) {
                if ($AuditOnly) {
                    Add-TierAction -Phase 'OU' -ObjectType 'GpoInheritance' -Target $dn -Result 'Missing' -Detail 'Tier OU does not exist'
                }
                else {
                    # Dry run: the OU is created earlier in the same plan, so the block is planned too.
                    Add-TierAction -Phase 'OU' -ObjectType 'GpoInheritance' -Target $dn -Result 'Planned'
                }
                continue
            }

            try {
                $inheritance = Get-GPInheritance -Target $dn -Domain $ctxLocal.DomainFqdn -Server $ctxLocal.Server -ErrorAction Stop

                if ($inheritance.GpoInheritanceBlocked -eq 'Yes' -or $inheritance.GpoInheritanceBlocked -eq $true) {
                    Write-TierLog -Message "GPO inheritance already blocked on $dn" -Level Skip
                    Add-TierAction -Phase 'OU' -ObjectType 'GpoInheritance' -Target $dn -Result 'Compliant'
                    continue
                }

                if ($AuditOnly) {
                    Write-TierLog -Message "GPO inheritance is not blocked on $dn - policies linked above reach this tier" -Level Warning
                    Add-TierAction -Phase 'OU' -ObjectType 'GpoInheritance' -Target $dn -Result 'Drift' -Detail 'Inheritance not blocked'
                    continue
                }

                if ($PSCmdlet.ShouldProcess($dn, 'Block Group Policy inheritance')) {
                    Set-GPInheritance -Target $dn -IsBlocked Yes -Domain $ctxLocal.DomainFqdn -Server $ctxLocal.Server -ErrorAction Stop | Out-Null
                    Write-TierLog -Message "GPO inheritance blocked on $dn" -Level Success
                    Add-TierAction -Phase 'OU' -ObjectType 'GpoInheritance' -Target $dn -Result 'Updated'
                }
            }
            catch {
                Write-TierLog -Message "GPO inheritance on $dn could not be set - $($_.Exception.Message)" -Level Error
                Add-TierAction -Phase 'OU' -ObjectType 'GpoInheritance' -Target $dn -Result 'Failed' -Detail $_.Exception.Message
            }
        }
    }

    if ($Configuration.options.blockInheritanceOnTierRoots -and -not $AuditOnly) {
        foreach ($tier in $Configuration.tiers) {
            $dn = "OU=$($tier.name),$($ctx.RootOuDn)"
            $result = Disable-TierAclInheritance -TargetDn $dn -PreserveInherited
            Write-TierLog -Message "ACL inheritance on $dn : $result" -Level Info
            Add-TierAction -Phase 'OU' -ObjectType 'AclInheritance' -Target $dn -Result $result
        }
    }
}

function New-TierGroupSet {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    Write-TierLog -Message 'Security groups' -Level Header
    $ad = Get-TierAdParameter

    foreach ($tier in $Configuration.tiers) {
        foreach ($group in @($tier.groups)) {
            $path = Resolve-TierOuDn -Reference $group.targetOu -TierName $tier.name
            $existing = Get-ADGroup -LDAPFilter "(sAMAccountName=$($group.name))" @ad -ErrorAction SilentlyContinue |
                Select-Object -First 1

            if ($existing) {
                Write-TierLog -Message "Group exists: $($group.name)" -Level Skip
                Add-TierAction -Phase 'Group' -ObjectType 'Group' -Target $group.name -Result 'Compliant' -Detail $existing.DistinguishedName
                continue
            }

            if ($AuditOnly) {
                Write-TierLog -Message "Group missing: $($group.name)" -Level Warning
                Add-TierAction -Phase 'Group' -ObjectType 'Group' -Target $group.name -Result 'Missing'
                continue
            }

            if ($PSCmdlet.ShouldProcess($group.name, "Create $($group.scope) security group in $path")) {
                try {
                    New-ADGroup -Name $group.name -SamAccountName $group.name -GroupScope $group.scope `
                        -GroupCategory Security -Path $path -Description $group.description @ad -ErrorAction Stop
                    Write-TierLog -Message "Group created: $($group.name)" -Level Success
                    Add-TierAction -Phase 'Group' -ObjectType 'Group' -Target $group.name -Result 'Created' -Detail $path
                }
                catch {
                    Write-TierLog -Message "Failed to create group $($group.name) - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'Group' -ObjectType 'Group' -Target $group.name -Result 'Failed' -Detail $_.Exception.Message
                }
            }
            else {
                Add-TierAction -Phase 'Group' -ObjectType 'Group' -Target $group.name -Result 'Planned'
            }
        }
    }
}

function Set-TierGroupNesting {
    <#
        .SYNOPSIS
        Applies the AGDLP nesting defined in the configuration. Runs after all groups exist.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    Write-TierLog -Message 'Group nesting' -Level Header
    $nestingBefore = (Get-TierActionLog).Count
    Clear-TierPrincipalCache
    $ad = Get-TierAdParameter

    foreach ($tier in $Configuration.tiers) {
        foreach ($group in @($tier.groups)) {
            $members = @($group.members) | Where-Object { $_ }
            if (-not $members) { continue }

            $container = Get-ADGroup -LDAPFilter "(sAMAccountName=$($group.name))" -Properties member @ad -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if (-not $container) {
                if ($WhatIfPreference) {
                    # The groups do not exist yet in a dry run; they would by the time this runs.
                    Add-TierAction -Phase 'Nesting' -ObjectType 'Group' -Target $group.name -Result 'Planned'
                    continue
                }
                Add-TierAction -Phase 'Nesting' -ObjectType 'Group' -Target $group.name -Result 'Missing' -Detail 'Container group does not exist'
                continue
            }

            foreach ($memberName in $members) {
                $member = Resolve-TierPrincipal -Reference $memberName -AllowMissing
                if (-not $member -or -not $member.DistinguishedName) {
                    if ($WhatIfPreference) {
                        Add-TierAction -Phase 'Nesting' -ObjectType 'GroupMember' -Target "$($group.name) <- $memberName" -Result 'Planned'
                    }
                    else {
                        Write-TierLog -Message "Member '$memberName' for $($group.name) not found" -Level Warning
                        Add-TierAction -Phase 'Nesting' -ObjectType 'GroupMember' -Target "$($group.name) <- $memberName" -Result 'Missing'
                    }
                    continue
                }

                if ($container.member -contains $member.DistinguishedName) {
                    Write-TierLog -Message "$memberName already nested in $($group.name)" -Level Skip
                    Add-TierAction -Phase 'Nesting' -ObjectType 'GroupMember' -Target "$($group.name) <- $memberName" -Result 'Compliant'
                    continue
                }

                if ($AuditOnly) {
                    Write-TierLog -Message "Nesting missing: $($group.name) <- $memberName" -Level Warning
                    Add-TierAction -Phase 'Nesting' -ObjectType 'GroupMember' -Target "$($group.name) <- $memberName" -Result 'Missing'
                    continue
                }

                if ($PSCmdlet.ShouldProcess($group.name, "Add member $memberName")) {
                    try {
                        Add-ADGroupMember -Identity $container.DistinguishedName -Members $member.DistinguishedName @ad -ErrorAction Stop
                        Write-TierLog -Message "Nested $memberName into $($group.name)" -Level Success
                        Add-TierAction -Phase 'Nesting' -ObjectType 'GroupMember' -Target "$($group.name) <- $memberName" -Result 'Created'
                    }
                    catch {
                        Write-TierLog -Message "Failed to nest $memberName into $($group.name) - $($_.Exception.Message)" -Level Error
                        Add-TierAction -Phase 'Nesting' -ObjectType 'GroupMember' -Target "$($group.name) <- $memberName" -Result 'Failed' -Detail $_.Exception.Message
                    }
                }
            }
        }
    }

    # Built-in groups are nested from the same stage, so Deploy, Sync and Audit all cover them
    # without a new stage name and without a new place to forget.
    Set-TierBuiltInGroupNesting -Configuration $Configuration -AuditOnly:$AuditOnly -Confirm:$false

    # A stage that logs nothing is indistinguishable from a stage that did nothing.
    $planned = (Get-TierActionLog).Count - $nestingBefore
    Write-TierLog -Message "Group nesting: $planned item(s) processed" -Level Info
}

function Set-TierBuiltInGroupNesting {
    <#
        .SYNOPSIS
        Nests declared groups into built-in groups such as DnsAdmins, additively.

        .DESCRIPTION
        A role that needs the permissions of a built-in group holds them by being nested into it,
        so the built-in group itself can stay empty of human members. That nesting has to happen
        somewhere, and the privileged group stage is the wrong place: it runs in report mode by
        default, where an absent declared member is reported rather than added. A role would then
        sit there with no permissions at all until somebody switched that stage to Enforce - which
        is the switch with the largest blast radius in the whole configuration and not something
        to require for a DNS delegation to work.

        The division is deliberate:

          * this function only ever ADDS the members the configuration declares
          * removing members that are not declared stays with the privileged group stage

        The two therefore cannot fight, but only as long as everything nested here is also
        declared in privilegedGroups.allowedMembers. Role expansion writes both from one
        declaration; a hand-written builtInNesting entry could get it wrong, so the mismatch is
        checked and the nesting skipped rather than left to flap - added by one stage on Monday,
        removed by the other on Tuesday, with a report that looks fine on both days.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    if (-not ($Configuration.PSObject.Properties.Name -contains 'builtInNesting')) { return }
    $entries = @($Configuration.builtInNesting | Where-Object { $_ })
    if (-not $entries) { return }

    Write-TierLog -Message 'Built-in group nesting' -Level Header
    $ad = Get-TierAdParameter

    foreach ($entry in $entries) {
        if (-not $entry.group) {
            Write-TierLog -Message 'A builtInNesting entry names no group - skipped' -Level Warning
            continue
        }

        $key = if ($entry.group.PSObject.Properties.Name -contains 'sid' -and $entry.group.sid) { $entry.group.sid } else { $entry.group.name }

        $group = $null
        try { $group = Get-TierPrivilegedGroupReference -Entry $entry.group -Properties @('member') }
        catch {
            Write-TierLog -Message "Built-in group '$key' could not be resolved - $($_.Exception.Message)" -Level Warning
        }

        if (-not $group) {
            # DnsAdmins does not exist until the DNS server role has been installed, which is a
            # legitimate state rather than a fault.
            Write-TierLog -Message "Built-in group '$key' does not exist in this domain - skipped" -Level Skip
            Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target $key -Result 'Missing' `
                -Detail 'The group does not exist in this domain'
            continue
        }

        # The declaration in privilegedGroups is what stops the next enforce run from undoing this.
        $declared = $null
        if ($Configuration.privilegedGroups) {
            $declared = @($Configuration.privilegedGroups.groups | Where-Object {
                    ($_.PSObject.Properties.Name -contains 'sid' -and $_.sid -eq $key) -or
                    ($_.PSObject.Properties.Name -contains 'name' -and $_.name -eq $key)
                }) | Select-Object -First 1
        }

        foreach ($memberName in @($entry.members | Where-Object { $_ })) {
            if ($declared -and (@($declared.allowedMembers) -notcontains $memberName)) {
                Write-TierLog -Message "$memberName is nested into $($group.Name) but not declared in privilegedGroups - an enforce run would remove it again. Nesting skipped." -Level Error
                Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target "$($group.Name) <- $memberName" -Result 'Failed' `
                    -Detail 'Not listed in privilegedGroups.allowedMembers - the two stages would fight over it' -Severity 'High'
                continue
            }

            $member = Resolve-TierPrincipal -Reference $memberName -AllowMissing
            if (-not $member -or -not $member.DistinguishedName) {
                if ($WhatIfPreference) {
                    Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target "$($group.Name) <- $memberName" -Result 'Planned'
                }
                else {
                    Write-TierLog -Message "Member '$memberName' for $($group.Name) not found" -Level Warning
                    Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target "$($group.Name) <- $memberName" -Result 'Missing'
                }
                continue
            }

            if ($group.member -contains $member.DistinguishedName) {
                Write-TierLog -Message "$memberName already nested in $($group.Name)" -Level Skip
                Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target "$($group.Name) <- $memberName" -Result 'Compliant'
                continue
            }

            if ($AuditOnly) {
                Write-TierLog -Message "Nesting missing: $($group.Name) <- $memberName" -Level Warning
                # The role exists but holds none of the permissions it was created for, which is
                # a control that is configured and not in effect.
                Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target "$($group.Name) <- $memberName" -Result 'Missing' `
                    -Detail 'The role holds none of this group''s permissions until it is nested' -Severity 'Medium'
                continue
            }

            if ($PSCmdlet.ShouldProcess($group.Name, "Add member $memberName")) {
                try {
                    Add-ADGroupMember -Identity $group.DistinguishedName -Members $member.DistinguishedName @ad -ErrorAction Stop
                    Write-TierLog -Message "Nested $memberName into $($group.Name)" -Level Success
                    Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target "$($group.Name) <- $memberName" -Result 'Created' -Detail $entry.comment
                }
                catch {
                    Write-TierLog -Message "Failed to nest $memberName into $($group.Name) - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target "$($group.Name) <- $memberName" -Result 'Failed' -Detail $_.Exception.Message
                }
            }
            else {
                Add-TierAction -Phase 'Nesting' -ObjectType 'BuiltInGroup' -Target "$($group.Name) <- $memberName" -Result 'Planned'
            }
        }
    }
}

function New-TierAdminAccountSet {
    # The generated password has to become a SecureString for New-ADUser, and the generator
    # returns a string. There is no conversion-free path; the plaintext never leaves the
    # expression it is created in.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialDirectory')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [string]$CredentialDirectory = (Join-Path (Get-Location) 'Credentials'),
        [switch]$AuditOnly
    )

    if (-not $Configuration.options.createAdminAccounts) {
        Write-TierLog -Message 'Administrative accounts are disabled in the configuration' -Level Info
        return
    }

    Write-TierLog -Message 'Administrative accounts' -Level Header
    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $disabled = [bool]$Configuration.options.adminAccountsDisabledOnCreation
    $sensitive = [bool]$Configuration.options.adminAccountsSensitiveNoDelegation

    foreach ($tier in $Configuration.tiers) {
        foreach ($account in @($tier.adminAccounts)) {
            $path = Resolve-TierOuDn -Reference $account.targetOu -TierName $tier.name
            $existing = Get-ADUser -LDAPFilter "(sAMAccountName=$($account.samAccountName))" @ad -ErrorAction SilentlyContinue |
                Select-Object -First 1

            if ($existing) {
                Write-TierLog -Message "Account exists: $($account.samAccountName)" -Level Skip
                Add-TierAction -Phase 'Account' -ObjectType 'User' -Target $account.samAccountName -Result 'Compliant'
            }
            elseif ($AuditOnly) {
                Write-TierLog -Message "Account missing: $($account.samAccountName)" -Level Warning
                Add-TierAction -Phase 'Account' -ObjectType 'User' -Target $account.samAccountName -Result 'Missing'
                continue
            }
            elseif ($PSCmdlet.ShouldProcess($account.samAccountName, "Create administrative account in $path")) {
                try {
                    # The generator produces a string and New-ADUser needs a SecureString, so the
                    # conversion is unavoidable. The plaintext exists only inside this expression
                    # and is never assigned to a variable.
                    $password = ConvertTo-SecureString -String (New-TierRandomPassword) -AsPlainText -Force
                    New-ADUser -Name $account.displayName -SamAccountName $account.samAccountName `
                        -DisplayName $account.displayName -Description $account.description -Path $path `
                        -AccountPassword $password -Enabled (-not $disabled) `
                        -UserPrincipalName "$($account.samAccountName)@$($ctx.DomainFqdn)" `
                        -PasswordNeverExpires $false -CannotChangePassword $false @ad -ErrorAction Stop

                    if ($sensitive) {
                        Set-ADAccountControl -Identity $account.samAccountName -AccountNotDelegated $true @ad -ErrorAction Stop
                    }

                    Export-TierCredential -SamAccountName $account.samAccountName -Password $password -Directory $CredentialDirectory

                    Write-TierLog -Message "Account created (disabled=$disabled): $($account.samAccountName)" -Level Success
                    Add-TierAction -Phase 'Account' -ObjectType 'User' -Target $account.samAccountName -Result 'Created' -Detail $path
                }
                catch {
                    Write-TierLog -Message "Failed to create $($account.samAccountName) - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'Account' -ObjectType 'User' -Target $account.samAccountName -Result 'Failed' -Detail $_.Exception.Message
                    continue
                }
            }
            else {
                Add-TierAction -Phase 'Account' -ObjectType 'User' -Target $account.samAccountName -Result 'Planned'
                continue
            }

            foreach ($groupName in @($account.memberOf)) {
                try {
                    $group = Get-ADGroup -LDAPFilter "(sAMAccountName=$groupName)" -Properties member @ad -ErrorAction Stop | Select-Object -First 1
                    if (-not $group) { continue }
                    $user = Get-ADUser -LDAPFilter "(sAMAccountName=$($account.samAccountName))" @ad | Select-Object -First 1
                    if (-not $user) { continue }
                    if ($group.member -contains $user.DistinguishedName) { continue }
                    if ($AuditOnly) {
                        Add-TierAction -Phase 'Account' -ObjectType 'GroupMember' -Target "$groupName <- $($account.samAccountName)" -Result 'Missing'
                        continue
                    }
                    if ($PSCmdlet.ShouldProcess($groupName, "Add $($account.samAccountName)")) {
                        Add-ADGroupMember -Identity $group.DistinguishedName -Members $user.DistinguishedName @ad -ErrorAction Stop
                        Add-TierAction -Phase 'Account' -ObjectType 'GroupMember' -Target "$groupName <- $($account.samAccountName)" -Result 'Created'
                    }
                }
                catch {
                    Write-TierLog -Message "Membership $groupName for $($account.samAccountName) failed - $($_.Exception.Message)" -Level Warning
                }
            }
        }
    }

    if ($Configuration.options.addTier0AdminsToProtectedUsers -and -not $AuditOnly) {
        Add-TierProtectedUser -Configuration $Configuration
    }
}

function Export-TierCredential {
    <#
        .SYNOPSIS
        Stores a generated password so that the account can actually be used.

        .DESCRIPTION
        The break glass account is the obvious case: a random password that is generated and then
        discarded leaves an account nobody can log on with. The credential is written with
        Export-Clixml, which encrypts the password through DPAPI and binds it to the account and
        the machine that produced it. Nobody else can read the file, and it is never plain text.

        Retrieve it with:
            $credential = Import-Clixml .\Credentials\<sam>.xml
            $credential.GetNetworkCredential().Password

        Move the file into whatever vault the organisation uses and delete it afterwards; DPAPI
        binding means it is worthless on any other machine anyway.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][System.Security.SecureString]$Password,
        [Parameter(Mandatory)][string]$Directory
    )

    try {
        if (-not (Test-Path -LiteralPath $Directory)) {
            New-Item -Path $Directory -ItemType Directory -Force | Out-Null
        }

        $path = Join-Path $Directory "$SamAccountName.xml"
        if (-not $PSCmdlet.ShouldProcess($path, 'Write encrypted credential')) { return }

        $credential = [System.Management.Automation.PSCredential]::new($SamAccountName, $Password)
        $credential | Export-Clixml -LiteralPath $path -Force

        Write-TierLog -Message "Credential for $SamAccountName written to $path (DPAPI encrypted for $($env:USERNAME) on $($env:COMPUTERNAME))" -Level Success
        Add-TierAction -Phase 'Account' -ObjectType 'Credential' -Target $SamAccountName -Result 'Created' -Detail $path
    }
    catch {
        Write-TierLog -Message "Credential for $SamAccountName could not be stored - $($_.Exception.Message). Reset the password manually." -Level Warning
        Add-TierAction -Phase 'Account' -ObjectType 'Credential' -Target $SamAccountName -Result 'Failed' -Detail $_.Exception.Message
    }
}

function New-TierRandomPassword {
    <#
        .SYNOPSIS
        Generates a random password that is guaranteed to satisfy the default complexity rules.
    #>
    [CmdletBinding()]
    param([ValidateRange(16, 127)][int]$Length = 32)

    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!#$%&*+-=?@'
    )
    $alphabet = -join $sets

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        # Rejection sampling keeps the distribution uniform - a plain modulo would bias
        # the low indices. Used for character picks and for the shuffle below.
        $nextIndex = {
            param([int]$Count)
            $limit = [math]::Floor(256 / $Count) * $Count
            do {
                $byte = [byte[]]::new(1)
                $rng.GetBytes($byte)
            } while ($byte[0] -ge $limit)
            return $byte[0] % $Count
        }

        $pick = {
            param($Pool)
            return $Pool[(& $nextIndex $Pool.Length)]
        }

        # One character from every class first, the remainder from the full alphabet.
        $chars = [System.Collections.Generic.List[char]]::new()
        foreach ($set in $sets) { $chars.Add((& $pick $set)) }
        while ($chars.Count -lt $Length) { $chars.Add((& $pick $alphabet)) }

        # Fisher-Yates shuffle so the class characters are not always in front. The index comes
        # from the same rejection-sampled source as the picks - a plain modulo here would bias
        # the positions even though the characters themselves are uniform.
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = & $nextIndex ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }

        return (-join $chars)
    }
    finally { $rng.Dispose() }
}

function Add-TierProtectedUser {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][object]$Configuration)

    $ad = Get-TierAdParameter

    # Domain relative identifier 525 - the display name is localised.
    $protectedUsers = Get-TierWellKnownGroup -Sid '525'
    if (-not $protectedUsers) {
        Write-TierLog -Message 'Protected Users group not found - requires domain functional level 2012 R2' -Level Warning
        return
    }

    $tier0 = $Configuration.tiers | Where-Object { $_.id -eq 0 } | Select-Object -First 1
    if (-not $tier0) { return }

    $candidates = @($tier0.adminAccounts) | Where-Object {
        -not ($_.PSObject.Properties.Name -contains 'excludeFromSilo' -and $_.excludeFromSilo)
    }

    foreach ($account in $candidates) {
        $user = Get-ADUser -LDAPFilter "(sAMAccountName=$($account.samAccountName))" @ad -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $user) { continue }

        $group = Get-TierWellKnownGroup -Sid '525'
        if (-not $group) { return }
        if ($group.member -contains $user.DistinguishedName) {
            Write-TierLog -Message "$($account.samAccountName) is already in Protected Users" -Level Skip
            Add-TierAction -Phase 'Account' -ObjectType 'ProtectedUsers' -Target $account.samAccountName -Result 'Compliant'
            continue
        }

        if ($PSCmdlet.ShouldProcess($account.samAccountName, "Add to $($protectedUsers.Name)")) {
            Add-ADGroupMember -Identity $protectedUsers.DistinguishedName -Members $user.DistinguishedName @ad -ErrorAction Stop
            Write-TierLog -Message "Added $($account.samAccountName) to $($protectedUsers.Name)" -Level Success
            Add-TierAction -Phase 'Account' -ObjectType 'ProtectedUsers' -Target $account.samAccountName -Result 'Created'
        }
    }
}

function Set-TierDelegationSet {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    Write-TierLog -Message 'ACL delegation' -Level Header
    $delegationBefore = (Get-TierActionLog).Count
    Clear-TierPrincipalCache

    foreach ($tier in $Configuration.tiers) {
        foreach ($delegation in @($tier.delegations)) {
            $targetDn = Resolve-TierOuDn -Reference $delegation.targetOu -TierName $tier.name
            $principal = Resolve-TierPrincipal -Reference $delegation.principal -AllowMissing

            if (-not $principal) {
                if ($WhatIfPreference) {
                    # The groups are created earlier in the same plan; the ACE is simply planned.
                    Add-TierAction -Phase 'Delegation' -ObjectType 'Ace' -Target "$($delegation.principal) on $targetDn" -Result 'Planned'
                }
                else {
                    Write-TierLog -Message "Delegation principal '$($delegation.principal)' not found" -Level Warning
                    Add-TierAction -Phase 'Delegation' -ObjectType 'Ace' -Target "$($delegation.principal) on $targetDn" -Result 'Missing'
                }
                continue
            }

            $inheritedObjectType = $null
            if ($delegation.PSObject.Properties.Name -contains 'inheritedObjectType') {
                $inheritedObjectType = $delegation.inheritedObjectType
            }

            try {
                $result = Set-TierAccessRule -TargetDn $targetDn -PrincipalSid $principal.SID `
                    -Rights $delegation.rights -AccessType $delegation.type `
                    -ObjectType $delegation.objectType -InheritedObjectType $inheritedObjectType `
                    -Inheritance $delegation.inheritance -AuditOnly:$AuditOnly -Confirm:$false

                $level = if ($result -eq 'Compliant') { 'Skip' } elseif ($result -eq 'Missing') { 'Warning' } else { 'Success' }
                # Without the object type six consecutive ACEs look like the same line repeated.
                $scope = @()
                if ($delegation.objectType) { $scope += $delegation.objectType }
                if ($inheritedObjectType) { $scope += "on $inheritedObjectType" }
                $scopeText = if ($scope) { ' {' + ($scope -join ' ') + '}' } else { '' }

                Write-TierLog -Message "$($delegation.principal) -> $targetDn [$($delegation.rights)]$scopeText : $result" -Level $level
                Add-TierAction -Phase 'Delegation' -ObjectType 'Ace' -Target "$($delegation.principal) on $targetDn$scopeText" -Result $result -Detail $delegation.comment
            }
            catch {
                Write-TierLog -Message "Delegation failed on $targetDn - $($_.Exception.Message)" -Level Error
                Add-TierAction -Phase 'Delegation' -ObjectType 'Ace' -Target "$($delegation.principal) on $targetDn" -Result 'Failed' -Detail $_.Exception.Message
            }
        }
    }

    # A stage that logs nothing is indistinguishable from a stage that did nothing.
    $planned = (Get-TierActionLog).Count - $delegationBefore
    Write-TierLog -Message "ACL delegation: $planned item(s) processed" -Level Info
}

function Set-TierObjectOwnership {
    <#
        .SYNOPSIS
        Reports, and optionally corrects, the owner of every object below the tier model.

        .DESCRIPTION
        The delegation model in this tool deliberately withholds WriteDacl and WriteOwner, so that
        a tier administrator cannot rewrite the permissions that constrain them. Ownership goes
        around that: an owner holds WRITE_DAC implicitly, whatever the DACL says.

        Windows decides the owner of a new object from the creator's token. A member of Domain
        Admins creates objects owned by Domain Admins; everybody else creates objects owned by
        themselves. A delegated tier administrator therefore owns every object they create - and
        an owned sub-OU can be re-permissioned, have objects moved into it, and be opened up to
        principals from another tier. The granular delegation is binding only until somebody
        creates something.

        This stage is the reason deployment alone is not enough. It finds nothing on a freshly
        deployed model, because everything was created by the deployment account, and starts
        finding things the moment the model is actually used. That makes it a sync stage rather
        than a deploy stage - it is included in both.

        Report mode is the default. Enforce mode reassigns the owner, which needs WriteOwner on
        the object; note that WRITE_OWNER on its own only permits setting the owner to the caller
        or to a group the caller belongs to, so the declared owner should be a group the operator
        is a member of - Domain Admins, in the shipped configuration.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    if (-not ($Configuration.PSObject.Properties.Name -contains 'ownership') -or -not $Configuration.ownership) { return }
    $definition = $Configuration.ownership
    if ($definition.PSObject.Properties.Name -contains 'enabled' -and -not $definition.enabled) {
        Write-TierLog -Message 'Ownership checking is disabled in the configuration' -Level Info
        return
    }

    Write-TierLog -Message 'Object ownership' -Level Header
    Clear-TierPrincipalCache
    $ad = Get-TierAdParameter
    $ctx = Get-TierContext

    $enforce = ($definition.mode -eq 'Enforce') -and -not $AuditOnly
    Write-TierLog -Message "Mode: $(if ($enforce) { 'ENFORCE - owners will be reassigned' } else { 'report only' })" `
        -Level $(if ($enforce) { 'Warning' } else { 'Info' })

    # --- the owner that objects are supposed to have --------------------------------------------
    $ownerReference = if ($definition.owner) { $definition.owner } else { '512' }
    $ownerPrincipal = Resolve-TierPrincipalReference -Reference $ownerReference -AllowMissing
    if (-not $ownerPrincipal) {
        Write-TierLog -Message "Declared owner '$ownerReference' could not be resolved - stage skipped" -Level Error
        Add-TierAction -Phase 'Ownership' -ObjectType 'Owner' -Target $ownerReference -Result 'Failed' -Detail 'Declared owner does not resolve'
        return
    }

    # Additional owners that are acceptable without being the declared one. A model that keeps
    # Enterprise Admins as the owner of objects it created should not be told about it daily.
    $acceptable = @{}
    $acceptable[$ownerPrincipal.SID] = $ownerReference
    foreach ($extra in @($definition.acceptableOwners | Where-Object { $_ })) {
        $resolved = Resolve-TierPrincipalReference -Reference $extra -AllowMissing
        if ($resolved) { $acceptable[$resolved.SID] = $extra }
        else { Write-TierLog -Message "Acceptable owner '$extra' could not be resolved - ignored" -Level Warning }
    }

    # --- what to look at -------------------------------------------------------------------------
    $scopes = @($definition.scopes | Where-Object { $_ })
    if (-not $scopes) { $scopes = @('$ModelRoot') }

    $classes = @($definition.objectClasses | Where-Object { $_ })
    if (-not $classes) { $classes = @('user', 'group', 'computer', 'organizationalUnit', 'msDS-GroupManagedServiceAccount') }

    # 'computer' derives from 'user' in the schema, so a bare (objectClass=user) also matches every
    # computer account. Pairing it with the category keeps a configuration that asks only for users
    # from silently auditing the whole server estate as well.
    $clauses = foreach ($class in $classes) {
        if ($class -eq 'user') { '(&(objectClass=user)(objectCategory=person))' } else { "(objectClass=$class)" }
    }
    $filter = '(|' + ($clauses -join '') + ')'

    $maxObjects = 5000
    if ($definition.maxObjects) { $maxObjects = [int]$definition.maxObjects }

    # The top tier is the one where a foreign owner is not merely untidy: whoever owns a Tier 0
    # object can rewrite its DACL, and a Tier 0 DACL is the boundary itself.
    $topTierName = @($Configuration.tiers)[0].name

    $totalCompliant = 0
    $totalDrift = 0
    $totalCorrected = 0
    $totalFailed = 0
    $listed = 0
    $listLimit = 100

    foreach ($scope in $scopes) {
        $scopeDn = Resolve-TierOuDn -Reference $scope

        $objects = @()
        try {
            # ResultSetSize is deliberately one over the cap, so exceeding it is detectable rather
            # than silently truncating the audit and reporting a clean result.
            $objects = @(Get-ADObject -SearchBase $scopeDn -SearchScope Subtree -LDAPFilter $filter `
                    -Properties nTSecurityDescriptor -ResultSetSize ($maxObjects + 1) @ad -ErrorAction Stop)
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($AuditOnly -or $WhatIfPreference) {
                Add-TierAction -Phase 'Ownership' -ObjectType 'OwnershipScope' -Target $scopeDn -Result 'Missing' -Detail 'Scope does not exist yet'
                continue
            }
            throw
        }
        catch {
            Write-TierLog -Message "Reading $scopeDn failed - $($_.Exception.Message)" -Level Error
            Add-TierAction -Phase 'Ownership' -ObjectType 'OwnershipScope' -Target $scopeDn -Result 'Failed' -Detail $_.Exception.Message
            continue
        }

        if ($objects.Count -gt $maxObjects) {
            Write-TierLog -Message "$scopeDn holds more than $maxObjects objects - only the first $maxObjects were checked. Raise ownership.maxObjects or narrow the scope." -Level Warning
            Add-TierAction -Phase 'Ownership' -ObjectType 'OwnershipScope' -Target $scopeDn -Result 'Drift' `
                -Detail "More than $maxObjects objects in scope - the check is incomplete" -Severity 'Medium'
            $objects = $objects[0..($maxObjects - 1)]
        }

        Write-TierLog -Message "$scopeDn : $($objects.Count) object(s) in scope" -Level Info

        foreach ($object in $objects) {
            $currentOwner = $null
            try { $currentOwner = $object.nTSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]) }
            catch {
                Write-TierLog -Message "Owner of $($object.DistinguishedName) is unreadable - $($_.Exception.Message)" -Level Warning
                Add-TierAction -Phase 'Ownership' -ObjectType 'Owner' -Target $object.DistinguishedName -Result 'Failed' -Detail $_.Exception.Message
                continue
            }

            if ($currentOwner -and $acceptable.ContainsKey($currentOwner.Value)) {
                # Counted, not logged. One action per compliant object would bury every real
                # finding under a few thousand lines that all say nothing happened.
                $totalCompliant++
                continue
            }

            $totalDrift++
            $ownerName = if ($currentOwner) { (Resolve-TierPrincipal -Reference $currentOwner.Value -AllowMissing).Name } else { $null }
            if (-not $ownerName) { $ownerName = if ($currentOwner) { $currentOwner.Value } else { '<no owner>' } }

            # A foreign owner in the top tier is an open path to the tier boundary, not untidiness.
            $severity = if ($object.DistinguishedName -match [regex]::Escape("OU=$topTierName,")) { 'High' } else { 'Medium' }

            if (-not $enforce) {
                if ($listed -lt $listLimit) {
                    Write-TierLog -Message "Owner drift: $($object.DistinguishedName) is owned by $ownerName" -Level Warning
                    Add-TierAction -Phase 'Ownership' -ObjectType 'Owner' -Target $object.DistinguishedName -Result 'Drift' `
                        -Detail "Owned by $ownerName instead of $ownerReference - the owner can rewrite this object's permissions" -Severity $severity
                    $listed++
                }
                continue
            }

            if ($PSCmdlet.ShouldProcess($object.DistinguishedName, "Set owner to $ownerReference")) {
                try {
                    Set-TierDirectoryOwner -Dn $object.DistinguishedName -OwnerSid $ownerPrincipal.SID | Out-Null
                    Write-TierLog -Message "Owner corrected on $($object.DistinguishedName) (was $ownerName)" -Level Success
                    Add-TierAction -Phase 'Ownership' -ObjectType 'Owner' -Target $object.DistinguishedName -Result 'Updated' -Detail "Was owned by $ownerName"
                    $totalCorrected++
                }
                catch {
                    Write-TierLog -Message "Could not set the owner of $($object.DistinguishedName) - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'Ownership' -ObjectType 'Owner' -Target $object.DistinguishedName -Result 'Failed' -Detail $_.Exception.Message
                    $totalFailed++
                }
            }
            else {
                Add-TierAction -Phase 'Ownership' -ObjectType 'Owner' -Target $object.DistinguishedName -Result 'Planned' -Detail "Would be reassigned from $ownerName"
            }
        }
    }

    if ($listed -ge $listLimit -and $totalDrift -gt $listed) {
        $remaining = $totalDrift - $listed
        Write-TierLog -Message "$remaining further object(s) with a drifted owner were not listed individually" -Level Warning
        Add-TierAction -Phase 'Ownership' -ObjectType 'OwnershipScope' -Target 'Owner drift' -Result 'Drift' `
            -Detail "$remaining further object(s) beyond the first $listLimit" -Severity 'Medium'
    }

    Add-TierAction -Phase 'Ownership' -ObjectType 'OwnershipSummary' -Target "Owned by $ownerReference" -Result 'Compliant' `
        -Detail "$totalCompliant object(s) with an acceptable owner"

    # An object whose owner was just corrected is not a finding - reporting it as drift after
    # fixing it makes a successful enforce run look like a failed audit.
    if ($enforce) {
        $verdict = if ($totalFailed -gt 0) { 'Error' } else { 'Success' }
        Write-TierLog -Message "Ownership: $totalCompliant already correct, $totalCorrected corrected, $totalFailed failed" -Level $verdict
    }
    else {
        $verdict = if ($totalDrift -eq 0) { 'Success' } else { 'Warning' }
        Write-TierLog -Message "Ownership: $totalCompliant acceptable, $totalDrift drifted" -Level $verdict
    }

    if ($totalDrift -gt 0 -and -not $enforce) {
        Write-TierLog -Message 'An owner holds WRITE_DAC implicitly. Until these are corrected, the granular delegation on those objects is advisory. Set ownership.mode to Enforce once you have reviewed the list.' -Level Warning
    }
}

function Set-TierPrivilegedGroupMembership {
    <#
        .SYNOPSIS
        Compares the built-in privileged groups against their declared membership and, in enforce
        mode, corrects them.

        .DESCRIPTION
        A tier model whose top tier groups are correct but whose Domain Admins still holds a
        service account from 2014 protects nothing. Reporting that is useful; fixing it is what
        actually closes the gap.

        Enforce mode is deliberately not the default and carries three hard guards that cannot be
        switched off:

          * the built-in Administrator (RID 500) is never removed from any group
          * the account running the deployment is never removed from any group
          * Domain Admins is never emptied - if enforcing would leave it without members the
            group is skipped and reported instead

        Groups are addressed by SID, so localised directories work unchanged.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    if (-not $Configuration.privilegedGroups) { return }
    $definition = $Configuration.privilegedGroups
    if (-not @($definition.groups)) { return }

    Write-TierLog -Message 'Privileged group membership' -Level Header

    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $enforce = ($definition.mode -eq 'Enforce') -and -not $AuditOnly

    Write-TierLog -Message "Mode: $(if ($enforce) { 'ENFORCE - surplus members will be removed' } else { 'report only' })" `
        -Level $(if ($enforce) { 'Warning' } else { 'Info' })

    # Protected identities - never removed regardless of configuration.
    $protectedSids = [System.Collections.Generic.List[string]]::new()
    $protectedSids.Add("$($ctx.DomainSid)-500")
    try {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $protectedSids.Add($me.User.Value)
    }
    catch {
        # Losing this means the guard that keeps the operator in the group is gone. Enforcing
        # anyway would be reckless, so the caller has to know.
        Write-TierLog -Message "Could not determine the current identity - the protection for the executing account is NOT active: $($_.Exception.Message)" -Level Warning
    }

    foreach ($entry in @($definition.groups)) {
        $group = Get-TierPrivilegedGroupReference -Entry $entry
        if (-not $group) {
            $reference = if ($entry.sid) { "SID $($entry.sid)" } else { "group '$($entry.name)'" }
            Write-TierLog -Message "$reference not present in this domain - skipped" -Level Skip
            continue
        }

        $label = $group.Name

        # Resolve the declared membership to distinguished names.
        $allowed = @{}
        foreach ($reference in @($entry.allowedMembers)) {
            $principal = Resolve-TierPrincipal -Reference $reference -AllowMissing
            if ($principal -and $principal.DistinguishedName) { $allowed[$principal.DistinguishedName] = $reference }
            elseif (-not $WhatIfPreference) { Write-TierLog -Message "Declared member '$reference' of $label not found" -Level Warning }
        }

        $current = @(Get-ADGroupMember -Identity $group.DistinguishedName @ad -ErrorAction SilentlyContinue)

        # The built-in Administrator (RID 500) is a default member of Domain, Enterprise and
        # Schema Admins and is meant to stay there - it is the break-glass path Microsoft's own
        # guidance keeps. Flagging it on every run would be noise, and enforce mode never removes
        # it anyway, so it counts as implicitly declared.
        $rid500 = "$($ctx.DomainSid)-500"
        $surplus = @($current | Where-Object { -not $allowed.ContainsKey($_.distinguishedName) -and $_.SID.Value -ne $rid500 })
        $absent = @($allowed.Keys | Where-Object { $_ -notin $current.distinguishedName })

        if ($surplus.Count -eq 0 -and $absent.Count -eq 0) {
            Write-TierLog -Message "$label membership matches the configuration" -Level Success
            Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'PrivilegedGroup' -Target $label -Result 'Compliant' -Detail "$($current.Count) member(s)"
            continue
        }

        # ---- members that are declared but not present ---------------------------------
        foreach ($dn in $absent) {
            if (-not $enforce) {
                $missResult = if ($WhatIfPreference) { 'Planned' } else { 'Missing' }
                if (-not $WhatIfPreference) {
                    # Without this line a group with only absent members produced no output at
                    # all - it simply vanished from the report between its compliant neighbours.
                    Write-TierLog -Message "$label is missing its declared member $($allowed[$dn])" -Level Warning
                }
                Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'GroupMember' -Target "$label <- $($allowed[$dn])" -Result $missResult
                continue
            }
            if ($PSCmdlet.ShouldProcess($label, "Add declared member $($allowed[$dn])")) {
                try {
                    Add-ADGroupMember -Identity $group.DistinguishedName -Members $dn @ad -ErrorAction Stop
                    Write-TierLog -Message "$label : added $($allowed[$dn])" -Level Success
                    Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'GroupMember' -Target "$label <- $($allowed[$dn])" -Result 'Created'
                }
                catch {
                    Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'GroupMember' -Target "$label <- $($allowed[$dn])" -Result 'Failed' -Detail $_.Exception.Message
                }
            }
        }

        # ---- members that are present but not declared ----------------------------------
        if ($surplus.Count -eq 0) { continue }

        $names = ($surplus | Select-Object -ExpandProperty name) -join ', '

        if (-not $enforce) {
            Write-TierLog -Message "$label holds undeclared members: $names" -Level Warning
            Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'PrivilegedGroup' -Target $label -Result 'Drift' -Detail "Undeclared members: $names" -Severity 'High'
            continue
        }

        $removable = @($surplus | Where-Object { $protectedSids -notcontains $_.SID.Value })
        $kept = @($surplus | Where-Object { $protectedSids -contains $_.SID.Value })

        foreach ($keep in $kept) {
            Write-TierLog -Message "$label : $($keep.name) is protected and stays" -Level Info
            Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'GroupMember' -Target "$label : $($keep.name)" -Result 'Compliant' -Detail 'Protected identity, never removed'
        }

        # Guard: Domain Admins must never end up empty.
        if ($entry.sid -eq '512') {
            $remaining = $current.Count - $removable.Count + $absent.Count
            if ($remaining -lt 1) {
                Write-TierLog -Message "Enforcing $label would leave it without members - skipped. Add a declared member first." -Level Error
                Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'PrivilegedGroup' -Target $label -Result 'Failed' -Detail 'Enforcement skipped: would empty the group' -Severity 'High'
                continue
            }
        }

        foreach ($member in $removable) {
            if ($PSCmdlet.ShouldProcess($label, "Remove undeclared member $($member.name)")) {
                try {
                    Remove-ADGroupMember -Identity $group.DistinguishedName -Members $member.distinguishedName -Confirm:$false @ad -ErrorAction Stop
                    Write-TierLog -Message "$label : removed $($member.name)" -Level Success
                    Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'GroupMember' -Target "$label : $($member.name)" -Result 'Updated' -Detail 'Removed, not declared in the configuration'
                }
                catch {
                    Write-TierLog -Message "$label : could not remove $($member.name) - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'PrivilegedGroups' -ObjectType 'GroupMember' -Target "$label : $($member.name)" -Result 'Failed' -Detail $_.Exception.Message
                }
            }
        }
    }
}

function Set-TierDomainHardening {
    <#
        .SYNOPSIS
        Domain wide settings the tier model depends on but that live outside the tier OUs.

        .DESCRIPTION
        Two settings, both of which quietly undermine the model if left at their defaults:

        ms-DS-MachineAccountQuota
            Ships as 10, which means every authenticated user may create ten computer accounts.
            A computer account the attacker controls is the starting point for resource based
            constrained delegation abuse. Tiering does not help if anyone can mint one.

        Default containers
            A machine joined without a target OU lands in CN=Computers, which is a container and
            cannot have Group Policy linked to it. Every such machine silently receives no tier
            policy at all. Redirecting the default location to a staging OU closes that hole at
            the source instead of reporting it afterwards.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    $options = $Configuration.options
    $names = $options.PSObject.Properties.Name

    Write-TierLog -Message 'Domain wide settings' -Level Header

    $ctx = Get-TierContext
    $ad = Get-TierAdParameter

    # ---- machine account quota --------------------------------------------------------
    if ($names -contains 'machineAccountQuota' -and $null -ne $options.machineAccountQuota) {
        $desired = [int]$options.machineAccountQuota
        try {
            $domainObject = Get-ADObject -Identity $ctx.DomainDn -Properties 'ms-DS-MachineAccountQuota' @ad -ErrorAction Stop
            $current = [int]$domainObject.'ms-DS-MachineAccountQuota'

            if ($current -eq $desired) {
                Write-TierLog -Message "ms-DS-MachineAccountQuota is already $desired" -Level Skip
                Add-TierAction -Phase 'Domain' -ObjectType 'MachineAccountQuota' -Target $ctx.DomainFqdn -Result 'Compliant' -Detail "Value $current"
            }
            elseif ($AuditOnly) {
                Write-TierLog -Message "ms-DS-MachineAccountQuota is $current, expected $desired - any authenticated user can create computer accounts" -Level Warning
                Add-TierAction -Phase 'Domain' -ObjectType 'MachineAccountQuota' -Target $ctx.DomainFqdn -Result 'Drift' -Detail "Value $current, expected $desired" -Severity 'High'
            }
            elseif ($PSCmdlet.ShouldProcess($ctx.DomainFqdn, "Set ms-DS-MachineAccountQuota from $current to $desired")) {
                Set-ADObject -Identity $ctx.DomainDn -Replace @{ 'ms-DS-MachineAccountQuota' = $desired } @ad -ErrorAction Stop
                Write-TierLog -Message "ms-DS-MachineAccountQuota set from $current to $desired" -Level Success
                Add-TierAction -Phase 'Domain' -ObjectType 'MachineAccountQuota' -Target $ctx.DomainFqdn -Result 'Updated' -Detail "Was $current, now $desired"
            }
            else {
                Add-TierAction -Phase 'Domain' -ObjectType 'MachineAccountQuota' -Target $ctx.DomainFqdn -Result 'Planned' -Detail "Would set $current to $desired"
            }
        }
        catch {
            Write-TierLog -Message "ms-DS-MachineAccountQuota could not be processed - $($_.Exception.Message)" -Level Error
            Add-TierAction -Phase 'Domain' -ObjectType 'MachineAccountQuota' -Target $ctx.DomainFqdn -Result 'Failed' -Detail $_.Exception.Message
        }
    }

    # ---- replication change notification -----------------------------------------------
    if ($names -contains 'enableSiteLinkNotification' -and $options.enableSiteLinkNotification) {
        # Without change notification a site link waits for its replication interval, by default
        # 180 minutes. A removed group membership or a revoked delegation then stays effective in
        # remote sites for hours. Option bit 1 turns on immediate notification.
        try {
            $links = @(Get-ADReplicationSiteLink -Filter * -Properties Options @ad -ErrorAction Stop)

            foreach ($link in $links) {
                $current = if ($null -eq $link.Options) { 0 } else { [int]$link.Options }

                if (($current -band 1) -eq 1) {
                    Write-TierLog -Message "Change notification already enabled on site link '$($link.Name)'" -Level Skip
                    Add-TierAction -Phase 'Domain' -ObjectType 'SiteLink' -Target $link.Name -Result 'Compliant' -Detail 'Change notification already enabled'
                    continue
                }

                if ($AuditOnly) {
                    Write-TierLog -Message "Site link '$($link.Name)' replicates on a schedule - security changes take up to the replication interval to reach remote sites" -Level Warning
                    Add-TierAction -Phase 'Domain' -ObjectType 'SiteLink' -Target $link.Name -Result 'Drift' -Detail 'Change notification disabled'
                    continue
                }

                if ($PSCmdlet.ShouldProcess($link.Name, 'Enable replication change notification')) {
                    try {
                        Set-ADReplicationSiteLink -Identity $link.DistinguishedName -Replace @{ Options = ($current -bor 1) } @ad -ErrorAction Stop
                        Write-TierLog -Message "Change notification enabled on site link '$($link.Name)'" -Level Success
                        Add-TierAction -Phase 'Domain' -ObjectType 'SiteLink' -Target $link.Name -Result 'Updated'
                    }
                    catch {
                        Add-TierAction -Phase 'Domain' -ObjectType 'SiteLink' -Target $link.Name -Result 'Failed' -Detail $_.Exception.Message
                    }
                }
            }
        }
        catch {
            Write-TierLog -Message "Site links could not be read - $($_.Exception.Message)" -Level Warning
        }
    }

    # ---- default container redirection -------------------------------------------------
    $redirects = @()
    if ($names -contains 'redirectComputersTo' -and $options.redirectComputersTo) {
        $redirects += [pscustomobject]@{ Kind = 'Computer'; Reference = $options.redirectComputersTo; Tool = 'redircmp.exe' }
    }
    if ($names -contains 'redirectUsersTo' -and $options.redirectUsersTo) {
        $redirects += [pscustomobject]@{ Kind = 'User'; Reference = $options.redirectUsersTo; Tool = 'redirusr.exe' }
    }

    if ($redirects.Count -eq 0) { return }

    $domain = Get-ADDomain @ad -ErrorAction SilentlyContinue

    foreach ($redirect in $redirects) {
        try {
            $targetDn = Resolve-TierOuDn -Reference $redirect.Reference
        }
        catch {
            Write-TierLog -Message "Redirection target '$($redirect.Reference)' could not be resolved - $($_.Exception.Message)" -Level Warning
            Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Failed' -Detail $_.Exception.Message
            continue
        }

        $currentDn = if ($redirect.Kind -eq 'Computer') { $domain.ComputersContainer } else { $domain.UsersContainer }

        if ($currentDn -eq $targetDn) {
            Write-TierLog -Message "Default $($redirect.Kind.ToLower()) location already points to $targetDn" -Level Skip
            Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Compliant' -Detail $targetDn
            continue
        }

        if ($AuditOnly) {
            Write-TierLog -Message "Default $($redirect.Kind.ToLower()) location is $currentDn, expected $targetDn" -Level Warning
            Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Drift' -Detail "Currently $currentDn"
            continue
        }

        $redirectTargetExists = $false
        try { $redirectTargetExists = [bool](Get-ADOrganizationalUnit -Identity $targetDn @ad -ErrorAction Stop) }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $redirectTargetExists = $false }
        if (-not $redirectTargetExists) {
            if ($WhatIfPreference) {
                Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Planned' -Detail $targetDn
            }
            else {
                Write-TierLog -Message "Redirection target $targetDn does not exist yet - run the OU stage first" -Level Warning
                Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Missing' -Detail "Target OU $targetDn does not exist"
            }
            continue
        }

        # redircmp and redirusr ship with the AD DS role. They are the supported way to rewrite
        # the wellKnownObjects entry; editing that DN-Binary attribute by hand is easy to corrupt.
        $tool = Get-Command $redirect.Tool -ErrorAction SilentlyContinue
        if (-not $tool) {
            Write-TierLog -Message "$($redirect.Tool) not found - run this stage on a domain controller or redirect manually" -Level Warning
            Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Missing' -Detail "$($redirect.Tool) unavailable on this host"
            continue
        }

        if ($PSCmdlet.ShouldProcess($redirect.Kind, "Redirect the default container to $targetDn")) {
            try {
                $output = & $tool.Source $targetDn 2>&1
                if ($LASTEXITCODE -ne 0) { throw ($output -join ' ') }
                Write-TierLog -Message "Default $($redirect.Kind.ToLower()) location redirected to $targetDn" -Level Success
                Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Updated' -Detail $targetDn
            }
            catch {
                Write-TierLog -Message "Redirection failed - $($_.Exception.Message)" -Level Error
                Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Failed' -Detail $_.Exception.Message
            }
        }
        else {
            Add-TierAction -Phase 'Domain' -ObjectType 'DefaultContainer' -Target $redirect.Kind -Result 'Planned' -Detail $targetDn
        }
    }
}

function Set-TierAuditPolicy {
    <#
        .SYNOPSIS
        Applies the configured SACL audit rules to the tier model.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    if (-not $Configuration.auditing) { return }
    if (-not $Configuration.auditing.enabled) { return }

    Write-TierLog -Message 'Directory auditing (SACL)' -Level Header

    foreach ($rule in @($Configuration.auditing.rules)) {
        try {
            $targetDn = Resolve-TierOuDn -Reference $rule.targetOu
        }
        catch {
            Write-TierLog -Message "Audit target '$($rule.targetOu)' could not be resolved - $($_.Exception.Message)" -Level Error
            Add-TierAction -Phase 'Auditing' -ObjectType 'Sacl' -Target $rule.targetOu -Result 'Failed' -Detail $_.Exception.Message
            continue
        }

        $principal = Resolve-TierPrincipal -Reference $rule.principal -AllowMissing
        if (-not $principal) {
            Write-TierLog -Message "Audit principal '$($rule.principal)' not found" -Level Warning
            Add-TierAction -Phase 'Auditing' -ObjectType 'Sacl' -Target "$($rule.principal) on $targetDn" -Result 'Missing'
            continue
        }

        $inherited = $null
        if ($rule.PSObject.Properties.Name -contains 'inheritedObjectType') { $inherited = $rule.inheritedObjectType }

        try {
            $result = Set-TierAuditRule -TargetDn $targetDn -PrincipalSid $principal.SID -Rights $rule.rights `
                -AuditFlags $rule.flags -ObjectType $rule.objectType -InheritedObjectType $inherited `
                -Inheritance $rule.inheritance -AuditOnly:$AuditOnly -Confirm:$false

            $level = if ($result -eq 'Compliant') { 'Skip' } elseif ($result -eq 'Missing') { 'Warning' } else { 'Success' }
            Write-TierLog -Message "Audit $($rule.flags) for $($rule.principal) on $targetDn : $result" -Level $level
            Add-TierAction -Phase 'Auditing' -ObjectType 'Sacl' -Target "$($rule.principal) on $targetDn" -Result $result -Detail $rule.comment
        }
        catch {
            Write-TierLog -Message "Audit rule on $targetDn failed - $($_.Exception.Message)" -Level Error
            Add-TierAction -Phase 'Auditing' -ObjectType 'Sacl' -Target "$($rule.principal) on $targetDn" -Result 'Failed' -Detail $_.Exception.Message
        }
    }

    Write-TierLog -Message 'SACL entries only produce events when the "Directory Service Changes" audit subcategory is enabled on the domain controllers.' -Level Info
}

function Test-TierLogonLockout {
    <#
        .SYNOPSIS
        Refuses to write a logon restriction that would lock the operator out of the machine they
        are working from.

        .DESCRIPTION
        Cross-tier denial is the whole point of the model: a Tier 0 account is supposed to lose
        its logon rights on Tier 1 and Tier 2 systems, and once the top tier group is nested into
        Domain Admins - which is what the configuration declares - every Tier 0 account is a
        Domain Admin sitting in the other tiers' deny groups. A check that flags that would fire
        on every correctly configured domain, and a warning that always fires is noise.

        What actually matters is narrower: would applying this policy remove the logon rights of
        a critical account on a machine that is needed to fix it afterwards? That is the domain
        controller, and the machine this script is running on. Only the GPOs targeting those are
        examined; everything else is the model working as designed.

        Logon rights are tattooed, so this has to run before the template is written - afterwards
        the only ways in are the console, another machine over the network, or DSRM.

        .OUTPUTS
        An array of human-readable problem descriptions. Empty means safe to proceed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Configuration
    )

    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $problems = [System.Collections.Generic.List[string]]::new()

    # ---- the identities that must keep their access ----------------------------------------
    $critical = @{}

    try {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $critical[$me.User.Value] = "the account running this deployment ($($me.Name))"
    }
    catch {
        Write-TierLog -Message "Could not determine the current identity - the lockout guard cannot check the executing account: $($_.Exception.Message)" -Level Warning
    }

    $critical["$($ctx.DomainSid)-500"] = 'the built-in Administrator'

    # ---- the machines whose access has to survive --------------------------------------------
    # The domain controller, because that is where the recovery happens, and whatever machine
    # this is running from, because that is the session in use right now.
    $protectedTargets = [System.Collections.Generic.List[string]]::new()
    $protectedTargets.Add($ctx.DomainControllersDn)

    try {
        $thisComputer = Get-ADComputer -Identity $env:COMPUTERNAME @ad -ErrorAction Stop
        $protectedTargets.Add($thisComputer.DistinguishedName)
    }
    catch {
        Write-TierLog -Message "Could not locate this machine in the directory - only the domain controller OU is checked for lockout risk." -Level Warning
    }

    # ---- only the policies that reach those machines -----------------------------------------
    foreach ($tier in $Configuration.tiers) {
        foreach ($gpo in @($tier.gpos)) {
            try { $targetDn = Resolve-TierOuDn -Reference $gpo.targetOu -TierName $tier.name }
            catch { continue }

            # Does this policy apply to a machine we must not lose?
            $reaches = $false
            foreach ($target in $protectedTargets) {
                if ($target -eq $targetDn -or $target -like "*,$targetDn") { $reaches = $true; break }
            }
            if (-not $reaches) { continue }

            $denyGroups = [System.Collections.Generic.List[string]]::new()
            foreach ($right in ($gpo.userRights.PSObject.Properties.Name | Where-Object { $_ -like 'SeDeny*Logon*' })) {
                foreach ($reference in @($gpo.userRights.$right)) {
                    if ($reference -like 'S-1-*') { continue }
                    if ($denyGroups -notcontains $reference) { $denyGroups.Add($reference) }
                }
            }

            foreach ($groupName in $denyGroups) {
                $group = Resolve-TierPrincipal -Reference $groupName -AllowMissing
                if (-not $group -or -not $group.DistinguishedName) { continue }

                foreach ($member in @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive @ad -ErrorAction SilentlyContinue)) {
                    if ($critical.ContainsKey($member.SID.Value)) {
                        $problems.Add("$($gpo.name) denies logon to $groupName on $targetDn, which contains $($critical[$member.SID.Value])")
                    }
                }
            }
        }
    }

    return $problems.ToArray()
}

function New-TierGpoSet {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly,
        [switch]$Force
    )

    if (-not $Configuration.options.createGpos) {
        Write-TierLog -Message 'GPO deployment is disabled in the configuration' -Level Info
        return
    }

    Write-TierLog -Message 'Group Policy Objects' -Level Header
    Clear-TierPrincipalCache
    $adParams = Get-TierAdParameter

    if (-not $AuditOnly) {
        Write-TierLog -Message 'Logon rights are tattooed: once applied, disabling a GPO link does NOT give a removed right back. Keep a second way into the domain controller available (console or DSRM) until you have verified a fresh logon.' -Level Warning
    }

    # Lockout guard. Logon rights are tattooed, so this has to stop the run before anything is
    # written - afterwards the only remedies are the console, another machine, or DSRM.
    $lockoutProblems = @(Test-TierLogonLockout -Configuration $Configuration)
    if ($lockoutProblems.Count -gt 0) {
        $verdict = if ($AuditOnly) { 'LOCKOUT RISK - these accounts would lose their logon rights' }
        else { 'LOCKOUT RISK - the logon restriction stage was not applied' }
        Write-TierLog -Message $verdict -Level Error

        # An override is a decision, not a failure. Counting it as one leaves every subsequent
        # run reporting 'Failed: 2' with nothing wrong, which trains the operator to ignore the
        # number - and the number is the thing that has to stay meaningful.
        $lockoutResult = if ($Force -and -not $AuditOnly) { 'Compliant' } else { 'Failed' }
        $lockoutSeverity = if ($Force -and -not $AuditOnly) { 'Medium' } else { 'High' }
        $lockoutSuffix = if ($Force -and -not $AuditOnly) { ' (accepted with -Force)' } else { '' }

        foreach ($problem in $lockoutProblems) {
            Write-TierLog -Message "  $problem" -Level Error
            Add-TierAction -Phase 'GPO' -ObjectType 'LockoutRisk' -Target 'Logon restrictions' `
                -Result $lockoutResult -Detail "$problem$lockoutSuffix" -Severity $lockoutSeverity
        }

        Write-TierLog -Message 'Remove the affected account from the tier role group, or give it a dedicated per-tier account, then run this stage again.' -Level Warning

        if (-not $AuditOnly) {
            Write-TierLog -Message 'Override with -Force only when a second way into the domain controller is available (console or DSRM).' -Level Warning
            if (-not $Force) { return }
            Write-TierLog -Message '-Force was supplied - continuing despite the lockout risk.' -Level Warning
        }
    }
    $enforce = [bool]$Configuration.options.enforceGpoLinks

    $restrictedMode = 'MemberOf'
    if ($Configuration.options.PSObject.Properties.Name -contains 'restrictedGroupsMode' -and $Configuration.options.restrictedGroupsMode) {
        $restrictedMode = $Configuration.options.restrictedGroupsMode
    }
    Write-TierLog -Message "Restricted groups mode: $restrictedMode" -Level $(if ($restrictedMode -eq 'Replace') { 'Warning' } else { 'Info' })

    foreach ($tier in $Configuration.tiers) {
        foreach ($gpoDef in @($tier.gpos)) {

            $creation = New-TierGpoIfMissing -Name $gpoDef.name -Comment $gpoDef.comment -AuditOnly:$AuditOnly
            if ($AuditOnly -and -not $creation.Gpo) {
                Write-TierLog -Message "GPO missing: $($gpoDef.name)" -Level Warning
                Add-TierAction -Phase 'GPO' -ObjectType 'Gpo' -Target $gpoDef.name -Result 'Missing'
                continue
            }
            Write-TierLog -Message "GPO $($gpoDef.name): $($creation.Result)" -Level $(if ($creation.Result -eq 'Compliant') { 'Skip' } else { 'Success' })
            Add-TierAction -Phase 'GPO' -ObjectType 'Gpo' -Target $gpoDef.name -Result $creation.Result

            if (-not $creation.Gpo) { continue }

            # --- resolve principals to SIDs -------------------------------------------------
            # Deny rights and allow rights land in the same [Privilege Rights] section, so both
            # sources are merged here. An allow entry is absolute: whoever is not listed loses
            # the right, including principals that hold it today by Windows default.
            $rightSources = @($gpoDef.userRights) | Where-Object { $_ }
            if ($gpoDef.PSObject.Properties.Name -contains 'allowedUserRights' -and $gpoDef.allowedUserRights) {
                $rightSources = @($rightSources) + $gpoDef.allowedUserRights
                Write-TierLog -Message "$($gpoDef.name) uses allow lists - principals not listed lose the right" -Level Warning
            }

            $userRights = @{}
            foreach ($source in $rightSources) {
            foreach ($rightName in $source.PSObject.Properties.Name) {
                $sids = [System.Collections.Generic.List[string]]::new()
                if ($userRights.ContainsKey($rightName)) { $sids.AddRange([string[]]$userRights[$rightName]) }

                foreach ($reference in @($source.$rightName)) {
                    $principal = Resolve-TierPrincipal -Reference $reference -AllowMissing
                    if ($principal) { $sids.Add($principal.SID) }
                    else { Write-TierLog -Message "User right principal '$reference' not found - skipped" -Level Warning }
                }
                if ($sids.Count -gt 0) { $userRights[$rightName] = @($sids | Sort-Object -Unique) }
            }
            }

            $restricted = @{}
            if ($gpoDef.restrictedGroups) {
                foreach ($targetSid in $gpoDef.restrictedGroups.PSObject.Properties.Name) {
                    $sids = [System.Collections.Generic.List[string]]::new()
                    foreach ($reference in @($gpoDef.restrictedGroups.$targetSid)) {
                        $principal = Resolve-TierPrincipal -Reference $reference -AllowMissing
                        if ($principal) { $sids.Add($principal.SID) }
                    }
                    if ($sids.Count -gt 0) { $restricted[$targetSid] = $sids.ToArray() }
                }
            }

            # --- security template ----------------------------------------------------------
            try {
                $templateResult = Set-TierGpoSecurityTemplate -GpoId $creation.Gpo.Id -UserRights $userRights `
                    -RestrictedGroups $restricted -RestrictedGroupsMode $restrictedMode -AuditOnly:$AuditOnly
                Write-TierLog -Message "Security template for $($gpoDef.name): $templateResult" -Level $(if ($templateResult -eq 'Compliant') { 'Skip' } else { 'Success' })
                Add-TierAction -Phase 'GPO' -ObjectType 'SecurityTemplate' -Target $gpoDef.name -Result $templateResult
            }
            catch {
                Write-TierLog -Message "Security template for $($gpoDef.name) failed - $($_.Exception.Message)" -Level Error
                Add-TierAction -Phase 'GPO' -ObjectType 'SecurityTemplate' -Target $gpoDef.name -Result 'Failed' -Detail $_.Exception.Message
            }

            # --- registry based settings ----------------------------------------------------
            foreach ($setting in @($gpoDef.registrySettings)) {
                try {
                    $regResult = Set-TierGpoRegistrySetting -GpoName $gpoDef.name -Key $setting.key `
                        -ValueName $setting.valueName -Type $setting.type -Value $setting.value -AuditOnly:$AuditOnly
                    Add-TierAction -Phase 'GPO' -ObjectType 'RegistrySetting' -Target "$($gpoDef.name):$($setting.valueName)" -Result $regResult -Detail $setting.comment
                }
                catch {
                    Write-TierLog -Message "Registry setting $($setting.valueName) in $($gpoDef.name) failed - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'GPO' -ObjectType 'RegistrySetting' -Target "$($gpoDef.name):$($setting.valueName)" -Result 'Failed' -Detail $_.Exception.Message
                }
            }

            # --- exception group ------------------------------------------------------------
            # A domain local group with a Deny on Apply Group Policy. During a rollout there is
            # always one machine that must be exempted; without this the only options are
            # unlinking the GPO or moving the machine out of its tier.
            if ($gpoDef.exceptionGroup) {
                $exceptionOu = Resolve-TierOuDn -Reference $gpoDef.exceptionGroupOu -TierName $tier.name
                $existing = Get-ADGroup -LDAPFilter "(sAMAccountName=$($gpoDef.exceptionGroup))" @adParams -ErrorAction SilentlyContinue | Select-Object -First 1

                if (-not $existing -and -not $AuditOnly) {
                    if ($PSCmdlet.ShouldProcess($gpoDef.exceptionGroup, "Create GPO exception group in $exceptionOu")) {
                        try {
                            New-ADGroup -Name $gpoDef.exceptionGroup -SamAccountName $gpoDef.exceptionGroup `
                                -GroupScope DomainLocal -GroupCategory Security -Path $exceptionOu `
                                -Description "Members are exempted from the GPO $($gpoDef.name)" @adParams -ErrorAction Stop
                            Write-TierLog -Message "Exception group created: $($gpoDef.exceptionGroup)" -Level Success
                            Add-TierAction -Phase 'GPO' -ObjectType 'ExceptionGroup' -Target $gpoDef.exceptionGroup -Result 'Created' -Detail $exceptionOu
                            Clear-TierPrincipalCache
                            $existing = Get-ADGroup -LDAPFilter "(sAMAccountName=$($gpoDef.exceptionGroup))" @adParams -ErrorAction SilentlyContinue | Select-Object -First 1
                        }
                        catch {
                            Write-TierLog -Message "Exception group $($gpoDef.exceptionGroup) failed - $($_.Exception.Message)" -Level Error
                            Add-TierAction -Phase 'GPO' -ObjectType 'ExceptionGroup' -Target $gpoDef.exceptionGroup -Result 'Failed' -Detail $_.Exception.Message
                        }
                    }
                }
                elseif (-not $existing) {
                    Add-TierAction -Phase 'GPO' -ObjectType 'ExceptionGroup' -Target $gpoDef.exceptionGroup -Result 'Missing'
                }
                else {
                    Write-TierLog -Message "Exception group exists: $($gpoDef.exceptionGroup)" -Level Skip
                    Add-TierAction -Phase 'GPO' -ObjectType 'ExceptionGroup' -Target $gpoDef.exceptionGroup -Result 'Compliant'
                }

                if ($existing) {
                    $gpoDn = "CN={$($creation.Gpo.Id.ToString().ToUpper())},CN=Policies,CN=System,$((Get-TierContext).DomainDn)"
                    try {
                        $denyResult = Set-TierAccessRule -TargetDn $gpoDn -PrincipalSid $existing.SID.Value `
                            -Rights 'ExtendedRight' -AccessType 'Deny' -ObjectType 'Apply-Group-Policy' `
                            -Inheritance 'None' -AuditOnly:$AuditOnly -Confirm:$false
                        Write-TierLog -Message "Deny apply for $($gpoDef.exceptionGroup) on $($gpoDef.name): $denyResult" -Level $(if ($denyResult -eq 'Compliant') { 'Skip' } else { 'Success' })
                        Add-TierAction -Phase 'GPO' -ObjectType 'GpoFiltering' -Target "$($gpoDef.name) deny $($gpoDef.exceptionGroup)" -Result $denyResult
                    }
                    catch {
                        Write-TierLog -Message "Deny ACE on $($gpoDef.name) failed - $($_.Exception.Message)" -Level Error
                        Add-TierAction -Phase 'GPO' -ObjectType 'GpoFiltering' -Target "$($gpoDef.name) deny $($gpoDef.exceptionGroup)" -Result 'Failed' -Detail $_.Exception.Message
                    }
                }
            }

            # --- delegation and ownership ---------------------------------------------------
            if ($gpoDef.PSObject.Properties.Name -contains 'delegation' -and $gpoDef.delegation) {
                foreach ($outcome in @(Set-TierGpoDelegation -Gpo $creation.Gpo -Delegation $gpoDef.delegation -AuditOnly:$AuditOnly -Confirm:$false)) {
                    $level = switch ($outcome.Result) {
                        'Compliant' { 'Skip' }
                        'Failed' { 'Error' }
                        'Missing' { 'Warning' }
                        default { 'Success' }
                    }
                    Write-TierLog -Message "GPO delegation $($outcome.Target): $($outcome.Result)" -Level $level
                    Add-TierAction -Phase 'GPO' -ObjectType 'GpoDelegation' -Target $outcome.Target -Result $outcome.Result -Detail $outcome.Detail
                }

                if ($gpoDef.delegation.owner) {
                    $ownerPrincipal = Resolve-TierPrincipalReference -Reference $gpoDef.delegation.owner -AllowMissing
                    if (-not $ownerPrincipal) {
                        Write-TierLog -Message "GPO owner '$($gpoDef.delegation.owner)' for $($gpoDef.name) not found" -Level Warning
                        Add-TierAction -Phase 'GPO' -ObjectType 'GpoOwner' -Target $gpoDef.name -Result 'Missing'
                    }
                    else {
                        $gpoDn = "CN={$($creation.Gpo.Id.ToString().ToUpper())},$((Get-TierContext).PoliciesDn)"
                        try {
                            $ownerResult = Set-TierGpoOwner -GpoDn $gpoDn -OwnerSid $ownerPrincipal.SID -AuditOnly:$AuditOnly -Confirm:$false
                            $level = if ($ownerResult -eq 'Compliant') { 'Skip' } elseif ($ownerResult -eq 'Missing') { 'Warning' } else { 'Success' }
                            Write-TierLog -Message "GPO owner $($gpoDef.name) -> $($gpoDef.delegation.owner): $ownerResult" -Level $level
                            # An owner other than the declared one means the creator can still
                            # rewrite the DACL, so a drifted owner is a real finding, not cosmetic.
                            Add-TierAction -Phase 'GPO' -ObjectType 'GpoOwner' -Target "$($gpoDef.name) owner" -Result $ownerResult `
                                -Detail 'An owner holds WRITE_DAC implicitly and can undo the delegation on this policy'
                        }
                        catch {
                            Write-TierLog -Message "Setting the owner of $($gpoDef.name) failed - $($_.Exception.Message)" -Level Error
                            Add-TierAction -Phase 'GPO' -ObjectType 'GpoOwner' -Target "$($gpoDef.name) owner" -Result 'Failed' -Detail $_.Exception.Message
                        }
                    }
                }
            }

            # --- link -----------------------------------------------------------------------
            if ($Configuration.options.linkGpos) {
                $targetDn = Resolve-TierOuDn -Reference $gpoDef.targetOu -TierName $tier.name
                try {
                    # A GPO may declare linkEnabled:false to stay linked but inactive. Absent
                    # means enabled, so existing configurations keep working unchanged.
                    $linkEnabled = $true
                    if ($gpoDef.PSObject.Properties.Name -contains 'linkEnabled' -and $null -ne $gpoDef.linkEnabled) {
                        $linkEnabled = [bool]$gpoDef.linkEnabled
                    }

                    $linkResult = Set-TierGpoLink -GpoName $gpoDef.name -TargetDn $targetDn -Enforced:$enforce -LinkEnabled $linkEnabled -AuditOnly:$AuditOnly
                    $linkNote = if ($linkEnabled) { '' } else { ' (link disabled by configuration)' }
                    Write-TierLog -Message "Link $($gpoDef.name) -> $targetDn$linkNote : $linkResult" -Level $(if ($linkResult -eq 'Compliant') { 'Skip' } else { 'Success' })
                    Add-TierAction -Phase 'GPO' -ObjectType 'GpoLink' -Target "$($gpoDef.name) -> $targetDn" -Result $linkResult
                }
                catch {
                    Write-TierLog -Message "Linking $($gpoDef.name) failed - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'GPO' -ObjectType 'GpoLink' -Target "$($gpoDef.name) -> $targetDn" -Result 'Failed' -Detail $_.Exception.Message
                }
            }
        }
    }
}

function Set-TierWindowsLaps {
    <#
        .SYNOPSIS
        Deploys Windows LAPS: schema, directory permissions and the policy GPO per tier.

        .DESCRIPTION
        Windows LAPS is the version built into Windows 11 22H2, Windows Server 2022 and later.
        The legacy Microsoft LAPS with its separate AdmPwd client-side extension is deliberately
        not supported here - it uses different attributes, a different ACL model and is on its
        way out.

        Why this belongs in a tier model at all: without LAPS every machine in a tier shares a
        local administrator password, so compromising one workstation yields local administrator
        on all of them. The logon restrictions stop a Tier 2 helpdesk account from reaching a
        Tier 0 server, but they do nothing about a local account that exists identically
        everywhere.

        The permissions are per tier, which is the point. Tier 2 operators can read the local
        password of a workstation and nothing else; the Tier 0 group can read Tier 0 machines.
        The domain controller OU is handled separately because the DSRM password decryptor always
        defaults to Domain Admins and cannot be redirected.

        Password encryption requires domain functional level 2016 or higher. Below that the
        password is stored in clear text in the directory, protected only by the ACL.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    if (-not $Configuration.windowsLaps) { return }
    if (-not $Configuration.windowsLaps.enabled) { return }

    # The option in the options block is the master switch: it is what the wizard sets and what
    # an operator reaches for first. Without this check, turning it off there would silently do
    # nothing because the stage only ever looked at windowsLaps.enabled.
    if ($Configuration.options.PSObject.Properties.Name -contains 'deployWindowsLaps' -and
        -not $Configuration.options.deployWindowsLaps) {
        Write-TierLog -Message 'Windows LAPS is disabled via options.deployWindowsLaps' -Level Info
        return
    }

    Write-TierLog -Message 'Windows LAPS' -Level Header

    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $lapsDef = $Configuration.windowsLaps

    # ---- module -----------------------------------------------------------------------------
    if (-not (Get-Command -Name 'Set-LapsADComputerSelfPermission' -ErrorAction SilentlyContinue)) {
        Write-TierLog -Message 'The LAPS PowerShell module is not available. It ships with Windows Server 2022 and Windows 11 22H2 (April 2023 update) and later - this stage needs to run on such a host.' -Level Error
        Add-TierAction -Phase 'LAPS' -ObjectType 'Module' -Target 'LAPS' -Result 'Missing' -Detail 'Set-LapsADComputerSelfPermission not found' -Severity 'Medium'
        return
    }

    # ---- schema -----------------------------------------------------------------------------
    $rootDse = Get-ADRootDSE @ad
    $schemaReady = [bool](Get-ADObject -SearchBase $rootDse.schemaNamingContext `
            -LDAPFilter '(lDAPDisplayName=msLAPS-EncryptedPassword)' @ad -ErrorAction SilentlyContinue)

    if ($schemaReady) {
        Write-TierLog -Message 'Windows LAPS schema attributes are present' -Level Skip
        Add-TierAction -Phase 'LAPS' -ObjectType 'Schema' -Target $ctx.DomainFqdn -Result 'Compliant'
    }
    elseif ($AuditOnly) {
        Write-TierLog -Message 'Windows LAPS schema extension is missing - no machine can store a password' -Level Warning
        Add-TierAction -Phase 'LAPS' -ObjectType 'Schema' -Target $ctx.DomainFqdn -Result 'Missing' -Detail 'msLAPS attributes absent' -Severity 'Medium'
    }
    elseif (-not $lapsDef.updateSchema) {
        Write-TierLog -Message 'Schema extension is missing and updateSchema is off - permissions and policy will not take effect' -Level Warning
        Add-TierAction -Phase 'LAPS' -ObjectType 'Schema' -Target $ctx.DomainFqdn -Result 'Missing' -Detail 'updateSchema disabled in the configuration'
    }
    elseif ($PSCmdlet.ShouldProcess($ctx.DomainFqdn, 'Extend the schema for Windows LAPS (irreversible, requires Schema Admins)')) {
        try {
            Update-LapsADSchema -Confirm:$false -ErrorAction Stop | Out-Null
            Write-TierLog -Message 'Schema extended for Windows LAPS' -Level Success
            Add-TierAction -Phase 'LAPS' -ObjectType 'Schema' -Target $ctx.DomainFqdn -Result 'Created'
            $schemaReady = $true
        }
        catch {
            Write-TierLog -Message "Schema extension failed - $($_.Exception.Message). Schema Admins membership and the schema master are required." -Level Error
            Add-TierAction -Phase 'LAPS' -ObjectType 'Schema' -Target $ctx.DomainFqdn -Result 'Failed' -Detail $_.Exception.Message
            return
        }
    }

    # ---- encryption capability ---------------------------------------------------------------
    $encryptionCapable = $ctx.Domain.DomainMode -notin @(
        'Windows2000Domain', 'Windows2003Domain', 'Windows2008Domain',
        'Windows2008R2Domain', 'Windows2012Domain', 'Windows2012R2Domain')

    if (-not $encryptionCapable) {
        Write-TierLog -Message "Domain functional level is $($ctx.Domain.DomainMode) - LAPS password encryption needs 2016 or higher. Passwords will be stored unencrypted, protected only by the ACL." -Level Warning
        Add-TierAction -Phase 'LAPS' -ObjectType 'Encryption' -Target $ctx.DomainFqdn -Result 'Drift' -Detail "Functional level $($ctx.Domain.DomainMode) does not support encryption" -Severity 'Medium'
    }

    # ---- delegations -------------------------------------------------------------------------
    # Without the schema attributes every permission call fails and the LAPS module prints its
    # own warnings. In a dry run the extension is part of the same plan, so the permissions are
    # simply planned; outside a dry run there is nothing useful to do until the schema is there.
    if (-not $schemaReady) {
        foreach ($entry in @($lapsDef.delegations)) {
            $result = if ($AuditOnly) { 'Missing' } elseif ($WhatIfPreference) { 'Planned' } else { 'Missing' }
            Add-TierAction -Phase 'LAPS' -ObjectType 'LapsPermission' -Target $entry.targetOu -Result $result -Detail 'Waiting for the schema extension'
        }
        if (-not $AuditOnly -and -not $WhatIfPreference) {
            Write-TierLog -Message 'Permissions and policies are skipped until the schema extension has run.' -Level Warning
        }
        return
    }

    foreach ($entry in @($lapsDef.delegations)) {
        try { $targetDn = Resolve-TierOuDn -Reference $entry.targetOu }
        catch {
            Write-TierLog -Message "LAPS target '$($entry.targetOu)' could not be resolved - $($_.Exception.Message)" -Level Error
            Add-TierAction -Phase 'LAPS' -ObjectType 'LapsPermission' -Target $entry.targetOu -Result 'Failed' -Detail $_.Exception.Message
            continue
        }

        $lapsTargetExists = $false
        try { $lapsTargetExists = [bool](Get-ADObject -Identity $targetDn @ad -ErrorAction Stop) }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $lapsTargetExists = $false }
        if (-not $lapsTargetExists) {
            Write-TierLog -Message "LAPS target $targetDn does not exist yet" -Level Warning
            Add-TierAction -Phase 'LAPS' -ObjectType 'LapsPermission' -Target $targetDn -Result 'Missing' -Detail 'Target OU does not exist'
            continue
        }

        # Existing extended rights, used both for the compliance check and for the audit run.
        $granted = @()
        try {
            $rights = Find-LapsADExtendedRights -Identity $targetDn -ErrorAction SilentlyContinue
            if ($rights) { $granted = @($rights.ExtendedRightHolders) }
        }
        catch {
            # Without the existing holders every permission looks missing and gets granted again
            # on every run - noisy rather than harmful, but worth knowing about.
            Write-TierLog -Message "Existing LAPS rights on $targetDn could not be read - permissions will be re-applied: $($_.Exception.Message)" -Level Warning
        }

        # --- computers must be able to write their own password --------------------------------
        if ($entry.computerSelfPermission) {
            # The self permission is NOT an extended right - it is WriteProperty for SELF on the
            # msLAPS attributes, so Find-LapsADExtendedRights never reports it. Which of those
            # attributes the cmdlet touches depends on the schema version and on whether
            # encryption is in play, so the check asks the schema for the whole msLAPS-* set and
            # accepts a write permission on any of them. Without this the permission is
            # re-applied on every run and reported as 'Created' forever.
            $selfPresent = $false
            try {
                if (-not $script:LapsAttributeGuids) {
                    $rootDseLocal = Get-ADRootDSE @ad
                    $script:LapsAttributeGuids = @(
                        Get-ADObject -SearchBase $rootDseLocal.schemaNamingContext `
                            -LDAPFilter '(&(objectClass=attributeSchema)(lDAPDisplayName=msLAPS-*))' `
                            -Properties schemaIDGUID @ad -ErrorAction Stop |
                            ForEach-Object { [guid]$_.schemaIDGUID }
                    )
                }

                $selfSid = 'S-1-5-10'
                $ouObject = Get-ADObject -Identity $targetDn -Properties nTSecurityDescriptor @ad -ErrorAction Stop

                foreach ($ace in $ouObject.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
                    if ($ace.IdentityReference.Value -ne $selfSid) { continue }
                    if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                    if (($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -eq 0) { continue }
                    if ($script:LapsAttributeGuids -notcontains $ace.ObjectType) { continue }
                    $selfPresent = $true
                    break
                }
            }
            catch {
                Write-TierLog -Message "Could not verify the computer self permission on $targetDn - $($_.Exception.Message)" -Level Warning
            }

            if ($selfPresent) {
                Write-TierLog -Message "Computer self permission already present on $targetDn" -Level Skip
                Add-TierAction -Phase 'LAPS' -ObjectType 'LapsSelfPermission' -Target $targetDn -Result 'Compliant'
            }
            elseif ($AuditOnly) {
                Write-TierLog -Message "Computer self permission missing on $targetDn - machines cannot store their password" -Level Warning
                Add-TierAction -Phase 'LAPS' -ObjectType 'LapsSelfPermission' -Target $targetDn -Result 'Missing'
            }
            elseif ($PSCmdlet.ShouldProcess($targetDn, 'Allow computers to write their own LAPS password')) {
                try {
                    Set-LapsADComputerSelfPermission -Identity $targetDn -ErrorAction Stop | Out-Null
                    Write-TierLog -Message "Computer self permission set on $targetDn" -Level Success
                    Add-TierAction -Phase 'LAPS' -ObjectType 'LapsSelfPermission' -Target $targetDn -Result 'Created'
                }
                catch {
                    Write-TierLog -Message "Computer self permission on $targetDn failed - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'LAPS' -ObjectType 'LapsSelfPermission' -Target $targetDn -Result 'Failed' -Detail $_.Exception.Message
                }
            }
        }

        # --- who may read and who may force a reset -------------------------------------------
        foreach ($permission in @(
                @{ Kind = 'Read'; Group = $entry.readGroup; Cmdlet = 'Set-LapsADReadPasswordPermission' },
                @{ Kind = 'Reset'; Group = $entry.resetGroup; Cmdlet = 'Set-LapsADResetPasswordPermission' })) {

            if (-not $permission.Group) { continue }

            $principal = Resolve-TierPrincipal -Reference $permission.Group -AllowMissing
            if (-not $principal) {
                if ($WhatIfPreference) {
                    Add-TierAction -Phase 'LAPS' -ObjectType "Laps$($permission.Kind)Permission" -Target "$($permission.Group) on $targetDn" -Result 'Planned'
                }
                else {
                    Write-TierLog -Message "LAPS $($permission.Kind.ToLower()) group '$($permission.Group)' not found" -Level Warning
                    Add-TierAction -Phase 'LAPS' -ObjectType "Laps$($permission.Kind)Permission" -Target "$($permission.Group) on $targetDn" -Result 'Missing'
                }
                continue
            }

            # Find-LapsADExtendedRights reports holders as DOMAIN\Name, the configuration names
            # them bare - compare against both spellings or every run grants them again.
            #
            # That list only covers the READ side: the cmdlet reports extended-rights holders,
            # i.e. principals allowed to read the password attributes. The reset permission is
            # WriteProperty on msLAPS-PasswordExpirationTime and never appears there, so it has
            # to be checked against the OU ACL directly - the same technique as the computer
            # self permission above, and for the same reason: without it the grant would be
            # re-applied and reported as 'Created' on every run.
            $present = $false
            if ($permission.Kind -eq 'Read') {
                $qualifiedName = "$($ctx.DomainNetBios)\$($principal.Name)"
                $present = ($granted -contains $principal.Name) -or ($granted -contains $qualifiedName)
            }
            else {
                try {
                    if (-not $script:LapsExpirationTimeGuid) {
                        $rootDseLocal = Get-ADRootDSE @ad
                        $attribute = Get-ADObject -SearchBase $rootDseLocal.schemaNamingContext `
                            -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' `
                            -Properties schemaIDGUID @ad -ErrorAction Stop
                        if ($attribute) { $script:LapsExpirationTimeGuid = [guid]$attribute.schemaIDGUID }
                    }

                    if ($script:LapsExpirationTimeGuid) {
                        $ouSecurity = (Get-ADObject -Identity $targetDn -Properties nTSecurityDescriptor @ad -ErrorAction Stop).nTSecurityDescriptor

                        foreach ($ace in $ouSecurity.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
                            if ($ace.IdentityReference.Value -ne $principal.SID.Value) { continue }
                            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                            if (($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -eq 0) { continue }
                            # The cmdlet writes an ACE scoped to the attribute; an unscoped
                            # WriteProperty (empty ObjectType) covers it as well.
                            if ($ace.ObjectType -ne $script:LapsExpirationTimeGuid -and $ace.ObjectType -ne [guid]::Empty) { continue }
                            $present = $true
                            break
                        }
                    }
                }
                catch {
                    Write-TierLog -Message "Existing LAPS reset permission on $targetDn could not be read - it will be re-applied: $($_.Exception.Message)" -Level Warning
                }
            }

            if ($present) {
                Write-TierLog -Message "LAPS $($permission.Kind.ToLower()) permission already granted to $($permission.Group) on $targetDn" -Level Skip
                Add-TierAction -Phase 'LAPS' -ObjectType "Laps$($permission.Kind)Permission" -Target "$($permission.Group) on $targetDn" -Result 'Compliant'
                continue
            }

            if ($AuditOnly) {
                Write-TierLog -Message "LAPS $($permission.Kind.ToLower()) permission for $($permission.Group) missing on $targetDn" -Level Warning
                Add-TierAction -Phase 'LAPS' -ObjectType "Laps$($permission.Kind)Permission" -Target "$($permission.Group) on $targetDn" -Result 'Missing'
                continue
            }

            if ($PSCmdlet.ShouldProcess($targetDn, "Grant $($permission.Kind.ToLower()) permission to $($permission.Group)")) {
                try {
                    # The LAPS cmdlets reject a bare group name: it has to be DOMAIN\Name or a UPN.
                    $qualified = "$($ctx.DomainNetBios)\$($principal.Name)"
                    & $permission.Cmdlet -Identity $targetDn -AllowedPrincipals $qualified -ErrorAction Stop | Out-Null
                    Write-TierLog -Message "LAPS $($permission.Kind.ToLower()) permission granted to $($permission.Group) on $targetDn" -Level Success
                    Add-TierAction -Phase 'LAPS' -ObjectType "Laps$($permission.Kind)Permission" -Target "$($permission.Group) on $targetDn" -Result 'Created'
                }
                catch {
                    Write-TierLog -Message "LAPS $($permission.Kind.ToLower()) permission failed on $targetDn - $($_.Exception.Message)" -Level Error
                    Add-TierAction -Phase 'LAPS' -ObjectType "Laps$($permission.Kind)Permission" -Target "$($permission.Group) on $targetDn" -Result 'Failed' -Detail $_.Exception.Message
                }
            }
        }

        # --- policy GPO -------------------------------------------------------------------------
        if ($entry.gpoName) {
            Set-TierLapsPolicyGpo -Configuration $Configuration -Entry $entry -TargetDn $targetDn `
                -EncryptionCapable $encryptionCapable -AuditOnly:$AuditOnly -Confirm:$false
        }
    }
}

function Set-TierLapsPolicyGpo {
    <#
        .SYNOPSIS
        Creates and configures the Windows LAPS policy GPO for one tier.

        .DESCRIPTION
        Windows LAPS reads its policy from HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS.
        ADPasswordEncryptionPrincipal decides who can decrypt the stored password and has to be
        set per tier, otherwise every tier's passwords are decryptable by the same group and the
        directory permissions above become decoration.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][object]$Entry,
        [Parameter(Mandatory)][string]$TargetDn,
        [bool]$EncryptionCapable = $true,
        [switch]$AuditOnly
    )

    $ctx = Get-TierContext
    $policy = $Configuration.windowsLaps.policy
    $lapsKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'

    $creation = New-TierGpoIfMissing -Name $Entry.gpoName -Comment "Windows LAPS policy for $TargetDn" -AuditOnly:$AuditOnly
    Add-TierAction -Phase 'LAPS' -ObjectType 'Gpo' -Target $Entry.gpoName -Result $creation.Result
    if (-not $creation.Gpo) { return }

    # Build the value set from the configuration; only what is present is written.
    $values = [System.Collections.Generic.List[object]]::new()
    $map = @{
        backupDirectory                     = @{ Name = 'BackupDirectory'; Type = 'DWord' }
        passwordAgeDays                     = @{ Name = 'PasswordAgeDays'; Type = 'DWord' }
        passwordLength                      = @{ Name = 'PasswordLength'; Type = 'DWord' }
        passwordComplexity                  = @{ Name = 'PasswordComplexity'; Type = 'DWord' }
        administratorAccountName            = @{ Name = 'AdministratorAccountName'; Type = 'String' }
        passwordExpirationProtectionEnabled = @{ Name = 'PasswordExpirationProtectionEnabled'; Type = 'DWord' }
        adEncryptedPasswordHistorySize      = @{ Name = 'ADEncryptedPasswordHistorySize'; Type = 'DWord' }
        postAuthenticationActions           = @{ Name = 'PostAuthenticationActions'; Type = 'DWord' }
        postAuthenticationResetDelay        = @{ Name = 'PostAuthenticationResetDelay'; Type = 'DWord' }
    }

    foreach ($key in $map.Keys) {
        if ($policy.PSObject.Properties.Name -notcontains $key) { continue }
        if ($null -eq $policy.$key) { continue }
        $values.Add([pscustomobject]@{ Name = $map[$key].Name; Type = $map[$key].Type; Value = $policy.$key })
    }

    # Encryption and the decryptor only make sense together, and only at 2016 or higher.
    if ($EncryptionCapable -and $Entry.decryptorGroup) {
        $decryptor = Resolve-TierPrincipal -Reference $Entry.decryptorGroup -AllowMissing
        if ($decryptor) {
            $values.Add([pscustomobject]@{ Name = 'ADPasswordEncryptionEnabled'; Type = 'DWord'; Value = 1 })
            $values.Add([pscustomobject]@{ Name = 'ADPasswordEncryptionPrincipal'; Type = 'String'; Value = "$($ctx.DomainNetBios)\$($decryptor.Name)" })
        }
        else {
            Write-TierLog -Message "Decryptor group '$($Entry.decryptorGroup)' not found - encryption left unconfigured for $($Entry.gpoName)" -Level Warning
            Add-TierAction -Phase 'LAPS' -ObjectType 'LapsDecryptor' -Target $Entry.gpoName -Result 'Missing' -Detail $Entry.decryptorGroup -Severity 'Medium'
        }
    }
    elseif (-not $EncryptionCapable) {
        $values.Add([pscustomobject]@{ Name = 'ADPasswordEncryptionEnabled'; Type = 'DWord'; Value = 0 })
    }

    foreach ($value in $values) {
        try {
            $result = Set-TierGpoRegistrySetting -GpoName $Entry.gpoName -Key $lapsKey `
                -ValueName $value.Name -Type $value.Type -Value $value.Value -AuditOnly:$AuditOnly
            Add-TierAction -Phase 'LAPS' -ObjectType 'LapsPolicy' -Target "$($Entry.gpoName):$($value.Name)" -Result $result -Detail "$($value.Value)"
        }
        catch {
            Write-TierLog -Message "LAPS policy value $($value.Name) in $($Entry.gpoName) failed - $($_.Exception.Message)" -Level Error
            Add-TierAction -Phase 'LAPS' -ObjectType 'LapsPolicy' -Target "$($Entry.gpoName):$($value.Name)" -Result 'Failed' -Detail $_.Exception.Message
        }
    }

    if ($Configuration.options.linkGpos) {
        try {
            $linkResult = Set-TierGpoLink -GpoName $Entry.gpoName -TargetDn $TargetDn -AuditOnly:$AuditOnly
            Write-TierLog -Message "LAPS policy $($Entry.gpoName) -> $TargetDn : $linkResult" -Level $(if ($linkResult -eq 'Compliant') { 'Skip' } else { 'Success' })
            Add-TierAction -Phase 'LAPS' -ObjectType 'GpoLink' -Target "$($Entry.gpoName) -> $TargetDn" -Result $linkResult
        }
        catch {
            Add-TierAction -Phase 'LAPS' -ObjectType 'GpoLink' -Target "$($Entry.gpoName) -> $TargetDn" -Result 'Failed' -Detail $_.Exception.Message
        }
    }
}

function New-TierKdsRootKey {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    if (-not $Configuration.options.createKdsRootKey) { return }

    Write-TierLog -Message 'KDS root key (gMSA/dMSA prerequisite)' -Level Header

    try {
        $keys = @(Get-KdsRootKey -ErrorAction Stop)
        if ($keys.Count -gt 0) {
            Write-TierLog -Message "KDS root key already present ($($keys.Count) key(s))" -Level Skip
            Add-TierAction -Phase 'KDS' -ObjectType 'KdsRootKey' -Target 'Forest' -Result 'Compliant'
            return
        }
    }
    catch {
        Write-TierLog -Message "Unable to query KDS root keys - $($_.Exception.Message)" -Level Warning
    }

    if ($AuditOnly) {
        Write-TierLog -Message 'No KDS root key in the forest - group managed service accounts cannot be created' -Level Warning
        Add-TierAction -Phase 'KDS' -ObjectType 'KdsRootKey' -Target 'Forest' -Result 'Missing' -Detail 'No root key present'
        return
    }

    if ($PSCmdlet.ShouldProcess('Forest', 'Create KDS root key')) {
        try {
            if ($Configuration.options.kdsRootKeyEffectiveImmediately) {
                # Backdating is only acceptable in single-DC lab environments.
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop | Out-Null
                Write-TierLog -Message 'KDS root key created with backdated effective time (lab mode)' -Level Warning
            }
            else {
                Add-KdsRootKey -EffectiveImmediately -ErrorAction Stop | Out-Null
                Write-TierLog -Message 'KDS root key created - usable after 10 hours of replication' -Level Success
            }
            Add-TierAction -Phase 'KDS' -ObjectType 'KdsRootKey' -Target 'Forest' -Result 'Created'
        }
        catch {
            Write-TierLog -Message "KDS root key creation failed - $($_.Exception.Message)" -Level Error
            Add-TierAction -Phase 'KDS' -ObjectType 'KdsRootKey' -Target 'Forest' -Result 'Failed' -Detail $_.Exception.Message
        }
    }
}

function Enable-TierRecycleBin {
    <#
        .SYNOPSIS
        Enables the Active Directory Recycle Bin optional feature.

        .DESCRIPTION
        Without the Recycle Bin a deleted OU, group or delegation can only be recovered from a
        system state backup with an authoritative restore. With it, objects can be undeleted
        including their group memberships and ACLs, which is exactly what you want while a tier
        model is being rolled out.

        Enabling is irreversible and forest wide. The optional feature is identified by its
        feature GUID rather than its name so that the check is independent of the directory
        language.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    if ($Configuration.options.PSObject.Properties.Name -notcontains 'enableAdRecycleBin') { return }
    if (-not $Configuration.options.enableAdRecycleBin) { return }

    Write-TierLog -Message 'Active Directory Recycle Bin' -Level Header

    $ad = Get-TierAdParameter
    $recycleBinFeatureGuid = '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a'

    try {
        $forest = Get-ADForest @ad -ErrorAction Stop
        $feature = Get-ADOptionalFeature -Filter * @ad -ErrorAction Stop |
            Where-Object { $_.FeatureGUID -eq $recycleBinFeatureGuid } |
            Select-Object -First 1
    }
    catch {
        Write-TierLog -Message "Unable to query optional features - $($_.Exception.Message)" -Level Error
        Add-TierAction -Phase 'RecycleBin' -ObjectType 'OptionalFeature' -Target 'Forest' -Result 'Failed' -Detail $_.Exception.Message
        return
    }

    if (-not $feature) {
        Write-TierLog -Message 'Recycle Bin feature not present - requires forest functional level 2008 R2 or higher' -Level Warning
        Add-TierAction -Phase 'RecycleBin' -ObjectType 'OptionalFeature' -Target 'Forest' -Result 'Missing' -Detail 'Feature unavailable at this forest functional level'
        return
    }

    if ($feature.EnabledScopes -and $feature.EnabledScopes.Count -gt 0) {
        Write-TierLog -Message 'Recycle Bin is already enabled' -Level Skip
        Add-TierAction -Phase 'RecycleBin' -ObjectType 'OptionalFeature' -Target $forest.Name -Result 'Compliant'
        return
    }

    if ($AuditOnly) {
        Write-TierLog -Message 'Recycle Bin is not enabled - deleted objects cannot be undeleted' -Level Warning
        Add-TierAction -Phase 'RecycleBin' -ObjectType 'OptionalFeature' -Target $forest.Name -Result 'Missing' -Detail 'Not enabled'
        return
    }

    if ($PSCmdlet.ShouldProcess($forest.Name, 'Enable the Active Directory Recycle Bin (irreversible)')) {
        try {
            Enable-ADOptionalFeature -Identity $feature.DistinguishedName `
                -Scope ForestOrConfigurationSet -Target $forest.Name @ad -Confirm:$false -ErrorAction Stop | Out-Null
            Write-TierLog -Message "Recycle Bin enabled for forest $($forest.Name)" -Level Success
            Add-TierAction -Phase 'RecycleBin' -ObjectType 'OptionalFeature' -Target $forest.Name -Result 'Created'
        }
        catch {
            Write-TierLog -Message "Enabling the Recycle Bin failed - $($_.Exception.Message)" -Level Error
            Add-TierAction -Phase 'RecycleBin' -ObjectType 'OptionalFeature' -Target $forest.Name -Result 'Failed' -Detail $_.Exception.Message
        }
    }
    else {
        Add-TierAction -Phase 'RecycleBin' -ObjectType 'OptionalFeature' -Target $forest.Name -Result 'Planned'
    }
}

function New-TierAuthenticationSilo {
    <#
        .SYNOPSIS
        Creates the Tier 0 authentication policy and silo and assigns members.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [switch]$AuditOnly
    )

    if (-not $Configuration.options.createAuthenticationPolicySilo) { return }

    # A silo per administrative plane, not just for the top tier: a Tier 1 administrator whose
    # ticket works on any machine in the domain is only marginally better than a Tier 0 one.
    $siloDefinitions = @()
    if ($Configuration.PSObject.Properties.Name -contains 'authenticationPolicySilos' -and $Configuration.authenticationPolicySilos) {
        $siloDefinitions = @($Configuration.authenticationPolicySilos)
    }
    elseif ($Configuration.PSObject.Properties.Name -contains 'authenticationPolicySilo' -and $Configuration.authenticationPolicySilo) {
        $siloDefinitions = @($Configuration.authenticationPolicySilo)
    }
    if ($siloDefinitions.Count -eq 0) { return }

    Write-TierLog -Message 'Authentication policy silos' -Level Header

    foreach ($siloDef in $siloDefinitions) {
        New-TierSingleAuthenticationSilo -Configuration $Configuration -SiloDefinition $siloDef -AuditOnly:$AuditOnly -Confirm:$false
    }
}

function New-TierSingleAuthenticationSilo {
    <#
        .SYNOPSIS
        Creates one authentication policy and its silo, then synchronises the membership.

        .DESCRIPTION
        Membership synchronisation runs on every invocation, not only at first deployment. A
        server moved into the tier next month has to end up in the silo as well, and nothing else
        does that automatically.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][object]$SiloDefinition,
        [switch]$AuditOnly
    )

    $ctx = Get-TierContext
    $ad = Get-TierAdParameter
    $siloDef = $SiloDefinition
    $enforce = ($Configuration.options.authenticationPolicyEnforcement -eq 'Enforce')
    $tgtLifetime = [int]$Configuration.options.tier0TgtLifetimeMinutes

    $mode = if ($enforce) { 'ENFORCED' } else { 'audit only' }
    Write-TierLog -Message "Silo enforcement mode: $mode" -Level $(if ($enforce) { 'Warning' } else { 'Info' })

    # --- policy ---------------------------------------------------------------------------
    # The silo condition on its own depends on every domain controller having been assigned to
    # the silo. A controller promoted later would not be, and the accounts in the silo would lose
    # the ability to authenticate against it. SID(ED) is the well known Enterprise Domain
    # Controllers identity, so controllers are covered whether or not the sync has run yet.
    $condition = '(@USER.ad://ext/AuthenticationSilo == "{0}")' -f $siloDef.name
    if ($siloDef.includeDomainControllers) {
        $condition = '((Member_of {SID(ED)}) || ' + $condition + ')'
    }
    $sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;' + $condition + ')'
    $policy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($siloDef.policyName)'" @ad -ErrorAction SilentlyContinue

    if (-not $policy) {
        if ($AuditOnly) {
            Write-TierLog -Message "Authentication policy missing: $($siloDef.policyName)" -Level Warning
            Add-TierAction -Phase 'Silo' -ObjectType 'AuthenticationPolicy' -Target $siloDef.policyName -Result 'Missing'
        }
        elseif ($PSCmdlet.ShouldProcess($siloDef.policyName, 'Create authentication policy')) {
            try {
                New-ADAuthenticationPolicy -Name $siloDef.policyName -Description $siloDef.description `
                    -UserTGTLifetimeMins $tgtLifetime -UserAllowedToAuthenticateFrom $sddl `
                    -Enforce:$enforce -ProtectedFromAccidentalDeletion $true @ad -ErrorAction Stop
                Write-TierLog -Message "Authentication policy created: $($siloDef.policyName)" -Level Success
                Add-TierAction -Phase 'Silo' -ObjectType 'AuthenticationPolicy' -Target $siloDef.policyName -Result 'Created'
                $policy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($siloDef.policyName)'" @ad
            }
            catch {
                Write-TierLog -Message "Authentication policy failed - $($_.Exception.Message)" -Level Error
                Add-TierAction -Phase 'Silo' -ObjectType 'AuthenticationPolicy' -Target $siloDef.policyName -Result 'Failed' -Detail $_.Exception.Message
                return
            }
        }
    }
    else {
        Write-TierLog -Message "Authentication policy exists: $($siloDef.policyName)" -Level Skip
        Add-TierAction -Phase 'Silo' -ObjectType 'AuthenticationPolicy' -Target $siloDef.policyName -Result 'Compliant'
    }

    # --- silo -----------------------------------------------------------------------------
    $silo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$($siloDef.name)'" @ad -ErrorAction SilentlyContinue

    if (-not $silo) {
        if ($AuditOnly) {
            Write-TierLog -Message "Authentication policy silo missing: $($siloDef.name)" -Level Warning
            Add-TierAction -Phase 'Silo' -ObjectType 'AuthenticationPolicySilo' -Target $siloDef.name -Result 'Missing'
            return
        }
        if ($PSCmdlet.ShouldProcess($siloDef.name, 'Create authentication policy silo')) {
            try {
                New-ADAuthenticationPolicySilo -Name $siloDef.name -Description $siloDef.description `
                    -UserAuthenticationPolicy $siloDef.policyName -ComputerAuthenticationPolicy $siloDef.policyName `
                    -ServiceAuthenticationPolicy $siloDef.policyName -Enforce:$enforce `
                    -ProtectedFromAccidentalDeletion $true @ad -ErrorAction Stop
                Write-TierLog -Message "Silo created: $($siloDef.name)" -Level Success
                Add-TierAction -Phase 'Silo' -ObjectType 'AuthenticationPolicySilo' -Target $siloDef.name -Result 'Created'
                $silo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$($siloDef.name)'" @ad
            }
            catch {
                Write-TierLog -Message "Silo creation failed - $($_.Exception.Message)" -Level Error
                Add-TierAction -Phase 'Silo' -ObjectType 'AuthenticationPolicySilo' -Target $siloDef.name -Result 'Failed' -Detail $_.Exception.Message
                return
            }
        }
    }
    else {
        Write-TierLog -Message "Silo exists: $($siloDef.name)" -Level Skip
        Add-TierAction -Phase 'Silo' -ObjectType 'AuthenticationPolicySilo' -Target $siloDef.name -Result 'Compliant'
    }

    if (-not $silo -or $AuditOnly) { return }

    # --- members --------------------------------------------------------------------------
    $members = [System.Collections.Generic.List[object]]::new()

    foreach ($groupName in @($siloDef.memberGroups)) {
        $group = Get-ADGroup -LDAPFilter "(sAMAccountName=$groupName)" @ad -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $group) { continue }
        Get-ADGroupMember -Identity $group.DistinguishedName -Recursive @ad -ErrorAction SilentlyContinue |
            Where-Object { $_.objectClass -eq 'user' } |
            ForEach-Object { $members.Add((Get-ADUser -Identity $_.distinguishedName @ad)) }
    }

    foreach ($ouRef in @($siloDef.memberComputerOus)) {
        $dn = Resolve-TierOuDn -Reference $ouRef
        if (-not (Test-Path -LiteralPath "AD:\$dn")) { continue }
        Get-ADComputer -Filter * -SearchBase $dn @ad -ErrorAction SilentlyContinue |
            ForEach-Object { $members.Add($_) }
    }

    if ($siloDef.includeDomainControllers) {
        Get-ADComputer -Filter * -SearchBase $ctx.DomainControllersDn @ad -ErrorAction SilentlyContinue |
            ForEach-Object { $members.Add($_) }
    }

    $assigned = 0
    $already = 0

    foreach ($member in $members) {
        if (-not $member) { continue }

        try {
            # Already in the silo? Then there is nothing to do - re-granting on every run turns
            # a routine sync into a wall of noise and hides the objects that actually changed.
            $existingAssignment = $null
            try { $existingAssignment = Get-ADObject -Identity $member.DistinguishedName -Properties 'msDS-AssignedAuthNPolicySilo' @ad -ErrorAction Stop }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $existingAssignment = $null }
            if ($existingAssignment -and $existingAssignment.'msDS-AssignedAuthNPolicySilo' -like "CN=$($siloDef.name),*") {
                $already++
                Add-TierAction -Phase 'Silo' -ObjectType 'SiloMember' -Target $member.SamAccountName -Result 'Compliant' -Detail $siloDef.name
                continue
            }

            if ($PSCmdlet.ShouldProcess($member.SamAccountName, "Assign to silo $($siloDef.name)")) {
                Grant-ADAuthenticationPolicySiloAccess -Identity $siloDef.name -Account $member.DistinguishedName @ad -ErrorAction SilentlyContinue
                Set-ADAccountAuthenticationPolicySilo -Identity $member.DistinguishedName -AuthenticationPolicySilo $siloDef.name @ad -ErrorAction Stop
                Write-TierLog -Message "Silo member assigned: $($member.SamAccountName)" -Level Success
                Add-TierAction -Phase 'Silo' -ObjectType 'SiloMember' -Target $member.SamAccountName -Result 'Created' -Detail $siloDef.name
                $assigned++
            }
        }
        catch {
            Write-TierLog -Message "Silo assignment failed for $($member.SamAccountName) - $($_.Exception.Message)" -Level Warning
            Add-TierAction -Phase 'Silo' -ObjectType 'SiloMember' -Target $member.SamAccountName -Result 'Failed' -Detail $_.Exception.Message
        }
    }

    Write-TierLog -Message "$($siloDef.name): $assigned newly assigned, $already already in place" -Level Info
}

#endregion DeploymentStages

####################################################################################################
#region Orchestration
#  Deployment and audit runners plus JSON/HTML reporting.
####################################################################################################

function Invoke-TierModelDeployment {
    <#
        .SYNOPSIS
        Deploys the complete Active Directory tier model described by a JSON configuration.

        .DESCRIPTION
        Runs all deployment stages in dependency order. Every stage is idempotent, so the
        function can be re-run at any time to converge the directory back to the configured
        state. Use -WhatIf for a dry run.

        .PARAMETER ConfigurationPath
        Path to the JSON configuration file.

        .PARAMETER Stage
        Limits the run to the given stages. Default is all stages.

        .PARAMETER Server
        Domain controller to target. Defaults to the PDC emulator.

        .EXAMPLE
        Invoke-TierModelDeployment -ConfigurationPath .\config\tiermodel.json -WhatIf

        .EXAMPLE
        Invoke-TierModelDeployment -ConfigurationPath .\config\tiermodel.json -Stage OU,Group,Nesting
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$ConfigurationPath,
        [ValidateSet('RecycleBin', 'OU', 'Domain', 'Group', 'Nesting', 'Account', 'Delegation', 'Ownership', 'PrivilegedGroups', 'Auditing', 'GPO', 'Laps', 'KDS', 'Silo')]
        [string[]]$Stage = @('RecycleBin', 'OU', 'Domain', 'Group', 'Nesting', 'Account', 'Delegation', 'Ownership', 'PrivilegedGroups', 'Auditing', 'GPO', 'Laps', 'KDS', 'Silo'),
        [string]$Server,
        [string]$LogDirectory = (Join-Path (Get-Location) 'Logs'),
        [string]$ReportDirectory = (Join-Path (Get-Location) 'Reports'),
        [string]$CredentialDirectory = (Join-Path (Get-Location) 'Credentials'),
        [switch]$SkipPrerequisiteCheck,
        [switch]$NoEventLog,
        [switch]$Force
    )

    $started = Get-Date
    Initialize-TierLog -LogDirectory $LogDirectory | Out-Null

    Write-TierLog -Message 'ADTierKit deployment' -Level Header
    $config = Import-TierConfiguration -Path $ConfigurationPath
    Initialize-TierContext -Configuration $config -Server $Server | Out-Null

    if (-not $SkipPrerequisiteCheck) {
        $prereq = Test-TierModelPrerequisite
        if (-not $prereq.Passed -and -not $Force) {
            throw 'Prerequisite check failed. Resolve the findings above or re-run with -Force.'
        }
    }

    if (-not $WhatIfPreference -and -not $Force) {
        Write-TierLog -Message 'This run will modify Active Directory. Review the plan with -WhatIf first.' -Level Warning
    }

    if ($Stage -contains 'RecycleBin') { Enable-TierRecycleBin  -Configuration $config -Confirm:$false }
    if ($Stage -contains 'OU')         { New-TierOuStructure    -Configuration $config -Confirm:$false }
    if ($Stage -contains 'Domain')     { Set-TierDomainHardening -Configuration $config -Confirm:$false }
    if ($Stage -contains 'Group')      { New-TierGroupSet       -Configuration $config -Confirm:$false }
    if ($Stage -contains 'Nesting')    { Set-TierGroupNesting   -Configuration $config -Confirm:$false }
    if ($Stage -contains 'Account')    { New-TierAdminAccountSet -Configuration $config -CredentialDirectory $CredentialDirectory -Confirm:$false }
    if ($Stage -contains 'Delegation') { Set-TierDelegationSet  -Configuration $config -Confirm:$false }
    if ($Stage -contains 'Ownership')  { Set-TierObjectOwnership -Configuration $config -Confirm:$false }
    if ($Stage -contains 'PrivilegedGroups') { Set-TierPrivilegedGroupMembership -Configuration $config -Confirm:$false }
    if ($Stage -contains 'Auditing')   { Set-TierAuditPolicy    -Configuration $config -Confirm:$false }
    if ($Stage -contains 'GPO')        { New-TierGpoSet         -Configuration $config -Force:$Force -Confirm:$false }
    if ($Stage -contains 'Laps')       { Set-TierWindowsLaps    -Configuration $config -Confirm:$false }
    if ($Stage -contains 'KDS')        { New-TierKdsRootKey     -Configuration $config -Confirm:$false }
    if ($Stage -contains 'Silo')       { New-TierAuthenticationSilo -Configuration $config -Confirm:$false }

    $actions = Get-TierActionLog
    $summary = [pscustomobject]@{
        Mode      = if ($WhatIfPreference) { 'WhatIf' } else { 'Apply' }
        Started   = $started
        Finished  = Get-Date
        Duration  = (New-TimeSpan -Start $started -End (Get-Date))
        Created   = @($actions | Where-Object Result -eq 'Created').Count
        Updated   = @($actions | Where-Object Result -eq 'Updated').Count
        Compliant = @($actions | Where-Object Result -eq 'Compliant').Count
        Planned   = @($actions | Where-Object Result -eq 'Planned').Count
        Missing   = @($actions | Where-Object Result -eq 'Missing').Count
        Failed    = @($actions | Where-Object Result -eq 'Failed').Count
        High      = @($actions | Where-Object Severity -eq 'High').Count
        Medium    = @($actions | Where-Object Severity -eq 'Medium').Count
        Low       = @($actions | Where-Object Severity -eq 'Low').Count
        Actions   = $actions
    }

    Write-TierLog -Message 'Summary' -Level Header
    if ($WhatIfPreference) {
        Write-TierLog -Message "Planned: $($summary.Planned) | Already compliant: $($summary.Compliant) | Failed: $($summary.Failed)" -Level Info
        Write-TierLog -Message 'Nothing was written. Re-run with -Apply to execute this plan.' -Level Info
    }
    else {
        Write-TierLog -Message "Created: $($summary.Created) | Updated: $($summary.Updated) | Already compliant: $($summary.Compliant) | Failed: $($summary.Failed)" -Level Info
    }
    Write-TierLog -Message "Findings by severity - high: $($summary.High) | medium: $($summary.Medium) | low: $($summary.Low)" -Level $(if ($summary.High -gt 0) { 'Error' } elseif ($summary.Medium -gt 0) { 'Warning' } else { 'Success' })

    $reportPath = New-TierModelReport -Summary $summary -OutputDirectory $ReportDirectory -Title 'ADTierKit Deployment Report'
    Write-TierLog -Message "Report: $reportPath" -Level Info
    Write-TierLog -Message "Log:    $script:TierLogFile" -Level Info

    if (-not $NoEventLog -and -not $WhatIfPreference) { Write-TierEventLog -Summary $summary }

    if ($summary.Failed -gt 0) {
        Write-TierLog -Message "$($summary.Failed) action(s) failed - review the report." -Level Warning
    }

    return $summary
}

function Invoke-TierModelSync {
    <#
        .SYNOPSIS
        Runs only the stages that maintain membership, so the model keeps up with the directory.

        .DESCRIPTION
        Deployment is a one-off; membership is not. A server moved into a tier OU next month has
        to end up in the authentication silo, and a group nested by hand has to be corrected.
        This mode covers exactly those stages and nothing else, which makes it safe to schedule.

        Structure, delegation, Group Policy and domain wide settings are untouched.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ConfigurationPath,
        [string]$Server,
        [string]$LogDirectory = (Join-Path (Get-Location) 'Logs'),
        [string]$ReportDirectory = (Join-Path (Get-Location) 'Reports'),
        [switch]$NoEventLog
    )

    $started = Get-Date
    Initialize-TierLog -LogDirectory $LogDirectory | Out-Null

    Write-TierLog -Message 'ADTierKit membership sync' -Level Header
    $config = Import-TierConfiguration -Path $ConfigurationPath
    Initialize-TierContext -Configuration $config -Server $Server | Out-Null

    Set-TierGroupNesting -Configuration $config -Confirm:$false
    New-TierAuthenticationSilo -Configuration $config -Confirm:$false
    # Ownership belongs here rather than only in deployment: a freshly deployed model has no
    # drifted owners at all, because the deployment account created everything. Drift appears the
    # first time a delegated administrator creates an object, which is a Tuesday, not a rollout.
    Set-TierObjectOwnership -Configuration $config -Confirm:$false
    Set-TierPrivilegedGroupMembership -Configuration $config -AuditOnly -Confirm:$false

    $actions = Get-TierActionLog
    $summary = [pscustomobject]@{
        Mode      = 'Sync'
        Started   = $started
        Finished  = Get-Date
        Duration  = (New-TimeSpan -Start $started -End (Get-Date))
        Created   = @($actions | Where-Object Result -eq 'Created').Count
        Updated   = @($actions | Where-Object Result -eq 'Updated').Count
        Compliant = @($actions | Where-Object Result -eq 'Compliant').Count
        Planned   = @($actions | Where-Object Result -eq 'Planned').Count
        Missing   = @($actions | Where-Object { $_.Result -in @('Missing', 'Drift') }).Count
        Failed    = @($actions | Where-Object Result -eq 'Failed').Count
        High      = @($actions | Where-Object Severity -eq 'High').Count
        Medium    = @($actions | Where-Object Severity -eq 'Medium').Count
        Low       = @($actions | Where-Object Severity -eq 'Low').Count
        Actions   = $actions
    }

    Write-TierLog -Message 'Sync summary' -Level Header
    Write-TierLog -Message "Assigned: $($summary.Created) | Already in place: $($summary.Compliant) | Failed: $($summary.Failed)" -Level Info

    $reportPath = New-TierModelReport -Summary $summary -OutputDirectory $ReportDirectory -Title 'ADTierKit Sync Report'
    Write-TierLog -Message "Report: $reportPath" -Level Info

    if (-not $NoEventLog -and -not $WhatIfPreference) { Write-TierEventLog -Summary $summary }

    return $summary
}

function Get-TierUntrustedPathWriter {
    <#
        .SYNOPSIS
        Lists principals outside the administrative set that can modify a file or directory.

        .DESCRIPTION
        The scheduled task runs whatever sits at the script and configuration path as SYSTEM on
        a domain controller. Anyone who can write to those files - or to the directories that
        contain them, because a writable parent means the file can be swapped - therefore owns
        the domain at 03:30 the next morning. This check finds exactly those principals.

        Trusted by definition: SYSTEM, the built-in Administrators, TrustedInstaller, and the
        Domain/Enterprise Admins RIDs of any domain SID. Everything else holding a write-capable
        allow ACE, or owning the object outright (an owner can rewrite the DACL), is reported.

        Deny ACEs are ignored, so a principal that is allowed and denied at the same time is
        still reported - a false positive in the safe direction.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Path)

    $trustedSids = @(
        'S-1-5-18',                                                          # SYSTEM
        'S-1-5-32-544',                                                      # BUILTIN\Administrators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'     # TrustedInstaller
    )

    # Write-capable in the sense of 'can change what the task executes': content, deletion
    # (replace after delete), the DACL itself, or ownership.
    $writeMask = [System.Security.AccessControl.FileSystemRights](
        [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership)

    $isTrusted = {
        param([System.Security.Principal.SecurityIdentifier]$Sid)
        if ($trustedSids -contains $Sid.Value) { return $true }
        # Domain Admins (-512) and Enterprise Admins (-519) of whatever domain the file came
        # from - matched by RID so this works for member servers of a child domain as well.
        if ($Sid.Value -match '^S-1-5-21-\d+-\d+-\d+-(512|519)$') { return $true }
        return $false
    }

    $findings = [System.Collections.Generic.List[string]]::new()

    foreach ($item in ($Path | Sort-Object -Unique)) {
        try {
            $acl = Get-Acl -LiteralPath $item -ErrorAction Stop
        }
        catch {
            $findings.Add("$item : ACL could not be read - $($_.Exception.Message)")
            continue
        }

        $owner = $null
        try { $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]) } catch { }
        if ($owner -and -not (& $isTrusted $owner)) {
            $ownerName = try { $acl.Owner } catch { $owner.Value }
            $findings.Add("$item : owned by $ownerName - the owner can rewrite the permissions")
        }

        foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if (($ace.FileSystemRights -band $writeMask) -eq 0) { continue }
            if (& $isTrusted $ace.IdentityReference) { continue }

            $name = $ace.IdentityReference.Value
            try { $name = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { }
            $findings.Add("$item : $name holds $($ace.FileSystemRights)")
        }
    }

    return $findings.ToArray()
}

function Install-TierModelScheduledTask {
    <#
        .SYNOPSIS
        Registers a daily scheduled task that runs the membership sync.

        .DESCRIPTION
        Without this the silo membership is only ever as current as the last manual run. The task
        runs as SYSTEM on a domain controller, which already has the rights it needs, and writes
        its result into the event log like every other run.

        Before registering, the ACLs of the script, the configuration and their directories are
        checked: nobody outside SYSTEM, Administrators, TrustedInstaller and the Domain and
        Enterprise Admins may be able to modify them. A tier model whose sync script is writable
        by a Tier 1 operator is a privilege escalation to SYSTEM on a domain controller with a
        daily trigger. -SkipAclCheck bypasses the check for environments that accept the risk.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$ConfigurationPath,
        [string]$TaskName = 'ADTierKit Membership Sync',
        [string]$TaskPath = '\ADTierKit\',
        [string]$At = '03:30',
        [switch]$SkipAclCheck
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) { throw "Script not found: $ScriptPath" }
    if (-not (Test-Path -LiteralPath $ConfigurationPath)) { throw "Configuration not found: $ConfigurationPath" }

    $scriptFull = (Resolve-Path -LiteralPath $ScriptPath).Path
    $configFull = (Resolve-Path -LiteralPath $ConfigurationPath).Path

    if (-not $SkipAclCheck) {
        $checkedPaths = @(
            $scriptFull, $configFull,
            (Split-Path $scriptFull -Parent), (Split-Path $configFull -Parent)
        )
        $writers = Get-TierUntrustedPathWriter -Path $checkedPaths

        if ($writers.Count -gt 0) {
            foreach ($writer in $writers) {
                Write-TierLog -Message "Scheduled task refused: $writer" -Level Error
            }
            throw ("The sync task would run these files as SYSTEM on a domain controller, but they are modifiable " +
                "by principals outside the administrative set (see above). Move ADTierKit to a directory only " +
                "administrators can write to - for example under Program Files - and register the task again, " +
                "or pass -SkipAclCheck to accept the risk deliberately.")
        }

        Write-TierLog -Message 'Script and configuration paths are writable only by the administrative set' -Level Info
    }
    else {
        Write-TierLog -Message 'ACL check on the script and configuration paths was skipped (-SkipAclCheck)' -Level Warning
    }

    # Log and report directories are passed explicitly. Under SYSTEM the working directory is
    # not the script folder, and a run whose output lands in C:\Windows\System32 is a run nobody
    # finds afterwards.
    $rootFull = Split-Path $scriptFull -Parent
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode Sync -ConfigurationPath "{1}" -LogDirectory "{2}" -ReportDirectory "{3}"' -f `
        $scriptFull, $configFull, (Join-Path $rootFull 'Logs'), (Join-Path $rootFull 'Reports')

    $existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($existing) {
        Write-TierLog -Message "Scheduled task '$TaskName' already exists - it will be replaced" -Level Info
    }

    if (-not $PSCmdlet.ShouldProcess($TaskName, "Register daily membership sync at $At")) { return }

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments -WorkingDirectory (Split-Path $scriptFull -Parent)
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 2)

    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Keeps tier group nesting and authentication silo membership in sync with the OU structure.' -Force | Out-Null

    Write-TierLog -Message "Scheduled task '$TaskPath$TaskName' registered, runs daily at $At as SYSTEM" -Level Success
}

function Invoke-TierModelAudit {
    <#
        .SYNOPSIS
        Compares the live directory against the configuration and reports drift. Read only.

        .EXAMPLE
        Invoke-TierModelAudit -ConfigurationPath .\config\tiermodel.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigurationPath,
        [string]$Server,
        [string]$LogDirectory = (Join-Path (Get-Location) 'Logs'),
        [string]$ReportDirectory = (Join-Path (Get-Location) 'Reports'),
        [switch]$NoEventLog
    )

    $started = Get-Date
    Initialize-TierLog -LogDirectory $LogDirectory | Out-Null

    Write-TierLog -Message 'ADTierKit audit (read only)' -Level Header
    $config = Import-TierConfiguration -Path $ConfigurationPath
    Initialize-TierContext -Configuration $config -Server $Server | Out-Null

    Enable-TierRecycleBin      -Configuration $config -AuditOnly -Confirm:$false
    New-TierOuStructure        -Configuration $config -AuditOnly -Confirm:$false
    Set-TierDomainHardening    -Configuration $config -AuditOnly -Confirm:$false
    New-TierGroupSet           -Configuration $config -AuditOnly -Confirm:$false
    Set-TierGroupNesting       -Configuration $config -AuditOnly -Confirm:$false
    New-TierAdminAccountSet    -Configuration $config -AuditOnly -Confirm:$false
    Set-TierDelegationSet      -Configuration $config -AuditOnly -Confirm:$false
    Set-TierObjectOwnership    -Configuration $config -AuditOnly -Confirm:$false
    Set-TierPrivilegedGroupMembership -Configuration $config -AuditOnly -Confirm:$false
    Set-TierAuditPolicy        -Configuration $config -AuditOnly -Confirm:$false
    New-TierGpoSet             -Configuration $config -AuditOnly -Confirm:$false
    Set-TierWindowsLaps        -Configuration $config -AuditOnly -Confirm:$false
    New-TierKdsRootKey         -Configuration $config -AuditOnly -Confirm:$false
    New-TierAuthenticationSilo -Configuration $config -AuditOnly -Confirm:$false

    try {
        Test-TierLogonRightImpact -Configuration $config
        Test-TierModelIsolation -Configuration $config
    }
    catch {
        Write-TierLog -Message "Isolation checks could not be completed - $($_.Exception.Message)" -Level Error
        Add-TierAction -Phase 'Isolation' -ObjectType 'IsolationCheck' -Target 'Domain' -Result 'Failed' -Detail $_.Exception.Message
    }

    $actions = Get-TierActionLog
    $summary = [pscustomobject]@{
        Mode      = 'Audit'
        Started   = $started
        Finished  = Get-Date
        Duration  = (New-TimeSpan -Start $started -End (Get-Date))
        Created   = 0
        Updated   = 0
        Compliant = @($actions | Where-Object Result -eq 'Compliant').Count
        Planned   = @($actions | Where-Object Result -eq 'Planned').Count
        Missing   = @($actions | Where-Object { $_.Result -in @('Missing', 'Drift') }).Count
        Failed    = @($actions | Where-Object Result -eq 'Failed').Count
        High      = @($actions | Where-Object Severity -eq 'High').Count
        Medium    = @($actions | Where-Object Severity -eq 'Medium').Count
        Low       = @($actions | Where-Object Severity -eq 'Low').Count
        Actions   = $actions
    }

    Write-TierLog -Message 'Audit summary' -Level Header
    Write-TierLog -Message "Compliant: $($summary.Compliant) | Missing or drifted: $($summary.Missing) | Errors: $($summary.Failed)" -Level Info
    Write-TierLog -Message "Findings by severity - high: $($summary.High) | medium: $($summary.Medium) | low: $($summary.Low)" -Level $(if ($summary.High -gt 0) { 'Error' } elseif ($summary.Medium -gt 0) { 'Warning' } else { 'Success' })

    if ($summary.High -gt 0) {
        Write-TierLog -Message 'High severity findings are listed first in the HTML report.' -Level Warning
    }

    $reportPath = New-TierModelReport -Summary $summary -OutputDirectory $ReportDirectory -Title 'ADTierKit Audit Report'
    Write-TierLog -Message "Report: $reportPath" -Level Info

    if (-not $NoEventLog) { Write-TierEventLog -Summary $summary }

    return $summary
}

function Test-TierLogonRightImpact {
    <#
        .SYNOPSIS
        Lists the accounts that an allow list would most likely lock out.

        .DESCRIPTION
        An allow list on SeServiceLogonRight or SeBatchLogonRight removes the right from every
        principal that is not named, and the failure shows up as a service that no longer starts
        after the next policy refresh - hours later, on a machine nobody was looking at.

        Active Directory cannot say which accounts run services on which host. What it can say is
        which accounts look like service accounts: they carry a service principal name, they are
        marked as not requiring a password change, or they sit in a service account OU. That list
        is the starting point for the allow list, not the finished article.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration)

    $usesAllowList = $false
    foreach ($tier in $Configuration.tiers) {
        foreach ($gpo in @($tier.gpos)) {
            if ($gpo.PSObject.Properties.Name -contains 'allowedUserRights' -and $gpo.allowedUserRights) { $usesAllowList = $true }
        }
    }
    if (-not $usesAllowList) { return }

    Write-TierLog -Message 'Allow list impact' -Level Header
    $ad = Get-TierAdParameter

    $serviceLike = @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(|(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=65536)))' `
            -Properties servicePrincipalName, description @ad -ErrorAction SilentlyContinue)

    if ($serviceLike.Count -eq 0) {
        Write-TierLog -Message 'No accounts with a service principal name or a non-expiring password found' -Level Success
        return
    }

    Write-TierLog -Message "$($serviceLike.Count) account(s) look like service accounts. If any of them runs a service or a scheduled task on a machine in scope, it needs to be in the allow list before you enforce it:" -Level Warning
    foreach ($account in ($serviceLike | Select-Object -First 25)) {
        Write-TierLog -Message "  $($account.SamAccountName)$(if ($account.description) { " - $($account.description)" })" -Level Info
    }
    if ($serviceLike.Count -gt 25) {
        Write-TierLog -Message "  ... and $($serviceLike.Count - 25) more" -Level Info
    }

    Add-TierAction -Phase 'Isolation' -ObjectType 'LogonRightImpact' -Target 'Domain' -Result 'Drift' `
        -Detail "$($serviceLike.Count) service-like accounts exist while allow lists are configured - verify each one" -Severity 'Medium'
}

function Test-TierModelIsolation {
    <#
        .SYNOPSIS
        Additional hygiene checks that are not derived from the configuration itself.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration)

    Write-TierLog -Message 'Tier isolation checks' -Level Header
    $ctx = Get-TierContext
    $ad = Get-TierAdParameter

    # 1. Privileged built-in groups should only contain Tier 0 principals.
    $tier0 = $Configuration.tiers | Where-Object { $_.id -eq 0 } | Select-Object -First 1
    $tier0Dn = "OU=$($tier0.name),$($ctx.RootOuDn)"

    # Looked up by SID, because the display names of these groups are localised.
    #   512 Domain Admins   519 Enterprise Admins   518 Schema Admins   526 Key Admins
    #   S-1-5-32-544 Administrators   -548 Account Operators   -551 Backup Operators
    #   S-1-5-32-549 Server Operators  -550 Print Operators
    $privilegedSids = @('512', '519', '518', '526', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-551', 'S-1-5-32-549', 'S-1-5-32-550')

    foreach ($sid in $privilegedSids) {
        $group = Get-TierWellKnownGroup -Sid $sid
        if (-not $group) { continue }
        $label = $group.Name

        $members = @(Get-ADGroupMember -Identity $group.DistinguishedName @ad -ErrorAction SilentlyContinue)
        $outside = @($members | Where-Object { $_.distinguishedName -notlike "*$tier0Dn" -and $_.distinguishedName -notlike "*CN=Users,$($ctx.DomainDn)" })

        if ($members.Count -eq 0) {
            Add-TierAction -Phase 'Isolation' -ObjectType 'PrivilegedGroup' -Target $label -Result 'Compliant' -Detail 'Empty'
            Write-TierLog -Message "$label is empty" -Level Success
        }
        elseif ($outside.Count -gt 0) {
            $names = ($outside | Select-Object -ExpandProperty name) -join ', '
            Add-TierAction -Phase 'Isolation' -ObjectType 'PrivilegedGroup' -Target $label -Result 'Drift' -Detail "Members outside the top tier: $names"
            Write-TierLog -Message "$label contains principals outside the top tier: $names" -Level Warning
        }
        else {
            Add-TierAction -Phase 'Isolation' -ObjectType 'PrivilegedGroup' -Target $label -Result 'Compliant' -Detail "$($members.Count) member(s), all top tier"
            Write-TierLog -Message "$label only contains top tier principals" -Level Success
        }
    }

    # 2. Computer objects still sitting in the default containers.
    # Each check gets its own try/catch: one failing query must not hide the results of the
    # others, and the message has to name the check that actually broke.
    foreach ($container in @("CN=Computers,$($ctx.DomainDn)")) {
        try {
            $stragglers = @(Get-ADComputer -Filter * -SearchBase $container @ad -ErrorAction Stop)
        }
        catch {
            Write-TierLog -Message "Default container check on $container failed - $($_.Exception.Message)" -Level Warning
            Add-TierAction -Phase 'Isolation' -ObjectType 'DefaultContainer' -Target $container -Result 'Failed' -Detail $_.Exception.Message
            continue
        }

        if ($stragglers.Count -gt 0) {
            Add-TierAction -Phase 'Isolation' -ObjectType 'DefaultContainer' -Target $container -Result 'Drift' -Detail "$($stragglers.Count) unclassified computer object(s)"
            Write-TierLog -Message "$($stragglers.Count) computer object(s) are still in $container and receive no tier policy" -Level Warning
        }
        else {
            Add-TierAction -Phase 'Isolation' -ObjectType 'DefaultContainer' -Target $container -Result 'Compliant'
        }
    }

    # 3. Accounts with unconstrained delegation are a Tier 0 escalation path.
    # Computers and users are queried separately: a computer object also carries objectClass=user
    # through inheritance, so a combined filter is redundant and harder to reason about.
    $unconstrained = [System.Collections.Generic.List[object]]::new()
    $isolationFailed = $false

    foreach ($query in @(
            @{ Cmd = 'Get-ADComputer'; Label = 'computer' },
            @{ Cmd = 'Get-ADUser'; Label = 'user' })) {
        try {
            $found = @(& $query.Cmd -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
                    -SearchBase $ctx.DomainDn @ad -ErrorAction Stop |
                    Where-Object { $_.DistinguishedName -notlike "*$($ctx.DomainControllersDn)" })
            foreach ($item in $found) { $unconstrained.Add($item) }
        }
        catch {
            $isolationFailed = $true
            Write-TierLog -Message "Unconstrained delegation check on $($query.Label) objects failed - $($_.Exception.Message)" -Level Warning
            Add-TierAction -Phase 'Isolation' -ObjectType 'UnconstrainedDelegation' -Target $query.Label -Result 'Failed' -Detail $_.Exception.Message
        }
    }

    if ($isolationFailed) { return }

    if ($unconstrained.Count -gt 0) {
        $names = ($unconstrained | Select-Object -ExpandProperty name) -join ', '
        Add-TierAction -Phase 'Isolation' -ObjectType 'UnconstrainedDelegation' -Target 'Domain' -Result 'Drift' -Detail $names
        Write-TierLog -Message "Unconstrained delegation found on: $names" -Level Warning
    }
    else {
        Add-TierAction -Phase 'Isolation' -ObjectType 'UnconstrainedDelegation' -Target 'Domain' -Result 'Compliant'
        Write-TierLog -Message 'No unconstrained delegation outside domain controllers' -Level Success
    }
}

function ConvertTo-TierHtmlText {
    [CmdletBinding()]
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Write-TierEventLog {
    <#
        .SYNOPSIS
        Writes the run result into the Windows Application event log of the machine it runs on.

        .DESCRIPTION
        A run leaves a log file and a report behind, but both live wherever the operator happened
        to unpack the tool. Writing to the event log means every change to the tier model is also
        visible to whatever already collects events from the domain controllers.

        Event IDs
          1000  run finished, nothing to report
          1001  run finished with medium severity findings
          1002  run finished with high severity findings or failures
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Summary,
        [string]$Source = 'ADTierKit',
        [string]$LogName = 'Application'
    )

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            New-EventLog -LogName $LogName -Source $Source -ErrorAction Stop
            Write-TierLog -Message "Event log source '$Source' registered in '$LogName'" -Level Info
        }
    }
    catch {
        Write-TierLog -Message "Could not register the event log source - $($_.Exception.Message)" -Level Warning
        return
    }

    $high = @($Summary.Actions | Where-Object Severity -eq 'High')
    $medium = @($Summary.Actions | Where-Object Severity -eq 'Medium')

    if ($high.Count -gt 0) { $eventId = 1002; $entryType = 'Error' }
    elseif ($medium.Count -gt 0) { $eventId = 1001; $entryType = 'Warning' }
    else { $eventId = 1000; $entryType = 'Information' }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("ADTierKit run finished in mode '$($Summary.Mode)'.")
    $lines.Add('')
    $lines.Add("Created: $($Summary.Created)  Updated: $($Summary.Updated)  Compliant: $($Summary.Compliant)")
    $lines.Add("High: $($high.Count)  Medium: $($medium.Count)  Failed: $($Summary.Failed)")
    $lines.Add("Duration: $([math]::Round($Summary.Duration.TotalSeconds, 1)) seconds")

    foreach ($finding in ($high + $medium | Select-Object -First 25)) {
        $lines.Add('')
        $lines.Add("[$($finding.Severity)] $($finding.Phase) / $($finding.ObjectType): $($finding.Target) - $($finding.Result)")
        if ($finding.Detail) { $lines.Add("        $($finding.Detail)") }
    }

    if (($high.Count + $medium.Count) -gt 25) {
        $lines.Add('')
        $lines.Add('Output truncated - see the HTML report for the complete list.')
    }

    $message = ($lines -join [Environment]::NewLine)
    # The event log rejects messages beyond roughly 32 KB.
    if ($message.Length -gt 30000) { $message = $message.Substring(0, 30000) + '...' }

    try {
        Write-EventLog -LogName $LogName -Source $Source -EventId $eventId -EntryType $entryType -Message $message -ErrorAction Stop
        Write-TierLog -Message "Result written to the $LogName event log (event ID $eventId)" -Level Info
    }
    catch {
        Write-TierLog -Message "Could not write to the event log - $($_.Exception.Message)" -Level Warning
    }
}

function New-TierModelReport {
    <#
        .SYNOPSIS
        Writes the action log as JSON and as a self-contained HTML report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [string]$Title = 'ADTierKit Report'
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath = Join-Path $OutputDirectory "ADTierKit-$($Summary.Mode)-$stamp.json"
    $htmlPath = Join-Path $OutputDirectory "ADTierKit-$($Summary.Mode)-$stamp.html"

    $Summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 -WhatIf:$false -Confirm:$false

    # Highest severity first so the report can be triaged from the top.
    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $sorted = $Summary.Actions | Sort-Object @{ Expression = { $order[[string]$_.Severity] } }, Phase, Target

    $rows = foreach ($action in $sorted) {
        $class = switch ([string]$action.Severity) {
            'High' { 'sev-high' }
            'Medium' { 'sev-medium' }
            'Low' { 'sev-low' }
            default { 'sev-info' }
        }
        '<tr class="{0}"><td class="sev">{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f `
            $class,
        (ConvertTo-TierHtmlText ([string]$action.Severity)),
        (ConvertTo-TierHtmlText ($action.Phase)),
        (ConvertTo-TierHtmlText ($action.ObjectType)),
        (ConvertTo-TierHtmlText ($action.Target)),
        (ConvertTo-TierHtmlText ($action.Result)),
        (ConvertTo-TierHtmlText ([string]$action.Detail))
    }

    $modeBadge = switch ($Summary.Mode) {
        'Apply' { 'apply' }
        'WhatIf' { 'plan' }
        default { 'read' }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$Title</title>
<style>
 :root{
  --bg:#f6f7f9; --panel:#fff; --line:#e3e6ea; --ink:#1b1e21; --muted:#6b7480;
  --high:#b3261e; --high-bg:#fdeceb; --med:#8a5a00; --med-bg:#fff6e6;
  --low:#0b5cad; --low-bg:#eaf2fb; --ok:#146c2e; --info:#8b929b;
 }
 @media (prefers-color-scheme:dark){
  :root{ --bg:#15181c; --panel:#1c2026; --line:#2b313a; --ink:#e6e9ed; --muted:#9aa3ad;
         --high-bg:#3a1f1d; --med-bg:#3a2f1a; --low-bg:#16283c; }
 }
 *{box-sizing:border-box}
 body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:2rem 2.5rem;
      background:var(--bg);color:var(--ink)}
 header{display:flex;align-items:baseline;gap:.75rem;flex-wrap:wrap;margin-bottom:.35rem}
 h1{font-size:1.35rem;margin:0;font-weight:650;letter-spacing:-.01em}
 .badge{font-size:.7rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
        padding:.2rem .5rem;border-radius:4px;background:var(--low-bg);color:var(--low)}
 .badge.apply{background:var(--high-bg);color:var(--high)}
 .badge.plan{background:var(--med-bg);color:var(--med)}
 .meta{color:var(--muted);font-size:.82rem;margin-bottom:1.4rem}
 .cards{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1.1rem}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
       padding:.6rem .9rem;min-width:104px;cursor:pointer;transition:border-color .12s,transform .12s}
 .card:hover{transform:translateY(-1px)}
 .card[aria-pressed=true]{border-color:currentColor;box-shadow:inset 0 0 0 1px currentColor}
 .card .lbl{display:block;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
 .card b{display:block;font-size:1.5rem;font-weight:650;line-height:1.25}
 .card.high{color:var(--high)} .card.medium{color:var(--med)} .card.low{color:var(--low)} .card.ok{color:var(--ok)}
 .toolbar{display:flex;gap:.6rem;align-items:center;margin-bottom:.7rem;flex-wrap:wrap}
 input[type=search]{flex:1;min-width:220px;padding:.5rem .7rem;border:1px solid var(--line);
                    border-radius:7px;background:var(--panel);color:var(--ink);font-size:.86rem}
 .count{color:var(--muted);font-size:.8rem}
 .wrap{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
 table{border-collapse:collapse;width:100%;font-size:.84rem}
 th{position:sticky;top:0;background:var(--panel);text-align:left;font-weight:600;font-size:.75rem;
    text-transform:uppercase;letter-spacing:.04em;color:var(--muted);
    padding:.6rem .8rem;border-bottom:1px solid var(--line);z-index:1}
 td{padding:.5rem .8rem;border-bottom:1px solid var(--line);vertical-align:top}
 tr:last-child td{border-bottom:none}
 tbody tr:hover{background:var(--bg)}
 .pill{display:inline-block;font-size:.7rem;font-weight:700;padding:.12rem .45rem;border-radius:4px;white-space:nowrap}
 .sev-high .pill{background:var(--high-bg);color:var(--high)}
 .sev-medium .pill{background:var(--med-bg);color:var(--med)}
 .sev-low .pill{background:var(--low-bg);color:var(--low)}
 .sev-info .pill{background:transparent;color:var(--info)}
 .target{font-family:ui-monospace,Consolas,monospace;font-size:.79rem;word-break:break-all}
 .detail{color:var(--muted)}
 .empty{padding:2rem;text-align:center;color:var(--muted)}
 footer{margin-top:1.2rem;color:var(--muted);font-size:.76rem}
</style></head><body>

<header>
 <h1>$Title</h1>
 <span class="badge $modeBadge">$($Summary.Mode)</span>
</header>
<div class="meta">$($Summary.Started) &middot; $([math]::Round($Summary.Duration.TotalSeconds,1)) seconds &middot; $($Summary.Actions.Count) actions</div>

<div class="cards" id="cards">
 <button class="card ok"     data-filter="all"    aria-pressed="true"><span class="lbl">All</span><b>$($Summary.Actions.Count)</b></button>
 <button class="card high"   data-filter="high"   aria-pressed="false"><span class="lbl">High</span><b>$($Summary.High)</b></button>
 <button class="card medium" data-filter="medium" aria-pressed="false"><span class="lbl">Medium</span><b>$($Summary.Medium)</b></button>
 <button class="card low"    data-filter="low"    aria-pressed="false"><span class="lbl">Low</span><b>$($Summary.Low)</b></button>
 <div class="card" style="cursor:default"><span class="lbl">Planned</span><b>$($Summary.Planned)</b></div>
 <div class="card" style="cursor:default"><span class="lbl">Created</span><b>$($Summary.Created)</b></div>
 <div class="card" style="cursor:default"><span class="lbl">Updated</span><b>$($Summary.Updated)</b></div>
 <div class="card" style="cursor:default"><span class="lbl">Compliant</span><b>$($Summary.Compliant)</b></div>
 <div class="card" style="cursor:default"><span class="lbl">Failed</span><b>$($Summary.Failed)</b></div>
</div>

<div class="toolbar">
 <input type="search" id="q" placeholder="Filter by phase, object, target or detail...">
 <span class="count" id="count"></span>
</div>

<div class="wrap">
<table>
<thead><tr><th>Severity</th><th>Phase</th><th>Object type</th><th>Target</th><th>Result</th><th>Detail</th></tr></thead>
<tbody id="rows">
$($rows -join "`n")
</tbody></table>
<div class="empty" id="empty" hidden>Nothing matches the current filter.</div>
</div>

<footer>Generated by ADTierKit. The JSON next to this file carries the same data for pipelines.</footer>

<script>
(function () {
  var rows = Array.prototype.slice.call(document.querySelectorAll('#rows tr'));
  var search = document.getElementById('q');
  var counter = document.getElementById('count');
  var empty = document.getElementById('empty');
  var buttons = Array.prototype.slice.call(document.querySelectorAll('.card[data-filter]'));
  var severity = 'all';

  function apply() {
    var needle = search.value.toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {
      var bySeverity = severity === 'all' || row.className.indexOf('sev-' + severity) > -1;
      var byText = needle === '' || row.textContent.toLowerCase().indexOf(needle) > -1;
      var visible = bySeverity && byText;
      row.hidden = !visible;
      if (visible) { shown++; }
    });
    counter.textContent = shown + ' of ' + rows.length + ' shown';
    empty.hidden = shown !== 0;
  }

  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      severity = button.getAttribute('data-filter');
      buttons.forEach(function (other) {
        other.setAttribute('aria-pressed', other === button ? 'true' : 'false');
      });
      apply();
    });
  });

  search.addEventListener('input', apply);
  apply();
})();
</script>
</body></html>
"@

    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8 -WhatIf:$false -Confirm:$false
    return $htmlPath
}

#endregion Orchestration

####################################################################################################
#region Wizard
#  Interactive rollout: naming questions, preview, configuration file, deployment.
####################################################################################################

function Start-TierModelWizard {
    <#
        .SYNOPSIS
        Interactive rollout wizard. Asks for the naming convention, previews the resulting
        objects, writes the configuration file and optionally starts the deployment.

        .PARAMETER ConfigurationPath
        Where the generated configuration is written.

        .PARAMETER UseDefaults
        Accept every default without prompting. Useful for a first look or for lab builds.

        .EXAMPLE
        Start-TierModelWizard

        .EXAMPLE
        Start-TierModelWizard -ConfigurationPath D:\tiermodel\config\contoso.json
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigurationPath = (Join-Path (Get-Location) 'config\tiermodel.json'),
        [switch]$UseDefaults
    )

    Set-TierPromptMode -UseDefaults:$UseDefaults

    Write-Host ''
    Write-Host '  ADTierKit - tier model rollout wizard' -ForegroundColor Cyan
    Write-Host '  Press Enter to accept the value shown as "Default".' -ForegroundColor DarkGray

    # =====================================================================================
    Write-TierPromptHeader -Title '1 / 8  Domain and root container' `
        -Description 'Where the tier model is anchored in the directory.'

    # Auto-detection is a convenience only: the wizard asks for the domain either way, so a
    # failure here is not worth reporting - the operator simply types the name.
    $detectedDomain = $null
    try { $detectedDomain = (Get-ADDomain -ErrorAction Stop).DNSRoot }
    catch { Write-Verbose "Domain auto-detection failed: $($_.Exception.Message)" }

    $domainFqdn = Read-TierText -Question 'Which domain should the model be deployed to?' `
        -Example 'contoso.com' `
        -Default $(if ($detectedDomain) { $detectedDomain } else { 'contoso.com' }) `
        -Hint 'Leave the detected value unless you are preparing a configuration for another domain.' `
        -ValidationPattern '^[A-Za-z0-9\.\-]+$' `
        -ValidationMessage 'Enter a DNS domain name.'

    $rootOu = Read-TierText -Question 'Name of the top level OU that contains the whole model?' `
        -Example "Tiering        ->  OU=Tiering,DC=$($domainFqdn.Replace('.', ',DC='))" `
        -Default 'Tiering' `
        -Hint 'Created directly below the domain root. Other common choices: Admin, _Tiering, Company.' `
        -ValidationPattern '^[A-Za-z0-9 _\-\.]+$' -MaxLength 64

    # =====================================================================================
    Write-TierPromptHeader -Title '2 / 8  Tier layout' `
        -Description 'How many tiers and how they are named.'

    $tierCountText = Read-TierChoice -Question 'How many tiers?' `
        -Options @('3', '2', '4') `
        -OptionDescriptions @('control plane / server plane / workstation plane (recommended)', 'control plane / everything else', 'extra plane for special environments') `
        -Default '3'
    $tierCount = [int]$tierCountText

    $tierNamePattern = Read-TierPattern -Question 'Naming pattern for the tier OUs?' `
        -Default 'Tier-{ID}' -SampleTokens @{ ID = '0' } `
        -Hint 'Placeholder {ID} is the tier number. Alternatives: Tier{ID}, T{ID}, Ebene-{ID}.' `
        -MaxLength 64

    $tierTokenPattern = Read-TierPattern -Question 'Short token used inside group, account and GPO names?' `
        -Default 'T{ID}' -SampleTokens @{ ID = '0' } `
        -Hint 'Keep this short - it appears in every object name. Alternatives: Tier{ID}, L{ID}.' `
        -MaxLength 12

    # =====================================================================================
    Write-TierPromptHeader -Title '3 / 8  Sub OU names' `
        -Description 'These OUs are created below every tier OU.'

    $sampleTier = Expand-TierName -Pattern $tierNamePattern -Tokens @{ ID = '0' }

    $accountsOu = Read-TierText -Question 'OU for administrative user accounts?' `
        -Example "Accounts        ->  OU=Accounts,OU=$sampleTier,OU=$rootOu,..." `
        -Default 'Accounts' -ValidationPattern '^[A-Za-z0-9 _\-\.]+$' -MaxLength 64

    $groupsOu = Read-TierText -Question 'OU for role and access groups?' `
        -Example "Groups          ->  OU=Groups,OU=$sampleTier,OU=$rootOu,..." `
        -Default 'Groups' -ValidationPattern '^[A-Za-z0-9 _\-\.]+$' -MaxLength 64

    $serversOu = Read-TierText -Question 'OU for servers?' `
        -Example "Servers         ->  OU=Servers,OU=$sampleTier,OU=$rootOu,..." `
        -Default 'Servers' -Hint 'Not created for the lowest tier, which holds workstations.' `
        -ValidationPattern '^[A-Za-z0-9 _\-\.]+$' -MaxLength 64

    $devicesOu = Read-TierText -Question 'OU for workstations and admin devices?' `
        -Example "Devices         ->  OU=Devices,OU=$sampleTier,OU=$rootOu,..." `
        -Default 'Devices' -ValidationPattern '^[A-Za-z0-9 _\-\.]+$' -MaxLength 64

    $serviceAccountsOu = Read-TierText -Question 'OU for service accounts, gMSA and dMSA?' `
        -Example "Service-Accounts -> OU=Service-Accounts,OU=$sampleTier,OU=$rootOu,..." `
        -Default 'Service-Accounts' -ValidationPattern '^[A-Za-z0-9 _\-\.]+$' -MaxLength 64

    $stagingOu = Read-TierText -Question 'OU used as landing zone for newly joined systems?' `
        -Example "Staging         ->  OU=Staging,OU=$sampleTier,OU=$rootOu,..." `
        -Default 'Staging' -Hint 'Newly joined machines land here until they are classified into a tier.' `
        -ValidationPattern '^[A-Za-z0-9 _\-\.]+$' -MaxLength 64

    # =====================================================================================
    Write-TierPromptHeader -Title '4 / 8  Group naming' `
        -Description 'Global role groups hold people, domain local access groups hold permissions.'

    $sampleToken = Expand-TierName -Pattern $tierTokenPattern -Tokens @{ ID = '0' }
    $groupSample = @{ ID = '0'; TIER = $sampleTier; TOKEN = $sampleToken; TOKENLC = $sampleToken.ToLower(); ROLE = 'Admins' }
    $accessSample = @{ ID = '0'; TIER = $sampleTier; TOKEN = $sampleToken; TOKENLC = $sampleToken.ToLower(); RESOURCE = 'DenyLogon' }

    $delegationModel = Read-TierChoice -Question 'How much control should a tier administrator have over their own branch?' `
        -Options @('Granular', 'FullControl') `
        -OptionDescriptions @(
        'everything except changing permissions and ownership (recommended)',
        'full control, including the ability to rewrite their own delegation'
    ) -Default 'Granular' `
        -Hint 'With Granular a tier administrator cannot widen the boundary that constrains them. FullControl is simpler but makes the delegation advisory rather than binding.'

    $roleGroupPattern = Read-TierPattern -Question 'Naming pattern for global role groups?' `
        -Default 'G-{TOKEN}-{ROLE}' -SampleTokens $groupSample `
        -Hint 'Alternatives: {TOKEN}-{ROLE}, GG_{TOKEN}_{ROLE}, ROLE-{TIER}-{ROLE}.' -MaxLength 64

    $accessGroupPattern = Read-TierPattern -Question 'Naming pattern for domain local access groups?' `
        -Default 'DL-{TOKEN}-{RESOURCE}' -SampleTokens $accessSample `
        -Hint 'Alternatives: {TOKEN}-{RESOURCE}, DLG_{TOKEN}_{RESOURCE}.' -MaxLength 64

    $adminRole = 'Admins'; $operatorRole = 'Operators'
    $localAdminsResource = 'LocalAdmins'; $rdpResource = 'RemoteDesktop'; $denyResource = 'DenyLogon'

    if (Read-TierBoolean -Question 'Customise the role and resource words as well?' `
            -Example 'no  ->  Admins, Operators, LocalAdmins, RemoteDesktop, DenyLogon' -Default $false) {

        $adminRole = Read-TierText -Question 'Word for the administrator role?' -Example 'Admins' -Default 'Admins' -ValidationPattern '^[A-Za-z0-9_\-]+$' -MaxLength 32
        $operatorRole = Read-TierText -Question 'Word for the operator role?' -Example 'Operators' -Default 'Operators' -ValidationPattern '^[A-Za-z0-9_\-]+$' -MaxLength 32
        $localAdminsResource = Read-TierText -Question 'Word for the local administrators access group?' -Example 'LocalAdmins' -Default 'LocalAdmins' -ValidationPattern '^[A-Za-z0-9_\-]+$' -MaxLength 32
        $rdpResource = Read-TierText -Question 'Word for the remote desktop access group?' -Example 'RemoteDesktop' -Default 'RemoteDesktop' -ValidationPattern '^[A-Za-z0-9_\-]+$' -MaxLength 32
        $denyResource = Read-TierText -Question 'Word for the deny logon group?' -Example 'DenyLogon' -Default 'DenyLogon' -ValidationPattern '^[A-Za-z0-9_\-]+$' -MaxLength 32
    }

    # =====================================================================================
    Write-TierPromptHeader -Title '5 / 8  Administrative accounts' `
        -Description 'Template and break glass accounts are created disabled with a random password.'

    $createAccounts = Read-TierBoolean -Question 'Create template and break glass accounts?' `
        -Example 'yes  ->  a disabled template account per tier plus one break glass account' -Default $true

    $accountSample = @{ ID = '0'; TIER = $sampleTier; TOKEN = $sampleToken; TOKENLC = $sampleToken.ToLower(); PURPOSE = 'template' }
    $adminAccountPattern = 'adm-{TOKENLC}-{PURPOSE}'

    if ($createAccounts) {
        $adminAccountPattern = Read-TierPattern -Question 'Naming pattern for administrative accounts?' `
            -Default 'adm-{TOKENLC}-{PURPOSE}' -SampleTokens $accountSample `
            -Hint 'Alternatives: a-{TOKENLC}-{PURPOSE}, {TOKENLC}_adm_{PURPOSE}. Maximum 20 characters when resolved.' `
            -MaxLength 20
    }

    $accountsDisabled = $true
    if ($createAccounts) {
        $accountsDisabled = Read-TierBoolean -Question 'Create these accounts in a disabled state?' `
            -Example 'yes  ->  enable them manually after setting a known password' -Default $true
    }

    $protectedUsers = Read-TierBoolean -Question 'Add top tier accounts to the Protected Users group?' `
        -Example 'yes  ->  blocks NTLM, DES and RC4 for those accounts' `
        -Default $true -Hint 'The break glass account is always excluded.'

    # =====================================================================================
    Write-TierPromptHeader -Title '6 / 8  Group Policy' `
        -Description 'One logon restriction GPO per tier, plus a baseline for the Domain Controllers OU.'

    $gpoSample = @{ ID = '0'; TIER = $sampleTier; TOKEN = $sampleToken; TOKENLC = $sampleToken.ToLower(); PURPOSE = 'Logon-Restrictions' }

    $denyNetwork = $false
    $logonMode = 'Deny'
    $createGpos = Read-TierBoolean -Question 'Create the logon restriction GPOs?' `
        -Example 'yes  ->  deny interactive, remote, batch and service logon across tiers' -Default $true

    $gpoPattern = '{TOKEN}-{PURPOSE}'
    $linkGpos = $true
    $enforceLinks = $true
    $restrictedMode = 'MemberOf'

    if ($createGpos) {
        $gpoPattern = Read-TierPattern -Question 'Naming pattern for the GPOs?' `
            -Default '{TOKEN}-{PURPOSE}' -SampleTokens $gpoSample `
            -Hint 'Alternatives: GPO-{TOKEN}-{PURPOSE}, {TIER} {PURPOSE}, C-{TOKEN}-{PURPOSE}.' -MaxLength 64

        $linkGpos = Read-TierBoolean -Question 'Link the GPOs to the tier OUs right away?' `
            -Example 'yes  ->  linked and active immediately after deployment' `
            -Default $true -Hint 'Answer no if you want to link them manually during a maintenance window.'

        if ($linkGpos) {
            $enforceLinks = Read-TierBoolean -Question 'Mark the links as enforced?' `
                -Example 'yes  ->  cannot be overridden by GPOs linked further down' -Default $true
        }

        $restrictedMode = Read-TierChoice -Question 'How should the local Administrators group be managed?' `
            -Options @('MemberOf', 'Replace') `
            -OptionDescriptions @(
            'additive - the access group is added, existing members stay (safe, recommended)',
            'strict - the access group becomes the only member, everything else is removed on every refresh'
        ) -Default 'MemberOf' `
            -Hint 'Replace also removes Domain Admins from the local Administrators group of every machine in scope.'

        if ($restrictedMode -eq 'Replace') {
            Write-Host '    Make sure your top tier access group is populated before this applies.' -ForegroundColor Yellow
        }

        $logonMode = Read-TierChoice -Question 'How should logon rights be expressed?' `
            -Options @('Deny', 'AllowList') `
            -OptionDescriptions @(
            'block the other tiers, leave everything else as Windows has it (recommended to start with)',
            'additionally state who MAY log on - everyone else loses the right'
        ) -Default 'Deny' `
            -Hint 'An allow list is stronger because it is default-deny, and riskier because a principal you forget silently loses access. Service and batch logon are left out of the generated allow lists for exactly that reason.'

        if ($logonMode -eq 'AllowList') {
            Write-Host '    Run an audit afterwards - it lists the accounts that look like service accounts.' -ForegroundColor Yellow
        }

        $denyNetwork = Read-TierBoolean -Question 'Also deny NETWORK logon across tiers?' `
            -Example 'no  ->  interactive, remote, batch and service logon are still denied' `
            -Default $false `
            -Hint 'Network logon is what remote management, agents and file access use. Denying it across tiers causes failures that are very hard to trace back to this policy. Local accounts and Guests are denied either way.'
    }

    # =====================================================================================
    Write-TierPromptHeader -Title '7 / 8  Authentication policy silo' `
        -Description 'Pins top tier accounts to top tier systems using Kerberos.'

    $createSilo = Read-TierBoolean -Question 'Create the authentication policy silo?' `
        -Example 'yes  ->  requires domain functional level 2012 R2 or higher' -Default $true

    $siloNamePattern = '{TIER}-Silo'
    $siloPolicyPattern = '{TIER}-AuthPolicy'
    $siloEnforcement = 'Audit'
    $tgtLifetime = 240

    if ($createSilo) {
        $siloSample = @{ ID = '0'; TIER = $sampleTier; TOKEN = $sampleToken; TOKENLC = $sampleToken.ToLower() }

        $siloNamePattern = Read-TierPattern -Question 'Name of the silo?' `
            -Default '{TIER}-Silo' -SampleTokens $siloSample -MaxLength 64

        $siloPolicyPattern = Read-TierPattern -Question 'Name of the authentication policy?' `
            -Default '{TIER}-AuthPolicy' -SampleTokens $siloSample -MaxLength 64

        $siloEnforcement = Read-TierChoice -Question 'Enforcement mode for the silo?' `
            -Options @('Audit', 'Enforce') `
            -OptionDescriptions @('log only, nothing is blocked (strongly recommended for the first weeks)', 'block logons that violate the silo') `
            -Default 'Audit'

        $tgtLifetimeText = Read-TierText -Question 'TGT lifetime for top tier accounts in minutes?' `
            -Example '240  ->  four hours' -Default '240' `
            -ValidationPattern '^\d+$' -ValidationMessage 'Enter a whole number of minutes.'
        $tgtLifetime = [int]$tgtLifetimeText
    }

    # =====================================================================================
    Write-TierPromptHeader -Title '8 / 8  Remaining options'

    $protectOus = Read-TierBoolean -Question 'Protect all created OUs from accidental deletion?' `
        -Example 'yes  ->  sets the deletion protection flag on every OU' -Default $true

    $blockInheritance = Read-TierBoolean -Question 'Block ACL inheritance on the tier root OUs?' `
        -Example 'no  ->  inherited permissions from the domain root stay in place' `
        -Default $false -Hint 'Existing inherited ACEs are converted to explicit ones when enabled.'

    $quotaText = Read-TierText -Question 'How many computer accounts may an ordinary user create?' `
        -Example '0  ->  nobody except delegated operators can join machines' `
        -Default '0' `
        -Hint 'This is ms-DS-MachineAccountQuota. The Active Directory default is 10, which lets any authenticated user create computer accounts - a common privilege escalation starting point. Enter -1 to leave the current value untouched.' `
        -ValidationPattern '^-?\d+$' -ValidationMessage 'Enter a whole number.'
    $machineQuota = [int]$quotaText

    $redirectComputers = Read-TierBoolean -Question 'Redirect the default location for new computer accounts?' `
        -Example "yes  ->  machines joined without a target OU land in the lowest tier staging OU" `
        -Default $true `
        -Hint 'Without this they land in CN=Computers, which cannot have Group Policy linked and therefore receives no tier policy at all.'

    $privilegedMode = Read-TierChoice -Question 'How should the built-in privileged groups be handled?' `
        -Options @('Report', 'Enforce') `
        -OptionDescriptions @(
        'list members that are not declared, change nothing (recommended to start with)',
        'remove members that are not declared from Domain Admins, Account Operators and friends'
    ) -Default 'Report' `
        -Hint 'Enforce never removes the built-in Administrator, never removes the account you are running as, and never empties Domain Admins.'

    if ($privilegedMode -eq 'Enforce') {
        Write-Host '    Run Report first and read the list before switching this on.' -ForegroundColor Yellow
    }

    $enableAuditing = Read-TierBoolean -Question 'Add audit entries (SACL) to the tier model?' `
        -Example 'yes  ->  every change to the structure and its delegation is recorded' `
        -Default $true `
        -Hint 'Events only appear once the "Directory Service Changes" audit subcategory is enabled on the domain controllers.'

    $deployLaps = Read-TierBoolean -Question 'Deploy Windows LAPS?' `
        -Example 'yes  ->  per-tier local administrator passwords, readable only by that tier' `
        -Default $true `
        -Hint 'Windows LAPS is the version built into Windows Server 2022 and Windows 11 22H2 and later. The legacy LAPS with the separate client is not supported. Extending the schema requires Schema Admins.'

    $recycleBin = Read-TierBoolean -Question 'Enable the Active Directory Recycle Bin if it is off?' `
        -Example 'yes  ->  deleted OUs, groups and delegations can be undeleted' `
        -Default $true -Hint 'Forest wide and irreversible. Strongly recommended before any structural change.'

    $createKds = Read-TierBoolean -Question 'Create the KDS root key if the forest has none?' `
        -Example 'yes  ->  prerequisite for group managed service accounts' -Default $true

    $kdsImmediate = $false
    if ($createKds) {
        $kdsImmediate = Read-TierBoolean -Question 'Backdate the KDS root key so it is usable immediately?' `
            -Example 'no  ->  the key becomes usable after ten hours, which is correct for production' `
            -Default $false -Hint 'Only answer yes in a single domain controller lab.'
    }

    # =====================================================================================
    # Build the configuration
    # =====================================================================================
    $configuration = $null
    while (-not $configuration) {
        try {
            $configuration = New-TierModelConfiguration `
                -ModelName "$($domainFqdn) administrative tier model" `
                -TierCount $tierCount `
                -DomainFqdn $domainFqdn `
                -RootOu $rootOu `
                -TierNamePattern $tierNamePattern `
                -TierTokenPattern $tierTokenPattern `
                -AccountsOuName $accountsOu `
                -GroupsOuName $groupsOu `
                -ServersOuName $serversOu `
                -DevicesOuName $devicesOu `
                -ServiceAccountsOuName $serviceAccountsOu `
                -StagingOuName $stagingOu `
                -RoleGroupPattern $roleGroupPattern `
                -AccessGroupPattern $accessGroupPattern `
                -AdminAccountPattern $adminAccountPattern `
                -GpoPattern $gpoPattern `
                -SiloNamePattern $siloNamePattern `
                -SiloPolicyNamePattern $siloPolicyPattern `
                -AdminRoleName $adminRole `
                -OperatorRoleName $operatorRole `
                -LocalAdminsResourceName $localAdminsResource `
                -RemoteDesktopResourceName $rdpResource `
                -DenyLogonResourceName $denyResource `
                -DenyNetworkLogonAcrossTiers:$denyNetwork `
                -LogonRightsMode $logonMode `
                -DelegationModel $delegationModel `
                -EnableAuditing $enableAuditing `
                -PrivilegedGroupMode $privilegedMode `
                -Options @{
                    protectOusFromAccidentalDeletion = $protectOus
                    blockInheritanceOnTierRoots      = $blockInheritance
                    createAdminAccounts              = $createAccounts
                    adminAccountsDisabledOnCreation  = $accountsDisabled
                    addTier0AdminsToProtectedUsers   = $protectedUsers
                    enableAdRecycleBin               = $recycleBin
                    deployWindowsLaps                = $deployLaps
                    machineAccountQuota              = $(if ($machineQuota -lt 0) { $null } else { $machineQuota })
                    redirectComputersTo              = $(if ($redirectComputers) { $null } else { '' })
                    createKdsRootKey                 = $createKds
                    kdsRootKeyEffectiveImmediately   = $kdsImmediate
                    createGpos                       = $createGpos
                    restrictedGroupsMode             = $restrictedMode
                    linkGpos                         = $linkGpos
                    enforceGpoLinks                  = $enforceLinks
                    createAuthenticationPolicySilo   = $createSilo
                    authenticationPolicyEnforcement  = $siloEnforcement
                    tier0TgtLifetimeMinutes          = $tgtLifetime
                }
        }
        catch {
            Write-Host ''
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
            if ($UseDefaults) { throw }
            $adminAccountPattern = Read-TierPattern -Question 'Please choose a shorter account naming pattern' `
                -Default 'a-{TOKENLC}-{PURPOSE}' -SampleTokens $accountSample -MaxLength 20
        }
    }

    Show-TierModelPreview -Configuration $configuration -DomainFqdn $domainFqdn

    if (-not (Read-TierBoolean -Question 'Save this configuration?' -Example 'yes' -Default $true)) {
        Write-Host ''
        Write-Host '  Nothing was written. Start the wizard again to change your answers.' -ForegroundColor Yellow
        return
    }

    $path = Read-TierText -Question 'Where should the configuration be stored?' `
        -Example '.\config\tiermodel.json' -Default $ConfigurationPath

    Save-TierModelConfiguration -Configuration $configuration -Path $path -Confirm:$false | Out-Null
    Write-Host ''
    Write-Host "  Configuration written to $path" -ForegroundColor Green

    # =====================================================================================
    Write-TierPromptHeader -Title 'Deployment' `
        -Description 'Nothing has been changed in Active Directory so far.'

    $action = Read-TierChoice -Question 'What should happen now?' `
        -Options @('DryRun', 'Structure', 'Full', 'Nothing') `
        -OptionDescriptions @(
        'simulate everything with -WhatIf and write a report, no changes',
        'create OUs, groups, nesting, accounts and delegation only - no GPOs, no silo',
        'run every stage including GPOs and the silo',
        'exit and deploy later with Deploy-TierModel.ps1'
    ) -Default 'DryRun'

    switch ($action) {
        'DryRun' {
            Invoke-TierModelDeployment -ConfigurationPath $path -WhatIf -Confirm:$false | Out-Null
        }
        'Structure' {
            if (Read-TierBoolean -Question 'This will modify Active Directory. Continue?' -Example 'yes' -Default $false) {
                Invoke-TierModelDeployment -ConfigurationPath $path -Stage OU, Group, Nesting, Account, Delegation -Force -Confirm:$false | Out-Null
            }
        }
        'Full' {
            if (Read-TierBoolean -Question 'This will modify Active Directory including Group Policy. Continue?' -Example 'yes' -Default $false) {
                Invoke-TierModelDeployment -ConfigurationPath $path -Force -Confirm:$false | Out-Null
            }
        }
        default {
            Write-Host ''
            Write-Host "  Run .\Deploy-TierModel.ps1 -ConfigurationPath `"$path`" -WhatIf when you are ready." -ForegroundColor Gray
        }
    }
}

function Show-TierModelPreview {
    <#
        .SYNOPSIS
        Prints the objects that the generated configuration will create.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Configuration,
        [Parameter(Mandatory)][string]$DomainFqdn
    )

    $domainDn = 'DC=' + ($DomainFqdn -replace '\.', ',DC=')
    $rootDn = "OU=$($Configuration.domain.rootOu),$domainDn"

    Write-TierPromptHeader -Title 'Preview' -Description 'These objects will be created when you deploy.'

    Write-Host ''
    Write-Host '  Organizational units' -ForegroundColor White
    Write-Host "    $rootDn" -ForegroundColor Gray
    foreach ($tier in $Configuration.tiers) {
        Write-Host "      OU=$($tier.name)" -ForegroundColor Gray
        foreach ($ou in $tier.organizationalUnits) {
            Write-Host "        OU=$($ou.name)" -ForegroundColor DarkGray
        }
    }

    Write-Host ''
    Write-Host '  Groups' -ForegroundColor White
    foreach ($tier in $Configuration.tiers) {
        foreach ($group in $tier.groups) {
            Write-Host ("    {0,-34} {1,-12} {2}" -f $group.name, $group.scope, $group.description) -ForegroundColor DarkGray
        }
    }

    if ($Configuration.options.createAdminAccounts) {
        Write-Host ''
        Write-Host '  Accounts (created disabled, random password)' -ForegroundColor White
        foreach ($tier in $Configuration.tiers) {
            foreach ($account in $tier.adminAccounts) {
                Write-Host ("    {0,-24} member of {1}" -f $account.samAccountName, ($account.memberOf -join ', ')) -ForegroundColor DarkGray
            }
        }
    }

    if ($Configuration.options.createGpos) {
        Write-Host ''
        Write-Host '  Group Policy Objects' -ForegroundColor White
        foreach ($tier in $Configuration.tiers) {
            foreach ($gpo in $tier.gpos) {
                $target = if ($gpo.targetOu) { $gpo.targetOu } else { "OU=$($tier.name),$rootDn" }
                Write-Host ("    {0,-38} linked to {1}" -f $gpo.name, $target) -ForegroundColor DarkGray
            }
        }
    }

    if ($Configuration.windowsLaps -and $Configuration.windowsLaps.enabled) {
        Write-Host ''
        Write-Host '  Windows LAPS' -ForegroundColor White
        foreach ($entry in $Configuration.windowsLaps.delegations) {
            $scope = if ($entry.gpoName) { "policy $($entry.gpoName)" } else { 'permissions only' }
            Write-Host ("    {0,-24} readable by {1,-20} {2}" -f $entry.targetOu, $entry.readGroup, $scope) -ForegroundColor DarkGray
        }
    }

    if ($Configuration.options.createAuthenticationPolicySilo) {
        Write-Host ''
        Write-Host '  Authentication policy silo' -ForegroundColor White
        Write-Host ("    {0} / {1} - mode: {2}" -f $Configuration.authenticationPolicySilo.name, $Configuration.authenticationPolicySilo.policyName, $Configuration.options.authenticationPolicyEnforcement) -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host '  Cross tier isolation' -ForegroundColor White
    foreach ($tier in $Configuration.tiers) {
        $deny = @($tier.groups)[-1]
        if ($deny -and $deny.members) {
            Write-Host ("    {0,-34} blocks {1}" -f $deny.name, ($deny.members -join ', ')) -ForegroundColor DarkGray
        }
    }
}

#endregion Wizard


####################################################################################################
#region Entry point
#  Dispatches the requested mode. Nothing above this line executes on its own.
####################################################################################################

$ErrorActionPreference = 'Stop'
$exitCode = 0

switch ($Mode) {

    'Wizard' {
        Start-TierModelWizard -ConfigurationPath $ConfigurationPath -UseDefaults:$UseDefaults
    }

    'Check' {
        Initialize-TierLog -LogDirectory $LogDirectory | Out-Null
        if (Test-Path -LiteralPath $ConfigurationPath) {
            $configuration = Import-TierConfiguration -Path $ConfigurationPath
            Initialize-TierContext -Configuration $configuration -Server $Server | Out-Null
        }
        else {
            Write-TierLog -Message "No configuration at $ConfigurationPath - checking the host only." -Level Warning
        }
        $result = Test-TierModelPrerequisite
        if (-not $result.Passed) { $exitCode = 3 }
    }

    'Deploy' {
        # Deploy plans by default. Applying requires -Apply, so a mistyped command line can
        # never change the directory.
        if (-not $Apply) {
            $WhatIfPreference = $true
            Write-Host ''
            Write-Host '  PLAN MODE - nothing will be changed. Re-run with -Apply to deploy.' -ForegroundColor Yellow
        }

        $parameters = @{
            ConfigurationPath     = $ConfigurationPath
            Stage                 = $Stage
            LogDirectory          = $LogDirectory
            ReportDirectory       = $ReportDirectory
            CredentialDirectory   = $CredentialDirectory
            SkipPrerequisiteCheck = $SkipPrerequisiteCheck
            NoEventLog            = $NoEventLog
            Force                 = $Force
            Confirm               = $false
        }
        if ($Server) { $parameters['Server'] = $Server }

        $summary = Invoke-TierModelDeployment @parameters
        if ($summary.Failed -gt 0) { $exitCode = 1 }
    }

    'Sync' {
        $parameters = @{
            ConfigurationPath = $ConfigurationPath
            LogDirectory      = $LogDirectory
            ReportDirectory   = $ReportDirectory
            NoEventLog        = $NoEventLog
            Confirm           = $false
        }
        if ($Server) { $parameters['Server'] = $Server }

        $summary = Invoke-TierModelSync @parameters
        if ($summary.Failed -gt 0) { $exitCode = 1 }
    }

    'InstallTask' {
        Initialize-TierLog -LogDirectory $LogDirectory | Out-Null
        $selfPath = if ($PSCommandPath) { $PSCommandPath } else { Join-Path $scriptRoot 'ADTierKit.ps1' }
        Install-TierModelScheduledTask -ScriptPath $selfPath -ConfigurationPath $ConfigurationPath -Confirm:$false
    }

    'Audit' {
        $parameters = @{
            ConfigurationPath = $ConfigurationPath
            LogDirectory      = $LogDirectory
            ReportDirectory   = $ReportDirectory
            NoEventLog        = $NoEventLog
        }
        if ($Server) { $parameters['Server'] = $Server }

        $summary = Invoke-TierModelAudit @parameters
        if ($summary.High -gt 0) { $exitCode = 4 }
        elseif ($summary.Missing -gt 0 -or $summary.Failed -gt 0) { $exitCode = 2 }
    }
}

#endregion Entry point

exit $exitCode
