<#
    .SYNOPSIS
    Checks the tier boundary by actually logging on: every test account, every logon type, on the
    machine this runs on - and compares the outcome with what the configuration says should happen.

    .DESCRIPTION
    Everything else in ADTierKit checks the directory: which groups exist, which GPO says what.
    None of it proves that a Tier 1 administrator is refused on a Tier 0 server, because that is
    decided on the server, by the policy it has actually processed. This script asks the server.

    Run it on one machine per tier, on a domain controller and on a staged machine, elevated, after
    gpupdate. It calls LogonUser for each test account and logon type locally, which is exactly
    the check Windows makes for a console, batch or service logon, and for a network logon to
    this machine. Remote interactive (RDP) has no LogonUser equivalent and is not tested; it is
    denied by the same deny group as interactive logon.

    The expectation is derived from the configuration, not typed in:

      * a logon type is expected DENIED when the GPO reaching this machine lists, in the matching
        SeDeny*LogonRight, a group that contains the account's role group
      * otherwise ALLOWED when the account belongs to the machine's tier (or the top tier on a
        domain controller), or when an allow list names it
      * otherwise NOT TESTED - batch and service logon need an allow right that a foreign account
        does not hold anyway, so a refusal there proves nothing about the tier model

    Test accounts: one enabled account per tier, member of that tier's administrator role group,
    ideally created from the template account. Do not use real administrators - a successful
    network logon test is still a logon.

    Lab only. Nothing here changes the directory or the machine.

    .PARAMETER MachineTier
    The tier of this machine: the tier id ('0', '1', '2'), 'DC' or 'Staging'.

    .PARAMETER Account
    Hashtable of tier id to PSCredential, e.g. @{ '0' = $t0; '1' = $t1; '2' = $t2 }.

    .EXAMPLE
    $accounts = @{ '0' = Get-Credential LAB\t0-probe; '1' = Get-Credential LAB\t1-probe; '2' = Get-Credential LAB\t2-probe }
    .\lab\Test-LogonMatrix.ps1 -MachineTier 1 -Account $accounts

    .NOTES
    Exit code 0 when every tested cell matches, 1 otherwise.
#>
[CmdletBinding()]
param(
    # Default: ..\config\tiermodel.json relative to this script.
    [string]$ConfigurationPath,
    [Parameter(Mandatory)][string]$MachineTier,
    [Parameter(Mandatory)][hashtable]$Account,
    [ValidateSet('Interactive', 'Network', 'Batch', 'Service')]
    [string[]]$LogonType = @('Interactive', 'Network', 'Batch', 'Service')
)

function Get-TierDeclaredMembership {
    <#
        .SYNOPSIS
        Every group name that contains the given group through declared nesting, itself included.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][string]$GroupName
    )

    $containers = @{ $GroupName = $true }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($tier in @($Configuration.tiers)) {
            foreach ($group in @($tier.groups | Where-Object { $_ })) {
                if ($containers.ContainsKey($group.name)) { continue }
                foreach ($member in @($group.members | Where-Object { $_ })) {
                    if ($containers.ContainsKey($member)) { $containers[$group.name] = $true; $changed = $true; break }
                }
            }
        }
    }
    return @($containers.Keys)
}

function Get-TierExpectedLogon {
    <#
        .SYNOPSIS
        What the configuration says should happen when an account of one tier logs on to a
        machine of another, for one logon type.

        .OUTPUTS
        'Denied', 'Allowed' or 'NotTested'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][string]$MachineTier,
        [Parameter(Mandatory)][string]$AccountTier,
        [Parameter(Mandatory)][ValidateSet('Interactive', 'Network', 'Batch', 'Service')][string]$LogonType
    )

    $tiers = @($Configuration.tiers)
    $accountTierDef = $tiers | Where-Object { "$($_.id)" -eq $AccountTier } | Select-Object -First 1
    if (-not $accountTierDef) { throw "Account tier '$AccountTier' is not in the configuration." }
    $adminGroup = (@($accountTierDef.groups | Where-Object { $_.scope -eq 'Global' }) | Select-Object -First 1).name
    $memberOf = Get-TierDeclaredMembership -Configuration $Configuration -GroupName $adminGroup

    # The GPOs that reach a machine of this kind.
    $gpos = switch ($MachineTier) {
        'DC' { @($tiers | ForEach-Object { $_.gpos } | Where-Object { $_ -and $_.targetOu -eq '$DomainControllers' }) }
        'Staging' { @($tiers | ForEach-Object { $_.gpos } | Where-Object { $_ -and $_.targetOu -eq '$Staging' }) }
        default {
            $machineTierDef = $tiers | Where-Object { "$($_.id)" -eq $MachineTier } | Select-Object -First 1
            if (-not $machineTierDef) { throw "Machine tier '$MachineTier' is not in the configuration." }
            @($machineTierDef.gpos | Where-Object { $_ -and [string]::IsNullOrEmpty($_.targetOu) })
        }
    }

    $denyRight = "SeDeny$($LogonType)LogonRight"
    $allowRight = "Se$($LogonType)LogonRight"

    foreach ($gpo in $gpos) {
        foreach ($principal in @($gpo.userRights.$denyRight | Where-Object { $_ })) {
            if ($memberOf -contains $principal) { return 'Denied' }
        }
    }

    $homeTier = switch ($MachineTier) { 'DC' { "$($tiers[0].id)" } 'Staging' { $null } default { $MachineTier } }
    $sameTier = $homeTier -and ($homeTier -eq $AccountTier)

    # An allow list, where one is configured, decides on its own.
    foreach ($gpo in $gpos) {
        $allowed = @($gpo.allowedUserRights.$allowRight | Where-Object { $_ })
        if ($allowed.Count -eq 0) { continue }
        if (@($allowed | Where-Object { $memberOf -contains $_ }).Count -gt 0) { return 'Allowed' }
        if ($allowed -contains 'S-1-5-11' -or $allowed -contains 'S-1-5-32-545') { return 'Allowed' }
        if ($allowed -contains 'S-1-5-32-544' -and $sameTier) { return 'Allowed' }
        return 'Denied'
    }

    switch ($LogonType) {
        'Network' { return 'Allowed' }                                   # Authenticated Users by default
        'Interactive' { if ($sameTier) { return 'Allowed' } else { return 'NotTested' } }
        'Batch' { if ($sameTier) { return 'Allowed' } else { return 'NotTested' } }   # local Administrators hold it
        default { return 'NotTested' }                                   # nobody holds service logon by default
    }
}

function Invoke-TierLogonProbe {
    <#
        .SYNOPSIS
        Attempts one local logon and reports 'Allowed', 'Denied' or an error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory)][ValidateSet('Interactive', 'Network', 'Batch', 'Service')][string]$LogonType
    )

    if (-not ('TierLogonProbe' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TierLogonProbe {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
    }

    $types = @{ Interactive = 2; Network = 3; Batch = 4; Service = 5 }
    $network = $Credential.GetNetworkCredential()
    $token = [IntPtr]::Zero
    $ok = [TierLogonProbe]::LogonUser($network.UserName, $network.Domain, $network.Password, $types[$LogonType], 0, [ref]$token)
    $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($ok) {
        [void][TierLogonProbe]::CloseHandle($token)
        return 'Allowed'
    }
    # 1385: the user has not been granted the requested logon type - which is what a deny right does.
    if ($code -eq 1385) { return 'Denied' }
    return "Error $code ($([System.ComponentModel.Win32Exception]::new($code).Message))"
}

# ---------------------------------------------------------------------------------------------
# Only the functions above are loaded when the offline tests parse this file.
# ---------------------------------------------------------------------------------------------
if ($MyInvocation.InvocationName -eq '.') { return }

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is empty while parameter defaults are bound under Windows PowerShell 5.1 (-File),
# so the script folder is resolved here, after binding, with two fallbacks.
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot -and $MyInvocation.MyCommand.Path) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }
if (-not $ConfigurationPath) { $ConfigurationPath = Join-Path $scriptRoot '..\config\tiermodel.json' }

# The configuration is expanded exactly as ADTierKit expands it, using its own functions, so the
# expectation includes generated role groups and the staging deny group. Only the function
# definitions are loaded - the tool itself does not run and needs no AD module here.
$toolPath = Join-Path $scriptRoot '..\ADTierKit.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($toolPath, [ref]$null, [ref]$null)
foreach ($name in 'Write-TierLog', 'Add-TierConfigurationItem', 'Copy-TierConfigurationObject', 'Get-TierToken', 'Get-TierDenyLogonGroupName',
    'Get-TierSiloDefinition', 'Expand-TierName', 'Add-TierAction', 'Get-TierSeverity', 'Expand-TierRoleDefinition', 'Expand-TierStagingDefinition') {
    $definition = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if ($definition) { . ([scriptblock]::Create($definition.Extent.Text)) }
}
$script:TierLogFile = $null
$script:TierActions = [System.Collections.Generic.List[object]]::new()

$config = Get-Content -LiteralPath $ConfigurationPath -Raw -Encoding UTF8 | ConvertFrom-Json
$config = Expand-TierRoleDefinition -Configuration $config
$config = Expand-TierStagingDefinition -Configuration $config

Write-Host ''
Write-Host "Logon matrix on $env:COMPUTERNAME (machine tier: $MachineTier)" -ForegroundColor Cyan

$results = foreach ($accountTier in ($Account.Keys | Sort-Object)) {
    $credential = $Account[$accountTier]
    foreach ($type in $LogonType) {
        $expected = Get-TierExpectedLogon -Configuration $config -MachineTier $MachineTier -AccountTier "$accountTier" -LogonType $type
        $actual = Invoke-TierLogonProbe -Credential $credential -LogonType $type
        $verdict = if ($expected -eq 'NotTested') { 'skip' } elseif ($actual -eq $expected) { 'PASS' } else { 'FAIL' }
        [pscustomobject]@{
            Account  = $credential.UserName
            Tier     = $accountTier
            Logon    = $type
            Expected = $expected
            Actual   = $actual
            Result   = $verdict
        }
    }
}

$results | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($results | Where-Object Result -eq 'FAIL')
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) cell(s) do not match the configuration." -ForegroundColor Red
    Write-Host 'Check gpupdate /force, then gpresult /h on this machine, before suspecting the model.' -ForegroundColor Yellow
    exit 1
}
Write-Host 'Every tested cell matches the configuration.' -ForegroundColor Green
exit 0
