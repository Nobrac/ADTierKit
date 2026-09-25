<#
    Offline checks for the 1.2.0 operations features: DSRM through LAPS, undeclared members of
    access groups, the cross-tier ACL scan, administrative account hygiene, the signed and pinned
    scheduled task, the run-over-run report comparison, and the expectation logic of the lab
    logon matrix. Active Directory, Group Policy and the task scheduler are mocked.
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

foreach ($file in "$PSScriptRoot/../ADTierKit.ps1", "$PSScriptRoot/../lab/Test-LogonMatrix.ps1") {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $file).Path, [ref]$null, [ref]$null)
    foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($f.Extent.Text))
    }
}

# Every directory command fails loudly unless a mock below replaces it - see TestIsolation.ps1.
. (Join-Path $PSScriptRoot 'TestIsolation.ps1')

# --- state ---------------------------------------------------------------------------------------
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$script:PrincipalCache = @{}
$domainDn = 'DC=lab,DC=example,DC=com'
$domainSid = 'S-1-5-21-1-2-3'
$root = "OU=Tiering,$domainDn"
$script:TierContext = [pscustomobject]@{
    DomainDn            = $domainDn
    DomainFqdn          = 'lab.example.com'
    DomainNetBios       = 'LAB'
    DomainSid           = $domainSid
    RootOuDn            = $root
    StagingOuDn         = "OU=Staging,$root"
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
$config = Get-ShippedConfiguration

# =================================================================================================
Write-Host "`nDSRM through LAPS"
# =================================================================================================

$script:Written = @{}
$script:Created = 0
function New-TierGpoIfMissing { param($Name) $script:Created++; [pscustomobject]@{ Gpo = [pscustomobject]@{ Id = [guid]::NewGuid() }; Result = 'Created' } }
function Set-TierGpoRegistrySetting { param($GpoName, $Key, $ValueName, $Type, $Value) $script:Written[$ValueName] = $Value; 'Created' }
function Set-TierGpoLink { 'Created' }
function Resolve-TierPrincipal { param($Reference, [switch]$AllowMissing) [pscustomobject]@{ Name = $Reference; SID = "$domainSid-1000"; DistinguishedName = "CN=$Reference,OU=Groups,OU=Tier-0,$root" } }

$dcEntry = $config.windowsLaps.delegations | Where-Object { $_.targetOu -eq '$DomainControllers' }
Assert-That 'DC LAPS delegation has a policy GPO' ([bool]$dcEntry.gpoName)

Set-TierLapsPolicyGpo -Configuration $config -Entry $dcEntry -TargetDn $script:TierContext.DomainControllersDn -EncryptionCapable $true -Confirm:$false
Assert-That 'DC policy enables encryption' ($script:Written['ADPasswordEncryptionEnabled'] -eq 1)
Assert-That 'DC policy names no decryptor (DSRM is always Domain Admins)' (-not $script:Written.ContainsKey('ADPasswordEncryptionPrincipal'))
Assert-That 'DC policy backs up to AD' ($script:Written['BackupDirectory'] -eq 2)

$script:Created = 0
Reset-Actions
Set-TierLapsPolicyGpo -Configuration $config -Entry $dcEntry -TargetDn $script:TierContext.DomainControllersDn -EncryptionCapable $false -Confirm:$false
Assert-That 'below DFL 2016 no DSRM policy is created' ($script:Created -eq 0)
Assert-That 'and that is reported' (@(Get-Actions 'LapsDsrm' | Where-Object Result -eq 'Missing').Count -eq 1)

$generated = New-TierModelConfiguration
Assert-That 'generator names the DSRM policy after the top tier' (($generated.windowsLaps.delegations | Where-Object targetOu -eq '$DomainControllers').gpoName -eq 'T0-DC-LAPS')
$generatedCustom = New-TierModelConfiguration -TierTokenPattern 'L{ID}' -LapsGpoPattern 'GPO-{TOKEN}-LAPS'
Assert-That 'and follows a custom naming pattern' (($generatedCustom.windowsLaps.delegations | Where-Object targetOu -eq '$DomainControllers').gpoName -eq 'GPO-L0-DC-LAPS')

$legacyWork = Join-Path ([System.IO.Path]::GetTempPath()) "adtierkit-dsrm-$PID"
New-Item -Path $legacyWork -ItemType Directory -Force | Out-Null
$legacy = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
($legacy.windowsLaps.delegations | Where-Object targetOu -eq '$DomainControllers').gpoName = $null
$legacyPath = Join-Path $legacyWork 'tiermodel.json'
$legacy | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $legacyPath -Encoding UTF8
$null = Invoke-ChildScript -Arguments @('-File', "$PSScriptRoot/../Update-TierConfiguration.ps1", '-Path', $legacyPath, '-SkipRoles')
$migrated = Get-Content -Raw $legacyPath | ConvertFrom-Json
Assert-That 'migration adds the DSRM policy' (($migrated.windowsLaps.delegations | Where-Object targetOu -eq '$DomainControllers').gpoName -eq 'T0-DC-LAPS')
Remove-Item -LiteralPath $legacyWork -Recurse -Force

function Get-ADComputer { @([pscustomobject]@{ Name = 'DC01'; 'msLAPS-EncryptedDSRMPassword' = [byte[]](1, 2) }, [pscustomobject]@{ Name = 'DC02'; 'msLAPS-EncryptedDSRMPassword' = $null }) }
Reset-Actions
Test-TierDsrmBackup
$dsrm = Get-Actions 'DsrmBackup'
Assert-That 'a DC with a DSRM backup is compliant' (@($dsrm | Where-Object { $_.Target -eq 'DC01' -and $_.Result -eq 'Compliant' }).Count -eq 1)
Assert-That 'a DC without one is a Medium finding' (@($dsrm | Where-Object { $_.Target -eq 'DC02' -and $_.Result -eq 'Missing' -and $_.Severity -eq 'Medium' }).Count -eq 1)

# =================================================================================================
Write-Host "`nUndeclared members of access groups"
# =================================================================================================

function Resolve-TierPrincipal { param($Reference, [switch]$AllowMissing) [pscustomobject]@{ Name = $Reference; SID = $Reference; DistinguishedName = "CN=$Reference,OU=Groups,OU=Tier-0,$root" } }
$t2User = "CN=helpdesk-anna,OU=Accounts,OU=Tier-2,$root"
$stray = "CN=jdoe,CN=Users,$domainDn"
$script:LiveMembers = @{
    'DL-T1-LocalAdmins'  = @("CN=G-T1-Admins,OU=Groups,OU=Tier-0,$root", $t2User, $stray)
    'DL-T1-RemoteDesktop' = @("CN=G-T1-Admins,OU=Groups,OU=Tier-0,$root", "CN=G-T1-Operators,OU=Groups,OU=Tier-0,$root")
    'DL-T1-DenyLogon'    = @("CN=G-T0-Admins,OU=Groups,OU=Tier-0,$root", $stray)
    'DL-T1-Exempt-Logon' = @("CN=APPLIANCE01,OU=Servers,OU=Tier-1,$root")
}
function Get-ADGroup { param($LDAPFilter) if ($LDAPFilter -match 'sAMAccountName=([^)]+)') { $n = $Matches[1]; if ($script:LiveMembers.ContainsKey($n)) { [pscustomobject]@{ DistinguishedName = "CN=$n"; member = $script:LiveMembers[$n] } } } }

Reset-Actions
Test-TierAccessGroupMembership -Configuration $config
$members = Get-Actions 'AccessGroupMember'
Assert-That 'a Tier 2 account in Tier 1 LocalAdmins is High' (@($members | Where-Object { $_.Target -match 'helpdesk-anna' -and $_.Severity -eq 'High' }).Count -eq 1)
Assert-That 'an unclassified account is Medium' (@($members | Where-Object { $_.Target -match 'jdoe' -and $_.Severity -eq 'Medium' }).Count -eq 1)
Assert-That 'declared members are not reported' (@($members | Where-Object { $_.Target -match 'G-T1-' }).Count -eq 0)
Assert-That 'extra members of a deny group are not reported' (@($members | Where-Object { $_.Target -match 'DenyLogon' }).Count -eq 0)
Assert-That 'every exempted machine is reported' (@(Get-Actions 'ExceptionMember' | Where-Object { $_.Target -match 'APPLIANCE01' }).Count -eq 1)

# =================================================================================================
Write-Host "`nAdministrative account hygiene"
# =================================================================================================

$alice = "CN=adm-t0-alice,OU=Accounts,OU=Tier-0,$root"
$breakGlass = "CN=adm-t0-breakglass,OU=Accounts,OU=Tier-0,$root"
$bob = "CN=adm-t1-bob,OU=Accounts,OU=Tier-1,$root"
$script:Flags = @{ $alice = $true; $breakGlass = $true; $bob = $false }
$script:Protected = @($breakGlass.Replace('adm-t0-breakglass', 'someone-else'))
$script:Calls = [System.Collections.Generic.List[string]]::new()

function Get-TierWellKnownGroup { [pscustomobject]@{ Name = 'Protected Users'; DistinguishedName = "CN=Protected Users,CN=Users,$domainDn"; member = $script:Protected } }
function Get-ADGroup { param($LDAPFilter) if ($LDAPFilter -match 'sAMAccountName=([^)]+)') { [pscustomobject]@{ DistinguishedName = "CN=$($Matches[1])" } } }
function Get-ADGroupMember {
    param($Identity)
    $map = @{ 'CN=G-T0-Admins' = @($alice, $breakGlass); 'CN=G-T1-Admins' = @($bob) }
    @($map[$Identity] | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ objectClass = 'user'; distinguishedName = $_ } })
}
function Get-ADUser { param($Identity) [pscustomobject]@{ DistinguishedName = $Identity; SamAccountName = (($Identity -split ',')[0] -replace '^CN='); AccountNotDelegated = $script:Flags[$Identity] } }
function Set-ADAccountControl { param($Identity, $AccountNotDelegated) $script:Calls.Add("sensitive $Identity") }
function Add-ADGroupMember { param($Identity, $Members) $script:Calls.Add("protect $Members") }

Reset-Actions
Set-TierAdminAccountHygiene -Configuration $config -AuditOnly -Confirm:$false
Assert-That 'audit reports a delegable admin account' (@(Get-Actions 'AccountNotDelegated' | Where-Object { $_.Target -eq 'adm-t1-bob' -and $_.Result -eq 'Drift' }).Count -eq 1)
Assert-That 'audit reports a Tier 0 admin outside Protected Users' (@(Get-Actions 'ProtectedUsers' | Where-Object { $_.Target -eq 'adm-t0-alice' }).Count -eq 1)
Assert-That 'the break-glass account is not pushed into Protected Users' (@(Get-Actions 'ProtectedUsers' | Where-Object { $_.Target -eq 'adm-t0-breakglass' }).Count -eq 0)
Assert-That 'Tier 1 accounts are not pushed into Protected Users' (@(Get-Actions 'ProtectedUsers' | Where-Object { $_.Target -eq 'adm-t1-bob' }).Count -eq 0)
Assert-That 'audit changes nothing' ($script:Calls.Count -eq 0)

Reset-Actions
Set-TierAdminAccountHygiene -Configuration $config -Confirm:$false
Assert-That 'deploy sets the delegation flag' ($script:Calls -contains "sensitive $bob")
Assert-That 'deploy adds the Tier 0 admin to Protected Users' ($script:Calls -contains "protect $alice")
Assert-That 'deploy leaves the break-glass account out' ($script:Calls -notcontains "protect $breakGlass")

# =================================================================================================
Write-Host "`nCross-tier ACL scan"
# =================================================================================================

class FakeAce {
    [object]$IdentityReference; [long]$ActiveDirectoryRights; [string]$AccessControlType; [guid]$ObjectType; [bool]$IsInherited
    FakeAce([string]$sid, [long]$rights) {
        $this.IdentityReference = [pscustomobject]@{ Value = $sid }; $this.ActiveDirectoryRights = $rights
        $this.AccessControlType = 'Allow'; $this.ObjectType = [guid]::Empty; $this.IsInherited = $false
    }
}
class FakeSd {
    [string]$Owner; [object[]]$Aces
    FakeSd([string]$owner, [object[]]$aces) { $this.Owner = $owner; $this.Aces = $aces }
    [object] GetOwner([type]$t) { return [pscustomobject]@{ Value = $this.Owner } }
    [object[]] GetAccessRules([bool]$explicit, [bool]$inherited, [type]$t) { return @($this.Aces | Where-Object { ($explicit -and -not $_.IsInherited) -or ($inherited -and $_.IsInherited) }) }
}

$t1Admins = "$domainSid-1101"; $t2Admins = "$domainSid-1201"; $t2User = "$domainSid-1250"; $da = "$domainSid-512"
$sidMap = @{
    $t1Admins = [pscustomobject]@{ Name = 'G-T1-Admins'; SID = $t1Admins; DistinguishedName = "CN=G-T1-Admins,OU=Groups,OU=Tier-1,$root" }
    $t2Admins = [pscustomobject]@{ Name = 'G-T2-Admins'; SID = $t2Admins; DistinguishedName = "CN=G-T2-Admins,OU=Groups,OU=Tier-2,$root" }
    $t2User   = [pscustomobject]@{ Name = 'helpdesk-anna'; SID = $t2User; DistinguishedName = "CN=helpdesk-anna,OU=Accounts,OU=Tier-2,$root" }
}
function Resolve-TierPrincipal { param($Reference, [switch]$AllowMissing) if ($sidMap.ContainsKey($Reference)) { $sidMap[$Reference] } else { [pscustomobject]@{ Name = $Reference; SID = $Reference; DistinguishedName = $null } } }
$script:Subtree = @{
    "OU=Tier-1,$root" = @(
        [pscustomobject]@{ DistinguishedName = "CN=SQL01,OU=Servers,OU=Tier-1,$root"; nTSecurityDescriptor = [FakeSd]::new($da, @([FakeAce]::new($t2Admins, 0xF01FF))) },
        [pscustomobject]@{ DistinguishedName = "CN=APP01,OU=Servers,OU=Tier-1,$root"; nTSecurityDescriptor = [FakeSd]::new($t2User, @()) },
        [pscustomobject]@{ DistinguishedName = "CN=WEB01,OU=Servers,OU=Tier-1,$root"; nTSecurityDescriptor = [FakeSd]::new($da, @([FakeAce]::new($t1Admins, 0xF01FF))) })
    "OU=Tier-2,$root" = @(
        [pscustomobject]@{ DistinguishedName = "CN=PC01,OU=Devices,OU=Tier-2,$root"; nTSecurityDescriptor = [FakeSd]::new($da, @([FakeAce]::new($t1Admins, 0xF01FF))) })
}
function Get-ADObject { param($Identity, $SearchBase) if ($SearchBase) { return $script:Subtree[$SearchBase] }; throw 'not found' }
function Get-ADOrganizationalUnit { @() }
function Get-GPInheritance { throw 'not in this test' }
function Get-ADComputer { }
function Get-ADUser { param($Identity) if ($Identity) { [pscustomobject]@{ PasswordLastSet = (Get-Date) } } }

Reset-Actions
Test-TierAttackPath -Configuration $config
$cross = Get-Actions 'CrossTierAce' | Where-Object Result -eq 'Drift'
Assert-That 'Tier 2 with full control on a Tier 1 server is High' (@($cross | Where-Object { $_.Target -match 'SQL01' -and $_.Severity -eq 'High' }).Count -eq 1)
Assert-That 'a Tier 1 server owned by a Tier 2 user is found' (@($cross | Where-Object { $_.Target -match 'APP01' -and $_.Detail -match 'Owned by' }).Count -eq 1)
Assert-That 'a tier controlling its own branch is not a finding' (@($cross | Where-Object { $_.Target -match 'WEB01' }).Count -eq 0)
Assert-That 'a higher tier controlling a lower one is not a finding' (@($cross | Where-Object { $_.Target -match 'PC01' }).Count -eq 0)

# =================================================================================================
Write-Host "`nSigned and pinned scheduled task"
# =================================================================================================

$work = Join-Path ([System.IO.Path]::GetTempPath()) "adtierkit-ops-$PID"
New-Item -Path $work -ItemType Directory -Force | Out-Null
$scriptCopy = Join-Path $work 'ADTierKit.ps1'
$configCopy = Join-Path $work 'tiermodel.json'
Copy-Item "$PSScriptRoot/../ADTierKit.ps1" $scriptCopy
Copy-Item "$PSScriptRoot/../config/tiermodel.json" $configCopy
$hash = (Get-FileHash -LiteralPath $configCopy -Algorithm SHA256).Hash

$script:Signature = 'Valid'
$script:TrustedPublisher = $true
$script:TaskArguments = $null
function Get-AuthenticodeSignature { [pscustomobject]@{ Status = $script:Signature; SignerCertificate = [pscustomobject]@{ Thumbprint = 'ABC123'; Subject = 'CN=Lab Code Signing' } } }
function Test-Path { param($LiteralPath) if ($LiteralPath -like 'Cert:*') { return $script:TrustedPublisher }; return [System.IO.File]::Exists($LiteralPath) -or [System.IO.Directory]::Exists($LiteralPath) }
function Get-ScheduledTask { }
function New-ScheduledTaskAction { param($Execute, $Argument, $WorkingDirectory) $script:TaskArguments = $Argument; 'action' }
function New-ScheduledTaskTrigger { 'trigger' }
function New-ScheduledTaskPrincipal { 'principal' }
function New-ScheduledTaskSettingsSet { 'settings' }
function Register-ScheduledTask { }

Install-TierModelScheduledTask -ScriptPath $scriptCopy -ConfigurationPath $configCopy -SkipAclCheck -RequireSignedScript -PinConfiguration -Confirm:$false
Assert-That 'a signed script runs under AllSigned' ($script:TaskArguments -match '-ExecutionPolicy AllSigned')
Assert-That 'the configuration hash is passed to the task' ($script:TaskArguments -match "-ConfigurationSha256 $hash")

Install-TierModelScheduledTask -ScriptPath $scriptCopy -ConfigurationPath $configCopy -SkipAclCheck -Confirm:$false
Assert-That 'without the switches nothing changes' ($script:TaskArguments -match '-ExecutionPolicy Bypass' -and $script:TaskArguments -notmatch 'ConfigurationSha256')

$script:Signature = 'NotSigned'
$refused = $false
try { Install-TierModelScheduledTask -ScriptPath $scriptCopy -ConfigurationPath $configCopy -SkipAclCheck -RequireSignedScript -Confirm:$false } catch { $refused = $true }
Assert-That 'an unsigned script is refused' $refused

$script:Signature = 'Valid'
$script:TrustedPublisher = $false
$refused = $false
try { Install-TierModelScheduledTask -ScriptPath $scriptCopy -ConfigurationPath $configCopy -SkipAclCheck -RequireSignedScript -Confirm:$false } catch { $refused = $true }
Assert-That 'a publisher outside TrustedPublisher is refused' $refused
Remove-Item Function:\Test-Path
# Back to the isolation wrapper, so AD: stays blind for the rest of the suite.
. (Join-Path $PSScriptRoot 'TestIsolation.ps1')

# The pin check runs before the AD module is loaded, so it can be exercised for real.
$exit = Invoke-ChildScript -Arguments @('-File', $scriptCopy, '-Mode', 'Check', '-Server', 'adtierkit-test.invalid', '-ConfigurationPath', $configCopy, '-ConfigurationSha256', ('0' * 64))
Assert-That 'a changed configuration is refused with exit code 5' ($exit -eq 5) "exit code $exit"
# Read-only mode against a server that cannot exist: on a machine with RSAT the run gets past the
# pin check and must not touch a real directory. Whatever it fails with afterwards is not code 5.
$exit = Invoke-ChildScript -Arguments @('-File', $scriptCopy, '-Mode', 'Check', '-Server', 'adtierkit-test.invalid', '-ConfigurationPath', $configCopy, '-ConfigurationSha256', $hash)
Assert-That 'the pinned configuration passes the check' ($exit -ne 5) "exit code $exit"

# =================================================================================================
Write-Host "`nReport comparison"
# =================================================================================================

$reports = Join-Path $work 'Reports'
New-Item -Path $reports -ItemType Directory -Force | Out-Null
function New-Finding { param($Target, $Severity = 'High', $Result = 'Drift') [pscustomobject]@{ Timestamp = ''; Phase = 'Isolation'; ObjectType = 'PrivilegedGroup'; Target = $Target; Result = $Result; Severity = $Severity; Detail = '' } }
function New-Summary {
    param([object[]]$Actions)
    [pscustomobject]@{ Mode = 'Audit'; Started = Get-Date; Finished = Get-Date; Duration = [timespan]::FromSeconds(3)
        Created = 0; Updated = 0; Compliant = 0; Planned = 0; Missing = 0; Failed = 0; High = 0; Medium = 0; Low = 0; Actions = $Actions }
}

$first = New-Summary @((New-Finding 'Domain Admins'), (New-Finding 'Backup Operators'))
$null = New-TierModelReport -Summary $first -OutputDirectory $reports
Assert-That 'the first run is the baseline' ($null -eq $first.NewFindings)

Start-Sleep -Milliseconds 1100   # report file names carry a one-second timestamp
$second = New-Summary @((New-Finding 'Domain Admins'), (New-Finding 'Schema Admins'), (New-Finding 'Tier-0' 'Info' 'Compliant'))
$html = New-TierModelReport -Summary $second -OutputDirectory $reports
Assert-That 'one new finding' ($second.NewFindings -eq 1)
Assert-That 'the new one is marked' (@($second.Actions | Where-Object { $_.IsNew }).Target -eq 'Schema Admins')
Assert-That 'the unchanged one is not' (-not ($second.Actions | Where-Object Target -eq 'Domain Admins').IsNew)
Assert-That 'a compliant entry is never new' (-not ($second.Actions | Where-Object Target -eq 'Tier-0').IsNew)
Assert-That 'the fixed one is listed as resolved' (@($second.ResolvedFindings).Count -eq 1 -and $second.ResolvedFindings[0].Target -eq 'Backup Operators')
$content = Get-Content -Raw $html
Assert-That 'the HTML marks new rows and lists resolved ones' ($content -match 'is-new' -and $content -match 'Resolved since' -and $content -match 'Backup Operators')

Remove-Item -LiteralPath $work -Recurse -Force

# =================================================================================================
Write-Host "`nLab logon matrix expectations"
# =================================================================================================

$expect = { param($machine, $account, $type) Get-TierExpectedLogon -Configuration $config -MachineTier $machine -AccountTier $account -LogonType $type }
Assert-That 'Tier 1 admin on a Tier 1 server: interactive allowed' ((& $expect '1' '1' 'Interactive') -eq 'Allowed')
Assert-That 'Tier 2 admin on a Tier 1 server: interactive denied' ((& $expect '1' '2' 'Interactive') -eq 'Denied')
Assert-That 'Tier 0 admin on a Tier 1 server: interactive denied' ((& $expect '1' '0' 'Interactive') -eq 'Denied')
Assert-That 'Tier 0 admin on a Tier 1 server: network allowed by default' ((& $expect '1' '0' 'Network') -eq 'Allowed')
Assert-That 'Tier 2 admin on a Tier 1 server: service denied' ((& $expect '1' '2' 'Service') -eq 'Denied')
Assert-That 'own tier service logon is not testable' ((& $expect '1' '1' 'Service') -eq 'NotTested')
Assert-That 'Tier 0 admin on a DC: interactive allowed' ((& $expect 'DC' '0' 'Interactive') -eq 'Allowed')
Assert-That 'Tier 1 admin on a DC: interactive denied' ((& $expect 'DC' '1' 'Interactive') -eq 'Denied')
Assert-That 'Tier 1 admin on a DC: network allowed' ((& $expect 'DC' '1' 'Network') -eq 'Allowed')
Assert-That 'Tier 0 admin on a staged machine: interactive denied' ((& $expect 'Staging' '0' 'Interactive') -eq 'Denied')
Assert-That 'Tier 2 admin on a staged machine: batch denied' ((& $expect 'Staging' '2' 'Batch') -eq 'Denied')
Assert-That 'role groups are covered through declared nesting' ((Get-TierDeclaredMembership -Configuration $config -GroupName 'G-T1-GPO-Admins') -contains 'DL-T0-DenyLogon')

# -------------------------------------------------------------------------------------------------
Write-Host ''
if ($script:Failures -eq 0) {
    Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
}
Write-Host "$script:Failures check(s) failed." -ForegroundColor Red
exit 1
