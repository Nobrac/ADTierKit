<#
    Offline check of Set-TierBuiltInGroupNesting. Active Directory is mocked: a small set of
    built-in groups with their current membership, and a record of every Add-ADGroupMember that
    would have been issued.
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

$domainDn = 'DC=lab,DC=example,DC=com'
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$script:PrincipalCache = @{}
$script:TierContext = [pscustomobject]@{ DomainDn = $domainDn; DomainSid = 'S-1-5-21-1-2-3'; Server = 'dc01' }
function Get-TierContext { return $script:TierContext }
function Get-TierAdParameter { return @{ Server = 'dc01' } }
function Write-TierLog { param($Message, $Level) }

$dnsRoleDn = "CN=G-T0-DNS-Admins,OU=Groups,OU=Tier-0,OU=Tiering,$domainDn"
$gpoRoleDn = "CN=G-T0-GPO-Admins,OU=Groups,OU=Tier-0,OU=Tiering,$domainDn"

$script:Groups = @{
    'DnsAdmins' = [pscustomobject]@{ Name = 'DnsAdmins'; DistinguishedName = "CN=DnsAdmins,CN=Users,$domainDn"; member = @() }
    '520'       = [pscustomobject]@{ Name = 'Group Policy Creator Owners'; DistinguishedName = "CN=Group Policy Creator Owners,CN=Users,$domainDn"; member = @() }
}
$script:Added = [System.Collections.Generic.List[string]]::new()

function Get-TierPrivilegedGroupReference {
    param($Entry, $Properties)
    $key = if ($Entry.PSObject.Properties.Name -contains 'sid' -and $Entry.sid) { $Entry.sid } else { $Entry.name }
    if ($script:Groups.ContainsKey($key)) { return $script:Groups[$key] }
    return $null
}
function Resolve-TierPrincipal {
    param([string]$Reference, [switch]$AllowMissing)
    switch ($Reference) {
        'G-T0-DNS-Admins' { return [pscustomobject]@{ Name = $_; SID = 'S-1-5-21-1-2-3-1101'; DistinguishedName = $dnsRoleDn } }
        'G-T0-GPO-Admins' { return [pscustomobject]@{ Name = $_; SID = 'S-1-5-21-1-2-3-1102'; DistinguishedName = $gpoRoleDn } }
        default { return $null }
    }
}
function Add-ADGroupMember {
    param($Identity, $Members, $Server, $ErrorAction)
    $script:Added.Add("$Identity <- $Members")
    foreach ($g in $script:Groups.Values) { if ($g.DistinguishedName -eq $Identity) { $g.member = @($g.member) + $Members } }
}

$config = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json
$config = Expand-TierRoleDefinition -Configuration $config

Write-Host 'Built-in nesting - first run' -ForegroundColor Cyan
$script:TierActions = [System.Collections.Generic.List[object]]::new()
Set-TierBuiltInGroupNesting -Configuration $config -Confirm:$false

Assert-That 'both roles were nested' ($script:Added.Count -eq 2) "-> $($script:Added.Count)"
Assert-That 'DNS role landed in DnsAdmins' (@($script:Added | Where-Object { $_ -match 'DnsAdmins.*G-T0-DNS-Admins' }).Count -eq 1)
Assert-That 'GPO role landed in Group Policy Creator Owners' (@($script:Added | Where-Object { $_ -match 'Creator Owners.*G-T0-GPO-Admins' }).Count -eq 1)
$created = @($script:TierActions | Where-Object { $_.ObjectType -eq 'BuiltInGroup' -and $_.Result -eq 'Created' })
Assert-That 'both are logged as Created' ($created.Count -eq 2)

Write-Host "`nIdempotency" -ForegroundColor Cyan
$script:Added = [System.Collections.Generic.List[string]]::new()
$script:TierActions = [System.Collections.Generic.List[object]]::new()
Set-TierBuiltInGroupNesting -Configuration $config -Confirm:$false
Assert-That 'second run adds nothing' ($script:Added.Count -eq 0)
Assert-That 'second run reports Compliant' (@($script:TierActions | Where-Object Result -eq 'Compliant').Count -eq 2)

Write-Host "`nAudit mode" -ForegroundColor Cyan
$script:Groups['DnsAdmins'].member = @()
$script:Added = [System.Collections.Generic.List[string]]::new()
$script:TierActions = [System.Collections.Generic.List[object]]::new()
Set-TierBuiltInGroupNesting -Configuration $config -AuditOnly -Confirm:$false
Assert-That 'audit mode writes nothing' ($script:Added.Count -eq 0)
$missing = @($script:TierActions | Where-Object { $_.ObjectType -eq 'BuiltInGroup' -and $_.Result -eq 'Missing' })
Assert-That 'audit reports the missing nesting as Medium' ($missing.Count -eq 1 -and $missing[0].Severity -eq 'Medium') "-> $($missing[0].Severity)"

Write-Host "`nFlap guard" -ForegroundColor Cyan
# A hand-written nesting entry whose member is not declared in privilegedGroups would be added by
# this stage and removed again by the next enforce run of the privileged group stage.
$script:Added = [System.Collections.Generic.List[string]]::new()
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$dnsDeclared = $config.privilegedGroups.groups | Where-Object { $_.name -eq 'DnsAdmins' }
$dnsDeclared.allowedMembers = @()
Set-TierBuiltInGroupNesting -Configuration $config -Confirm:$false
Assert-That 'undeclared member is not nested' (@($script:Added | Where-Object { $_ -match 'DnsAdmins' }).Count -eq 0)
$refused = @($script:TierActions | Where-Object { $_.ObjectType -eq 'BuiltInGroup' -and $_.Result -eq 'Failed' })
Assert-That 'the refusal is a High finding' ($refused.Count -eq 1 -and $refused[0].Severity -eq 'High')

Write-Host "`nAbsent built-in group" -ForegroundColor Cyan
# DnsAdmins does not exist before the DNS server role is installed - a state, not a fault.
$script:Groups.Remove('DnsAdmins')
$dnsDeclared.allowedMembers = @('G-T0-DNS-Admins')
$script:TierActions = [System.Collections.Generic.List[object]]::new()
Set-TierBuiltInGroupNesting -Configuration $config -Confirm:$false
$absent = @($script:TierActions | Where-Object { $_.ObjectType -eq 'BuiltInGroup' -and $_.Result -eq 'Missing' })
Assert-That 'a missing built-in group is reported, not thrown' ($absent.Count -eq 1)
Assert-That 'and is not a High finding' ($absent[0].Severity -ne 'High') "-> $($absent[0].Severity)"

Write-Host ''
if ($script:Failures -eq 0) { Write-Host 'All checks passed.' -ForegroundColor Green; exit 0 }
Write-Host "$script:Failures check(s) failed." -ForegroundColor Red
exit 1
