<#
    Offline check of the ownership stage. Active Directory is mocked: Get-ADObject returns a small
    fixed set of objects with owners attached, and Set-ADObject records what would have been
    written. Only the decision logic is under test - reporting versus enforcing, which owners are
    acceptable, and whether the top tier is escalated.
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
$domainDn = 'DC=lab,DC=example,DC=com'
$domainSid = 'S-1-5-21-1-2-3'
$script:TierContext = [pscustomobject]@{
    DomainDn  = $domainDn
    DomainSid = $domainSid
    RootOuDn  = "OU=Tiering,$domainDn"
    Server    = 'dc01'
    TierNames = @('Tier-0', 'Tier-1', 'Tier-2')
}
function Get-TierContext { return $script:TierContext }
function Write-TierLog { param($Message, $Level) }
function Clear-TierPrincipalCache { $script:PrincipalCache = @{} }

$domainAdminsSid = "$domainSid-512"
$tier1AdminSid = "$domainSid-1234"

# SecurityIdentifier is not implemented outside Windows, so the mock stands in for it with an
# object carrying the same .Value property, and New-TierSecurityIdentifier is overridden below.
class FakeSd {
    [string]$Owner
    FakeSd([string]$owner) { $this.Owner = $owner }
    [object] GetOwner([type]$t) { return [pscustomobject]@{ Value = $this.Owner } }
    [void] SetOwner([object]$sid) { $this.Owner = $sid.Value }
}
function New-TierSecurityIdentifier { param([string]$Sid) return [pscustomobject]@{ Value = $Sid } }

function New-FakeObject {
    param([string]$Dn, [string]$OwnerSid)
    return [pscustomobject]@{ DistinguishedName = $Dn; nTSecurityDescriptor = [FakeSd]::new($OwnerSid) }
}

$script:Directory = @(
    (New-FakeObject -Dn "CN=svc-app,OU=Service-Accounts,OU=Tier-1,OU=Tiering,$domainDn" -OwnerSid $domainAdminsSid)
    (New-FakeObject -Dn "CN=SRV01,OU=Servers,OU=Tier-1,OU=Tiering,$domainDn"            -OwnerSid $tier1AdminSid)
    (New-FakeObject -Dn "OU=AppTeam,OU=Servers,OU=Tier-1,OU=Tiering,$domainDn"          -OwnerSid $tier1AdminSid)
    (New-FakeObject -Dn "CN=DC-PAW,OU=Devices,OU=Tier-0,OU=Tiering,$domainDn"           -OwnerSid $tier1AdminSid)
    (New-FakeObject -Dn "CN=G-T2-Admins,OU=Groups,OU=Tier-2,OU=Tiering,$domainDn"       -OwnerSid $domainAdminsSid)
)
$script:Written = [System.Collections.Generic.List[string]]::new()

function Get-TierAdParameter { return @{ Server = 'dc01' } }
function Get-ADObject { param($SearchBase, $SearchScope, $LDAPFilter, $Properties, $ResultSetSize, $Server, $ErrorAction, $Identity, $Filter) return $script:Directory }
# The real Set-TierDirectoryOwner goes through DirectoryEntry, which has no meaningful offline
# equivalent. What is tested here is the stage around it: that a throw becomes a Failed action
# rather than a reported correction.
$script:OwnerWriteFails = $false
function Set-TierDirectoryOwner {
    param([string]$Dn, [string]$OwnerSid)
    if ($script:OwnerWriteFails) { throw "The owner of $Dn is still S-1-5-21-1-2-3-1234 after the write - the directory accepted the change without applying it." }
    $script:Written.Add($Dn)
    foreach ($o in $script:Directory) { if ($o.DistinguishedName -eq $Dn) { $o.nTSecurityDescriptor.SetOwner((New-TierSecurityIdentifier -Sid $OwnerSid)) } }
    return $true
}
function Get-TierWellKnownGroup {
    param($Sid, $Properties)
    if ($Sid -eq '512') { return [pscustomobject]@{ Name = 'Domain Admins'; SID = [pscustomobject]@{ Value = $domainAdminsSid }; DistinguishedName = "CN=Domain Admins,CN=Users,$domainDn" } }
    return $null
}
function Resolve-TierPrincipal {
    param([string]$Reference, [switch]$AllowMissing)
    switch ($Reference) {
        $domainAdminsSid { return [pscustomobject]@{ Name = 'Domain Admins'; SID = $domainAdminsSid } }
        $tier1AdminSid { return [pscustomobject]@{ Name = 'adm-t1-anna'; SID = $tier1AdminSid } }
        default { return $null }
    }
}

$config = Get-Content -Raw $PSScriptRoot/../config/tiermodel.json | ConvertFrom-Json

Write-Host 'Ownership - report mode' -ForegroundColor Cyan
Set-TierObjectOwnership -Configuration $config -Confirm:$false

$drift = @($script:TierActions | Where-Object { $_.ObjectType -eq 'Owner' -and $_.Result -eq 'Drift' })
Assert-That 'three drifted objects reported' ($drift.Count -eq 3) "-> $($drift.Count)"
Assert-That 'objects owned by Domain Admins are not reported' (@($drift | Where-Object Target -match 'svc-app').Count -eq 0)
Assert-That 'nothing was written in report mode' ($script:Written.Count -eq 0)

$summary = @($script:TierActions | Where-Object ObjectType -eq 'OwnershipSummary')
Assert-That 'compliant objects are counted, not listed' ($summary.Count -eq 1 -and $summary[0].Detail -match '^2 object')

$t0finding = $drift | Where-Object Target -match 'OU=Tier-0,'
$t1finding = $drift | Where-Object Target -match 'CN=SRV01'
Assert-That 'top tier drift is High' ($t0finding.Severity -eq 'High') "-> $($t0finding.Severity)"
Assert-That 'lower tier drift is Medium' ($t1finding.Severity -eq 'Medium') "-> $($t1finding.Severity)"
Assert-That 'the finding names the current owner' ($t1finding.Detail -match 'adm-t1-anna')

Write-Host "`nOwnership - enforce mode" -ForegroundColor Cyan
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$config.ownership.mode = 'Enforce'
Set-TierObjectOwnership -Configuration $config -Confirm:$false

Assert-That 'three objects rewritten' ($script:Written.Count -eq 3) "-> $($script:Written.Count)"
Assert-That 'owner is now Domain Admins' (@($script:Directory | Where-Object { $_.nTSecurityDescriptor.Owner -ne $domainAdminsSid }).Count -eq 0)
$updated = @($script:TierActions | Where-Object { $_.ObjectType -eq 'Owner' -and $_.Result -eq 'Updated' })
Assert-That 'updates are logged as Updated' ($updated.Count -eq 3)

# A corrected object is not a finding: an enforce run that fixed everything must not read like a
# failed audit.
$verdict = @($script:TierActions | Where-Object { $_.ObjectType -eq 'Owner' -and $_.Result -eq 'Drift' })
Assert-That 'nothing is reported as drift after correcting it' ($verdict.Count -eq 0) "-> $($verdict.Count)"

# The owner name, not the raw SID, has to reach the finding - a SID in a report is a lookup
# somebody has to do by hand at the worst possible moment.
$script:Directory[1].nTSecurityDescriptor.SetOwner((New-TierSecurityIdentifier -Sid $tier1AdminSid))
$script:TierActions = [System.Collections.Generic.List[object]]::new()
Set-TierObjectOwnership -Configuration $config -AuditOnly -Confirm:$false
$named = @($script:TierActions | Where-Object { $_.Result -eq 'Drift' })
Assert-That 'the finding names the owner rather than its SID' ($named[0].Detail -match 'adm-t1-anna' -and $named[0].Detail -notmatch 'S-1-5-21')
$script:Directory[1].nTSecurityDescriptor.SetOwner((New-TierSecurityIdentifier -Sid $domainAdminsSid))  # leave the fixture clean

Write-Host "`nOwnership - idempotency" -ForegroundColor Cyan
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$script:Written = [System.Collections.Generic.List[string]]::new()
Set-TierObjectOwnership -Configuration $config -Confirm:$false
Assert-That 'second enforce run writes nothing' ($script:Written.Count -eq 0)
Assert-That 'second enforce run reports no drift' (@($script:TierActions | Where-Object Result -eq 'Drift').Count -eq 0)

Write-Host "`nOwnership - audit mode never writes" -ForegroundColor Cyan
$script:Directory[1].nTSecurityDescriptor.SetOwner((New-TierSecurityIdentifier -Sid $tier1AdminSid))
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$script:Written = [System.Collections.Generic.List[string]]::new()
Set-TierObjectOwnership -Configuration $config -AuditOnly -Confirm:$false
Assert-That 'audit mode reports the drift' (@($script:TierActions | Where-Object Result -eq 'Drift').Count -eq 1)
Assert-That 'audit mode wrote nothing despite Enforce' ($script:Written.Count -eq 0)

Write-Host "`nOwnership - a write that does not stick" -ForegroundColor Cyan
# The failure this whole path exists to catch: the directory accepts the change and does not
# apply it. Reporting that as a correction is worse than reporting nothing.
$script:Directory[1].nTSecurityDescriptor.SetOwner((New-TierSecurityIdentifier -Sid $tier1AdminSid))
$script:OwnerWriteFails = $true
$script:TierActions = [System.Collections.Generic.List[object]]::new()
Set-TierObjectOwnership -Configuration $config -Confirm:$false
$failed = @($script:TierActions | Where-Object { $_.ObjectType -eq 'Owner' -and $_.Result -eq 'Failed' })
Assert-That 'a silent no-op is reported as Failed' ($failed.Count -eq 1) "-> $($failed.Count)"
Assert-That 'and never as Updated' (@($script:TierActions | Where-Object Result -eq 'Updated').Count -eq 0)
Assert-That 'the detail explains what happened' ($failed[0].Detail -match 'without applying it')
$script:OwnerWriteFails = $false
$script:Directory[1].nTSecurityDescriptor.SetOwner((New-TierSecurityIdentifier -Sid $domainAdminsSid))

Write-Host "`nOwnership - acceptable owners" -ForegroundColor Cyan
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$config.ownership.acceptableOwners = @($tier1AdminSid)
$config.ownership.mode = 'Report'
Set-TierObjectOwnership -Configuration $config -Confirm:$false
Assert-That 'a declared acceptable owner is not drift' (@($script:TierActions | Where-Object Result -eq 'Drift').Count -eq 0)

Write-Host "`nOwnership - disabled" -ForegroundColor Cyan
$script:TierActions = [System.Collections.Generic.List[object]]::new()
$config.ownership.enabled = $false
Set-TierObjectOwnership -Configuration $config -Confirm:$false
Assert-That 'disabled block produces no actions' ($script:TierActions.Count -eq 0)

Write-Host ''
if ($script:Failures -eq 0) { Write-Host 'All checks passed.' -ForegroundColor Green; exit 0 }
Write-Host "$script:Failures check(s) failed." -ForegroundColor Red
exit 1
