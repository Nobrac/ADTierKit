<#
    Test isolation. Dot-sourced by every suite right after the functions of ADTierKit.ps1 are
    loaded, before any mock is defined.

    The suites mock the directory, but a mock is only as complete as whoever wrote it. When one is
    missing, PowerShell resolves the name to the real cmdlet - and on a machine with RSAT that
    auto-loads the ActiveDirectory module and talks to the real domain. It did exactly that once:
    an unmocked Set-ADAuthenticationPolicy reached a real directory from an offline test.

    So every directory, Group Policy, LAPS, KDS, scheduled task, event log and signing command the
    tool uses is defined here as a function that fails loudly. Functions take precedence over
    cmdlets, so the real module is never auto-loaded; a suite that needs one of them defines its
    own mock afterwards, which replaces the guard. A forgotten mock is now a failing test instead
    of a write to somebody's domain.

    Test-Path is wrapped as well: with the AD: drive of an imported module it would query the
    directory, so AD: paths are reported as absent and everything else goes to the real cmdlet.
#>

$script:TierIsolatedCommands = @(
    'Add-ADGroupMember', 'Add-KdsRootKey', 'Enable-ADOptionalFeature', 'Find-LapsADExtendedRights',
    'Get-ADAuthenticationPolicy', 'Get-ADAuthenticationPolicySilo', 'Get-ADComputer', 'Get-ADDomain',
    'Get-ADForest', 'Get-ADGroup', 'Get-ADGroupMember', 'Get-ADObject', 'Get-ADOptionalFeature',
    'Get-ADOrganizationalUnit', 'Get-ADReplicationSiteLink', 'Get-ADRootDSE', 'Get-ADUser',
    'Get-AuthenticodeSignature', 'Get-GPInheritance', 'Get-GPO', 'Get-GPPermission', 'Get-GPRegistryValue',
    'Get-KdsRootKey', 'Get-ScheduledTask', 'Grant-ADAuthenticationPolicySiloAccess', 'Move-ADObject',
    'New-ADAuthenticationPolicy', 'New-ADAuthenticationPolicySilo', 'New-ADGroup', 'New-ADOrganizationalUnit',
    'New-ADUser', 'New-EventLog', 'New-GPLink', 'New-GPO', 'New-ScheduledTaskAction',
    'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet', 'New-ScheduledTaskTrigger',
    'Register-ScheduledTask', 'Remove-ADGroupMember', 'Revoke-ADAuthenticationPolicySiloAccess',
    'Set-ADAccountAuthenticationPolicySilo', 'Set-ADAccountControl', 'Set-ADAuthenticationPolicy',
    'Set-ADAuthenticationPolicySilo', 'Set-ADObject', 'Set-ADReplicationSiteLink', 'Set-AuthenticodeSignature',
    'Set-GPInheritance', 'Set-GPLink', 'Set-GPPermission', 'Set-GPRegistryValue',
    'Set-LapsADComputerSelfPermission', 'Set-LapsADReadPasswordPermission', 'Set-LapsADResetPasswordPermission',
    'Update-LapsADSchema', 'Write-EventLog', 'Remove-ADObject', 'Set-ADUser', 'Set-ADGroup', 'Remove-GPLink'
)

foreach ($name in $script:TierIsolatedCommands) {
    $body = "throw 'Unmocked call to $name in an offline test - define a mock for it in the suite.'"
    Set-Item -Path "Function:script:$name" -Value ([scriptblock]::Create($body))
}

function Test-Path {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string[]]$Path,
        [string[]]$LiteralPath,
        [Microsoft.PowerShell.Commands.TestPathType]$PathType = 'Any',
        [switch]$IsValid
    )
    $all = @($Path) + @($LiteralPath) | Where-Object { $_ }
    if (@($all | Where-Object { $_ -match '^AD:' }).Count -gt 0) { return $false }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
