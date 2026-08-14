<#
    .SYNOPSIS
    Runs every offline test suite and returns a non-zero exit code if any of them failed.

    .DESCRIPTION
    These suites need no domain, no elevation and no Active Directory module. They load the
    functions out of ADTierKit.ps1 without executing it, mock the directory, and exercise the
    logic that can be exercised that way: configuration expansion, name resolution, and the
    decision-making inside the stages.

    What they cannot cover is everything that depends on how a real domain controller behaves,
    which is where every bug found during the 1.0.0 lab run actually lived. Treat a green run as
    "the refactor did not break the logic", not as "this works".

    .EXAMPLE
    .\Invoke-AllTests.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$suites = Get-ChildItem -Path $PSScriptRoot -Filter 'Test-*.ps1' | Sort-Object Name
$failed = 0

# The parser check first: a syntax error makes every suite fail in the same confusing way.
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '..\ADTierKit.ps1'), [ref]$null, [ref]$errors)

if ($errors.Count -gt 0) {
    Write-Host "ADTierKit.ps1 does not parse - $($errors.Count) error(s):" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
    exit 1
}
Write-Host 'ADTierKit.ps1 parses cleanly.' -ForegroundColor Green

foreach ($suite in $suites) {
    Write-Host "`n=== $($suite.BaseName) ===" -ForegroundColor Cyan
    & $suite.FullName
    if ($LASTEXITCODE -ne 0) { $failed++ }
}

Write-Host ''
if ($failed -eq 0) {
    Write-Host "All $($suites.Count) suite(s) passed." -ForegroundColor Green
    exit 0
}

Write-Host "$failed of $($suites.Count) suite(s) failed." -ForegroundColor Red
exit 1
