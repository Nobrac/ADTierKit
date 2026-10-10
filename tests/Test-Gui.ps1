<#
    Offline checks for ADTierKit-Gui.ps1: the file parses, the window definition is well formed and
    names every control the code uses, and the helpers build the command line ADTierKit.ps1
    expects. The window itself needs Windows and WPF and is not opened here.
#>

$ErrorActionPreference = 'Stop'
$script:Failures = 0

function Assert-That {
    param([string]$What, [bool]$Condition, [string]$Detail)
    if ($Condition) { Write-Host "  PASS  $What" -ForegroundColor Green }
    else { Write-Host "  FAIL  $What $Detail" -ForegroundColor Red; $script:Failures++ }
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$guiPath = Join-Path $repoRoot 'ADTierKit-Gui.ps1'
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($guiPath, [ref]$null, [ref]$errors)
Assert-That 'GUI script parses' ($errors.Count -eq 0) (($errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')

# --- window definition ---------------------------------------------------------------------------
$source = Get-Content -Raw -LiteralPath $guiPath
$xamlMatch = [regex]::Match($source, "(?s)\[xml\]\`$xaml = @'\r?\n(.*?)\r?\n'@")
Assert-That 'XAML block found' $xamlMatch.Success
$xaml = $null
try { $xaml = [xml]$xamlMatch.Groups[1].Value } catch { }
Assert-That 'XAML is well formed' ($null -ne $xaml)
if ($xaml) {
    $named = @($xaml.SelectNodes('//*[@*[local-name()="Name"]]') | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') })
    $used = @([regex]::Matches($source, '\$ui\.([A-Za-z]+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    $missing = @($used | Where-Object { $named -notcontains $_ })
    Assert-That 'every control the code uses is named in the XAML' ($missing.Count -eq 0) ($missing -join ', ')
    Assert-That 'no event handlers in XAML (PowerShell cannot bind them)' ($xamlMatch.Groups[1].Value -notmatch '\s(Click|Checked|Loaded)=')
}

# The 5.1 parser rejects PowerShell 7 only syntax; catch the usual suspects even when this suite runs on 7.
$tokens = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$null)
$sevenOnly = @($tokens | Where-Object { $_.Kind -in @('QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket', 'AndAnd', 'OrOr') })
Assert-That 'no PowerShell 7 only operators' ($sevenOnly.Count -eq 0) (($sevenOnly | ForEach-Object { "line $($_.Extent.StartLineNumber)" }) -join ', ')
Assert-That 'no `u{} escapes' ($source -notmatch '`u\{')

# --- helpers -------------------------------------------------------------------------------------
$env:ADTIERKIT_GUI_NO_WINDOW = '1'
try { . $guiPath -ScriptPath 'C:\Tools\ADTierKit\ADTierKit.ps1' }
finally { Remove-Item Env:\ADTIERKIT_GUI_NO_WINDOW -ErrorAction SilentlyContinue }

# Main script parameters, so the GUI cannot drift from them.
$mainErrors = $null
$mainAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'ADTierKit.ps1'), [ref]$null, [ref]$mainErrors)
$mainParams = @($mainAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
$stageParam = $mainAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Stage' }
$validStages = @(($stageParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }).PositionalArguments | ForEach-Object { $_.Value })
Assert-That 'GUI stages match the -Stage ValidateSet' ((Compare-Object $validStages $script:AllStages -SyncWindow 0) -eq $null) ("main: $($validStages -join ',')")
$presetStages = @($script:StagePresets.Values | ForEach-Object { $_ })
Assert-That 'every preset stage is a real stage' (@($presetStages | Where-Object { $validStages -notcontains $_ }).Count -eq 0)
$guiModes = @($script:ModeInfo.Keys)
$modeParam = $mainAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' }
$validModes = @(($modeParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }).PositionalArguments | ForEach-Object { $_.Value })
Assert-That 'every GUI mode is a real mode' (@($guiModes | Where-Object { $validModes -notcontains $_ }).Count -eq 0)

$deploy = @{ Mode = 'Deploy'; ConfigurationPath = 'C:\Tier Config\tiermodel.json'; Stage = @('GPO', 'OU', 'Group'); Apply = $true }
$args1 = New-GuiArgumentList -Choice $deploy
$names = @($args1 | Where-Object { $_ -like '-*' } | ForEach-Object { $_.Substring(1) })
Assert-That 'every argument name is a real parameter' (@($names | Where-Object { $mainParams -notcontains $_ }).Count -eq 0) ($names -join ',')
Assert-That 'stages are passed in canonical order' (($args1 -join ' ') -match '-Stage OU,Group,GPO')
Assert-That 'all stages selected passes no -Stage' (@(New-GuiArgumentList -Choice @{ Mode = 'Deploy'; Stage = $script:AllStages }) -notcontains '-Stage')
Assert-That 'Deploy without stages is refused' ($(try { New-GuiArgumentList -Choice @{ Mode = 'Deploy'; Stage = @() } | Out-Null; $false } catch { $true }))
Assert-That 'Apply only when ticked' (@(New-GuiArgumentList -Choice @{ Mode = 'Deploy'; Stage = @('OU') }) -notcontains '-Apply')
Assert-That 'Deploy switches do not leak into Audit' ((@(New-GuiArgumentList -Choice @{ Mode = 'Audit'; Apply = $true; Force = $true; Stage = @('OU') }) -join ' ') -notmatch 'Apply|Force|Stage')
Assert-That 'NoEventLog is not passed to Check' (@(New-GuiArgumentList -Choice @{ Mode = 'Check'; NoEventLog = $true }) -notcontains '-NoEventLog')
$task = @(New-GuiArgumentList -Choice @{ Mode = 'InstallTask'; RequireSignedScript = $true; PinConfiguration = $true })
Assert-That 'InstallTask passes signing and pinning' ($task -contains '-RequireSignedScript' -and $task -contains '-PinConfiguration')

$line = Format-GuiCommandLine -ScriptPath 'C:\Tools\ADTierKit\ADTierKit.ps1' -Arguments $args1
Assert-That 'command line quotes a path with a space' ($line -like "*-ConfigurationPath 'C:\Tier Config\tiermodel.json'*") $line
Assert-That 'command line keeps the stage list unquoted' ($line -like '* -Stage OU,Group,GPO *') $line
Assert-That 'single quotes are doubled' ((ConvertTo-GuiPowerShellToken "O'Brien dir") -eq "'O''Brien dir'")
Assert-That 'metacharacters are quoted' ((ConvertTo-GuiPowerShellToken 'a;Remove-Item x') -eq "'a;Remove-Item x'")
Assert-That 'a value starting with a dash is quoted' ((ConvertTo-GuiPowerShellToken '-x y') -eq "'-x y'")

# The child command must reach the script with the same binding the console would use.
$probeDir = Join-Path ([System.IO.Path]::GetTempPath()) ("adtk-gui-" + [guid]::NewGuid().ToString('N'))
$probeSub = Join-Path $probeDir 'with space'
New-Item -ItemType Directory -Path $probeSub -Force | Out-Null
$probe = Join-Path $probeSub "probe'.ps1"
@'
param([string]$Mode, [string]$ConfigurationPath, [ValidateSet('OU','Group','GPO')][string[]]$Stage, [switch]$Apply)
"$Mode|$ConfigurationPath|$($Stage -join '+')|$Apply"
exit 4
'@ | Set-Content -LiteralPath $probe -Encoding UTF8
try {
    $command = New-GuiInvocationCommand -ScriptPath $probe -Arguments $args1
    $output = & ([scriptblock]::Create($command.Replace('; exit $LASTEXITCODE', '')))
    Assert-That 'invocation binds -Stage as an array' ("$output" -eq 'Deploy|C:\Tier Config\tiermodel.json|OU+Group+GPO|True') "$output"
    Assert-That 'invocation returns the script exit code' ($LASTEXITCODE -eq 4) "$LASTEXITCODE"
    Assert-That 'invocation ends by handing back the exit code' ($command.EndsWith('; exit $LASTEXITCODE'))
}
finally { Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue }

$a = Get-GuiPlanKey -Arguments (New-GuiArgumentList -Choice @{ Mode = 'Deploy'; Stage = @('OU'); Apply = $false }) -ConfigurationHash 'H'
$b = Get-GuiPlanKey -Arguments (New-GuiArgumentList -Choice @{ Mode = 'Deploy'; Stage = @('OU'); Apply = $true; Force = $true }) -ConfigurationHash 'H'
$c = Get-GuiPlanKey -Arguments (New-GuiArgumentList -Choice @{ Mode = 'Deploy'; Stage = @('OU', 'GPO'); Apply = $true }) -ConfigurationHash 'H'
$d = Get-GuiPlanKey -Arguments (New-GuiArgumentList -Choice @{ Mode = 'Deploy'; Stage = @('OU'); Apply = $true }) -ConfigurationHash 'changed'
Assert-That 'an apply matches its plan' ($a -eq $b)
Assert-That 'other stages need their own plan' ($a -ne $c)
Assert-That 'a changed configuration needs a new plan' ($a -ne $d)

$config = Join-Path (Join-Path $repoRoot 'config') 'tiermodel.json'
$summary = Get-GuiConfigurationSummary -Path $config
Assert-That 'shipped configuration is summarised' ($summary.Exists -and $summary.Lines.Count -ge 5) (($summary.Lines) -join ' / ')
$none = Get-GuiConfigurationSummary -Path (Join-Path $probeDir 'missing.json')
Assert-That 'missing configuration is reported' (-not $none.Exists)

Assert-That 'errors are red' ((Get-GuiLineColor '[!] failed') -eq 'Firebrick')
Assert-That 'plain lines have no colour' ($null -eq (Get-GuiLineColor 'plain'))

# -------------------------------------------------------------------------------------------------
Write-Host ''
if ($script:Failures -eq 0) {
    Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
}
Write-Host "$script:Failures check(s) failed." -ForegroundColor Red
exit 1
