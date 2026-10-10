<#
    .SYNOPSIS
    Graphical front end for ADTierKit.ps1.

    .DESCRIPTION
    A window for the same choices the command line expresses: mode, configuration, stages, plan or
    apply. It does not contain any deployment logic of its own. Every run starts ADTierKit.ps1 in
    a child Windows PowerShell process with exactly the parameters shown in the "Command line"
    box, streams its output into the window and reports the exit code - so what the window does
    can always be repeated, scripted or scheduled from a console, and the guardrails of the script
    (plan by default, lockout guard, prerequisite check, armoring check) apply unchanged.

    The window adds three guardrails of its own, on top of the script's:

      * Deploy plans unless "Apply" is ticked, and an apply is confirmed in a dialog that shows
        the exact command line.
      * An apply whose plan has not been run in this window first (same configuration, same
        stages) is pointed out before it starts.
      * -Force and -SkipPrerequisiteCheck are separate, explicitly labelled tick boxes and are
        repeated in the confirmation.

    The interactive wizard needs a console; "Start wizard" opens one.

    .PARAMETER ScriptPath
    Path to ADTierKit.ps1. Defaults to the copy next to this file.

    .NOTES
    Requires Windows, Windows PowerShell 5.1 (or PowerShell 7 on Windows) and the .NET WPF
    assemblies, which every Windows Server with Desktop Experience and every Windows client has.
    Run it elevated, as a Domain Admin, on the machine you would run ADTierKit.ps1 on.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ScriptPath
)

$ErrorActionPreference = 'Stop'

$guiRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ScriptPath) { $ScriptPath = Join-Path $guiRoot 'ADTierKit.ps1' }

####################################################################################################
#region Pure helpers
#  No WPF in here: these build the command line and read the configuration, and the offline tests
#  exercise them directly.
####################################################################################################

$script:AllStages = @('RecycleBin', 'OU', 'Domain', 'Group', 'Nesting', 'Account', 'Delegation', 'Ownership',
    'PrivilegedGroups', 'Auditing', 'GPO', 'Laps', 'KDS', 'Silo')

# The two rollout windows the README recommends: structure first, policy second.
$script:StagePresets = [ordered]@{
    'All stages' = $script:AllStages
    'Structure'  = @('RecycleBin', 'OU', 'Domain', 'Group', 'Nesting', 'Account', 'Delegation', 'Auditing')
    'Policy'     = @('GPO', 'Laps', 'KDS', 'Silo')
    'Ownership and privileged groups' = @('Ownership', 'PrivilegedGroups')
}

$script:ModeInfo = [ordered]@{
    Check       = 'Prerequisite check only. Read-only.'
    Audit       = 'Read-only drift, hygiene and attack path report. Writes nothing to the directory.'
    Deploy      = 'Converges the directory to the configuration. Plans unless "Apply" is ticked.'
    Sync        = 'Membership, account hygiene and silo assignment. Writes - this is what the daily task runs.'
    InstallTask = 'Registers the daily Sync task as SYSTEM on this machine.'
}

$script:ExitCodes = @{
    0 = 'success'
    1 = 'one or more actions failed - see the report'
    2 = 'audit found drift'
    3 = 'prerequisites failed'
    4 = 'audit found high severity findings'
    5 = 'configuration does not match the pinned hash'
}

function ConvertTo-GuiArgument {
    <#
        .SYNOPSIS
        Quotes one argument for a Windows command line the way CommandLineToArgvW reads it back.
    #>
    param([AllowEmptyString()][string]$Value)
    if ($Value -eq '') { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    # Backslashes are literal except before a quote: double those, then escape the quote itself.
    $escaped = [regex]::Replace($Value, '(\\*)"', { param($m) ($m.Groups[1].Value * 2) + '\"' })
    $escaped = [regex]::Replace($escaped, '(\\+)$', { param($m) $m.Groups[1].Value * 2 })
    return '"' + $escaped + '"'
}

function New-GuiArgumentList {
    <#
        .SYNOPSIS
        Turns the choices made in the window into the parameter list for ADTierKit.ps1.

        .DESCRIPTION
        Returns the arguments that follow -File <script>. Only what differs from the script's own
        defaults is passed, so the command line shown is the one a person would type.
    #>
    param([Parameter(Mandatory)][hashtable]$Choice)

    $list = [System.Collections.Generic.List[string]]::new()
    $list.Add('-Mode'); $list.Add($Choice.Mode)

    if ($Choice.ConfigurationPath) { $list.Add('-ConfigurationPath'); $list.Add($Choice.ConfigurationPath) }
    if ($Choice.Server) { $list.Add('-Server'); $list.Add($Choice.Server) }
    if ($Choice.LogDirectory) { $list.Add('-LogDirectory'); $list.Add($Choice.LogDirectory) }
    if ($Choice.ReportDirectory) { $list.Add('-ReportDirectory'); $list.Add($Choice.ReportDirectory) }

    switch ($Choice.Mode) {
        'Deploy' {
            $stages = @($Choice.Stage | Where-Object { $_ })
            if ($stages.Count -eq 0) { throw 'Pick at least one stage.' }
            # Keep the canonical order so equal selections produce equal command lines.
            $ordered = @($script:AllStages | Where-Object { $stages -contains $_ })
            if ($ordered.Count -ne $script:AllStages.Count) { $list.Add('-Stage'); $list.Add($ordered -join ',') }
            if ($Choice.CredentialDirectory) { $list.Add('-CredentialDirectory'); $list.Add($Choice.CredentialDirectory) }
            if ($Choice.Apply) { $list.Add('-Apply') }
            if ($Choice.Force) { $list.Add('-Force') }
            if ($Choice.SkipPrerequisiteCheck) { $list.Add('-SkipPrerequisiteCheck') }
        }
        'InstallTask' {
            if ($Choice.RequireSignedScript) { $list.Add('-RequireSignedScript') }
            if ($Choice.PinConfiguration) { $list.Add('-PinConfiguration') }
        }
    }

    if ($Choice.NoEventLog -and $Choice.Mode -in @('Deploy', 'Audit', 'Sync')) { $list.Add('-NoEventLog') }
    return $list.ToArray()
}

function ConvertTo-GuiPowerShellToken {
    <#
        .SYNOPSIS
        Writes one argument as PowerShell source: parameter names and plain words as they are,
        anything else in single quotes.
    #>
    param([AllowEmptyString()][string]$Value)
    if ($Value -match '^-[A-Za-z]+$') { return $Value }
    # Commas stay unquoted on purpose: "-Stage OU,Group" has to reach the script as an array.
    if ($Value -match '^[A-Za-z0-9_.,:\\/]+$') { return $Value }
    return "'" + $Value.Replace("'", "''") + "'"
}

function Format-GuiCommandLine {
    <#
        .SYNOPSIS
        The command a person would type in an elevated console to get the same run.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments
    )
    $parts = @('.\' + (Split-Path $ScriptPath -Leaf)) + @($Arguments | ForEach-Object { ConvertTo-GuiPowerShellToken $_ })
    return ($parts -join ' ')
}

function New-GuiInvocationCommand {
    <#
        .SYNOPSIS
        The PowerShell source the child process runs.

        .DESCRIPTION
        powershell.exe -File passes every argument as a single string, so "-Stage OU,Group" would
        arrive as one stage called "OU,Group" and fail validation. The run therefore goes through
        -EncodedCommand with the same tokens the command box shows, and hands the script's exit
        code back to the process.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments
    )
    $tokens = @($Arguments | ForEach-Object { ConvertTo-GuiPowerShellToken $_ })
    $script = "& '" + $ScriptPath.Replace("'", "''") + "'"
    if ($tokens.Count) { $script += ' ' + ($tokens -join ' ') }
    return $script + '; exit $LASTEXITCODE'
}

function Get-GuiPlanKey {
    <#
        .SYNOPSIS
        Identifies a run independently of -Apply, so an apply can be matched to its plan.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments, [string]$ConfigurationHash)
    $relevant = @($Arguments | Where-Object { $_ -notin @('-Apply', '-Force', '-SkipPrerequisiteCheck', '-NoEventLog') })
    return (($relevant -join [string][char]31) + '|' + $ConfigurationHash)
}

function Get-GuiConfigurationSummary {
    <#
        .SYNOPSIS
        Reads the configuration and returns the facts worth seeing before a run.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Exists = $false; Lines = @("No configuration at $Path - start the wizard to create one.") } }

    try { $config = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { return [pscustomobject]@{ Exists = $true; Lines = @("Not valid JSON: $($_.Exception.Message)") } }

    $lines = [System.Collections.Generic.List[string]]::new()
    $name = if ($config.metadata -and $config.metadata.name) { $config.metadata.name } else { '(unnamed)' }
    $revision = if ($config.metadata -and $config.metadata.revision) { " - revision $($config.metadata.revision)" } else { '' }
    $lines.Add("$name$revision")
    $domain = if ($config.domain.fqdn) { $config.domain.fqdn } else { '(current domain)' }
    $lines.Add("Domain $domain, root OU '$($config.domain.rootOu)', schema $($config.schemaVersion)")

    $tierText = @($config.tiers | ForEach-Object {
            $groups = @($_.groups).Count; $gpos = @($_.gpos).Count
            "$($_.name) ($groups groups, $gpos GPOs)"
        }) -join ', '
    $lines.Add("Tiers: $tierText")

    $options = $config.options
    $read = { param($object, $name, $default) if ($object -and $object.PSObject.Properties.Name -contains $name -and $null -ne $object.$name -and "$($object.$name)" -ne '') { $object.$name } else { $default } }

    $lines.Add(('Silos: {0}, enforcement {1}' -f $(if (& $read $options 'createAuthenticationPolicySilo' $false) { 'on' } else { 'off' }), (& $read $options 'authenticationPolicyEnforcement' 'Audit')))
    $lines.Add(('GPOs: {0}, links {1}, restricted groups {2}' -f $(if (& $read $options 'createGpos' $false) { 'on' } else { 'off' }),
            $(if (& $read $options 'enforceGpoLinks' $false) { 'enforced' } else { 'not enforced' }), (& $read $options 'restrictedGroupsMode' 'MemberOf')))
    $privileged = if ($config.privilegedGroups) { & $read $config.privilegedGroups 'mode' 'Report' } else { 'not configured' }
    $ownership = if ($config.ownership) { & $read $config.ownership 'mode' 'Report' } else { 'not configured' }
    $lines.Add("Privileged groups: $privileged, ownership: $ownership")
    $staging = if ($config.PSObject.Properties.Name -contains 'staging' -and $config.staging -and -not ($config.staging.PSObject.Properties.Name -contains 'enabled' -and -not $config.staging.enabled)) { 'on' } else { 'off' }
    $lines.Add("Neutral staging OU: $staging, Windows LAPS: $(if ($config.windowsLaps -and $config.windowsLaps.enabled) { 'on' } else { 'off' })")

    $warnings = [System.Collections.Generic.List[string]]::new()
    if ((& $read $options 'restrictedGroupsMode' 'MemberOf') -eq 'Replace') { $warnings.Add('Restricted groups mode is Replace - every other member of the local Administrators group is removed.') }
    if ($privileged -eq 'Enforce') { $warnings.Add('Privileged groups are in Enforce mode - undeclared members are removed.') }
    if ((& $read $options 'authenticationPolicyEnforcement' 'Audit') -eq 'Enforce') { $warnings.Add('Silos are enforced - accounts outside their silo devices cannot sign in.') }
    if (& $read $options 'kdsRootKeyEffectiveImmediately' $false) { $warnings.Add('The KDS root key is backdated - lab setting only.') }

    return [pscustomobject]@{ Exists = $true; Lines = $lines.ToArray(); Warnings = $warnings.ToArray() }
}

function Get-GuiLineColor {
    <#
        .SYNOPSIS
        Maps a line of ADTierKit output to a colour name, following the markers Write-TierLog uses.
    #>
    param([AllowEmptyString()][string]$Line)
    if ($Line -match '^\s*===') { return 'SteelBlue' }
    if ($Line -match '^\s*\[\+\]') { return 'ForestGreen' }
    if ($Line -match '^\s*\[!\]|^ERROR|Exception') { return 'Firebrick' }
    if ($Line -match '^\s*WARNING|^\s*\[~\]') { return 'DarkGoldenrod' }
    if ($Line -match '^\s*\[=\]') { return 'Gray' }
    return $null
}

#endregion Pure helpers

# The offline tests dot-source this file with -ScriptPath set to a marker to reach the helpers
# above without opening a window.
if ($env:ADTIERKIT_GUI_NO_WINDOW -eq '1') { return }

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    Write-Error 'ADTierKit-Gui needs Windows - it is a WPF application.'
    exit 1
}

# WPF needs a single threaded apartment. Windows PowerShell 5.1 starts STA by default, but a host
# started with -MTA (or some remoting hosts) does not; relaunching is cheaper than explaining.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $self = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    $relaunch = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $self)
    if ($ScriptPath) { $relaunch += @('-ScriptPath', $ScriptPath) }
    Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $relaunch
    exit 0
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

####################################################################################################
#region Window
####################################################################################################

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="ADTierKit" Width="1180" Height="820" MinWidth="980" MinHeight="640"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13"
        Background="#F6F7F9">
  <Window.Resources>
    <Style TargetType="GroupBox">
      <Setter Property="Margin" Value="0,0,0,10"/>
      <Setter Property="Padding" Value="8"/>
      <Setter Property="BorderBrush" Value="#D9DDE2"/>
      <Setter Property="Background" Value="White"/>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Padding" Value="12,5"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="MinWidth" Value="80"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Padding" Value="4,3"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Margin" Value="0,3,12,3"/>
    </Style>
    <Style TargetType="RadioButton">
      <Setter Property="Margin" Value="0,3,0,3"/>
    </Style>
  </Window.Resources>

  <DockPanel>
    <!-- header -->
    <Border DockPanel.Dock="Top" Background="#1F2A37" Padding="16,10">
      <DockPanel>
        <StackPanel Orientation="Vertical">
          <TextBlock Text="ADTierKit" Foreground="White" FontSize="20" FontWeight="SemiBold"/>
          <TextBlock x:Name="SubTitle" Foreground="#B8C2CC" Text="Deploy, audit and maintain an Active Directory tier model"/>
        </StackPanel>
        <TextBlock x:Name="ElevationBadge" DockPanel.Dock="Right" HorizontalAlignment="Right" VerticalAlignment="Center"
                   Foreground="White" Padding="10,4" FontWeight="SemiBold"/>
      </DockPanel>
    </Border>

    <!-- status bar -->
    <Border DockPanel.Dock="Bottom" Background="#E9ECEF" Padding="12,5" BorderBrush="#D9DDE2" BorderThickness="0,1,0,0">
      <DockPanel>
        <TextBlock x:Name="ExitText" DockPanel.Dock="Right" FontWeight="SemiBold"/>
        <TextBlock x:Name="StatusText" Text="Ready."/>
      </DockPanel>
    </Border>

    <Grid Margin="12">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="430"/>
        <ColumnDefinition Width="12"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- left: choices -->
      <ScrollViewer Grid.Column="0" VerticalScrollBarVisibility="Auto">
        <StackPanel>
          <GroupBox Header="Configuration">
            <StackPanel>
              <TextBlock Text="Configuration file" Margin="0,0,0,2"/>
              <DockPanel>
                <Button x:Name="BrowseConfig" DockPanel.Dock="Right" Content="Browse..." Margin="6,0,0,0" MinWidth="70"/>
                <TextBox x:Name="ConfigPath"/>
              </DockPanel>
              <TextBlock x:Name="ConfigSummary" TextWrapping="Wrap" Margin="0,8,0,0" Foreground="#3A4450"/>
              <TextBlock x:Name="ConfigWarnings" TextWrapping="Wrap" Margin="0,6,0,0" Foreground="#9A3412" FontWeight="SemiBold"/>
              <WrapPanel Margin="0,8,0,0">
                <Button x:Name="StartWizard" Content="Start wizard" ToolTip="Opens the interactive wizard in a console window"/>
                <Button x:Name="EditConfig" Content="Open in editor"/>
                <Button x:Name="ReloadConfig" Content="Reload" MinWidth="60"/>
              </WrapPanel>
            </StackPanel>
          </GroupBox>

          <GroupBox Header="Mode">
            <StackPanel>
              <RadioButton x:Name="ModeCheck" GroupName="Mode" Content="Check - prerequisites"/>
              <RadioButton x:Name="ModeAudit" GroupName="Mode" Content="Audit - read-only drift and attack path report" IsChecked="True"/>
              <RadioButton x:Name="ModeDeploy" GroupName="Mode" Content="Deploy - plan, or apply the configuration"/>
              <RadioButton x:Name="ModeSync" GroupName="Mode" Content="Sync - membership, hygiene and silos (writes)"/>
              <RadioButton x:Name="ModeInstallTask" GroupName="Mode" Content="Install task - daily Sync as SYSTEM"/>
              <TextBlock x:Name="ModeHint" TextWrapping="Wrap" Margin="0,6,0,0" Foreground="#5B6570"/>
            </StackPanel>
          </GroupBox>

          <GroupBox x:Name="DeployBox" Header="Deploy">
            <StackPanel>
              <DockPanel Margin="0,0,0,6">
                <TextBlock Text="Preset" VerticalAlignment="Center" Margin="0,0,8,0"/>
                <ComboBox x:Name="StagePreset"/>
              </DockPanel>
              <UniformGrid x:Name="StageGrid" Columns="3"/>
              <Separator Margin="0,8"/>
              <CheckBox x:Name="ApplyBox" FontWeight="SemiBold" Content="Apply - write to Active Directory (otherwise plan only)"/>
              <CheckBox x:Name="ForceBox" Content="-Force: override the lockout guard and armoring check"/>
              <CheckBox x:Name="SkipPrereqBox" Content="-SkipPrerequisiteCheck"/>
            </StackPanel>
          </GroupBox>

          <GroupBox x:Name="TaskBox" Header="Scheduled task">
            <StackPanel>
              <CheckBox x:Name="SignedBox" Content="-RequireSignedScript (AllSigned, publisher must be trusted)"/>
              <CheckBox x:Name="PinBox" Content="-PinConfiguration (refuse to run after the file changes)"/>
            </StackPanel>
          </GroupBox>

          <Expander Header="Advanced" Margin="0,0,0,10">
            <GroupBox Header="Directories and target">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="120"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Text="Domain controller" VerticalAlignment="Center"/>
                <TextBox Grid.Row="0" Grid.Column="1" x:Name="ServerBox" Margin="0,2" ToolTip="Empty: the PDC emulator"/>
                <TextBlock Grid.Row="1" Text="Log directory" VerticalAlignment="Center"/>
                <TextBox Grid.Row="1" Grid.Column="1" x:Name="LogDirBox" Margin="0,2" ToolTip="Empty: Logs next to the script"/>
                <TextBlock Grid.Row="2" Text="Report directory" VerticalAlignment="Center"/>
                <TextBox Grid.Row="2" Grid.Column="1" x:Name="ReportDirBox" Margin="0,2" ToolTip="Empty: Reports next to the script"/>
                <TextBlock Grid.Row="3" Text="Credentials" VerticalAlignment="Center"/>
                <TextBox Grid.Row="3" Grid.Column="1" x:Name="CredDirBox" Margin="0,2" ToolTip="Empty: Credentials next to the script"/>
                <CheckBox Grid.Row="4" Grid.Column="1" x:Name="NoEventLogBox" Content="-NoEventLog"/>
              </Grid>
            </GroupBox>
          </Expander>
        </StackPanel>
      </ScrollViewer>

      <!-- right: command and output -->
      <DockPanel Grid.Column="2">
        <GroupBox DockPanel.Dock="Top" Header="Command line - the same run from an elevated console">
          <DockPanel>
            <Button x:Name="CopyCommand" DockPanel.Dock="Right" Content="Copy" Margin="6,0,0,0" MinWidth="60"/>
            <TextBox x:Name="CommandBox" IsReadOnly="True" FontFamily="Consolas" TextWrapping="Wrap" Background="#FAFBFC"/>
          </DockPanel>
        </GroupBox>

        <WrapPanel DockPanel.Dock="Top" Margin="0,0,0,10">
          <Button x:Name="RunButton" Content="Run" FontWeight="SemiBold" MinWidth="110" Background="#1F6FEB" Foreground="White" BorderBrush="#1F6FEB"/>
          <Button x:Name="StopButton" Content="Stop" IsEnabled="False"/>
          <Button x:Name="OpenReport" Content="Open latest report"/>
          <Button x:Name="OpenLogs" Content="Open log folder"/>
          <Button x:Name="ClearOutput" Content="Clear"/>
        </WrapPanel>

        <GroupBox Header="Output">
          <RichTextBox x:Name="OutputBox" IsReadOnly="True" FontFamily="Consolas" FontSize="12"
                       VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Background="#FCFCFD" BorderThickness="0">
            <RichTextBox.Resources>
              <Style TargetType="Paragraph"><Setter Property="Margin" Value="0"/></Style>
            </RichTextBox.Resources>
            <FlowDocument PageWidth="4000"/>
          </RichTextBox>
        </GroupBox>
      </DockPanel>
    </Grid>
  </DockPanel>
</Window>
'@

$window = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($xaml))
$ui = @{}
foreach ($node in $xaml.SelectNodes('//*[@*[local-name()="Name"]]')) {
    $name = $node.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1 -ExpandProperty Value
    $ui[$name] = $window.FindName($name)
}

#endregion Window

####################################################################################################
#region State and behaviour
####################################################################################################

$script:Process = $null
$script:OutReader = $null
$script:ErrReader = $null
$script:OutTask = $null
$script:ErrTask = $null
$script:PlannedKeys = @{}
$script:RunningKey = $null
$script:RunningApply = $false
$script:StageBoxes = [ordered]@{}
$script:Updating = $false

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([System.Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if ($elevated) {
    $ui.ElevationBadge.Text = "Elevated - $($identity.Name)"
    $ui.ElevationBadge.Background = [System.Windows.Media.Brushes]::SeaGreen
}
else {
    $ui.ElevationBadge.Text = 'Not elevated - Deploy, Sync and InstallTask will fail'
    $ui.ElevationBadge.Background = [System.Windows.Media.Brushes]::Firebrick
}

$version = '?'
if (Test-Path -LiteralPath $ScriptPath) {
    $match = Select-String -LiteralPath $ScriptPath -Pattern "^\`$script:TierKitVersion = '([^']+)'" | Select-Object -First 1
    if ($match) { $version = $match.Matches[0].Groups[1].Value }
    $ui.SubTitle.Text = "Version $version - $ScriptPath"
}
else {
    $ui.SubTitle.Text = "ADTierKit.ps1 not found at $ScriptPath"
}

$ui.ConfigPath.Text = Join-Path (Split-Path -Parent $ScriptPath) 'config\tiermodel.json'

foreach ($stage in $script:AllStages) {
    $box = [System.Windows.Controls.CheckBox]::new()
    $box.Content = $stage
    $box.IsChecked = $true
    $ui.StageGrid.Children.Add($box) | Out-Null
    $script:StageBoxes[$stage] = $box
}
foreach ($preset in $script:StagePresets.Keys) { $ui.StagePreset.Items.Add($preset) | Out-Null }
$ui.StagePreset.Items.Add('Custom') | Out-Null
$ui.StagePreset.SelectedIndex = 0

function Get-GuiMode {
    foreach ($mode in 'Check', 'Audit', 'Deploy', 'Sync', 'InstallTask') {
        if ($ui["Mode$mode"].IsChecked) { return $mode }
    }
    return 'Audit'
}

function Get-GuiChoice {
    return @{
        Mode                  = Get-GuiMode
        ConfigurationPath     = $ui.ConfigPath.Text.Trim()
        Server                = $ui.ServerBox.Text.Trim()
        LogDirectory          = $ui.LogDirBox.Text.Trim()
        ReportDirectory       = $ui.ReportDirBox.Text.Trim()
        CredentialDirectory   = $ui.CredDirBox.Text.Trim()
        Stage                 = @($script:StageBoxes.Keys | Where-Object { $script:StageBoxes[$_].IsChecked })
        Apply                 = [bool]$ui.ApplyBox.IsChecked
        Force                 = [bool]$ui.ForceBox.IsChecked
        SkipPrerequisiteCheck = [bool]$ui.SkipPrereqBox.IsChecked
        RequireSignedScript   = [bool]$ui.SignedBox.IsChecked
        PinConfiguration      = [bool]$ui.PinBox.IsChecked
        NoEventLog            = [bool]$ui.NoEventLogBox.IsChecked
    }
}

function Get-GuiConfigurationHash {
    $path = $ui.ConfigPath.Text.Trim()
    if ($path -and (Test-Path -LiteralPath $path)) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    return ''
}

function Update-GuiCommand {
    $mode = Get-GuiMode
    $ui.ModeHint.Text = $script:ModeInfo[$mode]
    $ui.DeployBox.Visibility = if ($mode -eq 'Deploy') { 'Visible' } else { 'Collapsed' }
    $ui.TaskBox.Visibility = if ($mode -eq 'InstallTask') { 'Visible' } else { 'Collapsed' }

    $runLabel = switch ($mode) {
        'Deploy' { if ($ui.ApplyBox.IsChecked) { 'Apply' } else { 'Plan' } }
        'InstallTask' { 'Register task' }
        default { "Run $mode" }
    }
    if ($null -eq $script:Process) { $ui.RunButton.Content = $runLabel }
    $ui.RunButton.Background = if ($mode -eq 'Deploy' -and $ui.ApplyBox.IsChecked) { [System.Windows.Media.Brushes]::Firebrick } else { [System.Windows.Media.BrushConverter]::new().ConvertFromString('#1F6FEB') }

    try {
        $arguments = New-GuiArgumentList -Choice (Get-GuiChoice)
        $ui.CommandBox.Text = Format-GuiCommandLine -ScriptPath $ScriptPath -Arguments $arguments
        $ui.RunButton.IsEnabled = ($null -eq $script:Process)
    }
    catch {
        $ui.CommandBox.Text = "# $($_.Exception.Message)"
        $ui.RunButton.IsEnabled = $false
    }
}

function Update-GuiConfiguration {
    $summary = Get-GuiConfigurationSummary -Path $ui.ConfigPath.Text.Trim()
    $ui.ConfigSummary.Text = ($summary.Lines -join [Environment]::NewLine)
    $ui.ConfigWarnings.Text = if ($summary.PSObject.Properties.Name -contains 'Warnings') { ($summary.Warnings -join [Environment]::NewLine) } else { '' }
    Update-GuiCommand
}

function Add-GuiOutput {
    param([AllowEmptyString()][string]$Line, [string]$Color)
    $paragraph = [System.Windows.Documents.Paragraph]::new()
    $run = [System.Windows.Documents.Run]::new($Line)
    if (-not $Color) { $Color = Get-GuiLineColor -Line $Line }
    if ($Color) { $run.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($Color) }
    $paragraph.Inlines.Add($run)
    $ui.OutputBox.Document.Blocks.Add($paragraph)
    # A run of several thousand lines would make the document sluggish; the log file has all of it.
    while ($ui.OutputBox.Document.Blocks.Count -gt 5000) { $ui.OutputBox.Document.Blocks.Remove($ui.OutputBox.Document.Blocks.FirstBlock) | Out-Null }
    $ui.OutputBox.ScrollToEnd()
}

function Get-GuiDirectory {
    param([string]$Explicit, [string]$Default)
    if ($Explicit) { return $Explicit }
    return (Join-Path (Split-Path -Parent $ScriptPath) $Default)
}

function Stop-GuiRun {
    if (-not $script:Process) { return }
    try {
        if (-not $script:Process.HasExited) {
            # The whole tree: ADTierKit starts redircmp and friends as children.
            & taskkill.exe /PID $script:Process.Id /T /F | Out-Null
        }
    }
    catch { Add-GuiOutput -Line "Could not stop the run: $($_.Exception.Message)" -Color 'Firebrick' }
}

function Complete-GuiRun {
    $code = $script:Process.ExitCode
    $meaning = if ($script:ExitCodes.ContainsKey($code)) { $script:ExitCodes[$code] } else { 'unexpected exit code' }
    Add-GuiOutput -Line ''
    Add-GuiOutput -Line "Finished with exit code $code - $meaning." -Color $(if ($code -eq 0) { 'ForestGreen' } elseif ($code -in 2, 4) { 'DarkGoldenrod' } else { 'Firebrick' })
    $ui.ExitText.Text = "Exit code $code - $meaning"
    $ui.StatusText.Text = "Finished at $(Get-Date -Format 'HH:mm:ss')."

    # A plan that ran to the end (a failed action is still a plan the operator has seen) unlocks
    # the matching apply without the reminder.
    if (-not $script:RunningApply -and $script:RunningKey -and $code -in 0, 1) { $script:PlannedKeys[$script:RunningKey] = $true }

    $script:Process.Dispose()
    $script:Process = $null
    $script:OutTask = $null; $script:ErrTask = $null
    $ui.StopButton.IsEnabled = $false
    Update-GuiCommand
}

$timer = [System.Windows.Threading.DispatcherTimer]::new()
$timer.Interval = [TimeSpan]::FromMilliseconds(120)
$timer.Add_Tick({
        if (-not $script:Process) { return }
        # ReadLineAsync polled from the UI thread: no event handler runs on a foreign thread,
        # which a PowerShell scriptblock cannot do safely.
        for ($i = 0; $i -lt 200; $i++) {
            $progress = $false
            if ($script:OutTask -and $script:OutTask.IsCompleted) {
                $line = $script:OutTask.Result
                if ($null -ne $line) { Add-GuiOutput -Line $line; $script:OutTask = $script:OutReader.ReadLineAsync(); $progress = $true }
                else { $script:OutTask = $null }
            }
            if ($script:ErrTask -and $script:ErrTask.IsCompleted) {
                $line = $script:ErrTask.Result
                if ($null -ne $line) { Add-GuiOutput -Line $line -Color 'Firebrick'; $script:ErrTask = $script:ErrReader.ReadLineAsync(); $progress = $true }
                else { $script:ErrTask = $null }
            }
            if (-not $progress) { break }
        }
        if ($null -eq $script:OutTask -and $null -eq $script:ErrTask -and $script:Process.HasExited) { Complete-GuiRun }
    })
$timer.Start()

function Start-GuiRun {
    param([Parameter(Mandatory)][string[]]$Arguments, [string]$PlanKey, [bool]$IsApply)

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        [System.Windows.MessageBox]::Show("ADTierKit.ps1 was not found at`n$ScriptPath", 'ADTierKit', 'OK', 'Error') | Out-Null
        return
    }

    # Windows PowerShell 5.1 on purpose, whatever host runs this window: it is what the tool is
    # written and tested for, and what the scheduled task uses.
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $command = New-GuiInvocationCommand -ScriptPath $ScriptPath -Arguments $Arguments
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)

    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $powershell
    $info.Arguments = (($all | ForEach-Object { ConvertTo-GuiArgument $_ }) -join ' ')
    $info.WorkingDirectory = Split-Path -Parent $ScriptPath
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    # -NonInteractive turns any prompt into an error instead of a hang; the closed input does the
    # same for Read-Host.
    $info.RedirectStandardInput = $true
    $oem = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
    $info.StandardOutputEncoding = $oem
    $info.StandardErrorEncoding = $oem

    $ui.OutputBox.Document.Blocks.Clear()
    $ui.ExitText.Text = ''
    Add-GuiOutput -Line ("> " + $ui.CommandBox.Text) -Color 'SteelBlue'
    Add-GuiOutput -Line ''

    $script:Process = [System.Diagnostics.Process]::Start($info)
    $script:Process.StandardInput.Close()
    $script:OutReader = $script:Process.StandardOutput
    $script:ErrReader = $script:Process.StandardError
    $script:OutTask = $script:OutReader.ReadLineAsync()
    $script:ErrTask = $script:ErrReader.ReadLineAsync()
    $script:RunningKey = $PlanKey
    $script:RunningApply = $IsApply

    $ui.RunButton.IsEnabled = $false
    $ui.StopButton.IsEnabled = $true
    $ui.StatusText.Text = "Running since $(Get-Date -Format 'HH:mm:ss') - process $($script:Process.Id)."
}

# --- events ----------------------------------------------------------------------------------------

foreach ($mode in 'Check', 'Audit', 'Deploy', 'Sync', 'InstallTask') {
    $ui["Mode$mode"].Add_Checked({ Update-GuiCommand })
}
foreach ($box in $script:StageBoxes.Values) {
    $box.Add_Click({
            # A hand-made selection is a custom one; the preset no longer describes it.
            $script:Updating = $true
            $ui.StagePreset.SelectedItem = 'Custom'
            $script:Updating = $false
            Update-GuiCommand
        })
}
$ui.StagePreset.Add_SelectionChanged({
        if ($script:Updating) { return }
        $preset = [string]$ui.StagePreset.SelectedItem
        if ($script:StagePresets.Contains($preset)) {
            foreach ($stage in $script:AllStages) { $script:StageBoxes[$stage].IsChecked = ($script:StagePresets[$preset] -contains $stage) }
        }
        Update-GuiCommand
    })
foreach ($name in 'ApplyBox', 'ForceBox', 'SkipPrereqBox', 'SignedBox', 'PinBox', 'NoEventLogBox') {
    $ui[$name].Add_Click({ Update-GuiCommand })
}
foreach ($name in 'ServerBox', 'LogDirBox', 'ReportDirBox', 'CredDirBox') {
    $ui[$name].Add_TextChanged({ Update-GuiCommand })
}
$ui.ConfigPath.Add_LostFocus({ Update-GuiConfiguration })
$ui.ReloadConfig.Add_Click({ Update-GuiConfiguration })

$ui.BrowseConfig.Add_Click({
        $dialog = [Microsoft.Win32.OpenFileDialog]::new()
        $dialog.Filter = 'Tier model configuration (*.json)|*.json|All files (*.*)|*.*'
        $current = $ui.ConfigPath.Text.Trim()
        if ($current -and (Test-Path -LiteralPath (Split-Path -Parent $current))) { $dialog.InitialDirectory = Split-Path -Parent $current }
        if ($dialog.ShowDialog($window)) {
            $ui.ConfigPath.Text = $dialog.FileName
            Update-GuiConfiguration
        }
    })

$ui.EditConfig.Add_Click({
        $path = $ui.ConfigPath.Text.Trim()
        if (-not (Test-Path -LiteralPath $path)) {
            [System.Windows.MessageBox]::Show("No configuration at`n$path`n`nStart the wizard to create one.", 'ADTierKit', 'OK', 'Information') | Out-Null
            return
        }
        Start-Process -FilePath 'notepad.exe' -ArgumentList (ConvertTo-GuiArgument $path)
    })

$ui.StartWizard.Add_Click({
        # The wizard asks questions on the console, so it gets one of its own.
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $wizardArgs = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
        $path = $ui.ConfigPath.Text.Trim()
        if ($path) { $wizardArgs += @('-ConfigurationPath', $path) }
        Start-Process -FilePath $powershell -ArgumentList (($wizardArgs | ForEach-Object { ConvertTo-GuiArgument $_ }) -join ' ') -WorkingDirectory (Split-Path -Parent $ScriptPath)
        $ui.StatusText.Text = 'The wizard runs in its own console window. Press Reload here when it has written the configuration.'
    })

$ui.CopyCommand.Add_Click({
        [System.Windows.Clipboard]::SetText($ui.CommandBox.Text)
        $ui.StatusText.Text = 'Command line copied.'
    })

$ui.ClearOutput.Add_Click({ $ui.OutputBox.Document.Blocks.Clear(); $ui.ExitText.Text = '' })

$ui.OpenLogs.Add_Click({
        $dir = Get-GuiDirectory -Explicit $ui.LogDirBox.Text.Trim() -Default 'Logs'
        if (Test-Path -LiteralPath $dir) { Start-Process -FilePath 'explorer.exe' -ArgumentList (ConvertTo-GuiArgument $dir) }
        else { $ui.StatusText.Text = "No log folder yet at $dir." }
    })

$ui.OpenReport.Add_Click({
        $dir = Get-GuiDirectory -Explicit $ui.ReportDirBox.Text.Trim() -Default 'Reports'
        $latest = $null
        if (Test-Path -LiteralPath $dir) {
            $latest = Get-ChildItem -LiteralPath $dir -Filter 'ADTierKit-*.html' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        }
        if ($latest) { Start-Process -FilePath $latest.FullName }
        else { $ui.StatusText.Text = "No report yet in $dir." }
    })

$ui.StopButton.Add_Click({
        $answer = [System.Windows.MessageBox]::Show(
            "Stop the running ADTierKit process?`n`nA deploy that is stopped half way leaves the stages it finished in place. Every stage is idempotent, so running the same command again converges the rest.",
            'Stop run', 'YesNo', 'Warning', 'No')
        if ($answer -eq 'Yes') { Stop-GuiRun }
    })

$ui.RunButton.Add_Click({
        $choice = Get-GuiChoice
        try { $arguments = New-GuiArgumentList -Choice $choice }
        catch { [System.Windows.MessageBox]::Show($_.Exception.Message, 'ADTierKit', 'OK', 'Warning') | Out-Null; return }

        if ($choice.ConfigurationPath -and -not (Test-Path -LiteralPath $choice.ConfigurationPath) -and $choice.Mode -ne 'Check') {
            [System.Windows.MessageBox]::Show("No configuration at`n$($choice.ConfigurationPath)`n`nStart the wizard first.", 'ADTierKit', 'OK', 'Warning') | Out-Null
            return
        }

        $planKey = Get-GuiPlanKey -Arguments $arguments -ConfigurationHash (Get-GuiConfigurationHash)
        $isApply = ($choice.Mode -eq 'Deploy' -and $choice.Apply)
        $command = $ui.CommandBox.Text

        if ($isApply) {
            if (-not $script:PlannedKeys.ContainsKey($planKey)) {
                $planFirst = [System.Windows.MessageBox]::Show(
                    "This exact deployment (same configuration file contents, same stages) has not been planned in this window yet.`n`nRun the plan first? Choose No to apply without a plan.",
                    'Plan first?', 'YesNoCancel', 'Question', 'Yes')
                if ($planFirst -eq 'Cancel') { return }
                if ($planFirst -eq 'Yes') {
                    $ui.ApplyBox.IsChecked = $false
                    Update-GuiCommand
                    $planArgs = New-GuiArgumentList -Choice (Get-GuiChoice)
                    Start-GuiRun -Arguments $planArgs -PlanKey $planKey -IsApply $false
                    return
                }
            }

            $extra = @()
            if ($choice.Force) { $extra += '-Force overrides the logon lockout guard and the Kerberos armoring prerequisite.' }
            if ($choice.SkipPrerequisiteCheck) { $extra += '-SkipPrerequisiteCheck skips the prerequisite check.' }
            if ($choice.Stage -contains 'GPO') { $extra += 'Logon rights are tattooed: disabling a GPO link does not give a removed right back. Keep a second way into the domain controller (console, DSRM).' }
            $message = "This run writes to Active Directory:`n`n$command`n`n" + ($extra -join "`n`n") + "`n`nContinue?"
            $answer = [System.Windows.MessageBox]::Show($message, 'Apply to Active Directory', 'YesNo', 'Warning', 'No')
            if ($answer -ne 'Yes') { return }
        }
        elseif ($choice.Mode -in @('Sync', 'InstallTask')) {
            $what = if ($choice.Mode -eq 'Sync') { 'Sync writes group membership, account flags and silo assignments.' } else { 'This registers a scheduled task that runs Sync as SYSTEM every day.' }
            $answer = [System.Windows.MessageBox]::Show("$what`n`n$command`n`nContinue?", "Run $($choice.Mode)", 'YesNo', 'Question', 'No')
            if ($answer -ne 'Yes') { return }
        }

        Start-GuiRun -Arguments $arguments -PlanKey $planKey -IsApply $isApply
    })

$window.Add_Closing({
        param($closingWindow, $e)
        if ($script:Process -and -not $script:Process.HasExited) {
            $answer = [System.Windows.MessageBox]::Show('A run is still in progress. Stop it and close the window?', 'ADTierKit', 'YesNo', 'Warning', 'No')
            if ($answer -ne 'Yes') { $e.Cancel = $true; return }
            Stop-GuiRun
        }
        $timer.Stop()
    })

Update-GuiConfiguration
Add-GuiOutput -Line 'Pick a mode and press Run. Nothing is written to Active Directory unless you choose Deploy with Apply, Sync or Install task.' -Color 'Gray'
Add-GuiOutput -Line 'Every run is ADTierKit.ps1 with the parameters shown above - logs and reports land where the command line puts them.' -Color 'Gray'

$null = $window.ShowDialog()

#endregion State and behaviour
