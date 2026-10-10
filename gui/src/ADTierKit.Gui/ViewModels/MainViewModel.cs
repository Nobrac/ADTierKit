using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows.Input;
using System.Windows.Threading;
using ADTierKit.Gui.Core;
using ADTierKit.Gui.Mvvm;
using ADTierKit.Gui.Services;

namespace ADTierKit.Gui.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    public const string CustomPreset = "Custom";
    private const int MaxOutputLines = 20000;

    private readonly IShell _shell;
    private readonly GuiSettings _settings;
    private readonly PowerShellRunner _runner = new();
    private readonly RunSafety _safety = new();
    private readonly ConcurrentQueue<OutputLine> _pending = new();
    private readonly DispatcherTimer _flush;

    private string _scriptPath = string.Empty;
    private string _scriptInfo = string.Empty;
    private string _configurationPath = string.Empty;
    private string _configurationText = string.Empty;
    private string _configurationWarnings = string.Empty;
    private RunMode _mode = RunMode.Audit;
    private string _selectedPreset = "All stages";
    private bool _apply, _force, _skipPrerequisiteCheck, _requireSignedScript, _pinConfiguration, _noEventLog;
    private string _server = string.Empty, _logDirectory = string.Empty, _reportDirectory = string.Empty, _credentialDirectory = string.Empty;
    private string _commandLine = string.Empty;
    private bool _commandValid;
    private bool _isRunning;
    private bool _stopRequested;
    private string _statusText = "Ready.";
    private string _exitText = string.Empty;
    private LineKind _exitKind = LineKind.Normal;

    public MainViewModel(IShell shell, GuiSettings settings)
    {
        _shell = shell;
        _settings = settings;

        Stages = new ObservableCollection<StageItem>(
            TierKit.AllStages.Select(s => new StageItem(s, TierKit.StageDescriptions[s], OnStageClicked)));
        Presets = [.. TierKit.StagePresets.Keys, CustomPreset];

        _flush = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(100) };
        _flush.Tick += (_, _) => FlushOutput();
        _flush.Start();
        _runner.LineReceived += (line, isError) =>
            _pending.Enqueue(new OutputLine(line, isError ? LineKind.Error : OutputClassifier.Classify(line)));

        RunCommand = new RelayCommand(() => _ = RunAsync(), () => !IsRunning && _commandValid);
        StopCommand = new RelayCommand(Stop, () => IsRunning);
        BrowseScriptCommand = new RelayCommand(BrowseScript, () => !IsRunning);
        BrowseConfigurationCommand = new RelayCommand(BrowseConfiguration, () => !IsRunning);
        ReloadConfigurationCommand = new RelayCommand(LoadConfiguration);
        EditConfigurationCommand = new RelayCommand(EditConfiguration);
        StartWizardCommand = new RelayCommand(StartWizard, () => File.Exists(ScriptPath));
        CopyCommandLineCommand = new RelayCommand(() => { _shell.CopyText(CommandLine); StatusText = "Command line copied."; }, () => _commandValid);
        CopyOutputCommand = new RelayCommand(() => _shell.CopyText(string.Join(Environment.NewLine, Output.Select(o => o.Text))), () => Output.Count > 0);
        ClearOutputCommand = new RelayCommand(() => { Output.Clear(); ExitText = string.Empty; }, () => !IsRunning);
        OpenReportCommand = new RelayCommand(OpenReport);
        OpenLogsCommand = new RelayCommand(OpenLogs);
        RestartElevatedCommand = new RelayCommand(RestartElevated, () => !IsElevated && !IsRunning);

        var located = settings.ScriptPath is { } saved && File.Exists(saved) ? saved : ScriptInfo.Locate(AppContext.BaseDirectory);
        ScriptPath = located ?? string.Empty;
        ConfigurationPath = settings.ConfigurationPath is { } config && File.Exists(config) ? config : DefaultConfigurationPath();
        _server = settings.Server ?? string.Empty;
        _logDirectory = settings.LogDirectory ?? string.Empty;
        _reportDirectory = settings.ReportDirectory ?? string.Empty;
        _credentialDirectory = settings.CredentialDirectory ?? string.Empty;

        Output.Add(new OutputLine("Pick a mode and press Run. Nothing is written to Active Directory unless you choose Deploy with Apply, Sync or Install task.", LineKind.Skip));
        Output.Add(new OutputLine("Every run is ADTierKit.ps1 with the parameters shown above: logs, reports and exit codes are the same as from a console.", LineKind.Skip));
        UpdateCommand();
    }

    // --- bindable state -----------------------------------------------------------------------

    public ObservableCollection<StageItem> Stages { get; }
    public IReadOnlyList<string> Presets { get; }
    public ObservableCollection<OutputLine> Output { get; } = [];
    public IReadOnlyList<RunMode> Modes { get; } = Enum.GetValues<RunMode>();

    public bool IsElevated => _shell.IsElevated;
    public string ElevationText => IsElevated
        ? $"Elevated - {_shell.UserName}"
        : "Not elevated - Deploy, Sync and Install task need an elevated session";

    public string ScriptPath
    {
        get => _scriptPath;
        set
        {
            if (!SetProperty(ref _scriptPath, value)) return;
            var version = File.Exists(value) ? ScriptInfo.ReadVersion(value) : null;
            ScriptInfoText = File.Exists(value)
                ? $"ADTierKit {version ?? "(unknown version)"} - {value}"
                : $"{ScriptInfo.ScriptName} not found - choose it with Browse.";
            UpdateCommand();
        }
    }

    public string ScriptInfoText { get => _scriptInfo; private set => SetProperty(ref _scriptInfo, value); }

    public string ConfigurationPath
    {
        get => _configurationPath;
        set { if (SetProperty(ref _configurationPath, value)) LoadConfiguration(); }
    }

    public string ConfigurationText { get => _configurationText; private set => SetProperty(ref _configurationText, value); }

    public string ConfigurationWarnings
    {
        get => _configurationWarnings;
        private set { if (SetProperty(ref _configurationWarnings, value)) OnPropertyChanged(nameof(HasConfigurationWarnings)); }
    }

    public bool HasConfigurationWarnings => ConfigurationWarnings.Length > 0;

    public RunMode Mode
    {
        get => _mode;
        set
        {
            if (!SetProperty(ref _mode, value)) return;
            OnPropertyChanged(nameof(ModeDescription));
            OnPropertyChanged(nameof(IsDeploy));
            OnPropertyChanged(nameof(IsInstallTask));
            UpdateCommand();
        }
    }

    public string ModeDescription => TierKit.Describe(Mode);
    public bool IsDeploy => Mode == RunMode.Deploy;
    public bool IsInstallTask => Mode == RunMode.InstallTask;

    public string SelectedPreset
    {
        get => _selectedPreset;
        set
        {
            if (!SetProperty(ref _selectedPreset, value)) return;
            if (TierKit.StagePresets.TryGetValue(value, out var stages))
            {
                foreach (var item in Stages) item.Set(stages.Contains(item.Name));
                UpdateCommand();
            }
        }
    }

    public bool Apply { get => _apply; set { if (SetProperty(ref _apply, value)) UpdateCommand(); } }
    public bool Force { get => _force; set { if (SetProperty(ref _force, value)) UpdateCommand(); } }
    public bool SkipPrerequisiteCheck { get => _skipPrerequisiteCheck; set { if (SetProperty(ref _skipPrerequisiteCheck, value)) UpdateCommand(); } }
    public bool RequireSignedScript { get => _requireSignedScript; set { if (SetProperty(ref _requireSignedScript, value)) UpdateCommand(); } }
    public bool PinConfiguration { get => _pinConfiguration; set { if (SetProperty(ref _pinConfiguration, value)) UpdateCommand(); } }
    public bool NoEventLog { get => _noEventLog; set { if (SetProperty(ref _noEventLog, value)) UpdateCommand(); } }
    public string Server { get => _server; set { if (SetProperty(ref _server, value)) UpdateCommand(); } }
    public string LogDirectory { get => _logDirectory; set { if (SetProperty(ref _logDirectory, value)) UpdateCommand(); } }
    public string ReportDirectory { get => _reportDirectory; set { if (SetProperty(ref _reportDirectory, value)) UpdateCommand(); } }
    public string CredentialDirectory { get => _credentialDirectory; set { if (SetProperty(ref _credentialDirectory, value)) UpdateCommand(); } }

    public string CommandLine { get => _commandLine; private set => SetProperty(ref _commandLine, value); }

    public string RunButtonText => Mode switch
    {
        RunMode.Deploy => Apply ? "Apply" : "Plan",
        RunMode.InstallTask => "Register task",
        _ => $"Run {Mode}",
    };

    /// <summary>The run button turns red when the next press writes.</summary>
    public bool RunWrites => TierKit.Writes(CurrentOptions());

    public bool IsRunning
    {
        get => _isRunning;
        private set { if (SetProperty(ref _isRunning, value)) CommandManager.InvalidateRequerySuggested(); }
    }

    public string StatusText { get => _statusText; private set => SetProperty(ref _statusText, value); }
    public string ExitText { get => _exitText; private set => SetProperty(ref _exitText, value); }
    public LineKind ExitKind { get => _exitKind; private set => SetProperty(ref _exitKind, value); }

    public ICommand RunCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand BrowseScriptCommand { get; }
    public ICommand BrowseConfigurationCommand { get; }
    public ICommand ReloadConfigurationCommand { get; }
    public ICommand EditConfigurationCommand { get; }
    public ICommand StartWizardCommand { get; }
    public ICommand CopyCommandLineCommand { get; }
    public ICommand CopyOutputCommand { get; }
    public ICommand ClearOutputCommand { get; }
    public ICommand OpenReportCommand { get; }
    public ICommand OpenLogsCommand { get; }
    public ICommand RestartElevatedCommand { get; }

    // --- behaviour ------------------------------------------------------------------------------

    private string ScriptDirectory => Path.GetDirectoryName(ScriptPath) ?? AppContext.BaseDirectory;

    private string DefaultConfigurationPath() =>
        string.IsNullOrEmpty(ScriptPath) ? string.Empty : Path.Combine(ScriptDirectory, "config", "tiermodel.json");

    private RunOptions CurrentOptions() => new()
    {
        Mode = Mode,
        ConfigurationPath = ConfigurationPath,
        Server = Server,
        LogDirectory = LogDirectory,
        ReportDirectory = ReportDirectory,
        CredentialDirectory = CredentialDirectory,
        Stages = Stages.Where(s => s.IsSelected).Select(s => s.Name).ToList(),
        Apply = Apply,
        Force = Force,
        SkipPrerequisiteCheck = SkipPrerequisiteCheck,
        RequireSignedScript = RequireSignedScript,
        PinConfiguration = PinConfiguration,
        NoEventLog = NoEventLog,
    };

    private void OnStageClicked()
    {
        // A hand-made selection is a custom one; the preset no longer describes it.
        _selectedPreset = CustomPreset;
        OnPropertyChanged(nameof(SelectedPreset));
        UpdateCommand();
    }

    private void UpdateCommand()
    {
        OnPropertyChanged(nameof(RunButtonText));
        OnPropertyChanged(nameof(RunWrites));
        if (Stages is null) return;
        try
        {
            var arguments = CommandBuilder.BuildArguments(CurrentOptions());
            CommandLine = CommandBuilder.FormatCommandLine(string.IsNullOrEmpty(ScriptPath) ? ScriptInfo.ScriptName : ScriptPath, arguments);
            _commandValid = File.Exists(ScriptPath);
        }
        catch (ArgumentException ex)
        {
            CommandLine = "# " + ex.Message;
            _commandValid = false;
        }
        CommandManager.InvalidateRequerySuggested();
    }

    private void LoadConfiguration()
    {
        var summary = ConfigurationSummary.Load(ConfigurationPath);
        ConfigurationText = string.Join(Environment.NewLine, summary.Lines);
        ConfigurationWarnings = string.Join(Environment.NewLine, summary.Warnings);
        UpdateCommand();
    }

    private async Task RunAsync()
    {
        var options = CurrentOptions();
        IReadOnlyList<string> arguments;
        try { arguments = CommandBuilder.BuildArguments(options); }
        catch (ArgumentException ex) { _shell.Inform("ADTierKit", ex.Message); return; }

        if (!File.Exists(ScriptPath))
        {
            _shell.Inform("ADTierKit", $"{ScriptInfo.ScriptName} was not found at\n{ScriptPath}", isError: true);
            return;
        }

        // Read the file again: the plan key and the warnings are about what is on disk now.
        var summary = ConfigurationSummary.Load(ConfigurationPath);
        ConfigurationText = string.Join(Environment.NewLine, summary.Lines);
        ConfigurationWarnings = string.Join(Environment.NewLine, summary.Warnings);
        if (Mode != RunMode.Check && !summary.Valid)
        {
            _shell.Inform("ADTierKit", summary.Lines.Count > 0 ? summary.Lines[0] : "The configuration cannot be read.", isError: true);
            return;
        }

        if (TierKit.Writes(options) && !IsElevated &&
            !_shell.Confirm("Not elevated", "This window is not elevated, and this run writes to the directory or the machine. It will most likely fail.\n\nRun anyway?", warning: true))
        {
            return;
        }

        var planKey = CommandBuilder.PlanKey(arguments, summary.Hash);
        var gate = _safety.Evaluate(options, planKey, CommandLine);

        if (gate.PlanFirst)
        {
            var answer = _shell.AskYesNoCancel("Plan first?",
                "This exact deployment (same configuration file contents, same stages) has not been planned in this window yet.\n\n" +
                "Run the plan first? Choose No to apply without a plan.");
            if (answer is null) return;
            if (answer == true)
            {
                Apply = false;
                await StartAsync(CommandBuilder.BuildArguments(CurrentOptions()), planKey, isPlan: true);
                return;
            }
        }

        if (gate.Confirm && !_shell.Confirm(gate.Title, gate.Message, warning: options.Mode == RunMode.Deploy)) return;

        await StartAsync(arguments, planKey, isPlan: options.Mode == RunMode.Deploy && !options.Apply);
    }

    private async Task StartAsync(IReadOnlyList<string> arguments, string planKey, bool isPlan)
    {
        Output.Clear();
        ExitText = string.Empty;
        Output.Add(new OutputLine("> " + CommandBuilder.FormatCommandLine(ScriptPath, arguments), LineKind.Header));
        Output.Add(new OutputLine(string.Empty, LineKind.Normal));

        IsRunning = true;
        _stopRequested = false;
        var started = DateTime.Now;
        StatusText = $"Running since {started:HH:mm:ss}.";

        int code;
        try
        {
            var run = _runner.RunAsync(ScriptPath, arguments);
            StatusText = $"Running since {started:HH:mm:ss} - process {_runner.ProcessId}.";
            code = await run;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            FlushOutput();
            Output.Add(new OutputLine("Could not start Windows PowerShell: " + ex.Message, LineKind.Error));
            StatusText = "Not started.";
            IsRunning = false;
            return;
        }
        finally
        {
            _runner.Dispose();
        }

        FlushOutput();
        if (_stopRequested) code = -1;
        var meaning = TierKit.DescribeExitCode(code);
        var kind = code switch { 0 => LineKind.Success, 2 or 4 => LineKind.Warning, _ => LineKind.Error };
        Output.Add(new OutputLine(string.Empty, LineKind.Normal));
        Output.Add(new OutputLine(_stopRequested ? "Stopped." : $"Finished with exit code {code} - {meaning}.", kind));
        ExitText = _stopRequested ? "Stopped" : string.Create(CultureInfo.InvariantCulture, $"Exit code {code} - {meaning}");
        ExitKind = kind;
        StatusText = $"Finished at {DateTime.Now:HH:mm:ss} after {(DateTime.Now - started):mm\\:ss}.";

        if (isPlan && !_stopRequested) _safety.RecordPlan(planKey, code);
        IsRunning = false;
        UpdateCommand();
    }

    private void FlushOutput()
    {
        if (_pending.IsEmpty) return;
        while (_pending.TryDequeue(out var line)) Output.Add(line);
        // Thousands of lines would make the list sluggish; the transcript in the log folder has all of it.
        while (Output.Count > MaxOutputLines) Output.RemoveAt(0);
        OutputAppended?.Invoke();
    }

    /// <summary>Raised after new output lines were added, so the view can scroll.</summary>
    public event Action? OutputAppended;

    private void Stop()
    {
        if (!_shell.Confirm("Stop run",
                "Stop the running ADTierKit process?\n\nA deploy stopped half way leaves the stages it finished in place. Every stage is idempotent, so running the same command again converges the rest.",
                warning: true)) return;
        _stopRequested = true;
        _runner.Stop();
    }

    /// <summary>Asked by the window when it closes during a run.</summary>
    public bool ConfirmClose()
    {
        if (!IsRunning) return true;
        if (!_shell.Confirm("ADTierKit", "A run is still in progress. Stop it and close the window?", warning: true)) return false;
        _stopRequested = true;
        _runner.Stop();
        return true;
    }

    private void BrowseScript()
    {
        var path = _shell.PickFile("Choose ADTierKit.ps1", "ADTierKit|ADTierKit.ps1|PowerShell scripts (*.ps1)|*.ps1", ScriptPath);
        if (path is null) return;
        ScriptPath = path;
        if (!File.Exists(ConfigurationPath)) ConfigurationPath = DefaultConfigurationPath();
    }

    private void BrowseConfiguration()
    {
        var path = _shell.PickFile("Choose the tier model configuration", "Tier model configuration (*.json)|*.json|All files (*.*)|*.*", ConfigurationPath);
        if (path is not null) ConfigurationPath = path;
    }

    private void EditConfiguration()
    {
        if (!File.Exists(ConfigurationPath))
        {
            _shell.Inform("ADTierKit", $"No configuration at\n{ConfigurationPath}\n\nStart the wizard to create one.");
            return;
        }
        _shell.OpenWithEditor(ConfigurationPath);
    }

    private void StartWizard()
    {
        _shell.StartWizard(ScriptPath, string.IsNullOrWhiteSpace(ConfigurationPath) ? null : ConfigurationPath);
        StatusText = "The wizard runs in its own console window. Press Reload when it has written the configuration.";
    }

    private string Folder(string explicitValue, string defaultName) =>
        string.IsNullOrWhiteSpace(explicitValue) ? Path.Combine(ScriptDirectory, defaultName) : explicitValue.Trim();

    private void OpenReport()
    {
        var folder = Folder(ReportDirectory, "Reports");
        var latest = ScriptInfo.LatestReport(folder);
        if (latest is null) StatusText = $"No report yet in {folder}.";
        else _shell.OpenDocument(latest);
    }

    private void OpenLogs()
    {
        var folder = Folder(LogDirectory, "Logs");
        if (Directory.Exists(folder)) _shell.OpenFolder(folder);
        else StatusText = $"No log folder yet at {folder}.";
    }

    private void RestartElevated()
    {
        SaveSettings();
        if (_shell.RestartElevated()) System.Windows.Application.Current.Shutdown();
    }

    public void SaveSettings()
    {
        _settings.ScriptPath = ScriptPath;
        _settings.ConfigurationPath = ConfigurationPath;
        _settings.Server = Server;
        _settings.LogDirectory = LogDirectory;
        _settings.ReportDirectory = ReportDirectory;
        _settings.CredentialDirectory = CredentialDirectory;
        _settings.Save();
    }

    public void Dispose()
    {
        _flush.Stop();
        _runner.Dispose();
    }
}
