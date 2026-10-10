using System.Text;
using System.Text.RegularExpressions;

namespace ADTierKit.Gui.Core;

/// <summary>
/// Builds the ADTierKit.ps1 parameter list from the window's choices, the command a person would
/// type for the same run, and the command the child process actually runs.
/// </summary>
public static partial class CommandBuilder
{
    /// <summary>
    /// The parameters for ADTierKit.ps1. Only what differs from the script's defaults is passed, so
    /// the command line shown is the one a person would type.
    /// </summary>
    /// <exception cref="ArgumentException">Deploy without a stage.</exception>
    public static IReadOnlyList<string> BuildArguments(RunOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var list = new List<string> { "-Mode", options.Mode.ToString() };

        AddValue(list, "-ConfigurationPath", options.ConfigurationPath);
        AddValue(list, "-Server", options.Server);
        AddValue(list, "-LogDirectory", options.LogDirectory);
        AddValue(list, "-ReportDirectory", options.ReportDirectory);

        switch (options.Mode)
        {
            case RunMode.Deploy:
                // Canonical order, so equal selections give equal command lines and plan keys.
                var ordered = TierKit.AllStages.Where(s => options.Stages.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();
                if (ordered.Count == 0) throw new ArgumentException("Pick at least one stage.", nameof(options));
                if (ordered.Count != TierKit.AllStages.Count) { list.Add("-Stage"); list.Add(string.Join(',', ordered)); }
                AddValue(list, "-CredentialDirectory", options.CredentialDirectory);
                if (options.Apply) list.Add("-Apply");
                if (options.Force) list.Add("-Force");
                if (options.SkipPrerequisiteCheck) list.Add("-SkipPrerequisiteCheck");
                break;
            case RunMode.InstallTask:
                if (options.RequireSignedScript) list.Add("-RequireSignedScript");
                if (options.PinConfiguration) list.Add("-PinConfiguration");
                break;
        }

        if (options.NoEventLog && options.Mode is RunMode.Deploy or RunMode.Audit or RunMode.Sync) list.Add("-NoEventLog");
        return list;
    }

    private static void AddValue(List<string> list, string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        list.Add(name);
        list.Add(value.Trim());
    }

    /// <summary>
    /// One argument as PowerShell source: parameter names and plain words as they are, anything
    /// else in single quotes with embedded quotes doubled. Single quotes expand nothing, so no
    /// value can become code.
    /// </summary>
    public static string ToPowerShellToken(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (ParameterName().IsMatch(value)) return value;
        // Commas stay unquoted on purpose: "-Stage OU,Group" has to reach the script as an array.
        if (PlainWord().IsMatch(value)) return value;
        return ToPowerShellQuoted(value);
    }

    /// <summary>The command a person would type in an elevated console in the script's folder.</summary>
    public static string FormatCommandLine(string scriptPath, IEnumerable<string> arguments)
    {
        var parts = new List<string> { ".\\" + Path.GetFileName(scriptPath.Replace('\\', Path.DirectorySeparatorChar)) };
        parts.AddRange(arguments.Select(ToPowerShellToken));
        return string.Join(' ', parts);
    }

    /// <summary>
    /// The PowerShell source the child process runs.
    /// </summary>
    /// <remarks>
    /// powershell.exe -File passes every argument as a single string, so "-Stage OU,Group" would
    /// arrive as one stage called "OU,Group" and fail validation. The run therefore goes through
    /// -EncodedCommand with the same tokens the command box shows. Output is switched to UTF-8 so
    /// umlauts in OU names survive the pipe, progress bars are suppressed (they are noise without
    /// a console), and the script's exit code is handed back to the process.
    /// </remarks>
    public static string BuildInvocation(string scriptPath, IEnumerable<string> arguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scriptPath);
        var sb = new StringBuilder();
        sb.Append("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); ");
        sb.Append("$ProgressPreference = 'SilentlyContinue'; ");
        sb.Append("& ").Append(ToPowerShellQuoted(scriptPath));
        foreach (var token in arguments.Select(ToPowerShellToken)) sb.Append(' ').Append(token);
        sb.Append("; exit $LASTEXITCODE");
        return sb.ToString();
    }

    /// <summary>A single-quoted PowerShell string literal.</summary>
    /// <remarks>PowerShell also accepts the typographic single quotes as delimiters; they are doubled too.</remarks>
    private static string ToPowerShellQuoted(string value)
    {
        var sb = new StringBuilder(value.Length + 2).Append('\'');
        foreach (var c in value)
        {
            sb.Append(c);
            if (c is '\'' or '\u2018' or '\u2019' or '\u201A' or '\u201B') sb.Append(c);
        }
        return sb.Append('\'').ToString();
    }

    /// <summary>The value for powershell.exe -EncodedCommand: Base64 of UTF-16LE.</summary>
    public static string Encode(string command) => Convert.ToBase64String(Encoding.Unicode.GetBytes(command));

    /// <summary>The powershell.exe arguments for a run.</summary>
    /// <remarks>
    /// -OutputFormat Text is not optional: with -EncodedCommand and a redirected parent, PowerShell
    /// otherwise serialises the host and information streams as CLIXML onto stderr, and every
    /// Write-Host line of the tool would arrive as XML.
    /// </remarks>
    public static IReadOnlyList<string> BuildProcessArguments(string scriptPath, IEnumerable<string> arguments) =>
    [
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-OutputFormat", "Text",
        "-EncodedCommand", Encode(BuildInvocation(scriptPath, arguments)),
    ];

    /// <summary>
    /// Identifies a run independently of the switches that only change whether and how forcefully
    /// it writes, so an apply can be matched to the plan the operator has seen.
    /// </summary>
    public static string PlanKey(IEnumerable<string> arguments, string configurationHash)
    {
        string[] ignored = ["-Apply", "-Force", "-SkipPrerequisiteCheck", "-NoEventLog"];
        var relevant = arguments.Where(a => !ignored.Contains(a, StringComparer.OrdinalIgnoreCase));
        return string.Join('\u001f', relevant) + "|" + configurationHash;
    }

    [GeneratedRegex(@"^-[A-Za-z]+$")]
    private static partial Regex ParameterName();

    [GeneratedRegex(@"^[A-Za-z0-9_.,:\\/]+$")]
    private static partial Regex PlainWord();
}
