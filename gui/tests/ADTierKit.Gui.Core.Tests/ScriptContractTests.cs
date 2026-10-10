using System.Diagnostics;
using System.Text.RegularExpressions;
using ADTierKit.Gui.Core;

namespace ADTierKit.Gui.Core.Tests;

/// <summary>
/// The window must agree with ADTierKit.ps1: same stages, same modes, only parameters that exist,
/// and arguments that bind the way the console binds them.
/// </summary>
public partial class ScriptContractTests
{
    internal static string RepositoryRoot
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            {
                if (File.Exists(Path.Combine(dir.FullName, ScriptInfo.ScriptName))) return dir.FullName;
            }
            throw new InvalidOperationException("ADTierKit.ps1 not found above the test output.");
        }
    }

    private static readonly string Script = File.ReadAllText(Path.Combine(RepositoryRoot, ScriptInfo.ScriptName));

    private static string ParamBlock => ParamBlockRegex().Match(Script).Value;

    private static string[] ValidateSetOf(string parameter)
    {
        var match = Regex.Match(ParamBlock, @"\[ValidateSet\(([^)]*)\)\]\s*\[string(?:\[\])?\]\$" + parameter + @"\b");
        Assert.True(match.Success, $"ValidateSet of -{parameter} not found");
        return [.. Regex.Matches(match.Groups[1].Value, "'([^']+)'").Select(m => m.Groups[1].Value)];
    }

    [Fact]
    public void Stages_match_the_script()
    {
        Assert.Equal(ValidateSetOf("Stage"), TierKit.AllStages);
    }

    [Fact]
    public void Every_stage_has_a_description_and_presets_use_real_stages()
    {
        Assert.All(TierKit.AllStages, s => Assert.True(TierKit.StageDescriptions.ContainsKey(s), s));
        Assert.All(TierKit.StagePresets.Values.SelectMany(p => p), s => Assert.Contains(s, TierKit.AllStages));
    }

    [Fact]
    public void Every_mode_exists_in_the_script()
    {
        var modes = ValidateSetOf("Mode");
        Assert.All(Enum.GetNames<RunMode>(), m => Assert.Contains(m, modes));
    }

    [Fact]
    public void Every_parameter_the_window_passes_exists()
    {
        var parameters = ParameterName().Matches(ParamBlock).Select(m => m.Groups[1].Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var everything = new RunOptions
        {
            ConfigurationPath = "c", Server = "s", LogDirectory = "l", ReportDirectory = "r", CredentialDirectory = "d",
            Apply = true, Force = true, SkipPrerequisiteCheck = true, RequireSignedScript = true, PinConfiguration = true, NoEventLog = true,
            Stages = ["OU"],
        };
        foreach (var mode in Enum.GetValues<RunMode>())
        {
            var names = CommandBuilder.BuildArguments(everything with { Mode = mode }).Where(a => a.StartsWith('-')).Select(a => a[1..]);
            Assert.All(names, n => Assert.Contains(n, parameters));
        }
    }

    [Fact]
    public void Version_is_read_from_the_script()
    {
        var version = ScriptInfo.ReadVersion(Path.Combine(RepositoryRoot, ScriptInfo.ScriptName));
        Assert.NotNull(version);
        Assert.Matches(@"^\d+\.\d+\.\d+", version);
    }

    /// <summary>
    /// Runs the real invocation against a stand-in script when PowerShell is installed (it is on
    /// the CI runners): -Stage must arrive as an array, odd paths must survive, the exit code must
    /// come back, and non-ASCII output must arrive intact.
    /// </summary>
    [Fact]
    public void Invocation_binds_like_the_console()
    {
        var pwsh = FindPowerShell();
        if (pwsh is null) return;

        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "adtk-gui-" + Guid.NewGuid().ToString("N"), "with space ä"));
        try
        {
            var probe = Path.Combine(dir.FullName, "probe'.ps1");
            File.WriteAllText(probe, """
                param([string]$Mode, [string]$ConfigurationPath, [ValidateSet('OU','Group','GPO')][string[]]$Stage, [switch]$Apply)
                Write-Host "$Mode|$ConfigurationPath|$($Stage -join '+')|$Apply|Grüße"
                exit 4
                """, new System.Text.UTF8Encoding(true));

            var args = CommandBuilder.BuildArguments(new RunOptions
            {
                Mode = RunMode.Deploy, ConfigurationPath = @"C:\Tier Config\it's.json", Stages = ["GPO", "OU", "Group"], Apply = true,
            });

            var info = new ProcessStartInfo(pwsh)
            {
                RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
            };
            foreach (var a in CommandBuilder.BuildProcessArguments(probe, args).Where(a => a != "-ExecutionPolicy" && a != "Bypass")) info.ArgumentList.Add(a);

            using var process = Process.Start(info)!;
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            Assert.True(string.IsNullOrWhiteSpace(error), error);
            Assert.Equal(@"Deploy|C:\Tier Config\it's.json|OU+Group+GPO|True|Grüße", output.Trim());
            Assert.Equal(4, process.ExitCode);
        }
        finally
        {
            Directory.Delete(dir.Parent!.FullName, recursive: true);
        }
    }

    private static string? FindPowerShell()
    {
        var names = OperatingSystem.IsWindows() ? new[] { "pwsh.exe", "powershell.exe" } : ["pwsh"];
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        return path.Split(Path.PathSeparator)
            .SelectMany(d => names.Select(n => Path.Combine(d, n)))
            .FirstOrDefault(File.Exists);
    }

    [GeneratedRegex(@"(?s)^\[CmdletBinding[^\]]*\]\s*param\(.*?^\)", RegexOptions.Multiline)]
    private static partial Regex ParamBlockRegex();

    [GeneratedRegex(@"\]\s*\$([A-Za-z]+)")]
    private static partial Regex ParameterName();
}
