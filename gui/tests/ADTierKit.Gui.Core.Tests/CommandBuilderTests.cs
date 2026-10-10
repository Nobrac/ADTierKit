using ADTierKit.Gui.Core;

namespace ADTierKit.Gui.Core.Tests;

public class CommandBuilderTests
{
    private static RunOptions Deploy(params string[] stages) => new() { Mode = RunMode.Deploy, Stages = stages };

    [Fact]
    public void Stages_are_passed_in_canonical_order()
    {
        var args = CommandBuilder.BuildArguments(Deploy("GPO", "OU", "Group"));
        Assert.Equal("-Stage OU,Group,GPO", string.Join(' ', args.SkipWhile(a => a != "-Stage").Take(2)));
    }

    [Fact]
    public void All_stages_selected_passes_no_stage_parameter()
    {
        Assert.DoesNotContain("-Stage", CommandBuilder.BuildArguments(Deploy([.. TierKit.AllStages])));
    }

    [Fact]
    public void Deploy_without_a_stage_is_refused()
    {
        Assert.Throws<ArgumentException>(() => CommandBuilder.BuildArguments(Deploy()));
    }

    [Fact]
    public void Apply_is_passed_only_when_ticked()
    {
        Assert.DoesNotContain("-Apply", CommandBuilder.BuildArguments(Deploy("OU")));
        Assert.Contains("-Apply", CommandBuilder.BuildArguments(Deploy("OU") with { Apply = true }));
    }

    [Fact]
    public void Deploy_switches_do_not_leak_into_other_modes()
    {
        var options = new RunOptions { Mode = RunMode.Audit, Apply = true, Force = true, SkipPrerequisiteCheck = true, Stages = ["OU"], CredentialDirectory = @"C:\c" };
        var args = CommandBuilder.BuildArguments(options);
        Assert.Equal(["-Mode", "Audit"], args);
    }

    [Fact]
    public void NoEventLog_is_not_passed_to_modes_that_do_not_take_it()
    {
        Assert.DoesNotContain("-NoEventLog", CommandBuilder.BuildArguments(new RunOptions { Mode = RunMode.Check, NoEventLog = true }));
        Assert.Contains("-NoEventLog", CommandBuilder.BuildArguments(new RunOptions { Mode = RunMode.Sync, NoEventLog = true }));
    }

    [Fact]
    public void InstallTask_passes_signing_and_pinning()
    {
        var args = CommandBuilder.BuildArguments(new RunOptions { Mode = RunMode.InstallTask, RequireSignedScript = true, PinConfiguration = true });
        Assert.Contains("-RequireSignedScript", args);
        Assert.Contains("-PinConfiguration", args);
    }

    [Fact]
    public void Blank_values_are_left_out_and_values_are_trimmed()
    {
        var args = CommandBuilder.BuildArguments(new RunOptions { Mode = RunMode.Audit, Server = "  dc01.lab.example  ", LogDirectory = "   " });
        Assert.Equal(["-Mode", "Audit", "-Server", "dc01.lab.example"], args);
    }

    [Theory]
    [InlineData("-Apply", "-Apply")]
    [InlineData("OU,Group,GPO", "OU,Group,GPO")]
    [InlineData(@"C:\Tools\tiermodel.json", @"C:\Tools\tiermodel.json")]
    [InlineData(@"C:\Tier Config\tiermodel.json", @"'C:\Tier Config\tiermodel.json'")]
    [InlineData("O'Brien", "'O''Brien'")]
    [InlineData("a\u2019b", "'a\u2019\u2019b'")]
    [InlineData("a;Remove-Item x", "'a;Remove-Item x'")]
    [InlineData("$(whoami)", "'$(whoami)'")]
    [InlineData("`n", "'`n'")]
    [InlineData("-x y", "'-x y'")]
    [InlineData("", "''")]
    public void Values_are_quoted_so_they_cannot_become_code(string value, string expected)
    {
        Assert.Equal(expected, CommandBuilder.ToPowerShellToken(value));
    }

    [Fact]
    public void Command_line_is_what_a_person_would_type()
    {
        var args = CommandBuilder.BuildArguments(Deploy("OU", "Group") with { ConfigurationPath = @"C:\Tier Config\tiermodel.json", Apply = true });
        Assert.Equal(@".\ADTierKit.ps1 -Mode Deploy -ConfigurationPath 'C:\Tier Config\tiermodel.json' -Stage OU,Group -Apply",
            CommandBuilder.FormatCommandLine(@"C:\Tools\ADTierKit\ADTierKit.ps1", args));
    }

    [Fact]
    public void Invocation_quotes_the_script_and_hands_back_the_exit_code()
    {
        var command = CommandBuilder.BuildInvocation(@"C:\It's here\ADTierKit.ps1", ["-Mode", "Audit"]);
        Assert.Contains(@"& 'C:\It''s here\ADTierKit.ps1' -Mode Audit; exit $LASTEXITCODE", command, StringComparison.Ordinal);
        Assert.StartsWith("[Console]::OutputEncoding", command, StringComparison.Ordinal);
    }

    [Fact]
    public void Encoded_command_is_utf16_base64()
    {
        Assert.Equal("ZQB4AGkAdAAgADMA", CommandBuilder.Encode("exit 3"));
    }

    [Fact]
    public void Process_arguments_never_use_File()
    {
        var args = CommandBuilder.BuildProcessArguments(@"C:\x\ADTierKit.ps1", ["-Mode", "Audit"]);
        Assert.DoesNotContain("-File", args);
        Assert.Equal("-EncodedCommand", args[^2]);
        Assert.Contains("-NonInteractive", args);
        Assert.Equal("Text", args[args.ToList().IndexOf("-OutputFormat") + 1]);
    }

    [Fact]
    public void An_apply_matches_its_plan_and_nothing_else()
    {
        static string Key(RunOptions o, string hash) => CommandBuilder.PlanKey(CommandBuilder.BuildArguments(o), hash);
        var plan = Key(Deploy("OU"), "H");
        Assert.Equal(plan, Key(Deploy("OU") with { Apply = true, Force = true, SkipPrerequisiteCheck = true, NoEventLog = true }, "H"));
        Assert.NotEqual(plan, Key(Deploy("OU", "GPO") with { Apply = true }, "H"));
        Assert.NotEqual(plan, Key(Deploy("OU") with { Apply = true }, "changed"));
        Assert.NotEqual(plan, Key(Deploy("OU") with { Apply = true, Server = "dc02" }, "H"));
    }
}
