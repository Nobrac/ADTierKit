using ADTierKit.Gui.Core;

namespace ADTierKit.Gui.Core.Tests;

public sealed class ConfigurationSummaryTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("adtk-cfg-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Write(string json, bool bom = false)
    {
        var path = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, json, new System.Text.UTF8Encoding(bom));
        return path;
    }

    [Fact]
    public void Shipped_configuration_is_summarised()
    {
        var summary = ConfigurationSummary.Load(Path.Combine(ScriptContractTests.RepositoryRoot, "config", "tiermodel.json"));
        Assert.True(summary.Valid);
        Assert.True(summary.Lines.Count >= 6);
        Assert.Contains(summary.Lines, l => l.StartsWith("Tiers: ", StringComparison.Ordinal));
        Assert.Equal(64, summary.Hash.Length);
    }

    [Fact]
    public void Missing_file_is_reported()
    {
        var summary = ConfigurationSummary.Load(Path.Combine(_dir, "none.json"));
        Assert.False(summary.Exists);
        Assert.False(summary.Valid);
    }

    [Fact]
    public void Invalid_json_is_reported_not_thrown()
    {
        var summary = ConfigurationSummary.Load(Write("{ \"tiers\": [ "));
        Assert.True(summary.Exists);
        Assert.False(summary.Valid);
        Assert.StartsWith("Not valid JSON", summary.Lines[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Byte_order_mark_is_accepted()
    {
        Assert.True(ConfigurationSummary.Load(Write("{ \"metadata\": { \"name\": \"x\" } }", bom: true)).Valid);
    }

    [Fact]
    public void Settings_that_remove_access_are_warned_about()
    {
        var summary = ConfigurationSummary.Load(Write("""
            {
              "options": { "restrictedGroupsMode": "Replace", "createAuthenticationPolicySilo": true, "authenticationPolicyEnforcement": "Enforce" },
              "privilegedGroups": { "mode": "Enforce" },
              "ownership": { "mode": "Enforce" }
            }
            """));
        Assert.Equal(4, summary.Warnings.Count);
    }

    [Fact]
    public void Staging_is_off_only_when_disabled()
    {
        Assert.Contains(ConfigurationSummary.Load(Write("""{ "staging": { "enabled": false } }""")).Lines, l => l.StartsWith("Neutral staging OU: off", StringComparison.Ordinal));
        Assert.Contains(ConfigurationSummary.Load(Write("""{ "staging": { } }""")).Lines, l => l.StartsWith("Neutral staging OU: on", StringComparison.Ordinal));
    }

    [Fact]
    public void Hash_follows_the_contents()
    {
        Assert.NotEqual(ConfigurationSummary.Load(Write("{}")).Hash, ConfigurationSummary.Load(Write("{ }")).Hash);
    }
}

public class RunSafetyTests
{
    private static readonly RunOptions Apply = new() { Mode = RunMode.Deploy, Apply = true, Stages = ["OU", "GPO"] };

    [Fact]
    public void An_apply_without_a_plan_asks_for_one()
    {
        var safety = new RunSafety();
        Assert.True(safety.Evaluate(Apply, "k", "cmd").PlanFirst);
        safety.RecordPlan("k", 0);
        Assert.False(safety.Evaluate(Apply, "k", "cmd").PlanFirst);
        Assert.True(safety.Evaluate(Apply, "other", "cmd").PlanFirst);
    }

    [Fact]
    public void A_plan_that_failed_its_prerequisites_does_not_count()
    {
        var safety = new RunSafety();
        safety.RecordPlan("k", 3);
        Assert.True(safety.Evaluate(Apply, "k", "cmd").PlanFirst);
    }

    [Fact]
    public void Every_apply_is_confirmed_with_its_risks()
    {
        var gate = new RunSafety().Evaluate(Apply with { Force = true }, "k", "THE-COMMAND");
        Assert.True(gate.Confirm);
        Assert.Contains("THE-COMMAND", gate.Message, StringComparison.Ordinal);
        Assert.Contains("-Force", gate.Message, StringComparison.Ordinal);
        Assert.Contains("tattooed", gate.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(RunMode.Sync, true)]
    [InlineData(RunMode.InstallTask, true)]
    [InlineData(RunMode.Audit, false)]
    [InlineData(RunMode.Check, false)]
    public void Writing_modes_are_confirmed(RunMode mode, bool confirm)
    {
        var gate = new RunSafety().Evaluate(new RunOptions { Mode = mode }, "k", "cmd");
        Assert.Equal(confirm, gate.Confirm);
        Assert.False(gate.PlanFirst);
    }

    [Fact]
    public void A_plan_needs_no_confirmation()
    {
        var gate = new RunSafety().Evaluate(Apply with { Apply = false }, "k", "cmd");
        Assert.False(gate.Confirm);
        Assert.False(gate.PlanFirst);
    }
}

public class OutputClassifierTests
{
    [Theory]
    [InlineData("=== Stage: OU ===", LineKind.Header)]
    [InlineData("  [+] Created OU=Tier0", LineKind.Success)]
    [InlineData("  [=] Exists: G-T0-Admins", LineKind.Skip)]
    [InlineData("  [~] Would create G-T0-Admins", LineKind.Plan)]
    [InlineData("  [!] Failed: access denied", LineKind.Error)]
    [InlineData("  [i] Using DC01", LineKind.Info)]
    [InlineData("WARNING: lockout risk is unverified", LineKind.Warning)]
    [InlineData("plain", LineKind.Normal)]
    [InlineData("", LineKind.Normal)]
    public void Markers_map_to_kinds(string line, LineKind kind)
    {
        Assert.Equal(kind, OutputClassifier.Classify(line));
    }
}

public class TierKitTests
{
    [Theory]
    [InlineData(RunMode.Deploy, false, false)]
    [InlineData(RunMode.Deploy, true, true)]
    [InlineData(RunMode.Sync, false, true)]
    [InlineData(RunMode.InstallTask, false, true)]
    [InlineData(RunMode.Audit, true, false)]
    public void Writes_is_true_only_for_writing_runs(RunMode mode, bool apply, bool writes)
    {
        Assert.Equal(writes, TierKit.Writes(new RunOptions { Mode = mode, Apply = apply }));
    }

    [Fact]
    public void Exit_codes_are_translated()
    {
        Assert.Equal("audit found drift", TierKit.DescribeExitCode(2));
        Assert.Equal("unexpected exit code", TierKit.DescribeExitCode(99));
    }

    [Fact]
    public void Script_is_located_from_a_build_folder()
    {
        var root = ScriptContractTests.RepositoryRoot;
        Assert.Equal(Path.Combine(root, ScriptInfo.ScriptName), ScriptInfo.Locate(Path.Combine(root, "gui", "src", "x")) ?? ScriptInfo.Locate(Path.Combine(root, "gui")));
    }
}
