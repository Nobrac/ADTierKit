namespace ADTierKit.Gui.Core;

/// <summary>What the window has chosen for one run of ADTierKit.ps1.</summary>
public sealed record RunOptions
{
    public RunMode Mode { get; init; } = RunMode.Audit;
    public string? ConfigurationPath { get; init; }
    public string? Server { get; init; }
    public string? LogDirectory { get; init; }
    public string? ReportDirectory { get; init; }
    public string? CredentialDirectory { get; init; }
    public IReadOnlyCollection<string> Stages { get; init; } = TierKit.AllStages;
    public bool Apply { get; init; }
    public bool Force { get; init; }
    public bool SkipPrerequisiteCheck { get; init; }
    public bool RequireSignedScript { get; init; }
    public bool PinConfiguration { get; init; }
    public bool NoEventLog { get; init; }
}
