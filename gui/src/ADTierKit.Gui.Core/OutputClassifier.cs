using System.Text.RegularExpressions;

namespace ADTierKit.Gui.Core;

public enum LineKind
{
    Normal,
    Header,
    Success,
    Skip,
    Warning,
    Error,
    Plan,
    Info,
}

/// <summary>
/// Maps a line of ADTierKit output to a kind, following the markers Write-TierLog writes:
/// === header ===, [+] success, [=] skip, [~] plan, [!] error, [i] info, and WARNING: from Write-Warning.
/// </summary>
public static partial class OutputClassifier
{
    public static LineKind Classify(string? line)
    {
        if (string.IsNullOrEmpty(line)) return LineKind.Normal;
        if (Header().IsMatch(line)) return LineKind.Header;
        if (Success().IsMatch(line)) return LineKind.Success;
        if (Error().IsMatch(line)) return LineKind.Error;
        if (Warning().IsMatch(line)) return LineKind.Warning;
        if (Plan().IsMatch(line)) return LineKind.Plan;
        if (Skip().IsMatch(line)) return LineKind.Skip;
        if (Info().IsMatch(line)) return LineKind.Info;
        return LineKind.Normal;
    }

    [GeneratedRegex(@"^\s*===")]
    private static partial Regex Header();

    [GeneratedRegex(@"^\s*\[\+\]")]
    private static partial Regex Success();

    [GeneratedRegex(@"^\s*\[!\]|^\s*ERROR|^\s*At line:|Exception")]
    private static partial Regex Error();

    [GeneratedRegex(@"^\s*WARNING:")]
    private static partial Regex Warning();

    [GeneratedRegex(@"^\s*\[~\]")]
    private static partial Regex Plan();

    [GeneratedRegex(@"^\s*\[=\]")]
    private static partial Regex Skip();

    [GeneratedRegex(@"^\s*\[i\]")]
    private static partial Regex Info();
}
