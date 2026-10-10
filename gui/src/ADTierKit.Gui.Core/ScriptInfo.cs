using System.Text.RegularExpressions;

namespace ADTierKit.Gui.Core;

/// <summary>Finds ADTierKit.ps1 and reads what the window shows about it.</summary>
public static partial class ScriptInfo
{
    public const string ScriptName = "ADTierKit.ps1";

    /// <summary>
    /// Looks for ADTierKit.ps1 next to the application and in up to four parent folders, which
    /// covers both a published copy beside the script and a build output inside the repository.
    /// </summary>
    public static string? Locate(string startDirectory)
    {
        var directory = new DirectoryInfo(startDirectory);
        for (var i = 0; i < 5 && directory is not null; i++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, ScriptName);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    /// <summary>The value of $script:TierKitVersion, or null.</summary>
    public static string? ReadVersion(string scriptPath)
    {
        try
        {
            foreach (var line in File.ReadLines(scriptPath))
            {
                var match = VersionLine().Match(line);
                if (match.Success) return match.Groups[1].Value;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return null;
    }

    /// <summary>The newest HTML report in a folder, or null.</summary>
    public static string? LatestReport(string reportDirectory)
    {
        if (!Directory.Exists(reportDirectory)) return null;
        return new DirectoryInfo(reportDirectory).EnumerateFiles("ADTierKit-*.html")
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Select(f => f.FullName)
            .FirstOrDefault();
    }

    [GeneratedRegex(@"^\$script:TierKitVersion\s*=\s*'([^']+)'")]
    private static partial Regex VersionLine();
}
