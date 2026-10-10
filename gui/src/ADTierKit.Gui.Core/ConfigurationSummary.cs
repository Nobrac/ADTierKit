using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace ADTierKit.Gui.Core;

/// <summary>The facts about a configuration file worth seeing before a run.</summary>
public sealed record ConfigurationSummary(bool Exists, bool Valid, IReadOnlyList<string> Lines, IReadOnlyList<string> Warnings, string Hash)
{
    private static readonly JsonDocumentOptions ReadOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    public static ConfigurationSummary Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new(false, false, [$"No configuration at {path} - start the wizard to create one."], [], string.Empty);
        }

        byte[] bytes;
        try { bytes = File.ReadAllBytes(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(true, false, [$"Cannot read the file: {ex.Message}"], [], string.Empty);
        }

        var hash = Convert.ToHexString(SHA256.HashData(bytes));
        try
        {
            using var document = JsonDocument.Parse(StripBom(bytes), ReadOptions);
            var (lines, warnings) = Summarise(document.RootElement);
            return new(true, true, lines, warnings, hash);
        }
        catch (JsonException ex)
        {
            return new(true, false, [$"Not valid JSON: {ex.Message}"], [], hash);
        }
    }

    private static ReadOnlyMemory<byte> StripBom(byte[] bytes) =>
        bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? bytes.AsMemory(3) : bytes;

    private static (List<string> Lines, List<string> Warnings) Summarise(JsonElement root)
    {
        var lines = new List<string>();
        var warnings = new List<string>();

        var name = Text(root, "metadata", "name") ?? "(unnamed)";
        var revision = Text(root, "metadata", "revision");
        lines.Add(revision is null ? name : $"{name} - revision {revision}");
        lines.Add($"Domain {Text(root, "domain", "fqdn") ?? "(current domain)"}, root OU '{Text(root, "domain", "rootOu")}', schema {Text(root, "schemaVersion")}");

        if (root.TryGetProperty("tiers", out var tiers) && tiers.ValueKind == JsonValueKind.Array)
        {
            var parts = tiers.EnumerateArray().Select(t =>
                $"{Text(t, "name")} ({Count(t, "groups")} groups, {Count(t, "gpos")} GPOs)");
            lines.Add("Tiers: " + string.Join(", ", parts));
        }

        var siloOn = Flag(root, "options", "createAuthenticationPolicySilo");
        var enforcement = Text(root, "options", "authenticationPolicyEnforcement") ?? "Audit";
        lines.Add($"Silos: {(siloOn ? "on" : "off")}, enforcement {enforcement}");

        var restricted = Text(root, "options", "restrictedGroupsMode") ?? "MemberOf";
        lines.Add($"GPOs: {(Flag(root, "options", "createGpos") ? "on" : "off")}, links {(Flag(root, "options", "enforceGpoLinks") ? "enforced" : "not enforced")}, restricted groups {restricted}");

        var privileged = Has(root, "privilegedGroups") ? Text(root, "privilegedGroups", "mode") ?? "Report" : "not configured";
        var ownership = Has(root, "ownership") ? Text(root, "ownership", "mode") ?? "Report" : "not configured";
        lines.Add($"Privileged groups: {privileged}, ownership: {ownership}");

        // Staging is on when the block exists and does not say enabled = false.
        var staging = Has(root, "staging") && !(root.GetProperty("staging").TryGetProperty("enabled", out var e) && e.ValueKind == JsonValueKind.False);
        lines.Add($"Neutral staging OU: {(staging ? "on" : "off")}, Windows LAPS: {(Flag(root, "windowsLaps", "enabled") ? "on" : "off")}");

        if (string.Equals(restricted, "Replace", StringComparison.OrdinalIgnoreCase))
            warnings.Add("Restricted groups mode is Replace - every other member of the local Administrators group is removed.");
        if (string.Equals(privileged, "Enforce", StringComparison.OrdinalIgnoreCase))
            warnings.Add("Privileged groups are in Enforce mode - undeclared members are removed.");
        if (string.Equals(ownership, "Enforce", StringComparison.OrdinalIgnoreCase))
            warnings.Add("Ownership is in Enforce mode - owners outside the accepted set are replaced.");
        if (siloOn && string.Equals(enforcement, "Enforce", StringComparison.OrdinalIgnoreCase))
            warnings.Add("Silos are enforced - accounts outside their silo devices cannot sign in.");
        if (Flag(root, "options", "kdsRootKeyEffectiveImmediately"))
            warnings.Add("The KDS root key is backdated - lab setting only.");

        return (lines, warnings);
    }

    private static bool Has(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object;

    private static JsonElement? Find(JsonElement element, params string[] path)
    {
        foreach (var segment in path)
        {
            if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(segment, out element)) return null;
        }
        return element;
    }

    private static string? Text(JsonElement element, params string[] path)
    {
        var value = Find(element, path);
        if (value is null) return null;
        var text = value.Value.ValueKind switch
        {
            JsonValueKind.String => value.Value.GetString(),
            JsonValueKind.Number => value.Value.GetRawText(),
            JsonValueKind.True => bool.TrueString,
            JsonValueKind.False => bool.FalseString,
            _ => null,
        };
        return string.IsNullOrEmpty(text) ? null : text;
    }

    private static bool Flag(JsonElement element, params string[] path) =>
        Find(element, path) is { ValueKind: JsonValueKind.True };

    private static string Count(JsonElement element, string name) =>
        (element.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v.GetArrayLength() : 0)
        .ToString(CultureInfo.InvariantCulture);
}
