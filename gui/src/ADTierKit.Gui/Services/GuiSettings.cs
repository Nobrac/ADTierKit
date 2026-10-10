using System.IO;
using System.Text.Json;

namespace ADTierKit.Gui.Services;

/// <summary>
/// The paths the window remembers between sessions, in %APPDATA%\ADTierKit\gui.json. Only paths and
/// the target DC - never a mode or a switch, so a new session never starts armed.
/// </summary>
public sealed class GuiSettings
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public string? ScriptPath { get; set; }
    public string? ConfigurationPath { get; set; }
    public string? Server { get; set; }
    public string? LogDirectory { get; set; }
    public string? ReportDirectory { get; set; }
    public string? CredentialDirectory { get; set; }

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ADTierKit", "gui.json");

    public static GuiSettings Load()
    {
        try
        {
            if (File.Exists(FilePath)) return JsonSerializer.Deserialize<GuiSettings>(File.ReadAllText(FilePath)) ?? new();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { }
        return new();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Options));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
