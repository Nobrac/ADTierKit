using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows;
using Microsoft.Win32;

namespace ADTierKit.Gui.Services;

/// <summary>Everything the window asks of Windows: dialogs, files, folders, other processes.</summary>
public interface IShell
{
    bool IsElevated { get; }
    string UserName { get; }
    bool Confirm(string title, string message, bool warning);
    bool? AskYesNoCancel(string title, string message);
    void Inform(string title, string message, bool isError = false);
    string? PickFile(string title, string filter, string? current);
    void OpenWithEditor(string path);
    void OpenFolder(string path);
    void OpenDocument(string path);
    void StartWizard(string scriptPath, string? configurationPath);
    bool RestartElevated();
    void CopyText(string text);
}

public sealed class Shell : IShell
{
    public bool IsElevated { get; } = Environment.IsPrivilegedProcess;

    public string UserName { get; } = WindowsIdentity.GetCurrent().Name;

    public bool Confirm(string title, string message, bool warning) =>
        MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.YesNo,
            warning ? MessageBoxImage.Warning : MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;

    public bool? AskYesNoCancel(string title, string message) =>
        MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.YesNoCancel,
            MessageBoxImage.Question, MessageBoxResult.Yes) switch
        {
            MessageBoxResult.Yes => true,
            MessageBoxResult.No => false,
            _ => null,
        };

    public void Inform(string title, string message, bool isError = false) =>
        MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.OK,
            isError ? MessageBoxImage.Error : MessageBoxImage.Information);

    public string? PickFile(string title, string filter, string? current)
    {
        var dialog = new OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true };
        var folder = string.IsNullOrWhiteSpace(current) ? null : Path.GetDirectoryName(current);
        if (folder is not null && Directory.Exists(folder)) dialog.InitialDirectory = folder;
        return dialog.ShowDialog(Application.Current.MainWindow) == true ? dialog.FileName : null;
    }

    public void OpenWithEditor(string path)
    {
        var info = new ProcessStartInfo("notepad.exe") { UseShellExecute = false };
        info.ArgumentList.Add(path);
        Process.Start(info)?.Dispose();
    }

    public void OpenFolder(string path)
    {
        var info = new ProcessStartInfo("explorer.exe") { UseShellExecute = false };
        info.ArgumentList.Add(path);
        Process.Start(info)?.Dispose();
    }

    public void OpenDocument(string path) =>
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true })?.Dispose();

    /// <summary>The wizard asks its questions on a console, so it gets a console window of its own.</summary>
    public void StartWizard(string scriptPath, string? configurationPath)
    {
        var info = new ProcessStartInfo(PowerShellRunner.PowerShellPath)
        {
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(scriptPath) ?? Environment.CurrentDirectory,
        };
        foreach (var a in new[] { "-NoProfile", "-NoExit", "-ExecutionPolicy", "Bypass", "-File", scriptPath }) info.ArgumentList.Add(a);
        if (!string.IsNullOrWhiteSpace(configurationPath))
        {
            info.ArgumentList.Add("-ConfigurationPath");
            info.ArgumentList.Add(configurationPath);
        }
        Process.Start(info)?.Dispose();
    }

    public bool RestartElevated()
    {
        var self = Environment.ProcessPath;
        if (self is null) return false;
        try
        {
            Process.Start(new ProcessStartInfo(self) { UseShellExecute = true, Verb = "runas" })?.Dispose();
            return true;
        }
        catch (Win32Exception)
        {
            // The UAC prompt was declined.
            return false;
        }
    }

    public void CopyText(string text) => Clipboard.SetText(text);
}
