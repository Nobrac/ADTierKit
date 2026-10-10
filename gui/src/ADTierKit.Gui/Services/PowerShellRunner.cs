using System.Diagnostics;
using System.IO;
using System.Text;
using ADTierKit.Gui.Core;

namespace ADTierKit.Gui.Services;

/// <summary>
/// Runs ADTierKit.ps1 in Windows PowerShell 5.1 with redirected output. Lines arrive on thread
/// pool threads through <see cref="LineReceived"/>; the caller marshals them to the UI.
/// </summary>
public sealed class PowerShellRunner : IDisposable
{
    private Process? _process;

    public event Action<string, bool>? LineReceived;

    public bool IsRunning => _process is { HasExited: false };

    public int? ProcessId => _process?.Id;

    /// <summary>
    /// Windows PowerShell 5.1 on purpose, whatever started this window: it is what the tool is
    /// written and tested for, and what the scheduled task uses.
    /// </summary>
    public static string PowerShellPath =>
        Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

    public async Task<int> RunAsync(string scriptPath, IReadOnlyList<string> arguments)
    {
        if (IsRunning) throw new InvalidOperationException("A run is already in progress.");

        var info = new ProcessStartInfo(PowerShellPath)
        {
            WorkingDirectory = Path.GetDirectoryName(scriptPath) ?? Environment.CurrentDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // -NonInteractive turns a prompt into an error instead of a hang; the closed input
            // does the same for Read-Host.
            RedirectStandardInput = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        foreach (var argument in CommandBuilder.BuildProcessArguments(scriptPath, arguments)) info.ArgumentList.Add(argument);

        var process = new Process { StartInfo = info, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) LineReceived?.Invoke(e.Data, false); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) LineReceived?.Invoke(e.Data, true); };

        process.Start();
        _process = process;
        process.StandardInput.Close();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        // Also waits for both redirected streams to reach their end, so no line is lost.
        await process.WaitForExitAsync().ConfigureAwait(false);
        return process.ExitCode;
    }

    /// <summary>Ends the run and every process it started.</summary>
    public void Stop()
    {
        try
        {
            if (_process is { HasExited: false } p) p.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            // Exited in the meantime.
        }
    }

    public void Dispose()
    {
        _process?.Dispose();
        _process = null;
    }
}
