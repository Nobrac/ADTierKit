namespace ADTierKit.Gui.Core;

/// <summary>What has to happen before a run may start.</summary>
/// <param name="PlanFirst">An apply whose plan has not been seen in this window.</param>
/// <param name="Confirm">The run writes; ask before it starts.</param>
/// <param name="Title">Title of the confirmation.</param>
/// <param name="Message">What the confirmation says, the command line included.</param>
public sealed record RunGate(bool PlanFirst, bool Confirm, string Title, string Message);

/// <summary>
/// The safeguards in front of every run: an apply is planned first, and every write is confirmed
/// with what it does spelled out. Plans are remembered by <see cref="CommandBuilder.PlanKey"/>.
/// </summary>
public sealed class RunSafety
{
    private readonly HashSet<string> _planned = new(StringComparer.Ordinal);

    /// <summary>Remembers a plan that ran to the end (a plan with failed actions has still been seen).</summary>
    public void RecordPlan(string planKey, int exitCode)
    {
        if (exitCode is 0 or 1) _planned.Add(planKey);
    }

    public bool HasPlan(string planKey) => _planned.Contains(planKey);

    public RunGate Evaluate(RunOptions options, string planKey, string commandLine)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Mode == RunMode.Deploy && options.Apply)
        {
            var notes = new List<string>();
            if (options.Force) notes.Add("-Force overrides the logon lockout guard and the Kerberos armoring prerequisite.");
            if (options.SkipPrerequisiteCheck) notes.Add("-SkipPrerequisiteCheck skips the prerequisite check.");
            if (options.Stages.Contains("GPO", StringComparer.OrdinalIgnoreCase))
                notes.Add("Logon rights are tattooed: disabling a GPO link does not give a removed right back. Keep a second way into the domain controllers (console, DSRM).");
            if (options.Stages.Contains("RecycleBin", StringComparer.OrdinalIgnoreCase))
                notes.Add("Enabling the Recycle Bin cannot be undone (it is a no-op if it is already on).");
            if (options.Stages.Contains("PrivilegedGroups", StringComparer.OrdinalIgnoreCase))
                notes.Add("In Enforce mode the PrivilegedGroups stage removes undeclared members of Domain Admins and the other built-in groups.");

            var message = "This run writes to Active Directory:\n\n" + commandLine +
                          (notes.Count > 0 ? "\n\n" + string.Join("\n\n", notes) : string.Empty) + "\n\nContinue?";
            return new RunGate(!HasPlan(planKey), true, "Apply to Active Directory", message);
        }

        return options.Mode switch
        {
            RunMode.Sync => new RunGate(false, true, "Run Sync",
                "Sync writes group membership, account flags and silo assignments.\n\n" + commandLine + "\n\nContinue?"),
            RunMode.InstallTask => new RunGate(false, true, "Register the task",
                "This registers a scheduled task that runs Sync as SYSTEM every day.\n\n" + commandLine + "\n\nContinue?"),
            _ => new RunGate(false, false, string.Empty, string.Empty),
        };
    }
}
