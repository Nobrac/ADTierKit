namespace ADTierKit.Gui.Core;

/// <summary>The modes of ADTierKit.ps1 the window offers. The wizard runs in its own console.</summary>
public enum RunMode
{
    Check,
    Audit,
    Deploy,
    Sync,
    InstallTask,
}

/// <summary>Facts about ADTierKit.ps1 the window has to agree with.</summary>
public static class TierKit
{
    /// <summary>The deploy stages, in the order ADTierKit.ps1 runs them (its -Stage ValidateSet).</summary>
    public static readonly IReadOnlyList<string> AllStages =
    [
        "RecycleBin", "OU", "Domain", "Group", "Nesting", "Account", "Delegation", "Ownership",
        "PrivilegedGroups", "Auditing", "GPO", "Laps", "KDS", "Silo",
    ];

    /// <summary>The two rollout windows the README recommends, plus the ownership stages on their own.</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> StagePresets =
        new Dictionary<string, IReadOnlyList<string>>
        {
            ["All stages"] = AllStages,
            ["Structure"] = ["RecycleBin", "OU", "Domain", "Group", "Nesting", "Account", "Delegation", "Auditing"],
            ["Policy"] = ["GPO", "Laps", "KDS", "Silo"],
            ["Ownership and privileged groups"] = ["Ownership", "PrivilegedGroups"],
        };

    public static readonly IReadOnlyDictionary<string, string> StageDescriptions = new Dictionary<string, string>
    {
        ["RecycleBin"] = "Enables the AD Recycle Bin (irreversible forest change).",
        ["OU"] = "Creates the tier OU tree.",
        ["Domain"] = "MachineAccountQuota, default computer and user containers.",
        ["Group"] = "Role and access groups (AGDLP).",
        ["Nesting"] = "Role groups into access groups, into built-in groups.",
        ["Account"] = "Template and break-glass administrator accounts.",
        ["Delegation"] = "Per-tier ACL delegation on the OU tree.",
        ["Ownership"] = "Object owners inside the tier model.",
        ["PrivilegedGroups"] = "Membership of Domain Admins and the other built-in privileged groups.",
        ["Auditing"] = "SACLs on the tier OUs.",
        ["GPO"] = "Logon restriction and baseline GPOs. Logon rights are tattooed.",
        ["Laps"] = "Windows LAPS schema and permissions.",
        ["KDS"] = "KDS root key for gMSAs.",
        ["Silo"] = "Kerberos authentication policies and silos.",
    };

    public static string Describe(RunMode mode) => mode switch
    {
        RunMode.Check => "Prerequisite check only. Read-only.",
        RunMode.Audit => "Read-only drift, hygiene and attack path report. Writes nothing to the directory.",
        RunMode.Deploy => "Converges the directory to the configuration. Plans unless \"Apply\" is ticked.",
        RunMode.Sync => "Membership, account hygiene and silo assignment. Writes - this is what the daily task runs.",
        RunMode.InstallTask => "Registers the daily Sync task as SYSTEM on this machine.",
        _ => string.Empty,
    };

    /// <summary>Translates an ADTierKit.ps1 exit code.</summary>
    public static string DescribeExitCode(int code) => code switch
    {
        0 => "success",
        1 => "one or more actions failed - see the report",
        2 => "audit found drift",
        3 => "prerequisites failed",
        4 => "audit found high severity findings",
        5 => "configuration does not match the pinned hash",
        -1 => "stopped",
        _ => "unexpected exit code",
    };

    /// <summary>Whether a run in this mode with these options writes to Active Directory or the machine.</summary>
    public static bool Writes(RunOptions options) => options.Mode switch
    {
        RunMode.Deploy => options.Apply,
        RunMode.Sync or RunMode.InstallTask => true,
        _ => false,
    };
}
