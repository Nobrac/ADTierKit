# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-09-25

Review and hardening release. It closes gaps in the tier boundary itself, makes the audit and the
recovery script do what their documentation says, and adds the pieces the review found missing:
a neutral landing zone for new computers, Kerberos armoring for enforceable silos, checks of the
attack paths into Tier 0, account and access group hygiene, DSRM through LAPS, and CI.

Run `Update-TierConfiguration.ps1` on an existing configuration before the next deploy, then
review the plan: it moves groups, adds deny ACEs and GPO settings. The neutral staging OU is
added **disabled** by the updater - switching it on is a decision.

### Security

- **The break-glass account is kept out of the authentication policy silos.** Silo membership
  was derived from the role groups without looking at `excludeFromSilo`, so the break-glass
  account - a member of `G-T0-Admins` - was assigned like every other administrator, contrary to
  the README. Accounts marked `excludeFromSilo` are now skipped; if one is already assigned,
  audit reports it as a High finding and deploy/sync removes the assignment.
- **Operators no longer hold every control access right on the service account OU.** The
  delegation `ReadProperty, ExtendedRight` without an object type granted all extended rights,
  `Reset Password` on service account users included - Tier 0 operators could take over Tier 0
  service accounts. It never granted gMSA password retrieval either; that is controlled per
  account by `PrincipalsAllowedToRetrieveManagedPassword`. The delegation is gone from the
  generator and the shipped configuration. **The tool only adds ACEs, so remove an existing one
  by hand**, per tier, on `OU=Service-Accounts,OU=<tier>,OU=<root>,...`, for example with
  `dsacls "<OU DN>" /R "<DOMAIN>\G-T0-Operators"` (this removes *all* explicit ACEs of that
  group on the OU - there are no others in the shipped model).
- **Deny logon and GPO exception groups live in the top tier.** Kept in their own tier's branch,
  they were writable by that tier's administrators through the branch delegation: a Tier 2 admin
  could remove `G-T0-Admins` from `DL-T2-DenyLogon` or exempt workstations from
  `T2-Logon-Restrictions`, switching off exactly the protection Tier 0 credentials rely on.
  Both groups now default to `Tier-0/Groups`, and existing groups are moved there by the `Group`
  and `GPO` stages (new `Move-TierObjectToOu`; audit reports a misplaced group as drift).
- **Tier administrators below the top tier cannot block Group Policy inheritance.** The branch
  delegation includes `WriteProperty` on every sub-OU and with it `gPOptions`. A deny on
  `gPOptions` for the tier admin group is now part of the granular delegation. The LAPS policy
  link, which a Block Inheritance used to switch off, is now enforced like the other tier links.

### Added

- **Neutral staging OU.** A `staging` block, expanded at load time like roles, creates
  `OU=Staging` below the model root: a deny logon group holding every role group of every tier,
  a quarantine GPO denying them logon, a join group with the domain-join set and nothing else,
  top tier management of the OU and a LAPS policy readable by the top tier only.
  `redirectComputersTo: "$Staging"` sends new computers there instead of into the lowest tier,
  whose administrators used to control every new server until somebody classified it. The audit
  lists machines waiting there and for how long. New OU reference `$Staging`.
- **Kerberos armoring.** The DC baseline carries *KDC support for claims, compound
  authentication and Kerberos armoring* (level *Supported*), every tier GPO the matching client
  setting. `Test-TierKerberosArmoring` checks configuration and deployed policy.
- **Two-way silo reconciliation.** Objects assigned to a silo that no longer qualify are
  reported, or removed with `options.authenticationPolicySiloReconcile: "Enforce"`. An account
  that qualifies for two silos is a High conflict and is assigned to neither, instead of flapping
  between them on every run.
- **Attack path checks in the audit** (`Test-TierAttackPath`, `attackPathChecks` block): dangerous
  ACEs and foreign owners on the domain head (DCSync included), AdminSDHolder, the Policies
  container, the Domain Controllers OU and the model root; the same for every object below
  Tier 0 and the DC OU; who can edit or owns a GPO that applies to DCs or Tier 0 machines; RBCD
  on Tier 0 computers; shadow credentials on Tier 0 users; Kerberoastable privileged accounts;
  krbtgt password age.
- **CI.** `.github/workflows/ci.yml` parses every script, validates the JSON, runs
  PSScriptAnalyzer (errors fail the build) and the offline suites on PowerShell 7 and Windows
  PowerShell 5.1.
- **DSRM through Windows LAPS.** The Domain Controllers OU gets its own LAPS policy
  (`T0-DC-LAPS`), encrypted and without a decryptor principal - DSRM passwords are decryptable by
  Domain Admins only. Skipped and reported below domain functional level 2016. Every run
  reports each DC that has not stored its DSRM password yet (`Test-TierDsrmBackup`).
- **Undeclared members of access groups** (`Test-TierAccessGroupMembership`, runs with the
  Nesting stage in Deploy, Sync and Audit): an undeclared member of a LocalAdmins or
  RemoteDesktop group is Medium, High when it belongs to another tier; every member of a GPO
  exception group is reported. Report only.
- **Cross-tier ACL scan** as part of the attack path audit: a principal of a lower tier that
  holds control over, or owns, an object of a higher tier below Tier 0.
- **Administrative account hygiene** (`Set-TierAdminAccountHygiene`, Account stage and Sync):
  every user in a role group gets *account is sensitive and cannot be delegated*, every top tier
  account except `excludeFromSilo` lands in Protected Users - including administrators copied
  from the templates by hand. Audit reports, Deploy and Sync correct. Replaces
  `Add-TierProtectedUser`, which only ever looked at the template accounts.
- **Scheduled task integrity.** `-Mode InstallTask -RequireSignedScript` registers the task with
  `ExecutionPolicy AllSigned` after checking the signature and that the signer is a trusted
  publisher; `-PinConfiguration` passes the configuration's SHA256, and a changed file stops the
  run with exit code 5 and event 1003.
- **Findings over time.** Each report is compared with the previous report of the same mode:
  new findings are marked and filterable, resolved ones listed; both counts go to the event log.
- **`lab/Test-LogonMatrix.ps1`** - logs on locally with a test account per tier and logon type
  and checks each result against the expectation derived from the configuration.
- `Update-TierConfiguration.ps1` applies the configuration-side corrections and additions above
  to an existing configuration.
- Offline test suites `tests/Test-ReviewFixes.ps1`, `tests/Test-Hardening.ps1` and
  `tests/Test-Operations.ps1`.
- `tests/TestIsolation.ps1`, loaded by every suite: each directory, Group Policy, LAPS, KDS,
  scheduled task, event log and signing command fails loudly unless the suite mocks it, and
  `AD:` paths are blind. Without it a forgotten mock on a machine with RSAT auto-loads the
  ActiveDirectory module and reaches the real domain.

### Fixed

- **`Repair-TierLockout.ps1 -EnableGpoLinks` can succeed.** Step 3 checked every deny group
  against every Domain Admin; the other tiers' deny groups contain the top tier role group by
  design, so the check failed on every correctly configured domain. It now examines only the
  GPOs that reach the domain controller or the machine it runs on, the same rule the deploy-time
  lockout guard uses. Step 2 warns when such a link is still enabled, because the next policy
  refresh would undo the restored rights. GPO targets written as `Tier/Sub`, `$ModelRoot` or a DN
  are resolved correctly.
- **Audit checks silo membership.** The silo stage returned before the member check in audit
  mode, so an unassigned server never appeared in the report.
- **One failing stage no longer ends the run.** Each stage runs inside `Invoke-TierStage`; an
  unhandled error becomes a `Failed` action and the remaining stages, the report and the event
  log entry still happen. A GPO that cannot be created no longer stops the other GPOs.
- **Unreadable privileged group membership is a finding, not a pass.** A failed
  `Get-ADGroupMember` used to return an empty list, which compared as compliant.
- **Wizard options with side effects:** the allow list keeps `Users` in interactive logon on the
  workstation tier (it used to lock every end user out), and the cross-tier network logon deny is
  never applied to the domain controller baseline (it took LDAP and SYSVOL away from lower tier
  administrators).
- A GPO owned by the wrong principal is reported as `Drift` instead of `Missing`; the wizard
  checks the 20-character limit against the break-glass name; the HTML report styles severity,
  target and detail columns; `Update-TierConfiguration.ps1` resolves its default paths from the
  script folder instead of the current directory.
- **Silo enforcement reaches existing silos.** The enforcement state and the TGT lifetime were
  only set when a policy or silo was created, so changing `authenticationPolicyEnforcement` to
  `Enforce` never took effect on a deployed model. Both are now converged on every run, and
  enforcement is withheld while Kerberos armoring is missing (High finding; `-Force` overrides).
  Withheld enforcement never downgrades a silo somebody enforced by hand.
- **`Repair-TierLockout.ps1` finds its configuration under Windows PowerShell 5.1.** The default
  path was built from `$PSScriptRoot` inside the `param()` block, where 5.1 leaves it empty when
  a script is started with `-File` - the recovery script failed before it did anything. The
  script folder is now resolved after binding, as `ADTierKit.ps1` already did.
- The item counts in the Nesting and Delegation log lines are right on Windows PowerShell 5.1 when
  a stage recorded exactly one action (a single object has no `.Count` there).

## [1.1.0] — 2026-08-24

Hardening and documentation release. The three code changes came out of an external review of
1.0.0; none of them changes what a converged directory looks like — two close gaps in how the
tool protects and checks itself, one removes report noise.

### Security

- **`InstallTask` now refuses paths that principals outside the administrative set can
  modify.** The sync task executes the script and the configuration as SYSTEM on a domain
  controller — whoever can write to those files, or to the directories containing them, owns
  the domain at 03:30. The new `Get-TierUntrustedPathWriter` check inspects allow ACEs
  (write, delete, permission and ownership rights) and the object owner on all four paths,
  trusting only SYSTEM, `Administrators`, `TrustedInstaller` and the Domain/Enterprise Admins
  RIDs, and registration fails with the offending principals named. `-SkipAclCheck` bypasses
  it deliberately. Existing installations are unaffected until the task is registered again.

### Fixed

- **The password shuffle no longer has a modulo bias.** Character *picks* already used
  rejection sampling; the Fisher-Yates shuffle behind them still used a plain modulo, which
  biases positions slightly whenever 256 is not divisible by the remaining length. Both now
  draw from the same rejection-sampled source. No practical weakness — the characters
  themselves were always uniform — but the code now does what its own comment promised.

- **LAPS reset permissions are idempotent.** `Find-LapsADExtendedRights` reports read-permission
  holders only; the reset grant is `WriteProperty` on `msLAPS-PasswordExpirationTime` and never
  appears there, so every run re-granted it and reported `Created`. The reset side is now
  checked against the OU ACL directly — the same technique the computer self permission already
  used, for the same reason.

### Added

- **`docs/OPERATIONS.md`** — the operator's guide: the working model (converge, plan-first,
  additive), the complete change inventory with every default value the tool writes, day-two
  operations, the rollout playbook with per-phase checks, the pitfalls, and a verification
  checklist.

- **README: "What belongs in Tier 0."** The tool secures the boundary the configuration
  declares; this section is the classification test (control, not importance) and the usual
  omissions — PKI, Entra Connect, backup infrastructure, hypervisors hosting DCs, endpoint
  management that reaches DCs, and the kit's own directory.

- **README: silo pre-enforcement warning.** The PAWs must be inside `memberComputerOus` and
  synced before enforcement, and the `AuthenticationPolicyFailures-DomainController` log —
  where the audit-phase denials land — is disabled by default and must be enabled on every
  domain controller, or a clean audit phase proves nothing.

## [1.0.0] — 2026-08-14

First tagged release. Everything below has been deployed and exercised against a Windows Server
2025 lab domain at functional level `Windows2025Domain`; see
[Limitations & notes](docs/GUIDE.md#limitations--notes) for what that did not cover.

### Added

- **Roles.** A `roles` block that expands at configuration load time into everything a role
  actually consists of: a global group, a disabled template account, delegation ACEs, membership
  in the deny logon group of every *other* tier, and membership in the tier's authentication
  silo. Adding a role group by hand and forgetting the deny nesting is a silent hole in the tier
  boundary; declaring it once and generating all five closes that off. Deploy, audit and sync
  need no knowledge of roles — they only ever see ordinary groups and ACEs.

- **DNS and Group Policy roles**, shipped in `config/roles.example.json`. Both are Tier 0 where
  they create objects, because creating a DNS zone means being able to create records under
  `_msdcs`, and creating a policy makes you its owner. What is delegated per tier is linking and
  editing.

  The Group Policy role grants write access to `gpLink` and **read only** to `gpOptions`. The
  GPMC permission called *Link GPOs* grants both, and write access to `gpOptions` is the ability
  to block inheritance and cancel out the baseline handed down from the domain.

- **`builtInNesting`**, generated by role expansion and applied by the `Nesting` stage. Nests a
  role group into `DnsAdmins` or `Group Policy Creator Owners` so those groups can stay empty of
  direct members. Additive only — removing undeclared members remains the privileged group
  stage's job, and a member nested here but not declared there is refused rather than left to be
  added by one stage and removed by the other.

- **`Ownership` stage**, in deploy, sync and audit. An owner holds `WRITE_DAC` implicitly, so an
  object created by a delegated administrator is one whose permissions that administrator can
  rewrite — which quietly undoes the granular delegation the model is built on. Report mode by
  default; drift in the top tier is High, elsewhere Medium.

- **Per-GPO delegation** through `gpos[].delegation`, with `editors`, `readers` and `owner`.
  Written through the GroupPolicy module so the directory object and the SYSVOL folder stay
  consistent.

- **Six new OU references** for delegation targets outside the tier model: `$SystemContainer`,
  `$MicrosoftDns`, `$DomainDnsZones`, `$ForestDnsZones`, `$PoliciesContainer`, `$AdminSDHolder`,
  plus `$DnsZone:<name>` for record-level delegation on a single zone.

- **Three SACL rules** on `CN=Policies`, `CN=AdminSDHolder` and `CN=MicrosoftDNS`. The Group
  Policy *Edit settings* permission maps to write access on all properties, which includes
  `displayName` and `gPCWQLFilter` — a delegate can rename a policy and change which machines it
  applies to. The narrower grant that would prevent it is refused by the GPMC, so auditing is the
  available mitigation.

- **`Update-TierConfiguration.ps1`**, which brings a configuration written before this release up
  to the current schema. Derives each tier's token from the group names it already uses rather
  than assuming `T<id>`, and says so plainly when it cannot.

- **Offline test suites** in `tests/`, runnable without a domain.

- **`name` as an alternative to `sid`** in `privilegedGroups`. `DnsAdmins` is the one group in
  this tool not addressed by SID: it is created by the DNS server role rather than the operating
  system, so its RID differs between domains — but it is not localised either, which is what
  makes the name lookup safe there and nowhere else. It is now watched by default, since its
  members can load a DLL into a service running as SYSTEM on a domain controller and nothing
  otherwise flags it as privileged.

### Fixed

Seven defects, all found by running against a real domain controller rather than by testing:

- **Owner writes reported success without writing.** `Set-ADObject -Replace @{
  nTSecurityDescriptor = … }` applies the DACL and drops the owner portion, silently. The
  ownership stage reported a correction on every run while the owner never changed. Owner writes
  now go through the AD provider and are **read back and compared** before anything is reported
  as corrected. The `DirectoryEntry` route that would set the security mask by hand does not work
  from Windows PowerShell 5.1 — `DirectoryEntryConfiguration` returns null even after the entry
  is bound.

- **`-Properties @()`** does not bind on Windows PowerShell 5.1, though it does on 7.x. An empty
  property set is now normalised where it is accepted.

- **`if (-not $roleTiers)`** treated a role scoped to tier 0 alone as having no tiers, because
  the single-element array `@(0)` unrolls to a falsy `0`.

- **Principals were reported by SID** instead of by name. `Get-ADObject -Identity` binds a
  distinguished name or a GUID and rejects a SID; resolution now uses an LDAP filter.

- **A corrected owner was still counted as drift**, so a successful enforce run read like a failed
  audit.

- **`ForestDnsZones` DN construction** joined the domain components without separators.

- **Silent truncation** when an ownership scope held more objects than `maxObjects`. Exceeding the
  cap is now a finding rather than a clean result over a partial scan.

### Changed

- Generated configurations carry `token` and `denyLogonGroup` per tier. Role expansion needs both,
  and deriving them from a custom naming pattern is guesswork that would put a role group in the
  wrong deny group — a hole rather than an error message.
- Every log and report begins with the tool version.
