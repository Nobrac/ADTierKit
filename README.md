<div align="center">

# 🏛️ ADTierKit

**Deploy, audit and maintain an Active Directory tier model — from one script and one JSON file.**

<br>

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](docs/GUIDE.md#prerequisites)
[![Platform](https://img.shields.io/badge/Windows_Server-2012R2%2B-0078D6?style=for-the-badge&logo=windows&logoColor=white)](docs/GUIDE.md#prerequisites)
[![Lab tested](https://img.shields.io/badge/lab_tested-Server_2025-2ea44f?style=for-the-badge)](docs/GUIDE.md#limitations--notes)
[![License](https://img.shields.io/badge/license-MIT-555555?style=for-the-badge)](LICENSE)

<br>

[**Quick start**](#quick-start) &nbsp;·&nbsp;
[**Guide**](docs/GUIDE.md) &nbsp;·&nbsp;
[**Operator's Guide**](docs/OPERATIONS.md) &nbsp;·&nbsp;
[**Changelog**](CHANGELOG.md)

</div>

<br>

```
   wizard  ──▶   config/tiermodel.json   ◀── the source of truth
                   │         │         │
            deploy │   audit │    sync │
                   ▼         ▼         ▼
             converges   reports   keeps membership
           the directory  drift       current
```

A guided wizard asks for your naming convention, previews every object it would create and writes
one configuration file. From then on that file is the source of truth: **Deploy** converges the
directory to it, **Audit** reports every drift, **Sync** keeps memberships current. Everything is
idempotent, and nothing is written without a plan first. One PowerShell script, one JSON file - no
module, no build step.

<div align="center">
  <a href="docs/deployment.png"><img src="docs/deployment.png" alt="A deployment run: prerequisite check, OU structure and domain wide settings" width="700"></a>
</div>

> [!CAUTION]
> **Logon rights are tattooed.** Disabling a GPO link does not give a removed logon right back.
> Never enable the logon restrictions on a domain controller without a second way in (console,
> another machine, DSRM). [`Repair-TierLockout.ps1`](docs/GUIDE.md#when-it-goes-wrong) is the way back.

> [!WARNING]
> **Lab-tested, not production-tested.** Run end to end against a Windows Server 2025 lab domain,
> never against a production directory. Take a system state backup of a DC before the first
> enforced deployment.

> [!NOTE]
> **Built with AI assistance.** Requirements defined and reviewed by a human, most of the code and
> documentation written by an AI model. Review it before running it in production.

## What it does

- **Structure** - a tier OU tree, AGDLP groups, template and break-glass accounts, and delegation
  that lets each tier administer only its own branch (no `WriteDacl`, no `WriteOwner`).
- **Isolation** - per-tier logon restriction GPOs, a Domain Controller baseline, Kerberos
  authentication policy silos and a neutral staging OU for machines not yet classified.
- **Hardening** - Windows LAPS (DSRM included), `MachineAccountQuota`, Recycle Bin, KDS root key,
  SACL auditing, Kerberos armoring.
- **Audit** - privileged group membership, object ownership, undeclared access group members,
  and the attack paths into Tier 0: DCSync rights, dangerous ACEs, editable Tier 0 GPOs, RBCD,
  Kerberoastable admins, krbtgt age.
- **Upkeep** - a daily sync task (optionally signed and configuration-pinned), run-over-run
  reports that show what is new, and a lockout recovery script.

## Quick start

Requires domain functional level 2012 R2+ (2016+ recommended), the `ActiveDirectory` and
`GroupPolicy` modules and an elevated session as Domain Admin.

```powershell
Get-ChildItem C:\ADTierKit -Recurse | Unblock-File
cd C:\ADTierKit

.\ADTierKit.ps1                                   # wizard: naming, preview, configuration
.\ADTierKit.ps1 -Mode Check                       # prerequisites
.\ADTierKit.ps1 -Mode Deploy                      # plan only - nothing is written

.\ADTierKit.ps1 -Mode Deploy -Apply -Stage RecycleBin,OU,Domain,Group,Nesting,Account,Delegation,Auditing
.\ADTierKit.ps1 -Mode Deploy -Apply -Stage GPO,Laps,KDS,Silo

.\ADTierKit.ps1 -Mode Audit                       # read-only drift and attack path report
.\ADTierKit.ps1 -Mode InstallTask                 # daily Sync as SYSTEM
```

Upgrading an existing configuration: run `.\Update-TierConfiguration.ps1` first, then plan a deploy.

| Mode | Writes | Purpose |
| --- | :---: | --- |
| *(none)* | ⚠️ | Interactive wizard - start here |
| `Deploy` | ⚠️ | Converges the directory. Plans by default, writes only with `-Apply` |
| `Audit` | — | Read-only drift, hygiene and attack path report |
| `Sync` | ✅ | Membership, account hygiene and silo assignment - safe to schedule |
| `InstallTask` | ✅ | Registers the daily Sync task |
| `Check` | — | Prerequisite check |

⚠️ only with `-Apply` · ✅ writes · — read-only. Exit codes and every option: see the [Guide](docs/GUIDE.md#modes).

## Documentation

| | |
| --- | --- |
| **[Guide](docs/GUIDE.md)** | The complete reference - what gets deployed, roles, ownership, guardrails, configuration, reports, troubleshooting, recovery |
| **[Operator's Guide](docs/OPERATIONS.md)** | The walkthrough - every setting the tool writes, day-to-day work, the rollout playbook |
| **[Changelog](CHANGELOG.md)** | What changed in each release |

## License

[MIT](LICENSE)
