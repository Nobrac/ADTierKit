<div align="center">

# 🏛️ ADTierKit

**Deploy, audit and maintain an Active Directory tier model — from one script and one JSON file.**

<br>

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](#prerequisites)
[![Platform](https://img.shields.io/badge/Windows_Server-2012R2%2B-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#prerequisites)
[![Lab tested](https://img.shields.io/badge/lab_tested-Server_2025-2ea44f?style=for-the-badge)](#limitations--notes)
[![License](https://img.shields.io/badge/license-MIT-555555?style=for-the-badge)](LICENSE)

<br>

[**Modes**](#modes) &nbsp;·&nbsp;
[**What it deploys**](#what-it-deploys) &nbsp;·&nbsp;
[**Guardrails**](#guardrails) &nbsp;·&nbsp;
[**Quick start**](#quick-start) &nbsp;·&nbsp;
[**Design decisions**](#design-decisions-worth-knowing) &nbsp;·&nbsp;
[**Troubleshooting**](#troubleshooting)

</div>

<br>

```
                 ┌───────────────────────────────────────────────┐
   wizard  ──▶   │            config/tiermodel.json              │   ◀── you edit this
                 │              the source of truth              │
                 └───────────────────────────────────────────────┘
                            │            │            │
                     deploy │      audit │       sync │
                            ▼            ▼            ▼
                     converges     reports the    keeps membership
                    the directory     drift          current
```

<div align="center">
  <a href="docs/deployment.png"><img src="docs/deployment.png" alt="A deployment run: prerequisite check, OU structure and domain wide settings" width="700"></a>
  <br>
  <sub>A full deployment. Every stage reports what it created, skipped or found compliant.</sub>
</div>

<br>

Tiering an Active Directory is not hard to understand and very hard to finish. The structure can
be built in an afternoon; deciding which of nine hundred existing servers belongs to which tier
cannot, and the projects that stall usually stall exactly there. ADTierKit is built around that
reality — it automates everything that *can* be automated, refuses to guess at the rest, and tells
you plainly which is which.

A guided wizard asks for your naming convention, previews every object it would create, and writes
a single configuration file. From then on that file is the source of truth. Everything is
idempotent, and everything plans before it writes.

The whole tool is one PowerShell script plus one JSON configuration file. No module to import, no
folder structure to preserve, no build step. Copy two files onto a domain controller and run them.

<br>

> [!CAUTION]
> **Logon rights are tattooed.** Once a logon restriction has applied, disabling the GPO link does
> **not** give the right back — the entry stays in the local security database of every machine
> that processed it, and it survives reboots. Recovery needs `secedit` run locally, which in turn
> needs a way in: the console, another machine over the network, or DSRM. Never enable these GPOs
> on a domain controller without a second route in, and keep the DSRM password to hand.
> [`Repair-TierLockout.ps1`](#when-it-goes-wrong) automates the way back.

> [!WARNING]
> **Lab-tested, not production-tested.** Every mode has been run end to end against a Windows
> Server 2025 lab domain, idempotency is verified at `Created: 0`, and the tier separation was
> confirmed with real accounts in both directions. It has never run against a production
> directory and has not been reviewed by a second engineer — see [Limitations &
> notes](#limitations--notes). Take a system state backup of a domain controller before the first
> enforced deployment.

> [!NOTE]
> **Built with AI assistance.** Most of the code and documentation in this repository was written
> by Claude (Anthropic) in a pair-programming workflow: requirements defined and reviewed by a
> human, implementation by the model. As with any code you did not write yourself, review it
> before running it in production.

---

## Contents

| Getting there | Understanding it | When you need it |
|---|---|---|
| [Modes](#modes) | [Roles](#roles) | [Troubleshooting](#troubleshooting) |
| [What it deploys](#what-it-deploys) | [Ownership](#ownership) | [When it goes wrong](#when-it-goes-wrong) |
| [Guardrails](#guardrails) | [Design decisions](#design-decisions-worth-knowing) | [Checking the code](#checking-the-code) |
| [Prerequisites](#prerequisites) | [Configuration reference](#configuration-reference) | [Limitations & notes](#limitations--notes) |
| [Quick start](#quick-start) | [Reports and logging](#reports-and-logging) | [Repository layout](#repository-layout) |
| [What belongs in Tier 0](#what-belongs-in-tier-0) | | [License](#license) |
| [Rollout order](#recommended-rollout-order) | | |

For the full walkthrough — every setting the tool writes, the day-to-day working model and the
complete rollout playbook — see the **[Operator's Guide](docs/OPERATIONS.md)**.

---

## Modes

| Command | Writes? | Purpose |
| --- | :---: | --- |
| `.\ADTierKit.ps1` | ⚠️ | **Interactive wizard.** Asks for the naming convention, previews the result, writes the configuration, optionally starts the deployment. Start here. |
| `.\ADTierKit.ps1 -Mode Deploy` | ⚠️ | Applies the configuration. **Plans by default** — writes only with `-Apply`. Staged rollout via `-Stage`. |
| `.\ADTierKit.ps1 -Mode Audit` | — | Read-only drift and hygiene report with severity classification, including the attack paths into Tier 0 that lie outside the model (DCSync rights, dangerous ACEs, editable Tier 0 GPOs, RBCD, Kerberoastable admins, krbtgt age). |
| `.\ADTierKit.ps1 -Mode Sync` | ✅ | Re-runs only the membership stages. Safe to schedule. |
| `.\ADTierKit.ps1 -Mode InstallTask` | ✅ | Registers a daily scheduled task that runs `Sync` as SYSTEM. `-RequireSignedScript` runs it under `AllSigned`, `-PinConfiguration` makes it refuse a changed configuration. |
| `.\ADTierKit.ps1 -Mode Check` | — | Prerequisite check only. |

⚠️ needs `-Apply` before anything is written · ✅ writes to the directory · — read-only

**Exit codes** &nbsp; `0` success &nbsp;·&nbsp; `1` deploy failures &nbsp;·&nbsp; `2` drift found &nbsp;·&nbsp; `3` prerequisites failed &nbsp;·&nbsp; `4` high severity findings &nbsp;·&nbsp; `5` pinned configuration changed

---

## What it deploys

```
OU=Tiering
├── OU=Staging                    neutral landing zone — new computers, administered by no tier
├── OU=Tier-0                     control plane — domain controllers, PKI, identity
│   ├── OU=Accounts               adm-t0-*, break glass
│   ├── OU=Groups                 G-T0-Admins · G-T0-Operators · DL-T0-* · every tier's DenyLogon / Exempt-Logon
│   ├── OU=Servers                Tier 0 member servers
│   ├── OU=Devices                privileged access workstations
│   ├── OU=Service-Accounts
│   └── OU=Staging                landing zone before production
├── OU=Tier-1                     server plane — applications, databases, file services
│   └── … same shape
└── OU=Tier-2                     workplace plane — clients and their administrators
    └── … same shape
```

| Stage | What it creates |
| --- | --- |
| `RecycleBin` | Enables the AD Recycle Bin, so a mistake during rollout is recoverable without an authoritative restore. Irreversible and forest-wide. |
| `OU` | Tier model root plus one branch per tier, each with sub-OUs for accounts, groups, servers, devices, service accounts and staging. Protected from deletion, with Group Policy inheritance blocked. |
| `Domain` | Sets `ms-DS-MachineAccountQuota`, redirects the default location for new computer accounts away from `CN=Computers`, enables replication change notification on the site links. |
| `Group` | Per tier: global role groups (admins, operators) and domain local access groups (local admins, remote desktop, deny logon). |
| `Nesting` | Cross-tier nesting — in particular the deny-logon group that holds the *other* tiers' principals. |
| `Account` | Disabled template and break-glass accounts, flagged sensitive-and-cannot-be-delegated, optionally added to `Protected Users`. Passwords exported DPAPI-encrypted. |
| `Delegation` | Explicit ACEs so each tier administers only its own branch — including the full domain-join permission set, and deliberately excluding `WriteDacl` and `WriteOwner`. |
| `PrivilegedGroups` | Compares `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Key Admins` and the `Account` / `Server` / `Print` / `Backup Operators` against their declared membership. Reports by default, corrects in enforce mode. |
| `Auditing` | SACL audit entries on the model root and the Domain Controllers OU, so changes to the structure and its delegation produce directory service change events. |
| `GPO` | Per-tier logon restriction GPOs: deny rights for foreign-tier principals, restricted groups for local `Administrators` and `Remote Desktop Users`, UNC hardened paths, plus an exception group per GPO. |
| `Laps` | Windows LAPS: schema extension, per-tier read and reset permissions, and one policy GPO per tier with its own decryption principal. |
| `KDS` | KDS root key, the prerequisite for gMSA and dMSA. |
| `Silo` | One Kerberos authentication policy and silo per administrative tier. Deployed in audit mode by default; enforcement is withheld until Kerberos armoring is in place. Membership is reconciled both ways, and an account that qualifies for two silos is reported rather than moved back and forth. |

<table>
<tr>
<td width="50%" valign="top" align="center">
  <a href="docs/result-aduc.png"><img src="docs/result-aduc.png" alt="The resulting OU structure in Active Directory Users and Computers" width="330"></a>
  <br>
  <sub><b>The result in ADUC</b><br>Three tiers, each with the same six sub-OUs.</sub>
</td>
<td width="50%" valign="top" align="center">
  <a href="docs/result-gpmc.png"><img src="docs/result-gpmc.png" alt="The resulting GPO links in Group Policy Management" width="290"></a>
  <br>
  <sub><b>The result in GPMC</b><br>Logon restrictions and a LAPS policy per tier, plus the domain controller baseline.</sub>
</td>
</tr>
</table>

The isolation logic is deliberately simple and reviewable: each tier has exactly one deny-logon group, and the GPO denies that single SID the logon types that matter. Changing who is locked out of a tier is a group membership change, not a GPO edit.

---

## Roles

DNS zones get created, Group Policy objects get written — jobs somebody has to be allowed to do
without being allowed to do everything else.

A role is not one object, which is what makes adding one by hand risky. It is a global group, a
disabled template account, a set of ACEs, a membership in the deny logon group of *every other
tier*, and a membership in the tier's authentication silo. Forgetting the deny nesting is the
expensive one: the new group can then log on everywhere, and nothing reports it, because from the
directory's point of view nothing is wrong. So a role is declared once and expanded into all of
it at load time:

```json
"roles": [
  {
    "name": "DNS",
    "tiers": [0],
    "roleGroup": "G-{TOKEN}-DNS-Admins",
    "templateAccount": "adm-{TOKENLC}-dns-template",
    "privilegedGroupNesting": [ { "name": "DnsAdmins" } ],
    "delegations": [ … ]
  }
]
```

Expansion happens inside `Import-TierConfiguration`, before validation and before any stage sees
the configuration. Deploy, audit and sync therefore need no knowledge of roles at all — the groups
and ACEs a role produces are indistinguishable from ones written out by hand, and are audited,
synced and reported the same way.

| Field | Default | Effect |
| --- | --- | --- |
| `tiers` | — | Which tier IDs the role is created in. One role, one group per listed tier. |
| `roleGroup` | — | Naming pattern. `{ID}` `{TIER}` `{TOKEN}` `{TOKENLC}` `{ROLE}` `{ROLELC}`. |
| `templateAccount` | none | Creates a disabled template account in the role group, like the tier templates. |
| `nestIntoForeignDenyGroups` | `true` | Nests the role group into the deny logon group of every other tier. |
| `siloMember` | `true` | Adds the role group to the tier's authentication policy silo. |
| `privilegedGroupNesting` | none | Built-in groups the role is nested into, and which are then watched for direct members. |
| `delegations` | none | ACEs, in the same format as `tiers[].delegations`. `principal` defaults to the role group. |
| `enabled` | `true` | `false` expands nothing. |

`nestIntoForeignDenyGroups` defaults to on because the failure mode of forgetting it is silent and
the failure mode of over-denying is a logon error somebody notices within the hour.

### Nesting into built-in groups

`privilegedGroupNesting` produces **two** things from one declaration, and they are not the same:

- an entry in `privilegedGroups`, which is what *watches* the built-in group for members that are
  not supposed to be there
- an entry in `builtInNesting`, which is what actually *performs* the nesting, from the `Nesting`
  stage

The split exists because the privileged group stage runs in report mode by default, where an
absent declared member is reported rather than added — a DNS role would hold no permissions at
all until somebody switched `privilegedGroups.mode` to `Enforce`.

The division of labour is strict: `Nesting` only ever *adds* what the configuration declares,
`PrivilegedGroups` only ever *removes* what it does not. They cannot fight, as long as everything
nested is also declared. Role expansion writes both from one line; a hand-written `builtInNesting`
entry that gets it wrong is refused rather than left to flap between the two stages.

Two refusals worth knowing:

- **A role below the top tier cannot be nested into a privileged built-in group.** `DnsAdmins`
  members can load a DLL into a service running as SYSTEM on a domain controller. The role group
  is still created — only the nesting is refused, as a High finding.
- **A built-in group that does not exist is a state, not a fault.** `DnsAdmins` appears with the
  DNS server role; the entry is skipped and reported at Low severity.

In audit mode, a role that exists but is not nested is a **Medium** finding: configured, not in
effect.

Roles reach containers outside the tier model — the DNS server object, the policies container,
`AdminSDHolder` — through seven additional `targetOu` values listed under
[OU references](#ou-references).

### The two roles that ship

Both are in `config/roles.example.json`, and both are Tier 0 where they create objects — creating
a DNS zone means being able to create records under `_msdcs`, and creating a Group Policy object
makes you its owner.

**DNS.** The goal is an empty `DnsAdmins`. Its members can load a DLL into a service running as
SYSTEM on a domain controller, and it is neither covered by AdminSDHolder nor marked with
`adminCount`, so nothing in a standard audit flags it as privileged. The role holds its
permissions by being nested into it, and the group is watched so a direct member becomes a
finding.

`DnsAdmins` is also the one group here not addressed by SID: created by the DNS server role rather
than the operating system, it has an ordinary RID that differs between domains — but it is not
localised either, which is what makes the name lookup safe there and nowhere else.

**Group Policy.** The interesting part is what the role deliberately cannot do. The GMPC
permission called *Link GPOs* grants write access to both `gpLink` and `gpOptions`, and write
access to `gpOptions` is the ability to block inheritance and cancel every policy handed down from
the domain — including the baseline. The shipped delegation grants `gpLink` for writing and
`gpOptions` for reading only. The GPMC displays the inheritance state correctly and refuses to
change it.

*Edit settings* is less satisfying: it maps to write access on all properties, so a delegate can
rename a policy and change its WMI filter, and changing the filter changes which machines it
applies to. The narrower grant that would prevent it is refused by the GPMC, which will not open a
policy it cannot fully write. Auditing is the available mitigation, so `$PoliciesContainer` carries
a SACL and every rename and filter change is recorded.

### Who owns a policy

Creation stays in Tier 0 for a reason the delegation model cannot work around: **an owner holds
`WRITE_DAC` implicitly, whatever the DACL says.** A policy created by a delegated administrator is
permanently re-permissionable by them, and any granular delegation placed on it afterwards is
advisory.

Any GPO in the configuration can now declare its owner and its editors:

```json
{
  "name": "T1-Logon-Restrictions",
  "delegation": {
    "editors": ["G-T1-GPO-Admins"],
    "owner": "512"
  }
}
```

The owner is compared on every run and reported when it has drifted, because a drifted owner means
the granular delegation on that object is no longer binding.

The same problem exists for every object a tier administrator creates in their own branch — a
sub-OU they own is one they can re-permission and move objects into. That is what the `Ownership`
stage is for.

---

## Ownership

The delegation model withholds `WriteDacl` and `WriteOwner` so that a tier administrator cannot
rewrite the permissions that constrain them. Ownership goes around it: **an owner holds
`WRITE_DAC` implicitly, whatever the DACL says.**

Windows takes the owner of a new object from the creator's token. A member of `Domain Admins`
creates objects owned by `Domain Admins`; everybody else creates objects owned by themselves. So a
delegated administrator owns everything they create — and an owned sub-OU can be re-permissioned,
have objects moved into it, and be opened to principals from another tier. The granular delegation
is binding right up until somebody creates something.

```json
"ownership": {
  "enabled": true,
  "mode": "Report",
  "owner": "512",
  "acceptableOwners": [],
  "scopes": ["$ModelRoot"],
  "objectClasses": ["user", "group", "computer", "organizationalUnit", "msDS-GroupManagedServiceAccount"],
  "maxObjects": 5000
}
```

The stage finds **nothing at all on a freshly deployed model** — the deployment account created
everything, so everything is owned correctly. It starts finding things the first time the model is
actually used, which is why it runs in `Sync` as well as in `Deploy` and `Audit`.

| Behaviour | Why |
|---|---|
| Report is the default | The first list is worth reading. Reassigning ownership silently on a daily scheduled task is not where this should start. |
| Compliant objects are counted, not listed | One action per object would bury every real finding under several thousand lines saying nothing happened. Only drift is listed, and only the first 100, then a count. |
| Drift in the top tier is High, elsewhere Medium | A Tier 0 DACL *is* the boundary. Elsewhere an owner can rewrite permissions on objects inside their own tier, which is untidy rather than an escalation path. |
| `maxObjects` stops at 5000 by default | The check reads the security descriptor of every object in scope. Exceeding the cap is reported as a finding rather than silently truncating and returning a clean result. |
| The declared owner should be a group you are in | `WRITE_OWNER` alone only permits setting the owner to the caller or to a group the caller belongs to. `Domain Admins` satisfies that for the account running the tool. |

`acceptableOwners` exists for the cases that are fine but not the declared owner — objects created
by `Enterprise Admins` during a forest operation, for instance. Listing them stops the same
finding appearing every day.

Switch `mode` to `Enforce` once the list has been reviewed. Nothing about reassigning an owner is
destructive, but it is the kind of change that is easier to explain before it happens than after.

---

## Guardrails

> A tool that removes logon rights can lock you out of the domain it is meant to secure.
> These are the mechanisms that stop that from happening — and every one of them exists in
> response to a way it actually went wrong.

### The lockout guard

Before a single logon restriction is written, deployment resolves every deny group **recursively**
and checks it against two identities that must not lose access: the account running the
deployment, and the built-in `Administrator`. If either would be denied, the GPO stage is skipped
entirely, and the finding names the policy, the group and the target:

```
[!] LOCKOUT RISK - the logon restriction stage was not applied
[!]   T0-DomainController-Baseline denies logon to DL-T0-DenyLogon on
      OU=Domain Controllers,DC=... , which contains the account running this deployment
```

The check is deliberately **narrow**, and that is the interesting part. Cross-tier denial is the
whole point of the model: a Tier 0 account is *supposed* to lose its logon rights on Tier 1 and
Tier 2 systems, and once the top tier group is nested into `Domain Admins` as the configuration
declares, every Tier 0 account is a Domain Admin sitting in the other tiers' deny groups. A guard
that flagged that would fire on every correctly configured domain — and a warning that always
fires is one nobody reads. So it examines only the policies that reach a machine you would need in
order to *fix* the result: the domain controller, and the host the script runs from.

`-Force` overrides it. The override is then recorded as a deliberate decision rather than a
failure, so the next run's summary stays meaningful. Audit mode reports the same check as a high
severity finding, which catches a membership added *after* deployment.

### The rest of them

| Guardrail | What it prevents |
|---|---|
| **Plan by default** | `-Mode Deploy` writes nothing without `-Apply`. A mistyped command line cannot change the directory. |
| **The DC baseline names its own allow side** | A template that writes only deny entries relies on the allow side being held somewhere else — and on a domain controller that can be an implicit default rather than a policy. The baseline writes `SeInteractiveLogonRight` and `SeRemoteInteractiveLogonRight` explicitly, so applying it can never leave the controller without an administrative logon path. |
| **No empty rights are ever written** | `SeSomeRight =` with nothing after it does not mean "leave alone", it means "nobody holds this right". A right whose principals fail to resolve is skipped rather than emptied. |
| **Enforce mode has three unremovable guards** | The built-in `Administrator` is never removed from a privileged group, nor is the account running the deployment, and `Domain Admins` is never emptied — if enforcing would leave it without members, the group is skipped and reported. |
| **Disabled links stay disabled** | Each GPO carries a `linkEnabled` flag. A link you disabled to get out of trouble is not silently switched back on by the next deployment. |
| **The Recycle Bin goes first** | The first stage enables the AD Recycle Bin, so a mistake later in the same run is recoverable without an authoritative restore. |
| **Tattooing is stated out loud** | Every run warns, before writing logon rights, that disabling the link later will not give a removed right back. |
| **Silos start in audit mode** | Authentication policy silos deploy with enforcement off, so you can watch events 4820 / 4821 before anything is actually denied. |
| **No enforcement without armoring** | An enforced silo needs Kerberos armoring on the KDC and on the clients, or it refuses logons for the wrong reason. The generated GPOs carry both settings (level *Supported*), and the Silo stage withholds enforcement until they are configured and deployed — `-Force` overrides. |
| **New machines belong to nobody** | Computers joined without a pre-staged object land in `OU=Staging` below the model root, where every tier's administrators are denied logon and only a join group and the top tier hold rights — not in a tier whose administrators would then own a machine that may turn out to be Tier 0. |
| **Break-glass stays outside** | The generated break-glass account is excluded from the silo and from `Protected Users` by design. |
| **No silent failures** | Every failure path writes to the log, not just to the report object. A problem that only shows up as a number in the summary is a problem nobody finds. |

And if it goes wrong anyway, [`Repair-TierLockout.ps1`](#when-it-goes-wrong) is the way back.

---

## Prerequisites

| Requirement | Detail |
| --- | --- |
| Domain functional level | 2012 R2 minimum. 2016+ for authentication policy silos and LAPS password encryption. |
| PowerShell | 5.1 or 7.x with the `ActiveDirectory` and `GroupPolicy` modules (RSAT). |
| Privileges | Elevated session, member of `Domain Admins`. Schema Admins additionally for the LAPS schema extension. |
| Access | Write access to `\\<domain>\SYSVOL\<domain>\Policies`. |
| Host | The `Domain` stage needs a domain controller (`redircmp` / `redirusr` ship with the AD DS role). The `Laps` stage needs the LAPS module — Windows Server 2022 / Windows 11 22H2 and later. |

Run `.\ADTierKit.ps1 -Mode Check` to verify all of it, including whether the target domain is the forest root.

---

## Quick start

**1. Unblock the files** after copying them to the server:

```powershell
Get-ChildItem C:\ADTierKit -Recurse | Unblock-File
cd C:\ADTierKit
```

**2. Run the wizard:**

```powershell
.\ADTierKit.ps1
```

Eight sections, every question with an example and a default. Naming patterns resolve live, so you see the real object names before accepting them:

```
  Naming pattern for global role groups?
    Available placeholders: {ID}, {ROLE}, {TIER}, {TOKEN}, {TOKENLC}
    Example : G-{TOKEN}-{ROLE}  ->  G-T0-Admins
    Default : G-{TOKEN}-{ROLE}
  > GG_{TOKEN}_{ROLE}
    Resolves to: GG_T0_Admins
```

<div align="center">
  <a href="docs/wizard.png"><img src="docs/wizard.png" alt="The wizard asking for domain, tier count and naming patterns" width="620"></a>
  <br>
  <sub>Every question carries an example and a default, and naming patterns resolve as you type.</sub>
</div>

The sections in order: domain and root container · tier layout · sub-OU names · group naming · administrative accounts · Group Policy · authentication policy silo · remaining options.

<div align="center">
  <a href="docs/wizard-preview.png"><img src="docs/wizard-preview.png" alt="Preview of every OU, group and account that would be created" width="700"></a>
  <br>
  <sub>Nothing is written until you have seen the complete object list, with the purpose of every group spelled out.</sub>
</div>

Afterwards you get a full preview — OU tree, every group, accounts, GPOs, LAPS delegation and the cross-tier deny matrix — then the configuration is written and you choose whether to dry-run, deploy the structure only, deploy everything, or exit.

`.\ADTierKit.ps1 -UseDefaults` accepts every default without prompting, which is a fast way to produce a reference configuration and edit it by hand.

**3. Deploy in stages:**

```powershell
# Plan — this is what Deploy does without -Apply, nothing is written
.\ADTierKit.ps1 -Mode Deploy

# Structure first, policy later
.\ADTierKit.ps1 -Mode Deploy -Apply -Stage RecycleBin,OU,Domain,Group,Nesting,Account,Delegation,Auditing
.\ADTierKit.ps1 -Mode Deploy -Apply -Stage GPO,Laps,KDS,Silo

# Check for drift at any time
.\ADTierKit.ps1 -Mode Audit
```

---

## What belongs in Tier 0

The tool secures whatever the configuration declares as Tier 0. Declaring it correctly is the one
step no tool can do for you — and it is the step most tier deployments get wrong, because Tier 0
is larger than "the domain controllers".

The test is **control, not importance**: anything that can modify a domain controller, the
credentials stored on it, or the policy that reaches it *is* Tier 0, whichever OU it lives in
today. In most environments that list includes:

| System | Why it is Tier 0 |
| --- | --- |
| **AD Certificate Services** | A CA that issues logon-capable certificates can mint a domain controller identity. Every ESC-class attack is a Tier 0 compromise through a "Tier 1" server. |
| **Entra Connect / AAD Connect** | Holds the password-hash-sync credentials and an account with directory-wide replication rights. |
| **Backup infrastructure** | Whoever can read a domain controller system state backup holds `NTDS.dit` — every hash in the domain. The backup server, its service account and its storage are all in scope. |
| **Hypervisors hosting DC VMs** | A host administrator can read DC disks and memory, snapshot credentials, or attach a rogue disk. The virtualisation management plane (vCenter, SCVMM) comes with it. |
| **Endpoint management that reaches DCs** | SCCM/MECM, patch management, EDR consoles with live response — anything that executes code on a DC by design. |
| **Script and installation shares** | A share referenced by a GPO startup script or scheduled task on Tier 0 machines is writable code execution on Tier 0. |
| **Privileged access workstations** | The machines Tier 0 administrators type their credentials into. |
| **The ADTierKit directory itself** | Once the sync task is registered, whoever can edit `ADTierKit.ps1` or `tiermodel.json` runs as SYSTEM on a domain controller at 03:30. The `InstallTask` mode refuses paths writable outside the administrative set for exactly this reason. |

Work through the list before step 2 of the rollout: move these machines into `Tier-0/Servers` (or
`Devices` for the workstations) and their administrators into the Tier 0 role groups. A tier
boundary with the backup server on the wrong side of it is decoration — the deny rights will be
perfectly enforced around a hole.

---

## Recommended rollout order

Deploying tiering in one shot is how people lock themselves out.

```
  1. Structure  ──▶  2. Populate  ──▶  3. Empty built-ins  ──▶  4. GPOs in report mode
     nobody              move objects,     Domain Admins &          link to staging,
     affected            add admins        friends                  watch for failures
                                                                         │
       7. Silo enforce  ◀──  6. Enforce  ◀──  5. Verify a fresh logon  ◀─┘
          after 4820/4821       populate the      in a second session
          are clean             deny groups
```


1. **Structure only** — `-Stage RecycleBin,OU,Domain,Group,Nesting,Account,Delegation,Auditing -Apply`. Nothing is enforced yet; nobody is affected.
2. **Populate** — move servers, workstations and service accounts into the tier OUs, starting with the **staging** OU of each tier rather than production. Add real administrators to the role groups, and give each admin a separate account per tier they work in.
3. **Empty the built-in groups** — run `-Stage PrivilegedGroups` in `Report` mode, work through the list, then switch `privilegedGroups.mode` to `Enforce`.
4. **GPOs in report mode** — link them to the staging OUs first, or link them with the deny groups temporarily emptied, and watch logon failures in the event log.
5. **Verify a fresh logon** — with a second session already open, apply the policy, run `gpupdate /force`, and confirm a *new* logon works in a third session before closing the second.
6. **Enforce** — populate the deny groups and let the GPOs apply to the full tier OUs.
7. **Silo enforcement** — flip `authenticationPolicyEnforcement` from `Audit` to `Enforce` only after event IDs 4820 / 4821 have been clean for a few weeks.

> **Before any silo enforcement:** the workstations your Tier 0 administrators actually work
> from must sit inside the OUs listed in `memberComputerOus` (by default `Tier-0/Devices` and
> `Tier-0/Servers`) and have been picked up by a `Sync` run. An enforced silo allows
> authentication **only from silo members** — a T0 admin whose PAW was never moved in can no
> longer log on anywhere except the domain controller console. The audit phase exists to catch
> exactly this: every 4820/4821 event names an account that would have been refused, so a clean
> event log *is* the proof that the PAWs are in. Note that the log these failures land in —
> `AuthenticationPolicyFailures-DomainController` under *Applications and Services Logs →
> Microsoft → Windows → Authentication* — is **disabled by default**: enable it on every domain
> controller before starting the audit phase, or a clean log proves nothing.

Keep at least one break-glass account **outside** the silo and outside `Protected Users`. The generated configuration does this via `"excludeFromSilo": true`.

---

## Design decisions worth knowing

These are the places where the tool takes a position. Each one is configurable.

### Network logon is not denied across tiers by default

Interactive, remote interactive, batch and service logon place reusable credentials on a machine — those are denied across tiers. `SeDenyNetworkLogonRight` is different: it is what remote management, monitoring agents, backup software and plain file access use. Denying it across tiers produces failures far away from the policy that caused them, and the symptom rarely points back to Group Policy.

The default therefore denies network logon only to `S-1-5-113` (any local account) and `S-1-5-32-546` (Guests) — the part that actually blocks pass-the-hash with local credentials.

### Deny list or allow list

The generated GPOs state who may **not** log on. Choosing **AllowList** in the wizard adds the positive side, so anyone not listed loses the right. That is default-deny and materially stronger — and it is also how you lock yourself out.

Two deliberate omissions in the generated allow lists: `SeServiceLogonRight` and `SeBatchLogonRight` are **not** included, because an allow list on those stops every domain service account not named in it. And `Authenticated Users` stays in `SeNetworkLogonRight`, because removing it makes the machine unreachable over the network.

Before enforcing an allow list, work out which accounts actually run services and scheduled tasks on the machines in that tier — the security log (event 4624, logon type 5 for service and 4 for batch) is the only reliable source, because the directory cannot tell you which account runs what where. Audit mode lists the candidates; confirming them is manual work.

Collect over weeks, not days: a monthly job or a quarterly maintenance account will not have run in a short window, and it will be missing from the list. Machines that were switched off during the collection contribute nothing either — and those are exactly the ones whose service accounts you would omit.

### Granular delegation instead of full control

By default a tier administrator gets `CreateChild, DeleteChild` for the object classes their branch holds, plus `ReadProperty, WriteProperty, Delete, DeleteTree, ExtendedRight, Self` on everything below it. Absent are `WriteDacl` and `WriteOwner`.

That omission is the point: with `GenericAll` a tier administrator can rewrite the delegation that constrains them, which makes the tier boundary advisory rather than binding. Choosing **FullControl** in the wizard restores the old behaviour if a workflow needs it — or add a single `GenericAll` delegation to the JSON yourself.

### Restricted groups: `MemberOf` versus `Replace`

`MemberOf` (default) declares each access group a member of the local group; existing members are left alone and nobody can be locked out. `Replace` enforces the listed members as the *only* members — on every refresh everything else is removed, **including `Domain Admins`**. That is the correct end state, but only switch to it once the access groups are populated and you have verified access with a real tier account.

### Everything privileged is addressed by SID

`Domain Admins`, `Administrators`, `Account Operators`, `Protected Users` — all built-in group names are localised. A German directory calls them `Domänen-Admins` and `Administratoren`. Looking them up by name silently finds nothing, and the audit then cheerfully reports "no problems". Every privileged group in this tool is resolved through its well-known SID, so a localised directory works unchanged.

### Every write is read back when success is not self-evident

Most directory writes fail loudly. A few do not: `Set-ADObject` on `nTSecurityDescriptor` accepts
an owner change and applies only the DACL, returning nothing to indicate it. Code that trusts the
call reports a correction that never happened, on every run, forever.

So the owner write reads the object back and compares before reporting anything. It costs one
round trip per corrected object — nothing, since only drifted objects are written at all — and it
converts an invisible false negative into a `Failed` line that names the object. The same
reasoning is why enforce runs should be executed twice: the second run is the check, and it is
worth doing by hand even where the code checks itself.

DACL and SACL writes keep using `Set-ADObject`, because their success *is* self-evident: the next
run compares every ACE and reports it compliant or missing.

### Membership does not stay correct by itself

Deployment is a one-off event; membership is not. A server moved into a tier OU next month does not join the authentication silo on its own, and nothing in the directory notices.

```powershell
.\ADTierKit.ps1 -Mode Sync          # nesting, account hygiene, silo assignment, ownership
.\ADTierKit.ps1 -Mode InstallTask   # daily at 03:30 as SYSTEM
.\ADTierKit.ps1 -Mode InstallTask -RequireSignedScript -PinConfiguration   # hardened
```

`-RequireSignedScript` registers the task with `ExecutionPolicy AllSigned` after checking that
the script carries a valid signature from a publisher in `LocalMachine\TrustedPublisher`, so a
modified script does not run even for someone who managed to write it. `-PinConfiguration`
passes the configuration's SHA256 to the task; a changed file makes the run stop with exit code
`5` and event 1003 until the task is registered again - every configuration change becomes a
deliberate re-approval.

---

## Configuration reference

The configuration is one JSON document, normally `config/tiermodel.json`. The wizard generates it, but it is plain JSON meant to be edited, diffed and version-controlled.

### Naming placeholders

| Placeholder | Example | Available in |
| --- | --- | --- |
| `{ID}` | `0` | all patterns |
| `{TIER}` | `Tier-0` | all except the tier name itself |
| `{TOKEN}` / `{TOKENLC}` | `T0` / `t0` | all except the tier token itself |
| `{ROLE}` / `{ROLELC}` | `Admins`, `DNS` / `dns` | role group pattern, `roles` block |
| `{RESOURCE}` | `DenyLogon` | access group pattern |
| `{PURPOSE}` | `template`, `Logon-Restrictions` | account and GPO patterns |

### OU references

Used anywhere a `targetOu` appears:

| Value | Resolves to |
| --- | --- |
| `""` | the tier root OU |
| `"Servers"` | `OU=Servers,OU=<tier>,<model root>` |
| `"Tier-1/Servers"` | explicit path below the model root |
| `"$DomainRoot"` | the domain naming context |
| `"$Staging"` | the neutral landing zone below the model root (requires an enabled `staging` block) |
| `"$ModelRoot"` | the model root OU |
| `"$DomainControllers"` | `OU=Domain Controllers,<domain>` |
| `"$SystemContainer"` | `CN=System,<domain>` |
| `"$MicrosoftDns"` | `CN=MicrosoftDNS,CN=System,<domain>` — the DNS server object |
| `"$DomainDnsZones"` | the domain DNS application partition |
| `"$ForestDnsZones"` | the forest DNS application partition |
| `"$PoliciesContainer"` | `CN=Policies,CN=System,<domain>` |
| `"$AdminSDHolder"` | `CN=AdminSDHolder,CN=System,<domain>` |
| `"$DnsZone:contoso.com"` | that zone inside the domain DNS partition |
| `"OU=…,DC=…"` | used verbatim |

### Selected options

| Option | Effect |
| --- | --- |
| `machineAccountQuota` | Value for `ms-DS-MachineAccountQuota`; ships as `0`. The AD default of `10` lets any authenticated user create computer accounts — the entry point for resource-based constrained delegation abuse. |
| `redirectComputersTo` | Target for `redircmp`. Without it, machines joined without an explicit OU land in `CN=Computers`, which cannot have Group Policy linked and therefore receives no tier policy at all. |
| `blockGpoInheritanceOnTierRoots` | Blocks Group Policy inheritance per tier, so the Default Domain Policy does not leak into Tier 0. |
| `gpos[].linkEnabled` | Per GPO: `false` keeps it linked but inactive, and a later deployment respects that instead of switching it back on. |
| `restrictedGroupsMode` | `MemberOf` (additive) or `Replace` (strict). |
| `authenticationPolicyEnforcement` | `Audit` or `Enforce`. Converged on existing policies and silos; `Enforce` is withheld while Kerberos armoring is missing. |
| `authenticationPolicySiloReconcile` | `Report` (default) lists silo members that no longer qualify; `Enforce` removes them. |
| `staging` | The neutral landing zone. Expanded at load time into a deny logon group (every role group of every tier), a join group, delegation, a quarantine GPO and a LAPS policy. Point `redirectComputersTo` at `$Staging` to use it. |
| `attackPathChecks` | Audit only: `enabled`, `trustedPrincipals` (principals that legitimately hold Tier 0 rights, e.g. Entra Connect once it lives in Tier 0), `krbtgtMaxAgeDays`, `maxObjects`. |
| `ownership.mode` | `Report` (default) or `Enforce`. See [Ownership](#ownership). |
| `roles` | Role definitions. Expanded at load time into groups, accounts, ACEs, deny nesting and silo membership. See [Roles](#roles). |
| `builtInNesting` | Generated by role expansion. Nests a group into a built-in group such as `DnsAdmins`, additively. |
| `gpos[].delegation` | Per GPO: `editors`, `readers` and `owner`. |
| `enableAdRecycleBin`, `createKdsRootKey`, `deployWindowsLaps` | Feature switches for the corresponding stages. |

Two choices are **wizard-time, not runtime**: the logon rights mode (`Deny` / `AllowList`) and the
delegation model (`Granular` / `FullControl`). They are questions the wizard asks, and their
*result* is baked into the configuration — as the `delegations` list and the `allowedUserRights`
blocks. Adding a `logonRightsMode` key to the JSON by hand does nothing; to switch, either re-run
the wizard or edit those sections directly.

---

## Reports and logging

Every run writes a timestamped log to `.\Logs`, a JSON + HTML report to `.\Reports`, and a summary to the Windows Application event log (source `ADTierKit`, event IDs 1000 clean / 1001 medium findings / 1002 high findings or failures). Suppress the last one with `-NoEventLog`.

The HTML report is a single self-contained file — clickable severity filters, full-text search, sticky header, dark mode. No external dependencies, so it survives being emailed.

Each report is compared with the previous report of the same mode in the same folder. Findings that were not there last time are marked **new** and get their own filter; findings that disappeared are listed as *resolved*. The event log entry carries both counts - for a daily sync, that is the part worth reading.

Findings are classified so a report can be triaged from the top instead of read line by line:

| Severity | Meaning |
| --- | --- |
| **High** | Something failed, or an attack path is open right now — a privileged group holding principals outside the top tier, unconstrained delegation, a missing or drifted delegation ACE |
| **Medium** | A control the model depends on is missing or has drifted — a GPO, a link, a silo assignment |
| **Low** | A structural object is missing with no immediate security impact |
| **Info** | Everything that went as planned |

---

## Troubleshooting

**The GPO exists but the restrictions do not appear in the GPMC Settings tab.**
Expected. User Rights Assignment and Restricted Groups are not exposed by the `GroupPolicy` module, so the tool writes `GptTmpl.inf` directly into SYSVOL, registers the security client side extension and bumps the GPO version. The **Edit** view shows the settings and clients apply them — the Settings *report* sometimes does not render entries written this way. Verify on a client with `gpresult /h` rather than in the report.

**Nothing changed and the output says "PLAN MODE".**
`-Mode Deploy` plans by default. Add `-Apply`. This is deliberate: a mistyped command line can never change the directory.

**`ms-DS-MachineAccountQuota` or the container redirection fails.**
`redircmp` and `redirusr` ship with the AD DS role, so the `Domain` stage has to run on a domain controller. On a management workstation it reports the tool as unavailable and skips that part.

**The LAPS stage reports the module as missing.**
The LAPS PowerShell module ships with Windows Server 2022 and Windows 11 22H2 (April 2023 update) and later. Only **Windows LAPS** is supported — the legacy Microsoft LAPS with its separate AdmPwd client uses different attributes and a different ACL model and is not handled.

**A moved computer still has its old policy.**
Group Policy applies at reboot or at the next refresh. After moving a machine into a tier OU it needs a `gpupdate /force` or a restart.

**Enforcing privileged groups skipped `Domain Admins`.**
Three guards apply in enforce mode and cannot be turned off: the built-in `Administrator` (RID 500) is never removed, the account running the deployment is never removed, and `Domain Admins` is never emptied. If enforcing would leave it without members, the group is skipped and reported as a failure. Add a declared member first.

**Silo enforcement locked out an account.**
Check event IDs 4820 and 4821 on the domain controllers — they name the account and the machine. The break-glass account is excluded from the silo by design; use it, fix the assignment with `-Mode Sync`, and set `authenticationPolicyEnforcement` back to `Audit` until the log is clean.

---

## When it goes wrong

The tier model works by removing logon rights, which is also its failure mode: put the account you
are working with into a tier role group, and the deny groups take its logon rights away on every
other tier's systems.

**Disabling the GPO does not help.** User rights are *tattooed* — the security extension writes
them into the machine's local security database, and unlinking the GPO only stops them being
written *again*. They have to be put back locally with `secedit`, which means getting onto the
machine first.

### Routes back in, in order

1. **Another domain-joined machine over the network.** Network logon is not denied across tiers by
   default, so PowerShell remoting to the domain controller still works even when interactive and
   remote interactive logon are gone. This is the fastest route and usually the one that works.
2. **The hypervisor console.** Only helps if *interactive* logon is still intact — if the deny hit
   both interactive and remote interactive, the console is locked too.
3. **DSRM.** Reboot into Directory Services Restore Mode and log on as `.\Administrator` with the
   DSRM password. That account is local to the machine and no domain policy touches it. Keep that
   password somewhere you can reach without the domain.

### The scripted way back

```powershell
.\Repair-TierLockout.ps1 -WhatIf          # show what would change
.\Repair-TierLockout.ps1                  # remove the memberships, restore the logon rights
.\Repair-TierLockout.ps1 -EnableGpoLinks  # and re-enable the tier GPOs, if the check comes back clean
```

Four steps, each reported before and after: remove the built-in Administrator from every tier role
group (names taken from your configuration, nothing outside them touched); restore the default
holders of the interactive logon rights and clear the deny entries, exporting the result rather
than assuming it — `-SkipUserRightsRestore` keeps an Administrators-only setting instead; re-check
the deny groups of the GPOs that reach this domain controller recursively against the running
account, the built-in Administrator and `Domain Admins` (the other tiers' deny groups contain the
top tier by design and are not a lockout risk here); and re-enable the GPO links, only with `-EnableGpoLinks` and only if the check was clean.

### The manual way back

If the script cannot run — DSRM only, no remoting, or you would rather see every command. On the
domain controller, elevated:

```powershell
@'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-548,*S-1-5-32-549,*S-1-5-32-550,*S-1-5-32-551,*S-1-5-9
SeRemoteInteractiveLogonRight = *S-1-5-32-544
SeDenyInteractiveLogonRight =
SeDenyRemoteInteractiveLogonRight =
SeDenyBatchLogonRight =
SeDenyServiceLogonRight =
'@ | Set-Content C:\fix.inf -Encoding Unicode

secedit /configure /db C:\fix.sdb /cfg C:\fix.inf /areas USER_RIGHTS
secedit /export /areas USER_RIGHTS /cfg C:\check.txt
findstr /i "InteractiveLogonRight" C:\check.txt
```

The SIDs are Administrators, Account / Server / Print / Backup Operators and Enterprise Domain
Controllers — the Windows default for a domain controller. `-Encoding Unicode` is not optional:
`secedit` only reads UTF-16.

In DSRM, where the policy would be re-applied on the next refresh anyway, also rename the template
out of the way before rebooting:

```powershell
Get-ChildItem C:\Windows\SYSVOL\domain\Policies -Recurse -Filter GptTmpl.inf |
  Where-Object { (Get-Content $_.FullName -Raw) -match 'SeDenyRemoteInteractiveLogonRight' } |
  ForEach-Object { Rename-Item $_.FullName "$($_.Name).bak"; $_.FullName }
```

Then find out what happened. `scesrv.log` records every setting the security extension touched:

```powershell
Get-Content C:\Windows\security\logs\scesrv.log -Tail 120
Get-ADGroupMember DL-T0-DenyLogon -Recursive | Select-Object name, objectClass
```

The second command is usually the answer: an account that should not be there, inherited through
a tier role group.

### What stops it happening again

**The lockout guard** stops a deployment before it writes a restriction that would remove your own
access on the machine you would need to undo it — see [Guardrails](#guardrails).

**The domain controller baseline names its own allow side.** A template writing only deny entries
relies on the allow side living somewhere else, which on a domain controller is an implicit
default rather than a policy. The baseline writes `SeInteractiveLogonRight` and
`SeRemoteInteractiveLogonRight` explicitly, so applying it cannot leave the controller without an
administrative logon path.

**Disabled links stay disabled.** `linkEnabled: false` keeps a GPO linked but inactive, and a
later deployment respects that instead of switching it back on — which matters exactly when you
disabled a link to get out of trouble.

**Keep a second session open.** Before enabling a logon restriction, leave a second administrative
session to the domain controller untouched. Apply, `gpupdate /force`, then verify a *fresh* logon
in a third session. If it fails, recovery is a two-minute job instead of an evening.

---

## Checking the code

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path .\ADTierKit.ps1 -Severity Error
.\tests\Invoke-AllTests.ps1
```

The same runs on every push and pull request in GitHub Actions (`.github/workflows/ci.yml`):
parse check, JSON validation, PSScriptAnalyzer (errors fail the build, warnings become
annotations) and the offline suites on PowerShell 7 and on Windows PowerShell 5.1.

No errors as of the last commit. Running without `-Severity` adds a few hundred style findings
that are deliberate here and can be ignored:

| Rule | Why it does not apply |
|---|---|
| `PSAvoidUsingWriteHost` | The wizard and the status output *are* a console interface. `Write-Output` would put them into the pipeline and corrupt the runners' return values; `Write-Information` is not displayed by default on PowerShell 5.1. Anything that belongs in a log goes through `Write-TierLog`. |
| `PSUseShouldProcessForStateChangingFunctions` | Flags helpers that build an object or return a string. Every function that touches Active Directory does declare `SupportsShouldProcess` — that is what `-WhatIf` depends on. |
| `PSUseSingularNouns` | `LAPS` is a product name, not a plural. |
| `PSAvoidUsingPlainTextForPassword` | Matches `$CredentialDirectory`, which is a folder path rather than a secret. |
| `PSUseOutputTypeCorrectly` | Informational, and these are private helpers inside one script rather than a published module surface. |

The rules that did find real defects are all still on: `PSAvoidUsingEmptyCatchBlock` caught four
swallowed exceptions, two of them inside the lockout guard itself, and
`PSAvoidUsingConvertToSecureStringWithPlainText` led to the credential export taking a
`SecureString` instead of a plaintext string.

---

## Limitations & notes

- **Deployment is additive.** Removing an entry from the configuration does not remove the corresponding object, ACE, group member or GPO link from the directory — a run only converges what is *declared*. Clean up removed entries by hand.
- **Rollback is not automated.** Take a system state backup of a domain controller before the first enforced run. The `RecycleBin` stage exists so that a deleted OU or group is recoverable.
- **Single domain per run.** For a forest, run once per domain and keep the top tier forest-wide. `Enterprise Admins` and `Schema Admins` live in the root domain; the prerequisite check says so when the target is a child domain.
- **Domain controllers cannot be moved** out of `OU=Domain Controllers`; the top-tier restrictions are applied there through a separate linked GPO.
- **Not included:** managed service account (MSA/gMSA/dMSA) ACL delegation, ADMX central store deployment, WMI filters, functional level upgrades, and prepackaged hardening baselines such as AppLocker, BitLocker or Defender. This tool secures the tier boundary; it is not a complete hardening suite.
- **What has not been run.** No production directory, no multi-domain forest, no second
  engineer's review, no code signing. `privilegedGroups.mode: Enforce`, `restrictedGroupsMode:
  Replace`, `logonRightsMode: AllowList` and silo `Enforce` have been deployed but never enforced
  against a populated directory — those four have the largest blast radius and are the ones to
  introduce slowly. The `DnsAdmins` path through MMC or RPC is untested: it needs a second
  machine, since a Tier 0 role account deliberately cannot log on to a domain controller.
- **The test suites in `tests/` run offline against mocks.** They cover configuration expansion
  and stage logic — useful for catching a refactor, useless for catching anything that depends on
  how a real domain controller behaves, which is where the interesting failures live. A write that
  the directory accepts and silently does not apply looks identical to a successful one from
  inside a mock.

---

## Repository layout

```
README.md                     this file
LICENSE                       MIT
ADTierKit.ps1                 the entire tool
Repair-TierLockout.ps1        recovery from a logon lockout
config/tiermodel.json         your configuration — the source of truth
config/roles.example.json     ready-made DNS and Group Policy roles to copy in
Update-TierConfiguration.ps1  brings a pre-1.0 configuration up to the current schema
tests/                        offline test suites — no domain required
lab/Test-LogonMatrix.ps1      logs on with test accounts and checks the tier boundary on a real machine
.github/workflows/ci.yml      parse, analyzer and offline tests on every push
docs/                         screenshots used by this README
docs/OPERATIONS.md            the operator's guide — every setting, the working model, the playbook
Logs/                         per-run transcript, created on first run
Reports/                      JSON + HTML reports
Credentials/                  DPAPI-encrypted passwords of generated accounts
```

`ADTierKit.ps1` is organised into regions, in the order they execute:

| Region | Contents |
| --- | --- |
| `Core` | logging, configuration loading, runtime context, name and schema GUID resolution |
| `Prompts` | console helpers for the wizard |
| `ACL` | access control and audit rule management |
| `GPO` | GPO creation, security template, CSE registration, version bump, links |
| `ConfigurationGenerator` | builds a configuration document from naming patterns |
| `DeploymentStages` | the individual stages |
| `Orchestration` | deploy, audit and sync runners plus reporting |
| `Wizard` | the interactive rollout |
| `Entry point` | mode dispatch — the only part that runs on load |

Generated account passwords are written with `Export-Clixml`, which encrypts them through DPAPI and binds them to the account and machine that produced them:

```powershell
$credential = Import-Clixml .\Credentials\adm-t0-breakglass.xml
$credential.GetNetworkCredential().Password
```

Move it into your password vault and delete the file. This matters most for the break-glass account — without it, the account exists but nobody can log on with it.

## License

[MIT](LICENSE) — see the `LICENSE` file.

<div align="center">
<br>

**Built for the part of tiering that nobody automates: keeping it correct after day one.**

<sub>Issues and pull requests welcome. If you run this against a production directory, the
maintainers would genuinely like to hear how it went.</sub>

</div>
