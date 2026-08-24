# ADTierKit — Operator's Guide

This is the long-form manual: how the tool thinks, every change it makes to the directory and to
the machines the policies reach, how to work with it day to day, and the mistakes that cost
people a weekend. The [README](../README.md) is the reference; this is the walkthrough. If the
two ever disagree, the README and the code win.

## Contents

1. [How the tool thinks](#1-how-the-tool-thinks)
2. [Before the first run](#2-before-the-first-run)
3. [The complete change inventory](#3-the-complete-change-inventory)
4. [Working with it day to day](#4-working-with-it-day-to-day)
5. [The rollout playbook](#5-the-rollout-playbook)
6. [Things that bite](#6-things-that-bite)
7. [When it goes wrong](#7-when-it-goes-wrong)
8. [Verification checklist](#8-verification-checklist)

---

## 1. How the tool thinks

Four ideas explain everything else the tool does. Internalise these and its behaviour stops
being surprising.

**The configuration is the source of truth.** One JSON document — normally
`config/tiermodel.json` — declares every OU, group, account, delegation, GPO, LAPS grant and
silo. The tool never invents objects at run time; it *converges* the directory toward the
document. That makes the document the thing to review, diff and version-control, and it makes a
code review of the tool meaningful: what it can do is bounded by what the document can express.

**Every run is a converge, not a script.** Each stage compares the desired state against the
directory and only touches what differs. Running Deploy twice in a row is not just safe, it is
the recommended self-check: the second run should report everything `Compliant`. Anything it
reports as `Created` or `Updated` on a second pass is a bug or an idempotency gap worth
reporting.

**Plan is the default, writing is opt-in.** `-Mode Deploy` without `-Apply` walks every stage
and prints what *would* happen — the same code path, with the writes suppressed via
`ShouldProcess`. Nothing in the tool writes until you say `-Apply`, with two exceptions that say
so on the tin: `Sync` and `InstallTask`.

**Deployment is additive.** Removing an entry from the configuration does not delete the object
it once created. A run converges what is *declared*; it never garbage-collects what is not.
Renaming a group in the JSON therefore leaves the old group behind — clean up removed entries by
hand, and treat renames as remove-plus-create.

The modes, for reference:

| Command | Writes? | What it does |
| --- | :---: | --- |
| `.\ADTierKit.ps1` | with consent | Interactive wizard: naming, preview, writes the configuration, optionally deploys. |
| `.\ADTierKit.ps1 -Mode Deploy` | with `-Apply` | Converges the directory toward the configuration. `-Stage` limits it to named stages. |
| `.\ADTierKit.ps1 -Mode Audit` | never | Read-only drift report with severity classification. Exit code `2` on drift, `4` on high findings. |
| `.\ADTierKit.ps1 -Mode Sync` | yes | Membership only: group nesting and silo assignment. Safe to schedule. |
| `.\ADTierKit.ps1 -Mode InstallTask` | yes | Registers the daily 03:30 Sync task as SYSTEM — after checking the file ACLs (see §6). |
| `.\ADTierKit.ps1 -Mode Check` | never | Prerequisite check only. Exit code `3` on failure. |

Exit codes (`0` success · `1` deploy failures · `2` drift · `3` prerequisites failed · `4` high
severity findings) are stable, so `Audit` drops into a scheduled job or a pipeline gate without
parsing the report.

---

## 2. Before the first run

**Take a system state backup of a domain controller.** Rollback is not automated. The Recycle
Bin stage exists so a deleted OU or group is recoverable without an authoritative restore, but a
backup is the floor you stand on, not an optional extra.

**Put the kit somewhere only administrators can write.** `C:\Program Files\ADTierKit` is the
right kind of place; `C:\Temp` and department shares are not. This matters twice: the scheduled
task later executes these files as SYSTEM on a domain controller, and `InstallTask` will refuse
paths that principals outside SYSTEM, `Administrators`, `TrustedInstaller`, Domain Admins and
Enterprise Admins can modify. Getting the location right on day one avoids moving it later.

**Unblock the files and run the prerequisite check:**

```powershell
Get-ChildItem 'C:\Program Files\ADTierKit' -Recurse | Unblock-File
cd 'C:\Program Files\ADTierKit'
.\ADTierKit.ps1 -Mode Check
```

The check verifies the functional level (2012 R2 minimum; 2016+ for silo and LAPS encryption
features), the required modules, elevation, SYSVOL write access, and whether the target domain
is the forest root — `Enterprise Admins` and `Schema Admins` live there, and a child domain gets
a reduced privileged-group watch list.

**Decide what Tier 0 actually contains** before generating a configuration. The README section
[What belongs in Tier 0](../README.md#what-belongs-in-tier-0) has the test and the usual
suspects — PKI, Entra Connect, backup, hypervisors hosting DCs, endpoint management that reaches
DCs. The tool secures the boundary you declare; classification is the part it cannot do for you.

**Then run the wizard.** Eight sections, every question with an example and a default, naming
patterns resolving live. Nothing is written until you have seen the complete object preview.
`-UseDefaults` accepts everything and is the fastest way to produce a reference configuration to
edit by hand. The result is `config/tiermodel.json` — put it in version control now, before the
first deployment, so every later change has a diff.

---

## 3. The complete change inventory

Everything the tool writes, stage by stage, with the shipped default values. Where your wizard
answers differ (naming patterns, tier count), substitute accordingly — the *shape* is fixed, the
names are yours. Stages run in this order.

### RecycleBin — forest

Enables the Active Directory Recycle Bin optional feature (GUID
`766ddcd8-acd0-445e-f3b9-a7f9b6744f2a`). **Irreversible and forest-wide.** Requires forest
functional level 2008 R2+. Controlled by `options.enableAdRecycleBin` (default `true`).

### OU — directory structure

Creates `OU=Tiering` (or your chosen root) with one branch per tier, each containing `Accounts`,
`Groups`, `Servers`, `Devices`, `Service-Accounts` and `Staging`. Every OU is created with
*protect from accidental deletion* set and **Group Policy inheritance blocked on the tier
roots** (`blockGpoInheritanceOnTierRoots: true`) — domain-linked GPOs do not reach into the tier
branches, which is deliberate: what applies inside a tier should be declared inside the tier.
ACL inheritance is *not* blocked by default (`blockInheritanceOnTierRoots: false`).

### Domain — three settings outside the tier OUs

| Setting | Value | Effect |
| --- | --- | --- |
| `ms-DS-MachineAccountQuota` | `0` | No ordinary user can create computer accounts. Closes the standard entry point for resource-based constrained delegation abuse. Machine joins now require a delegated right — which the Delegation stage grants to the tier admins on their own branches. |
| Default computer container | redirected to `Tier-2/Staging` | Machines joined without a target OU land in a tier OU with policy instead of `CN=Computers` with none. Uses `redircmp.exe` (must run on a DC). User redirection (`redirectUsersTo`) ships as `null` — off. |
| Site link `options` | bit `1` set on every site link | Replication change notification: a revoked membership reaches remote sites in seconds instead of the 180-minute schedule. |

### Group — the AGDLP skeleton, per tier

Global role groups `G-T<x>-Admins` and `G-T<x>-Operators` (people go here), and domain-local
access groups `DL-T<x>-LocalAdmins`, `DL-T<x>-RemoteDesktop`, `DL-T<x>-DenyLogon` (rights attach
here). Membership changes to a tier's access are group edits, never GPO edits.

### Nesting — the cross-tier lock

Each tier's `DL-T<x>-DenyLogon` group receives the *other* tiers' role groups as members: the
Tier 1 deny group holds the Tier 0 and Tier 2 role groups, and so on. This single membership is
what the GPO deny rights bite on. `builtInNesting` entries (from the roles feature) additionally
nest role groups into built-ins such as `DnsAdmins` — always additively; removal belongs to the
PrivilegedGroups stage.

### Account — templates and break-glass

Per the shipped configuration: `adm-t0-breakglass` and `adm-t0-template` in `Tier-0/Accounts`,
members of `G-T0-Admins`. Created **disabled** (`adminAccountsDisabledOnCreation: true`) and
flagged *account is sensitive and cannot be delegated*
(`adminAccountsSensitiveNoDelegation: true`). Tier 0 admin accounts are added to **Protected
Users** (`addTier0AdminsToProtectedUsers: true`) — except the break-glass account, which carries
`excludeFromSilo: true` and is also kept out of Protected Users so it still works when Kerberos
does not (see §6 for what Protected Users switches off).

Generated passwords are written to `Credentials\<sam>.xml` via `Export-Clixml` — DPAPI-encrypted,
bound to the creating user *and* machine. Move them into your vault and delete the files; they
are unreadable anywhere else by design.

### Delegation — who administers what

Each tier's admin group receives explicit ACEs on its own branch: `CreateChild, DeleteChild` for
the object classes that branch holds, plus `ReadProperty, WriteProperty, Delete, DeleteTree,
ExtendedRight, Self` on everything below — including the full domain-join permission set on the
computer OUs. **Deliberately absent: `WriteDacl` and `WriteOwner`.** With those, a tier admin
could rewrite the delegation that constrains them, and the boundary would be advisory.

The Ownership stage backs this up: it checks that objects under the model root are *owned* by
Domain Admins (RID 512), because an object's owner can always re-permission it regardless of the
DACL. Ships in `Report` mode, scope `$ModelRoot`, capped at 5000 objects per run.

### PrivilegedGroups — the watch list

Compares these groups, addressed by SID so localised directories work, against their declared
membership: Domain Admins (`-512`), Enterprise Admins (`-519`), Schema Admins (`-518`), Key
Admins (`-526`), and Account / Server / Print / Backup Operators (`S-1-5-32-548/549/550/551`).
Ships in `Report` mode. In `Enforce` mode, surplus members are removed — with three guards that
cannot be switched off: RID 500 is never removed, the account running the deployment is never
removed, and Domain Admins is never emptied.

### Auditing — SACLs

Success-audit entries for *Everyone* (`S-1-1-0`) covering create/delete/write/DACL/owner changes
on: the model root, the Domain Controllers OU, the Policies container (a GPO edit changes what
applies where), and `AdminSDHolder`. The SACLs only produce events once the **Directory Service
Changes** audit subcategory is enabled on the domain controllers — the tool tells you this, but
enabling advanced audit policy is your move.

### GPO — the actual logon boundary

Per tier, `T<x>-Logon-Restrictions` linked (enforced, `enforceGpoLinks: true`) to the tier OU,
written directly as a security template (`GptTmpl.inf`, UTF-16 LE) with the security CSE
registered and the machine version bumped — visible in GPMC like any hand-made GPO.

**User rights (deny side, all tiers identical in shape):**

| Right | Denied to | Meaning |
| --- | --- | --- |
| `SeDenyInteractiveLogonRight` | `DL-T<x>-DenyLogon` | Console logon |
| `SeDenyRemoteInteractiveLogonRight` | `DL-T<x>-DenyLogon` | RDP |
| `SeDenyBatchLogonRight` | `DL-T<x>-DenyLogon` | Scheduled tasks |
| `SeDenyServiceLogonRight` | `DL-T<x>-DenyLogon` | Services |
| `SeDenyNetworkLogonRight` | `S-1-5-113`, `S-1-5-32-546` | **Only** local accounts and Guests — not the foreign tiers. See §6 for why. |

**Restricted groups** (`MemberOf` mode — additive, cannot lock anyone out): local
`Administrators` (`S-1-5-32-544`) ← `DL-T<x>-LocalAdmins`; `Remote Desktop Users`
(`S-1-5-32-555`) ← `DL-T<x>-RemoteDesktop`.

**Registry settings**, per tier GPO:

| Value | Data | Effect |
| --- | --- | --- |
| `...\Policies\System\LocalAccountTokenFilterPolicy` | `0` | Keeps UAC remote restrictions for local accounts — remote use of a local admin gets a filtered token. |
| `...\NetworkProvider\HardenedPaths\\\\*\SYSVOL` and `\\*\NETLOGON` | `RequireMutualAuthentication=1, RequireIntegrity=1` | Policy and script retrieval require mutual auth and signing — blocks GPO-over-SMB spoofing. |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | `1` | LSASS as a protected process — raises the bar for credential dumping. |

Each GPO also gets an **exception group** (`DL-T<x>-Exempt-Logon` in the tier's `Groups` OU):
an escape hatch for the one appliance account that legitimately crosses the line, visible and
auditable instead of an undocumented GPO edit.

**The Tier 0 baseline** (`T0-DomainController-Baseline`) links the same deny set to the Domain
Controllers OU — DCs cannot be moved out of their OU, so they get their own link — and
additionally carries an **allow list**: `SeInteractiveLogonRight` and
`SeRemoteInteractiveLogonRight` restricted to `Administrators` + `G-T0-Admins`. Note what that
removes: Account, Server, Print and Backup Operators lose interactive logon on DCs. That is the
point, but if you rely on those groups, know it before you link.

### Laps — Windows LAPS end to end

- **Schema**: `Update-LapsADSchema` if the `msLAPS-*` attributes are missing
  (`updateSchema: true`). Irreversible, needs Schema Admins and reachability of the schema
  master. Requires the Windows LAPS module (Server 2022 / Win11 22H2+ host).
- **Directory permissions**, per delegation entry: computers get self-write on their password
  attributes; `G-T<x>-Admins` get read and reset on their own tier's OU. The Domain Controllers
  OU gets self/read/reset but **no policy GPO and no decryptor entry** — the DSRM password's
  decryptor is always Domain Admins and cannot be redirected.
- **Policy GPO** per tier (`T<x>-LAPS`), values under
  `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS`:

| Value | Default | Meaning |
| --- | --- | --- |
| `BackupDirectory` | `2` | Back up to Active Directory. |
| `PasswordAgeDays` | `30` | Rotation interval. |
| `PasswordLength` / `PasswordComplexity` | `24` / `4` | Upper, lower, digits, specials. |
| `PasswordExpirationProtectionEnabled` | `1` | Nobody can push the expiry beyond policy. |
| `ADPasswordEncryptionEnabled` | `1` (DFL 2016+) | Below DFL 2016 the tool sets `0` and warns: the password is then clear text in the directory, protected only by the ACL. |
| `ADPasswordEncryptionPrincipal` | `G-T<x>-Admins` | **Per tier.** One shared decryptor would make the per-tier ACLs decoration. |
| `ADEncryptedPasswordHistorySize` | `12` | Old passwords stay recoverable. |
| `PostAuthenticationActions` / `...ResetDelay` | `3` / `8` | Reset the password and log off 8 h after the account was used. |

### KDS — gMSA prerequisite

Creates a KDS root key if the forest has none (`createKdsRootKey: true`). Default uses
`-EffectiveImmediately`, which despite its name means *usable after ~10 hours* of replication —
the safe production behaviour. `kdsRootKeyEffectiveImmediately: true` backdates it for
single-DC labs only.

### Silo — the Kerberos boundary

Per configured silo (default: Tier 0 and Tier 1), one authentication policy and one silo:

- **`Tier-0-AuthPolicy`**: user TGT lifetime **240 minutes**
  (`tier0TgtLifetimeMinutes`), and an *allowed-to-authenticate-from* condition requiring the
  source machine to be a silo member — with an `ED` (Enterprise Domain Controllers) escape so a
  DC promoted after the last sync does not orphan the accounts.
- **`Tier-0-Silo`**: members are the role groups' users (`G-T0-Admins`, `G-T0-Operators`), all
  computers under `Tier-0/Devices` and `Tier-0/Servers`, and the domain controllers. Membership
  is (re-)synchronised on every Deploy and every Sync run.
- **Enforcement default: `Audit`.** In audit mode the DCs log event 4820/4821 for every logon
  the silo *would* refuse, and refuse nothing. Flipping
  `options.authenticationPolicyEnforcement` to `Enforce` is the last step of the rollout, not
  the first.

### InstallTask — the daily converge

Registers `\ADTierKit\ADTierKit Membership Sync`: daily at 03:30, as SYSTEM, running
`-Mode Sync` with explicit log and report directories, 2-hour execution limit. Before
registering, the ACLs of the script, the configuration and both parent directories are checked;
paths modifiable outside the administrative set are refused (override: `-SkipAclCheck`, see §6).

### Files on disk

`Logs\` (per-run transcript), `Reports\` (JSON + HTML per run), `Credentials\` (DPAPI-encrypted
account passwords), and timestamped `GptTmpl.inf.bak-*` backups in SYSVOL whenever a security
template is rewritten.

---

## 4. Working with it day to day

**The loop is always the same:** edit the JSON → `-Mode Deploy` (plan) → read the plan →
`-Mode Deploy -Apply` → `-Mode Deploy -Apply` again (the second run is the check — everything
should be `Compliant`) → `-Mode Audit` whenever you want proof. Commit the JSON change together
with the report of the run that applied it and you have a change record for free.

**Onboarding a Tier 0 administrator.** Copy `adm-t0-template` in ADUC (it exists for exactly
this), set a password, enable it, done — the copy inherits the group membership and flags. Give
each human a *separate account per tier they work in*; one account in two tiers' role groups
ends up in both deny lists and works nowhere, which is the model failing safe.

**Bringing a new server into a tier.** Join it (it lands in `Tier-2/Staging` via the
redirection), move it to the right tier's `Staging`, verify the GPOs behave, then move it to
`Servers`. The silo does not know about it until a Sync runs — either wait for 03:30 or run
`.\ADTierKit.ps1 -Mode Sync` by hand. Under an *enforced* silo, do the sync **before** anyone
needs to authenticate from that machine.

**Adding an exception.** Something legitimately needs to cross a tier line? Put the account in
that tier's `DL-T<x>-Exempt-Logon` group and document why in the group's description. That is
the entire mechanism — no GPO edit, visible in every audit.

**Changing policy values.** Edit the JSON, never the GPO. The tier GPOs belong to the tool: a
manual edit to their security template is treated as drift and overwritten on the next run (a
`.bak` is kept, but do not rely on racing the tool). Anything you want to keep goes in the
configuration or in a separate GPO you own.

**Watching for drift.** `-Mode Audit` weekly (or in a pipeline — exit codes `2`/`4` are your
gate) and read the HTML report's High findings first: ownership drift and privileged-group
surplus members are the ones that void the boundary. Pair it with a periodic BloodHound or
Purple Knight run: the audit answers *"is the declared state still true?"*, the graph tools
answer *"are there attack paths that were never declared?"* — you need both.

**Upgrading the tool.** Replace `ADTierKit.ps1`, run `Update-TierConfiguration.ps1` if the
schema version moved, then a plan run before the next apply — the diff between plan and
expectation is your upgrade review.

---

## 5. The rollout playbook

The README's [rollout order](../README.md#recommended-rollout-order) is the map; this is the
same route with the checks written out. The principle behind every step: **nothing that removes
a logon right gets applied until the thing replacing it has been proven to work.**

**Phase 1 — Structure** (`-Stage RecycleBin,OU,Domain,Group,Nesting,Account,Delegation,Auditing -Apply`).
Nothing here restricts anyone. Afterwards: OU tree in ADUC matches the preview, deny groups
exist and contain the foreign role groups, `Get-ADObject -Identity <domain> -Properties
ms-DS-MachineAccountQuota` shows `0`, a test join lands in `Tier-2/Staging`.

**Phase 2 — Populate.** Move machines into the tier OUs — staging first, production after the
GPOs are proven. Move the Tier 0 list from the README's classification section (PKI, Entra
Connect, backup, hypervisors) into `Tier-0/Servers`, and the admin workstations into
`Tier-0/Devices` — **the silo's audit phase can only prove the PAWs are in if they are actually
in.** Create the per-tier admin accounts and populate the role groups.

**Phase 3 — Empty the built-ins.** `-Stage PrivilegedGroups` in `Report` mode gives you the
list. Work through it — every member of Domain Admins either becomes a `G-T0-Admins` member with
a personal T0 account, or gets an explanation, or gets removed. Only then switch
`privilegedGroups.mode` to `Enforce`, and run it twice.

**Phase 4 — GPOs, carefully.** Link to staging OUs first, or link with the deny groups
temporarily emptied. Watch the security log on the targets: 4625 with status
`0xC000015B` ("logon type not granted") is the deny rights working — check *who* it hits.

**Phase 5 — The fresh-logon test.** With a second session already open on a target machine,
`gpupdate /force`, then confirm a *new* logon works in a third session **before closing the
second**. User rights are tattooed; the open session is your way back if the answer is no.

**Phase 6 — Enforce.** Populate the deny groups fully, extend the links from staging to the
full tier OUs, re-run the fresh-logon test per tier.

**Phase 7 — Silo enforcement, last.** First, make the audit phase observable: the log the
would-be denials land in — *Applications and Services Logs → Microsoft → Windows →
Authentication → AuthenticationPolicyFailures-DomainController* — is **disabled by default**
and capped at 1 MB. Enable it on every DC and raise the size, or the audit phase runs for weeks
against an empty log and proves nothing. Then run in `Audit` for weeks, not days. Every entry
there (Event 105/106), and every 4820/4821 in the Security log, is an account the silo would
have refused — chase each one down (usually: a PAW not yet
moved into `Tier-0/Devices`, or a T0 account used from a T1 box, which is a process problem the
event just made visible). Clean log for a few weeks → flip
`authenticationPolicyEnforcement` to `Enforce` → deploy → fresh-logon test from a PAW while a
DC console session stays open. The break-glass account stays outside the silo throughout.

Then `-Mode InstallTask`, and the model maintains its own membership from here.

---

## 6. Things that bite

**Tier 0 classification is the whole game.** Perfectly enforced deny rights around a backup
server that sits in Tier 1 protect nothing. Re-read
[What belongs in Tier 0](../README.md#what-belongs-in-tier-0) once a year and whenever
infrastructure changes — new hypervisor cluster, new backup product, new management tool with an
agent on the DCs.

**Deny rights control *where to*, not *where from*.** A T1 admin RDPing from their ordinary T2
workstation to a T1 server breaks no rule — and exposes T1 credentials to a T2 machine. Only
the Tier 0 silo enforces the source side. For Tier 1/2, source hygiene is operational: dedicated
admin workstations or Remote Credential Guard, and the discipline to use them. The tool cannot
enforce this; the concept still requires it.

**Protected Users switches things off.** Members lose NTLM, DES/RC4, delegation of any kind and
credential caching, and get a non-renewable 4-hour TGT. An account that must work when Kerberos
does not — the break-glass account above all — must stay out, which is why the generated
configuration keeps it out. If a T0 admin suddenly cannot reach an NTLM-only appliance, this is
why, and the answer is the exception group plus a plan to fix the appliance, not removing them
from Protected Users.

**Enforced silos have client-side prerequisites.** Authentication policies ride on Kerberos
armoring (FAST): domain functional level 2012 R2+, *KDC support for claims, compound
authentication and Kerberos armoring* enabled on the DCs, and the matching Kerberos client
setting on the machines T0 admins authenticate from. **The tool does not deploy these two GPO
settings.** Verify them during the audit phase — enforcement without them refuses logons for
the wrong reason.

**User rights are tattooed.** Unlinking a GPO does not restore the rights it removed; the
values persist until something writes new ones. This is why the fresh-logon test keeps a session
open, and why `Repair-TierLockout.ps1` explicitly restores DC logon defaults rather than just
unlinking.

**Allow lists and the service accounts you forgot.** Before enforcing any `allowedUserRights`,
collect logon events 4624 type 4/5 over *weeks* — a monthly job's account will not appear in a
short window, and machines that were off contribute nothing. The generated allow lists
deliberately exclude `SeServiceLogonRight`/`SeBatchLogonRight` and keep `Authenticated Users`
in network logon for exactly these reasons.

**`Replace` mode restricted groups remove Domain Admins too.** `MemberOf` (the default) is
additive and safe. `Replace` makes the listed members the *only* members on every refresh. It
is the correct end state — switch to it only after the access groups are populated and a real
tier account has been verified to have local admin.

**The tier GPOs belong to the tool.** Manual security-template edits in them are drift and get
overwritten (with a `.bak`). Own settings go in the JSON or in your own GPO.

**Additive deployment leaves renames behind.** Renaming a group or OU in the configuration
creates the new one and orphans the old one, which keeps its members and its ACEs. Audit will
not flag it — it is not declared, so it is invisible. Rename = migrate + delete, by hand.

**The kit's own directory is Tier 0.** Whoever can edit the script or the configuration owns
the domain at 03:30. `InstallTask` enforces this with the ACL check; `-SkipAclCheck` exists for
labs and should be treated like `--force` on anything: if you need it in production, the
location is wrong, not the check.

**One forest, one boundary.** The security boundary is the forest, not the domain. In a
multi-domain forest, run per domain but keep Tier 0 forest-wide — a child-domain Tier 0 that
does not include the root domain's privileged groups is a fiction the trust path walks straight
through.

---

## 7. When it goes wrong

The short version — the README's [When it goes wrong](../README.md#when-it-goes-wrong) has the
full route list. Ways back in, in order: an already-open session (this is why the playbook keeps
one), another machine over the network (network logon is not denied across tiers by default),
the built-in RID 500 Administrator at the console, and DSRM as the last resort.
`Repair-TierLockout.ps1 -WhatIf` first, then without: it removes RID 500 from the tier role
groups (that membership is what put it in a deny group), restores the DC logon-right defaults,
and re-checks every deny group before it will re-enable anything. GPO links stay disabled unless
you pass `-EnableGpoLinks` and the check is clean.

---

## 8. Verification checklist

After structure: OU tree matches the preview · deny groups hold the foreign role groups ·
`ms-DS-MachineAccountQuota` is `0` · a test join lands in `Tier-2/Staging` · second Deploy run
is all `Compliant`.

After GPOs: `gpresult /scope computer /r` on a tier machine shows the tier GPO applied ·
fresh logon works for the right account and fails with `0xC000015B` for a foreign-tier account ·
local `Administrators` contains `DL-T<x>-LocalAdmins`.

After LAPS: `Get-LapsADPassword -Identity <machine> -AsPlainText` works as a tier admin of that
tier and **fails as any other tier's admin** · the DC's DSRM password is readable by Domain
Admins only.

Before silo enforcement: PAWs are in `Tier-0/Devices` and a Sync has run · the
`AuthenticationPolicyFailures-DomainController` log is enabled on every DC and has been clean
for weeks (alongside 4820/4821 in the Security log) · FAST settings verified on DCs and PAWs ·
break-glass tested from outside the silo.

Standing: weekly `-Mode Audit` with exit-code gating · the scheduled task's last run result is
`0` · quarterly BloodHound/Purple Knight pass · annual re-read of the Tier 0 classification.
