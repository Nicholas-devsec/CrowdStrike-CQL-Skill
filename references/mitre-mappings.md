# MITRE ATT&CK Mappings for CrowdStrike Hunts

Use this file to translate user-provided telemetry, behaviors, or hunt goals into a likely MITRE ATT&CK technique and a Falcon-friendly query starting point.

This is a hunt-assist reference, not a labeling engine. Do not force an ATT&CK mapping when the telemetry is too weak or ambiguous.

## How To Use This File

When a user provides telemetry:

1. Identify the observable type.
2. Decide whether it looks like execution, persistence, discovery, credential access, lateral movement, or defense evasion.
3. Find the nearest ATT&CK entry below.
4. Start with the smallest high-confidence Falcon query.
5. Then broaden with pivots only if the user wants a wider hunt.

## Mapping Rules

- Map to ATT&CK only when the behavior meaningfully aligns to a technique or sub-technique.
- Prefer sub-techniques when the behavior is specific enough, such as `T1059.001` instead of only `T1059`.
- If multiple techniques plausibly fit, say `Likely ATT&CK mappings:` and list the top 1 to 3 candidates.
- If the telemetry only shows an observable and not the adversary behavior, say `ATT&CK mapping is tentative`.
- Do not claim ATT&CK coverage just because a binary name appears.
- Use ATT&CK to choose a query family, not to overstate certainty.

## Hunt Intake Shortcuts

Use these fast mappings before building a query:

- Encoded PowerShell, `-enc`, `-encodedcommand`, suspicious `powershell.exe`:
  Likely `T1059.001 PowerShell`
- `cmd.exe` used as the execution container for commands or batch logic:
  Likely `T1059.003 Windows Command Shell`
- `whoami`, `query user`, `net user`:
  Likely `T1033 System Owner/User Discovery`
- `tasklist`, `Get-Process`, process enumeration:
  Likely `T1057 Process Discovery`
- `netstat`, `Get-NetTCPConnection`, connection listing:
  Likely `T1049 System Network Connections Discovery`
- `mshta.exe` executing HTA, script, or remote URL:
  Likely `T1218.005 Mshta`
- `rundll32.exe` loading unexpected DLLs:
  Likely `T1218.011 Rundll32`
- Registry `Run`, `RunOnce`, Winlogon, startup persistence:
  Likely `T1547.001 Registry Run Keys / Startup Folder`
- Scheduled task creation or execution:
  Likely `T1053.005 Scheduled Task`
- RDP logons or RDP tunneling:
  Likely `T1021.001 Remote Desktop Protocol`
- Admin shares or SMB-based lateral movement:
  Likely `T1021.002 SMB/Windows Admin Shares`
- LSASS dumping, Mimikatz, Procdump against LSASS:
  Likely `T1003.001 LSASS Memory`

## Technique Mappings

### T1059.001 - PowerShell

- ATT&CK name: `Command and Scripting Interpreter: PowerShell`
- Tactic: `Execution`
- When to map:
  PowerShell is used to execute commands, scripts, encoded payloads, or staged content.
- Common hunt cues:
  `powershell.exe`, `pwsh.exe`, `-enc`, `-encodedcommand`, `FromBase64String`, download cradles, unusual parent processes.
- Primary Falcon event types:
  `ProcessRollup2`
- Key fields:
  `ImageFileName`, `CommandLine`, `ParentImageFileName`, `ParentBaseFileName`, `UserName`, `aid`, `ComputerName`
- Starter query strategy:
  Start with `#event_simpleName=ProcessRollup2` plus `ImageFileName` and command-line filtering.
- Good pivots:
  Same host, same user, same parent process, prevalence of identical command line, decoded payload clustering.
- ATT&CK confidence note:
  High confidence when execution semantics are visible in `CommandLine`.

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(powershell|pwsh)\.exe$/i
| CommandLine=/\s-(e|enc|encoded|encodedcommand)\s+/i
| table([@timestamp, aid, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

### T1059.003 - Windows Command Shell

- ATT&CK name: `Command and Scripting Interpreter: Windows Command Shell`
- Tactic: `Execution`
- When to map:
  `cmd.exe` or batch command execution is used as the primary execution layer.
- Common hunt cues:
  `cmd.exe /c`, `cmd.exe /r`, `.bat`, `.cmd`, suspicious parent-child chains.
- Primary Falcon event types:
  `ProcessRollup2`
- Key fields:
  `ImageFileName`, `CommandLine`, `ParentImageFileName`, `UserName`, `aid`
- Starter query strategy:
  Filter on `cmd.exe`, then narrow by command switches or suspicious children.
- Good pivots:
  Child process tree, prevalence of the same command, user and host spread.
- ATT&CK confidence note:
  High confidence when the shell itself is the execution container.

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\cmd\.exe$/i
| CommandLine=/\s\/[cr]\s/i
| table([@timestamp, aid, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

### T1033 - System Owner/User Discovery

- ATT&CK name: `System Owner/User Discovery`
- Tactic: `Discovery`
- When to map:
  The activity is trying to identify the current user, logged-on users, or account context.
- Common hunt cues:
  `whoami`, `query user`, `quser`, `net user`, user enumeration via PowerShell.
- Primary Falcon event types:
  `ProcessRollup2`
- Key fields:
  `FileName`, `ImageFileName`, `CommandLine`, `UserSid`, `UserName`, `ParentBaseFileName`
- Starter query strategy:
  Hunt process execution of built-in user-discovery commands.
- Good pivots:
  Follow-on discovery commands on the same host or by the same user.
- ATT&CK confidence note:
  Moderate to high depending on whether the executed command clearly enumerates user context.

```logscale
event_platform=Win #event_simpleName=ProcessRollup2
| FileName=/(whoami|quser)\.exe/i OR CommandLine=/\b(net\s+user|query\s+user)\b/i
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc)
```

### T1057 - Process Discovery

- ATT&CK name: `Process Discovery`
- Tactic: `Discovery`
- When to map:
  The activity enumerates running processes or loaded process information.
- Common hunt cues:
  `tasklist`, `Get-Process`, process enumeration from scripts or shells.
- Primary Falcon event types:
  `ProcessRollup2`
- Key fields:
  `FileName`, `CommandLine`, `ParentBaseFileName`, `UserName`, `ComputerName`
- Starter query strategy:
  Hunt for known process-enumeration commands and suspicious parent processes.
- Good pivots:
  Pair with account discovery, network discovery, or credential dumping in the same session.
- ATT&CK confidence note:
  High when the command semantics are explicit.

```logscale
event_platform=Win #event_simpleName=ProcessRollup2
| FileName=/(tasklist|wmic)\.exe/i OR CommandLine=/\b(Get-Process|tasklist)\b/i
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc)
```

### T1049 - System Network Connections Discovery

- ATT&CK name: `System Network Connections Discovery`
- Tactic: `Discovery`
- When to map:
  The behavior enumerates active local or remote network connections.
- Common hunt cues:
  `netstat`, `Get-NetTCPConnection`, `net use`, `net session`.
- Primary Falcon event types:
  `ProcessRollup2`
- Key fields:
  `FileName`, `CommandLine`, `UserName`, `ParentBaseFileName`, `ComputerName`
- Starter query strategy:
  Hunt process execution of discovery commands before pivoting to actual connection telemetry.
- Good pivots:
  `NetworkConnectIP4`, follow-up RDP, SMB, or suspicious outbound connections.
- ATT&CK confidence note:
  Moderate to high; make sure the command is enumerating, not configuring.

```logscale
event_platform=Win #event_simpleName=ProcessRollup2
| CommandLine=/\b(netstat|Get-NetTCPConnection|net\s+use|net\s+session)\b/i
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc)
```

### T1218.005 - Mshta

- ATT&CK name: `System Binary Proxy Execution: Mshta`
- Tactic: `Defense Evasion`
- When to map:
  `mshta.exe` is used to execute HTA content, remote URLs, or script content through a signed Windows utility.
- Common hunt cues:
  `mshta.exe`, `.hta`, `vbscript:`, `javascript:`, remote URL invocation.
- Primary Falcon event types:
  `ProcessRollup2`, `ProcessBlocked`
- Key fields:
  `ImageFileName`, `CommandLine`, `ParentImageFileName`, `ComputerName`, `UserName`
- Starter query strategy:
  Start from `mshta.exe` execution and extract target path or URL.
- Good pivots:
  Parent process, downloaded files, network egress, child processes.
- ATT&CK confidence note:
  High when `mshta.exe` executes script or HTA content.

```logscale
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/mshta.exe/i
| CommandLine=/mshta(?:\.exe)?\"?\s+\"?(?<HtaPath>(?:.*?\.hta|(?=\").*?(?=\")|.*?(?=(?:\s|$))))/i
| table([@timestamp, aid, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine, HtaPath])
| sort(@timestamp, order=desc)
```

### T1218.011 - Rundll32

- ATT&CK name: `System Binary Proxy Execution: Rundll32`
- Tactic: `Defense Evasion`
- When to map:
  `rundll32.exe` is used to load a DLL or invoke exported code in a suspicious way.
- Common hunt cues:
  `rundll32.exe` with unusual paths, remote content, temp folders, random DLLs, or suspicious parents.
- Primary Falcon event types:
  `ProcessRollup2`, `ClassifiedModuleLoad`
- Key fields:
  `ImageFileName`, `CommandLine`, `ParentImageFileName`, `FilePath`, `ModuleLoadTelemetryClassification`
- Starter query strategy:
  Start with process execution, then enrich with module-load context when available.
- Good pivots:
  DLL path, signer, first-seen prevalence, MOTW, parent process lineage.
- ATT&CK confidence note:
  Moderate to high; `rundll32.exe` also has many legitimate uses.

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\rundll32\.exe$/i
| table([@timestamp, aid, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

### T1547.001 - Registry Run Keys / Startup Folder

- ATT&CK name: `Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder`
- Tactic: `Persistence`
- When to map:
  Registry autoruns or startup folder locations are modified to achieve execution on logon.
- Common hunt cues:
  `Run`, `RunOnce`, startup paths, Winlogon-related persistence edits.
- Primary Falcon event types:
  `RegGenericValueUpdate`
- Key fields:
  `RegObjectName`, `RegValueName`, `RegStringValue`, `ProcessImageFileName`, `aid`
- Starter query strategy:
  Hunt writes to common persistence registry paths and then filter obvious noise.
- Good pivots:
  Writing process, resulting child process execution, affected user context.
- ATT&CK confidence note:
  High when the modified key is a well-known autorun location.

```logscale
#event_simpleName=RegGenericValueUpdate
| RegObjectName=/\\(Run|RunOnce|Winlogon|AppInit_DLLs|Image File Execution Options)/i
| table([@timestamp, aid, ComputerName, RegObjectName, RegValueName, RegStringValue, ProcessImageFileName])
| sort(@timestamp, order=desc)
```

### T1053.005 - Scheduled Task

- ATT&CK name: `Scheduled Task/Job: Scheduled Task`
- Tactics: `Execution`, `Persistence`, `Privilege Escalation`
- When to map:
  Windows scheduled tasks are created or modified for persistence or delayed execution.
- Common hunt cues:
  `schtasks.exe`, XML task creation, task names under odd paths, GPO-linked task deployment.
- Primary Falcon event types:
  `ProcessRollup2`
- Key fields:
  `ImageFileName`, `CommandLine`, `ParentImageFileName`, `UserName`, `ComputerName`
- Starter query strategy:
  Hunt `schtasks.exe` creation or modification commands.
- Good pivots:
  Created task name, target binary, later process execution, user or admin context.
- ATT&CK confidence note:
  High when task creation semantics are visible in the command line.

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\schtasks\.exe$/i OR CommandLine=/\bschtasks(\.exe)?\b/i
| table([@timestamp, aid, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

### T1021.001 - Remote Desktop Protocol

- ATT&CK name: `Remote Services: Remote Desktop Protocol`
- Tactic: `Lateral Movement`
- When to map:
  Remote interactive logons or RDP tunneling are used to access another system.
- Common hunt cues:
  `LogonType=10`, RDP-related sessions, Plink tunneling to 3389, suspicious remote admin activity.
- Primary Falcon event types:
  `UserLogon`, `ProcessRollup2`
- Key fields:
  `LogonType`, `aid`, `UserName`, `UserPrincipal`, `LogonServer`, `CommandLine`, `ImageFileName`
- Starter query strategy:
  Start with `UserLogon` for logons or `ProcessRollup2` for RDP tunneling behavior.
- Good pivots:
  Same account across hosts, same source admin tool, adjacent process execution after logon.
- ATT&CK confidence note:
  High when `LogonType=10` or explicit RDP tunneling is present.

```logscale
#event_simpleName=UserLogon
| LogonType=10
| table([@timestamp, aid, ComputerName, UserName, UserPrincipal, LogonServer])
| sort(@timestamp, order=desc)
```

### T1021.002 - SMB/Windows Admin Shares

- ATT&CK name: `Remote Services: SMB/Windows Admin Shares`
- Tactic: `Lateral Movement`
- When to map:
  SMB admin shares or related remote service access are used to move laterally or stage files.
- Common hunt cues:
  Share creation, admin share access, `net use`, remote file placement, service execution chains.
- Primary Falcon event types:
  `SmbServerShareOpenedEtw`, `SmbClientShareOpenedEtw`, `ProcessRollup2`, `NetworkConnectIP4`
- Key fields:
  `SmbShareName`, `ComputerName`, `UserName`, `CommandLine`, `RemoteIP`, `RemotePort`
- Starter query strategy:
  Hunt SMB share access or SMB-oriented command execution first.
- Good pivots:
  User account, destination host, service creation, follow-on process execution.
- ATT&CK confidence note:
  Moderate; share activity alone may be admin behavior rather than lateral movement.

```logscale
#event_simpleName=SmbServerShareOpenedEtw
| table([@timestamp, aid, ComputerName, UserName, SmbShareName, RemoteIP, DomainName])
| sort(@timestamp, order=desc)
```

### T1003.001 - LSASS Memory

- ATT&CK name: `OS Credential Dumping: LSASS Memory`
- Tactic: `Credential Access`
- When to map:
  Activity targets LSASS memory directly or uses known dumping tools and semantics.
- Common hunt cues:
  `mimikatz`, `procdump`, `sekurlsa`, LSASS in command lines, suspicious process access against LSASS.
- Primary Falcon event types:
  `ProcessRollup2`, optionally `SyntheticProcessRollup2`
- Key fields:
  `CommandLine`, `ImageFileName`, `ParentImageFileName`, `RawProcessId`, `SHA256HashData`, `UserName`
- Starter query strategy:
  Start with known tool names and LSASS-oriented command-line semantics, then enrich with user and hash context.
- Good pivots:
  Same hash on multiple hosts, parent process lineage, privilege context, adjacent discovery activity.
- ATT&CK confidence note:
  High when the command line explicitly targets LSASS or uses a well-known dumping tool.

```logscale
#event_simpleName=ProcessRollup2
| (CommandLine=/mimikatz|procdump|lsass|sekurlsa/i OR ImageFileName=/\\(mimikatz|procdump|pwdump)\.exe$/i)
| table([@timestamp, aid, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

## Multi-Technique Hunt Patterns

Use these when the user gives a broader hunt story instead of a single IOC.

### Office app spawning PowerShell

- Likely ATT&CK mappings:
  `T1059.001 PowerShell`
- Sometimes also relevant:
  broader execution or initial access context, depending on delivery method
- Query approach:
  Hunt parent-child process relationships first, then prevalence, then decoded payloads if present.

### Admin utilities used in bursts

- Likely ATT&CK mappings:
  `T1033 System Owner/User Discovery`
  `T1057 Process Discovery`
  `T1049 System Network Connections Discovery`
- Query approach:
  Use a weighted or grouped prevalence query across `whoami`, `nltest`, `net`, `ipconfig`, `systeminfo`, `ping`, `quser`.

### RDP plus suspicious process execution

- Likely ATT&CK mappings:
  `T1021.001 Remote Desktop Protocol`
- Query approach:
  Find `LogonType=10` events, then pivot to process execution on the same host and same time window.

### Registry persistence plus follow-on execution

- Likely ATT&CK mappings:
  `T1547.001 Registry Run Keys / Startup Folder`
- Query approach:
  Hunt registry writes first, then look for the referenced binary executing later on the same host.

## Ambiguity Guidance

Do not over-map the following:

- DNS requests alone:
  Usually this is a lead, not enough for a firm ATT&CK technique without process or session context.
- Network connections alone:
  Often useful for scoping, but not always enough to classify ATT&CK behavior.
- File writes alone:
  Helpful for pivots, but not always enough to assign a technique.
- Generic shell execution:
  If the command line content is weak, keep the ATT&CK mapping tentative.

## Maintenance Notes

- Source priority: official MITRE ATT&CK technique pages.
- This file should be updated when ATT&CK technique names, IDs, or tactic assignments change.
- Checked against official MITRE ATT&CK pages on 2026-06-04.
