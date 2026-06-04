# Query Patterns

These patterns are curated Falcon EDR examples organized for LLM use.

Use these patterns as examples only when the requested datasource, event type, and fields match. Do not blindly reuse them across unrelated repositories.

Some patterns below reference event types that are not part of the current packaged 67-event schema subset. Those patterns must be confirmed against the local environment before use.

## Pattern Template

### Name

- Purpose:
- Data source:
- Required fields:
- Optional parameters:
- False positive considerations:

```logscale
# put vetted query here
```

## Falcon EDR Patterns

### Plink RDP tunnel detection

- Purpose: Detect `plink.exe` or `plink64.exe` being used to set up SSH port forwarding to TCP 3389.
- Data source: Falcon EDR `ProcessRollup2`
- Required fields: `#event_simpleName`, `ImageFileName`, `CommandLine`, `aid`, `ComputerName`, `UserName`, `ParentBaseFileName`
- Optional parameters: None
- False positive considerations: Legitimate administrators may use Plink for remote administration.

```logscale
#event_simpleName=ProcessRollup2
| ImageFileName=/\\plink(64)?\.exe$/i
| CommandLine=/\s-(R|L).*:3389/i
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
```

### Remote interactive logons

- Purpose: Find `LogonType=10` remote interactive sessions on a specific endpoint.
- Data source: Falcon EDR `UserLogon`
- Required fields: `#event_simpleName`, `aid`, `LogonType`, `@timestamp`, `UserName`, `UserPrincipal`, `LogonServer`
- Optional parameters: `?aid`
- False positive considerations: RDP and other sanctioned remote admin workflows will appear here.

```logscale
#event_simpleName=UserLogon
| aid=?aid LogonType=10
| table([@timestamp, UserName, UserPrincipal, LogonServer], limit=1000)
```

### Falcon sensor configuration version tracking

- Purpose: Track observed Falcon sensor configuration versions per host and spot hosts with version drift.
- Data source: Falcon EDR `SensorHeartbeat`
- Required fields: `#event_simpleName`, `ConfigurationVersion`, `aid`, `ComputerName`, `@timestamp`, `event_platform`
- Optional parameters: `?ComputerName`
- False positive considerations: Configuration changes may reflect expected staged rollouts or policy changes.

```logscale
#event_simpleName=SensorHeartbeat
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| groupBy([aid, ComputerName, ConfigurationVersion], function=[min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen), count(as=HeartbeatCount)])
| sort(LastSeen, order=desc)
```

### SMB share access activity

- Purpose: Show observed SMB share access activity on hosts, optionally narrowed by user, host, or share name.
- Data source: Falcon EDR `SmbServerShareOpenedEtw`
- Required fields: `#event_simpleName`, `ComputerName`, `UserName`, `SmbShareName`, `RemoteIP`, `@timestamp`
- Optional parameters: `?UserName`, `?ComputerName`, `?SmbShareName`
- False positive considerations: Normal IT administration, software deployment, and file-sharing workflows can appear here.

```logscale
#event_simpleName=SmbServerShareOpenedEtw
| wildcard(field=UserName, pattern=?UserName, ignoreCase=true)
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| wildcard(field=SmbShareName, pattern=?SmbShareName, ignoreCase=true)
| table([@timestamp, ComputerName, UserName, SmbShareName, RemoteIP, DomainName], limit=1000)
| sort(@timestamp, order=desc)
```

### DNS requests to AI domains via lookup

- Purpose: Identify DNS requests to domains in a lookup file while excluding common browser noise.
- Data source: Falcon EDR `DnsRequest`
- Required fields: `#event_simpleName`, `event_platform`, `DomainName`, `ContextBaseFileName`, `ComputerName`
- Optional parameters: Requires lookup file `generative-ai-domains.csv`
- False positive considerations: Browser exclusions reduce noise but do not remove all legitimate use.

```logscale
#event_simpleName=DnsRequest event_platform=Win
| match(file="generative-ai-domains.csv", field=[DomainName],column=domain,ignoreCase=true,mode=glob)
| !in(field=ContextBaseFileName, values=[msedge.exe,chrome.exe],ignoreCase=true)
| SourceProcess := ContextBaseFileName
| groupBy([DomainName, ComputerName,SourceProcess],function=count(as=Count))
| sort(field=Count,type=number,order=desc)
```

### PowerShell encoded command decoding

- Purpose: Detect PowerShell encoded command usage, decode payloads, and summarize reuse across hosts.
- Data source: Falcon EDR `ProcessRollup2`
- Required fields: `#event_simpleName`, `event_platform`, `ImageFileName`, `CommandLine`, `aid`
- Optional parameters: None
- False positive considerations: Administrators and management agents sometimes use encoded PowerShell.

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\powershell\.exe/
| CommandLine=/\s+\-(e|encoded|encodedcommand|enc)\s+/i
| CommandLine=/\-(?<psEncFlag>(e|encoded|encodedcommand|enc))\s+/i
| length("CommandLine", as="cmdLength")
| groupby([psEncFlag, cmdLength, CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| CmdLinePrefix := splitString(field=CommandLine, by="-e* ", index=0)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")
| case {
  DecodedString = /encoded/i
  | SubEncodedString := splitString(field=DecodedString, by="-EncodedCommand ", index=1)
  | SubCmdLinePrefix := splitString(field=EncodedString, by="-EncodedCommand ", index=0)
  | SubDecodedString := base64Decode(SubEncodedString, charset="UTF-16LE");
  *
}
| table([executionCount, uniqueEndpoitnCount, cmdLength, DecodedString, CommandLine])
| sort(executionCount, order=desc)
```

### Driver certificate correlation

- Purpose: Correlate Windows driver load events with certificate metadata from `Event_ModuleSummaryInfoEvent`.
- Data source: Mixed Falcon EDR plus `#repo=detections`
- Required fields: `#event_simpleName`, `event_platform`, `SHA256HashData`, `FilePath`, `FileName`, `OriginalFilename`, `SubjectCN`, `IssuerCN`, `ExternalApiType`
- Optional parameters: None
- False positive considerations: Unsigned or oddly signed drivers are not always malicious; hardware vendors vary.

```logscale
(#event_simpleName=DriverLoad event_platform=Win) OR (#repo=detections ExternalApiType=Event_ModuleSummaryInfoEvent )
| case{
    #event_simpleName=DriverLoad | FilePath=/Device\\HarddiskVolume\d+(?<ShortFileParth>.+$)/;
    *;
}
| selfJoinFilter(field=[SHA256HashData], where=[{#event_simpleName=DriverLoad}, {#repo=detections ExternalApiType=Event_ModuleSummaryInfoEvent}])
| groupBy([SHA256HashData], function=([collect([ShortFileParth, FileName, OriginalFilename, SubjectCN, IssuerCN])]), limit=max)
| FileName=*
| default(value="-", field=[SubjectCN, IssuerCN, OriginalFilename])
```

### Unusual administrative tool clustering

- Purpose: Score suspicious use of common administrative binaries across hosts and time buckets.
- Data source: Falcon EDR `ProcessRollup2`
- Required fields: `#event_simpleName`, `event_platform`, `ImageFileName`, `ProcessStartTime`, `CommandLine`, `aid`, `cid`
- Optional parameters: Thresholds may be tuned
- False positive considerations: Admin activity, troubleshooting, scripts, and software deployment can match.

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(?<FileName>(whoami|net1?|systeminfo|ping|nltest|sc|hostname|ipconfig)\.exe)/i
| ProcessStartTime := ProcessStartTime*1000
| dayBucket := formatTime("%Y-%m-%d %H", field=ProcessStartTime, locale=en_US, timezone=Z)
| CommandLine := lower(CommandLine)
| FileName := lower(FileName)
| regex("(sc|net1?)\s+(?<netFlag>\S+)\s+", field=CommandLine, strict=false)
| netFlag := lower(netFlag)
| case {
       FileName=/net1?\.exe/ AND netFlag="start" | behaviorWeight := "4" ;
       FileName=/net1?\.exe/ AND netFlag="stop" | behaviorWeight := "4" ;
       FileName=/net1?\.exe/ AND netFlag="stop" AND CommandLine=/falcon/i | behaviorWeight := "25" ;
       FileName=/sc\.exe/ AND netFlag="start" | behaviorWeight := "4" ;
       FileName=/sc\.exe/ AND netFlag="stop" | behaviorWeight := "4" ;
       FileName=/sc\.exe/ AND netFlag=/(query|stop)/i AND CommandLine=/csagent/i | behaviorWeight := "25" ;
       FileName=/net1?\.exe/ AND netFlag="share" | behaviorWeight := "2" ;
       FileName=/net1?\.exe/ AND netFlag="user" AND CommandLine=/\/delete/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="user" AND CommandLine=/\/add/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="group" AND CommandLine=/\/domain\s+/i | behaviorWeight := "5" ;
       FileName=/net1?\.exe/ AND netFlag="group" AND CommandLine=/admin/i | behaviorWeight := "5" ;
       FileName=/net1?\.exe/ AND netFlag="localgroup" AND CommandLine=/\/add/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="localgroup" AND CommandLine=/\/delete/i | behaviorWeight := "10" ;
       FileName=/nltest\.exe/ | behaviorWeight := "3" ;
       FileName=/systeminfo\.exe/ | behaviorWeight := "3" ;
       FileName=/whoami\.exe/ | behaviorWeight := "3" ;
       FileName=/ping\.exe/ | behaviorWeight := "3" ;
       FileName=/hostname\.exe/ | behaviorWeight := "3" ;
       FileName=/ipconfig\.exe/ | behaviorWeight := "3" ;
 * }
| default(field=behaviorWeight, value=1)
| format(format="(Score: %s) %s • %s", field=[behaviorWeight, FileName, CommandLine], as="executionDetails")
| groupby([cid,aid, dayBucket], function=[count(FileName, distinct=true, as="fileCount"), sum(behaviorWeight, as="behaviorWeight"), series(executionDetails)], limit=max)
| fileCount >= 5 OR behaviorWeight > 30
| format("[Host Search](https://falcon.crowdstrike.com/investigate/events/en-us/app/eam2/investigate__computer?earliest=-24h&latest=now&computer=*&aid_tok=%s&customer_tok=*)", field=["aid"], as="Host Search")
| sort(behaviorWeight)
| drop([@timestamp, _duration])
```

### Low-frequency network ports

- Purpose: Show remote ports that make up less than 10 percent of observed IPv4 connection volume.
- Data source: Falcon EDR `NetworkConnectIP4`
- Required fields: `#event_simpleName`, `RemotePort`
- Optional parameters: Threshold may be changed
- False positive considerations: Rare ports are not automatically suspicious.

```logscale
#event_simpleName=NetworkConnectIP4
| groupBy([RemotePort], function=count(as=count), limit=max)
| [sum(count, as=total), sort(field=RemotePort, order=ascending, limit=20000)]
| percent := 100 * (count / total)
| drop([total])
| percent < 10
```

### Discovery command counting

- Purpose: Count user execution of common reconnaissance commands and threshold on totals.
- Data source: Falcon EDR `ProcessRollup2`
- Required fields: `event_platform`, `#event_simpleName`, `FileName`, `UserSid`, `UserName`, `CommandLine`
- Optional parameters: Threshold may be tuned
- False positive considerations: Helpdesk, sysadmins, and inventory scripts often trigger this behavior.

```logscale
event_platform=Win #event_simpleName=ProcessRollup2 FileName=/(whoami|ping|net1?|systeminfo|quser|ipconfig)/iF
| UserSid=S-1-5-21-*
| case {
    FileName=/whoami/iF     | whoami:="1";
    FileName=/ping/iF       | ping:="1";
    FileName=/net1?/iF      | net:="1";
    FileName=/systeminfo/iF | systeminfo:="1";
    FileName=/quser/iF      | quser:="1";
    FileName=/ipconfig/iF   | ipconfig:="1";
}
| groupBy([UserName, UserSid], function=([sum(whoami, as=whoami), sum(ping, as=ping), sum(net, as=net), sum(systeminfo, as=systeminfo), sum(quser, as=quser), sum(ipconfig, as=ipconfig), selectLast([CommandLine])]), limit=max)
| rename(field="CommandLine", as="LastCommandRun")
| totalDiscovery:=whoami+ping+net+systeminfo+quser+ipconfig
| totalDiscovery>5
| table([UserName, UserSid, totalDiscovery, whoami, ping, net, systeminfo, quser, ipconfig, LastCommandRun])
```

### Firewall rule change attribution

- Purpose: Attribute firewall rule changes to the processes that triggered them.
- Data source: Falcon EDR `ProcessRollup2` and `FirewallSetRule`
- Required fields: `#event_simpleName`, `ContextProcessId`, `TargetProcessId`, `FirewallRule`, `FirewallRuleId`, `ImageFileName`, `CommandLine`
- Optional parameters: None
- False positive considerations: Local administrators and security products may legitimately change rules.

```logscale
#event_simpleName=ProcessRollup2
| join({#event_simpleName=FirewallSetRule}, key=ContextProcessId, field=TargetProcessId, include=[FirewallRule, FirewallRuleId])
| ImageFileName=/.*\\(?<fileName>.*\..*)/
| table([aid, UserSid, fileName, FirewallRuleId, FirewallRule, ImageFileName, CommandLine])
```

### External connections joined to process context

- Purpose: Correlate external IPv4 connections on a host with the process responsible for the traffic.
- Data source: Falcon EDR `NetworkConnectIP4` and `ProcessRollup2`
- Required fields: `#event_simpleName`, `aid`, `ComputerName`, `RemoteAddressIP4`, `ContextProcessId`, `TargetProcessId`, `FileName`, `UserName`, `ImageFileName`, `RemotePort`, `CommandLine`
- Optional parameters: `?aid`, `?Computername`, `?RemoteIP`, `?Processname`
- False positive considerations: This depends on the join keys and field names matching the environment.

```logscale
#event_simpleName=NetworkConnectIP4 aid=?aid ComputerName=?Computername RemoteAddressIP4=?RemoteIP
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","192.168.0.0/16","172.16.0.0/12","127.0.0.0/8"])
| join({#event_simpleName=ProcessRollup2  FileName=?Processname }, field=[ContextProcessId],key=TargetProcessId, include=[FileName, UserName,ImageFileName, RemoteAddressIP4, RemotePort,CommandLine], mode=left)
| groupBy(UserName, function=collect([FileName, UserName, ImageFileName, RemoteIP, RPort, CommandLine]))
| sort([_count], order=asc)
```

### LOLBin mshta path extraction

- Purpose: Detect `mshta.exe` execution and extract the referenced HTA path, folder, and filename.
- Data source: Falcon EDR `ProcessRollup2` and `ProcessBlocked`
- Required fields: `#event_simpleName`, `event_platform`, `ImageFileName`, `CommandLine`
- Optional parameters: None
- False positive considerations: Some legacy applications and admins may legitimately use `mshta.exe`.

```logscale
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/mshta.exe/i
| CommandLine=/mshta(?:\.exe)?\"?\s+\"?(?<HtaPath>(?:.*?\.hta|(?=\").*?(?=\")|.*?(?=(?:\s|$))))/i
| HtaPath=/(?<HtaFolder>.*)(\\\\|\/)/i
| HtaPath=/(.*(\\\\|\/))?(?<HtaFile>.*)$/i
```

### Parent processes spawning cmd or PowerShell

- Purpose: Show parent process names for `cmd.exe` and `powershell.exe` child executions, grouped by distinct hosts.
- Data source: Falcon EDR `ProcessRollup2`
- Required fields: `#event_simpleName`, `event_platform`, `FileName`, `ComputerName`, `ParentBaseFileName`, `aid`
- Optional parameters: `?ComputerName`
- False positive considerations: Many parent processes legitimately spawn shells during administration or software operations.

```logscale
"#event_simpleName" = ProcessRollup2 event_platform="Win" FileName=/(cmd.exe|powershell.exe)/i
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| groupBy([ParentBaseFileName], function=[count(aid, distinct=true, as="DistinctHosts")])
| sort(DistinctHosts)
| rename(field="ParentBaseFileName", as="FileName")
```

### Suspicious registry persistence changes

- Purpose: Detect changes to common persistence-related registry locations and enrich with username.
- Data source: Falcon EDR `RegGenericValueUpdate` and `UserLogon`
- Required fields: `#event_simpleName`, `RegObjectName`, `RegValueName`, `RegStringValue`, `AuthenticationId`, `UserName`
- Optional parameters: None
- False positive considerations: Installers, enterprise tools, and logon customizations can hit these keys.

```logscale
#event_simpleName=RegGenericValueUpdate
| RegObjectName=/\\(Run|RunOnce|Winlogon|AppInit_DLLs|Image File Execution Options)/i
| RegValueName!=/^(ctfmon|SecurityHealth|OneDrive)$/i
| join({#event_simpleName=UserLogon}, field=AuthenticationId, include=[UserName])
| table([aid, UserName, RegObjectName, RegValueName, RegStringValue])
```

### Suspicious PowerShell execution

- Purpose: Identify PowerShell encoded-command style execution and enrich with username.
- Data source: Falcon EDR `ProcessRollup2` and `UserLogon`
- Required fields: `#event_simpleName`, `ImageFileName`, `CommandLine`, `AuthenticationId`, `UserName`, `ParentImageFileName`
- Optional parameters: None
- False positive considerations: Some enterprise tooling launches PowerShell with encoded parameters.

```logscale
#event_simpleName=ProcessRollup2 ImageFileName=/\\powershell\\.exe/i
| CommandLine=/\s-[eE^]{1,2}[nN][cC][oO][dD][eE][mM][aA][nN][dD^]+\s/i
| join({#event_simpleName=UserLogon}, field=AuthenticationId, include=[UserName])
| table([aid, UserName, ParentImageFileName, ImageFileName, CommandLine])
```

### DNS to GenAI services

- Purpose: Identify DNS requests to a curated list of GenAI-related domains.
- Data source: Falcon EDR `DnsRequest`
- Required fields: `#event_simpleName`, `DomainName`, `ComputerName`, `event_platform`
- Optional parameters: Domain list can be maintained externally
- False positive considerations: Many AI domains are legitimate business traffic; use for visibility, not automatic detection.

```logscale
#event_simpleName=DnsRequest
| in(field=DomainName, values=[".ai", ".ai21.com", ".aleph-alpha.com", ".anthropic.com", ".assemblyai.com", ".bolt.ai", ".bubble.io", ".character.ai", ".claude.ai", ".clickup.com", ".codeium.com", ".cohere.ai", ".copy.ai", ".cursor.so", ".deepmind.com", ".deepseek.ai", ".deepl.com", ".dalle.ai", ".elevenlabs.io", ".feedhive.io", ".forefront.ai", ".grok.x.ai", ".gpt3.com", ".huggingface.co", ".inflection.ai", ".jasper.ai", ".llama.ai", ".looka.com", ".lovable.ai", ".midjourney.com", ".mistral.ai", ".openai.com", ".opus.ai", ".perplexity.ai", ".pi.ai", ".poe.com", ".replicate.com", ".runwayml.com", ".rytr.me", ".scale.com", ".stability.ai", ".sudowrite.com", ".synthesia.io", ".tabnine.com", ".together.ai", ".v0.dev", ".vercel.ai", ".vista.social", ".wordtune.com", ".writesonic.com", ".x.ai", ".you.com", "ai21.com", "aleph-alpha.com", "anthropic.com", "api.anthropic.com", "api.openai.com", "assemblyai.com", "bard.google.com", "bedrock.aws.amazon.com", "bolt.ai", "bubble.io", "character.ai", "chat.openai.com", "chatgpt.com", "claude.ai", "clickup.com", "codeium.com", "cohere.ai", "console.anthropic.com", "copilot.github.com", "copilot.microsoft.com", "copy.ai", "cursor.so", "dalle.ai", "deepmind.com", "deepseek.ai", "deepl.com", "elevenlabs.io", "ernie.baidu.com", "feedhive.io", "forefront.ai", "gemini.google.com", "gigachat.sberbank.ru", "grok.x.ai", "gpt3.com", "huggingface.co", "inflection.ai", "jasper.ai", "labs.perplexity.ai", "llama.ai", "looka.com", "lovable.ai", "midjourney.com", "mistral.ai", "openai.com", "opus.ai", "perplexity.ai", "pi.ai", "platform.openai.com", "poe.com", "replicate.com", "runwayml.com", "rytr.me", "scale.com", "stability.ai", "sudowrite.com", "synthesia.io", "tabnine.com", "together.ai", "v0.dev", "vercel.ai", "vista.social", "wordtune.com", "writesonic.com", "x.ai", "you.com"])
| groupBy([DomainName, ComputerName, event_platform])
| sort(field=_count,type=number,order=desc)
```

### Potential credential dumping

- Purpose: Hunt for LSASS and credential-dumping-related process activity enriched with user and hash context.
- Data source: Falcon EDR `ProcessRollup2`, `UserLogon`, and `SyntheticProcessRollup2`
- Required fields: `#event_simpleName`, `CommandLine`, `ImageFileName`, `ParentImageFileName`, `AuthenticationId`, `UserName`, `aid`, `RawProcessId`, `SHA256HashData`
- Optional parameters: None
- False positive considerations: IR tooling, malware analysis, and some admin tools can match portions of this logic.

```logscale
#event_simpleName=ProcessRollup2
| (CommandLine=/mimikatz|procdump|lsass|sekurlsa/i OR ImageFileName=/\\(mimikatz|procdump|pwdump)\.exe$/i)
| ParentImageFileName!=/\\(powershell|cmd)\.exe$/i
| join({#event_simpleName=UserLogon}, field=AuthenticationId, include=[UserName])
| join({#event_simpleName=SyntheticProcessRollup2}, field=[aid, RawProcessId], include=[SHA256HashData], suffix="Parent")
| table([aid, UserName, ImageFileName, CommandLine, ParentImageFileName, SHA256HashData])
```

## Advanced Multi-Stage Pattern

### DLL and EXE masquerade plus side-loading chain

- Purpose: Trace processes that write both DLL and EXE files to the same path, show masquerading indicators, and follow the chain into side-loading behavior.
- Data source: Falcon EDR `PeFileWritten`, `ProcessRollup2`, `ClassifiedModuleLoad`, `MotwWritten`
- Required fields: Extensive. Confirm all file-write, process lineage, hash, MOTW, and module load fields before reuse.
- Optional parameters: None
- False positive considerations: This is powerful but environment-sensitive; only reuse when the target environment exposes the same event types and field names.

```logscale
defineTable(query={#event_simpleName=/(PeFileWritten)/iF
|lowercase("FileName")
|lowercase("OriginalFilename")
|(FileName="*" and OriginalFilename="*")
| regex("(?<DllFileName>^.*)\.dll", field=FileName, strict=false)
| regex("(?<EXEFileName>^.*)\.exe", field=FileName, strict=false)
| MasquraeCheck:=if(FileName==OriginalFilename, then="Normal", else="Masquarade") |MasquraeCheck!="Normal"
|SusProcessID:=format(format="%s%s", field=[aid,ContextProcessId])
|rename(field="SHA256HashData", as="SusHash")
|rename(field="FileName", as="FileWritten")
|OriginalFilename!=microsoftedgeupdate.exe OriginalFilename!=msedgeupdate.dll
|groupBy([SusProcessID,FilePath],function=([collect([DllFileName,EXEFileName,SusHash,FileWritten,OriginalFilename,CompanyName]),count(DllFileName,as=DllC),count(EXEFileName,as=EXEC)]),limit=max)
|DllC>=1 EXEC>=1 CompanyName=/Microsoft/iF
}, include=[FilePath,FileWritten,OriginalFilename,SusHash,DllFileName,EXEFileName,CompanyName,SusProcessID,ComputerName,UserName], name="DLL-Filewrite")
|defineTable(query={#event_simpleName=/(ProcessRollup2)/iF
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|match(file="DLL-Filewrite", field=[TargetProcessId],column=[SusProcessID],strict=true,include=[FilePath,FileWritten,OriginalFilename,SusHash,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="ParentBaseFileName", as="FileWriteParent")
|case{
CommandLine=* |regex("\"[^\"]+\"\\s+\"(?P<FullPath>[^\"]*\\\\)?", field=CommandLine)| regex(".*\\\\(?<FileNamey>[^\\\\\"]+?)\"?$", field=CommandLine);
*
}
|case{
  FullPath="*" or FileNamey="*" | FileWriteFileSource:=format(format="%s\n\t└-> %s", field=[FileNamey,FullPath]);
  FullPath!="*" FileNamey!="*" | FileWriteFileSource:=format(format="%s", field=[FileName]);
  *
}
| coalesce([FileNamey,FileName],as=FileWriteFile,ignoreEmpty=false)
}, include=[FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName], name="DLL-Parent")
|defineTable(query={#event_simpleName=/(ProcessRollup2)/iF |DLLSideLoadProcess:=format(format="%s\n\t└-> %s", field=[ParentBaseFileName,FileName])
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|match(file="DLL-Parent", field=[ParentProcessId],column=[SusProcessID],strict=true,include=[FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="TargetProcessId", as="ModuleLoadId")
| rename(field="ProcessStartTime", as="ProcessStartTime")
}, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,ModuleLoadId,SusProcessID,ComputerName,UserName], name="DLLSideLoadProcess")
|defineTable(query={#event_simpleName=/(ClassifiedModuleLoad)/iF |rename(field="FileName", as="DllLoad")
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|ContextProcessId:=format(format="%s%s", field=[aid,ContextProcessId])
| "DllLoaded Files":= format(format="%s\n\t└-> %s", field=[DllLoad,FilePath])
|match(file="DLLSideLoadProcess", field=[ContextProcessId],column=[ModuleLoadId],strict=true,include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="TargetProcessId", as="ModuleLoadId")
|case {
  ModuleLoadTelemetryClassification = 1
| ModuleLoadTelemetryClassification := "FIRST_LOAD\n\t\t└->This is the first time this module has been loaded into a process on the host";
  ModuleLoadTelemetryClassification = 2
| ModuleLoadTelemetryClassification := "RUNDLL32_TARGET\n\t\t└->This module is the target of a rundll32.exe invocation";
  ModuleLoadTelemetryClassification = 4
| ModuleLoadTelemetryClassification := "DETECT_TREE\n\t\t└->The module was loaded into a process that is in an active detect tree";
  ModuleLoadTelemetryClassification = 8
| ModuleLoadTelemetryClassification := "MAPPED_FROM_KERNEL_MODE\n\t\t└->The module was loaded into kernel mode address space";
  ModuleLoadTelemetryClassification = 16
| ModuleLoadTelemetryClassification := "UNUSUAL_EXTENSION\n\t\t└->The module has an unexpected, unusual or rare extension";
  ModuleLoadTelemetryClassification = 32
| ModuleLoadTelemetryClassification := "MOTW\n\t\t└->The module has the Mark of the Web zone identifier";
  ModuleLoadTelemetryClassification = 64
| ModuleLoadTelemetryClassification := "SIGN_INFO_CONTINUITY\n\t\t└->The module does not have a valid signature and it was loaded into a process with a primary module that does have a valid signature";
  ModuleLoadTelemetryClassification = 256
| ModuleLoadTelemetryClassification := "ORIGINAL_FILENAME_MISMATCH\n\t\t└->Module's ImageFileName doesn't match OriginalFileName";
  ModuleLoadTelemetryClassification = 512
| ModuleLoadTelemetryClassification := "REMOVABLE_MEDIA\n\t\t└->The module was loaded from removable media (ISO/IMG)";
  ModuleLoadTelemetryClassification = 1024
| ModuleLoadTelemetryClassification := "DATA_EXTENSION\n\t\t└->The module has a data type extension";
  ModuleLoadTelemetryClassification = 257
| ModuleLoadTelemetryClassification := "FIRST_LOAD_AND_FILENAME_MISMATCH\n\t\t└->This is the first time this module has been loaded into a process on the host and its ImageFileName doesnt match OriginalFileName";
  *
| ModuleLoadTelemetryClassification := format(format="Value=%s\n\t\t└->Multiple module load telemetry flags are set, Check ModuleLoadTelemetryClassification documentation", field=[ModuleLoadTelemetryClassification])
}
}, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName], name="DllLoading")
|defineTable(query={readFile([DllLoading])
|groupBy([ProcessStartTime,SusProcessID,ComputerName,UserName],function=([collect([FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash]),count("DllLoaded Files",distinct=true,as="DllLoaded Files Count")]),limit=max)},include=[ProcessStartTime,SusProcessID,ComputerName,FileWriteFile,UserName,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash,"DllLoaded Files Count"], name="Aggregation")
|defineTable(query={#event_simpleName=MotwWritten
|match(file="Aggregation", field=[ComputerName,FileName],column=[ComputerName,FileWriteFile],strict=true,ignoreCase=true, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName,"DllLoaded Files Count"])
|case{
  HostUrl!="" ReferrerUrl="" |FileWriteFileSourceURL:=format(format="Download URL= %s", field=[HostUrl]);
  HostUrl="" ReferrerUrl!="" |FileWriteFileSourceURL:=format(format="Referrer URL= %s", field=[ReferrerUrl]);
  HostUrl!="" OR ReferrerUrl!="" |FileWriteFileSourceURL:=format(format="Download URL= %s\nReferrer URL= %s", field=[HostUrl,ReferrerUrl]);
  *
}
}, include=[FileWriteFile,FileWriteFileSourceURL,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName,"DllLoaded Files Count"], name="MOTW")
|readFile(["Aggregation","MOTW"])
|case{
  FileWriteFileSourceURL!="*" |FileWriteFileSourceURL:=format(format="No URL Found", field=[]);
  *
}
|groupBy([ProcessStartTime,SusProcessID,ComputerName,UserName],function=([collect([FileWriteFileSourceURL,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash,"DllLoaded Files Count"])]))
| ProcessStartTime:=ProcessStartTime*1000 |ProcessStartTime := formatTime("%e %b %Y %r", field=ProcessStartTime, locale=en_UAE, timezone="Asia/Dubai")
| rename([[FilePath,FileWrittenPath],[CompanyName,"ExeAuthorCompanyName"],[ModuleLoadTelemetryClassification,"DllLoaded Files Signature"]])
|drop([SusProcessID])
```
