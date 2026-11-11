# Field Maps

This file is the primary guide for hunting with the 67 packaged events: confirmed fields, pivots, join keys, and notes.

Use these field maps before generating queries.

This file explains how to hunt with each event: useful pivots, join keys, and notes. It does not list every field. For the complete list of confirmed fields per event, use [event-field-catalog.md](event-field-catalog.md). If a field is missing here, check the catalog before assuming it does not exist.

## Contents

- [How To Use This File](#how-to-use-this-file)
- [Common Cross-Event Anchors](#common-cross-event-anchors)
- [Raw Event Coverage](#raw-event-coverage)
- [Core Falcon EDR Events](#core-falcon-edr-events): `ProcessRollup2`, `SyntheticProcessRollup2`, `NetworkConnectIP4`, `DnsRequest`, `UserLogon`, `UserLogonFailed2`, `ProcessAncestryInformation`
- [Persistence and Configuration Events](#persistence-and-configuration-events): `RegGenericValueUpdate`, `RegCrowdstrikeValueUpdate`, `RegSystemConfigValueUpdate`, `AsepValueUpdate`, `AsepKeyUpdate`, `ScheduledTaskRegistered`, `ScheduledTaskDeleted`, `CreateService`, `ServiceStopped`, `KernelServiceStarted`
- [File and Content Events](#file-and-content-events): `MsiFileWritten`, `NewExecutableWritten`, `NewExecutableRenamed`, `ExecutableDeleted`, `RegistryHiveFileWritten`, `MotwWritten`, `LFODownloadConfirmation`, `GzipFileWritten`, `ZipFileWritte`, `SevenZipFileWritten`, `JavaClassFileWritten`, `PythonFileWritten`, `WebScriptFileWritten`, `NewScriptWritten`, `ScriptFileWrittenInfo`, `ScriptControlDetectInfo`, `MSDocxFileWritten`, `SuspiciousPeFileWritten`, `FileWrittenWithEntropyHigh`
- [Network and Share Events](#network-and-share-events): `NetworkReceiveAcceptIP4`, `SuspiciousDnsRequest`, `SmbClientShareOpenedEtw`, `SmbServerShareOpenedEtw`, `DirectoryTraversalOverSMB`, `NetShareDelete`, `FirewallSetRule`, `FirewallDeleteRule`
- [Injection, Handle, and Advanced Detection Events](#injection-handle-and-advanced-detection-events): `InjectedThread`, `ProcessInjection`, `DllInjection`, `BrowserInjectedThread`, `ReflectiveDotnetModuleLoad`, `SuspiciousPrivilegedProcessHandle`, `RegistryOperationDetectInfo`, `SuspiciousRegAsepUpdate`, `SAMHashDumpFromUnsignedModule`
- [Operational and Miscellaneous Events](#operational-and-miscellaneous-events): `SensorHeartbeat`, `DriverLoad`, `AgentConnect`, `BITSJobCreated`, `DetectionExcluded`, `FileDeleteInfo`, `FileOpenInfo`, `VolumeSnapshotDeleted`, `ScreenshotTakenEtw`, `SensitiveWmiQuery`, `PeVersionInfo`, `WmiProviderRegistrationEtw`, `RansomwareOpenFile`, `RansomwareFileAccessPattern`
- [Environment Notes](#environment-notes)

## How To Use This File

1. Pick the target `#event_simpleName`.
2. Check for confirmed fields below.
3. Prefer the confirmed native Falcon field names first.
4. When ECS-style aliases also exist, they can be used for compatibility queries, but prefer native names when following existing Falcon examples in this skill.
5. Only use joins when the join keys are confirmed here or in the user’s prompt.

## Common Cross-Event Anchors

These fields appear broadly and are usually safe starting pivots when present:

- `aid`
- `cid`
- `ComputerName`
- `UserName`
- `@timestamp`
- `event_platform`
- `ContextProcessId`
- `TargetProcessId`
- `AuthenticationId`
- `ContextBaseFileName`
- `CommandLine`
- `FileName`
- `ImageFileName`
- `SHA256HashData`
- `Technique`
- `Tactic`

## Raw Event Coverage

The following `#event_simpleName` values are included in this packaged skill and can be treated as in-scope for query generation:

- `NetworkConnectIP4`, `DnsRequest`, `SensorHeartbeat`, `RegCrowdstrikeValueUpdate`, `ProcessAncestryInformation`, `UserLogon`, `NewScriptWritten`, `NetworkReceiveAcceptIP4`, `DriverLoad`, `GzipFileWritten`, `SyntheticProcessRollup2`, `ExecutableDeleted`, `NewExecutableWritten`, `RegistryHiveFileWritten`, `AsepValueUpdate`, `LFODownloadConfirmation`, `FirewallDeleteRule`, `RegSystemConfigValueUpdate`, `ServiceStopped`, `NewExecutableRenamed`, `SensitiveWmiQuery`, `ReflectiveDotnetModuleLoad`, `ZipFileWritte`, `WebScriptFileWritten`, `AgentConnect`, `BITSJobCreated`, `InjectedThread`, `MotwWritten`, `RegGenericValueUpdate`, `AsepKeyUpdate`, `PeVersionInfo`, `ScheduledTaskRegistered`, `ScheduledTaskDeleted`, `CreateService`, `JavaClassFileWritten`, `ScriptControlDetectInfo`, `MSDocxFileWritten`, `ScriptFileWrittenInfo`, `SmbClientShareOpenedEtw`, `UserLogonFailed2`, `ScreenshotTakenEtw`, `SuspiciousDnsRequest`, `SuspiciousPrivilegedProcessHandle`, `RegistryOperationDetectInfo`, `SuspiciousRegAsepUpdate`, `DetectionExcluded`, `SevenZipFileWritten`, `ProcessInjection`, `FileDeleteInfo`, `SmbServerShareOpenedEtw`, `KernelServiceStarted`, `FileWrittenWithEntropyHigh`, `FileOpenInfo`, `VolumeSnapshotDeleted`, `PythonFileWritten`, `WmiProviderRegistrationEtw`, `DirectoryTraversalOverSMB`, `DllInjection`, `SuspiciousPeFileWritten`, `NetShareDelete`, `BrowserInjectedThread`, `SAMHashDumpFromUnsignedModule`, `RansomwareOpenFile`, `RansomwareFileAccessPattern`, `FirewallSetRule`

Use the curated sections below for the safest fields and pivots.

## Core Falcon EDR Events

### ProcessRollup2

- Source: Packaged field inventory
- Confirmed fields:
  `ProcessStartTime`, `ProcessEndTime`, `ParentProcessId`, `TargetProcessId`, `SourceProcessId`, `RawProcessId`, `RpcClientProcessId`, `ParentAuthenticationId`, `AuthenticationId`, `UserSid`, `UserName`, `ComputerName`, `FileName`, `ImageFileName`, `FilePath`, `CommandLine`, `ParentBaseFileName`, `GrandParentBaseFileName`, `OriginalFilename`, `SHA256HashData`, `SHA1HashData`, `MD5HashData`, `AuthenticodeHashData`, `IntegrityLevel`, `ContextProcessId`, `ContextBaseFileName`, `HostUrl`, `ReferrerUrl`, `Tags`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `aid`, `ComputerName`, `UserName`, `AuthenticationId`, `TargetProcessId`, `RawProcessId`, `ContextProcessId`
- Confirmed join candidates:
  `AuthenticationId` to `UserLogon` or other events that explicitly expose the same key
  `TargetProcessId` or `ContextProcessId` to other process-context events
  `[aid, RawProcessId]` to `SyntheticProcessRollup2`
- Notes:
  This is the primary process execution event for most Falcon EDR hunts.
  It contains both command-line and parent process context.

### SyntheticProcessRollup2

- Source: Packaged field inventory
- Confirmed fields:
  `ProcessStartTime`, `ProcessEndTime`, `ParentProcessId`, `TargetProcessId`, `SourceProcessId`, `RawProcessId`, `AuthenticationId`, `UserSid`, `UserName`, `ComputerName`, `FileName`, `ImageFileName`, `FilePath`, `CommandLine`, `SHA256HashData`, `SHA1HashData`, `MD5HashData`, `IntegrityLevel`, `ContextTimeStamp`, `TreeId`, `SyntheticPR2Flags`, `aid`, `cid`, `event_platform`
- Confirmed ECS aliases:
  `process.command_line`, `process.executable`, `process.pid`, `process.entity_id`, `process.parent.entity_id`, `process.hash.sha256`, `process.hash.sha1`, `process.hash.md5`, `process.start`, `process.end`, `file.target_path`, `file.name`, `host.hostname`, `host.os.platform`, `user.name`
- Confirmed useful pivots:
  `[aid, RawProcessId]`, `process.entity_id`, `SHA256HashData`, `UserName`, `ComputerName`
- Confirmed join candidates:
  `[aid, RawProcessId]` from `ProcessRollup2`
- Notes:
  Useful for hash enrichment and ECS-style hunting.

### NetworkConnectIP4

- Source: Packaged field inventory
- Confirmed fields:
  `Protocol`, `ConnectionDirection`, `ConnectionFlags`, `InContext`, `IcmpCode`, `IcmpType`, `LocalIP`, `LocalAddressIP4`, `LocalPort`, `LPort`, `RemoteIP`, `RemoteAddressIP4`, `RemoteAddressString`, `RemotePort`, `RPort`, `CommunityID`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ContextBaseFileName`, `ComputerName`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `aid`, `ComputerName`, `ContextProcessId`, `ContextBaseFileName`, `RemoteAddressIP4`, `RemotePort`
- Confirmed join candidates:
  `ContextProcessId` to process events
- Notes:
  This is the primary IPv4 outbound/inbound connection telemetry event.
  Both `RemotePort` and `RPort` appear present in the dump.

### DnsRequest

- Source: Packaged field inventory
- Confirmed fields:
  `DomainName`, `RequestType`, `DnsRequestCount`, `QueryStatus`, `DualRequest`, `DnsResponseType`, `RespondingDnsServer`, `InterfaceIndex`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ContextBaseFileName`, `ComputerName`, `LocalIP`, `LocalAddressIP4`, `IP4Records`, `FirstIP4Record`, `IP6Records`, `FirstIP6Record`, `CNAMERecords`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `DomainName`, `ContextProcessId`, `ContextBaseFileName`, `ComputerName`, `aid`
- Confirmed join candidates:
  `ContextProcessId` to process events
- Notes:
  Strong event for domain-based hunting and process-attributed DNS pivots.

### UserLogon

- Source: Packaged field inventory
- Confirmed fields:
  `LogonTime`, `ClientComputerName`, `UserPrincipal`, `AuthenticationId`, `UserSid`, `UserName`, `LogonServer`, `LogonDomain`, `RemoteAccount`, `UserIsAdmin`, `EnabledPrivilegesBitmask`, `PrivilegesBitmask`, `UserGroupsBitmask`, `RemoteAddressIP6`, `destination.ip`, `source.ip`, `source.domain`, `ContextThreadId`, `ContextProcessId`, `ComputerName`, `event_platform`, `Technique`, `Tactic`, `aid`
- Confirmed ECS aliases:
  `agent.id`, `host.hostname`, `host.os.platform`, `process.entity_id`, `network.type`, `event.action`, `user.name`
- Confirmed useful pivots:
  `AuthenticationId`, `UserSid`, `UserName`, `ClientComputerName`, `LogonServer`, `source.ip`
- Confirmed join candidates:
  `AuthenticationId` to process or registry events that also carry it
- Notes:
  This is better than assuming `UserIdentity` in environments where `UserLogon` is the actual logon event.

### UserLogonFailed2

- Source: Packaged field inventory
- Confirmed fields:
  `Status`, `SubStatus`, `ClientComputerName`, `RawProcessId`, `TargetProcessId`, `UserName`, `LogonDomain`, `RemoteIP`, `RemoteAddressIP4`, `RemoteAddressIP6`, `LogonType`, `ContextThreadId`, `ContextProcessId`, `ComputerName`, `event_platform`, `Technique`, `Tactic`, `aid`, `AuthenticationId`
- Confirmed ECS aliases:
  `agent.id`, `host.hostname`, `host.os.platform`, `process.entity_id`, `process.pid`, `destination.ip`, `source.ip`, `source.domain`, `event.action`, `user.name`
- Confirmed useful pivots:
  `UserName`, `ClientComputerName`, `RemoteIP`, `LogonType`, `ContextProcessId`
- Notes:
  Useful for failed-auth and brute-force style hunt pivots.

### ProcessAncestryInformation

- Source: Packaged field inventory
- Confirmed fields:
  `BaseFileName`, `ParentBaseFileName`, `GrandParentBaseFileName`, `GreatGrandParentBaseFileName`, `SHA256HashData`, `ParentSHA256HashData`, `GrandparentSHA256HashData`, `GreatGrandparentSHA256HashData`, `OriginalFilename`, `TargetProcessId`, `ComputerName`, `event_platform`, `aid`, `cid`
- Confirmed useful pivots:
  `TargetProcessId`, `BaseFileName`, hash lineage fields
- Notes:
  Good for lineage and ancestry enrichment when parent-child context from `ProcessRollup2` is not enough.

## Persistence and Configuration Events

### RegGenericValueUpdate

- Source: Packaged field inventory
- Confirmed fields:
  `registry.value`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ComputerName`, `RegClassificationIndex`, `RegClassification`, `RegClassificationFlags`, `RegValueName`, `RegNumericValue`, `RegStringValue`, `RegObjectName`, `RegType`, `RegOperationType`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed ECS aliases:
  `agent.id`, `host.hostname`, `host.os.platform`, `process.entity_id`, `network.type`, `event.action`, `source.ip`, `registry.key`, `threat.technique.name[0]`, `threat.tactic.name[0]`
- Confirmed useful pivots:
  `RegObjectName`, `RegValueName`, `RegStringValue`, `RegNumericValue`, `AuthenticationId`, `ContextProcessId`
- Confirmed join candidates:
  `AuthenticationId` to `UserLogon` or process context
  `ContextProcessId` to process events
- Notes:
  Strong registry-value event for persistence, system tampering, and config hunts.

### RegCrowdstrikeValueUpdate

- Source: Packaged field inventory
- Confirmed fields:
  `registry.value`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ComputerName`, `RegClassificationIndex`, `RegClassification`, `RegClassificationFlags`, `RegValueName`, `RegNumericValue`, `RegStringValue`, `RegBinaryValue`, `RegObjectName`, `RegType`, `RegOperationType`, `event_platform`, `aid`, `cid`
- Confirmed ECS aliases:
  `agent.id`, `host.hostname`, `host.os.platform`, `process.entity_id`, `network.type`, `event.action`, `source.ip`, `registry.key`
- Confirmed useful pivots:
  `RegObjectName`, `RegValueName`, `RegStringValue`, `RegBinaryValue`, `AuthenticationId`, `ContextProcessId`
- Notes:
  This appears to be Falcon-specific registry/config telemetry and is useful for Falcon tamper or agent-configuration hunts.

### RegSystemConfigValueUpdate

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `Technique`, `@rawstring`, `@timezone`, `TreeId`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `@timestamp.nanos`, `ContextTimeStamp`, `RegNumericValue`, `aip`, `Tactic`, `RegClassificationIndex`, `RegValueName`, `event_platform`, `BoundingLimitCount`, `RegClassification`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `RegStringValue`, `RegBinaryValue`, `ConfigBuild`, `aid`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`, `RegClassificationFlags`, `RegOperationType`, `cid`, `RegObjectName`, `RegType`
- Notes:
  Useful for system configuration change hunts after confirming the exact registry fields.

### AsepValueUpdate

- Source: Packaged field inventory
- Confirmed fields:
  `TargetSHA256HashData`, `FilePath`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ComputerName`, `UserName`, `FileName`, `TargetFileName`, `TargetCommandLineParameters`, `RegNumericValue`, `RegValueName`, `RegStringValue`, `RegBinaryValue`, `RegObjectName`, `RegType`, `RegOperationType`, `AsepIndex`, `AsepFlags`, `AsepClass`, `AsepValueType`, `RpcClientThreadId`, `RpcClientProcessId`, `TreeId`, `BoundingLimitCount`, `BoundingLimitDuration`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `RegObjectName`, `RegValueName`, `TargetFileName`, `TargetSHA256HashData`, `UserName`, `ContextProcessId`
- Confirmed join candidates:
  `AuthenticationId` to logon/process context
  `ContextProcessId` to process events
- Notes:
  High-value ASEP telemetry for ATT&CK `T1547.001` and similar persistence hunts.

### AsepKeyUpdate

- Source: Packaged field inventory
- Confirmed fields:
  `AuthenticationId`, `TokenType`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ComputerName`, `UserName`, `AsepFlags`, `AsepIndex`, `AsepClass`, `AsepValueType`, `RegObjectName`, `RegOperationType`, `BoundingLimitCount`, `BoundingLimitDuration`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `RegObjectName`, `AsepClass`, `UserName`, `AuthenticationId`, `ContextProcessId`
- Confirmed join candidates:
  `AuthenticationId` to logon/process context
  `ContextProcessId` to process events
- Notes:
  Key-oriented ASEP telemetry that complements `AsepValueUpdate`.

### ScheduledTaskRegistered

- Source: Packaged field inventory
- Confirmed fields:
  `TaskAuthor`, `TaskName`, `TaskExecArguments`, `TaskExecCommand`, `TaskXml`, `RpcOpNum`, `RpcClientProcessId`, `RpcClientThreadId`, `RpcNestingLevel`, `InterfaceGuid`, `InterfaceVersion`, `AuthenticationId`, `TokenType`, `UserName`, `ComputerName`, `ContextTimeStamp`, `ContextProcessId`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `TaskName`, `TaskExecCommand`, `TaskExecArguments`, `UserName`, `ContextProcessId`
- Confirmed join candidates:
  `ContextProcessId` to process events
  `AuthenticationId` to logon/process context
- Notes:
  Strong event for ATT&CK `T1053.005`.

### ScheduledTaskDeleted

- Source: Packaged field inventory
- Confirmed fields:
  `TaskName`, `RpcOpNum`, `RpcClientProcessId`, `RpcClientThreadId`, `RpcNestingLevel`, `InterfaceGuid`, `InterfaceVersion`, `AuthenticationId`, `TokenType`, `UserName`, `ComputerName`, `ContextTimeStamp`, `ContextProcessId`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed ECS aliases:
  `process.entity_id`, `process.pid`, `host.hostname`, `host.os.platform`, `event.action`, `user.name`, `threat.technique.name[0]`, `threat.tactic.name[0]`
- Notes:
  Useful for defense evasion or cleanup hunts around scheduled-task abuse.

### CreateService

- Source: Packaged field inventory
- Confirmed fields:
  `ServiceServiceDll`, `ServiceDependOnService`, `ServiceSecurity`, `ServiceRequiredPrivileges`, `ServiceDelayedAutoStart`, `ServiceDescription`, `ServiceFailureActions`, `ServiceDisplayName`, `ServiceServiceSidType`, `ServiceGroup`, `ServiceErrorControl`, `ServiceImagePath`, `RpcClientProcessId`, `RpcClientThreadId`, `AuthenticationId`, `TokenType`, `UserName`, `ContextThreadId`, `ContextProcessId`, `ComputerName`, `BoundingLimitCount`, `BoundingLimitDuration`, `event_platform`, `Technique`, `Tactic`, `aid`
- Confirmed useful pivots:
  `ServiceImagePath`, `ServiceDisplayName`, `ContextProcessId`, `UserName`
- Confirmed join candidates:
  `ContextProcessId` to process events
- Notes:
  High-value for service-based persistence and lateral movement hunts.

### ServiceStopped

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `TargetProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `Technique`, `ClientProcessStartKey`, `#event.dataset`, `file.target_path`, `IsHosted`, `FilePath`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `process.command_line`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `event_platform`, `aip`, `BoundingLimitCount`, `ServiceDisplayName`, `Tactic`, `process.entity_id`, `@rawstring`, `@timezone`, `TargetProcessId`, `Parser.version`, `process.executable`, `host.hostname`, `EtwRawProcessId`, `event.action`, `source.ip`, `EtwRawRpcClientProcessId`, `network.type`, `BoundingLimitDuration`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `process.pid`, `ConfigBuild`, `#ecs.version`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `SourceProcessId`, `CommandLine`
- Notes:
  Relevant for defense evasion or service tampering.

### KernelServiceStarted

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `aip`, `Tactic`, `ServiceDisplayName`, `Technique`, `event_platform`, `FilePath`, `@rawstring`, `@timezone`, `ImageFileName`, `Agent IP`, `RpcClientProcessId`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `LocalAddressIP4`, `ConfigBuild`, `ContextThreadId`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `FileName`, `ImageBaseName`, `@timestamp.nanos`, `ContextTimeStamp`, `EffectiveTransmissionClass`, `#type`, `ConfigStateHash`
- Notes:
  Useful for driver/service startup hunts after deeper normalization.

## File and Content Events

### MsiFileWritten

- Source: Packaged field inventory
- Confirmed fields:
  `FilePath`, `TargetFileName`, `FileName`, `SHA256HashData`, `FileIdentifier`, `FileObject`, `FileCategory`, `FileWrittenFlags`, `FileEcpBitmask`, `FileOperatorSid`, `OperationFlags`, `MajorFunction`, `MinorFunction`, `IrpFlags`, `IsOnNetwork`, `IsOnRemovableDisk`, `DiskParentDeviceInstanceId`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ContextBaseFileName`, `ComputerName`, `UserName`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `FilePath`, `FileName`, `SHA256HashData`, `ContextProcessId`, `UserName`

### NewExecutableWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Agent IP`, `Status`, `@ingesttimestamp`, `LocalIP`, `FileEcpBitmask`, `ShareAccess`, `ContextImageFileName`, `FileAttributes`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `ContextBaseFileName`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `@timezone`, `TreeId`, `@rawstring`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `aid`, `Information`, `ConfigBuild`, `MinorFunction`, `#type`, `EffectiveTransmissionClass`, `ConfigStateHash`, `Options`, `DesiredAccess`, `cid`
- Notes:
  Strong event for dropped executable hunts; normalize exact fields next.

### NewExecutableRenamed

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Agent IP`, `SourceFileName`, `@ingesttimestamp`, `LocalIP`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `NewFileIdentifier`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `TargetFileName`, `@rawstring`, `@timezone`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `aid`, `ConfigBuild`, `MinorFunction`, `#type`, `EffectiveTransmissionClass`, `ConfigStateHash`

### ExecutableDeleted

- Source: Packaged field inventory
- Confirmed fields:
  `FilePath`, `FileName`, `ContextThreadId`, `ContextTimeStamp`, `OperationFlags`, `MajorFunction`, `IrpFlags`, `FileIdentifier`, `ComputerName`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`

### RegistryHiveFileWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields:
  `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `#event.dataset`, `file.target_path`, `FilePath`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `file.size`, `TokenType`, `agent.id`, `LocalAddressIP4`, `ContextThreadId`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `aip`, `TargetFileName`, `Tactic`, `event_platform`, `BoundingLimitCount`, `@timezone`, `host.hostname`, `@rawstring`, `Parser.version`, `TreeId`, `FileCategory`, `event.action`, `source.ip`, `network.type`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `FileObject`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ConfigBuild`, `FileWrittenFlags`, `#ecs.version`, `EffectiveTransmissionClass`, `#Cps.version`, `DiskParentDeviceInstanceId`, `MinorFunction`, `file.name`, `#type`, `ConfigStateHash`, `FileOperatorSid`, `user.name`, `FileSubType`, `cid`

### MotwWritten

- Source: Packaged field inventory
- Confirmed fields:
  `ReferrerUrl`, `FilePath`, `FileIdentifier`, `ZoneIdentifier`, `ComputerName`, `FileName`, `HostUrl`, `TargetFileName`, `ContextProcessId`, `BoundingLimitCount`, `BoundingLimitDuration`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `FileName`, `TargetFileName`, `HostUrl`, `ReferrerUrl`, `ContextProcessId`, `ComputerName`
- Confirmed join candidates:
  `ContextProcessId` to process events
- Notes:
  Key enrichment event for download origin, Mark-of-the-Web, and post-download execution hunts.

### LFODownloadConfirmation

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields:
  `EventOrigin`, `aip`, `event_platform`, `TargetFileName`, `@rawstring`, `DownloadPort`, `CompletionEventId`, `FilePath`, `@timezone`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `#Vendor`, `DownloadServer`, `@source`, `@id`, `id`, `name`, `aid`, `LocalAddressIP4`, `ConfigBuild`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `FileName`, `#type`, `DownloadPath`, `EffectiveTransmissionClass`, `ConfigStateHash`

### GzipFileWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields:
  `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `ContextBaseFileName`, `FileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `TemporaryFileName`, `@rawstring`, `@timezone`, `TreeId`, `FileCategory`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `FileWrittenFlags`, `ConfigBuild`, `aid`, `MinorFunction`, `#type`, `EffectiveTransmissionClass`, `DiskParentDeviceInstanceId`, `ConfigStateHash`, `FileOperatorSid`, `cid`, `user.name`

### ZipFileWritte

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields:
  `IrpFlags`, `OperationFlags`, `EventOrigin`, `Technique`, `MajorFunction`, `#event.dataset`, `FilePath`, `Size`, `file.target_path`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `TokenType`, `file.size`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `VolumeSessionUUID`, `BoundingLimitCount`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `TemporaryFileName`, `TargetFileName`, `host.hostname`, `@rawstring`, `TreeId`, `Parser.version`, `@timezone`, `network.type`, `event.action`, `source.ip`, `FileCategory`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `FileObject`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `FileWrittenFlags`, `ConfigBuild`, `aid`, `EffectiveTransmissionClass`, `#Cps.version`, `DiskParentDeviceInstanceId`, `MinorFunction`, `file.name`, `#type`, `ConfigStateHash`, `FileOperatorSid`, `cid`, `user.name`, `IsOnRemovableDisk`
- Notes:
  Name appears truncated in dump as `ZipFileWritte`; preserve exact spelling unless later confirmed otherwise.

### SevenZipFileWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`
- Confirmed fields:
  `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `#event.dataset`, `file.target_path`, `FilePath`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `file.size`, `TokenType`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `FileOperatorSid`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `ContextBaseFileName`, `FileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `aip`, `BoundingLimitCount`, `Tactic`, `event_platform`, `TargetFileName`, `host.hostname`, `@rawstring`, `Parser.version`, `@timezone`, `FileCategory`, `event.action`, `source.ip`, `network.type`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `FileObject`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ConfigBuild`, `FileWrittenFlags`, `#ecs.version`, `EffectiveTransmissionClass`, `#Cps.version`, `DiskParentDeviceInstanceId`, `MinorFunction`, `file.name`, `#type`, `ConfigStateHash`

### JavaClassFileWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields:
  `EventOrigin`, `IrpFlags`, `OperationFlags`, `aip`, `TargetFileName`, `event_platform`, `@timezone`, `MajorFunction`, `FilePath`, `Size`, `@rawstring`, `Agent IP`, `FileCategory`, `@ingesttimestamp`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `FileOperatorSid`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `ContextBaseFileName`, `FileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `FileWrittenFlags`, `ConfigBuild`, `aid`, `MinorFunction`, `#type`, `DiskParentDeviceInstanceId`, `EffectiveTransmissionClass`, `ConfigStateHash`

### PythonFileWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `TargetFileName`, `event_platform`
- Confirmed fields:
  `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `FileOperatorSid`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `ContextBaseFileName`, `FileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `SHA256HashData`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `@rawstring`, `@timezone`, `FileCategory`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `aid`, `FileWrittenFlags`, `ConfigBuild`, `MinorFunction`, `#type`, `DiskParentDeviceInstanceId`, `EffectiveTransmissionClass`, `ConfigStateHash`

### WebScriptFileWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields:
  `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `#event.dataset`, `file.target_path`, `FilePath`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `file.size`, `TokenType`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `VolumeSessionUUID`, `TargetFileName`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `TemporaryFileName`, `BoundingLimitCount`, `@timezone`, `host.hostname`, `TreeId`, `Parser.version`, `@rawstring`, `FileCategory`, `event.action`, `source.ip`, `network.type`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `FileObject`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ConfigBuild`, `FileWrittenFlags`, `#ecs.version`, `EffectiveTransmissionClass`, `#Cps.version`, `DiskParentDeviceInstanceId`, `MinorFunction`, `file.name`, `#type`, `ConfigStateHash`, `user.name`, `FileOperatorSid`, `cid`, `IsOnRemovableDisk`

### NewScriptWritten

- Source: Packaged field inventory
- Confirmed fields:
  `FilePath`, `Status`, `FileEcpBitmask`, `ShareAccess`, `ContextImageFileName`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ContextBaseFileName`, `ComputerName`, `FileName`, `TargetFileName`, `TreeId`, `FileAttributes`, `FileIdentifier`, `FileObject`, `Information`, `OperationFlags`, `MajorFunction`, `MinorFunction`, `IrpFlags`, `Options`, `DesiredAccess`, `BoundingLimitCount`, `BoundingLimitDuration`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `FilePath`, `FileName`, `TargetFileName`, `ContextBaseFileName`, `ContextProcessId`, `ComputerName`

### ScriptFileWrittenInfo

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `Technique`, `#event.dataset`, `FilePath`, `file.target_path`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `#event.module`, `FileFormatString`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `CscStatus`, `file.hash.sha256`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `SHA256HashData`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `TargetFileName`, `@rawstring`, `@timezone`, `Parser.version`, `host.hostname`, `event.action`, `network.type`, `source.ip`, `BoundingLimitDuration`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ConfigBuild`, `file.type`, `#ecs.version`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `OriginalContentLength`, `ScriptContent`, `WritingProcessId`, `cid`

### ScriptControlDetectInfo

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `event_platform`, `Technique`
- Confirmed fields:
  `EventOrigin`, `process.parent.name`, `DetectSeverity`, `Technique`, `#event.dataset`, `FilePath`, `HostProcessType`, `file.target_path`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `DetectScenario`, `EventCorrelationId`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `file.hash.sha256`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `FileName`, `process.command_line`, `SHA256HashData`, `@timestamp.nanos`, `host.os.platform`, `CommandLine`, `OriginalFilename`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `ContentSHA256HashData`, `ParentImageFileName`, `process.executable`, `DetectDescription`, `Parser.version`, `@timezone`, `ScriptContentName`, `ScriptContentSource`, `host.hostname`, `@rawstring`, `ScriptingLanguageId`, `TemplateInstanceId`, `event.action`, `source.ip`, `process.name`, `network.type`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `ConfigBuild`, `#ecs.version`, `aid`, `TemplateDisposition`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `OriginalContentLength`, `ScriptContent`, `DetectName`, `cid`

### MSDocxFileWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields:
  `Filters`, `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `FilePath`, `Size`, `MajorFunction`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `TokenType`, `FileEcpBitmask`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `VolumeSessionUUID`, `TargetFileName`, `MSOfficeSubType`, `aip`, `Tactic`, `TemporaryFileName`, `event_platform`, `BoundingLimitCount`, `@timezone`, `TreeId`, `@rawstring`, `FileCategory`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `FileWrittenFlags`, `aid`, `ConfigBuild`, `MinorFunction`, `#type`, `DiskParentDeviceInstanceId`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`, `FileOperatorSid`

### SuspiciousPeFileWritten

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`
- Confirmed fields:
  `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `FilePath`, `#event.dataset`, `file.target_path`, `Size`, `ImageFileName`, `Agent IP`, `@ingesttimestamp`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `file.size`, `TokenType`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#repo`, `@sourcetype`, `IsOnNetwork`, `#event_simpleName`, `#repo.cid`, `FileIdentifier`, `file.hash.sha256`, `Entitlements`, `@timestamp`, `timestamp`, `UserName`, `ComputerName`, `process.command_line`, `FileName`, `ContextBaseFileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `aip`, `TargetFileName`, `Tactic`, `event_platform`, `@rawstring`, `@timezone`, `process.executable`, `Parser.version`, `host.hostname`, `network.type`, `event.action`, `source.ip`, `threat.tactic.name[0]`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `FileObject`, `#ecs.version`, `ConfigBuild`, `FileWrittenFlags`, `aid`, `file.name`, `MinorFunction`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`, `FileOperatorSid`, `SHA256HashData`, `CommandLine`, `IsOnRemovableDisk`

### FileWrittenWithEntropyHigh

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `Technique`, `FilePath`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `ShannonEntropy`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `@rawstring`, `@timezone`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`

## Network and Share Events

### NetworkReceiveAcceptIP4

- Source: Packaged field inventory
- Confirmed fields:
  `ConnectionDirection`, `ConnectionFlags`, `CommunityID`, `LocalIP`, `LocalAddressIP4`, `ContextBaseFileName`, `ComputerName`, `ContextTimeStamp`, `ContextProcessId`, `RemoteIP`, `RemoteAddressIP4`, `RemoteAddressString`, `RemotePort`, `RPort`, `LocalPort`, `LPort`, `Protocol`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Notes:
  Useful complement to `NetworkConnectIP4` for inbound or accepted traffic hunts.

### SuspiciousDnsRequest

- Source: Packaged field inventory
- Confirmed fields:
  `DomainName`, `DualRequest`, `RequestType`, `ContextThreadId`, `ContextTimeStamp`, `ContextProcessId`, `ComputerName`, `event_platform`, `aid`, `cid`, `BoundingLimitCount`, `BoundingLimitDuration`
- Confirmed ECS aliases:
  `process.entity_id`, `host.hostname`, `host.os.platform`, `source.ip`, `event.action`
- Confirmed useful pivots:
  `DomainName`, `ContextProcessId`, `ComputerName`
- Notes:
  Better than generic DNS when the environment already classifies the request as suspicious.

### SmbClientShareOpenedEtw

- Source: Packaged field inventory
- Confirmed fields:
  `SmbShareName`, `ClientComputerName`, `ComputerName`, `event_platform`, `Technique`, `Tactic`, `aid`
- Confirmed ECS aliases:
  `host.hostname`, `host.os.platform`, `source.ip`, `event.action`, `threat.technique.name[0]`, `threat.tactic.name[0]`
- Notes:
  Good starting point for SMB or admin-share ATT&CK mappings.

### SmbServerShareOpenedEtw

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `aid`, `cid`, `DomainName`, `RemoteIP`, `RemoteAddressIP4`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `aip`, `Tactic`, `Technique`, `event_platform`, `RemoteAddressIP6`, `@timezone`, `host.hostname`, `#event.dataset`, `Parser.version`, `@rawstring`, `Agent IP`, `SmbShareName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `#ecs.version`, `agent.id`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `destination.ip`, `host.os.platform`, `event.action`, `network.type`, `source.ip`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `RemoteIP`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `user.name`, `cid`, `DomainName`, `RemoteAddressIP4`

### DirectoryTraversalOverSMB

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `UserSid`, `AuthenticationId`, `aid`, `cid`, `RemoteIP`, `RemoteAddressIP4`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `aip`, `Tactic`, `Technique`, `event_platform`, `@rawstring`, `ClientComputerName`, `EventThreshold`, `@timezone`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `UserSid`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `TargetDirectoryName`, `RemoteAddressIP4`, `#Vendor`, `name`, `@id`, `id`, `@source`, `RemoteIP`, `#type`, `LogonType`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`

### NetShareDelete

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `event_platform`
- Confirmed fields:
  `EventOrigin`, `aip`, `RpcOpNum`, `event_platform`, `@rawstring`, `@timezone`, `InterfaceGuid`, `Agent IP`, `RpcClientProcessId`, `ShareName`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `LocalAddressIP4`, `ConfigBuild`, `ContextThreadId`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `UserName`, `ComputerName`, `@timestamp.nanos`, `ContextTimeStamp`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`, `user.name`, `cid`, `InterfaceVersion`, `RpcNestingLevel`

### FirewallSetRule

- Source: Packaged field inventory
- Confirmed fields:
  `RpcOpNum`, `InterfaceGuid`, `InterfaceVersion`, `RpcClientProcessId`, `RpcClientThreadId`, `RpcNestingLevel`, `AuthenticationId`, `TokenType`, `FirewallRule`, `FirewallRuleId`, `UserName`, `ComputerName`, `ContextTimeStamp`, `ContextProcessId`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed ECS aliases:
  `user.name`
- Confirmed useful pivots:
  `FirewallRule`, `FirewallRuleId`, `UserName`, `ContextProcessId`
- Confirmed join candidates:
  `ContextProcessId` to process events
  `AuthenticationId` to logon/process context
- Notes:
  This validates the earlier process-to-firewall-rule join pattern.

### FirewallDeleteRule

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `FirewallRuleId`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `aip`, `Tactic`, `RpcOpNum`, `Technique`, `event_platform`, `@rawstring`, `@timezone`, `InterfaceGuid`, `Agent IP`, `RpcClientProcessId`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `TokenType`, `aid`, `LocalAddressIP4`, `ConfigBuild`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `FirewallRuleId`, `ContextTimeStamp`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `#type`, `ConfigStateHash`, `EffectiveTransmissionClass`, `user.name`, `cid`, `InterfaceVersion`, `RpcNestingLevel`

## Injection, Handle, and Advanced Detection Events

### InjectedThread

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `TargetProcessId`, `RawProcessId`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `Technique`, `SourceThreadModule`, `Agent IP`, `RawProcessId`, `@ingesttimestamp`, `LocalIP`, `ThreadStartBytes`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `UserThread`, `Entitlements`, `InjectedThreadFlag`, `@timestamp`, `TargetThreadId`, `ComputerName`, `timestamp`, `SourceThreadStartAddress`, `@timestamp.nanos`, `ContextTimeStamp`, `ThreadStartContext`, `TargetThreadModule`, `event_platform`, `aip`, `Tactic`, `ThreadStartAddressMemoryDescriptionFlags`, `BoundingLimitCount`, `TargetProcessId`, `@rawstring`, `@timezone`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@source`, `@id`, `name`, `ConfigBuild`, `ThreadStartAddress`, `aid`, `#type`, `EffectiveTransmissionClass`, `RawThreadId`, `ConfigStateHash`, `cid`

### ProcessInjection

- Source: Packaged field inventory
- Confirmed fields:
  `DetectSeverity`, `InjecteeImageFileName`, `ExecutableBytes`, `DetectScenario`, `PayloadClassificationFlags`, `PayloadClassification`, `TargetThreadId`, `ModuleName`, `ModifiedRegisters`, `ThreadExecutionControlType`, `TargetProcessId`, `DetectDescription`, `ContextProcessId`, `PatternId`, `ThreadStartAddress`, `MemoryDescriptionFlags`, `HookId`, `WellKnownTargetFunction`, `InjectorImageFileName`, `DetectName`, `BoundingLimitCount`, `BoundingLimitDuration`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `InjectorImageFileName`, `InjecteeImageFileName`, `TargetProcessId`, `DetectName`, `PatternId`, `ContextProcessId`
- Confirmed join candidates:
  `TargetProcessId` or `ContextProcessId` to process events
- Notes:
  High-signal advanced detection telemetry for process-injection hunts.

### DllInjection

- Source: Packaged field inventory
- Confirmed fields:
  `TargetProcessId`, `RawProcessId`, `ContextProcessId`, `ContextThreadId`, `ComputerName`, `InjectedDll`, `ThreadStartAddress`, `InjectedThreadFlag`, `TargetThreadId`, `ContextTimeStamp`, `ThreadStartContext`, `RawThreadId`, `event_platform`, `aid`, `cid`
- Confirmed useful pivots:
  `InjectedDll`, `TargetProcessId`, `ContextProcessId`, `TargetThreadId`, `ComputerName`
- Confirmed join candidates:
  `TargetProcessId` or `ContextProcessId` to process events
- Notes:
  Useful lower-level injection event that complements `ProcessInjection`.

### BrowserInjectedThread

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `TargetProcessId`, `RawProcessId`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `aip`, `Tactic`, `ThreadStartAddressMemoryDescriptionFlags`, `Technique`, `event_platform`, `@rawstring`, `@timezone`, `TargetProcessId`, `Agent IP`, `RawProcessId`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `ThreadStartAddress`, `LocalAddressIP4`, `ConfigBuild`, `ContextThreadId`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `UserThread`, `Entitlements`, `InjectedThreadFlag`, `@timestamp`, `TargetThreadId`, `timestamp`, `ComputerName`, `@timestamp.nanos`, `ContextTimeStamp`, `SourceThreadStartAddress`, `ThreadStartContext`, `#type`, `RawThreadId`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`

### ReflectiveDotnetModuleLoad

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `Technique`, `AssemblyId`, `#event.dataset`, `AssemblyFlags`, `FilePath`, `file.target_path`, `AssemblyName`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `EtwProviderType`, `ManagedPdbBuildPath`, `LocalAddressIP4`, `agent.id`, `ModuleILPath`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `DotnetModuleFlags`, `FileName`, `process.command_line`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `event_platform`, `aip`, `ModuleNativePath`, `Tactic`, `process.entity_id`, `BoundingLimitCount`, `@timezone`, `@rawstring`, `Parser.version`, `process.executable`, `host.hostname`, `source.ip`, `event.action`, `network.type`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `DotnetModuleId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `aid`, `ConfigBuild`, `NativePdbBuildPath`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `CommandLine`

### SuspiciousPrivilegedProcessHandle

- Source: Packaged field inventory
- Confirmed fields:
  `HandleCreated`, `TargetProcessId`, `AuthenticationId`, `TargetAuthenticationId`, `SuspiciousHandleOpenReason`, `ContextThreadId`, `ComputerName`, `event_platform`, `aid`, `cid`
- Confirmed ECS aliases:
  `host.hostname`, `source.ip`, `event.action`
- Confirmed useful pivots:
  `TargetProcessId`, `AuthenticationId`, `TargetAuthenticationId`, `SuspiciousHandleOpenReason`
- Notes:
  High-value event for credential-access and privilege abuse hunts.

### RegistryOperationDetectInfo

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `event_platform`
- Confirmed fields:
  `registry.value`, `EventOrigin`, `DetectSeverity`, `Technique`, `#event.dataset`, `file.target_path`, `FilePath`, `ImageFileName`, `Agent IP`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `DetectScenario`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `process.command_line`, `FileName`, `@timestamp.nanos`, `host.os.platform`, `CommandLine`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `RegValueName`, `RegClassificationIndex`, `RegNumericValue`, `DetectDescription`, `@rawstring`, `@timezone`, `process.executable`, `Parser.version`, `host.hostname`, `network.type`, `event.action`, `TemplateInstanceId`, `source.ip`, `RegClassification`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `#ecs.version`, `ConfigBuild`, `RegClassificationFlags`, `RegOperationType`, `EffectiveTransmissionClass`, `#Cps.version`, `TemplateDisposition`, `file.name`, `#type`, `ConfigStateHash`, `cid`, `RegType`, `registry.key`, `DetectName`, `RegObjectName`

### SuspiciousRegAsepUpdate

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `TargetFileName`
- Confirmed fields:
  `EventOrigin`, `registry.value`, `DetectSeverity`, `Technique`, `TargetSHA256HashData`, `RegConfigFlags`, `#event.dataset`, `FilePath`, `file.target_path`, `Agent IP`, `ImageFileName`, `RegConfigClass`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `DetectScenario`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RegConfigValueType`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `RegKeyName`, `FileName`, `process.command_line`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `CommandLine`, `TargetFileName`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `RegValueName`, `TargetCommandLineParameters`, `@timezone`, `@rawstring`, `DetectDescription`, `Parser.version`, `process.executable`, `host.hostname`, `source.ip`, `event.action`, `network.type`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `RegStringValue`, `RegConfigIndex`, `ConfigBuild`, `aid`, `RegOperationType`, `ConfigStateHash`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `file.name`, `RegObjectName`, `RegType`, `DetectName`, `registry.key`, `cid`

### SAMHashDumpFromUnsignedModule

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `RegRootObjectName`, `file.code_signature.timestamp`, `EventOrigin`, `Technique`, `FilePath`, `#event.dataset`, `file.target_path`, `ImageFileName`, `Agent IP`, `Status`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `file.hash.sha256`, `#repo.cid`, `@sourcetype`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `FileSigningTime`, `RegKeyName`, `FileName`, `RegCreateDisposition`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `Certificate`, `process.entity_id`, `aip`, `Tactic`, `ExtendedKeyUsages`, `event_platform`, `host.hostname`, `@rawstring`, `process.executable`, `Parser.version`, `@timezone`, `source.ip`, `network.type`, `event.action`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `SignInfoFlags`, `ConfigBuild`, `aid`, `file.name`, `#type`, `PublicKeys`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `DesiredAccess`, `RegPostObjectName`, `cid`, `KeyObject`, `RegCreateOptions`, `file.x509.serial_number`, `SHA256HashData`
- Notes:
  High-value credential-access event for ATT&CK expansion later.

## Operational and Miscellaneous Events

### SensorHeartbeat

- Source: Packaged field inventory
- Confirmed fields:
  `ConfigIDPlatform`, `ConfigIDBuild`, `ConfigurationVersion`, `SensorStateBitMap`, `ProvisionState`, `NetworkContainmentState`, `ConfigIDBase`, `ComputerName`, `event_platform`, `aid`, `cid`
- Confirmed ECS aliases:
  `agent.id`, `host.hostname`, `host.os.platform`, `network.type`, `event.action`, `source.ip`
- Notes:
  Operational event useful for host state and sensor health awareness, not usually a primary hunt event.

### DriverLoad

- Source: Packaged field inventory
- Confirmed fields:
  `CertificateSignatureHashAlgorithm`, `CertificateIssuer`, `FilePath`, `HashAlgorithm`, `CertificateThumbprintAlgorithm`, `ImageFileName`, `AuthenticodeHashDataSHA256`, `RegistryPath`, `ContextThreadId`, `ComputerName`, `MD5HashData`, `ContextTimeStamp`, `FileName`, `OriginalFilename`, `CompanyName`, `ServiceDisplayName`, `FixedFileVersion`, `DriverLoadFlags`, `ImageEntryPoint`, `RpcClientProcessId`, `RpcClientThreadId`, `ContextProcessId`, `AuthenticodeHashData`, `ImageTimeStamp`, `FileVersion`, `ImageCheckSum`, `CertificateThumbprint`, `CertificateSignatureHash`, `CertificatePublisher`, `SHA256HashData`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed useful pivots:
  `SHA256HashData`, `FileName`, `OriginalFilename`, `CompanyName`, `CertificateIssuer`, `CertificatePublisher`, `ServiceDisplayName`, `ContextProcessId`
- Confirmed join candidates:
  `SHA256HashData` to module-summary or file-write enrichment
  `ContextProcessId` to process events
- Notes:
  Strong kernel/driver event for signer, publisher, and service-linked hunts.

### AgentConnect

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `LocalAddressIP4`, `event_platform`
- Confirmed fields:
  `PreviousConnectTime`, `EventOrigin`, `ConfigIDPlatform`, `aip`, `event_platform`, `ConnectionExchange`, `@timezone`, `ConnectionAddressIP6`, `ConnectionCipher`, `ConfigIDBuild`, `@rawstring`, `Agent IP`, `FailedConnectCount`, `ConnectionExchangeStrength`, `ConfigurationVersion`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ConfigBuild`, `ProvisionState`, `ConnectType`, `ConnectionHash`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `ConnectionProtocol`, `VerifiedCertificate`, `ConnectionAddressIP4`, `@timestamp.nanos`, `ConnectTime`, `ConnectionCipherStrength`, `ConnectionHashStrength`, `#type`, `EffectiveTransmissionClass`, `NetworkContainmentState`, `ConfigStateHash`, `cid`, `ConfigIDBase`

### BITSJobCreated

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`
- Confirmed fields:
  `EventOrigin`, `RpcOpNum`, `Technique`, `FilePath`, `@rawstring`, `@timezone`, `Agent IP`, `InterfaceGuid`, `RpcClientProcessId`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `BoundingLimitCount`, `aip`, `TargetFileName`, `Tactic`, `event_platform`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@source`, `@id`, `name`, `ConfigBuild`, `aid`, `EffectiveTransmissionClass`, `#type`, `ConfigStateHash`, `cid`, `user.name`, `InterfaceVersion`, `RpcNestingLevel`

### DetectionExcluded

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `UserSid`, `aid`, `cid`, `TargetProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `TargetFileName`
- Confirmed fields:
  `EventOrigin`, `DetectSeverity`, `Technique`, `TargetSHA256HashData`, `FilePath`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `DetectScenario`, `UserSid`, `EventCorrelationId`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `TargetProcessTags`, `CommandLine`, `BoundingLimitCount`, `ExclusionType`, `aip`, `Tactic`, `TargetFileName`, `event_platform`, `DetectDescription`, `@rawstring`, `@timezone`, `ContextData`, `ExclusionSource`, `TargetProcessId`, `BoundingLimitDuration`, `id`, `#Vendor`, `@source`, `@id`, `name`, `PatternId`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`, `MigoTemplateInstanceId`, `user.name`, `AllowlistingFilterId`, `DetectName`, `MLModelVersion`, `cid`

### FileDeleteInfo

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `Technique`, `FilePath`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `TreeId`, `@rawstring`, `@timezone`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@source`, `@id`, `name`, `ConfigBuild`, `aid`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`

### FileOpenInfo

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields:
  `EventOrigin`, `Technique`, `TreeId`, `@rawstring`, `FilePath`, `@timezone`, `Agent IP`, `Status`, `@ingesttimestamp`, `LocalIP`, `ShareAccess`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `DesiredAccess`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `TargetFileName`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `ConfigBuild`, `aid`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`

### VolumeSnapshotDeleted

- Source: Packaged field inventory
- Common filter candidates:
  `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`
- Confirmed fields:
  `EventOrigin`, `RpcOpNum`, `Technique`, `#event.dataset`, `FilePath`, `file.target_path`, `Agent IP`, `ImageFileName`, `InterfaceGuid`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#repo`, `@sourcetype`, `#event_simpleName`, `#repo.cid`, `file.hash.sha256`, `RpcClientThreadId`, `VolumeName`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `VolumeDriveLetter`, `FileName`, `process.command_line`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `process.executable`, `Parser.version`, `@timezone`, `TreeId`, `host.hostname`, `VolumeSnapshotName`, `@rawstring`, `event.action`, `RpcClientProcessId`, `source.ip`, `network.type`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `process.pid`, `ConfigBuild`, `#ecs.version`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `user.name`, `cid`, `RpcNestingLevel`, `CommandLine`, `SHA256HashData`, `InterfaceVersion`
- Notes:
  Relevant for ransomware and recovery-inhibition hunts.

### ScreenshotTakenEtw

- Source: Packaged field inventory
- Confirmed fields:
  `ScreenshotType`, `FilePath`, `FileName`, `ImageFileName`, `RawProcessId`, `ProcessStartKey`, `CommandLine`, `PerformanceCounter`, `RawThreadId`, `ContextTimeStamp`, `ContextProcessId`, `UserName`, `ComputerName`, `BoundingLimitCount`, `BoundingLimitDuration`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed ECS aliases:
  `process.command_line`, `process.executable`, `process.entity_id`, `process.pid`, `file.target_path`, `file.name`, `host.hostname`, `host.os.platform`, `source.ip`, `event.action`, `user.name`
- Notes:
  High-value surveillance/collection event if present in the environment.

### SensitiveWmiQuery

- Source: Packaged field inventory
- Confirmed fields:
  `ClientComputerName`, `WmiNamespaceName`, `WmiQuery`, `UserName`, `ComputerName`, `ContextProcessId`, `BoundingLimitCount`, `BoundingLimitDuration`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed ECS aliases:
  `host.hostname`, `host.os.platform`, `process.entity_id`, `source.ip`, `event.action`, `network.type`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `user.name`
- Confirmed useful pivots:
  `WmiNamespaceName`, `WmiQuery`, `ClientComputerName`, `UserName`, `ContextProcessId`
- Confirmed join candidates:
  `ContextProcessId` to process events
- Notes:
  High-value discovery and execution-adjacent telemetry for WMI-based hunts.

### PeVersionInfo

- Source: Packaged field inventory
- Confirmed fields:
  `FixedFileVersion`, `CompanyName`, `OriginalFilename`, `TargetProcessId`, `FilePath`, `ImageFileName`, `LanguageId`, `FileVersion`, `ComputerName`, `FileName`, `SHA256HashData`, `LocalAddressIP4`, `event_platform`, `aid`, `cid`
- Confirmed useful pivots:
  `ImageFileName`, `FileName`, `OriginalFilename`, `CompanyName`, `FileVersion`, `SHA256HashData`, `TargetProcessId`
- Confirmed join candidates:
  `TargetProcessId` to process events
  `SHA256HashData` to file or process enrichment
- Notes:
  Useful for version-info enrichment, masquerading review, and publisher/name mismatch hunts.

### WmiProviderRegistrationEtw

- Source: Packaged field inventory
- Confirmed fields:
  `ProcessStartTime`, `DetectSeverity`, `ClientComputerName`, `FilePath`, `ImageFileName`, `DetectScenario`, `UserName`, `ComputerName`, `FileName`, `ContextTimeStamp`, `event_platform`, `BoundingLimitCount`, `BoundingLimitDuration`, `DetectDescription`, `EtwRawProcessId`, `ContextProcessId`, `PatternId`, `PerformanceCounter`, `WmiProviderType`, `WmiProviderName`, `DetectName`, `CommandLine`, `aid`, `cid`
- Confirmed ECS aliases:
  `file.target_path`, `process.start`, `process.command_line`, `process.executable`, `process.entity_id`, `process.pid`, `host.hostname`, `host.os.platform`, `source.ip`, `event.action`, `network.type`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `file.name`, `user.name`
- Confirmed useful pivots:
  `WmiProviderName`, `WmiProviderType`, `DetectName`, `ImageFileName`, `CommandLine`, `ContextProcessId`, `UserName`
- Confirmed join candidates:
  `ContextProcessId` to process events
- Notes:
  High-value telemetry for suspicious WMI provider registration and execution-adjacent WMI behavior.

### RansomwareOpenFile

- Source: Packaged field inventory
- Confirmed fields:
  `IrpFlags`, `OperationFlags`, `MajorFunction`, `FilePath`, `Status`, `FileAttributes`, `ShareAccess`, `ContextThreadId`, `FileIdentifier`, `ComputerName`, `FileName`, `ContextTimeStamp`, `TargetFileName`, `event_platform`, `BoundingLimitCount`, `BoundingLimitDuration`, `ContextProcessId`, `FileObject`, `Information`, `DesiredAccess`, `Options`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed ECS aliases:
  `file.target_path`, `agent.id`, `host.hostname`, `host.os.platform`, `process.entity_id`, `source.ip`, `event.action`, `network.type`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `file.name`
- Confirmed useful pivots:
  `FilePath`, `FileName`, `TargetFileName`, `ContextProcessId`, `ComputerName`, `DesiredAccess`
- Confirmed join candidates:
  `ContextProcessId` to process events
- Notes:
  Useful for ransomware-style file-access hunts and recovery-inhibition investigations.

### RansomwareFileAccessPattern

- Source: Packaged field inventory
- Confirmed fields:
  `FilePath`, `ImageFileName`, `SourceFileName`, `ComputerName`, `ClientId`, `FileName`, `CommandLine`, `SHA256HashData`, `TargetFileName`, `Tags`, `ContextProcessId`, `PatternId`, `event_platform`, `Technique`, `Tactic`, `aid`, `cid`
- Confirmed ECS aliases:
  `file.target_path`, `file.hash.sha256`, `process.command_line`, `process.entity_id`, `process.executable`, `host.hostname`, `host.os.platform`, `source.ip`, `event.action`, `network.type`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `file.name`
- Confirmed useful pivots:
  `ImageFileName`, `FileName`, `TargetFileName`, `SHA256HashData`, `PatternId`, `ContextProcessId`, `CommandLine`
- Confirmed join candidates:
  `ContextProcessId` to process events
  `SHA256HashData` to process or file enrichment
- Notes:
  Strong behavioral event for ransomware patterning and related process attribution.

## Environment Notes

- The environment includes a mix of native Falcon fields and ECS-style aliases on some events.
- Several events include ATT&CK-enrichment-style fields such as `Technique`, `Tactic`, `threat.technique.name[0]`, and `threat.tactic.name[0]`.
- Some event names may include spelling inconsistencies from the source dump. Preserve exact event names until validated in-console.
- `field-maps.md` now includes all 67 packaged `#event_simpleName` values.
- The next highest-value normalization step is deeper interpretation of the entries still marked with only raw confirmed fields or `Event exists in dump`, starting with:
  `RegistryHiveFileWritten`
  `LFODownloadConfirmation`
  `FirewallDeleteRule`
  `RegSystemConfigValueUpdate`
  `ServiceStopped`
  `ReflectiveDotnetModuleLoad`
  `ScriptFileWrittenInfo`
  `ScriptControlDetectInfo`
  `InjectedThread`
  `RegistryOperationDetectInfo`
