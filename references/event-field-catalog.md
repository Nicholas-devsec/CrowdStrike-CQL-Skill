# Event Field Catalog

This file is a systematic catalog of every packaged `#event_simpleName` section included with this skill.
This is the complete list of confirmed fields for each event, and the final check on whether a field exists. If a field is not listed under an event here, do not use it for that event. For pivots, joins, and hunt notes, use [field-maps.md](field-maps.md).

Total event types extracted: **67**.

## How To Use

- Use this file when you need raw confirmed field availability for an event.
- Treat the listed fields as queryable/context fields observed in the dump.
- If a field is not listed under an event here, do not assume it exists for that event.
- Prefer [field-maps.md](field-maps.md) when you want safer pivots and join guidance.

## Event Index

- [MsiFileWritten](#msifilewritten)
- [ProcessRollup2](#processrollup2)
- [NetworkConnectIP4](#networkconnectip4)
- [DnsRequest](#dnsrequest)
- [SensorHeartbeat](#sensorheartbeat)
- [RegCrowdstrikeValueUpdate](#regcrowdstrikevalueupdate)
- [ProcessAncestryInformation](#processancestryinformation)
- [UserLogon](#userlogon)
- [NewScriptWritten](#newscriptwritten)
- [NetworkReceiveAcceptIP4](#networkreceiveacceptip4)
- [DriverLoad](#driverload)
- [GzipFileWritten](#gzipfilewritten)
- [SyntheticProcessRollup2](#syntheticprocessrollup2)
- [ExecutableDeleted](#executabledeleted)
- [NewExecutableWritten](#newexecutablewritten)
- [RegistryHiveFileWritten](#registryhivefilewritten)
- [AsepValueUpdate](#asepvalueupdate)
- [LFODownloadConfirmation](#lfodownloadconfirmation)
- [FirewallDeleteRule](#firewalldeleterule)
- [RegSystemConfigValueUpdate](#regsystemconfigvalueupdate)
- [ServiceStopped](#servicestopped)
- [NewExecutableRenamed](#newexecutablerenamed)
- [SensitiveWmiQuery](#sensitivewmiquery)
- [ReflectiveDotnetModuleLoad](#reflectivedotnetmoduleload)
- [ZipFileWritte](#zipfilewritte)
- [WebScriptFileWritten](#webscriptfilewritten)
- [AgentConnect](#agentconnect)
- [BITSJobCreated](#bitsjobcreated)
- [InjectedThread](#injectedthread)
- [MotwWritten](#motwwritten)
- [RegGenericValueUpdate](#reggenericvalueupdate)
- [AsepKeyUpdate](#asepkeyupdate)
- [PeVersionInfo](#peversioninfo)
- [ScheduledTaskRegistered](#scheduledtaskregistered)
- [ScheduledTaskDeleted](#scheduledtaskdeleted)
- [CreateService](#createservice)
- [JavaClassFileWritten](#javaclassfilewritten)
- [ScriptControlDetectInfo](#scriptcontroldetectinfo)
- [MSDocxFileWritten](#msdocxfilewritten)
- [ScriptFileWrittenInfo](#scriptfilewritteninfo)
- [SmbClientShareOpenedEtw](#smbclientshareopenedetw)
- [UserLogonFailed2](#userlogonfailed2)
- [ScreenshotTakenEtw](#screenshottakenetw)
- [SuspiciousDnsRequest](#suspiciousdnsrequest)
- [SuspiciousPrivilegedProcessHandle](#suspiciousprivilegedprocesshandle)
- [RegistryOperationDetectInfo](#registryoperationdetectinfo)
- [SuspiciousRegAsepUpdate](#suspiciousregasepupdate)
- [DetectionExcluded](#detectionexcluded)
- [SevenZipFileWritten](#sevenzipfilewritten)
- [ProcessInjection](#processinjection)
- [FileDeleteInfo](#filedeleteinfo)
- [SmbServerShareOpenedEtw](#smbservershareopenedetw)
- [KernelServiceStarted](#kernelservicestarted)
- [FileWrittenWithEntropyHigh](#filewrittenwithentropyhigh)
- [FileOpenInfo](#fileopeninfo)
- [VolumeSnapshotDeleted](#volumesnapshotdeleted)
- [PythonFileWritten](#pythonfilewritten)
- [WmiProviderRegistrationEtw](#wmiproviderregistrationetw)
- [DirectoryTraversalOverSMB](#directorytraversaloversmb)
- [DllInjection](#dllinjection)
- [SuspiciousPeFileWritten](#suspiciouspefilewritten)
- [NetShareDelete](#netsharedelete)
- [BrowserInjectedThread](#browserinjectedthread)
- [SAMHashDumpFromUnsignedModule](#samhashdumpfromunsignedmodule)
- [RansomwareOpenFile](#ransomwareopenfile)
- [RansomwareFileAccessPattern](#ransomwarefileaccesspattern)
- [FirewallSetRule](#firewallsetrule)

## MsiFileWritten

- Field count: `60`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `TargetFileName`
- Confirmed fields: `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `FilePath`, `Size`, `MajorFunction`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `TokenType`, `FileEcpBitmask`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `SHA256HashData`, `TargetFileName`, `aip`, `BoundingLimitCount`, `Tactic`, `event_platform`, `TreeId`, `@rawstring`, `@timezone`, `FileCategory`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `ConfigBuild`, `FileWrittenFlags`, `aid`, `MinorFunction`, `#type`, `DiskParentDeviceInstanceId`, `EffectiveTransmissionClass`, `ConfigStateHash`, `FileOperatorSid`, `user.name`, `cid`

## ProcessRollup2

- Field count: `79`
- Common filter candidates: `ComputerName`, `UserName`, `UserSid`, `AuthenticationId`, `aid`, `cid`, `TargetProcessId`, `RawProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`
- Confirmed fields: `ProcessStartTime`, `ParentProcessId`, `EventOrigin`, `SourceThreadId`, `Technique`, `ReferrerUrl`, `FilePath`, `SessionId`, `ParentBaseFileName`, `CallStackModuleNames`, `Agent IP`, `ImageFileName`, `LocalIP`, `RawProcessId`, `@ingesttimestamp`, `UserSid`, `AuthenticationId`, `TokenType`, `LocalAddressIP4`, `ImageSubsystem`, `WindowStation`, `#event_simpleName`, `LinkName`, `#repo`, `@sourcetype`, `#repo.cid`, `ZoneIdentifier`, `Entitlements`, `UserName`, `timestamp`, `CallStackModuleNamesVersion`, `ComputerName`, `MD5HashData`, `@timestamp`, `FileName`, `HostUrl`, `IntegrityLevel`, `WindowFlags`, `@timestamp.nanos`, `aip`, `OriginalFilename`, `Tactic`, `ProcessSxsFlags`, `WindowTitle`, `event_platform`, `@rawstring`, `@timezone`, `Tags`, `ProcessEndTime`, `TargetProcessId`, `TreeId`, `RpcClientProcessId`, `ShowWindowFlags`, `AuthenticodeHashData`, `#Vendor`, `@id`, `id`, `name`, `@source`, `aid`, `SignInfoFlags`, `ProcessCreateFlags`, `ConfigBuild`, `Desktop`, `SHA1HashData`, `EffectiveTransmissionClass`, `ProcessParameterFlags`, `CreateProcessType`, `ParentAuthenticationId`, `WindowStartingPositionHorizontal`, `#type`, `ConfigStateHash`, `cid`, `GrandParentBaseFileName`, `user.name`, `SHA256HashData`, `WindowStartingPositionVertical`, `SourceProcessId`, `CommandLine`

## NetworkConnectIP4

- Field count: `50`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `RemoteIP`, `RemoteAddressIP4`, `RemotePort`, `LocalAddressIP4`, `LocalPort`, `event_platform`, `Technique`
- Confirmed fields: `EventOrigin`, `aip`, `Protocol`, `Tactic`, `Technique`, `event_platform`, `@timezone`, `@rawstring`, `ConnectionDirection`, `ConnectionFlags`, `TreeId`, `Agent IP`, `InContext`, `IcmpCode`, `@ingesttimestamp`, `LocalIP`, `RPort`, `ConfigBuild`, `LocalPort`, `LocalAddressIP4`, `CommunityID`, `ContextThreadId`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `RemotePort`, `ContextBaseFileName`, `@timestamp.nanos`, `ContextTimeStamp`, `IcmpType`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `RemoteIP`, `#type`, `LPort`, `EffectiveTransmissionClass`, `ConfigStateHash`, `RemoteAddressString`, `RemoteAddressIP4`

## DnsRequest

- Field count: `49`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `DomainName`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `FirstIP6Record`, `Tactic`, `Technique`, `event_platform`, `InterfaceIndex`, `RequestType`, `@rawstring`, `TreeId`, `DnsRequestCount`, `@timezone`, `Agent IP`, `@ingesttimestamp`, `LocalIP`, `QueryStatus`, `DualRequest`, `IP6Records`, `DnsResponseType`, `CNAMERecords`, `LocalAddressIP4`, `ConfigBuild`, `ContextThreadId`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `IP4Records`, `Entitlements`, `FirstIP4Record`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `ContextBaseFileName`, `DomainName`, `@timestamp.nanos`, `ContextTimeStamp`, `RespondingDnsServer`, `#Vendor`, `name`, `@id`, `@source`, `ContextProcessId`, `id`, `ConfigStateHash`, `EffectiveTransmissionClass`, `#type`

## SensorHeartbeat

- Field count: `48`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `LocalAddressIP4`, `event_platform`
- Confirmed fields: `eventOrigin`, `aip`, `ConfigIDPlatform`, `event_platform`, `@rawstring`, `@timezone`, `#event.dataset`, `Parser.version`, `ConfigIDBuild`, `host.hostname`, `Agent IP`, `ConfigurationVersion`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `SensorStateBitMap`, `@timestamp`, `timestamp`, `ComputerName`, `@timestamp.nanos`, `host.os.platform`, `event.action`, `network.type`, `source.ip`, `#event.kind`, `#Vendor`, `@id`, `@source`, `id`, `name`, `#ecs.version`, `ProvisionState`, `ConfigBuild`, `aid`, `ConfigStateHash`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `NetworkContainmentState`, `ConfigIDBase`, `cid`

## RegCrowdstrikeValueUpdate

- Field count: `61`
- Common filter candidates: `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `event_platform`
- Confirmed fields: `EventOrigin`, `registry.value`, `#event.dataset`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `#event.module`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `RegNumericValue`, `process.entity_id`, `aip`, `event_platform`, `RegValueName`, `RegClassificationIndex`, `BoundingLimitCount`, `@timezone`, `host.hostname`, `Parser.version`, `@rawstring`, `RegClassification`, `event.action`, `source.ip`, `network.type`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `aid`, `RegStringValue`, `RegBinaryValue`, `ConfigBuild`, `#ecs.version`, `RegClassificationFlags`, `RegOperationType`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `RegObjectName`, `RegType`, `registry.key`, `cid`

## ProcessAncestryInformation

- Field count: `39`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `TargetProcessId`, `LocalAddressIP4`, `SHA256HashData`, `event_platform`
- Confirmed fields: `EventOrigin`, `aip`, `GreatGrandparentSHA256HashData`, `OriginalFilename`, `event_platform`, `BaseFileName`, `TargetProcessId`, `ParentSHA256HashData`, `@timezone`, `GreatGrandParentBaseFileName`, `@rawstring`, `Agent IP`, `ParentBaseFileName`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `@source`, `@id`, `id`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `GrandparentSHA256HashData`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `GrandParentBaseFileName`, `cid`, `@timestamp.nanos`, `SHA256HashData`, `ConfigStateHash`, `EffectiveTransmissionClass`, `#type`

## UserLogon

- Field count: `74`
- Common filter candidates: `ComputerName`, `UserName`, `UserSid`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `RemoteIP`, `RemoteAddressIP4`, `LocalAddressIP4`, `event_platform`, `Technique`
- Confirmed fields: `EventOrigin`, `LogonTime`, `Technique`, `RemoteAddressIP6`, `ClientComputerName`, `#event.dataset`, `PasswordLastSet`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `UserPrincipal`, `AuthenticationId`, `#event.module`, `UserSid`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `UserName`, `timestamp`, `LogonServer`, `EnabledPrivilegesBitmask`, `ComputerName`, `@timestamp`, `destination.ip`, `PrivilegesBitmask`, `@timestamp.nanos`, `ContextTimeStamp`, `source.domain`, `LogonDomain`, `RemoteAccount`, `host.os.platform`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `host.hostname`, `@rawstring`, `Parser.version`, `@timezone`, `event.action`, `UserIsAdmin`, `source.ip`, `UserGroupsBitmask`, `network.type`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `LinkedAuthenticationId`, `UserFlags`, `ConfigBuild`, `#ecs.version`, `RemoteIP`, `#type`, `LogonType`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`, `AuthenticationPackage`, `RemoteAddressIP4`, `UserLogonFlags`

## NewScriptWritten

- Field count: `55`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Agent IP`, `Status`, `@ingesttimestamp`, `LocalIP`, `FileEcpBitmask`, `ShareAccess`, `ContextImageFileName`, `FileAttributes`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `ContextBaseFileName`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `@timezone`, `TreeId`, `@rawstring`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `aid`, `Information`, `ConfigBuild`, `MinorFunction`, `#type`, `EffectiveTransmissionClass`, `ConfigStateHash`, `Options`, `DesiredAccess`, `cid`

## NetworkReceiveAcceptIP4

- Field count: `49`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `RemoteIP`, `RemoteAddressIP4`, `RemotePort`, `LocalAddressIP4`, `LocalPort`, `event_platform`, `Technique`
- Confirmed fields: `EventOrigin`, `Technique`, `@timezone`, `ConnectionDirection`, `ConnectionFlags`, `@rawstring`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `RPort`, `CommunityID`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `ContextBaseFileName`, `RemotePort`, `@timestamp.nanos`, `ContextTimeStamp`, `IcmpType`, `RemoteAddressIP4`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `Protocol`, `InContext`, `IcmpCode`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `LocalPort`, `aid`, `ConfigBuild`, `RemoteIP`, `#type`, `EffectiveTransmissionClass`, `LPort`, `ConfigStateHash`

## DriverLoad

- Field count: `60`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `CertificateSignatureHashAlgorithm`, `CertificateIssuer`, `Technique`, `FilePath`, `HashAlgorithm`, `CertificateThumbprintAlgorithm`, `Agent IP`, `ImageFileName`, `AuthenticodeHashDataSHA256`, `RegistryPath`, `@ingesttimestamp`, `LocalIP`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `CertificatePublisher`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `MD5HashData`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `OriginalFilename`, `aip`, `Tactic`, `event_platform`, `CompanyName`, `ServiceDisplayName`, `FixedFileVersion`, `@rawstring`, `DriverLoadFlags`, `ImageEntryPoint`, `@timezone`, `RpcClientProcessId`, `ContextProcessId`, `id`, `#Vendor`, `@source`, `@id`, `name`, `AuthenticodeHashData`, `ImageTimeStamp`, `ConfigBuild`, `FileVersion`, `aid`, `ConfigStateHash`, `EffectiveTransmissionClass`, `#type`, `ImageCheckSum`, `CertificateThumbprint`, `cid`, `CertificateSignatureHash`, `SHA256HashData`

## GzipFileWritten

- Field count: `60`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields: `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `ContextBaseFileName`, `FileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `TemporaryFileName`, `@rawstring`, `@timezone`, `TreeId`, `FileCategory`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `FileWrittenFlags`, `ConfigBuild`, `aid`, `MinorFunction`, `#type`, `EffectiveTransmissionClass`, `DiskParentDeviceInstanceId`, `ConfigStateHash`, `FileOperatorSid`, `cid`, `user.name`

## SyntheticProcessRollup2

- Field count: `77`
- Common filter candidates: `ComputerName`, `UserName`, `UserSid`, `AuthenticationId`, `aid`, `cid`, `TargetProcessId`, `RawProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`
- Confirmed fields: `EventOrigin`, `ProcessStartTime`, `ParentProcessId`, `SourceThreadId`, `#event.dataset`, `FilePath`, `file.target_path`, `Agent IP`, `ImageFileName`, `RawProcessId`, `process.parent.entity_id`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `#event.module`, `UserSid`, `process.start`, `ImageSubsystem`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `timestamp`, `UserName`, `process.hash.sha1`, `ComputerName`, `MD5HashData`, `@timestamp`, `FileName`, `process.command_line`, `IntegrityLevel`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `event_platform`, `aip`, `process.hash.sha256`, `process.entity_id`, `ProcessEndTime`, `Parser.version`, `TargetProcessId`, `Tags`, `process.executable`, `@timezone`, `TreeId`, `host.hostname`, `@rawstring`, `network.type`, `source.ip`, `event.action`, `#event.kind`, `#Vendor`, `@id`, `@source`, `id`, `name`, `aid`, `process.pid`, `SyntheticPR2Flags`, `process.end`, `ConfigBuild`, `#ecs.version`, `SHA1HashData`, `EffectiveTransmissionClass`, `process.hash.md5`, `#Cps.version`, `file.name`, `#type`, `ConfigStateHash`, `user.name`, `cid`, `SourceProcessId`, `CommandLine`, `SHA256HashData`

## ExecutableDeleted

- Field count: `46`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `TargetFileName`, `@timezone`, `TreeId`, `@rawstring`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `aid`, `ConfigBuild`, `MinorFunction`, `#type`, `EffectiveTransmissionClass`, `ConfigStateHash`

## NewExecutableWritten

- Field count: `55`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Agent IP`, `Status`, `@ingesttimestamp`, `LocalIP`, `FileEcpBitmask`, `ShareAccess`, `ContextImageFileName`, `FileAttributes`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `ContextBaseFileName`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `@timezone`, `TreeId`, `@rawstring`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `aid`, `Information`, `ConfigBuild`, `MinorFunction`, `#type`, `EffectiveTransmissionClass`, `ConfigStateHash`, `Options`, `DesiredAccess`, `cid`

## RegistryHiveFileWritten

- Field count: `78`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields: `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `#event.dataset`, `file.target_path`, `FilePath`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `file.size`, `TokenType`, `agent.id`, `LocalAddressIP4`, `ContextThreadId`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `aip`, `TargetFileName`, `Tactic`, `event_platform`, `BoundingLimitCount`, `@timezone`, `host.hostname`, `@rawstring`, `Parser.version`, `TreeId`, `FileCategory`, `event.action`, `source.ip`, `network.type`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `FileObject`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ConfigBuild`, `FileWrittenFlags`, `#ecs.version`, `EffectiveTransmissionClass`, `#Cps.version`, `DiskParentDeviceInstanceId`, `MinorFunction`, `file.name`, `#type`, `ConfigStateHash`, `FileOperatorSid`, `user.name`, `FileSubType`, `cid`

## AsepValueUpdate

- Field count: `60`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `TargetFileName`
- Confirmed fields: `EventOrigin`, `Technique`, `TargetSHA256HashData`, `FilePath`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `AsepIndex`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `Data1`, `TargetFileName`, `TargetCommandLineParameters`, `RegNumericValue`, `aip`, `Tactic`, `event_platform`, `RegValueName`, `BoundingLimitCount`, `TreeId`, `@rawstring`, `@timezone`, `AsepFlags`, `RpcClientProcessId`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `AsepClass`, `RegStringValue`, `RegBinaryValue`, `ConfigBuild`, `aid`, `#type`, `EffectiveTransmissionClass`, `RegOperationType`, `ConfigStateHash`, `RegObjectName`, `RegType`, `AsepValueType`, `user.name`, `cid`

## LFODownloadConfirmation

- Field count: `36`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields: `EventOrigin`, `aip`, `event_platform`, `TargetFileName`, `@rawstring`, `DownloadPort`, `CompletionEventId`, `FilePath`, `@timezone`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `#Vendor`, `DownloadServer`, `@source`, `@id`, `id`, `name`, `aid`, `LocalAddressIP4`, `ConfigBuild`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `FileName`, `#type`, `DownloadPath`, `EffectiveTransmissionClass`, `ConfigStateHash`

## FirewallDeleteRule

- Field count: `44`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `FirewallRuleId`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `Tactic`, `RpcOpNum`, `Technique`, `event_platform`, `@rawstring`, `@timezone`, `InterfaceGuid`, `Agent IP`, `RpcClientProcessId`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `TokenType`, `aid`, `LocalAddressIP4`, `ConfigBuild`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `FirewallRuleId`, `ContextTimeStamp`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `#type`, `ConfigStateHash`, `EffectiveTransmissionClass`, `user.name`, `cid`, `InterfaceVersion`, `RpcNestingLevel`

## RegSystemConfigValueUpdate

- Field count: `49`
- Common filter candidates: `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `@rawstring`, `@timezone`, `TreeId`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `@timestamp.nanos`, `ContextTimeStamp`, `RegNumericValue`, `aip`, `Tactic`, `RegClassificationIndex`, `RegValueName`, `event_platform`, `BoundingLimitCount`, `RegClassification`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `RegStringValue`, `RegBinaryValue`, `ConfigBuild`, `aid`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`, `RegClassificationFlags`, `RegOperationType`, `cid`, `RegObjectName`, `RegType`

## ServiceStopped

- Field count: `65`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `TargetProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `ClientProcessStartKey`, `#event.dataset`, `file.target_path`, `IsHosted`, `FilePath`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `process.command_line`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `event_platform`, `aip`, `BoundingLimitCount`, `ServiceDisplayName`, `Tactic`, `process.entity_id`, `@rawstring`, `@timezone`, `TargetProcessId`, `Parser.version`, `process.executable`, `host.hostname`, `EtwRawProcessId`, `event.action`, `source.ip`, `EtwRawRpcClientProcessId`, `network.type`, `BoundingLimitDuration`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `process.pid`, `ConfigBuild`, `#ecs.version`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `SourceProcessId`, `CommandLine`

## NewExecutableRenamed

- Field count: `47`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Agent IP`, `SourceFileName`, `@ingesttimestamp`, `LocalIP`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `NewFileIdentifier`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `TargetFileName`, `@rawstring`, `@timezone`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `aid`, `ConfigBuild`, `MinorFunction`, `#type`, `EffectiveTransmissionClass`, `ConfigStateHash`

## SensitiveWmiQuery

- Field count: `54`
- Common filter candidates: `ComputerName`, `UserName`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `WmiQuery`, `WmiNamespaceName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `@timezone`, `host.hostname`, `ClientComputerName`, `#event.dataset`, `Parser.version`, `@rawstring`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `#event.module`, `WmiNamespaceName`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `WmiQuery`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `@timestamp.nanos`, `host.os.platform`, `process.entity_id`, `aip`, `BoundingLimitCount`, `Tactic`, `event_platform`, `source.ip`, `event.action`, `network.type`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `aid`, `ConfigBuild`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `user.name`, `cid`

## ReflectiveDotnetModuleLoad

- Field count: `68`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `AssemblyId`, `#event.dataset`, `AssemblyFlags`, `FilePath`, `file.target_path`, `AssemblyName`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `EtwProviderType`, `ManagedPdbBuildPath`, `LocalAddressIP4`, `agent.id`, `ModuleILPath`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `DotnetModuleFlags`, `FileName`, `process.command_line`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `event_platform`, `aip`, `ModuleNativePath`, `Tactic`, `process.entity_id`, `BoundingLimitCount`, `@timezone`, `@rawstring`, `Parser.version`, `process.executable`, `host.hostname`, `source.ip`, `event.action`, `network.type`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `DotnetModuleId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `aid`, `ConfigBuild`, `NativePdbBuildPath`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `CommandLine`

## ZipFileWritte

- Field count: `79`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields: `IrpFlags`, `OperationFlags`, `EventOrigin`, `Technique`, `MajorFunction`, `#event.dataset`, `FilePath`, `Size`, `file.target_path`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `TokenType`, `file.size`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `VolumeSessionUUID`, `BoundingLimitCount`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `TemporaryFileName`, `TargetFileName`, `host.hostname`, `@rawstring`, `TreeId`, `Parser.version`, `@timezone`, `network.type`, `event.action`, `source.ip`, `FileCategory`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `FileObject`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `FileWrittenFlags`, `ConfigBuild`, `aid`, `EffectiveTransmissionClass`, `#Cps.version`, `DiskParentDeviceInstanceId`, `MinorFunction`, `file.name`, `#type`, `ConfigStateHash`, `FileOperatorSid`, `cid`, `user.name`, `IsOnRemovableDisk`

## WebScriptFileWritten

- Field count: `79`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields: `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `#event.dataset`, `file.target_path`, `FilePath`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `file.size`, `TokenType`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `VolumeSessionUUID`, `TargetFileName`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `TemporaryFileName`, `BoundingLimitCount`, `@timezone`, `host.hostname`, `TreeId`, `Parser.version`, `@rawstring`, `FileCategory`, `event.action`, `source.ip`, `network.type`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `FileObject`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ConfigBuild`, `FileWrittenFlags`, `#ecs.version`, `EffectiveTransmissionClass`, `#Cps.version`, `DiskParentDeviceInstanceId`, `MinorFunction`, `file.name`, `#type`, `ConfigStateHash`, `user.name`, `FileOperatorSid`, `cid`, `IsOnRemovableDisk`

## AgentConnect

- Field count: `49`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `LocalAddressIP4`, `event_platform`
- Confirmed fields: `PreviousConnectTime`, `EventOrigin`, `ConfigIDPlatform`, `aip`, `event_platform`, `ConnectionExchange`, `@timezone`, `ConnectionAddressIP6`, `ConnectionCipher`, `ConfigIDBuild`, `@rawstring`, `Agent IP`, `FailedConnectCount`, `ConnectionExchangeStrength`, `ConfigurationVersion`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ConfigBuild`, `ProvisionState`, `ConnectType`, `ConnectionHash`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `ConnectionProtocol`, `VerifiedCertificate`, `ConnectionAddressIP4`, `@timestamp.nanos`, `ConnectTime`, `ConnectionCipherStrength`, `ConnectionHashStrength`, `#type`, `EffectiveTransmissionClass`, `NetworkContainmentState`, `ConfigStateHash`, `cid`, `ConfigIDBase`

## BITSJobCreated

- Field count: `49`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`
- Confirmed fields: `EventOrigin`, `RpcOpNum`, `Technique`, `FilePath`, `@rawstring`, `@timezone`, `Agent IP`, `InterfaceGuid`, `RpcClientProcessId`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `BoundingLimitCount`, `aip`, `TargetFileName`, `Tactic`, `event_platform`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@source`, `@id`, `name`, `ConfigBuild`, `aid`, `EffectiveTransmissionClass`, `#type`, `ConfigStateHash`, `cid`, `user.name`, `InterfaceVersion`, `RpcNestingLevel`

## InjectedThread

- Field count: `49`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `TargetProcessId`, `RawProcessId`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `SourceThreadModule`, `Agent IP`, `RawProcessId`, `@ingesttimestamp`, `LocalIP`, `ThreadStartBytes`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `UserThread`, `Entitlements`, `InjectedThreadFlag`, `@timestamp`, `TargetThreadId`, `ComputerName`, `timestamp`, `SourceThreadStartAddress`, `@timestamp.nanos`, `ContextTimeStamp`, `ThreadStartContext`, `TargetThreadModule`, `event_platform`, `aip`, `Tactic`, `ThreadStartAddressMemoryDescriptionFlags`, `BoundingLimitCount`, `TargetProcessId`, `@rawstring`, `@timezone`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@source`, `@id`, `name`, `ConfigBuild`, `ThreadStartAddress`, `aid`, `#type`, `EffectiveTransmissionClass`, `RawThreadId`, `ConfigStateHash`, `cid`

## MotwWritten

- Field count: `41`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `HostUrl`, `ReferrerUrl`, `event_platform`, `Technique`
- Confirmed fields: `EventOrigin`, `ReferrerUrl`, `Technique`, `FilePath`, `@rawstring`, `@timezone`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `aid`, `LocalAddressIP4`, `ConfigBuild`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `ZoneIdentifier`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `FileName`, `HostUrl`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `TargetFileName`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@source`, `@id`, `name`, `ConfigStateHash`, `EffectiveTransmissionClass`, `#type`

## RegGenericValueUpdate

- Field count: `64`
- Common filter candidates: `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `registry.value`, `EventOrigin`, `Technique`, `#event.dataset`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `#event.module`, `AuthenticationId`, `TokenType`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `BoundingLimitCount`, `process.entity_id`, `aip`, `Tactic`, `RegClassificationIndex`, `RegValueName`, `event_platform`, `RegNumericValue`, `host.hostname`, `@rawstring`, `Parser.version`, `@timezone`, `network.type`, `event.action`, `source.ip`, `RegClassification`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `RegStringValue`, `ConfigBuild`, `aid`, `#Cps.version`, `ConfigStateHash`, `#type`, `RegClassificationFlags`, `RegOperationType`, `EffectiveTransmissionClass`, `RegObjectName`, `RegType`, `registry.key`, `cid`

## AsepKeyUpdate

- Field count: `46`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `RegObjectName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `BoundingLimitCount`, `Tactic`, `Technique`, `event_platform`, `@rawstring`, `@timezone`, `Agent IP`, `AsepFlags`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `AsepIndex`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `ContextTimeStamp`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `AsepClass`, `aid`, `ConfigBuild`, `#type`, `EffectiveTransmissionClass`, `RegOperationType`, `ConfigStateHash`, `cid`, `AsepValueType`, `user.name`, `RegObjectName`

## PeVersionInfo

- Field count: `40`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `TargetProcessId`, `ImageFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `event_platform`
- Confirmed fields: `EventOrigin`, `FixedFileVersion`, `aip`, `CompanyName`, `OriginalFilename`, `event_platform`, `TargetProcessId`, `@rawstring`, `FilePath`, `@timezone`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `@source`, `@id`, `id`, `LanguageId`, `FileVersion`, `LocalAddressIP4`, `ConfigBuild`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `VersionInfo`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `FileName`, `SHA256HashData`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`

## ScheduledTaskRegistered

- Field count: `48`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `TaskName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `TaskAuthor`, `TaskName`, `RpcOpNum`, `TaskExecArguments`, `Technique`, `@rawstring`, `@timezone`, `Agent IP`, `InterfaceGuid`, `LocalIP`, `RpcClientProcessId`, `TaskXml`, `@ingesttimestamp`, `AuthenticationId`, `TokenType`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `TaskExecCommand`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `@timestamp.nanos`, `ContextTimeStamp`, `aip`, `event_platform`, `Tactic`, `#Vendor`, `name`, `@id`, `@source`, `ContextProcessId`, `id`, `EffectiveTransmissionClass`, `#type`, `ConfigStateHash`, `cid`, `user.name`, `InterfaceVersion`, `RpcNestingLevel`

## ScheduledTaskDeleted

- Field count: `60`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `TaskName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `TaskName`, `RpcOpNum`, `Technique`, `#event.dataset`, `InterfaceGuid`, `Agent IP`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `AuthenticationId`, `TokenType`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `event_platform`, `aip`, `Tactic`, `process.entity_id`, `@rawstring`, `@timezone`, `Parser.version`, `host.hostname`, `event.action`, `source.ip`, `RpcClientProcessId`, `network.type`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `process.pid`, `ConfigBuild`, `#ecs.version`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `user.name`, `cid`, `RpcNestingLevel`, `InterfaceVersion`

## CreateService

- Field count: `59`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `RemoteIP`, `RemoteAddressIP4`, `LocalAddressIP4`, `ServiceImagePath`, `event_platform`, `Technique`
- Confirmed fields: `Technique`, `EventOrigin`, `@rawstring`, `@timezone`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `ServiceServiceDll`, `#repo`, `@sourcetype`, `#event_simpleName`, `#repo.cid`, `ServiceDependOnService`, `RpcClientThreadId`, `ServiceSecurity`, `Entitlements`, `timestamp`, `UserName`, `ServiceRequiredPrivileges`, `ComputerName`, `ServiceDelayedAutoStart`, `@timestamp`, `@timestamp.nanos`, `ServiceDescription`, `ContextTimeStamp`, `ServiceFailureActions`, `aip`, `Tactic`, `event_platform`, `ServiceDisplayName`, `ServiceServiceSidType`, `BoundingLimitCount`, `ServiceGroup`, `ServiceErrorControl`, `RpcClientProcessId`, `ServiceImagePath`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `ConfigBuild`, `aid`, `RemoteIP`, `ServiceStart`, `#type`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`, `ServiceObjectName`, `RemoteAddressIP4`, `ServiceType`

## JavaClassFileWritten

- Field count: `52`
- Common filter candidates: `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields: `EventOrigin`, `IrpFlags`, `OperationFlags`, `aip`, `TargetFileName`, `event_platform`, `@timezone`, `MajorFunction`, `FilePath`, `Size`, `@rawstring`, `Agent IP`, `FileCategory`, `@ingesttimestamp`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `FileOperatorSid`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `ContextBaseFileName`, `FileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `FileWrittenFlags`, `ConfigBuild`, `aid`, `MinorFunction`, `#type`, `DiskParentDeviceInstanceId`, `EffectiveTransmissionClass`, `ConfigStateHash`

## ScriptControlDetectInfo

- Field count: `77`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `event_platform`, `Technique`
- Confirmed fields: `EventOrigin`, `process.parent.name`, `DetectSeverity`, `Technique`, `#event.dataset`, `FilePath`, `HostProcessType`, `file.target_path`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `DetectScenario`, `EventCorrelationId`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `file.hash.sha256`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `FileName`, `process.command_line`, `SHA256HashData`, `@timestamp.nanos`, `host.os.platform`, `CommandLine`, `OriginalFilename`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `ContentSHA256HashData`, `ParentImageFileName`, `process.executable`, `DetectDescription`, `Parser.version`, `@timezone`, `ScriptContentName`, `ScriptContentSource`, `host.hostname`, `@rawstring`, `ScriptingLanguageId`, `TemplateInstanceId`, `event.action`, `source.ip`, `process.name`, `network.type`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `ConfigBuild`, `#ecs.version`, `aid`, `TemplateDisposition`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `OriginalContentLength`, `ScriptContent`, `DetectName`, `cid`

## MSDocxFileWritten

- Field count: `63`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`
- Confirmed fields: `Filters`, `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `FilePath`, `Size`, `MajorFunction`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `TokenType`, `FileEcpBitmask`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `FileName`, `ContextBaseFileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `VolumeSessionUUID`, `TargetFileName`, `MSOfficeSubType`, `aip`, `Tactic`, `TemporaryFileName`, `event_platform`, `BoundingLimitCount`, `@timezone`, `TreeId`, `@rawstring`, `FileCategory`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `FileWrittenFlags`, `aid`, `ConfigBuild`, `MinorFunction`, `#type`, `DiskParentDeviceInstanceId`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`, `FileOperatorSid`

## ScriptFileWrittenInfo

- Field count: `61`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `#event.dataset`, `FilePath`, `file.target_path`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `#event.module`, `FileFormatString`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `CscStatus`, `file.hash.sha256`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `SHA256HashData`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `TargetFileName`, `@rawstring`, `@timezone`, `Parser.version`, `host.hostname`, `event.action`, `network.type`, `source.ip`, `BoundingLimitDuration`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ConfigBuild`, `file.type`, `#ecs.version`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `OriginalContentLength`, `ScriptContent`, `WritingProcessId`, `cid`

## SmbClientShareOpenedEtw

- Field count: `47`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `Tactic`, `Technique`, `event_platform`, `@timezone`, `host.hostname`, `ClientComputerName`, `#event.dataset`, `Parser.version`, `@rawstring`, `Agent IP`, `SmbShareName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `host.os.platform`, `network.type`, `event.action`, `source.ip`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `aid`, `ConfigBuild`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`

## UserLogonFailed2

- Field count: `68`
- Common filter candidates: `ComputerName`, `UserName`, `aid`, `cid`, `ContextProcessId`, `TargetProcessId`, `RawProcessId`, `RemoteIP`, `RemoteAddressIP4`, `LocalAddressIP4`, `event_platform`, `Technique`
- Confirmed fields: `EventOrigin`, `Technique`, `ClientComputerName`, `#event.dataset`, `RemoteAddressIP6`, `Agent IP`, `RawProcessId`, `Status`, `LocalIP`, `SubStatus`, `@ingesttimestamp`, `#event.module`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `EtwRawThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `destination.ip`, `source.domain`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `LogonDomain`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `process.entity_id`, `host.hostname`, `TargetProcessId`, `@rawstring`, `Parser.version`, `@timezone`, `event.action`, `EtwRawProcessId`, `source.ip`, `network.type`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `process.pid`, `ConfigBuild`, `aid`, `RemoteIP`, `#type`, `LogonType`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`, `RemoteAddressIP4`

## ScreenshotTakenEtw

- Field count: `66`
- Common filter candidates: `ComputerName`, `UserName`, `aid`, `cid`, `ContextProcessId`, `RawProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `event_platform`
- Confirmed fields: `EventOrigin`, `ScreenshotType`, `Technique`, `FilePath`, `#event.dataset`, `file.target_path`, `ImageFileName`, `Agent IP`, `RawProcessId`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `process.command_line`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `CommandLine`, `BoundingLimitCount`, `aip`, `process.entity_id`, `Tactic`, `event_platform`, `host.hostname`, `@rawstring`, `process.executable`, `Parser.version`, `@timezone`, `source.ip`, `network.type`, `event.action`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ProcessStartKey`, `process.pid`, `PerformanceCounter`, `ConfigBuild`, `#ecs.version`, `RawThreadId`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`, `#Cps.version`, `file.name`, `cid`, `user.name`

## SuspiciousDnsRequest

- Field count: `51`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `DomainName`, `LocalAddressIP4`, `event_platform`
- Confirmed fields: `EventOrigin`, `aip`, `BoundingLimitCount`, `process.entity_id`, `event_platform`, `#event.dataset`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `#event.module`, `DualRequest`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `@timezone`, `RequestType`, `@rawstring`, `InterfaceIndex`, `Parser.version`, `host.hostname`, `network.type`, `source.ip`, `event.action`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `aid`, `ConfigBuild`, `#ecs.version`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `DomainName`

## SuspiciousPrivilegedProcessHandle

- Field count: `55`
- Common filter candidates: `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `TargetProcessId`, `LocalAddressIP4`, `event_platform`
- Confirmed fields: `EventOrigin`, `HandleCreated`, `TargetProcessId`, `host.hostname`, `@timezone`, `#event.dataset`, `Parser.version`, `@rawstring`, `Agent IP`, `event.action`, `@ingesttimestamp`, `source.ip`, `LocalIP`, `network.type`, `AuthenticationId`, `SuspiciousHandleOpenReason`, `#event.module`, `TargetAuthenticationId`, `LocalAddressIP4`, `agent.id`, `ContextThreadId`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `cid`, `@timestamp`, `timestamp`, `ComputerName`, `DesiredAccess`, `IntegrityLevel`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `TargetIntegrityLevel`, `aip`, `event_platform`, `BoundingLimitCount`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `#ecs.version`, `aid`, `ConfigBuild`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`

## RegistryOperationDetectInfo

- Field count: `72`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `event_platform`
- Confirmed fields: `registry.value`, `EventOrigin`, `DetectSeverity`, `Technique`, `#event.dataset`, `file.target_path`, `FilePath`, `ImageFileName`, `Agent IP`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `DetectScenario`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `process.command_line`, `FileName`, `@timestamp.nanos`, `host.os.platform`, `CommandLine`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `RegValueName`, `RegClassificationIndex`, `RegNumericValue`, `DetectDescription`, `@rawstring`, `@timezone`, `process.executable`, `Parser.version`, `host.hostname`, `network.type`, `event.action`, `TemplateInstanceId`, `source.ip`, `RegClassification`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `#ecs.version`, `ConfigBuild`, `RegClassificationFlags`, `RegOperationType`, `EffectiveTransmissionClass`, `#Cps.version`, `TemplateDisposition`, `file.name`, `#type`, `ConfigStateHash`, `cid`, `RegType`, `registry.key`, `DetectName`, `RegObjectName`

## SuspiciousRegAsepUpdate

- Field count: `77`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `RegObjectName`, `RegValueName`, `TargetFileName`
- Confirmed fields: `EventOrigin`, `registry.value`, `DetectSeverity`, `Technique`, `TargetSHA256HashData`, `RegConfigFlags`, `#event.dataset`, `FilePath`, `file.target_path`, `Agent IP`, `ImageFileName`, `RegConfigClass`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `DetectScenario`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RegConfigValueType`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `RegKeyName`, `FileName`, `process.command_line`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `CommandLine`, `TargetFileName`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `RegValueName`, `TargetCommandLineParameters`, `@timezone`, `@rawstring`, `DetectDescription`, `Parser.version`, `process.executable`, `host.hostname`, `source.ip`, `event.action`, `network.type`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `RegStringValue`, `RegConfigIndex`, `ConfigBuild`, `aid`, `RegOperationType`, `ConfigStateHash`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `file.name`, `RegObjectName`, `RegType`, `DetectName`, `registry.key`, `cid`

## DetectionExcluded

- Field count: `57`
- Common filter candidates: `ComputerName`, `UserName`, `UserSid`, `aid`, `cid`, `TargetProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `TargetFileName`
- Confirmed fields: `EventOrigin`, `DetectSeverity`, `Technique`, `TargetSHA256HashData`, `FilePath`, `Agent IP`, `ImageFileName`, `@ingesttimestamp`, `LocalIP`, `DetectScenario`, `UserSid`, `EventCorrelationId`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `TargetProcessTags`, `CommandLine`, `BoundingLimitCount`, `ExclusionType`, `aip`, `Tactic`, `TargetFileName`, `event_platform`, `DetectDescription`, `@rawstring`, `@timezone`, `ContextData`, `ExclusionSource`, `TargetProcessId`, `BoundingLimitDuration`, `id`, `#Vendor`, `@source`, `@id`, `name`, `PatternId`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`, `MigoTemplateInstanceId`, `user.name`, `AllowlistingFilterId`, `DetectName`, `MLModelVersion`, `cid`

## SevenZipFileWritten

- Field count: `74`
- Common filter candidates: `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`
- Confirmed fields: `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `#event.dataset`, `file.target_path`, `FilePath`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `file.size`, `TokenType`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `FileOperatorSid`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `ContextBaseFileName`, `FileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `aip`, `BoundingLimitCount`, `Tactic`, `event_platform`, `TargetFileName`, `host.hostname`, `@rawstring`, `Parser.version`, `@timezone`, `FileCategory`, `event.action`, `source.ip`, `network.type`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `FileObject`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `ConfigBuild`, `FileWrittenFlags`, `#ecs.version`, `EffectiveTransmissionClass`, `#Cps.version`, `DiskParentDeviceInstanceId`, `MinorFunction`, `file.name`, `#type`, `ConfigStateHash`

## ProcessInjection

- Field count: `53`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `TargetProcessId`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `DetectSeverity`, `Technique`, `InjecteeImageFileName`, `ExecutableBytes`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `DetectScenario`, `PayloadClassificationFlags`, `LocalAddressIP4`, `PayloadClassification`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `TargetThreadId`, `ComputerName`, `timestamp`, `@timestamp.nanos`, `ModuleName`, `ModifiedRegisters`, `BoundingLimitCount`, `aip`, `Tactic`, `event_platform`, `@rawstring`, `ThreadExecutionControlType`, `TargetProcessId`, `DetectDescription`, `@timezone`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `ThreadStartAddress`, `ConfigBuild`, `MemoryDescriptionFlags`, `aid`, `ConfigStateHash`, `EffectiveTransmissionClass`, `#type`, `HookId`, `WellKnownTargetFunction`, `InjectorImageFileName`, `DetectName`, `cid`

## FileDeleteInfo

- Field count: `40`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `FilePath`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `TreeId`, `@rawstring`, `@timezone`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@source`, `@id`, `name`, `ConfigBuild`, `aid`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`

## SmbServerShareOpenedEtw

- Field count: `53`
- Common filter candidates: `ComputerName`, `UserName`, `aid`, `cid`, `DomainName`, `RemoteIP`, `RemoteAddressIP4`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `Tactic`, `Technique`, `event_platform`, `RemoteAddressIP6`, `@timezone`, `host.hostname`, `#event.dataset`, `Parser.version`, `@rawstring`, `Agent IP`, `SmbShareName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `#ecs.version`, `agent.id`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `destination.ip`, `host.os.platform`, `event.action`, `network.type`, `source.ip`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `RemoteIP`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `user.name`, `cid`, `DomainName`, `RemoteAddressIP4`

## KernelServiceStarted

- Field count: `41`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `Tactic`, `ServiceDisplayName`, `Technique`, `event_platform`, `FilePath`, `@rawstring`, `@timezone`, `ImageFileName`, `Agent IP`, `RpcClientProcessId`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `LocalAddressIP4`, `ConfigBuild`, `ContextThreadId`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `FileName`, `ImageBaseName`, `@timestamp.nanos`, `ContextTimeStamp`, `EffectiveTransmissionClass`, `#type`, `ConfigStateHash`

## FileWrittenWithEntropyHigh

- Field count: `42`
- Common filter candidates: `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `FilePath`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `ShannonEntropy`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `@rawstring`, `@timezone`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`

## FileOpenInfo

- Field count: `43`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `Technique`, `TreeId`, `@rawstring`, `FilePath`, `@timezone`, `Agent IP`, `Status`, `@ingesttimestamp`, `LocalIP`, `ShareAccess`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `DesiredAccess`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `@timestamp.nanos`, `ContextTimeStamp`, `FileName`, `event_platform`, `aip`, `BoundingLimitCount`, `Tactic`, `TargetFileName`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `ConfigBuild`, `aid`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`

## VolumeSnapshotDeleted

- Field count: `74`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`
- Confirmed fields: `EventOrigin`, `RpcOpNum`, `Technique`, `#event.dataset`, `FilePath`, `file.target_path`, `Agent IP`, `ImageFileName`, `InterfaceGuid`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `agent.id`, `#repo`, `@sourcetype`, `#event_simpleName`, `#repo.cid`, `file.hash.sha256`, `RpcClientThreadId`, `VolumeName`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `VolumeDriveLetter`, `FileName`, `process.command_line`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `aip`, `Tactic`, `event_platform`, `process.executable`, `Parser.version`, `@timezone`, `TreeId`, `host.hostname`, `VolumeSnapshotName`, `@rawstring`, `event.action`, `RpcClientProcessId`, `source.ip`, `network.type`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `aid`, `process.pid`, `ConfigBuild`, `#ecs.version`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `user.name`, `cid`, `RpcNestingLevel`, `CommandLine`, `SHA256HashData`, `InterfaceVersion`

## PythonFileWritten

- Field count: `57`
- Common filter candidates: `ComputerName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `TargetFileName`, `event_platform`
- Confirmed fields: `EventOrigin`, `IrpFlags`, `OperationFlags`, `Technique`, `FilePath`, `MajorFunction`, `Size`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `TokenType`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `IsOnNetwork`, `Entitlements`, `FileOperatorSid`, `@timestamp`, `timestamp`, `ComputerName`, `cid`, `ContextBaseFileName`, `FileName`, `IsOnRemovableDisk`, `@timestamp.nanos`, `ContextTimeStamp`, `SHA256HashData`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `BoundingLimitCount`, `@rawstring`, `@timezone`, `FileCategory`, `BoundingLimitDuration`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `FileObject`, `aid`, `FileWrittenFlags`, `ConfigBuild`, `MinorFunction`, `#type`, `DiskParentDeviceInstanceId`, `EffectiveTransmissionClass`, `ConfigStateHash`

## WmiProviderRegistrationEtw

- Field count: `73`
- Common filter candidates: `ComputerName`, `UserName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `event_platform`, `Technique`
- Confirmed fields: `ProcessStartTime`, `EventOrigin`, `DetectSeverity`, `Technique`, `ClientComputerName`, `FilePath`, `#event.dataset`, `file.target_path`, `ImageFileName`, `Agent IP`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `DetectScenario`, `process.start`, `agent.id`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `UserName`, `timestamp`, `ComputerName`, `process.command_line`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `event_platform`, `aip`, `process.entity_id`, `Tactic`, `BoundingLimitCount`, `@timezone`, `DetectDescription`, `@rawstring`, `process.executable`, `Parser.version`, `host.hostname`, `event.action`, `EtwRawProcessId`, `source.ip`, `network.type`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `process.pid`, `PerformanceCounter`, `ConfigBuild`, `aid`, `file.name`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `user.name`, `WmiProviderType`, `DetectName`, `cid`, `WmiProviderName`, `CommandLine`

## DirectoryTraversalOverSMB

- Field count: `41`
- Common filter candidates: `ComputerName`, `UserName`, `UserSid`, `AuthenticationId`, `aid`, `cid`, `RemoteIP`, `RemoteAddressIP4`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `Tactic`, `Technique`, `event_platform`, `@rawstring`, `ClientComputerName`, `EventThreshold`, `@timezone`, `@ingesttimestamp`, `Agent IP`, `LocalIP`, `AuthenticationId`, `UserSid`, `ConfigBuild`, `LocalAddressIP4`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `UserName`, `@timestamp.nanos`, `TargetDirectoryName`, `RemoteAddressIP4`, `#Vendor`, `name`, `@id`, `id`, `@source`, `RemoteIP`, `#type`, `LogonType`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`

## DllInjection

- Field count: `40`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `TargetProcessId`, `RawProcessId`, `LocalAddressIP4`, `event_platform`
- Confirmed fields: `EventOrigin`, `aip`, `event_platform`, `@rawstring`, `@timezone`, `TargetProcessId`, `Agent IP`, `RawProcessId`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `@source`, `@id`, `ContextProcessId`, `id`, `ContextThreadId`, `aid`, `LocalAddressIP4`, `ConfigBuild`, `InjectedDll`, `ThreadStartAddress`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `InjectedThreadFlag`, `@timestamp`, `TargetThreadId`, `ComputerName`, `timestamp`, `@timestamp.nanos`, `ContextTimeStamp`, `ThreadStartContext`, `#type`, `EffectiveTransmissionClass`, `RawThreadId`, `ConfigStateHash`, `cid`

## SuspiciousPeFileWritten

- Field count: `79`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `ContextBaseFileName`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`
- Confirmed fields: `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `FilePath`, `#event.dataset`, `file.target_path`, `Size`, `ImageFileName`, `Agent IP`, `@ingesttimestamp`, `LocalIP`, `FileEcpBitmask`, `AuthenticationId`, `#event.module`, `file.size`, `TokenType`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#repo`, `@sourcetype`, `IsOnNetwork`, `#event_simpleName`, `#repo.cid`, `FileIdentifier`, `file.hash.sha256`, `Entitlements`, `@timestamp`, `timestamp`, `UserName`, `ComputerName`, `process.command_line`, `FileName`, `ContextBaseFileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `process.entity_id`, `aip`, `TargetFileName`, `Tactic`, `event_platform`, `@rawstring`, `@timezone`, `process.executable`, `Parser.version`, `host.hostname`, `network.type`, `event.action`, `source.ip`, `threat.tactic.name[0]`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `FileObject`, `#ecs.version`, `ConfigBuild`, `FileWrittenFlags`, `aid`, `file.name`, `MinorFunction`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`, `user.name`, `FileOperatorSid`, `SHA256HashData`, `CommandLine`, `IsOnRemovableDisk`

## NetShareDelete

- Field count: `41`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `event_platform`
- Confirmed fields: `EventOrigin`, `aip`, `RpcOpNum`, `event_platform`, `@rawstring`, `@timezone`, `InterfaceGuid`, `Agent IP`, `RpcClientProcessId`, `ShareName`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `LocalAddressIP4`, `ConfigBuild`, `ContextThreadId`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `Entitlements`, `@timestamp`, `timestamp`, `UserName`, `ComputerName`, `@timestamp.nanos`, `ContextTimeStamp`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `ConfigStateHash`, `#type`, `EffectiveTransmissionClass`, `user.name`, `cid`, `InterfaceVersion`, `RpcNestingLevel`

## BrowserInjectedThread

- Field count: `44`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `TargetProcessId`, `RawProcessId`, `LocalAddressIP4`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `Tactic`, `ThreadStartAddressMemoryDescriptionFlags`, `Technique`, `event_platform`, `@rawstring`, `@timezone`, `TargetProcessId`, `Agent IP`, `RawProcessId`, `@ingesttimestamp`, `LocalIP`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `ThreadStartAddress`, `LocalAddressIP4`, `ConfigBuild`, `ContextThreadId`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `UserThread`, `Entitlements`, `InjectedThreadFlag`, `@timestamp`, `TargetThreadId`, `timestamp`, `ComputerName`, `@timestamp.nanos`, `ContextTimeStamp`, `SourceThreadStartAddress`, `ThreadStartContext`, `#type`, `RawThreadId`, `EffectiveTransmissionClass`, `ConfigStateHash`, `cid`

## SAMHashDumpFromUnsignedModule

- Field count: `72`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `RegRootObjectName`, `file.code_signature.timestamp`, `EventOrigin`, `Technique`, `FilePath`, `#event.dataset`, `file.target_path`, `ImageFileName`, `Agent IP`, `Status`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `file.hash.sha256`, `#repo.cid`, `@sourcetype`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `FileSigningTime`, `RegKeyName`, `FileName`, `RegCreateDisposition`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `Certificate`, `process.entity_id`, `aip`, `Tactic`, `ExtendedKeyUsages`, `event_platform`, `host.hostname`, `@rawstring`, `process.executable`, `Parser.version`, `@timezone`, `source.ip`, `network.type`, `event.action`, `id`, `ContextProcessId`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `#ecs.version`, `SignInfoFlags`, `ConfigBuild`, `aid`, `file.name`, `#type`, `PublicKeys`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `DesiredAccess`, `RegPostObjectName`, `cid`, `KeyObject`, `RegCreateOptions`, `file.x509.serial_number`, `SHA256HashData`

## RansomwareOpenFile

- Field count: `69`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `FileName`, `FilePath`, `LocalAddressIP4`, `TargetFileName`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `IrpFlags`, `EventOrigin`, `OperationFlags`, `Technique`, `MajorFunction`, `#event.dataset`, `file.target_path`, `FilePath`, `Agent IP`, `Status`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `FileAttributes`, `ShareAccess`, `agent.id`, `ContextThreadId`, `LocalAddressIP4`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `FileIdentifier`, `Entitlements`, `@timestamp`, `timestamp`, `ComputerName`, `FileName`, `@timestamp.nanos`, `ContextTimeStamp`, `host.os.platform`, `TargetFileName`, `aip`, `process.entity_id`, `Tactic`, `event_platform`, `BoundingLimitCount`, `@timezone`, `host.hostname`, `@rawstring`, `Parser.version`, `TreeId`, `source.ip`, `event.action`, `network.type`, `BoundingLimitDuration`, `ContextProcessId`, `id`, `threat.tactic.name[0]`, `#Vendor`, `@id`, `@source`, `name`, `#event.kind`, `threat.technique.name[0]`, `FileObject`, `#ecs.version`, `Information`, `ConfigBuild`, `aid`, `file.name`, `MinorFunction`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `ConfigStateHash`, `DesiredAccess`, `cid`, `Options`

## RansomwareFileAccessPattern

- Field count: `62`
- Common filter candidates: `ComputerName`, `aid`, `cid`, `ContextProcessId`, `ImageFileName`, `FileName`, `CommandLine`, `FilePath`, `LocalAddressIP4`, `SHA256HashData`, `TargetFileName`, `event_platform`
- Confirmed fields: `EventOrigin`, `Technique`, `#event.dataset`, `FilePath`, `file.target_path`, `Agent IP`, `ImageFileName`, `SourceFileName`, `@ingesttimestamp`, `LocalIP`, `#event.module`, `LocalAddressIP4`, `agent.id`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `file.hash.sha256`, `Entitlements`, `@timestamp`, `timestamp`, `ClientId`, `ComputerName`, `cid`, `FileName`, `process.command_line`, `CommandLine`, `@timestamp.nanos`, `host.os.platform`, `SHA256HashData`, `event_platform`, `aip`, `TargetFileName`, `Tactic`, `process.entity_id`, `@timezone`, `Tags`, `@rawstring`, `Parser.version`, `process.executable`, `host.hostname`, `event.action`, `network.type`, `source.ip`, `ContextProcessId`, `id`, `#Vendor`, `@id`, `@source`, `name`, `PatternId`, `#event.kind`, `threat.technique.name[0]`, `threat.tactic.name[0]`, `ConfigBuild`, `#ecs.version`, `aid`, `ConfigStateHash`, `#type`, `#Cps.version`, `EffectiveTransmissionClass`, `file.name`

## FirewallSetRule

- Field count: `45`
- Common filter candidates: `ComputerName`, `UserName`, `AuthenticationId`, `aid`, `cid`, `ContextProcessId`, `LocalAddressIP4`, `FirewallRuleId`, `FirewallRule`, `event_platform`, `Technique`, `Tactic`
- Confirmed fields: `EventOrigin`, `aip`, `Tactic`, `RpcOpNum`, `Technique`, `event_platform`, `@rawstring`, `@timezone`, `InterfaceGuid`, `Agent IP`, `RpcClientProcessId`, `@ingesttimestamp`, `LocalIP`, `AuthenticationId`, `TokenType`, `FirewallRule`, `LocalAddressIP4`, `ConfigBuild`, `aid`, `#event_simpleName`, `#repo`, `@sourcetype`, `#repo.cid`, `RpcClientThreadId`, `Entitlements`, `@timestamp`, `UserName`, `ComputerName`, `timestamp`, `@timestamp.nanos`, `FirewallRuleId`, `ContextTimeStamp`, `#Vendor`, `name`, `id`, `@id`, `@source`, `ContextProcessId`, `EffectiveTransmissionClass`, `#type`, `ConfigStateHash`, `cid`, `user.name`, `RpcNestingLevel`, `InterfaceVersion`
