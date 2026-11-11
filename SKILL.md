---
name: crowdstrike-cql-query-writer
description: Use this skill when asked to generate, repair, review, or explain CrowdStrike Falcon LogScale / CQL queries for Falcon EDR or NG-SIEM. It helps produce valid, conservative queries, asks for missing repository or event context when needed, and avoids inventing fields, functions, or detections.
---

# CrowdStrike CQL Query Writer

This skill is for writing reliable CrowdStrike Falcon LogScale queries with emphasis on Falcon EDR and NG-SIEM use cases.

The goal is not to produce the most clever query. The goal is to produce the safest useful query that matches known CQL syntax and clearly separates facts from assumptions.

## Use This Skill For

- Generating a new CrowdStrike CQL query
- Repairing a broken LogScale query
- Translating a detection idea into CQL
- Explaining what a CQL query does
- Tightening an existing query to reduce noise
- Producing dashboard-ready queries with parameters

## Core Rules

1. Never invent field names, event names, repositories, parsers, lookup files, or custom saved searches.
2. Never claim a query is valid for a dataset unless the required fields are known from the prompt or local references.
3. Prefer the simplest valid pipeline over complex logic.
4. Filter early, aggregate later.
5. Prefer field filters over free-text filters when the field is known.
6. When regex is needed, prefer field-scoped regex over all-field regex for performance and clarity.
7. If a needed detail is unknown, say so explicitly and use a parameter or placeholder rather than fabricating.
8. Mark assumptions in plain language after the query.

## Default Workflow

Follow this order every time:

1. Identify the target.
2. Decide whether the user means Falcon EDR telemetry, NG-SIEM logs, or generic LogScale data.
3. Identify whether the user is asking for an IOC hunt, a behavior hunt, an ATT&CK/TTP hunt, a prevalence query, or an explanation.
4. Load the right reference file(s) before writing the query.
5. Identify the minimum known anchors.
6. Build the query from those anchors outward.
7. Validate syntax shape against the rules below.
8. Return the query plus a short assumptions/checks note.

## Reference Routing

Use references deliberately instead of relying on memory:

- Use `references/field-maps.md` first when you know the event type and want safer pivots, joins, ECS aliases, and hunt notes.
- Use `references/event-field-catalog.md` to confirm whether a field exists for an event. It lists every confirmed field and is the final check; `field-maps.md` is a curated subset and can omit real fields.
- Use `references/mitre-mappings.md` when the user gives a TTP, ATT&CK technique, behavior narrative, or raw telemetry that needs ATT&CK interpretation.
- Use `references/query-patterns.md` when the user wants a proven hunting pattern or a detection-style starting point.

If multiple files apply, use them in this order:

1. `field-maps.md`
2. `event-field-catalog.md` if needed
3. `mitre-mappings.md` if behavior/TTP mapping is needed
4. `query-patterns.md` for pattern reuse

## Hunt Intake

Normalize the user request into these parts before writing a query:

- Observable type:
  process, command line, file, registry, service, DNS, IP, port, user, share, driver, WMI, injection, or ransomware-like behavior
- Scope:
  single host, multiple hosts, single user, timeframe, repository, or event type
- Goal:
  exact-match hunt, broadened hunt, prevalence summary, enrichment, or explanation
- Confidence:
  exact field known, event known but field uncertain, or both event and field uncertain

## Event Selection Fallbacks

When the user asks for a query and there is no direct mapped event match, do not stop at "unsupported" unless no safe alternative exists.

Use this fallback order:

1. Direct mapped event match
2. High-confidence alternative mapped event
3. Minimal schema-safe pivot query using a confirmed broader event
4. Ask for clarification only if none of the above can be done safely

### Direct Match

Use the requested `#event_simpleName` when it exists in `references/field-maps.md` or `references/event-field-catalog.md` and the needed fields are confirmed.

The one exception is a pattern in `references/query-patterns.md` marked `Schema status: Validated example`. See What To Avoid for how to reuse it.

### High-Confidence Alternative

If no direct event is mapped, choose an alternative only when both of these are true:

- The alternative event is in the packaged 67-event set
- The alternative event exposes the core fields needed for the hunt

Treat the alternative as high confidence when the event preserves the user's main intent, for example:

- process execution intent -> `ProcessRollup2` or `SyntheticProcessRollup2`
- outbound connection intent -> `NetworkConnectIP4`
- domain lookup intent -> `DnsRequest` or `SuspiciousDnsRequest`
- logon intent -> `UserLogon` or `UserLogonFailed2`
- registry persistence intent -> `RegGenericValueUpdate`, `AsepValueUpdate`, `AsepKeyUpdate`, or `SuspiciousRegAsepUpdate`
- SMB/share activity intent -> `SmbServerShareOpenedEtw`, `SmbClientShareOpenedEtw`, `DirectoryTraversalOverSMB`, or `NetShareDelete`
- injection intent -> `ProcessInjection`, `DllInjection`, `InjectedThread`, or `SuspiciousPrivilegedProcessHandle`
- driver or kernel intent -> `DriverLoad`
- scheduled task intent -> `ScheduledTaskRegistered` or `ScheduledTaskDeleted`
- service creation or service state intent -> `CreateService`, `ServiceStopped`, or `KernelServiceStarted`

When using an alternative event:

- Say which mapped event was chosen
- Say why it is the nearest safe fit
- Do not claim it is identical to the originally requested event

### Minimal Schema-Safe Pivot

If there is no clean near-match event, fall back to a broader event with confirmed fields and keep the query narrow.

Examples:

- use `ProcessRollup2` for command line, LOLBin, script launcher, and parent-child hunts
- use `NetworkConnectIP4` for remote IP, port, and egress hunts
- use `DnsRequest` for domain-oriented hunts
- use `UserLogon` for session and account activity hunts

In this mode, tell the user that the query is a safe pivot based on the closest confirmed telemetry in the packaged event set.

### Confidence Threshold

Only present a query as a working answer when at least one of these is true:

- direct mapped event plus confirmed fields
- alternative mapped event plus confirmed fields that cover the main hunt objective
- broader mapped pivot event plus clear disclosure that it is a fallback

If those conditions are not met, do not invent a query. Return a minimal scoped query or ask for the missing event, repo, or field context.

## Enrichment Workflow

When enough context exists, enrich in this order:

1. Event type
2. Core entity filters such as `aid`, `ComputerName`, `UserName`, `AuthenticationId`, `ContextProcessId`
3. ATT&CK mapping if behavior-driven
4. Process or object context joins only when the join key is confirmed
5. Aggregation only if the user wants prevalence, clustering, or summarization

Do not skip the schema step and jump straight to examples.

## Target Identification

Use these working distinctions:

- `Falcon EDR`: endpoint telemetry with event types such as `#event_simpleName=ProcessRollup2`, `NetworkConnectIP4`, `DnsRequest`, `UserLogon`, registry events, driver loads, and similar Falcon sensor data.
- `NG-SIEM / generic LogScale`: broader log repositories where the schema depends on parser, datasource, vendor, and repository design.

If the user asks for CrowdStrike but does not specify EDR vs NG-SIEM:

- Prefer `Falcon EDR` only when the request clearly names Falcon endpoint event types or endpoint behaviors.
- Otherwise produce a schema-safe NG-SIEM pattern with parameters and an explicit note that field names must match the repository parser.

If the user gives a concrete `#event_simpleName`, prefer that event and validate field choices against `field-maps.md` or `event-field-catalog.md` before generating the query.

If the user names an event that is not in the packaged 67-event set, try to map it to the nearest high-confidence packaged event before asking for more detail.

## Safe Query Construction

### Start Narrow

When possible, start with one or more of:

- A datasource or tag filter such as `#event_simpleName=...`
- A platform filter such as `event_platform=Win`
- A stable entity filter such as `aid=?aid`, `ComputerName=?ComputerName`, `UserName=?UserName`
- A known field predicate such as `ImageFileName=/.../i`

### Preferred Query Shape

Use this general shape:

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| FieldA=...
| FieldB=...
| NewField := ...
| groupBy([...], function=[...], limit=max)
| sort(_count, order=desc)
```

### Use Parameters Instead of Guessing

If a host, user, IP, domain, process name, repo, or threshold is unknown, prefer parameters:

```logscale
aid=?aid
ComputerName=?ComputerName
?{threshold=10}
```

### Build From Confirmed Fields

- Prefer fields confirmed in `references/field-maps.md`.
- If a field is not in `field-maps.md`, check `references/event-field-catalog.md`. A field listed there is confirmed for that event.
- If the field is absent from both, do not invent it.
- If a query pattern conflicts with the confirmed field maps, trust the field maps and state the assumption.
- If the requested event is absent but a high-confidence mapped alternative exists, use the alternative and state the substitution plainly.

### Aggregation Discipline

- Do not place generic free-text search after the first aggregate.
- Use `table()` for readable output.
- Use `groupBy()` only when summarization is actually needed.
- Use `sort()` after the dataset has the field being sorted.

## Syntax Guardrails

Apply these checks before returning a query:

### Filters

- Space-separated filters imply `AND`.
- `OR` has unusual precedence in CQL and binds tighter than `AND`.
- Add parentheses when mixing `AND` and `OR`.
- `field = *` checks field existence.
- `field != *` checks field absence.

### Comparisons

- In filter syntax, the left side is interpreted as a field name.
- For field-to-field comparisons, use expression-capable functions such as `test()` or `if()` patterns only when necessary.
- Use `=` in filters and `==` inside eval-style expressions.

### Regex

- `/regex/` without a field can search broadly and may be expensive.
- Prefer `FieldName=/regex/`.
- Add `/i` only when case-insensitive matching is required.
- Use anchors like `^` and `$` when exact matching matters.

### Field Creation

- Use `:=` to create or overwrite fields.
- Keep derived field names simple and readable.
- Do not chain unnecessary renames if a direct `as=` or `:=` is clearer.

### Conditionals

- Use `if()` for simple binary choices.
- Use `case { ... }` for multiple branches.
- Use `match { ... }` only when all branches evaluate the same field.

### Time

- Prefer UI time range unless the user specifically asks for time syntax inside the query.
- When query text needs time parameters, prefer explicit user-provided values or documented relative forms like `2h`, `1d`, `now@d`.
- Do not invent unsupported calendar anchoring in contexts like live queries.

## Falcon EDR Patterns

Use these only when the user request clearly maps to Falcon endpoint telemetry.

### Process Execution

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\powershell\.exe$/i
| table([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
```

### Network Connections

```logscale
#event_simpleName=NetworkConnectIP4
| aid=?aid
| RemoteAddressIP4=?RemoteAddressIP4
| table([@timestamp, aid, ComputerName, ContextProcessId, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort])
| sort(@timestamp, order=desc)
```

### DNS

```logscale
#event_simpleName=DnsRequest
| DomainName=?DomainName
| table([@timestamp, aid, ComputerName, DomainName, event_platform])
| sort(@timestamp, order=desc)
```

### Remote Logons

```logscale
#event_simpleName=UserLogon
| aid=?aid LogonType=10
| table([@timestamp, UserName, UserPrincipal, LogonServer], limit=1000)
| sort(@timestamp, order=desc)
```

Prefer `UserLogon` when that event is confirmed in the local field maps. Only use `UserIdentity` if the environment explicitly exposes it.

## NG-SIEM / Generic LogScale Patterns

Use these when the schema is parser-dependent or the datasource is not Falcon endpoint telemetry.

### Schema-Safe Narrowing Pattern

```logscale
#repo=?repo
| table([@timestamp, @rawstring], limit=200)
```

If the field names are not known, do not fake them. Return a minimal repo-scoped query like the above, then state which parsed fields must be confirmed before adding filters.

### Parameterized Summary Pattern

```logscale
#repo=?repo
| ConfirmedField=*
| groupBy([ConfirmedField], function=count(as=_count), limit=max)
| sort(_count, order=desc)
```

Only use this pattern when the user explicitly wants aggregation and the target grouping field is already confirmed in the target repository.

## What To Avoid

- Do not output SQL, Splunk SPL, KQL, Sigma, YARA, or pseudo-code when the user asked for CQL.
- Do not write new queries against event types outside the packaged mapped event set unless the user explicitly supplies new confirmed schema.
- Do not extend or adapt a pattern marked `Schema status: Validated example` with events or fields outside the packaged set. Reuse it as written, and say it uses events outside the packaged set and should be confirmed in the target environment.
- Do not use undocumented functions just because they sound plausible.
- Do not mix parser-time behavior with search-time behavior unless you are sure it applies.
- Do not assume a join key exists.
- Do not assume `FileName`, `CommandLine`, `UserName`, or `ComputerName` exist in non-EDR repositories.
- Do not hide uncertainty behind confident wording.

## Response Contract

When generating a query, return:

1. The query in a `logscale` fenced block.
2. A short `Assumptions:` line.
3. A short `Check before running:` line when schema, repo, or field validity is uncertain.
4. If ATT&CK was part of the request, add a short `Likely ATT&CK:` line.
5. If a direct event match was not available, add a short `Mapped event used:` line.

Example:

```text
Assumptions: This uses Falcon EDR ProcessRollup2 telemetry on Windows and assumes CommandLine is parsed.
Check before running: Confirm the target repo exposes ProcessRollup2 and that the host filter should be aid or ComputerName.
```

## Expansion Points

Expand these sections over time instead of bloating the main workflow:

- `references/field-maps.md`
  Add confirmed field maps by datasource, parser, and event type.
- `references/event-field-catalog.md`
  Keep this as the complete list of confirmed fields per packaged event.
- `references/query-patterns.md`
  Add vetted detection and hunting patterns with a short note on when to use each.

Keep examples in references concise and confirmed. Remove or label any example that has not been tested against a real environment.

## Local References

Use these files only as needed:

- [references/field-maps.md](references/field-maps.md)
  Use this as the primary schema-and-enrichment guide.
- [references/event-field-catalog.md](references/event-field-catalog.md)
  Use this to confirm whether a field exists for a packaged `#event_simpleName`.
- [references/query-patterns.md](references/query-patterns.md)
  Use this for vetted Falcon EDR hunting and detection examples after validating the schema.
- [references/mitre-mappings.md](references/mitre-mappings.md)
  Use this when the user describes behavior, a TTP, or raw telemetry and you need to choose the most likely ATT&CK technique and starting query shape.

## Maintenance Notes

When updating this skill:

- Keep `SKILL.md` focused on workflow, rules, and trusted patterns.
- Move bulky examples and field inventories into `references/`.
- Remove duplicated syntax explanations.
- Prefer fewer, safer examples over many unverified ones.
- If a query example is environment-specific, label what must be changed.
