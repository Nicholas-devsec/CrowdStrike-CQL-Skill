# CrowdStrike CQL Query Writer

A Claude skill for writing CrowdStrike Falcon LogScale (CQL) queries against Falcon EDR telemetry. It keeps Claude to event types and fields that actually exist, so the queries it writes run instead of just looking right.

It covers 67 vetted common `#event_simpleName` values: process, DNS, network, registry, SMB, services, scheduled tasks, drivers, injection and ransomware-related activity. Outside that set it falls back to the closest mapped event, then to a narrow pivot query, and asks you for clarification if neither fits. It won't make up fields.

## Install

Copy this folder into your skills directory:

```bash
git clone https://github.com/Nicholas-devsec/CrowdStrike-CQL-Skill ~/.claude/skills/crowdstrike-cql-query-writer
```

Claude picks it up when you ask for a CrowdStrike or CQL query.

## Example prompts

- Write a CQL query for suspicious PowerShell using ProcessRollup2.
- Hunt for remote interactive logons on host X.
- Here's a command line. Which Falcon event should I start with?
- Map this behavior to MITRE ATT&CK and give me a starter query.

Including an event name, `aid`, hostname, IP, domain, hash, or command line gives better results.

## Layout

| File | Purpose |
| --- | --- |
| [SKILL.md](SKILL.md) | Workflow, guardrails, fallback rules |
| [references/field-maps.md](references/field-maps.md) | How to hunt with each event: pivots, join hints, notes |
| [references/event-field-catalog.md](references/event-field-catalog.md) | Complete confirmed field list per event |
| [references/mitre-mappings.md](references/mitre-mappings.md) | ATT&CK techniques mapped to events |
| [references/query-patterns.md](references/query-patterns.md) | Example queries |

## Limits

- Only the 67 packaged events are covered.
- Your environment may expose extra fields or aliases.
- Joins may need testing in your own tenant.
- NG-SIEM parsers vary more than Falcon EDR, so check those queries before relying on them.

## Contributing

Useful additions: field lists for more events, tested queries tied to the mapped events, ATT&CK mappings, and notes on fields that are often empty. Please sanitize any sample data.
