# CrowdStrike CQL Query Writer

This skill pack is a curated reference for generating safer CrowdStrike Falcon LogScale / CQL queries for Falcon EDR and related hunting workflows.

It is designed to help an LLM:

- generate query drafts
- repair broken queries
- choose safer event types
- map telemetry to ATT&CK behavior
- avoid hallucinating fields, joins, or event names

## What This Pack Contains

- [SKILL.md](SKILL.md)
  Main workflow, guardrails, fallback rules, and response contract.
- [references/field-maps.md](references/field-maps.md)
  Normalized event-by-event field reference with pivots, joins, and notes.
- [references/event-field-catalog.md](references/event-field-catalog.md)
  Exhaustive packaged field inventory for the curated event set.
- [references/mitre-mappings.md](references/mitre-mappings.md)
  ATT&CK-oriented guidance for turning TTPs and telemetry into likely query shapes.
- [references/query-patterns.md](references/query-patterns.md)
  Vetted example patterns constrained to mapped events in this package.

## Intended Use

Use this pack when you want an LLM to generate or review CrowdStrike queries with better schema awareness and lower hallucination risk.

Good use cases:

- IOC hunts
- behavior hunts
- ATT&CK/TTP-driven hunts
- prevalence queries
- query repair
- process, DNS, network, registry, SMB, service, scheduled task, driver, injection, and ransomware-adjacent Falcon hunts

## Scope

This `v1` pack is intentionally scoped to a curated set of **67 high-value `#event_simpleName` values**.

That means:

- it is strong inside the packaged event scope
- it should fail safer outside that scope
- it may substitute a high-confidence mapped event when no direct event match exists
- it should not invent unsupported Falcon schema

If a requested event is not directly mapped, the skill is expected to:

1. use a direct mapped event when possible
2. otherwise choose a high-confidence alternative from the packaged set
3. otherwise fall back to a narrow schema-safe pivot query
4. otherwise ask for clarification

## How To Use It With an LLM

Give the LLM:

- the user’s hunt question or telemetry
- this skill pack
- the relevant repository or event context if you know it

Best prompts usually include at least one of:

- `#event_simpleName`
- `aid`
- `ComputerName`
- `UserName`
- IP
- domain
- hash
- command line
- ATT&CK technique or behavior description

Example asks:

- `Write a CrowdStrike CQL query for suspicious PowerShell using ProcessRollup2.`
- `Hunt for remote interactive logons on host X.`
- `Given this command line, what Falcon event should I start with and what query should I run?`
- `Map this telemetry to MITRE ATT&CK and produce a safe starter query.`

## Recommended Reference Order

The pack is meant to be used in this order:

1. [references/field-maps.md](references/field-maps.md)
2. [references/event-field-catalog.md](references/event-field-catalog.md)
3. [references/mitre-mappings.md](references/mitre-mappings.md)
4. [references/query-patterns.md](references/query-patterns.md)

Why:

- `field-maps.md` is the main schema authority
- `event-field-catalog.md` is the exhaustive backup inventory
- `mitre-mappings.md` helps when the ask is behavior-driven instead of schema-driven
- `query-patterns.md` provides reusable vetted shapes after schema validation

## How This Was Curated

This pack was not built from generic Falcon assumptions alone.

It was curated from:

- vetted query examples
- a larger syntax/reference dump used privately during development
- field inventories exported from a real CrowdStrike environment
- per-event field normalization for the selected high-value event set

The most important curation step was building the event references from actual observed field availability for the chosen `#event_simpleName` values, rather than relying on guessed schema.

That curation process included:

1. extracting the selected event names and their available fields
2. normalizing those into [references/event-field-catalog.md](references/event-field-catalog.md)
3. converting the raw inventory into [references/field-maps.md](references/field-maps.md) with safer pivots, join hints, and notes
4. aligning ATT&CK mappings and example queries to the confirmed event set
5. removing or rewriting examples that referenced unmapped events
6. adding fallback logic so the skill prefers confirmed alternatives over fabricated queries

## Accuracy Model

This pack is built to optimize for safe usefulness, not blind completeness.

It tries to reduce bad output by enforcing:

- confirmed field usage
- confirmed event scope
- explicit assumptions
- cautious join behavior
- event substitution only at a high-confidence threshold

The skill should be more likely to say:

- `use this mapped event instead`
- `this is a fallback pivot`
- `confirm this field before running`

and less likely to:

- invent a field
- invent an event
- assume a join works
- produce a fake Falcon query that only looks plausible

## Limits

This is not a complete model of every CrowdStrike event or every NG-SIEM parser.

Known limits:

- only the curated 67-event Falcon set is packaged here
- some environments may expose additional fields or aliases
- some joins may still need local validation
- NG-SIEM queries remain more schema-dependent than Falcon EDR queries

## Best Way To Extend It

If you want to improve this pack over time, the highest-value additions are:

- more confirmed event field dumps
- more vetted query examples tied to mapped events
- more ATT&CK mappings tied to confirmed telemetry
- sanitized sample events for tricky event types
- notes on fields that are often empty or environment-specific

## Bottom Line

This pack is meant to be a practical `v1` production skill for safer CrowdStrike query generation, especially when paired with a strong reasoning model and real hunt context.
