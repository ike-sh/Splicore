# Diagnostics and field debugging

- Documentation status: Canonical
- Audience: Core developers and field operators
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Proposed diagnostic command semantics and bounded redacted local bundles.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Current Phase 2 implementation

Doctor describes registry entries and actual native listener health without PSKs. Metadata has decimal payload counters; only explicit export returns secrets. See [Snell support](../protocol/SNELL.md).

Phase 1 implements version, status, doctor, capabilities, validate and run.
Status is the shared application System response; an absent daemon prints
not running and exits normally. Doctor reports real Foundation checks from
System/Capabilities and read-only path existence checks. Offline it marks DB
integrity/schema unavailable rather than opening or repairing the database.
Diagnose/support-bundle and the full runtime checks below remain deferred.

| Command | Output |
|---|---|
| `splicore version` | product, full commit, UTC build time, Go/platform, upstream baseline, config/DB/ABI/API versions, channel and compiled capabilities |
| `splicore status` | node/instance, committed/applied generation, operation state, listener/engine health and explicit degraded reasons |
| `splicore doctor` | structured checks for DB/schema/permissions/ports/clock/kernel/required features and actionable failure codes |
| `splicore validate` | syntactic/domain/capability errors; no live mutation |
| `splicore diagnose` | bounded targeted listener/auth/route/engine observations; secret-safe and consented network probes |
| `splicore support-bundle` | local archive + manifest of selected redacted diagnostics; no upload |

Machine-readable JSON and human-readable summaries share check codes. Distinguish
not compiled, unsupported platform, unqualified protocol, unhealthy engine,
revision conflict and permission failure. Exit code 0 success, 1 operational/check
failure; Foundation currently uses 1 for rejected input as well. Future richer
operation failures will expose structured result details.

Default support bundle includes version/full commit/upstream SHA, OS/kernel/arch,
config and DB schemas, Protocol ABI/API version, doctor results, redacted bootstrap
and domain snapshot, listener observations, committed/applied generation and pending
operations, bounded recent logs and sanitized crash metadata. Firewall inspection
is read-only, platform-specific and marked unavailable when permission/tools lack.

Exclude PSK, secret UUIDs, passwords, API/subscription tokens, private keys, client
credentials, raw DB, raw child config and raw memory dumps. Minimize IP/domain/
Account display metadata; optional sensitive network detail must be explicit.
Bundle generator cannot mutate firewall/listeners or silently install diagnostic
tools on user servers. Redaction is tested at typed inputs and final archive scan.

Manifest records creation UTC time, generator version, selected sections, byte
limits, check outcomes, omitted fields, file digests and sensitivity level.
Limit total size/time and protect output permissions. Raw crash reports are kept
locally with strict permissions/retention; default bundle includes sanitized stack
and crash identity only. No support server/upload endpoint is added in Phase 0.
