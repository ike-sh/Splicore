# Windows Host Network Ownership

- Documentation status: Canonical
- Audience: Core developers and maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Windows partial activation and exact recovery decisions.
- Lifecycle: Update when Windows runtime dependency coverage is completed.

## Status

Accepted for the Experimental Phase 13 local freeze. Actual runtime
underlay integration is qualified through the protected contract/fake backend;
real Windows activation remains guarded pending platform qualification.

## Decision

Separate adapter creation, session start, addresses, routes and readiness. Persist
random GUID/generation/owner before creation; retain candidate handles on failure.
Interrupt/join I/O before ending sessions or closing adapters. Failed child
restoration retains the parent debt. Crash recovery selects only the journal GUID
with Wintun service through SetupAPI, including nonpresent devices. OpenAdapter
handle closure cannot delete an orphan. WintunCloseAdapter has a void C contract;
the Go wrapper's unspecified return-register interpretation is not an OS error.
Readback establishes removal. A restart requirement becomes debt, never a reboot.

WinINET ownership is default LAN user intent. Query FLAGS_UI, restore FLAGS, include
seven supported intent options, and keep RAS/detection cache outside scope. Persist
forward/restore intermediates before setters. Compare before each setter, verify
afterward and preserve unknown C. Notify SETTINGS_CHANGED then REFRESH. Returned
strings are bounded, copied and GlobalFree'd. Reject sensitive PAC/credentials.

Bypass belongs to the host/runtime graph. Validate before bootstrap, normalize
mapped addresses, merge reasons and install new protection before removing old
ownership. Borrowed routes remain untouched. Failed acknowledgment compensates;
unresolved conflicts remain durable/degraded. No payload lock or guessed reset.

## Remaining integration requirement

Runtime socket owners now consume the protected underlay and fresh dependency set,
including retained generations and reused TUN listeners, through [ADR 0031](0031-unified-underlay-protection.md).
Actual adapter fixtures extend model/reconciliation evidence. Real Windows
qualification remains pending.
Keep the original Windows guards until validation, complete ownership planning and
durable recovery precede the whole transaction.

## Qualification

Portable tests use default race/checkptr in WSL. Native Windows uses ordinary
fixtures, compilation and symbol/ABI checks. Real Windows TUN/auto-route/WinINET are
NOT CERTIFIED; full Windows race NOT EXECUTED. No developer network mutation or
upstream edits. See [Windows](../PLATFORM_WINDOWS.md),
[system integration](../SYSTEM_INTEGRATION.md) and [recovery](../RECOVERY.md).
