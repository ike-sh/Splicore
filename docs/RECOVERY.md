# Host Network Recovery

- Documentation status: Canonical
- Audience: Operators and maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Bounded recovery of recorded host ownership.
- Lifecycle: Update with journal schema and recovery behavior.

Stop client listeners before `network repair`. The private operational journal is
separate from SQLite desired configuration. Schema 1 remains readable; new typed
Windows records require schema 2. Unknown versions, truncation, invalid shapes,
foreign scope and unsafe permissions fail closed. Doctor exposes redacted recovery
status. Do not delete a corrupt journal to force activation or reset the network.

Recovery compares current with before/after/authorized partial states and compensates
in reverse ownership order. Unknown external state is preserved and marked conflict.
Failed persistence/cleanup retains debt and rejects subsequent activation.

Wintun sessions are process-local; adapter GUID/generation/owner are durable. Close
interrupts and joins I/O before releasing handles. Parent deletion waits for failed
child restoration. Orphan deletion requires exact GUID and Wintun service; display
name is insufficient. Restart requirements are reported without rebooting the host.

WinINET A→B→A applies only while current state is owned. External B→C is preserved,
including during partial apply/restore. Unexpected listener exit restores A immediately;
a conflict leaves C and reports degraded. Notifications follow restoration. Named
RAS connections are outside LAN scope.

Windows activation remains blocked pending real platform qualification.
These are tested ownership components, not real Windows certification. See
[system integration](SYSTEM_INTEGRATION.md), [Windows](PLATFORM_WINDOWS.md)
and [testing](TESTING.md).

## Endpoint leases and cleanup debt

Current desired endpoints are reconciled with live generation references before
publication. Last reference release follows real query/adapter/socket retirement.
A failed release keeps logical ownership and durable journal debt; health is degraded
and shutdown returns cleanup failure. Explicit recovery requires stopped runtimes.
After crash, in-memory refs are gone: reconcile the observed journal and restored
canonical desired state; do not restore imaginary sockets or trust stale PIDs.
Borrowed protections and unknown external edits are preserved.
