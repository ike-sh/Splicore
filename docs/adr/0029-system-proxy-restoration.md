# System Proxy Ownership and Restoration

- Documentation status: Canonical
- Audience: Core developers and operators
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Accepted Phase 13 proxy restoration decision and qualification boundary.
- Lifecycle: Update with the supported ownership and qualification boundary.

## Status

Accepted for the Experimental Phase 13 local freeze. Real WinINET runtime is NOT
CERTIFIED and activation stays guarded.

## Decision

Target an owned HTTP/mixed literal loopback listener. Capture typed default LAN
WinINET intent through its per-connection API, journal previous/expected/intermediate
states, compare current ownership and restore the previous snapshot. Preserve an
unknown external C and report conflict. Refuse credentials and sensitive PAC data.
Use SETTINGS_CHANGED then REFRESH; do not write registry proxy values. Unexpected
listener exit restores the owned proxy deterministically; restoration failure stays
degraded. Linux desktop is unsupported. Native Windows guards remain pending
real platform qualification, which still needs an isolated Windows
environment. See [Windows ownership](0030-windows-host-network-ownership.md).

## Consequences

No new protocol ID, engine ID, binary or service. No upstream/dependency edits.
Native Linux and Windows real-network qualification remain pending under the local
environment constraint. See [system integration](../SYSTEM_INTEGRATION.md).
