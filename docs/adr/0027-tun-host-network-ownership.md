# TUN and Host Network Ownership

- Documentation status: Canonical
- Audience: Core developers and operators
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Accepted Phase 13 ownership decision and qualification boundary.
- Lifecycle: Update with the supported ownership and qualification boundary.

## Status

Accepted for the Experimental Phase 13 local freeze. Real platform qualifications
remain pending; Windows activation stays guarded.

## Decision

Reuse official gVisor and one client runtime. Canonical typed intent has no protocol branches. Owned platform CRUD, dedicated Linux daemon UID bypass, explicit capture and conflict-preserving restoration protect the underlay. Unified runtime socket wiring is implemented; Windows capture rejects pending real platform qualification. Source/runtime/OS qualifications stay distinct.

## Consequences

No new protocol ID, engine ID, binary or service. No upstream/dependency edits.
Native Linux and Windows real-network qualification remain pending under the local
environment constraint. See [system integration](../SYSTEM_INTEGRATION.md).
