# Crash-safe Network Mutation Journal

- Documentation status: Canonical
- Audience: Core developers and operators
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Accepted Phase 13 operational journal ownership decision.
- Lifecycle: Update with the supported ownership and qualification boundary.

## Status

Accepted for the Experimental Phase 13 local freeze. Power-loss and real Windows
platform qualification remain pending.

## Decision

Desired configuration stays in SQLite schema 7. Private bounded operational journal records before/after state, scope, generation, owner and acknowledgments. Persist before writes, verify every step and restore in reverse. Stop data-plane readers before device restoration. Corruption, external mutations and failed writes are degraded errors, never guessed global repair. ExecStopPost, next start and uninstall use the original owner.

## Consequences

No new protocol ID, engine ID, binary or service. No upstream/dependency edits.
Native Linux and Windows real-network qualification remain pending under the local
environment constraint. See [system integration](../SYSTEM_INTEGRATION.md).
