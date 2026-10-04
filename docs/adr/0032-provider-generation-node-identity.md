# Provider Generation and Stable Node Identity

- Documentation status: Canonical
- Audience: Core, client and integration maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Phase 14 implemented decisions and alternatives.
- Lifecycle: Update with implemented contracts and qualified evidence.

## Status

Accepted for the authorized Experimental Phase 14 local freeze, 2026-10-04.

## Decision

Provider IDs, Node IDs and generated Outbound IDs are separate persistent random UUIDs.
Source-native keys are hashed scoped matching hints; fallback fingerprints exclude
secrets and mutable labels. Complete candidate generations commit before publication.
Referenced disappearances retain explicit usable stale nodes; unreferenced resources
are removed transactionally. Protocol changes on a native key reject and require a
new key. Existing sessions retain retired runtime ownership. URL/order/name identity,
host:port-only merge and destructive refresh cascade were rejected. Tradeoff: without
a native hint, endpoint changes create replacement resources requiring reference review.
See [Node](../architecture/NODE_MODEL.md) and [Provider](../architecture/PROVIDER_MODEL.md).
