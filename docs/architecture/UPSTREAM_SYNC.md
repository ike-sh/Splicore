# Upstream stable sync procedure

- Documentation status: Canonical
- Audience: Maintainers and upstream integrators
- Last reviewed: 2026-10-01
- Owner: Upstream maintainers
- Responsibility: Stable candidate review, merge/selective port, drift control and qualification.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Current anchor: v1.14.1 at `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
Full ancestry/tags retained; only remote is upstream. Never squash/filter/orphan
history or force-update upstream tags. No sync is executed beyond Phase 0 fetch.

1. `git fetch upstream --tags`; identify official non-draft, non-prerelease stable
   release (e.g. future v1.14.2/v1.15/v1.16), peel full SHA and record tag provenance.
2. Compare current baseline and candidate (`git log`, `git diff`, merge-base and
   changed module/build tags); verify baseline ancestor and unexpected tag movement.
3. Review protocol/network/TLS/REALITY/QUIC/listener/auth/stats changes, config
   migrations, toolchain/dependency/licensing and security fixes. Read release notes
   **and source**, including removed defaults/platform features.
4. Create isolated integration branch from Splicore main; merge stable history
   where feasible. Selective ports require explicit source-commit mapping and
   reason; do not claim full release baseline if only selected changes are ported.
5. Resolve conflicts by preserving public domain contracts and adapter isolation;
   update translation/capabilities/qualification, not silently importing upstream JSON.
6. Build platform matrix and tests, lint, applicable race/fuzz, differential
   protocol tests, third-party interop and DB/config/NoBrand migration tests.
7. Failure injection and upgrade/rollback restore exercise; field beta with
   support bundles and per-protocol flags; qualify stable only after review.
8. Update baseline SHA/source map/ADR/evidence and release manifest. Maintainer
   controls publication; nothing pushes automatically.

Conflict ranking: new Splicore docs/modules low; composition/include/build assets
medium; global option schema, Box construction, auth/private services, route/stats
fast paths and listener/TLS/QUIC medium-high/high. Track patch inventory with owner,
rationale, touched upstream symbols and tests; propose generic hooks upstream.
Avoid formatting/branding churn and runtime implementation copies without provenance.

Prevent drift with periodic stable comparisons, pinned module/tag identities,
protocol differential references, a short adapter patch budget and explicit review
of upstream removals. Keep old qualified reference binaries in test fixtures with
source/digests; do not auto-upgrade production through a CI webhook.
