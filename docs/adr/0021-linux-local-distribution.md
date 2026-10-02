# ADR 0021: Local Pinned Linux Service Distribution

- Documentation status: Canonical
- Audience: Core, distribution and security reviewers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Durable Phase 9 layout, service identity and rollback decisions.
- Lifecycle: Update status after review; supersede with a new ADR for incompatible choices.

## Status

Proposed for Phase 9 review; implementation and qualification are recorded separately.

## Context

The frozen protocol/runtime foundation needs a predictable installation and
operations contract before a controlled NoBrand canary. SQLite is authoritative,
credentials depend on an external master key, and Xray remains an owned child.

## Decision

Use local checksum-pinned versioned tarballs, machine manifests and one systemd
unit running as a dedicated non-login user. Keep the current `state.db` name in
the canonical state directory. Use CAP_NET_BIND_SERVICE only. Mieru stays embedded;
Xray is a separate exact pinned artifact with no startup downloads.

Stop before SQLite snapshotting, save matching key/config/program and replace
files through fsync+rename. Verify READY and API health before recording success.
Rollback restores the original snapshot; older binaries never reverse migrations.
Default uninstall retains state; explicit purge accepts only validated fixed
owned trees. Support bundles use allowlisted summaries, excluding raw journal text.

## Alternatives

Bundling every engine would enlarge each package and blur platform qualification.
Root runtime would grant excessive privileges. Online latest installation would
remove reproducible pinning. Copying live WAL files cannot provide a coherent
backup. Arbitrary install/purge roots increase path ambiguity and deletion risk.

## Consequences and review triggers

Root is needed for installation, not steady-state proxy traffic. A brief upgrade
maintenance window is required. Power-loss installer recovery remains manual,
with private retained backups and fail-closed receipts. Stable/beta/nightly,
signatures, deb/rpm, SELinux/AppArmor, additional platforms and real NoBrand
integration require new evidence. See [distribution](../DISTRIBUTION.md) for the
contract and [upgrade](../UPGRADE.md) for rollback limits.
