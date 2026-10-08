# Architecture decision records

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-05
- Owner: Core maintainers
- Responsibility: Decision navigation, individual decision status and review lifecycle.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Fixed product principles come from the Phase 0 brief. Proposed implementation decisions await maintainer review; no runtime implementation is implied.

Documentation status is separate from each decision's `Status` section. Keep
accepted rationale; when superseding a durable decision, add a new numbered ADR
and link the old record to it. Routine documentation/index edits need no new ADR.
See [documentation policy](../DOCUMENTATION_POLICY.md) and the
[architecture map](../architecture/README.md) for detailed specification ownership.

* [0001-upstream-baseline — Upstream stable baseline](0001-upstream-baseline.md) — Accepted for Phase 0
* [0002-product-identity — Independent product and gradual namespace](0002-product-identity.md) — Proposed for maintainer review
* [0003-domain-state-authority — Single domain state authority](0003-domain-state-authority.md) — Proposed for maintainer review
* [0004-account-binding-credential — Account, Binding and Credential separation](0004-account-binding-credential.md) — Proposed for maintainer review
* [0005-protocol-engine-separation — Protocol and Engine separation](0005-protocol-engine-separation.md) — Proposed for maintainer review
* [0006-client-profile-exporter — Canonical ClientProfile and exporters](0006-client-profile-exporter.md) — Proposed for maintainer review
* [0007-storage-strategy — SQLite WAL and driver qualification](0007-storage-strategy.md) — Proposed for maintainer review
* [0008-api-boundary — Application services and local API boundary](0008-api-boundary.md) — Proposed for maintainer review
* [0009-xray-compatibility-engine — Internal Xray compatibility engine](0009-xray-compatibility-engine.md) — Proposed for maintainer review
* [0010-mieru-integration-strategy — Mieru reference to native embedding](0010-mieru-integration-strategy.md) — Proposed for maintainer review
* [0011-upstream-sync-strategy — Stable mergeability and drift control](0011-upstream-sync-strategy.md) — Proposed for maintainer review
* [0012-versioning-model — Independent product/schema/API identities](0012-versioning-model.md) — Proposed for maintainer review

* [0013-snell-runtime-composition — Owned Snell runtime composition](0013-snell-runtime-composition.md) — Proposed for maintainer review
* [0014-hysteria2-runtime-composition — Owned Hysteria2 service and UDP lifecycle](0014-hysteria2-runtime-composition.md) — Proposed; implemented experimentally

* [0015-tuic-shared-control-plane — Registered creation and shared QUIC control plane](0015-tuic-shared-control-plane.md) — Proposed; implemented experimentally

- [0016: VLESS engine placement and inbound server secrets](0016-vless-engine-server-secrets.md): accepted candidate foundation; Vision deferred under ADR 0017.

- [0017: Defer Vision due to dependency safety](0017-defer-vision-dependency-safety.md): accepted for the Phase 5 candidate.

- [0018: Owned Xray compatibility engine](0018-xray-owned-child-engine.md): accepted for the Experimental Phase 6 local freeze.

- [0019: Xray specialized feature boundary](0019-xray-specialized-feature-boundary.md): accepted for the Experimental Phase 7 local freeze, official source and shared transport secret scope.

## Phase 8 implementation decision

[0020 — Mieru owned native embedding](0020-mieru-owned-native-embedding.md): accepted for the Phase 8 Experimental local freeze; official dependency, raw/session ownership, global metrics exclusion and policy limits.

## Phase 9 distribution decision

[0021 — Local pinned Linux service distribution](0021-linux-local-distribution.md): proposed for review; canonical layout, dedicated user, one unit, separate pinned Xray and snapshot rollback.

## Phase 10 client decision

[0022 — Client Runtime domain](0022-client-runtime-domain.md): accepted for the Phase 10 Experimental local freeze;
Node/Outbound separation, shared daemon and SOCKS-first scope.

## Phase 11 ownership decision

[0023 — Client UDP and adapter ownership](0023-client-udp-ownership.md): accepted
for the Phase 11 Experimental local freeze; bounded SOCKS association lifetime and per-adapter leases.

## Phase 12 decisions

[0024 routing](0024-routing-snapshot-match-semantics.md), [0025 policy](0025-policy-selection-health.md),
[0026 DNS bootstrap](0026-dns-bootstrap-dependency.md): accepted for the Experimental
Phase 12 local freeze; ordered snapshots, typed selection/health and explicit bootstrap.

## Phase 13 host integration

[0027 TUN](0027-tun-host-network-ownership.md), [0028 journal](0028-network-mutation-journal.md),
[0029 proxy](0029-system-proxy-restoration.md): accepted for the Experimental Phase 13 local freeze.

[0030 Windows ownership](0030-windows-host-network-ownership.md): accepted;
Wintun partial recovery, typed LAN WinINET restoration and guarded real qualification.

## Unified runtime protection

[0031 underlay](0031-unified-underlay-protection.md): accepted for the Experimental Phase 13 freeze; typed socket/child
capabilities, retained endpoint leases, dynamic bootstrap and reused TUN ownership.

## Phase 14 management decisions

[0032 identity/generation](0032-provider-generation-node-identity.md),
[0033 preview/transaction](0033-management-preview-transaction.md),
[0034 source security](0034-remote-source-security.md): accepted for the Experimental Phase 14 local freeze;
implemented experimentally, with explicit rejected alternatives and current limits.

## Current architecture correction

Native is the sole runtime engine. Historical Phase 6/7 direction is superseded; FinalMask/Sudoku are out of scope.

- [Decision](../adr/0035-xray-runtime-removed-from-core.md)
- [Correction report](../reports/ARCHITECTURE_CORRECTION_XRAY_BOUNDARY_REPORT.md)

## Qualification fix native runtime decision

- [0036 — Official gVisor eventfd ownership](0036-official-gvisor-eventfd-lifecycle.md):
  Accepted for the local Qualification Fix / Native TUN freeze; Splicore-owned
  runtime and exact official stack dependency, preserving historical compatibility
  evidence. Platform Qualification is not resumed.

## Phase 16 native Shadowsocks decision

- [0037 — Shadowsocks editions and credential ownership](0037-native-shadowsocks-editions-and-credential-ownership.md):
  Accepted for the consolidated Phase 16 + Phase 17 freeze; native AEAD 2017/2022 framing,
  encrypted inbound/account/node credentials and bounded generation ownership.

## Phase 17 independent core decision

- [0038 — Remove sing-box / SagerNet core dependency graph](0038-remove-sager-net-core-dependency-graph.md):
  Accepted after Final Independent Re-Review PASS; independent module identity,
  owned runtime and zero SagerNet dependency graph. Phase 16 is consolidated
  into the Phase 17 freeze.

## Phase 18 standard Trojan decision

- [0039 — Native standard Trojan TLS and association ownership](0039-native-standard-trojan-tls-and-association-ownership.md):
  Accepted after final independent Phase 18 re-review PASS; shared encrypted
  credentials and TLS, terminal framed IO, bounded
  associations, generic user mutation and explicit fallback deferral.
  Phase 18 locally frozen after exact-index EOL recovery; first blocked attempt
  preserved in the canonical Freeze report.

## Phase 19 modern VMess decision

- [0040 — Modern VMess and replay/clock ownership](0040-modern-vmess-and-replay-clock-ownership.md):
  Proposed; alterId0 AEAD boundary, shared managed resources and bounded
  generation-independent replay history. Independent review is pending.

## Phase 20 generic proxy interfaces decision

- [0041 — Generic proxy interfaces and credential ownership](0041-generic-proxy-interfaces-and-credentials.md):
  Proposed; consolidate local SOCKS5/HTTP/Mixed, typed local bindings in existing
  listener documents, strict no-auth upstream marker and shared remote DNS policy.
  Phase 20 review is pending.
