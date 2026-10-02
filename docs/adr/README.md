# Architecture decision records

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-02
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
