# Splicore

Splicore is an independent proxy core project derived from sing-box, with a
modular, extensible server architecture as its target.

## Status

**Early Development / Snell, Hysteria2, TUIC, VLESS and Mieru Experimental.** Phases 0–8 are locally frozen.
Phase 6 native/Xray VLESS duality is **FROZEN**, with 40 actual client
traffic cells and default race/checkptr gates passing. See the
[Phase 6 report](docs/reports/PHASE_6_XRAY_ENGINE_DUALITY_REPORT.md).
Phase 7 is **FROZEN**, with typed FinalMask/Sudoku options and the same pinned Xray child,
shared credential vault and authorized Xray exporter. Scope: plain TCP, flow none,
prefer_ascii, padding 0–3; masked UDP is NOT QUALIFIED, masked TLS/REALITY is UNSUPPORTED.
See [Phase 7 workflow](docs/development/PHASE_7_XRAY_EXTENSIONS.md) and
[freeze report](docs/reports/PHASE_7_FREEZE_REPORT.md). Both features remain Experimental.

Phase 8 is **FROZEN** with official Mieru v3.38.0 embedded in the existing Native
Engine, 24 managed client cells and default race/checkptr gates passing. No permanent
mita service is required. Quota/rate, hot updates, persistent usage and Mieru arm64
runtime qualification remain deferred. See [Mieru support](docs/protocol/MIERU.md)
and the [Phase 8 freeze report](docs/reports/PHASE_8_FREEZE_REPORT.md).
The Phase 9 branch is prepared; Distribution implementation has not started.

Phase 2 implements Snell v5/v6 using committed SQLite state, the existing sing-box
data plane, payload stats, protected Linux API/CLI and client exporters. Pinned
Mihomo and sing-box clients pass actual TCP/UDP tests. Surge has contract tests only.
Phase 2 is a local freeze; no stable Splicore runtime is released.

Phase 3 adds Hysteria2 using the pinned native QUIC/TLS implementation, encrypted
password credentials, multi-user Bindings, static TLS, TCP/UDP and per-Binding
payload stats. Mihomo 1.19.30 and sing-box 1.14.1 pass trusted-CA traffic tests.
Phase 3 is locally frozen. Phase 4 freezes TUIC v5 with shared TLS/QUIC,
registered creation and Binding attribution. Phase 5 implements a native VLESS/REALITY
candidate with separate Protocol and Engine identities. Vision is **DEFERRED / UNSUPPORTED**
and rejected before runtime or export. Flow-none VLESS/REALITY uses default safety
checks; see the [final acceptance report](docs/reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md). See [Hysteria2 support](docs/protocol/HYSTERIA2.md),
[workflow](docs/development/PHASE_3_HYSTERIA2.md) and
[Phase 3 report](docs/reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md).

See [TUIC support](docs/protocol/TUIC.md), [Phase 4 workflow](docs/development/PHASE_4_TUIC.md)
and [Phase 4 report](docs/reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md).

See [Snell support](docs/protocol/SNELL.md), [workflow](docs/development/PHASE_2_SNELL.md)
and the [Phase 2 report](docs/reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md).

This checkout retains the upstream runtime for baseline verification. Implemented
Splicore boundaries are listed above; future architecture surfaces remain deferred.

## Goals

- Build an independent domain and control plane on a mature network foundation.
- Keep protocols modular and make future protocol extensions practical.
- Model multi-user access through separate Accounts, Bindings and Credentials.
- Unify usage accounting, quota and policy across authorized protocol bindings.
- Preserve standard wire behavior for protocols declared compatible.
- Separate server runtime configuration from client profiles and exporters.
- Reserve stable API and CLI boundaries for future management integrations.
- Maintain upstream provenance and a sustainable process for upstream updates.

## Architecture

The architecture separates domain and application services from protocol
adapters, execution engines, storage and control transports. Protocols describe
wire behavior; engines supply implementations. Committed SQLite domain state
will drive runtime configuration and independent client profiles. The sing-box
network foundation remains behind those boundaries.

See the [architecture overview](docs/ARCHITECTURE.md) for the design and its limits.

## Protocol Direction

Snell, Hysteria2, TUIC, VLESS and FinalMask/Sudoku have bounded experimental profiles.
Mieru is also Experimental within the qualified default profile.

| Protocol / capability | Planned engine |
| --- | --- |
| Snell | Native: v5 no obfs, v6 default; experimental |
| Hysteria2 | Native: static TLS, password multi-user, TCP/UDP; experimental |
| TUIC | Native: v5, static TLS, UUID/password, cubic/native UDP; experimental |
| VLESS / REALITY | Native: TCP/XUDP, UUID, plain/static TLS/REALITY; experimental; Vision deferred/unsupported |
| Mieru | Native: official v3.38.0 embedding, username/password multi-user, TCP/UDP; Experimental |
| FinalMask / Sudoku | Xray v26.3.27: bounded plain TCP Sudoku mask; Experimental |

Details and qualification gates: [protocol and engine index](docs/protocol/README.md).

## Compatibility

Server implementations may evolve while preserving the wire behavior of profiles
declared compatible. Actual interoperability with third-party clients is a
release requirement, qualified by client version and feature profile. A rendered
configuration alone does not establish compatibility. See
[client compatibility](docs/architecture/CLIENT_COMPATIBILITY.md).

## Documentation

Start at the [documentation index](docs/README.md).

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/adr/README.md)
- [API design and contract](docs/api/README.md)
- [Storage model](docs/architecture/STORAGE_MODEL.md)
- [Testing strategy](docs/testing/TEST_STRATEGY.md)
- [Development context](docs/DEVELOPMENT_CONTEXT.md) and [workflow](docs/development/README.md)
- [Foundation build, commands and tests](docs/development/FOUNDATION.md)
- [Phase 1 Foundation Report](docs/reports/PHASE_1_FOUNDATION_REPORT.md)
- [Historical Phase 0 architecture report](docs/PHASE_0_ARCHITECTURE_REPORT.md)

## Upstream

Splicore is an independent derivative project based in part on
[SagerNet/sing-box](https://github.com/SagerNet/sing-box). It is not affiliated
with or endorsed by SagerNet. Original upstream copyright and licensing terms
are preserved. See [provenance](docs/UPSTREAM.md) and [NOTICE](NOTICE.md).

## License

The derived source retains GPL-3.0-or-later and the upstream naming/association
wording in the unchanged [LICENSE](LICENSE).

<!--
Documentation status: Canonical
Audience: Project visitors and developers
Last reviewed: 2026-10-02
Owner: Project maintainers
Responsibility: Project identity, development status and documentation entry point.
Lifecycle: Update with project status and navigation; keep detailed specifications in docs.
-->

See [VLESS support and blockers](docs/protocol/VLESS.md), [Phase 5 workflow](docs/development/PHASE_5_VLESS.md)
and [Phase 5 report](docs/reports/PHASE_5_VLESS_REALITY_NATIVE_VERTICAL_SLICE_REPORT.md).

## Xray compatibility engine candidate

Phase 6 implements an Experimental owned external Xray child for the same
ProtocolID `vless`, selected with EngineID `native` or `xray`. Account/Binding/UUID,
ClientProfile and exporters stay shared. Vision is DEFERRED / UNSUPPORTED for both.
Phase 7 adds Experimental FinalMask with one bounded Sudoku TCP mask. Xray stats and strict policy enforcement
remain deferred. See [workflow](docs/development/PHASE_6_XRAY.md),
[process decision](docs/adr/0018-xray-owned-child-engine.md) and
[acceptance report](docs/reports/PHASE_6_XRAY_ENGINE_DUALITY_REPORT.md).
