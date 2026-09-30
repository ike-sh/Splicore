# Splicore

Splicore is an independent proxy core project derived from sing-box, with a
modular, extensible server architecture as its target.

## Status

**Early Development / Architecture Phase.** Phase 0 architecture is complete
and available for maintainer review. Splicore has **not been released as a stable
proxy runtime**; its domain services and control interfaces are proposed designs.

This checkout retains the upstream runtime for baseline verification. The
architecture described here is not a claim of implemented Splicore support.

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

The proposed design separates domain and application services from protocol
adapters, execution engines, storage and control transports. Protocols describe
wire behavior; engines supply implementations. Committed SQLite domain state
would drive runtime configuration and independent client profiles. The sing-box
network foundation remains behind those boundaries.

See the [architecture overview](docs/ARCHITECTURE.md) for the design and its limits.

## Protocol Direction

**All rows are planned architecture targets, not implemented or qualified
Splicore protocol support.**

| Protocol / capability | Planned engine |
| --- | --- |
| Snell | Native |
| Hysteria2 | Native |
| TUIC | Native |
| VLESS / REALITY | Native |
| Mieru | Planned native integration |
| FinalMask / Sudoku | Future Xray compatibility engine |

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
Last reviewed: 2026-10-01
Owner: Project maintainers
Responsibility: Project identity, development status and documentation entry point.
Lifecycle: Update with project status and navigation; keep detailed specifications in docs.
-->
