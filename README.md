# Splicore

Documentation status: Current architecture correction
Audience: Maintainers and operators
Last reviewed: 2026-10-04
Owner: Splicore maintainer
Responsibility: Independent native Server + Client Core boundary
Lifecycle: Experimental; Phase 14 local freeze

Splicore is an independent **Server + Client Core**, derived from sing-box v1.14.1.
It is experimental, locally qualified, and distributed as one `splicore` binary.

| Protocol | Server | Client |
| --- | --- | --- |
| Snell v5/v6 | Experimental | Experimental |
| Hysteria2 | Experimental | Experimental |
| TUIC v5 | Experimental | Experimental |
| VLESS plain/TLS/REALITY, flow-none | Experimental | Experimental |
| Mieru | Experimental, embedded v3.38.0 | Experimental, embedded v3.38.0 |

Client ingress includes SOCKS TCP/UDP, HTTP and TUN. Shared control includes
SQLite, encrypted credentials, API/CLI transactions, routing, DNS, policy groups,
imports and proxy/RuleSet providers. The [Phase 14 local freeze](docs/reports/PHASE_14_FREEZE_REPORT.md)
records the accepted implementation, architecture correction and qualification limits.

Vision is Deferred/Unsupported. FinalMask and Sudoku are **out of scope for
Splicore**. Xray is absent from its runtime and distribution. Future
NoBrand-OneClick can deploy an independent Xray service for specialized modes;
Splicore neither installs nor manages it. [Architecture decision](docs/adr/0035-xray-runtime-removed-from-core.md).

## Build

```sh
go build -tags with_quic,with_utls,with_gvisor ./cmd/splicore
go test -race -tags with_quic,with_utls,with_gvisor ./internal/splicore/...
```

No external runtime is required. See [installation](docs/INSTALLATION.md),
[operations](docs/OPERATIONS.md), [architecture](docs/ARCHITECTURE.md),
[capabilities](docs/architecture/CAPABILITY_MATRIX.md), and [documentation](docs/README.md).

Linux race/checkptr and owned disposable WSL namespace/service tests are local
evidence. Native Ubuntu auto-route and real Windows host networking remain
uncertified; Windows race is not executed, and Linux arm64 is build-only.
Historical frozen reports remain preserved. The
[correction report](docs/reports/ARCHITECTURE_CORRECTION_XRAY_BOUNDARY_REPORT.md)
records the current superseding architecture and exact regression results.

## License

See [LICENSE](LICENSE), [NOTICE](NOTICE.md), and
[license boundaries](docs/architecture/LICENSE_BOUNDARIES.md). Inherited runtime
source and official embedded Mieru source remain unchanged.
