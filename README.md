# Splicore

Documentation status: Current
Audience: Maintainers and operators
Last reviewed: 2026-10-09
Owner: Splicore maintainer
Responsibility: Independent proxy Core identity and entry points
Lifecycle: Experimental; Phase 21 cleanup awaiting independent review

Splicore is an independent **proxy core** usable as Server Core and Client Core,
derived in part from sing-box v1.14.1. It runs as one `splicore` binary.

Protocols include SS/SS2022, Snell, Hysteria2, TUIC, VLESS, Mieru, Trojan and VMess;
SOCKS5/HTTP proxy nodes and SOCKS5/HTTP/Mixed/TUN traffic entry use shared routing,
DNS, policy and protected networking. Shared stream transports include Raw,
WebSocket, HTTPUpgrade, gRPC, TLS and supported REALITY integration.
SQLite, encrypted credentials, API/CLI transactions, providers and Core service
deployment belong to its control plane. The authoritative boundary is
[Core scope](docs/architecture/CORE_SCOPE.md).

Vision is deferred/unsupported. FinalMask/Sudoku are outside Splicore runtime scope.
No external core child process is required. Splicore has no desktop client, GUI,
tray, system proxy controller or PAC ownership.

## Build

```sh
go build -tags with_quic,with_utls,with_gvisor ./cmd/splicore
go test ./...
go test -race -tags with_quic,with_utls,with_gvisor ./internal/splicore/...
```

See [installation](docs/INSTALLATION.md), [operations](docs/OPERATIONS.md),
[architecture](docs/ARCHITECTURE.md), [capabilities](docs/architecture/CAPABILITY_MATRIX.md)
and [documentation](docs/README.md).

Historical platform qualification remains PARTIALLY PASSED. Phase 21 is NOT
PLATFORM QUALIFIED; native Ubuntu auto-route and real Windows host networking
remain uncertified, Windows race is not executed, Linux arm64 is BUILD ONLY.
Historical frozen reports remain preserved. Deep Core Purge requires targeted
independent review before any Freeze.

## License

See [LICENSE](LICENSE), [NOTICE](NOTICE.md), [third-party notices](THIRD_PARTY_NOTICES.md)
and [license boundaries](docs/architecture/LICENSE_BOUNDARIES.md).
Inherited source copyright and derivative provenance remain preserved.
