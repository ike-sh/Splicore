# Splicore

Splicore is an independent **proxy core** for Server Core and Client Core use.
One `splicore` binary provides proxy protocols, local traffic entry, routing,
DNS, policy and a persistent control plane. It is derived in part from sing-box;
it does not require an external Xray, sing-box or Mihomo process.

Protocols include Shadowsocks/SS2022, Snell, Hysteria2, TUIC, VLESS, Mieru,
Trojan and VMess, with SOCKS5/HTTP proxy nodes and SOCKS5/HTTP/Mixed/TUN local
entry. Shared stream transports include raw TCP, WebSocket, HTTPUpgrade and
gRPC, with TLS and the supported raw VLESS REALITY profile.
See the [capability matrix](docs/architecture/CAPABILITY_MATRIX.md) for limits.

## Build

Use Go 1.26.3 or newer:

```sh
go build -trimpath -tags with_quic,with_utls,with_gvisor ./cmd/splicore
```

`with_utls` enables REALITY, and `with_gvisor` enables the native TUN stack.
The recommended profile includes `with_quic`; current QUIC adapters are included
in both default and tagged builds. Build outputs are `splicore`
on Linux and `splicore.exe` on Windows.

Start with [installation](docs/INSTALLATION.md), [configuration](docs/CONFIGURATION.md),
[CLI usage](docs/CLI.md), [operations](docs/OPERATIONS.md) and the
[documentation index](docs/README.md). Integrators can use the
[local API](docs/api/README.md) and [architecture overview](docs/ARCHITECTURE.md).

## Scope and platform limits

Splicore includes native Core networking and Linux service assets. GUI, tray,
desktop system proxy/PAC management, mobile/desktop application shells and
container distribution are outside its [Core scope](docs/architecture/CORE_SCOPE.md).
Vision is unsupported; FinalMask and Sudoku are outside runtime scope.

Platform support is experimental and partially qualified. Linux arm64 is
**build-only**. Native Linux auto-route and real Windows host networking have
unqualified areas. Windows production local control/service integration is
unavailable; a successful Windows build is not a host networking qualification.

## License

The preserved [LICENSE](LICENSE), [NOTICE](NOTICE.md),
[third-party notices](THIRD_PARTY_NOTICES.md) and
[license boundaries](docs/architecture/LICENSE_BOUNDARIES.md) describe attribution
and licensing. Existing source copyright notices remain intact.
