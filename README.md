# Splicore

Splicore is an independent proxy Core for Server Core and Client Core use.
It combines proxy protocols, local traffic entry, routing, DNS, policy, TUN
and a persistent control plane in a single Core implementation.

## Capabilities

Supported protocols include Shadowsocks/SS2022, Snell, Hysteria2, TUIC, VLESS,
Mieru, Trojan, VMess, AnyTLS and [NaiveProxy](docs/architecture/NAIVE.md), with local
SOCKS5, HTTP, Mixed and TUN traffic entry.
Shared stream transports include raw TCP, WebSocket, HTTPUpgrade, gRPC,
[XHTTP](docs/architecture/XHTTP.md) and [modern mKCP](docs/architecture/MKCP.md).
Hysteria2 uses the native [specialized Hysteria transport](docs/architecture/HYSTERIA_TRANSPORT.md).

See the [capability matrix](docs/architecture/CAPABILITY_MATRIX.md) and
[Core scope](docs/architecture/CORE_SCOPE.md) for capability details and boundaries.

## Build

Go 1.26.3 or newer is required.

```sh
go build -trimpath -tags with_quic,with_utls,with_gvisor ./cmd/splicore
```

## Documentation

- [Installation and bootstrap configuration](docs/INSTALLATION.md)
- [CLI](docs/CLI.md)
- [Operations](docs/OPERATIONS.md)
- [Local API](docs/api/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Documentation index](docs/README.md)

## Releases

Official downloads and version-specific release notes are published through
[GitHub Releases](https://github.com/ike-sh/Splicore/releases).
Download the release archives and accompanying checksums to verify their integrity.

## Scope

Splicore focuses on proxy Core functionality and native Core networking.
Client Core is a reusable proxy runtime; application UI and application shells
are outside the Core repository.

## License

See [LICENSE](LICENSE), [NOTICE](NOTICE.md),
[third-party notices](THIRD_PARTY_NOTICES.md) and
[license boundaries](docs/architecture/LICENSE_BOUNDARIES.md).
