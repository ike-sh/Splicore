# Splicore

Splicore is an independent proxy Core for Server Core and Client Core use.
It combines proxy protocols, local traffic entry, routing, DNS, policy, TUN
and a persistent control plane in a single Core implementation.

## Capabilities

Supported protocols include Shadowsocks/SS2022, Snell, Hysteria2, TUIC, VLESS,
Mieru, Trojan, VMess, AnyTLS, [TrustTunnel](docs/protocol/TRUSTTUNNEL.md) and
[NaiveProxy](docs/architecture/NAIVE.md), with local
SOCKS5, HTTP, Mixed and TUN traffic entry.
Shared stream transports include raw TCP, WebSocket, HTTPUpgrade, gRPC,
[XHTTP](docs/architecture/XHTTP.md) and [modern mKCP](docs/architecture/MKCP.md).
Hysteria2 uses the native [specialized Hysteria transport](docs/architecture/HYSTERIA_TRANSPORT.md),
including Salamander, Gecko obfuscation (experimental) and UDP port hopping.
Native REALITY protected destinations can use a
[local tunnel guard](docs/protocol/LOCAL_TUNNEL_GUARD.md) with bounded TLS SNI
inspection, route-only matching and fail-closed routing to a fixed destination.

See the [capability matrix](docs/architecture/CAPABILITY_MATRIX.md) and
[Core scope](docs/architecture/CORE_SCOPE.md) for capability details and boundaries.

## Build

Go 1.26.3 or newer is required.

```sh
make build
# build/linux-amd64/splicore (on Linux amd64)
```

Native Windows builds use PowerShell and Go; WSL is not required:

```powershell
./scripts/splicore-build.ps1
./build/windows-amd64/splicore.exe help
```

Both builders use CGO_ENABLED=0 and embed source commit, time and feature tags.
`make build-matrix` evaluates Windows/Linux amd64/arm64. Cross-compilation does
not establish native arm64 runtime support. Build outputs remain development
builds; this change does not publish a release.

## Run the core

One executable owns the daemon, local API, protocol listeners and management CLI.
Provision a new vault key as the Core account, check the bootstrap, then run:

```sh
splicore help
splicore version --json
splicore key init --file /var/lib/splicore/master.key
splicore check --config distribution/splicore.yaml
splicore run --config distribution/splicore.yaml
# From another terminal:
splicore status --config distribution/splicore.yaml
splicore stop --config distribution/splicore.yaml
```

On Windows use [the Windows bootstrap](distribution/splicore-windows.yaml),
`splicore.exe`, and its configured `D:/Splicore/keys/master.key` path. New state
and key directories receive a private owner/SYSTEM DACL. Existing broad or
foreign-owned state is rejected. Linux requires private mode-0700 directories
and mode-0600 state/key files. `run` prints `Splicore ready` on stderr after
initialization; Ctrl+C/SIGTERM or `stop` performs orderly shutdown.

Bootstrap selects process paths. Proxy resources are managed through the local
API/CLI and persisted in SQLite; no proxy listener is invented for an empty
database. See [the loopback VLESS example and run sequence](docs/CLI.md).
Windows foreground control uses a local named pipe; Linux uses a Unix socket.
No external proxy core is installed or launched. Optional TUN still requires OS
facilities and privileges, including an external Wintun DLL/driver on Windows.

Native amd64 process tests cover VLESS loopback transfer, authentication refusal,
shutdown and restart on Windows/Linux. This is a bounded runtime qualification;
it does not qualify every protocol, TUN, Windows service installation or arm64.
The frozen v0.3.0 and main histories differ: frozen WireGuard, ShadowQUIC, VLESS
Encryption and extra transports are not restored by this runtime change.

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
