# Splicore

Splicore is an independent proxy Core for Server Core and Client Core use.
It combines proxy protocols, local traffic entry, routing, DNS, policy, TUN
and a persistent control plane in a single Core implementation.

## Capabilities

Implemented experimental protocol modules include Shadowsocks/SS2022, Snell, Hysteria2, TUIC, VLESS,
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

Go 1.26.3 or newer is required. Release qualification uses Go 1.26.3.

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
not establish native arm64 runtime support. Local build outputs default to development builds. Official archives embed the
version from `distribution/RELEASE_VERSION` and their exact main release commit.

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
v0.5.0 adds [native VLESS Encryption](docs/protocol/VLESS_ENCRYPTION.md) to the
v0.4.0 baseline, with hybrid ML-KEM-768/X25519, AES-GCM/ChaCha records and
independent official Xray v26.10.21 peer tests on both native platforms.
Android/v2rayNG real-device traffic is NOT EXECUTED. Frozen WireGuard, ShadowQUIC,
XHTTP H3 and generic carriers remain pending separate main-based restorations.

## Documentation

- [Installation and bootstrap configuration](docs/INSTALLATION.md)
- [CLI](docs/CLI.md)
- [Operations](docs/OPERATIONS.md)
- [Local API](docs/api/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Documentation index](docs/README.md)

## Download and qualification

[Official v0.5.0 downloads](https://github.com/ike-sh/Splicore/releases/tag/v0.5.0)
contain one executable per platform plus licenses, examples and RUNNING.md.
The project remains pre-1.0; a formal downloadable Release does not certify every
implemented experimental protocol.

| Platform | Build | Native runtime evidence |
| --- | --- | --- |
| Linux amd64 | CGO0 | Default/full tests and vet, selected-package Race, VLESS real process |
| Windows amd64 | CGO0 | Default/full tests and vet, VLESS real process; Race NOT EXECUTED |
| Linux arm64 | CGO0 cross-build | BUILD ONLY; no native tests |
| Windows arm64 | CGO0 cross-build | BUILD ONLY; no native tests |

Download the matching `splicore-v0.5.0-<os>-<arch>` archive and SHA256SUMS.
Linux: `sha256sum -c SHA256SUMS`. Windows: compare
`Get-FileHash -Algorithm SHA256 ./splicore-v0.5.0-windows-amd64.zip` with the
published line. After unpacking, use `./splicore help` or `./splicore.exe help`,
then follow [Linux](docs/releases/RUNNING_linux.md) or
[Windows](docs/releases/RUNNING_windows.md) instructions. Go/WSL and a separate
proxy core are not required to run the binary. No digital signature is claimed.
The source archive includes vendored dependencies and offline build instructions.

High-port foreground listeners need ordinary user permissions. Private state/key
paths are required. Logs go to stderr (Linux installed services use journald).
Optional TUN requires OS devices/drivers/privileges, including external Wintun on
Windows; drivers are not built into the binary. `check` is a bounded static
validation, and `stop` acknowledges a shutdown request rather than waiting for
process completion.

This pre-1.0 minor adds protocol capability to the v0.4.0 baseline. Do not
mix Frozen and current configurations/databases. See the
[release notes](docs/releases/v0.5.0.md) and [changelog](CHANGELOG.md): Windows
WireGuard Hotfix is NOT QUALIFIED; Phase37 and independent SQLite WAL/P1-B
candidates are excluded; WSL2 UDP, historical SOCKS, Mieru throughput and broad
protocol interoperability limits remain open. The local Windows symlink fixture
may be skipped for Win32 1314; hosted tests do not allow that skip. ARM64 builds
remain BUILD ONLY. The VLESS Encryption reference matrix does not certify
other clients or every implemented protocol. Historical v0.3.0 and v0.4.0
remain unchanged.

For security reporting and support boundaries, see [SECURITY.md](SECURITY.md).
中文说明见 [README_CN.md](README_CN.md).

## Scope

Splicore focuses on proxy Core functionality and native Core networking.
Client Core is a reusable proxy runtime; application UI and application shells
are outside the Core repository.

## License

See [LICENSE](LICENSE), [NOTICE](NOTICE.md),
[third-party notices](THIRD_PARTY_NOTICES.md) and
[license boundaries](docs/architecture/LICENSE_BOUNDARIES.md).
