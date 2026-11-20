# Splicore

[简体中文](README_CN.md)

Splicore is a standalone proxy core written in Go. Its Server Core and Client
Core share one native executable, with a local control API and encrypted
SQLite state. It runs without Xray, V2Ray, sing-box, or Mihomo as production
dependencies. The repository provides the core, CLI, and API for operators
and integrators.

## Latest stable release

[Splicore v0.6.4](https://github.com/ike-sh/Splicore/releases/tag/v0.6.4) is the
current stable release. The `v0.6.3` tag remains an unpublished candidate.

## Downloads

Splicore uses the `AMD64_ONLY` support policy. Linux amd64 and Windows amd64
are the official CI and release targets. ARM64 packages in v0.6.4 are historical
`BUILD_ONLY` assets. Formal ARM64 support is paused.

| Platform | v0.6.4 archive | Release archive qualification |
| --- | --- | --- |
| Linux amd64 | [tar.gz](https://github.com/ike-sh/Splicore/releases/download/v0.6.4/splicore-v0.6.4-linux-amd64.tar.gz) | Native tests and Linux Race |
| Linux ARM64 | [tar.gz](https://github.com/ike-sh/Splicore/releases/download/v0.6.4/splicore-v0.6.4-linux-arm64.tar.gz) | Historical `BUILD_ONLY` |
| Windows amd64 | [zip](https://github.com/ike-sh/Splicore/releases/download/v0.6.4/splicore-v0.6.4-windows-amd64.zip) | Native tests |
| Windows ARM64 | [zip](https://github.com/ike-sh/Splicore/releases/download/v0.6.4/splicore-v0.6.4-windows-arm64.zip) | Historical `BUILD_ONLY` |

[SHA256SUMS](https://github.com/ike-sh/Splicore/releases/download/v0.6.4/SHA256SUMS) ·
[RELEASE_MANIFEST.json](https://github.com/ike-sh/Splicore/releases/download/v0.6.4/RELEASE_MANIFEST.json) ·
[Corresponding source archive](https://github.com/ike-sh/Splicore/releases/download/v0.6.4/splicore-v0.6.4-source.tar.gz)

Verify the archive SHA256 before extraction. Each platform archive includes one
executable, build metadata, examples, and licenses. The source archive includes
vendored dependencies and offline build instructions. For the recorded v0.6.4
results, see the [historical qualification scope](docs/releases/v0.6.4.md#qualification-scope)

## Quick start

On Linux, run these commands from the extracted archive. Use a local filesystem
that enforces POSIX permissions and a directory owned by the account running
the core. `run` stays in the foreground.

```sh
./splicore version
./splicore help

umask 077
data_dir="$HOME/.local/state/splicore"
install -d -m 700 "$data_dir"
cat > "$data_dir/bootstrap.yaml" <<EOF
schema: 1
state_directory: $data_dir/state
key_file: $data_dir/keys/master.key
api:
  unix_socket: $data_dir/ctl/core.sock
EOF

./splicore key init --file "$data_dir/keys/master.key"
./splicore check --config "$data_dir/bootstrap.yaml"
./splicore run --config "$data_dir/bootstrap.yaml"
```

From a second terminal in the extracted directory, check status or request a
graceful stop.

```sh
./splicore status --config "$HOME/.local/state/splicore/bootstrap.yaml"
./splicore stop --config "$HOME/.local/state/splicore/bootstrap.yaml"
```

On Windows, open PowerShell in the extracted directory and use the bootstrap
setup in the [Windows run guide](docs/releases/RUNNING_windows.md).

```powershell
.\splicore.exe version
.\splicore.exe help
.\splicore.exe key init --file 'D:/Splicore/keys/master.key'
.\splicore.exe check --config 'D:/Splicore/bootstrap.yaml'
.\splicore.exe run --config 'D:/Splicore/bootstrap.yaml'
```

Query or stop it from a second PowerShell window.

```powershell
.\splicore.exe status --config 'D:/Splicore/bootstrap.yaml'
.\splicore.exe stop --config 'D:/Splicore/bootstrap.yaml'
```

The bootstrap YAML selects process paths. Manage protocol resources through
the CLI or the local control API, which uses a Unix socket on Linux and a
user-restricted named pipe on Windows. An empty database starts without proxy
listeners. The Linux guide walks through applying the bundled loopback VLESS
example. Keep key and state directories private, and back up the SQLite state
with its matching original master key. [Linux run guide](docs/releases/RUNNING_linux.md)

## Capabilities

- **Proxy protocols and endpoints.** VLESS, VMess, Shadowsocks and SS2022,
  Trojan, Hysteria2, TUIC, Mieru, Snell, AnyTLS, TrustTunnel, NaiveProxy, and
  standard userspace WireGuard are available within their documented profiles.
- **Transports.** Supported combinations include TLS and REALITY, WebSocket,
  HTTPUpgrade, gRPC, XHTTP, HTTP/H2/QUIC stream carriers, and modern mKCP.
- **Client networking.** Local SOCKS5, HTTP, Mixed, and optional TUN ingress
  feed managed routing, DNS, and provider policies.
- **Management.** The CLI and local API manage runtime resources and lifecycle.
  SQLite persists state with encrypted credentials.

The [Capability Matrix](docs/architecture/CAPABILITY_MATRIX.md) defines supported
profiles, dependencies, and limits. Independent peer and platform coverage is
recorded per release. [v0.6.4 release notes](docs/releases/v0.6.4.md)

## Changes in v0.6.4

- **TUIC.** A valid authentication command stream can finish before the server
  cancels its reads, allowing authenticated parallel CONNECT to proceed.
- **Mieru.** Full accept queues no longer stall UDP receive for established
  sessions. The patch also fixes read-deadline wakeup order and preserves
  socket access during session cleanup. The release pins the internal Mieru
  fork at `f237626f5345d83ba35d8e24c1721dc8e1c928d3`.
- **Test fixtures.** Gecko reassembly uses a deterministic test clock. The
  WireGuard Xray fixture uses OS-assigned ports and verifies child socket ownership.
- **Engineering tools.** Native CI includes runtime qualification and bounded
  persistence checks. Network performance baselines run on demand.

See the [release notes](docs/releases/v0.6.4.md) for changes and evidence.

## Build from source

Use Go 1.26.3 or newer. On Linux, run `make build`. On Windows, run
`.\scripts\splicore-build.ps1` in PowerShell. The standard build profile uses
`CGO_ENABLED=0` and `with_quic,with_utls,with_gvisor`. Cross-compilation
establishes build compatibility. Native execution and interoperability have
their own gates. [Build and installation guide](docs/INSTALLATION.md)

## Known limitations

- ShadowQUIC and Linux kernel WireGuard remain `ISOLATED_NOT_QUALIFIED`.
  AmneziaWG/Phase37 is `RETIRED`. Standard userspace WireGuard is available.
- WAL/P1-B remains outside production qualification. Physical power loss and
  OS crash recovery are `NOT_EXECUTED`.
- The historical Snell v5 concurrent QUIC IPv6 read timeout and TrustTunnel
  HTTP/2 Race `tcp_connect` failure remain `ROOT_CAUSE_UNRESOLVED`.
- Linux TUN requires a kernel device and appropriate network privileges.
  Windows TUN requires an operator-supplied Wintun driver/DLL and privileges.
  Physical TUN/Wintun, Android/v2rayNG interoperability, and extended soak
  tests remain outside the release qualification. [Release limits](docs/releases/v0.6.4.md#known-limits)

## Documentation

- [Installation](docs/INSTALLATION.md) and [configuration](docs/CONFIGURATION.md)
- [CLI](docs/CLI.md) and [local API](docs/api/README.md)
- [Architecture](docs/ARCHITECTURE.md) and [Capability Matrix](docs/architecture/CAPABILITY_MATRIX.md)
- [Operations](docs/OPERATIONS.md), [contributor workflow](docs/DEVELOPMENT.md) and [project roadmap](docs/ROADMAP.md)
- [Release notes](docs/releases/v0.6.4.md) and [changelog](CHANGELOG.md)
- [Security policy](SECURITY.md) and [license](LICENSE)
