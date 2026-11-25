# Splicore

[简体中文](README_CN.md)

Splicore is a standalone proxy core written in Go. Its Server Core and Client
Core share one native executable, with a local control API and encrypted
SQLite state. It runs without Xray, V2Ray, sing-box, or Mihomo as production
dependencies. The repository provides the core, CLI, and API for operators
and integrators.

## Latest stable release

Download the latest public release from GitHub. The v0.6.7 notes document the
Naive H2/H3 lifecycle repair, qualified fixture/evidence improvements, retained
historical root-cause boundaries, and the native amd64 qualification scope.
[Latest release](https://github.com/ike-sh/Splicore/releases/latest) · [v0.6.7 notes](docs/releases/v0.6.7.md)

## Downloads

Splicore uses the `AMD64_ONLY` support policy. Linux amd64 and Windows amd64
are the official CI and release targets. ARM64 packages in v0.6.4 are historical
`BUILD_ONLY` assets. Formal ARM64 support is paused.

| Platform | v0.6.7 archive | Release archive qualification |
| --- | --- | --- |
| Linux amd64 | `splicore-v0.6.7-linux-amd64.tar.gz` | Native tests, Linux Race and downloaded smoke |
| Windows amd64 | `splicore-v0.6.7-windows-amd64.zip` | Native tests, Windows Race and downloaded smoke |

Download `SHA256SUMS` from the same release as your archive and verify the hash
before extraction. With a single archive on Linux, use
`sha256sum --ignore-missing -c SHA256SUMS`. On Windows, compare
`Get-FileHash -Algorithm SHA256 .\splicore-v0.6.7-windows-amd64.zip` with the
matching line. `RELEASE_MANIFEST.json` records the source identity, platforms
and checksums. The corresponding offline source archive is
`splicore-v0.6.7-source.tar.gz`.
[Latest release](https://github.com/ike-sh/Splicore/releases/latest)

Each platform archive includes one executable, build metadata, examples and
licenses. The corresponding source archive includes vendored dependencies and
offline build instructions. [Historical v0.6.4 qualification](docs/releases/v0.6.4.md#qualification-scope)

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
- **Managed SOCKS5.** The loopback-default server requires username/password
  authentication. It supports TCP CONNECT and opt-in UDP ASSOCIATE to IPv4,
  IPv6 and domain targets. [Server and client examples](docs/CLI.md#managed-socks5-and-a-local-client)
- **Managed HTTP Proxy.** The `http/1.1/base` server requires Basic proxy
  authentication and supports CONNECT and absolute-form HTTP forwarding with
  managed accounts, per-binding statistics and SQLite recovery. [Server and client examples](docs/CLI.md#managed-http-proxy)
- **Transports.** Supported combinations include TLS and REALITY, WebSocket,
  HTTPUpgrade, gRPC, XHTTP, HTTP/H2/QUIC stream carriers, and modern mKCP.
- **Client networking.** Local SOCKS5, HTTP, Mixed, and optional TUN ingress
  feed managed routing, DNS, and provider policies.
- **Management.** The CLI and local API manage runtime resources and lifecycle.
  SQLite persists state with encrypted credentials.

The [Capability Matrix](docs/architecture/CAPABILITY_MATRIX.md) defines supported
profiles, dependencies, and limits. The direction audit records runtime
traffic, lifecycle, independent peer coverage and remaining gaps for each
profile. [Inbound and outbound audit](docs/architecture/INBOUND_OUTBOUND_MATRIX.md)

## Changes in v0.6.7

- **Naive H2/H3 lifecycle.** CloseWrite, concurrent carrier writes, Padding,
  full Close, asynchronous cleanup, connection-pool capacity, idle timers and
  Client shutdown now have explicit ownership and terminal-state contracts.
- **Qualification fixtures.** Naive H3 target join, Hysteria LivePool ingress,
  Snell v5 endpoint lifetime and Hysteria2 abnormal cleanup fixtures now own
  and join their resources deterministically. These are test repairs, not
  production protocol-performance claims.
- **Failure evidence.** Phase20 retains bounded dedicated lifecycle records on
  every native profile while general and failure-event output stays redacted.

[Release notes, compatibility and historical limits](docs/releases/v0.6.7.md)

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
- The historical Snell v5 IPv6 Race timeout, Windows protected DNS fallback,
  Mieru reconnect, Naive H3, Phase20 proxy-lifetime and Hysteria2 parallel UDP
  failures retain their unresolved historical conclusions. The historical
  Phase15 backup-crash failure still cannot exclude a production integrity
  defect. [Known limits](docs/releases/v0.6.7.md#known-limits-and-open-investigations)
- Linux TUN requires a kernel device and appropriate network privileges.
  Windows TUN requires an operator-supplied Wintun driver/DLL and privileges.
  Physical TUN/Wintun, Android/v2rayNG interoperability, and extended soak
  tests remain outside the release qualification. [Release limits](docs/releases/v0.6.7.md#known-limits-and-open-investigations)

## Documentation

- [Installation](docs/INSTALLATION.md) and [configuration](docs/CONFIGURATION.md)
- [CLI](docs/CLI.md) and [local API](docs/api/README.md)
- [Architecture](docs/ARCHITECTURE.md) and [Capability Matrix](docs/architecture/CAPABILITY_MATRIX.md)
- [Operations](docs/OPERATIONS.md), [contributor workflow](docs/DEVELOPMENT.md) and [project roadmap](docs/ROADMAP.md)
- [Release notes](docs/releases/v0.6.7.md) and [changelog](CHANGELOG.md)
- [Security policy](SECURITY.md) and [license](LICENSE)
