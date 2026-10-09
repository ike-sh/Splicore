# Installation

## Build from source

Go 1.26.3 or newer is required. From the source checkout:

```sh
go build -trimpath -tags with_quic,with_utls,with_gvisor ./cmd/splicore
./splicore version
```

For cross compilation, set `GOOS` and `GOARCH` to `linux/amd64`,
`windows/amd64` or `linux/arm64`; set `CGO_ENABLED=0` and choose an output with
`-o`. Windows uses `splicore.exe`. The optional
[PowerShell build helper](../scripts/splicore-build.ps1) injects version and
timestamp metadata and uses the default feature set, without REALITY or native
TUN; use the command above for the full feature set.

## Run the Linux Core

[distribution/splicore.yaml](../distribution/splicore.yaml) is a minimal bootstrap
for process paths and the protected local API socket. Prepare its state directory
for the account that will run the Core, and protect the configuration and state.
The API socket parent must exist with appropriate ownership and permissions.

```sh
./splicore validate distribution/splicore.yaml
./splicore run --config distribution/splicore.yaml
```

First startup creates a private master key only when both the key and database
are absent, and applies embedded SQLite migrations. An existing database without
its original key is rejected. The bootstrap creates no sample users or proxy
listeners. Manage resources through the [CLI](CLI.md) or [API](api/README.md).

## Native Linux packages

For a separately supplied, trusted native package, the retained
[installer](../scripts/install.sh) verifies a pinned local artifact and invokes
the Core's package verifier/installer. It requires Linux, systemd, GNU
tar/coreutils, useradd and root. It does not download a package or change firewall
rules. See [distribution](DISTRIBUTION.md) for the package contract.

```sh
sudo sh scripts/install.sh --artifact /absolute/path/splicore-linux-amd64.tar.gz \
  --sha256 EXACT_64_CHARACTER_SHA256 --start
```

Omit `--start` to enable the unit without starting it. The long-running service
uses the dedicated `splicore` account. The source checkout does not itself provide
a ready-made binary package. [Operations](OPERATIONS.md) describes service assets
and platform limits; Linux arm64 remains build-only.
