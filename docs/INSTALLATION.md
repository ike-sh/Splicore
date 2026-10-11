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
timestamp metadata and builds the same `with_quic,with_utls,with_gvisor` profile.

## Run the Linux Core

[distribution/splicore.yaml](../distribution/splicore.yaml) is a minimal bootstrap
for process paths and the protected local API socket. Prepare its state directory
for the account that will run the Core, and protect the configuration and state.
State, key and API socket parent directories must be owned by that account
and have mode 0700, without symlinks. For a fresh installation, provision the
configured key as that account before running the Core. `key init` creates a
new private 32-byte key and refuses to overwrite an existing file.

```sh
./splicore validate distribution/splicore.yaml
./splicore key init --file /var/lib/splicore/master.key
./splicore run --config distribution/splicore.yaml
```

Startup loads the configured key and applies embedded SQLite migrations.
A missing or unsafe configured key is rejected. Never create a replacement key
for an existing database; preserve the database and its matching original key. The bootstrap creates no sample users or proxy
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
