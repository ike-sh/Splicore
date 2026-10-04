# Experimental Linux Installation

- Documentation status: Canonical
- Audience: Linux operators and distribution reviewers
- Last reviewed: 2026-10-02
- Owner: Distribution maintainers
- Responsibility: Local installation and first start of the Phase 9 candidate.
- Lifecycle: Update with layout, package or service changes.

## Qualification

This is an experimental local development package, with no public release or
stable channel. See [distribution contract](DISTRIBUTION.md) for artifact identity
and actual platform qualification. Use an isolated machine for evaluation.
The installer requires Linux, running systemd, GNU tar/coreutils, useradd and root.
Root installs files; the long-running process uses the dedicated `splicore` user.

## Build and inspect

From a source checkout with its pinned Go dependencies already available:

```sh
python3 scripts/splicore-package.py --output /absolute/external/build \
  --epoch 1790966400 --version 0.0.0-dev
```

The output includes Linux amd64/arm64 tarballs, a Windows build and `update.json`.
Use the exact archive SHA256 from independently trusted metadata. A checksum
proves integrity relative to that metadata, not publisher authenticity.
Extract and inspect `manifest.json`, `SHA256SUMS`, licenses and this documentation.
Never execute an installer or binary from an untrusted package.

```sh
sudo sh scripts/install.sh --artifact /absolute/path/splicore-0.0.0-dev-linux-amd64.tar.gz \
  --sha256 EXACT_64_CHARACTER_SHA256 --start
sudo systemctl status splicore.service
sudo /usr/local/bin/splicore doctor --config /etc/splicore/splicore.yaml
```

Omitting `--start` enables the unit without starting it. Installation does not
download anything or change firewall rules. Bootstrap is preserved during updates.

## First start and authority

The minimal [bootstrap](../distribution/splicore.yaml) contains process paths
only. SQLite remains the sole account/inbound/credential authority. No sample
proxy account or listener is created. The first start creates a 0600 master key
only when both the key and database are absent, then applies existing migrations.
An existing database without its original key fails rather than rekeying it.

Layout uses `/var/lib/splicore/state.db`, preserving the existing database name.
State and runtime directories are 0700; config is root:splicore 0640; key and
SQLite files are service-owned 0600. Back up the key together with SQLite.

## Single core installation

Only the Splicore binary is installed. Mieru is embedded. No external runtime,
artifact pin, download or runtime directory is required. FinalMask/Sudoku are
out of scope; future NoBrand can deploy an independent Xray service.
For experimental upgrade preflight see [UPGRADE](UPGRADE.md).

## Phase 13 host integration

Packages include with_gvisor and optional splicore-tun.conf. Standard service keeps CAP_NET_BIND_SERVICE; explicitly install the shipped drop-in as /etc/systemd/system/splicore.service.d/20-tun.conf, then daemon-reload/restart before enabling TUN. It adds NET_ADMIN to the same dedicated-user service and retains all hardening. No driver is supplied/downloaded. See [Linux](PLATFORM_LINUX.md) and [Windows](PLATFORM_WINDOWS.md).
