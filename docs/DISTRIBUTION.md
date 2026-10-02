# Distribution and Future NoBrand Contract

- Documentation status: Canonical
- Audience: Distribution, CI and future NoBrand integration maintainers
- Last reviewed: 2026-10-02
- Owner: Distribution maintainers
- Responsibility: Artifact identity, deterministic build and bounded integration contract.
- Lifecycle: Update with package/metadata formats and qualification policy.

## Filesystem contract

| Purpose | Layout 1 |
| --- | --- |
| Program | /usr/local/bin/splicore |
| Bootstrap | /etc/splicore/splicore.yaml |
| Install receipt / ownership | /etc/splicore/install.json and .owned |
| Domain state / key | /var/lib/splicore/state.db and master.key |
| Transient control/engine files | /run/splicore/ |
| Optional pinned engine | /var/lib/splicore/engines/xray-artifact/ |
| Root-only upgrade backups | /var/lib/splicore-upgrades/ |
| Main unit | /etc/systemd/system/splicore.service |
| Logs | journald |

## Package and metadata

The [build entry](../scripts/splicore-package.py) emits
`splicore-0.0.0-dev-linux-{amd64,arm64}.tar.gz` and a Windows build. Linux packages
contain binary, unit, minimal bootstrap, local installer, manifest, checksums,
license/NOTICE, actual linked-module license files and operation documents.
An accompanying source tarball records every checkout source hash and build
provenance. Its SHA256 is in update metadata; pinned dependency source versions
remain in go.mod/go.sum and the recorded local module cache.
Only regular files are packaged. The installer rejects links, devices, unsafe
names, duplicate members, extra/missing members and hash/size/mode mismatches.

`manifest.json` schema 1 records product development version, full Git commit,
source dirty flag and source byte digest, fixed UTC build time, Go toolchain,
GOOS/GOARCH, exact tags, config/DB/protocol/API schema identities, sing-box baseline,
optional pinned Xray references and per-file SHA256/size/mode. `SHA256SUMS` covers
all package files plus the manifest. The archive SHA256 lives in `update.json`
outside the archive, avoiding a self-referential checksum.

Same source bytes, toolchain, platform, version and epoch yield the same binary
and sorted tar/gzip bytes. Builds use CGO=0, trimpath, explicit tags, no VCS
embedding and no generated source files. Toolchain/version/epoch are intentionally
part of identity. Linux amd64 runtime qualification does not imply arm64 or
Windows service qualification. Xray arm64 is unqualified; Mieru stays embedded.
Dependencies stay pinned to go.mod/go.sum. Artifact signing is deferred; SHA256
does not replace a trusted metadata distribution channel.

## Future NoBrand interface

NoBrand consumes an explicitly qualified exact version, artifact URL, archive
SHA256, GOOS/GOARCH, schema boundary and install/update command. It downloads
that exact artifact separately, verifies trusted metadata, then invokes the local
installer. It uses canonical import/API routes and protected explicit client
exports; it never needs sing-box internal paths, Mieru internals or Xray JSON.

Future stable/beta/nightly channels must carry their own explicit qualification
and immutable artifact identities. Phase 9 publishes none of these: its channel
is `development`, qualification `experimental`, publication `local-only`.
Never follow GitHub Latest or substitute an engine automatically at startup.
There is no online updater or update server. Real NoBrand stays unchanged until
the unified client/server core is complete and integration is separately authorized.

## Distribution gate

Build all targets, inspect package/checksums/metadata, rebuild with the same
inputs and compare hashes, run blocking support-secret tests, then validate a
disposable actual systemd install/start/restart/upgrade/failed-upgrade/uninstall/
reinstall/purge with installed-service protocol smoke. Record parent/child crash
ownership, DB integrity, permissions and low TCP/UDP ports. Default race/checkptr
and existing protocol tests remain required. No Docker or production host
installation is part of this gate. See [operations](OPERATIONS.md) and the
[Phase 9 report](reports/PHASE_9_DISTRIBUTION_SERVICE_FOUNDATION_REPORT.md)
for observed results and exact remaining qualifications.

The manual [distribution workflow](../.github/workflows/splicore-distribution.yml)
runs on a dedicated disposable Linux runner with an already provisioned Go/module
cache and pinned client fixture directory. It does not upload or publish artifacts.
The same [gate driver](../scripts/splicore-distribution-gate.py) runs locally:

```sh
python3 scripts/splicore-migration-fixture.py --output /external/fault \
  --base-package /external/b/splicore-0.0.0-dev.1-linux-amd64.tar.gz
sudo python3 scripts/splicore-distribution-gate.py --output /external/new-lab \
  --package-a /external/a/splicore-0.0.0-dev-linux-amd64.tar.gz --sha256-a SHA_A \
  --package-b /external/b/splicore-0.0.0-dev.1-linux-amd64.tar.gz --sha256-b SHA_B \
  --fault-package /external/fault/fault-migration.tar.gz --sha256-fault SHA_FAULT \
  --clients /external/fixtures/clients --xray /external/fixtures/xray
```

The fixture builder edits a new external source copy, adds a schema5 step that
executes DDL then fails transactionally, and leaves production migrations intact.
The lab driver refuses unowned output paths, isolates the actual unit, confines
networking to loopback and stops only its owned transient lab unit. On WSL, keep
a command session open throughout qualification; systemd services alone do not
keep the distribution running. Evidence/rootfs remain external for review.
