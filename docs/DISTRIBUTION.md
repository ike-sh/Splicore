# Native distribution contract

Splicore uses a single Core binary. Linux native distribution can include the
systemd unit, optional TUN drop-in, schema-1 bootstrap, pinned local installer,
manifest/checksums, public operations pages and required license/notice texts.
The retained [installer](../scripts/install.sh) consumes a separately assembled
package and delegates verification and installation to the Core.

The source tree supplies native assets; it does not promise an available binary
package, update endpoint or Windows service wrapper. Windows amd64 and Linux arm64
source builds are supported as build targets; Linux arm64 remains build-only.
Container images and mobile/desktop application distribution are outside Core.

## Version metadata

An ordinary source build reports `devel`. Product version, commit, dirty flag,
timestamp, source digest and build tags can be injected with Go `-ldflags` through
variables in `internal/splicore/version`. Building does not rewrite source.
The configuration schema, database schema, protocol ABI and API version are
independent compatibility identities; changing a product version does not change
those schemas. Do not identify a binary only by an upstream sing-box version.

Native package verification checks its manifest, file hashes, platform, schemas
and build identity. A SHA256 checksum is useful only relative to trusted metadata;
the installer makes no publisher-authenticity claim from a checksum alone.
See [installation](INSTALLATION.md), [upgrades](UPGRADE.md) and
[licensing](architecture/LICENSE_BOUNDARIES.md).
