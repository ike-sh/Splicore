# Native distribution contract

Splicore uses a single Core binary. Linux native distribution can include the
systemd unit, optional TUN drop-in, schema-1 bootstrap, pinned local installer,
manifest/checksums, public operations pages and required license/notice texts.
The retained [installer](../scripts/install.sh) consumes a separately assembled
package and delegates verification and installation to the Core.

The `AMD64_ONLY` release contract covers native Linux amd64 and Windows amd64.
The product builds use `CGO_ENABLED=0`. Each future release has five assets: two
platform archives, a corresponding source archive, `SHA256SUMS` and
`RELEASE_MANIFEST.json`. ARM64 formal support is paused. The seven v0.6.4 assets
remain historical, including the ARM64 `BUILD_ONLY` packages.
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
