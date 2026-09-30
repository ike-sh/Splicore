# Phase 0 validation evidence

- Documentation status: Historical
- Audience: Maintainers and validation reviewers
- Last reviewed: 2026-10-01
- Owner: Validation maintainers
- Responsibility: Interpretation and provenance of frozen Phase 0 generated captures.
- Lifecycle: Frozen snapshot; only typo, broken-link or factual corrections.

Captured on 2026-10-01 (Asia/Shanghai), against source SHA
`1ac1a339cb1223e9c70eae14c44411c75033c02d`.

Nonempty `*.log.gz` files preserve complete raw command transcripts (including
their original whitespace/line endings), compressed solely as architecture evidence.
They are not executable artifacts. `SHA256SUMS.json` records compressed-file
digests. Build binaries and validation tools were kept outside the repository
under `C:\Users\admin\AppData\Local\Temp\splicore-phase0-20261001`.
No binary was published or included in the worktree.

Factual clarification from the documentation audit: six files have zero bytes:
`baseline-format.log.gz`, `post-doc-build-ci.log.gz`,
`post-doc-build-minimal.log.gz`, `post-doc-build-windows.log.gz`,
`post-doc-format.log.gz`, and `post-doc-linux-build.log.gz`. These are empty-output
captures, not valid gzip streams or empty specification placeholders. Preserve
their original bytes/names and interpret them alongside `results.jsonl` or the
Linux exit ledgers. Empty output alone is not a success result. The checksum
manifest covers these zero-byte artifacts as well as the 15 valid gzip captures.

All files in this directory are frozen Phase 0 evidence. This README is Historical;
the machine captures are Generated and owned by Validation maintainers, with an
immutable capture lifecycle. Fresh validation belongs in a separate completed
report, not an overwrite of these files.

* `baseline-*`: original build/test/lint/format invocations before product changes.
* `post-doc-*`: repeated corresponding gates after architecture documents.
* `baseline-linux-test.log.gz`: initial constrained container failure.
* `baseline-linux-qualified-env-test.log.gz`: complete Linux root CI retry with
  required container test tooling/permissions; no test-name exclusions.
* `*-without-integration.log.gz`: Windows supplementary tests excluding
  `^TestIntegration`; do not count these as full Windows CI success.
* `results.jsonl`: Windows command arguments/exit codes and observed lint version.
* Linux results files, `linux-image.txt`, `linux-go-env.json`, `linux-go-version.txt`:
  image/toolchain/exit evidence. Linux test/build command strings are below.
* `git-verification.json`, `document-check.log`, `diff-stat.txt`, `diff-check.txt`:
  source/branch/remote/allowed-file scope and final review evidence.

Windows official command equivalents are in [baseline ledger](../UPSTREAM_BASELINE.md).
golangci-lint v2.14.0 Windows amd64 archive was downloaded from its official GitHub
release into temporary storage, verified against the published SHA256 checksums,
and used with the repository's .golangci.yml. No fmt rewrite or dependency install
occurred in the repository.

Linux runs used `golang:1.26.6` image digest recorded in linux-image.txt. Source
was mounted read-only at `/src`, output at `/evidence`, dedicated module/build
cache volumes `splicore-phase0-go-mod` and `splicore-phase0-go-build`. Complete
successful tests used root, `--cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN
--security-opt seccomp=unconfined`; no host-network or Docker-socket mount.
`apt-get update && apt-get install -y --no-install-recommends tcpdump` installed
only inside disposable containers. The containers were removed automatically.

```sh
cd /src
export CGO_ENABLED=0 GOTOOLCHAIN=local
TAGS=$(cat release/DEFAULT_BUILD_TAGS_OTHERS)
LDFLAGS=$(cat release/LDFLAGS)
go build -trimpath -tags "$TAGS" -ldflags "$LDFLAGS" -o /tmp/baseline ./cmd/sing-box
go test -count=1 -v -tags "$TAGS" -ldflags "$LDFLAGS" ./...
```

Initial container lacked tcpdump and namespace permissions; those failures were
captured, not overwritten. Successful Linux coverage is root module with default
CI tags on amd64/CGO=0, not the separate `test` module, every OS/arch, or every
optional feature. Docker volumes are cache only; no Splicore domain DB exists yet.

OpenAPI skeleton uses JSON syntax (valid YAML) and is checked with a pinned
OpenAPI 3.1 validator in a disposable Python container. Document consistency
checks cover mandatory files, links, ADR sections, API references/paths and allowed
file scope. They do not claim to test a nonexistent runtime implementation.

Real index remains unstaged. Since normal `git diff` omits untracked documents,
final document-inclusive stat/whitespace check uses a copied temporary Git index
with intent-to-add entries. The original index hash is checked unchanged; no
commit/staging of document content is performed. Read these results alongside
[the complete report](../../PHASE_0_ARCHITECTURE_REPORT.md).
