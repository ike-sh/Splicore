# Release qualification and CI evidence

`Official release` runs on every PR to `main`, on pushes to `main` and
`codex/restore-*`, and on version Tag pushes. The same `build` matrix and
`scripts/release.py` commands run for each event. The existing `prepare`,
`build`, `assemble`, Core runtime, and Native platform qualification check
names remain available for GitHub rules. Review rulesets separately if a
repository requires the additional `download-test` checks on PRs.

| Target | Runner label | Release gate on PR, main and Tag |
| --- | --- | --- |
| Linux amd64 | `ubuntu-24.04` | Native release build, default/full build, vet and tests, full release Linux Race, and downloaded-product smoke |
| Windows amd64 | `windows-2025-vs2026` | Native release build, default/full build, vet and tests, and downloaded-product smoke |
| Linux ARM64 | `ubuntu-24.04` | Cross-build of the release core and default/full packages, `BUILD_ONLY` |
| Windows ARM64 | `ubuntu-24.04` | Cross-build of the release core and default/full packages, `BUILD_ONLY` |

The workflow uses the Go version in `go.mod`, a local toolchain, readonly module
resolution, Go telemetry off and `GOMAXPROCS=4`. Product, default and full
builds use `CGO_ENABLED=0`. Full builds use `with_quic,with_utls,with_gvisor`.
The default and full Go tests run `./...` with `-json -count=1 -timeout=1200s`.
Windows serializes packages with `-p=1`. Linux Race uses CGO with the full tags
and `./internal/splicore/... ./protocol/...`. The same 2,100-second per-command
limit applies to qualification commands. `qualification_policy.py` continues
to enforce the required test identities and the versioned skip rules. Linux
uses the owned loopback network namespace from `scripts/dev/isolated-linux.py`.
Xray, Snell on Linux amd64, and the wireguard-go fixture keep their pinned
sources. Their archive and executable digests are recorded where applicable.

`assemble` validates the complete candidate and corresponding source. On PR and
main, `download-test` verifies and executes the candidate archive. A Tag push
must point to the exact current `origin/main` commit and match the distribution
version. Its job verifies the public download of the newly published artifacts
with the same native smoke command. Production publication remains Tag-only.

Native ARM64 and Windows amd64 Race retain their independent PR and dispatch
jobs and their existing scope. Linux ARM64 Race and Windows amd64 Race run
`./...` with the full tags and CGO in those jobs. Windows ARM64 Race stays
`NOT_EXECUTED`. Core runtime retains guard tests, feature inventory, the
independent network baseline, and ARM64 compilation. Its network baseline
has no performance SLO.

## Runner fingerprints

GitHub-hosted labels select an OS/architecture and allow rolling image updates.
The artifact records `ImageOS` and `ImageVersion`, kernel, architecture, CPU,
memory, relevant limits, Go settings, commands, peer digests and test port
environment. Command records include the actual native test namespace and each
command's Go settings, including the change to CGO for Race. Source commit,
tree, event, run ID, attempt and job bind the observations to a run.

On main and Tag pushes, `environment-diff` finds the successful `Official
release` run of the associated merged PR with the same source tree. It checks
the target fingerprints and their hashes before comparing recorded fields.
Ephemeral namespace IDs and load snapshots appear in fingerprints and are
excluded from comparison. The result lists specific changed values. Missing
or expired artifacts, an incomplete runner fingerprint, or a different source
tree produce `NOT_EXECUTED` or `INCOMPLETE`. The comparison reports observations
and does not change any test verdict. Exact VM image pinning requires a runner
whose image version the operator controls. [GitHub-hosted runner images](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners#runner-images)

## Evidence and retention

- The runner writes original command stdout and stderr under `RUNNER_TEMP`.
  Go output includes the original JSON stream. The command record keeps the
  actual exit code, start/end time, PID, test identities and the verdict.
- The bounded failure snapshot records local fixture sockets, Linux queues and
  namespace, and process resource limits where available. A post-exit snapshot
  can miss sockets already closed by the fixture. Go events record observed
  peer startup, readiness, ownership, exit and rebind checks.
- The public projection preserves structured Go events and known diagnostic
  fields from race reports and peer logs. Unclassified messages and stack
  arguments are redacted. A separate selection retains failed Go test events
  when general stdout is truncated. Complete peer configuration, private keys, vault
  credentials, state DBs, environment dumps, binaries and support bundles
  stay out of public evidence. Hosted raw files remain private for the life
  of the runner. Retain raw reproduction evidence in a controlled operator
  workspace when troubleshooting after the job ends.
- Evidence collection and upload run after success or failure. The collector
  preserves the failed command and emits target-specific artifacts for 30 days
  (14 days for the independent performance baseline). Each artifact has a
  SHA256 inventory with byte counts and run identity. The projection limits
  the bundle to 24 MiB and 512 files, with at most 2 MiB per file. Look for
  truncation and omission markers when an artifact approaches its limits.
- Release transfer and candidate artifacts carry the required packages and
  verified manifests. They use the archive inventory from `release.py`.

## Exercise the failure path

Run `python -m unittest discover -s scripts/qualification -p 'test_*.py'` on
Linux or Windows to check exit propagation, raw output retention, redaction,
file limits, and runner comparison. `Official release` also accepts the
`inject_failure=true` workflow dispatch input. The two native `build` contexts
run a synthetic required test that exits 42. They upload
`diagnostic-injection-*` evidence and remain failed. This dispatch omits the
real qualification, packaging, assembly and publication steps.
