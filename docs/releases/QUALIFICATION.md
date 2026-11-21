# Release qualification and CI evidence

`Official release` is the unified `AMD64_ONLY` workflow for PRs to `main`,
pushes to `main` and version Tag pushes. Its build jobs check the Git guard,
feature inventory and qualification Python tests on both native targets.
`Performance baseline` is a manual, independent workflow without a release SLO.

| Official target | Native runner | Required execution |
| --- | --- | --- |
| Linux amd64 | `ubuntu-24.04` | Release build, default/full build, vet, tests, Linux Race and downloaded-product smoke |
| Windows amd64 | `windows-2025-vs2026` | Release build, default/full build, vet, tests, native Windows Race and downloaded-product smoke |

ARM64 support is paused and sits outside future builds, CI gates and releases.
The [v0.6.4 record](v0.6.4.md) retains its historical seven-asset inventory.
The [roadmap](../ROADMAP.md) tracks development on main.

The workflow uses the Go version in `go.mod`, a local toolchain, readonly module
resolution, Go telemetry off and `GOMAXPROCS=4`. Product, default and full
builds use `CGO_ENABLED=0`. Full builds use `with_quic,with_utls,with_gvisor`.
Default and full tests run `./...` with `-json -count=1 -timeout=1200s`.
Windows keeps `-p=1`. Linux Race uses CGO with the full tags and runs
`./internal/splicore/... ./protocol/...`. The separate Windows Race job uses
the pinned test compiler, CGO, full tags and `-p=1` on `./...` with its own
CGO-free core for process lifecycle checks. The per-command limit is 2,100
seconds. The default Windows tests verify all former Symlink workflow test
identities and proof of real link creation, traversal rejection and cleanup.

Linux uses the owned loopback network namespace from `scripts/dev/isolated-linux.py`.
Xray, Snell on Linux amd64 and the wireguard-go fixture keep their pinned sources.
Their archive and executable digests are recorded where applicable.
`qualification_policy.py` enforces required traffic, lifecycle, safety,
interop and persistence identities and records approved skip reasons.

`assemble` requires both qualified targets and source-matched Windows Race
evidence. It verifies the two platform archives and corresponding source, then
writes `SHA256SUMS` and `RELEASE_MANIFEST.json` for the five-asset set.
On PR and main, both `download-test` jobs verify and execute the downloaded
candidate, using the current source commit and tree. The smoke requires the VLESS
process lifecycle with all four traffic subtests, the managed HTTP process
suite, and both managed SOCKS5 TCP and UDP process suites. The UDP suite requires
real per-address-type datagrams, source isolation, scoped routing, a two-Core
TCP/UDP and DNS chain, credential revocation and recovery from the SQLite state.
Native Default, Full and Race also require the UDP socket and configuration
test identities recorded in `qualification_policy.py`.

A Tag push must match the distribution version and the exact `origin/main`
commit. The `draft` job stages a new Draft after build, Race, assembly and
provenance checks. It downloads all five assets by ID and verifies their
GitHub SHA256 digests and the exact candidate checksum list. Both native
smoke jobs use the verified download. `authorize-publication` requires a
successful draft and both jobs. The Tag-only `publish` job rechecks the
Draft ID, Tag commit and asset snapshot before making that draft public.
On smoke failure the draft and diagnostic evidence remain available for review.
A new staging attempt rejects any existing Draft or Release for the same Tag.

## Runner fingerprints

GitHub-hosted labels select an OS/architecture and allow rolling image updates.
The artifact records `ImageOS` and `ImageVersion`, kernel, architecture, CPU,
memory, relevant limits, Go settings, commands, peer digests and test port
environment. Command records include the actual native test namespace and each
command's Go settings, including the change to CGO for Race. Source commit,
tree, event, run ID, attempt and job bind the observations to a run.

`environment-diff` checks the effective result for each target against the
run’s job history. GitHub copies successful jobs into a partial rerun with new
job IDs and the original runner, timestamps and steps. The comparison follows
those copies back to the execution that produced the evidence. It validates
the Artifact ZIP digest, inventory and fingerprint hashes, the original
attempt, and the checked-out commit and Tree. A newer failed execution or a
missing or invalid Artifact produces `INCOMPLETE`. Each target retains the
conclusions of earlier attempts alongside the effective execution.

On main and Tag pushes, the job compares against the latest `Official release`
run of the associated merged PR when that run succeeded and used the same
source tree. PR jobs verify both current target artifacts. PR/main comparison
is `NOT_EXECUTED` until main or Tag runs. A required missing or unverifiable
comparison fails the gate and retains the JSON report.
Ephemeral namespace IDs and load snapshots appear in fingerprints and are
excluded from comparison. The result lists specific changed values. Missing
or expired artifacts, an incomplete runner fingerprint, or a different source
tree produce `NOT_EXECUTED` or `INCOMPLETE`. Provenance failures preserve the
original test outcomes and block the affected gate. Exact VM image pinning requires a runner
whose image version the operator controls. [GitHub-hosted runner images](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners#runner-images)

## Evidence and retention

- The runner writes original command stdout and stderr under `RUNNER_TEMP`.
  Go output includes the original JSON stream. The command record keeps the
  actual exit code, start/end time, PID, test identities and the verdict.
- The bounded failure snapshot records local fixture sockets, Linux queues and
  namespace, and process resource limits where available. A post-exit snapshot
  can miss sockets already closed by the fixture. Go events record observed
  peer startup, readiness, ownership, exit and rebind checks.
- `commands/*.test-identities.json` records allowed Go test identities and their
  terminal results separately from bounded stdout. The index includes an omitted
  count for identifiers outside the public projection rules.
- `commands/*.protocol-observations.jsonl` retains bounded Snell v5 and protected
  DNS fallback fixture evidence outside the truncated log tail. It records
  synthetic socket ports, phase and byte counts, echo counts, peer cleanup,
  DNS transaction metadata and OS error codes. The projection accepts fixed
  fields only from the corresponding Go test identities.
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

## Verify failure handling

Run `python -m unittest discover -s scripts/qualification -p 'test_*.py'`
on Linux or Windows. The tests exercise original exit propagation, bounded
redacted failure evidence, artifact and retry provenance, five-asset draft
inventory, downloads by asset ID and publication blocking after smoke failure.
PR and main runs exercise real candidate packaging and native downloaded smoke.
Formal Draft creation and public release mutation occur only on a version Tag.
