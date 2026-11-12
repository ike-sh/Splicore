# Persistence and native platform qualification

The production SQLite and Vault implementation and its settings are unchanged.
`TestPersistenceReliability` uses disposable real files, actual SQLite, actual
transactions and independent child processes. It extends the existing rollback,
concurrent access, schema migration, encrypted credential and lifecycle tests.

```sh
# A private, disk-backed temporary filesystem is required. Set TMPDIR and
# GOTMPDIR as well as GOCACHE/GOMODCACHE outside the source checkout.
SPLICORE_PERSISTENCE_EVIDENCE=/external/persistence \
  go test -json -count=1 -timeout=10m -run '^TestPersistenceReliability$' ./internal/splicore/storage/sqlite

# On actual Linux ARM64, populate the digest-pinned ARM64 test peers first:
python3 scripts/dev/fetch-restoration-references.py --output /external/reference --github-env /external/peers.env
# Import those NAME=value peer paths into the process environment, then:
python3 scripts/dev/isolated-linux.py -- python3 scripts/qualification/platform.py --mode arm64 --output /external/native-arm64

# On actual Windows ARM64, use native ARM64 Go/Python and omit isolated-linux.py:
python scripts/qualification/platform.py --mode arm64 --output D:/external/native-arm64

# On native Windows amd64 only, CC must name a mingw-w64 v8+ compiler:
python scripts/qualification/fetch-windows-race-toolchain.py --output D:/external/compiler --github-env D:/external/compiler.env
python scripts/qualification/platform.py --mode windows-race --output D:/external/windows-race
```

Go must match `go.mod`. Import the generated compiler `CC` entry before running
Race. Production default/full builds remain `CGO_ENABLED=0`; only Race test
binaries require the C toolchain. No compiler is installed globally. Pinned
compiler and Xray archives are SHA256 checked; Xray and the separately compiled
official wireguard-go peer are test tools, never production dependencies. The
existing amd64 peer hashes remain unchanged. A native official Snell executable
is currently pinned only for Linux amd64; ARM64 outcomes enumerate that missing
oracle rather than claim independent Snell qualification.

`platform-qualification.yml` runs on actual `ubuntu-24.04-arm`, `windows-11-arm`
and native Windows amd64. Host architecture is checked independently of Go's
target (Windows uses GetNativeSystemInfo); emulated amd64 on ARM64 is rejected.
The script preserves all default/full build, vet and test scope, checks required
behavior identities and actual CLI process traffic/restart, and records every
allowed skip. Linux ARM64 also runs its supported native Race detector. Native
ARM64 outcomes remain `QUALIFIED_WITH_LIMITATIONS` while
hardware networking, missing oracle campaigns and broad physical devices are
unqualified. BUILD PASS, native startup, native traffic and full scope are
recorded separately. Cross-build success alone cannot pass the script.

The persistent test evidence records actual `sqlite_version/source_id`, Schema,
journal_mode, synchronous, busy_timeout, foreign_keys, checkpoint threshold,
page size, cache/locking/mmap and connection pool limits. Expected current
Schema is 8. The official store already uses WAL; this test does not restore
the historical WAL/P1-B architecture or change transaction policy.

Each subprocess is stopped exactly after transaction begin, first write,
two writes before commit, acknowledged commit, or completed TRUNCATE checkpoint.
Normal Close is a separate case. `os.Exit(77)` and `Process.Kill` are distinct
process-failure injections. They are **not** OS crash or physical power loss.
Killing during an actual in-flight checkpoint/sync is **NOT EXECUTED**. Physical
power-loss testing is **POWER_LOSS_TEST_NOT_EXECUTED**. No random sleeps, traffic
retries, permission changes or weakened integrity assertions are used.

Pre-commit candidate rows must disappear, the acknowledged baseline must remain,
and the pending application journal must block mutation pending operator review.
Post-commit rows and counts must survive. Every reopened case runs full
`integrity_check`, `foreign_key_check` and application revision/content/count
checks. Original dead-child DB/WAL/SHM files are retained before recovery when
evidence is requested. A copy of files from a stopped test child is a diagnostic
capture; it is never called a coherent backup.

The native WAL diagnostic uses synthetic copies only: unchanged WAL, partial
uncommitted tail, last committed frame truncation and checksum corruption.
It reports native SQLite recovery separately from application journal protection.
A structurally valid earlier state missing acknowledged rows is
`NOT_QUALIFIED`, even when `integrity_check=ok`. The ordinary test assertion
protects fail-closed application mutation; a test PASS does not certify media
corruption recovery. Retain the per-fault JSON classification. This is a bounded
diagnostic, not exhaustive WAL/P1-B qualification.

Linux production MaintenanceBackup refuses the running store, then uses
lock-protected `VACUUM INTO` on the stopped source. A separately preserved
synthetic Vault key must decrypt the restored snapshot, survive a new write and
reopen, and wrong/missing keys must fail. Keys are never logged or put in CI
artifacts. AES-256-GCM protects secret fields; metadata is not whole-file
encrypted. Key identity is recorded without key bytes. Windows production
maintenance remains Linux-only: the Windows `VACUUM INTO` test is explicitly a
test-only snapshot, and production Windows backup is **NOT EXECUTED**.

Use fresh output directories. Retain environment/source SHA, exact commands,
per-test events, per-fault JSON, original and recovered files, and checksums of
the artifacts. CI uploads evidence after failures as well as success. Do not
publish a release merely for these tests. Existing encrypted state, security,
protected underlays and all release assertions remain in force.
