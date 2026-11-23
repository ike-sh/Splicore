# Persistence and native platform qualification

Official qualification uses Linux and Windows amd64 under the
[AMD64_ONLY release contract](../../docs/releases/QUALIFICATION.md).
The [roadmap](../../docs/ROADMAP.md) describes current development priorities.

`TestPersistenceReliability` uses disposable real files, SQLite transactions
and independent child processes. It extends rollback, concurrent access,
schema migration, encrypted credential and lifecycle tests.

```sh
# Use a private, disk-backed temporary filesystem and caches outside the checkout.
SPLICORE_PERSISTENCE_EVIDENCE=/external/persistence \
  go test -json -count=1 -timeout=10m -run '^TestPersistenceReliability$' ./internal/splicore/storage/sqlite
```

On native Windows amd64, fetch the pinned compiler and test peers, then import
the generated environment assignments before running the independent Race job.

```powershell
python scripts/qualification/fetch-windows-race-toolchain.py --output D:/external/compiler --github-env D:/external/compiler.env
python scripts/dev/fetch-restoration-references.py --output D:/external/reference --github-env D:/external/peers.env
python scripts/qualification/native.py --output D:/external/windows-race
```

Use the Go version in `go.mod` and `GOMAXPROCS=4` as in CI. The script checks the
native OS and architecture and preserves the original Race exit and behavior
evidence. The compiler and independent peers are SHA256-checked test tools.
Production default/full builds remain CGO-free. The Linux and Windows test
profiles, interop scope and artifact retention are described in the release
contract.

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
It reports native SQLite structural recovery separately from acknowledged-state
protection. The independent commit witness must reject a structurally valid
earlier state missing acknowledged rows with `storage_integrity_unverified`,
even when `integrity_check=ok`. A test PASS qualifies loss detection and
fail-closed admission; it does not certify automatic media-corruption recovery.
Retain the per-fault JSON classification. This is a bounded diagnostic, not
exhaustive WAL recovery qualification.

The committed-WAL safety-boundary diagnostic also captures real runtime-operation
commits, verifies commit-frame offsets, and uses separate native-reader and
application copies of each damaged input. It distinguishes structural validity,
acknowledged business rows/revision, witness comparison before writable Open,
and restoration from an intact verified DB+witness backup. Damage to either the
business or pending-journal commit frame must not reach startup `RecoverPending`
or a mutation callback when the surviving witness names a newer generation.
Preserve the original DB/WAL/SHM/witness before opening diagnostic copies. No
automatic repair or production WAL parser is added. The diagnostic records
journal row counts separately and retains the verified backup files, their
SHA256 values, and native/application/backup-restored copies.

Pinned Xray's h3-only server listens on UDP. The peer fixture reserves both
protocols at an OS-selected port on the exact IPv4/IPv6 address, then releases
the parent sockets immediately before starting the child without startup retry.
A separate loopback-only TCP SOCKS sentinel in that child verifies TCP binding
at the same endpoint; H3 application payload still exclusively uses the original
QUIC profile. Windows records dynamic/excluded ranges, actual socket outcomes
and child PID ownership; cleanup requires immediate TCP/UDP rebind.

Linux production MaintenanceBackup refuses the running store, then uses
lock-protected `VACUUM INTO` on the stopped source, verifies the snapshot's
logical digest, and persists the matching witness. A separately preserved
synthetic Vault key must decrypt the restored snapshot, survive a new witnessed
write and reopen, and wrong/missing keys must fail. Keys are never logged or put
in CI artifacts. AES-256-GCM protects secret fields; metadata is not whole-file
encrypted. Key identity is recorded without key bytes. Windows production
maintenance remains Linux-only: the Windows `VACUUM INTO` test is explicitly a
test-only snapshot with a copied verified witness, and production Windows backup
is **NOT EXECUTED**.

Use fresh output directories. Retain environment/source SHA, exact commands,
per-test events, per-fault JSON, original and recovered files, and checksums of
the artifacts. CI uploads evidence after failures as well as success. Do not
publish a release merely for these tests. Existing encrypted state, security,
protected underlays and all release assertions remain in force.
