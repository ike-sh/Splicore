# Commit witness and storage-integrity boundary

Schema 8 keeps SQLite in WAL mode with `synchronous=FULL`. SQLite structural
checks prove that the pages SQLite selected form a valid database; they do not
prove that the selected generation still contains every transaction for which
Splicore returned success. A damaged committed WAL frame can expose an older,
structurally valid generation. Splicore therefore maintains a durable commit
witness beside `state.db` and treats disagreement as
`storage_integrity_unverified`.

This mechanism qualifies **detection and fail-closed admission**, not automatic
reconstruction of missing data.

## Files and trust boundary

For `state.db`, the owned state directory contains:

- `state.db.witness`: the last Splicore commit that completed the durable
  acknowledgement boundary;
- `state.db.witness.pending`: a same-directory staging file used only during an
  atomic witness replacement.

The version-1 JSON witness contains the installation UUID, Schema, monotonic
global Revision, transaction UUID, previous Revision/digest, current logical
state SHA256, UTC commit time, format/version, and a SHA256 checksum of the
record. `native` lineage begins with a newly initialized database.
`legacy_baseline` lineage records an administrator's explicit baseline of a
pre-witness database and remains in later witnesses; it never claims proof of
the installation's earlier acknowledgements.

The logical digest covers SQLite schema objects and every column of every
Schema 8 table in canonical table/column/row order, including encrypted
ciphertext. Transaction-journal row contents are excluded because pending and
failed lifecycle transitions do not publish business state; the current
witness transaction UUID and base/target Revisions are checked separately
against a matching committed journal row. No credential plaintext, Vault key,
password, or private key is written to the witness.

The checksum detects accidental corruption. It is not an HMAC or signature:
a principal able to rewrite both SQLite and the witness is outside this local
media-integrity model. The database, WAL, and witness are normally on the same
disk. They are separate commit evidence, not independent backups or independent
failure domains. A paired rollback or loss of all three can be detected only by
comparing an independently retained newer witness/backup generation.

## Commit and response protocol

All production business mutations use `Transact` or
`BeginRuntimeOperation`/`CommitOperation` under the Store writer mutex:

1. Before any new journal row, Splicore validates the on-disk witness, absence
   of a pending witness, installation/revision identity, the logical state
   digest, and the witness's committed transaction row.
2. The domain callback, business rows, global Revision, and committed journal
   transition are applied in one SQLite transaction.
3. The candidate logical digest is calculated from that transaction's snapshot.
4. SQLite Commit completes.
5. The next witness is written to a new same-directory staging file, fully
   written and file-synchronized.
6. The staging file atomically replaces `state.db.witness`. Unix then
   synchronizes the parent directory. Windows uses `MoveFileEx` with
   `REPLACE_EXISTING|WRITE_THROUGH` after synchronizing the staging file.
7. Only after step 6 does the repository return a successful commit.

A successful witness can precede actual delivery of the network response. As
with ordinary durable APIs, a client that loses the response must read the
Revision or retry idempotently; Splicore never returns success before the
durability boundary.

## Crash windows

| Failure point | Durable observation | Restart behavior |
| --- | --- | --- |
| Before SQLite Commit | Older DB generation and witness agree | Normal rollback/recovery; pending runtime intent is handled by the existing journal policy |
| SQLite Commit complete, before witness write | DB Revision/digest is higher than witness | Fail closed; the unacknowledged higher DB generation is not promoted automatically |
| During witness staging write or sync | Older witness plus a partial/pending file, or DB ahead of witness | Fail closed and retain the pending file for diagnosis |
| Atomic replacement complete, before API response | DB and new witness agree | Normal reopen; the commit is durable even if the caller did not receive the response |
| Checkpoint, normal close, WAL cleanup | Logical state is unchanged | Normal reopen |
| Checkpoint interrupted after some main-file pages were written, complete WAL retained | WAL still names the committed generation and the logical digest agrees | Normal recovery; the deterministic partial-checkpoint fixture remains accepted |
| Committed WAL frame loss/checksum damage | SQLite may expose an older valid Revision while the witness remains newer | `storage_integrity_unverified`; no startup recovery or mutation is run |
| Witness missing, damaged, rolled back, ahead, or same Revision with a different digest | Evidence is incomplete or contradictory | Fail closed |

An error from SQLite Commit is outcome-ambiguous and also seals the Store. A
witness write/sync/replace error is returned as
`storage_integrity_unverified`, latches mutation admission, denies managed
binding admission, and cancels the owning application so listeners and workers
are shut down. A retry cannot overwrite the older witness or publish another
Revision.

## Startup, runtime, and diagnostics

Existing witnessed databases are first checked through a read-only SQLite
handle. A mismatch is rejected before writable journal-mode setup, migration,
`RecoverPending`, or listener restoration. A healthy Open repeats validation
after migration-history checks. New installations create the Revision-0 native
witness before becoming available.

`splicore state integrity --source /absolute/private/state.db` reports only
non-secret identity, Revision, digest, lineage, pending state, and a fixed
status. It does not initialize, migrate, recover, or establish trust. Preserve
the database, WAL, SHM, witness, pending witness, and their hashes before manual
recovery.

Read-only verification copies the DB, WAL, witness and pending-witness bytes to
a private disposable directory, verifies that those authoritative source files
did not change during the copy, and lets SQLite derive or update SHM only in
that copy. The source DB, WAL, existing SHM and witness bytes therefore remain
unchanged even when SQLite needs to rebuild its transient WAL index. Normal
cleanup removes the private copy; it contains the same encrypted state and must
be treated as sensitive if a process is terminated before cleanup.

## Existing Schema 8 and explicit legacy baseline

A pre-witness database does not open writable. After stopping the service and
retaining a coherent backup plus its Vault key, an administrator may run:

```sh
splicore state integrity --source /absolute/private/state.db
splicore state establish-witness --source /absolute/private/state.db \
  --acknowledge-current-state
```

The second command requires the explicit flag, the installation lock, valid
SQLite/foreign keys/migration history, no pending transaction, and the runtime
compatibility boundary. It applies any supported forward Schema migration in
one transaction, writes a `legacy_baseline` witness, and never overwrites an
existing or pending witness. This makes the inspected current state an explicit
operational baseline; it does not prove that older acknowledgements were never
lost. Suspicious existing witness evidence must be preserved and resolved by
restoring a known pair rather than re-baselining over it.

## Backup and restore

Linux `state backup` still requires a stopped service and uses `VACUUM INTO`.
For a verified source it validates the source witness, validates that the
logical snapshot matches it, and durably writes the same witness beside the
backup database. Preserve the matching Vault key and both backup files.

A legacy source with no witness can be snapshotted for evidence, but the
snapshot remains unwitnessed and needs the same explicit baseline decision
before writable use. A mismatched, corrupt, or pending witness blocks the
ordinary backup path. Restoring an older DB without its matching witness is
detected. Restoring an internally matching older DB+witness pair cannot prove
freshness without an independently retained newer witness or backup catalog.

## Cost and limits

Each acknowledged business commit adds two canonical logical-state scans (one
before mutation admission and one in the candidate transaction), one small
witness-file write, one file synchronization, one atomic replacement, and the
platform rename/directory durability barrier. The witness is fixed-size and no
whole-database copy is made per commit. SQLite busy timeout, connection pool,
WAL/FULL policy, encrypted fields, and Vault ownership are unchanged.

The protection is deliberately conservative: an ambiguous post-Commit window
requires operator recovery rather than automatic promotion. It detects lost
acknowledged state when the witness survives; it does not repair arbitrary
media damage, survive loss of the common disk by itself, prove a legacy
installation's full history, or replace a separately retained backup.
