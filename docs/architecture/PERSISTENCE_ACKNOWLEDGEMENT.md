# Independent persistence acknowledgement: design decision

Status: **design experiment only; production integration NOT_QUALIFIED**.
Schema 8, WAL, synchronous FULL, busy timeout 5000 ms and the four-connection
pool remain unchanged. No production sidecar, new schema, key format or success
contract is introduced by this decision.

## Problem and current boundary

The P3.1 reproductions at `896a69482a57056e13c0eb22e084328bb3c9851f` establish
loss of acknowledged business rows after committed WAL frame damage despite
`integrity_check=ok`. The settings revision and transaction journal occupy the
same WAL. A pre-commit process crash and loss of a later acknowledged commit can
leave identical pending runtime state. Loss of the journal commit can remove
even that symptom. The journal cannot attest its own WAL's completeness.

P3.2 admission checks run under the Store write mutex before creating a journal.
An admitted business validation failure still receives a failed audit record.
Runtime completion requires process-local ownership; a reopened pending operation
cannot be adopted with its database identity. Ambiguous recovery leaves rows
untouched and refuses mutation with the existing `unavailable` code. This
intentionally blocks automatic retirement of ordinary crash pending operations
too. Existing crash recovery assertions remain qualification blockers; safe
rejection is not successful recovery. This candidate must remain Draft.

The recovery latch is process-local, not an independent durable watermark. Its
absence after restart proves nothing. Valid-looking rollback with no pending
journal remains undetectable. SQLite reader open can rebuild SHM; ordinary last
connection close can checkpoint/delete WAL. A read-only recovery method does not
make opening/closing an original fault image forensically safe. Preserve a stopped
installation's DB/WAL/SHM and matching key before opening diagnostic copies.

## Candidate and acknowledgement order

An external authenticated commit ledger is worth further investigation. A bare
revision anchor can detect a lower database revision while the anchor survives,
but misses different content at the same revision. A content digest should cover
a versioned canonical logical snapshot: all journal columns, settings, encrypted
records, schema checksums and relevant business tables. Do not hash the main DB
alone: checkpoint timing and WAL contain valid committed state. Canonicalization,
snapshot isolation, bounds and cost require a separate specification.

The proposed ledger binds format version, installation/node identity, a random
restore epoch, key identity, sequence number, previous-record digest, operation
identity, base/target revision, content digest and prepared/confirmed phase. Use a
separately derived authentication key with explicit domain separation. Do not
reuse a raw Vault encryption key as a MAC key without a reviewed derivation and
rotation protocol. No secret is stored in the ledger. SHA256 detects accidental
change; neither a digest nor a MAC makes an old authentic generation fresh.

The ordering to investigate, under the installation lock and write mutex, is:

1. Validate the previous confirmed ledger and exact committed DB generation.
2. Durably record an intent/prepared generation, retaining the previous confirmed
   generation. If persistence fails, do not begin the business mutation.
3. Perform the SQLite transaction and FULL commit. A commit error is indeterminate;
   retain evidence and close the write gate rather than claiming rollback.
4. Persist an authenticated confirmed generation that binds the actual committed
   contents. Flush data and required namespace metadata before acknowledging.
5. Only then return the newly defined durable success to the caller.

This would change today's success contract, and therefore is **not implemented**.
If confirmation persistence fails after DB commit, return an indeterminate error,
latch mutation refusal and retain both generations. Do not pretend SQL rolled
back, rerun the callback, or mark that committed transaction failed. Caller retry
requires durable operation identities/idempotency and reconciliation semantics;
request ID uniqueness is not currently that protocol. Successful confirmation
followed by a lost response also needs that treatment.

## Reconciliation and controlled crash cuts

| Observed state | Proposed decision |
| --- | --- |
| Exact authenticated confirmed generation and matching DB contents | Eligible only under the stated ledger durability/trust assumptions |
| DB ahead of confirmed record | Indeterminate commit; refuse writes and preserve both |
| Prepared intent, with DB at base or target | Refuse automatic retirement/finalization; require independent recovery evidence |
| Confirmed ledger ahead of DB | Lost data or an old restore; refuse writes; never lower the ledger |
| Same revision, different digest | Refuse writes; revision equality is insufficient |
| Missing, truncated, unauthenticated or discontinuous ledger | Refuse writes; never bootstrap it from the current DB |
| Wrong/missing key, installation or restore epoch | Refuse mutation; do not generate a replacement key/ledger |
| DB and ledger both replaced by one authentic old pair | Undetectable without an independent trusted freshness source |

`TestIndependentAcknowledgementDesign` is an isolated reconciliation fixture. It
uses actual SQLite commits, a separately written/synced synthetic MAC record and
controlled old/new/prepared/missing/corrupt/key/restore observations. It asserts
that probing never modifies SQLite or rewrites the oracle, and asserts the
coordinated rollback counterexample. It is **not** a tested atomic replacement
implementation, process/power-loss ledger protocol, full canonicalization format,
or production Vault key derivation. DB/WAL fault injection remains in
`TestPersistenceReliability`. Passing this experiment establishes only the
reconciliation observations, not ledger durability or safe automatic recovery.

Before implementation, test actual subprocess termination at every intent,
write, flush, rename, directory flush, SQL commit, confirmation and response cut;
inject short writes, disk-full, EIO, flush failure, missing generations and
malformed records. Every acknowledged transaction must either remain verifiable
or cause write refusal. An unacknowledged transaction may still have committed.
Detection and successful content recovery must have separate assertions.

## Platform, lock and durability requirements

On Linux a candidate replacement must use a private, exclusive new file on the
same filesystem, check every write and file `fsync`, atomically rename within the
directory, and `fsync` the containing directory. Flushes for initial directory
creation and explicit backup/restore activation also matter. Append-only,
bounded-size generations with a checksummed/authenticated chain avoid overwriting
the last good record but still need directory durability and a trusted high-water
mark to detect loss of the whole suffix. Temp/orphan files and failed flushes are
evidence, not garbage to automatically remove. Filesystem/drive flush honesty and
actual OS/power-loss tests are separate assumptions.

Windows needs its own reviewed NTFS implementation: appropriate CreateFile access,
sharing and reparse-point/ACL protection, FlushFileBuffers, a qualified replacement
primitive and durable namespace semantics. Go `os.Rename` does not promise atomic
replacement on non-Unix platforms. ReplaceFile's WRITE_THROUGH flag is unsupported;
MoveFileEx WRITE_THROUGH documents copy/delete flushing and must not be assumed
to establish the entire required same-volume replacement/directory contract.
Antivirus sharing failures must fail closed. The fixture exercises Windows file
flush and logical checks only; Windows namespace durability is NOT_EXECUTED.

All writers, migration, backup and restore tooling must share one installation
OS lock. Acquire it before reading either authority, preserve its stable inode/
file identity, and retain it through DB commit and external confirmation. SQLite's
own locks do not serialize an unrelated sidecar. A second process must fail before
writing either file; within the owner, serialize with the same Store mutex. Network
shares and unsupported lock/durability semantics must be rejected rather than
silently downgraded. Locking proves mutual exclusion, not media integrity.

## Backup, keys and legacy upgrade

A qualified backup must contain a coherent committed database, the matching key,
authenticated confirmed ledger/epoch and a verified watermark/content manifest.
Copying live DB bytes without its WAL is not that backup. Preserve the fault
installation separately. Verify contents and key-dependent decryption on a new
restore target; compare to a trusted external watermark. An older backup must
not silently replace current authority or lower its ledger. Explicit operator
acceptance of data loss needs a new restore epoch and an auditable retained old
authority. Matching old files alone do not authorize such rollback. Current
production Windows backup remains unavailable; test-only VACUUM is not its
qualification.

Key loss cannot be repaired by recreating an anchor: authenticated history and
encrypted contents may be unrecoverable. A wrong key or mismatched key ID must
stop recovery. Rotation needs authenticated linkage and paired backups; corrupt
ledger needs another verified copy or independent authority. Never regenerate it
on startup from the possibly rolled-back DB. An old Schema 8 installation without
any anchor has no historic acknowledgement proof. Enrollment must be explicit,
stopped, backed up and content-verified by the operator; it can establish future
assurance only, not certify past durability. Downgrade/older-writer exclusion and
format negotiation must be designed before enrollment is offered.

## Decision and remaining qualification

An external ledger could detect isolated DB/WAL regression **if** its authentic
fresh watermark survives. A same-disk sidecar is not an independent hardware fault
domain: controller/medium failure, snapshot restore, malicious substitution or
coordinated rollback can affect both. An independently retained remote witness,
hardware monotonic authority or otherwise trusted external high-water mark is
needed to address that class. A checksum, MAC or hash chain alone cannot do it.

Keep the experiment outside production. Resolve durable acknowledgement/error and
retry semantics, canonicalization, native Windows namespace durability, all crash
cuts, independent locking and explicit restore/enrollment before proposing a new
contract/file format. Until then conservative pending refusal and verified backup
restore are separate limited capabilities; universal WAL corruption recovery and
compatibility with automatic pending retirement remain NOT_QUALIFIED.

## Primary references

- [SQLite WAL recovery and checksums](https://www.sqlite.org/walformat.html#recovery)
- [SQLite synchronous semantics](https://www.sqlite.org/pragma.html#pragma_synchronous)
- [SQLite WAL lifecycle and backup state](https://www.sqlite.org/wal.html#the_wal_file)
- [Linux fsync and directory persistence](https://man7.org/linux/man-pages/man2/fsync.2.html)
- [Go os.Rename platform contract](https://pkg.go.dev/os#Rename)
- [Windows FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [Windows ReplaceFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
- [Windows MoveFileEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexa)

## P3.3: recovery contract validation

This section continues the decision above. It does not replace the production
contract or claim that conservative refusal restored runtime availability.

There are two different guarantees. With process failure alone, assuming intact
committed storage, SQLite rolls back the open SQL transaction and the old
runtime journal can be retired before rebuilding committed listeners. Under
possible loss of committed WAL frames, that same visible journal is ambiguous.
Schema8 supplies no evidence that distinguishes those histories. Keeping the
original automatic behavior preserves process-crash availability under the first
assumption; it does not establish the second guarantee.

| Existing compatibility test | Safe subscenarios without a new authority | Ambiguous subscenario |
| --- | --- | --- |
| Snell concurrent revision / interrupted create | One competing revision wins; live owned operations can finish or compensate | Reopened runtime_create pending after the last confirmed configuration |
| Hysteria2 replacement rollback / interrupted journal | Same-process storage rejection preserves bindings and rebuilds old runtime | Reopened runtime_replace pending |
| TUIC replacement rollback / interrupted journal | Same-process storage rejection preserves bindings and rebuilds old runtime | Reopened runtime_replace pending |
| Phase15 process runtime crash | Existing after-commit, after-activation, before-retirement and provider cuts reconstruct committed state when no pending remains | before-commit and prepare leave a runtime pending journal |

All original assertions remain. A controlled test parent knows exactly where it
killed its child; a restarted production process does not possess that external
knowledge. No-pending reconstruction is safe under the process-only assumption,
but still cannot attest that acknowledged media contents never disappeared.

`TestIndependentAcknowledgementCrashProtocol` fills the ordering gap in the
earlier reconciliation fixture with actual Schema8 transactions and a separate
live witness process. The witness owns a synced append-only test log outside the
fault image and retains a current high-water mark. It authenticates the chain,
installation, key, epoch, sequence, operation ID and complete command digest.
The parent must accept persistence before the child may report success. Its
freshness is an explicit assumption supplied by the surviving parent, never
reconstructed from the current DB or the local log's last valid prefix.

The existing six logical crash positions are exercised: prepared before journal
commit; pending before the business transaction; staged business SQL before
commit; SQL committed with confirmation persistence failure; confirmed before
response; response acknowledged. Retirement itself has prepared/SQL/confirmed
ordering, including interrupted retirement confirmation. A staged record binds
the exact pending preimage and exact candidate content, rather than revision
alone. This is important because the existing generic callback cannot predict
all resulting ciphertext and timestamps before it executes.

Under a fresh witness, matching pending/base contents can be retired, an exact
committed candidate can be confirmed without rerunning its callback, and a
confirmed state can be reconstructed without changing it. The fixture asserts
that an operation acknowledged to the parent is never cleaned as pending, even
when the DB is replaced with its saved pending generation: the intact fresh
confirmation makes that replacement a read-only refusal. Same-revision content
changes, missing/corrupt records, an old authentic prefix and wrong keys are
refused. Matching request ID/content returns the recorded terminal outcome;
different content conflicts. This bounded prototype does not implement a full
historical idempotency index, authenticated remote service, witness restart or
production enrollment API. Unknown outcomes must never cause automatic replay.

The coordinated-rollback counterexample remains: if both the DB and the assumed
fresh witness are replayed to the same authentic old generation, the algorithm
can retire an actually acknowledged operation. The test explicitly reproduces
that unsafe result as NOT_QUALIFIED. A same-medium log cannot provide independent
freshness. File Sync and process-crash results on Linux/Windows do not qualify
Windows namespace durability, witness-host failure or power loss.

Legacy Schema8 enrollment requires explicit approval, a separately verified
backup/content authority, no ambiguous pending state, a matching Vault key and
a new epoch. It can establish future evidence only. An already ambiguous legacy
pending operation cannot be made safe merely by enrolling its present revision.
The fixture refuses automatic enrollment; a production upgrade/downgrade and
key-rotation protocol still requires separate qualification before integration.

| Evidence available at restart | Decision |
| --- | --- |
| Fresh authenticated confirmation and exact contents | Reconstruct the committed generation; do not retire it |
| Fresh prepared record and exact base/pending preimage | Retire only under the validated new contract, retaining previous confirmed data |
| Fresh prepared record and exact staged committed candidate | Confirm the candidate; never rerun the business callback |
| Missing/untrusted freshness, unknown phase or mismatched contents | Refuse mutation and preserve the original evidence |
| Valid independent backup and matching key, explicit restore procedure | Restore to a separate verified generation; do not silently lower authority |
| Acknowledged data lost without a valid backup | Data recovery remains NOT_QUALIFIED |
