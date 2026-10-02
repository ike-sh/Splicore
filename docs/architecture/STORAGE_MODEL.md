# SQLite storage model

- Documentation status: Canonical
- Audience: Storage and deployment developers
- Last reviewed: 2026-10-02
- Owner: Storage maintainers
- Responsibility: Driver qualification, durability, migration mechanics, backup and corruption recovery.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Current committed schema

Schema 4 adds checksummed 0004_private_key after 0003_password, without editing
migration history. It extends the credential-kind CHECK for generic private-key
payloads, preserves ciphertext/AAD and Binding FKs, and restores the Snell
single-Binding trigger. Populated schema-2/schema-3 migrations and encrypted
password/private-key roundtrips cover these boundaries. Network I/O stays outside
SQL callbacks. Explicit private Linux master-key files protect credentials.
See [VLESS support](../protocol/VLESS.md).

Scope: storage operations and qualification. The [ERD](DATABASE_ERD.md) owns
logical entities/relationships/ownership; migration files own actual
schema history. This document specifies migration mechanics, not duplicate SQL.

Foundation selection: SQLite 3.53.4 + WAL on local filesystem, `database/sql`
behind repository ports, **modernc.org/sqlite v1.59.0 + libc v1.75.7**. Driver
Go requirement is 1.25.0; the repository stays at 1.25.5. v1.60.1 was rejected
because it requires Go 1.26.0. Exact dependency/licensing evidence is in the
[Foundation dependency audit](../development/DEPENDENCIES_PHASE_1.md).

| Choice | Build/deployment | Tradeoff |
|---|---|---|
| mattn/go-sqlite3 | CGO and C compiler/cross toolchain; Linux amd64/arm64 supported with appropriate compiler | mature native SQLite path; static deployment possible with deliberate libc/toolchain, not automatically portable |
| modernc.org/sqlite | CGo-free SQLite translation; supports Linux amd64/arm64 and Windows | simpler existing CGO=0 cross builds; larger dependency surface and potential CPU/memory overhead; pair libc version with driver's declared dependency |
| other pure-Go/WASM binding | additional runtime/binding choice | evaluate only if concrete required API/measurement justifies replacing preferred driver |

Use benchmark workloads resembling accounts, plans, usage settlement and audit,
not generic microbenchmarks to claim equivalent performance. Foundation gates:
Windows and Linux amd64 run, Linux arm64 compiles, WAL lock/busy behavior,
process failure, coherent snapshot/reopen, migrations and concurrent revision
writes. Arm64 execution, power-loss testing and representative accounting
performance remain prerequisites for production storage qualification.
If modernc fails those gates, switch adapter to mattn with a documented build matrix.

## Connections and durability

Single daemon process holds installation ownership lock. One serialized domain
mutation coordinator with a four-connection bounded pool in Foundation. Separate
writer/read pools are deferred until measured concurrency requires them. SQLite
still has one writer in WAL; WAL improves read/write coexistence, not concurrent
writer capacity. Set `foreign_keys=ON`, bounded `busy_timeout`, and agreed pragmas
on **every physical connection** via DSN/hook, not one pooled Exec.
Use `journal_mode=WAL`, `synchronous=FULL` for domain journal/commit and strict
budget reservations. Keep transactions short; runtime/network calls happen
outside SQLite transactions. Foundation uses SQLite's default WAL auto-checkpoint;
explicit checkpoint scheduling/monitoring is deferred. Never place WAL DB on NFS
or share it across servers.

## Schema and migration

Forward-only numbered migrations with checksums, executable compatibility ranges
and monotonic DB schema version. Acquire exclusive migration lock, stop admissions,
create consistent backup, apply migration in a transaction where supported,
validate FK/integrity/schema, start/reconstruct runtime, health-check. Never issue
ad hoc ALTER at startup. Unknown newer schema refuses writable startup.

Foundation acquires an OS installation file lock before SQLite opens; startup
validates migration sequence/checksum, product/schema/node metadata, quick_check
and foreign keys. Schema 1 preserves 0001_initial; schema 2 adds 0002_snell;
schema 3 adds 0003_password; schema 4 adds generic private_key payloads.
Fresh/close/reopen/repeat/failure/future/corruption tests exist. Pre-upgrade backup
orchestration remains deferred; the driver VACUUM INTO snapshot/reopen path is
tested. Managed Snell has listener health and committed-state reconstruction.

If migration fails before commit, DB transaction rolls back. If an upgrade with
committed forward migration fails health, rollback is restore of a coherent
pre-upgrade DB/secret-key/binary checkpoint, not arbitrary down migrations.
Keep any later usage/audit for reconciliation; do not restore over a serving DB
and silently lose traffic. No runtime mutation should depend on destructive schema
upgrade completing halfway.

## Backup/recovery

Use SQLite online backup API or a documented snapshot method (e.g. VACUUM INTO),
with driver support validated; **never copy only state.db while WAL is active**.
Backups include schema/generation/checksum, protected secret-key references and
restore instructions. Encrypt secret-bearing backups with reviewed tools.
Check integrity and perform restore drills; filesystem permissions 0700 state
directory, 0600 DB/keys/backups (Windows equivalent ACLs).

On startup recover WAL, validate committed generation and pending journal, then
reconstruct committed runtime. Suspected corruption prevents writes/admission;
retain original DB/WAL/SHM for analysis, restore to a separate checked path and
reconcile identity/usage before promotion. Do not auto-delete or silently recreate
an empty authoritative DB. Upstream bbolt cache remains a distinct operational file.

Sources: [modernc driver](https://pkg.go.dev/modernc.org/sqlite),
[CGO driver](https://github.com/mattn/go-sqlite3),
[SQLite WAL](https://sqlite.org/wal.html), [backup](https://sqlite.org/backup.html),
[corruption causes](https://sqlite.org/howtocorrupt.html).

## Third-protocol storage

TUIC uses existing schema-3 uuid_password encrypted payloads; no migration/protocol
column/Account field. Shared creation writes distinct Account/Binding/Credential rows;
SQLite committed state alone recovers. Display SQL is generic after service checks.

## Generic inbound server secrets

Schema 4 rebuilds only the generic credential-kind CHECK for PrivateKeyPayload
(algorithm=x25519). Inbound ownership already existed. No vless_uuid,
reality_private_key, protocol columns or Account fields are added. Populated schema
2 and 3 migration tests cover prior ciphertext/AAD, Binding/policy references and
Snell constraints. Existing UUID/password/PSK and private-key roundtrips use the same
AES-256-GCM vault and owner/kind/schema-bound AAD. Master key remains external.
Recovery loads committed inbound credentials through a bounded explicit port; client
exports cannot read it. Provisioning/rotation/backup/Windows production permissions
retain the foundation limits. [ADR 0016](../adr/0016-vless-engine-server-secrets.md).

## Phase 8 Mieru storage boundary

Mieru adds no schema/migration or protocol column. Existing username_password
credential payloads are encrypted with the existing vault. Account/Binding/Inbound
settings and DisplayEndpoint use shared committed SQLite resources. Runtime private
protobuf and client configs are derived output, never authority. Recovery rebuilds
users and listeners solely from committed state; imported files are removed in tests.
Generation stats reset on restart; persistent usage remains deferred.
[Contract](../protocol/MIERU.md).
