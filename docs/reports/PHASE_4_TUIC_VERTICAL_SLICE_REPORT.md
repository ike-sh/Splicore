# Splicore Phase 4 TUIC Vertical Slice Report

- Documentation status: Generated
- Audience: Maintainers and acceptance reviewers
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Actual Phase 4 implementation, acceptance and scalability results.
- Lifecycle: Preserve this acceptance record after review; canonical specs own behavior.

## Baseline

Phase 3 Freeze / implementation entry HEAD / main: `94555d9608ebcc36c5a396bc06a5743cce4e0788`.
Upstream: sing-box v1.14.1, `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
Dependency: sing-quic v0.7.0. Branch: `codex/phase-4-tuic-vertical-slice`.
Implementation entry working tree CLEAN; implementation acceptance was unstaged. Evidence:
`D:\splicore-validation\phase4-20261001`; private runtime executed on native WSL2 ext4.

## Status

TUIC: **Experimental**. Supported versions: **v5 only**. Unsupported: v4/token and
older versions. Managed profile: cubic/native UDP/h3/TLS1.3/no-0RTT. Upstream also
supports other congestion/relay/0-RTT variants; these remain unqualified and managed
input rejects them. No Stable/release designation.

## Architecture

- Protocol: registered TUIC Module/CreationCodec and strict bounded typed settings.
- Engine: one native compiler map; protocol factory composes exact pinned TUIC Service.
- Account/Binding/Credential: existing distinct resources; UUIDPassword typed encrypted payload.
- TLS/QUIC: shared static trust/load/snapshot, owned UDP/Box/router/admission/lifecycle.
- ClientProfile: engine-neutral v5 endpoint/credential/TLS/SNI/options projection.
- Exporter: existing format/protocol dispatcher; fixed Mihomo/sing-box contracts.

See [ADR 0015](../adr/0015-tuic-shared-control-plane.md) and
[TUIC specification](../protocol/TUIC.md).

## Third Protocol Scalability

| Addition metric | Count |
|---|---:|
| Central protocol switch cases | 0 |
| Central Engine selection branches | 0 |
| TUIC-specific Application Service branches | 0 |
| Storage protocol-specific columns | 0 |
| Account protocol-specific fields | 0 |
| ClientProfile central special cases | 0 |
| SQLite migrations | 0 |
| Upstream runtime source modifications | 0 |

Result: **PASS**. Registration entries and module-local settings/exporter checks are
not central branch dispatch. Generic action/resource switches remain; legacy Snell
HTTP response cases remain compatible. Existing optional ABI ports/typed envelopes
retain bounded code; no third stateful coordinator/resource builder.

## Shared Infrastructure

Reused from HY2: audited TLS trust/loading/private files and snapshots; minimal
Box/router/direct/DNS/static platform; owned UDP admission/health/cancellation/100ms
close grace; immutable Binding identities and session/payload meters. Shared test CA
supports explicit names; HY2's default fixture remains compatible.

New generic abstractions: CreationCodec/CreationDraft, shared envelope/password helpers,
registered CLI/API dispatch, shared resource builder/HMAC transaction coordinator,
service-owned display check, direct composition and relocated lifecycle/views/export/
Binding/plan methods. Snell/HY2 typed methods remain compatibility wrappers.

Protocol-specific code: Snell TCP/PSK/version mapping; HY2 password/service settings;
TUIC UUID/password/v5 settings/service factory and target option mappings.
Duplicated HY2/TUIC control-plane implementation: **NONE**; wire internals stay upstream.

## Capabilities

TCP/UDP payload/UDP transport/IPv4/IPv6/domain: true; MultiUserNative/PerUserStats:
true; Stats: authenticated payload and routed sessions. HotUserUpdate=false;
Users mutation=Restart; HotReload=false; listener mutation unavailable. TLS=true;
QUIC=true; Version=5. Policy quota/rate/max-session enforcement unsupported.

## Runtime

Start/Health/Stop/Restart/Recovery: PASS. UDP release/restart reuse/conflict: PASS.
Malformed datagrams do not route. Close is idempotent; forced client kill leaves
server usable; healthy shutdown releases socket. Health means owned listener/service
startup, with actual authenticated traffic qualified separately.

## Transaction

Apply/rollback/TLS failure/UDP conflict/recovery: PASS. Compile/start/health/storage
faults publish no Inbound/Account/Binding/Credential rows and clear pending state.
Invalid UUID/password/settings reject before publication. Explicit null enable flags
and null 0-RTT settings/profile options reject; adversarial unit/fuzz gates PASS. TLS pair/trust/SNI errors
compensate; UDP conflict is typed port_conflict. Admission opens after commit only.
Binding replacement failure restores committed credentials and listener; interrupted
journal recovers from SQLite. No generated JSON is authority.

## Multi-user

Alice/Bob use distinct Account/Binding/UUIDPassword rows on one Inbound: PASS.
Concurrent traffic and cross-user attribution: PASS. Unknown UUID/wrong password and
Bob UUID + Alice password fail without attributed payload. Binding disable/re-enable
interrupts only its Inbound; saved Alice credentials fail, Bob reconnects.
Disabled Account is created through production API in a separate synthetic Inbound;
both clients fail before and after recovery; exporter refuses it. No SQL mutation.
General live Account mutation remains DEFERRED.

## TLS

Trusted synthetic CA/correct SNI: PASS for all cells. Wrong SNI/untrusted CA: FAIL
as expected for both clients. Display endpoint changes leave actual Listener and SNI
unchanged. Shared private-key owner/mode/symlink/bounded-file/pair/chain/validity/SNI
validation retained; Linux tests PASS. Runtime snapshots key; private keys never
enter SQLite/client export. Windows production ACL qualification remains deferred.

## QUIC / UDP

Real authenticated QUIC transport and UDP proxy: PASS. Each user/cell returns 32
sequenced synthetic datagrams (800–831 bytes plus sequence); response equality
checked. Native datagram mode qualified; QUIC stream relay and UDP-over-stream unqualified.

## Stats

Inbound/Binding payload bytes and routed session total/active: PASS. Account identity
via Binding join: available. Durable cross-Inbound Account aggregate: DEFERRED.
4 MiB transfer grows attributed upload/download counters. Counters reset with runtime
generation; handshake/wire overhead excluded. Session cleanup PASS; no billing claim.

## ClientProfile

Public Endpoint independent of bind; typed UUID/password; explicit CA/h3/TLS/SNI;
Version=5; cubic/native/no-0RTT options. No Engine ID/upstream runtime struct/private
key/runtime JSON/policy enforcement fields. Default formatting is redacted.

## Exporters

Mihomo 1.19.30 and sing-box 1.14.1: config check + actual traffic PASS. No client
upgrade/latest. Mihomo receives UUID/password without v4 token and non-leaf CA pin;
sing-box receives verified explicit CA. Surge: UnsupportedExport. URI: DEFERRED,
no invented syntax. Explicit export is secret-returning and Binding-scoped.

## Interoperability

All 12 cells below ran on native Ubuntu-24.04 WSL2 with a race-built server and
loopback-only network namespaces. Client SHA256 values are executable hashes.

| Client | Version | SHA256 | User | Endpoint | TCP | UDP | TLS | Result |
|---|---|---|---|---|---|---|---|---|
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | 127.0.0.1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | 127.0.0.1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | ::1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | ::1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | localhost | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | localhost | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | 127.0.0.1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | 127.0.0.1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | ::1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | ::1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | localhost | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | localhost | PASS | PASS | CA + tuic.synthetic.test | PASS |

Client archive SHA256:

- mihomo 1.19.30: `cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553`.
- sing-box 1.14.1: `12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f`.

Primary pinned [Mihomo contract](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/adapter/outbound/tuic.go)
was audited; [baseline inbound](https://github.com/SagerNet/sing-box/blob/v1.14.1/protocol/tuic/inbound.go)
and dependency protocol/service/client/packet/congestion/tests determine capability.

## Stress

16 concurrent across both identities under race: PASS. 4 MiB per cell SHA256
integrity and stats: PASS. UDP32 sequence: PASS. Disconnect/reconnect and existing
client reconnect after daemon/reconcile restart: PASS. TCP reset and client force
kill: PASS. No panic/data race/deadlock; session cleanup/socket reuse PASS.

## Regressions

Snell: **PASS**, nine real client/wire/endpoint cells including TCP/UDP/stress/recovery.
Hysteria2: **PASS**, full 12-cell trusted-CA dual-user campaign with both clients.
Original sing-box: **PASS**, exact root CI tags/ldflags on native WSL2. Nested Docker
reference test module: NOT RUN per authorization. Historical extra unsafe.Pointer
vet findings remain inherited; own vet has no findings.

## Registry Architecture

Protocol Registry/Engine Registry: PASS. Phase4 directly composes modules/compilers/
exporters; old Foundation/Phase2/Phase3 tests stay. Fourth TLS/QUIC protocol expected
changes: module/codec, small pinned service factory, exporters, explicit entries,
fixtures/tests/docs; no Account/DB fields, creation dispatch/runtime Engine branches.
A different listener requires a bounded adapter, while transaction/storage stay shared.

## Storage

Schema migration: **NO**. Protocol columns: **0**. SQLite authority: PASS.
Existing schema3 UUIDPassword payload stores encrypted typed credential, without
TUIC columns. Recovery excludes disabled/unavailable identities and reconstructs
committed runtime only. Input document erased before restart tests.

## Security

Credential generation/validation/redaction/encryption boundaries: PASS. Ordinary
API/CLI/journal/error/log secret boundaries: PASS; doctor query/redaction unit
contract PASS (live doctor not separately rerun); explicit exporter only
returns authorized UUID/password. Private key protection: Linux PASS. Synthetic
fixtures only; no real NoBrand secrets. Secret/diff/protected-source audit is recorded
externally. No custom crypto or wire implementation.

## Platform

Windows Go 1.26.2: full owned unit/command tests and both builds PASS.
Linux Ubuntu-24.04 WSL2 Go 1.26.6: native unit/race/runtime/interop/root CI/both builds PASS.
arm64: both Linux command compiles PASS, execution NOT RUN. Production control
transport remains Linux; Windows is development only.

## Upstream Runtime Modifications

Count: **0**. Module/dependency files unchanged; no protocol wire/QUIC/crypto edits.
Changes confined to owned Splicore packages/scripts/fixtures and canonical docs/new report.

## Tests

Unit/race/module/credential/validation/registry/lifecycle/TLS/QUIC/transaction/recovery/
multi-user/disabled identity/stats/profile/export: PASS. Four TUIC fuzz smokes
(settings/creation/credential/export), 5 seconds each: PASS. Runtime/interop/regression/
own vet/root CI: PASS. Docs/links/OpenAPI/live response/secret/diff/index audits: PASS. 68 owned Markdown
documents, 638 local links, 28 operations and all three protocol response campaigns
validated. Both tracked and every untracked addition passed whitespace checks. Root CI uses default tags and release
ldflags; official pinned clients remain external binaries.

## Docker

Touched/queried: **NO**. Redis/TeleLedger: **UNTOUCHED**. Docker Desktop issue and old
residue: **DEFERRED EXTERNAL ENVIRONMENT CLEANUP**. No Docker cleanup/reference suites.

## NoBrand

Real changes/access: **NONE**. Synthetic migration fixture validates actual CLI/API
creation and SQLite recovery. Listener/display/UUID/password/TLS/SNI/v5/options map
is in [migration design](../integration/NOBRAND_MIGRATION.md#phase-4-synthetic-tuic-mapping).
No production extractor/importer/canary is claimed.

## Documentation

Canonical README/index/context/architecture/SDK/capability/client/engine/storage/
transaction/security/testing/interop/API/OpenAPI/migration and Phase4 workflow updated.
New ADR0015, TUIC specification and this report. Native/source snapshot verifies
all 131 owned functional files; 181 recorded owned processes have exited and
private state/TLS inputs are removed. Historical Phase0/1/2/3 reports
modified: **NONE**; archived evidence and migrations unchanged.

## Git

Implementation acceptance recorded Stage/Commit/Push/Tag/Release **NONE**, with
HEAD/main at Phase3 and index SHA256 `8eab71bd01cf9a33c7e1898fba5e019ba5cf102d1418785841ae630679aa1c56`.
The subsequent authorized local freeze uses exactly one commit containing this
finalized record: `feat(protocol): add experimental TUIC vertical slice`, whose
sole parent is Phase3. Main advances with `--ff-only`; the Phase4 branch retains
that commit. Exact commit SHA, stat, ancestry and final refs are recorded externally
at `D:\splicore-validation\phase4-freeze-20261001`. No origin/push/tag/release.

## Phase 4 freeze disposition and validation

Implementation acceptance: **TUIC VERTICAL SLICE READY FOR REVIEW**, preserved
unchanged in `D:\splicore-validation\phase4-20261001\final-acceptance.json`.
Freeze source inspection independently confirms all six architecture increments
are **0** and **THIRD-PROTOCOL SCALABILITY PASS**. Protocol/Engine/Exporter registries
remain extension points; one creation resource builder/coordinator and shared
TLS model/snapshot/UDP lifecycle/Binding meters serve HY2 and TUIC. UUID/password
use existing encrypted typed Credential; no Account fields or schema changes.
Upstream runtime/wire/other upstream protocols/dependencies/history changes: **0**.

All **131** functional source/test/script/fixture hashes equal final acceptance;
the **41** functional files in the reviewed 63-file change set remain byte-identical
through freeze. Staged text is checked against the accepted source after Git's
LF normalization. Freeze-only edits affect this report and canonical docs.
The original TUIC12/HY2-12/Snell9 full campaigns, race, four 5s fuzz gates,
arm64 compilation and exact upstream root CI remain valid and were not repeated.

Fresh native WSL2 critical smoke: **TUIC 4 cells / HY2 4 / Snell 3 PASS**, using
the checksum-verified acceptance race server and fixed clients. An external AST
runner restricts only endpoint loops to IPv4, preserving all existing assertions:
TCP/UDP, both QUIC identities, 16 concurrent, 4MiB SHA256, UDP32 (QUIC), wrong
credentials/SNI/CA, identity isolation, disabled Account creation (TUIC), Binding
reconcile, SQLite recovery, reconnect, client kill and socket release. This is
11-cell critical smoke, not a repeat of the 33-cell endpoint matrix.
**54** recorded owned processes exited; private state/TLS/config inputs removed.

Fresh Windows/Linux full owned unit/command tests, own vet and both Splicore/original
sing-box builds: **PASS**. Original builds use actual release tags/ldflags with
baseline version1.14.1; inherited vet findings remain unchanged. Targeted docs,
OpenAPI and all three accepted/smoke response schema campaigns: **PASS** (68 Markdown
documents, 639 local links, 28 operations). Complete
reviewed/staged source secret scan and whitespace/protected-source gates: **PASS**.
Historical Phase0–3 reports/evidence and archived Phase4 evidence remain unchanged.
Docker daemon not queried; Docker/Redis/TeleLedger/real NoBrand remain untouched.

Reserved next branch: `codex/phase-5-vless-reality-vertical-slice`, based on frozen
main; working tree CLEAN. Phase5 implementation: **NOT STARTED**. Stop after
branch creation. TUIC remains **Experimental v5**; freeze is local only.

## Deferred

VLESS/REALITY, Mieru, Xray, Panel, new wire protocols, real unified quota/rate,
NoBrand production canary, Stable designation, general live Account mutation,
credential rotation, durable usage aggregates, dynamic TLS, additional congestion/
relay/0-RTT profiles, licensed Surge traffic and URI grammar.

## Architecture Deviations

NONE blocking. Owned service composition follows prior HY2 admission realization;
shared extraction is bounded to control infrastructure. Native server can accept
unqualified upstream UDP stream wire while managed clients use native only. Shared
source ABI remains internal; no binary plugin compatibility promise. General live
Account mutation is deferred; production disabled creation/recovery is qualified.

## Final Result

**PHASE 4 FROZEN** locally by the commit containing this finalized record.

## Blockers

None. Experimental/deferred limits above remain explicit; no publication authorization.
