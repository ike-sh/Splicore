# Splicore Phase 10 Freeze Report

- Documentation status: Historical
- Audience: Maintainers and subsequent client outbound developers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Authorized Phase 10 checkpoint, ownership audit and Git closure.
- Lifecycle: Preserve this freeze snapshot; later implementation uses a new phase report.

## Baseline

Phase 9: `d47ef2c584654eaa8eaa965ef26b7acc24881e1f`.
Entry branch: `codex/phase-10-client-runtime-foundation`.
Entry HEAD == main == Phase 9; index EMPTY; sole existing remote upstream;
origin NONE. Working tree contains exactly the 79 accepted Phase 10 files
(51 tracked modifications, 28 new files). No unknown commit, staged change,
remote or unrelated modification was found.

The maintainer explicitly authorized exact-file staging, staged audits, one
Phase 10 commit, main fast-forward and creation of a clean Phase 11 branch.
This supersedes the implementation-stage commit prohibition for this freeze only.
Push/tag/release, history rewrite, new remotes, NoBrand changes and Docker
query/touch remain prohibited. Phase 11 implementation is not authorized here.

## Client Runtime

Status: **Experimental**. Phase 10: **FROZEN** after the authorized closure checks.
The [acceptance report](PHASE_10_CLIENT_RUNTIME_FOUNDATION_REPORT.md) remains
byte-identical as the historical **CLIENT RUNTIME FOUNDATION READY FOR REVIEW**
snapshot. Its original stage/commit NONE statements describe that acceptance time.

## Supported Client Surface

| Capability | Frozen state |
| --- | --- |
| Local SOCKS5 TCP CONNECT | SUPPORTED / Experimental; no-auth loopback only |
| Local SOCKS UDP ASSOCIATE | DEFERRED; explicit reply 7 |
| DIRECT | SUPPORTED builtin outbound through Client Runtime |
| Snell/native outbound | Experimental / SUPPORTED TCP |
| Remote Snell adapter UDP | SUPPORTED through optional adapter port, separate from local SOCKS |
| Minimal routing | Default/final outbound and local selected override |
| Advanced routing / DNS | DEFERRED |
| TUN | NOT IMPLEMENTED |

No other client outbound or qualification is added by this freeze.

## Architecture

| Invariant / gate | Evidence and result |
| --- | --- |
| Node != Outbound | PASS: separate RemoteNode/Outbound models and schema-5 tables |
| Server Account != Remote Node | PASS: separate identities and exactly-one credential owner |
| ClientProfile != Runtime Outbound | PASS: exported projection differs from committed ProfileState and ephemeral adapters |
| Protocol != Engine | PASS: Snell ProtocolID with separate native EngineID |
| Server Runtime != Client Runtime | PASS: distinct lifecycle managers under one Application |
| Server + Client single daemon | PASS: one splicore binary, API/CLI, SQLite and splicore.service |
| Immutable identity / rename | PASS: references use IDs; node/outbound rename preserves routes and credentials |
| Credential abstraction | PASS: node-owned generic encrypted PSK; no RemoteNode PSK field or snell_psk DB column |
| Snell roles | PASS: one snell ProtocolID, inbound + outbound roles; other protocols/Xray inbound only |
| Version mapping | PASS: canonical snell.ClientVersion reused by exporter and adapter; server5→client4,6→6 |
| Outbound registry | PASS: immutable exact (protocol, engine) factory lookup; DIRECT builtin, not ProtocolID |
| Unsupported pair | PASS: snell/xray explicitly rejects without native fallback |
| SQLite authority | PASS: schema 5 reconstructs client intent on restart; generated native options are artifacts |
| Minimal route snapshot | PASS: atomic immutable generation; session data path does not query SQLite |
| CLI / API | PASS: Application commands and existing /api/v1; no direct CLI SQL writes |
| Doctor | PASS: passive counts, listener/route/outbound health; no active node scanning |

Source boundaries: [client domain](../../internal/splicore/domain/client/client.go),
[application commands](../../internal/splicore/application/client.go),
[runtime](../../internal/splicore/clientruntime/runtime.go),
[registry](../../internal/splicore/registry/outbounds.go),
[native adapter](../../internal/splicore/engine/native/snell_outbound.go) and
[ADR 0022](../adr/0022-client-runtime-domain.md).

## Scope Audit

| Category | Owned changes |
| --- | --- |
| A. Remote Node domain | RemoteNode, endpoint/options/metadata validation and generic remote credential owner |
| B. Client Outbound | Independent Outbound identity and exact factory registry |
| C. Local Inbound | Loopback SOCKS5 listener and canonical local resource |
| D. Minimal Route | Default/selected references and immutable generation selection |
| E. Client Runtime lifecycle | Prepare/abort/activate, session lifetime, stop/restart/recovery |
| F. Snell adapter | Embedded inherited outbound and shared canonical version mapping |
| G. DIRECT | Builtin real TCP dialer in the same client data path |
| H. Transactions | Shared revision/HMAC/journal, commit-before-admission and compensation |
| I. Stats | Atomic local/outbound/node/session observations and passive health |
| J. API | Client CRUD/lifecycle in /api/v1 and OpenAPI |
| K. CLI | Existing splicore commands and control transport |
| L. Doctor/support | Unified passive diagnostics and eighth redacted client projection |
| M. Tests | Domain, vault/migration, transactions, E2E, ownership, race/fuzz and installed smokes |
| N. Docs/ADR | Canonical client/routing/security/storage/API/operations/test contracts and ADR 0022 |
| O. Phase 10 reports | Preserved acceptance snapshot and this freeze report |

Functional changes stay in owned internal/splicore, cmd/splicore tests and scripts.
Freeze adds only status/navigation/ADR documentation and this report.
No generated binaries, archives, runtime DB/config/keys, support bundles, logs,
caches, source copies or validation directories enter the commit.

## Acceptance

| Gate | Result |
| --- | --- |
| Accepted installed server traffic | **48/48 PASS**, Source Match verified |
| Accepted installed client traffic | **90/90 PASS**, Source Match verified |
| Fresh installed initial/restart server smoke | **16/16 PASS** |
| Fresh installed initial/restart client smoke | **30/30 PASS** |
| SOCKS→DIRECT / SOCKS→Snell | **PASS**, actual client data path |
| Server + Client simultaneous traffic | **PASS** |
| 16 concurrent / 4 MiB SHA256 integrity | **PASS** |
| Reconnect / abnormal local and remote close | **PASS** within inherited EOF contract |
| Remote offline isolation | **PASS**: DIRECT/server/API/CLI survive; passive error state |
| Service restart / SQLite restore | **PASS** |
| Port conflict / missing credential / invalid node / unsupported pair | **PASS**: clean rejection and preserved committed state |
| Startup / commit failure compensation | **PASS** |
| Transactional client restart | **PASS**: failed commit preserves session/revision; success advances once and closes old sessions |
| Linux complete owned tests / build / vet | **PASS** |
| Windows complete owned tests / build / native E2E | **PASS** |
| Default race/checkptr | **PASS**, no suppressions |
| Minimal ownership reproducer 10x | **PASS** |
| Affected shared package race | **PASS** |
| Five bounded fuzz targets | **PASS** |
| Server protocols / distribution regression | **PASS**, accepted six-stage evidence plus fresh installed restart smoke |
| Docs / links / OpenAPI / fresh live schemas | **PASS** |
| Secret, scope, whitespace and staged audits | **PASS** |

Server coverage retains Snell, HY2, TUIC, VLESS Native, VLESS Xray,
FinalMask/Sudoku and Mieru TCP/UDP. Accepted six-stage installation coverage
includes initial, restart, crash recovery, upgrade, failed migration rollback
and retained-state reinstall, plus safe purge, non-root low ports and unrelated
Xray survival. Source Match permits reuse of these 138 accepted cells.

4 MiB SHA256: `3cab7815c40973b8fb036c7a2a69b3649882622a4a0a2f1a980efa4ef8545577`.
Inherited Snell command-1 EOF/half-close may close its tunnel. Fixed-length full
duplex tests verify all bytes before closing the application connection; no new
full duplex EOF capability is claimed.

## Ownership Fix

Retired adapter: an immutable generation owns the adapter; each session holds
a reference acquired under the narrow route lock. Atomic publication retires
the manager reference; the adapter closes only at the last release.

Connection Close: the session cleanup first closes local/remote connections,
then releases its generation, then removes the session and notifies idle waiters.
Conn.Close may return resources to an adapter/pool, so that adapter must remain
alive throughout final connection cleanup. Both payload workers finish before
this final cleanup. Remote assignment/close uses the session bookkeeping lock.

The [minimal reproducer](../../internal/splicore/clientruntime/runtime_test.go)
uses real localhost SOCKS/TCP and a tracking adapter. The prior source fails
with one unclosed connection at adapter retirement; final source passes ten
times under default race. This is Splicore Client Runtime ownership correctness.
Per-direction buffers, atomic counters/health and immutable state preserve
lifetime without a global payload mutex, sleep/retry masking, panic recovery,
sanitizer disabling, skipped tests or protocol changes. Wire changed: **NO**.
Server lifecycle regression: **PASS**.

## Acceptance Source Match

Entry's complete **1935** source files match the final accepted manifest and
source archive byte-for-byte. Digest:
`1105f3058b7be56a1990e75c7d25bd60ba156bff9ccacfcf86e460a8777c2ba2`.
The three inherited client submodule Git entries are unchanged and are not source
files in that manifest. Final review-a/review-b/review-repeat artifact SHA256s,
archive provenance, ownership test hashes and six-stage traffic records verify.

Freeze changes only six existing documentation files and adds this report;
runtime, tests, scripts, migrations, binary composition and unit bytes retain
their accepted identities. Fresh service smoke uses the exact final accepted
review-a artifact. Fresh builds/package inventory cover final freeze source,
with its separate manifest recorded externally. Precommit artifact provenance
honestly records Phase 9 HEAD and source_dirty:true; no public release is made.

## Security

SOCKS default: **loopback**, actual 127.0.0.1 and ::1 traffic PASS.
Unauthenticated wildcard/LAN/domain listen hosts reject.
Generic API stored-secret leak: **NO**. Doctor secret leak: **NO**.
Support bundle secret leak: **NO**, eight decompressed allowlisted projections.
Adversarial tests retain Snell PSK, HY2/TUIC/Mieru passwords, VLESS UUID,
REALITY private key and API token gates; installed synthetic scans also pass.
Staged scan distinguishes explicit synthetic test/localhost fixtures from
production credentials. No real key, runtime DB or credential artifact is staged.

## Stats

LocalInbound, Outbound, Node and ClientSession observations: **SUPPORTED**.
They describe the same successful payload through several dimensions and must
not be summed as billing usage. Counters are ephemeral; persistent commercial
usage, strict quotas/rates and accounting remain **DEFERRED**.

## Platform

Linux amd64 Ubuntu 24.04 WSL2: Client Runtime fully accepted within current
**Experimental** scope; Go 1.26.6. Windows amd64: Go 1.26.2 build/tests and actual
native client E2E PASS; Windows service/production UDS is not qualified.
Linux arm64: **compile only**, not runtime certified.

The owned nested systemd lab's outer init teardown again reaches the existing
20-second timeout after successful product gates. MainPID is zero and the owned
cgroup is empty; failed-unit bookkeeping is reset. Clean outer-init termination
is not claimed. No product test condition is relaxed.

## Runtime Audit

sing-box upstream runtime source: **0 modifications**.
Mieru source: **0 modifications**. Xray source/artifact: **0 modifications**.
Wire: **0 modifications**. New product binary/service: **0**.
Historical Phase 0–9 reports, original Phase 10 acceptance report and migrations
0001–0004: **UNCHANGED**. Schema 5 is the legitimate client intent migration.
NoBrand HEAD/status/145 tracked-file hashes: **UNCHANGED**.
Docker: **UNTOUCHED / NOT QUERIED**. No external system traffic or downloads.

## Commit

Exactly **ONE** authorized Phase 10 commit contains this report.
Message: `feat(client): add client runtime foundation`.
Sole parent: `d47ef2c584654eaa8eaa965ef26b7acc24881e1f`.
PHASE_10_COMMIT: resolve
`git rev-parse codex/phase-10-client-runtime-foundation`.
Its own SHA cannot be embedded in the same commit; full SHA and actual
file/insertion/deletion counts are recorded externally and in the final answer.
No amend, merge commit or rewritten history.

## Git

Final equality: main == Phase 10 == Phase 11 HEAD == PHASE_10_COMMIT.
main moves only by `git merge --ff-only codex/phase-10-client-runtime-foundation`.
Working tree: **CLEAN**. Index: **EMPTY** after closure.
Unrelated refs/remotes/tags remain unchanged.

## Remote / Release

origin: **NONE**. Sole existing upstream remote unchanged.
Push: **NONE**. Tag: **NONE**. Release: **NONE**.

## Phase 11

Branch: `codex/phase-11-client-outbound-expansion`.
Base: **PHASE_10_COMMIT**. Working tree: **CLEAN**. Index: **EMPTY**.
Implementation: **NOT STARTED**. Branch creation is the final action of this freeze.

## Deferred

Local SOCKS UDP; HY2, TUIC, VLESS Native, VLESS Xray and Mieru outbounds;
advanced routing, DNS engine, policy groups, TUN, subscriptions/providers,
active health probing, persistent commercial usage, arm64 runtime qualification
and NoBrand migration. Existing server feature deferrals remain unchanged.

## Evidence

Acceptance: `D:/splicore-validation/phase10-20261002`.
Freeze: `D:/splicore-validation/phase10-freeze-20261003`.
Owned native service lab: `/root/splicore-p10-freeze-20261003/service-lab`.
Source Match, full manifests, commands/toolchains/logs, fresh 46 installed cells,
live schemas, redacted support archive, scope/secret/staged audits, package
provenance and final Git closure remain external. Owned processes are stopped;
cleanup records include the outer-init limitation above. Prior evidence is preserved.

## Final Result

**PHASE 10 FROZEN** after the authorized single commit and Git closure checks.

## Blockers

None within the bounded Experimental Phase 10 scope.
