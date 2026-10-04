# Splicore Phase 13 Freeze Report

- Documentation status: Historical
- Audience: Maintainers and subsequent client-management developers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Authorized Phase 13 checkpoint, source match and Git closure.
- Lifecycle: Preserve this freeze snapshot; subsequent work uses a new phase report.

## Baseline

Phase 12: `d09f5f10797aa63798419fa77ffd676257f1b609`.
Entry branch: `codex/phase-13-tun-system-integration`; HEAD == main == Phase 12.
Index EMPTY; working tree contained exactly the 146 accepted Phase 13 paths.
origin NONE; existing upstream remote unchanged. No unknown baseline commit.
The maintainer explicitly authorized exact-file staging, one Phase 13 commit,
main fast-forward and creation of the clean Phase 14 branch, then immediate stop.
No history rewrite, push, tag, release, developer-host network or NoBrand changes.

The three acceptance reports remain byte-identical to the final review snapshot:
[TUN integration](PHASE_13_TUN_SYSTEM_INTEGRATION_REPORT.md),
[Windows closure](PHASE_13_WINDOWS_BLOCKER_CLOSURE_REPORT.md) and
[underlay closure](PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md).
Their READY FOR REVIEW and no-stage/commit/freeze statements describe acceptance
time; this separately authorized freeze records the subsequent checkpoint.

## Status

| Capability | Frozen actual scope |
| --- | --- |
| TUN | Experimental; official gVisor/sing-tun adapter, IPv4/IPv6 TCP/UDP in owned WSL namespaces |
| HTTP Local Proxy | Loopback CONNECT and one-request plain HTTP, bounded headers and stripped proxy/hop fields |
| Mixed | Loopback shared SOCKS5/HTTP ingress through the existing client graph |
| System Proxy | Typed default-LAN WinINET ownership/exact restore implementation PASS in fixtures; real activation guarded |
| DNS Interception | Shared managed UDP/53 and TCP/53 engine; host DNS settings unchanged |
| Auto-route | Opt-in Linux dual-stack journaled UID/mark/main-table rules; real Windows unavailable/fail closed |
| IPv4 / IPv6 / domain | Qualified TCP/UDP through DIRECT and six frozen outbound pairs within reported fixtures |
| FakeIP / DoH | DEFERRED; no transparent HTTPS/DoH interception |

All capabilities remain Experimental. No Stable release or platform certification
is created by this freeze. SOCKS/HTTP/mixed default to literal loopback; no LAN
open-proxy default. Ordinary client/server modes require no new NET_ADMIN/root
privilege. TUN uses the existing service with an explicit capability drop-in and
dedicated non-login UID; no extra daemon/service or network stack.

## Underlay

Production egress Unknown: **0**. Reviewed static inventory: 61 production
construction/delegation surfaces and 112 test-only surfaces. The earlier lexical
inventory used a different counting method and remains preserved.

| Surface | Result / frozen protection |
| --- | --- |
| DIRECT | PASS; TCP/UDP socket protection after logical selection, both families/domain |
| DNS upstream | PASS; protected direct provider or selected protected outbound/group |
| Bootstrap | PASS; explicit TUN-independent root before dependent runtime construction |
| Health / URL-Test | PASS; selected protected outbound and safe bootstrap |
| Native Client | PASS; Snell/HY2/TUIC/VLESS plain/TLS/REALITY, including QUIC UDP socket Control |
| Native Server | PASS; explicit protected final target TCP/UDP for Snell/HY2/TUIC/VLESS |
| Mieru | PASS; official v3.38.0 Dialer/PacketDialer/Resolver hooks and protected server targets |
| Xray | PASS for Linux verified inherited UID/main-table plan; required unavailable platforms FAIL CLOSED |

Logical flow remains ingress → Routing/DNS/Policy → selected runtime action →
underlay protection → physical network. Protection does not choose DIRECT, switch
outbounds or change DNS policy. Typed Factory/Scope/Purpose capabilities enforce
construction, including explicit no-TUN providers. Reviewed local/control/test
socket exemptions do not acquire physical bypass routes. Arbitrary DIRECT/server
target destinations are not kept as persistent route or browsing-history records.

Linux uses mature socket RoutingMark plus journaled dedicated daemon UID/main-table
rules and readback. Windows combines the existing interface-binding primitive with
bounded infrastructure leases/reconciliation through the production contract;
actual adapters run with a stateful fake Windows backend. The real Windows provider
and activation guards remain fail closed. Required unsafe system stubs, independent
Windows System API/mDNS paths and unverified child DNS reject. Explicit safe DNS
retains original semantics and DoT SNI. No-TUN behavior and privilege remain unchanged.

Xray v26.3.27 / commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`
and Phase 6 artifacts are unchanged. EngineUnderlayPlan binds the actual child
generation/PID exactly once; preflight and health verify protection. Sole process
Wait and socket/relay retirement precede release, including Bind-after-launch
failure. The isolated kernel matrix exercises actual client children with a
localhost proxy; it is not a separate non-loopback Xray server-target capture
qualification. Server plan/ownership, pinned protocol regressions and inherited
Linux UID rule evidence retain the precise acceptance scope.

## Dynamic Reconciliation

DNS re-resolution: PASS. New protection before publish: PASS. Old connection:
PASS. Old lease retirement: PASS. Shared endpoint refs: PASS. Reused TUN: PASS.

At reconciliation, fresh immutable bootstrap results enter the adapter reuse key.
IP1→IP2 provisions/readbacks new protection, publishes C2 while C1 survives and
retains IP1 until the final old adapter/socket reference retires. Failed resolution
or provisioning preserves the old working graph and compensates only candidate
ownership. Two actual adapters and two Mieru SDK runtimes retain shared protection
until the final owner closes. Synthetic infrastructure IPs carry no external traffic.

TUN interface/host generation, client snapshot, underlay lease, route/DNS snapshot
and actual Xray child generation/PID have separate lifetimes. Reusing unchanged TUN
identity reconciles node/DNS/outbound updates without device recreation. UDP/QUIC/
resolver references follow association/runtime/socket lifetime rather than each
packet/query/stream. Removal from new selection precedes worker/session retirement
and protection release. Cleanup failure retains protection/debt, degrades health
and is reported by shutdown. Narrow metadata/reconciliation locks do not serialize
payload I/O; buffers and borrowed payload copies retain per-connection ownership.

## Wintun

Implementation blocker: **CLOSED**. Partial failure: PASS. Ownership: PASS.
Real runtime: **NOT CERTIFIED**. Durable exact GUID/generation/owner precedes creation;
partial adapter/session handles remain owned through rollback and debt. Double
cleanup and pre-existing adapter safety PASS. Close interrupts/joins ring I/O,
copies borrowed payload before asynchronous use and never reopens admission after
session stop, even when later handle cleanup fails. Exact GUID/service orphan
recovery and ABI/symbol checks remain fixture-qualified; no real driver/adapter runs.

## WinINET

Implementation blocker: **CLOSED**. Exact restore: PASS. External mutation: PASS.
Real runtime: **NOT CERTIFIED**. Typed supported default-LAN manual/bypass/PAC/
autodetect intent, durable setter intermediates and ordered notifications preserve
A→B→A; external C remains intact with conflict/debt. Partial failures, crash,
notification and double restoration fixtures PASS. No registry write fallback or
destructive developer-host validation is introduced.

## Journal

Ownership: PASS. Crash reconciliation: PASS. Corrupt journal: PASS/fail closed.
Canonical authority: **SQLite**, schema 7 desired state. The private network journal
is bounded operational recovery state, not canonical configuration. Persist/fsync/
atomic replace and exact resource readback precede mutation/publication; unknown
scope/version/corruption rejects with degraded diagnostics, never broad reset.

Crash recovery combines recorded ownership, observed state and canonical desired
configuration. Stale generation cleanup never invents refs to dead sockets/PIDs.
Borrowed/pre-existing routes/adapters/proxy state and external mutations are
preserved. Real isolated Linux process recovery and portable failure injection PASS;
real Windows crash recovery is NOT CERTIFIED. Uninstall/purge stop and restore as
the original service UID before removing program/state, retaining recoverable debt
on failure. No journal chown, route flush or guessed adapter-name deletion.

## Scope Audit

| Category | Phase 13 owned changes |
| --- | --- |
| A. TUN Local Inbound | Typed model, official stack adapter, shared immutable ingress/session lifecycle |
| B. Host Route Manager | Exact owned/borrowed CRUD, readback and conflict-preserving reverse restoration |
| C. DNS interception | Shared TCP/UDP53 handling and copied borrowed callback payload |
| D. HTTP/Mixed | Loopback CONNECT/plain HTTP/SOCKS dispatch and bounded parsing |
| E. System Proxy | Typed host intent, owned listener readiness and exact restoration |
| F. Windows Wintun | Split partial adapter/session ownership, joined I/O and exact orphan identity |
| G. WinINET ownership | Supported typed LAN snapshot, external C and durable partial states |
| H. Network Mutation Journal | Private operational schema 1/2, bounded persistence/recovery and debt |
| I. Underlay Protection | Daemon-shared typed capabilities and platform verification |
| J. Runtime Dialer Factory | Mature native registries/NetworkManager and protected socket/resolver hooks |
| K. Endpoint Leases | Bounded infrastructure effective set and last-reference release |
| L. Generation/Reconciliation | Fresh resolution, retained snapshots, shared refs and reused TUN |
| M. Xray integration | Verified inherited process plan, actual generation/PID and sole Wait ownership |
| N. Mieru integration | Official SDK client/server TCP/UDP/Resolver hooks and joined ownership |
| O. Egress wiring | DIRECT, DNS/health, native client and server final-target call graph |
| P. API/CLI/Doctor | Generic host resources, underlay status and redacted diagnostics |
| Q. Distribution | Same-service optional TUN profile, recovery before uninstall/purge and schema-7 provenance |
| R. Tests/failure injection | Actual adapter spies, dynamic/shared/reused fixtures, race/10x/fuzz/kernel/service |
| S. Docs/ADR | Canonical frozen boundary and accepted ADR0027–0031 |
| T. Phase 13 reports | Preserved acceptance snapshots plus this freeze record |

Freeze changes documentation only. Accepted functional code/tests/scripts/package
logic and migration 0007 remain byte-identical before staging. No validation logs,
DB, route snapshots, private journal, bundle, key, binary, driver or fuzz artifact
enters the explicit stage list.

## Acceptance

| Gate | Result / evidence |
| --- | --- |
| Race/checkptr | PASS; fresh full owned/cmd tagged default race, no suppression |
| Shared race | PASS; fresh common/dialer, DNS/route, DIRECT/Snell/HY2/TUIC/VLESS and clientio |
| 10x | PASS; fresh underlay/host fixtures and safe real kernel TUN cycles |
| DIRECT/client/server underlay smoke | PASS; actual runtime/fake Windows socket observations |
| DNS/bootstrap/health | PASS; safe resolver/DoT SNI, dependency rejection and actual HTTP probes |
| Dynamic/shared/reused/retirement | PASS; production manager fixtures, preserved C1 and failure rollback |
| Xray/Mieru ownership | PASS; actual child plan/Wait and official SDK transport/worker lifetime |
| TUN safe tests | PASS; fresh isolated IPv4/IPv6 TCP/UDP six-outbound kernel campaign |
| Routing/DNS/Policy | PASS; fresh complete suites and installed A–H canonical scenarios |
| Server regression | PASS; Snell/HY2/TUIC/VLESS Native/Xray/FinalMask/Sudoku/Mieru |
| Client regression | PASS; SOCKS TCP/UDP, six adapters, HTTP/mixed and no-TUN behavior |
| Windows ordinary tests/build | PASS; fresh complete safe native tests and build |
| Linux/three-platform build | PASS; local Linux amd64/arm64 and Windows amd64 candidate |
| Fuzz/vet | PASS; five bounded race-enabled underlay/host targets, no real host fuzz |
| Distribution regression | PASS; fresh install/restart/crash/upgrade/rollback/uninstall/reinstall/purge |
| Docs/links/OpenAPI/live schemas | PASS; static plus fresh installed API/CLI stage snapshots |
| Secret/privacy/scope/staged/whitespace | PASS; allowlisted fixtures, redacted diagnostics and exact explicit source |

Named freeze gate `.json/.log`, package manifests and fresh service evidence are
under `D:/splicore-validation/phase13-freeze-20261004`. Earlier final acceptance is
preserved. The kernel wrapper launches Python; its log/harness prove the nested Go
test binary uses -race/default checkptr even when the wrapper metadata says race
not requested. No skipping, panic recovery, sanitizer suppression or sleep/retry
masking. Existing deterministic fixture corrections are reused without weakening
restoration assertions. Kernel DNS leak counters remain UDP=0/TCP=0.

Ten repeats cover dynamic DNS, old/new retirement, shared endpoints, reused TUN,
Xray underlay and Mieru lifecycles plus complete hostnetwork activation/cleanup.
Kernel ten start/stop cycles include actual Xray client-child reconstruction.
Lease/route refs return to zero, Mieru protocol workers exit, owned sockets/workers
close/join and child Wait completes. Installed lab cleanup has zero processes and
empty cgroup. Outer nested init timeout bookkeeping remains an explicit limit;
graceful outer-init exit is not claimed.

Distribution includes Phase 12 schema 6→7, failed schema-8 migration rollback,
original UID/hardening, unrelated Xray preservation and active TUN removal/reinstall/
stale-journal purge. Exact routes/rules/DNS restoration PASS. Before-upgrade snapshots
use pinned Phase 12 schema; candidate upgrade/rollback/reinstall and TUN/host live
responses use current schema without weakening required fields.

## Acceptance Source Match

Accepted 345-file functional manifest SHA256:
`5b94721c1926f832d1ca87ade8a730d7bc606294c46cedd395fd11ca4b9a4576`.
Accepted packaged source digest:
`6490ec8e8592a6317eddedc0d7f59d8023c6372fc120c17b255429146b6241fc`.
Entry source equals the accepted final audit, with the prior seven documented
post-package doc differences. Every functional file matches accepted manifest and
archive provenance. Freeze documentation edits have an explicit allowlist.

The final staged whitespace gate removed the source-audit document's extra EOF
blank line and clarified its obsolete underlay wording. This report records that
post-package documentation correction; both changed documents are listed in the
final audit. Packaged functional source remains exact and installed acceptance is
unaffected; these final doc revisions are not claimed to be embedded in the archive.

Fresh local freeze package/source provenance captures the completed docs; its
separate digest is in external package/source manifests. Repeated Linux amd64 and
source archives reproduce. Precommit artifacts honestly record Phase 12 HEAD and
source_dirty=true. Existing core.autocrlf=input normalizes CRLF to LF in Git text
blobs; staged/committed bytes are checked against normalized accepted source and
archive bytes, with any checkout-only normalization listed externally. No Git
configuration or functional behavior changes to manufacture a source match.

## Safety

Developer Windows network modified: **NO**. Real destructive Windows validation:
**NONE**. No route/DNS/WinINET/Wintun/adapter/driver/reset/reboot mutation.
Linux mutations stay inside owned disposable namespaces/nested labs; all DNS,
echo and reference targets are owned/local. Docker/Redis/TeleLedger not queried
or touched; NoBrand unchanged and not accessed.

Repository/staged source and evidence/support projections pass secret review.
Explicit synthetic local fixtures remain classified. No real proxy credential,
REALITY private key/API token, runtime config/key or private artifact is staged.
Underlay status/doctor/support expose strategy, generation IDs, bounded counts and
redacted error classes, never complete user destination history or permanent
per-destination metrics. SQLite remains encrypted desired-state authority;
operational journals and child configs stay private.

## Platform

| Platform/surface | Frozen qualification |
| --- | --- |
| Windows ordinary tests/build | PASS |
| Windows full race | NOT EXECUTED |
| Windows real TUN | NOT CERTIFIED; activation FAIL CLOSED |
| Windows real auto-route | NOT CERTIFIED; activation FAIL CLOSED |
| Windows real WinINET | NOT CERTIFIED; activation FAIL CLOSED |
| Native Ubuntu host networking | DEFERRED |
| WSL2 Ubuntu 24.04 amd64 | Safe isolated kernel/race/service qualification only; PASS |
| Linux arm64 | BUILD ONLY / runtime NOT CERTIFIED |

WSL evidence does not certify native Ubuntu host networking, arbitrary VPN/roaming,
physical interfaces or abrupt power loss. Windows fake backend PASS proves owned
implementation, not destructive platform traffic/restore. Required unsafe System
DNS/unavailable child protection continue to reject. Full Windows race is not
silently replaced by ordinary tests.

## Runtime Audit

sing-box: **0**. Mieru: **0**. Xray: **0**. Wire: **0**.
Dependencies: **0 unexpected**. Frozen migrations 0001–0006 and accepted new
migration 0007 unchanged. Phase 0–12 historical reports unchanged. NoBrand unchanged;
Docker untouched. Exact original/staged/committed paths, hashes and A–T scope are
recorded externally; no upstream/wire/protocol/dependency path enters staging.

## Commit

Status: **CREATED** after gates, as the single authorized Phase 13 commit.
Message: `feat(client): add TUN and system integration foundation`.
Sole parent: `d09f5f10797aa63798419fa77ffd676257f1b609`.
PHASE_13_COMMIT: resolve `git rev-parse codex/phase-13-tun-system-integration`.
The same commit cannot embed its own SHA; full SHA and actual files/insertions/
deletions are recorded externally in `commit.json`/`final-freeze.json` and final reply.
No amend, rewritten history or merge commit.

## Git

main == Phase13: **TRUE**, at PHASE_13_COMMIT after
`git merge --ff-only codex/phase-13-tun-system-integration`.
Working tree **CLEAN**; index **EMPTY**. Unrelated refs/tags/remotes unchanged.
origin **NONE**. Push **NONE**. Tag **NONE**. Release **NONE**.

## Phase 14

Branch: `codex/phase-14-client-management-providers`.
Base: **PHASE_13_COMMIT**. Implementation: **NOT STARTED**.
Branch creation is the final authorized mutation; only read-only final checks and
external evidence recording follow. Stop before Subscription/Provider implementation.

## Deferred

Windows destructive qualification, native Ubuntu host-network qualification,
arm64 runtime, Windows full race, DoH, FakeIP, Geo, Subscriptions, Providers,
NoBrand migration, Vision, client FinalMask/Sudoku, Xray TCP half-close qualification
and existing roaming/power-loss/server enforcement deferrals.

## Final Result

**PHASE 13 FROZEN** after all gates and the authorized single-commit Git closure.

## Blockers

None within the qualified Experimental Phase 13 scope. Platform qualifications
remain limited as above; they do not enable unsafe Windows activation.
