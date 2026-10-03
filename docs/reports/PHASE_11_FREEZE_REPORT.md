# Splicore Phase 11 Freeze Report

- Documentation status: Historical
- Audience: Maintainers and subsequent routing/DNS developers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Authorized Phase 11 checkpoint, source match and Git closure.
- Lifecycle: Preserve this freeze snapshot; later work uses a new phase report.

## Baseline

Phase 10: `463cb8ea4fc497d684b0f4ff8923015009d1187e`, read from actual Git history.
Message: `feat(client): add client runtime foundation`; sole parent Phase 9
`d47ef2c584654eaa8eaa965ef26b7acc24881e1f`. That commit contains the historical
[Phase 10 freeze report](PHASE_10_FREEZE_REPORT.md).

Entry branch: `codex/phase-11-client-outbound-expansion`. Entry HEAD == main ==
Phase 10; working tree contains exactly accepted Phase 11 changes; index EMPTY.
origin NONE; sole existing upstream remote unchanged. No unknown baseline commit.
The maintainer explicitly authorized exact-file staging, one Phase 11 commit,
main fast-forward and creation of a clean Phase 12 branch, then immediate stop.
No history rewrite, push, tag, release, NoBrand change or Docker query/touch.

## Client Runtime

Status: **Experimental**. Phase 11: **FROZEN** after the authorized closure gates.
The [acceptance report](PHASE_11_CLIENT_OUTBOUND_EXPANSION_REPORT.md) remains
byte-identical as the **CLIENT OUTBOUND EXPANSION READY FOR REVIEW** snapshot;
its original stage/commit NONE statements describe acceptance time.

## SOCKS

TCP CONNECT: **SUPPORTED**. Standard UDP ASSOCIATE: **SUPPORTED**.
Default bind: **loopback**, including actual 127.0.0.1 and ::1 traffic.
Unauthenticated wildcard/LAN/domain listen hosts reject. DIRECT remains builtin.

Each UDP association owns its TCP control connection, loopback relay and at most
32 target flows. Peer IP and requested/first-valid source port isolate clients;
invalid RSV/FRAG packets discard before admission. Independent request/response
buffers and copied pool encoding preserve payload lifetime. EOF, timeout, changed
route/adapter and shutdown close sockets and join workers before releasing the
generation. Idle expiry is two minutes. Cross-client leakage and stale ownership:
**NONE in qualified tests**. IPv4/IPv6/domain target traffic and cleanup PASS.

## Outbounds

All entries below are actual payload traversal, not compile-only claims.

| Protocol / engine | TCP | UDP | IPv4 | IPv6 | Domain | Frozen scope / limitations |
| --- | --- | --- | --- | --- | --- | --- |
| Snell / native | PASS | PASS | PASS | PASS | PASS | Existing v5/v6 mapping; UDP domains resolve per-flow locally |
| Hysteria2 / native | PASS | PASS | PASS | PASS | PASS | Static TLS, password, inherited QUIC; remote UDP resolution |
| TUIC v5 / native | PASS | PASS | PASS | PASS | PASS | Static TLS, UUID/password, cubic/native UDP; remote UDP resolution |
| VLESS / native | PASS | PASS | PASS | PASS | PASS | Flow none, plain/static TLS/REALITY, XUDP; Vision rejects |
| VLESS / xray | PASS | PASS | PASS | PASS | PASS | Flow none, plain/static TLS/REALITY; client masks deferred; half-close unqualified |
| Mieru / native | PASS | PASS | PASS | PASS | PASS | Official v3.38.0, username/password, TCP/UDP underlays; UDP domains resolve per-flow locally |

Every client capability remains Experimental. No public Stable certification.

## Acceptance

| Gate | Result / evidence |
| --- | --- |
| Six outbound real TCP/UDP traffic | PASS, fresh installed six campaigns, 24 adapter/target cells per campaign |
| Reference traffic | PASS, seven reference cells per campaign; pinned existing clients/servers |
| SOCKS TCP / UDP critical smoke | PASS, actual runtime traversal |
| Server + Client coexistence | PASS, eight frozen server inbounds with all client pairs |
| 16 TCP + 16 UDP / 4 MiB integrity | PASS per adapter in accepted source and installed campaigns |
| Reconnect / abnormal close / credentials | PASS within documented inherited stream contract |
| Default full owned race / checkptr | PASS, fresh Linux CGO-enabled run; no suppressions |
| Affected shared race | PASS, fresh common/protocol/adapter run |
| SOCKS UDP lifecycle/source ownership 10x | PASS, fresh default race run |
| Mieru / native worker / Xray lifecycle 10x | PASS, source-identical accepted records verified |
| Mieru owned lifecycles | PASS, accepted 200-lifecycle stack/socket exit gate |
| Windows complete tests / build | PASS, fresh runs; accepted VLESS matrix 10x verified |
| Linux tests / build / vet | PASS, fresh default race tests, build and vet |
| Three bounded fuzz targets | PASS, fresh canonical node, REALITY public options and SOCKS UDP parsing |
| Installed service recovery / offline isolation | PASS, fresh restart and SQLite reconstruction |
| Install / crash recovery / upgrade / failed migration rollback / reinstall / safe purge | PASS, fresh disposable systemd lab |
| Package / source reproducibility | PASS, identical repeated local Linux amd64 artifact and source archive |
| Docs / links / OpenAPI / live API and CLI schemas | PASS, fresh checks and six adapter status projections |
| Secret / scope / whitespace / staged audit | PASS |

Earlier six-campaign final acceptance is preserved externally. Fresh service smoke
uses the exact accepted final-a/final-b packages after functional Source Match.
Invalid credential validation and failed commit preserve old committed adapters;
a syntactically valid credential unknown to the remote reports runtime failure
until explicit valid rotation. Remote offline isolation keeps other outbounds,
server runtimes and API/CLI healthy. No new hard dependency on a remote server.

## VLESS

Native flow-none: **SUPPORTED**. Xray flow-none: **SUPPORTED**.
REALITY: **PASS** across both server and client engine placements, with public key,
short ID and server name. Plain and explicit-CA TLS TCP/UDP also PASS. Explicit CA
is exclusive in Xray (`disableSystemRoot`), including Windows. Wrong UUID/key/
short ID/SNI and untrusted CA reject; valid recovery passes.

Vision: **DEFERRED / UNSUPPORTED**, rejected before construction on both client
engines; [ADR 0017](../adr/0017-defer-vision-dependency-safety.md) continues to apply.
FinalMask/Sudoku client: **NOT IMPLEMENTED / DEFERRED**. Phase 7 server capabilities
retain their qualified scope; an Xray outbound does not inherit them.
Xray TCP half-close: **NOT QUALIFIED / DEFERRED BEHAVIOR QUALIFICATION**.
Ordinary payload PASS does not certify full TCP EOF semantics. The private stream
does not expose raw socket CloseWrite as an end-to-end contract.

## Architecture

| Invariant / metric | Result |
| --- | --- |
| Outbound registry | Immutable exact `(protocol, engine)` factory lookup |
| Central client protocol switches added | 0 |
| Application protocol branches added | 0 |
| Protocol-specific Node secret fields | 0 |
| Protocol-specific DB columns / new migrations | 0 / 0; frozen schema 5 retained |
| New upper Engine IDs | 0; five native protocols use existing Native Engine |
| New process supervisors / client services | 0; original Xray Engine/Handle/owner/reaper reused |
| Protocol != Engine | `ProtocolID=vless`, `EngineID=native` or `xray`; no split protocol IDs |
| Credentials | Existing generic node-owned encrypted Credential abstraction |
| API / CLI | Unified node/outbound resources and commands; no per-protocol resource families |
| Capabilities | Separate server/client role, protocol/engine, transports, flow and qualification |

Adapter leases are per effective canonical settings/credential ID. Immutable
generations retain session references; unchanged adapters survive reconcile,
changed UDP routes close and join affected associations, and abort releases only
candidate refs. Retired lease health cannot alter a replacement. Pending dials and
socket registration order against Close under a narrow owner lock; payload I/O
does not take a global mutex. Separate per-adapter native boxes own pools and
runtime contexts. Official Mieru APIs own protocol state; Splicore owns injected
raw/logical sockets. SDK event-loop join is not exported; exit qualification is
observed stack/socket cleanup. No external mita. HY2/TUIC lifecycle tests cover
QUIC workers, shutdown/reconnect and packet ownership without detected leaks.

## Scope Audit

| Category | Owned Phase 11 changes |
| --- | --- |
| A. SOCKS5 UDP | Standard association framing, source isolation, bounded flows and joined cleanup |
| B. Hysteria2 adapter | Registered native constructor, generic TLS and password validation |
| C. TUIC adapter | Native v5 UUID/password and frozen cubic/native UDP options |
| D. VLESS Native | Flow-none plain/TLS/REALITY and inherited XUDP constructor |
| E. VLESS Xray | Role-specific config, owned private SOCKS connection and original child boundary |
| F. Mieru adapter | Official Client APIs with isolated socket/credential ownership |
| G. Registry | Existing pair registry reused; composition registers five additional pairs |
| H. Capabilities | Client role, TCP/UDP/families/TLS/REALITY and bounded qualification |
| I. Lifecycle | Adapter leases, reconcile/abort and affected association closure |
| J. Stats | Shared LocalInbound/Outbound/Node/Session counters and passive lease health |
| K. Storage | Existing generic Credential payload codecs; no migration or protocol column |
| L. API/CLI | Existing generic mutation parsing, schemas and node/outbound commands |
| M. Tests | Local payload, isolation, rotation/rollback, race/lifecycle/fuzz and installed smoke |
| N. Docs/ADR | Contracts, current freeze navigation and accepted ADR 0023 |
| O. Reports | Unchanged Phase 11 acceptance plus this freeze report |

Freeze edits only six existing documentation files and adds this report. Accepted
functional code, tests, scripts and packaging remain byte-identical. No binary,
DB, key, support bundle, log, cache or external validation file enters staging.

## Stats

Unified Node, Outbound, LocalInbound and Session statistics: **SUPPORTED**.
UDP association/packet and TCP session counters remain distinct decimal-string
observations. Multiple dimensions describe the same payload; they must not be
summed as billing. Persistent commercial usage/strict quota/rate remain deferred.

## Acceptance Source Match

Entry complete source matches final accepted artifact provenance byte-for-byte.
Accepted digest: `ec034cd3dffa4a798921b7993c6502fe73ba3874064f3b48f30ab643b0a4ca45`.
Freeze has an explicit documentation-only allowlist; every functional/test/script/
packaging byte and the Phase 11 acceptance report retain their accepted hashes.
Final freeze builds record a separate complete source manifest and local artifact
identity externally. Precommit provenance honestly records Phase 10 HEAD with
source_dirty:true. Existing three client submodule entries remain unchanged.

## Security

Repository, docs/log evidence, decompressed support projections and staged diff:
**PASS**. No real PSK/password/UUID/REALITY private key/API token or runtime
artifact is staged. Explicit synthetic localhost/test fixtures remain bounded and
are classified by the scan. Installed status/doctor/support omit credentials.
Loopback defaults apply to TCP and UDP. No external target traffic or downloads.

## Platform

Ubuntu 24.04 WSL2 amd64: **QUALIFIED Experimental**, Linux Go 1.26.6.
Windows amd64: **BUILD/TEST PASS**; Windows race: **NOT EXECUTED**.
Linux arm64: **BUILD ONLY / runtime NOT CERTIFIED**. No arm64 runtime execution.
No Windows production service, TUN or system proxy qualification is claimed.

The owned nested systemd lab's outer init reaches the existing teardown timeout
after successful gates. MainPID is zero and cgroup empty; failed-unit bookkeeping
is reset. Clean outer-init termination is not claimed; no product gate is relaxed.

## Runtime Audit

sing-box upstream source: **0 modifications**. Mieru source: **0 modifications**.
Xray source/artifact: **0 modifications**. Wire: **0 modifications**.
Dependencies: **0 changes**, including official Mieru v3.38.0 pin.
Phase 0–10 historical reports and frozen migrations 0001–0005: **UNCHANGED**.
NoBrand HEAD/status/145 file hashes: **UNCHANGED**. Docker: **UNTOUCHED / NOT QUERIED**.

## Commit

Exactly **ONE** authorized Phase 11 commit contains this report.
Message: `feat(client): expand protocol outbounds and SOCKS UDP`.
Sole parent: `463cb8ea4fc497d684b0f4ff8923015009d1187e`.
PHASE_11_COMMIT: resolve `git rev-parse codex/phase-11-client-outbound-expansion`.
Its own SHA cannot be embedded in the same commit; full SHA and actual file/
insertion/deletion counts are recorded externally and in the final answer.
No amend, merge commit or rewritten history.

## Git

Final main == Phase 11 == Phase 12 HEAD == PHASE_11_COMMIT.
main moves only by `git merge --ff-only codex/phase-11-client-outbound-expansion`.
Working tree: **CLEAN**. Index: **EMPTY**. Unrelated refs/remotes/tags unchanged.
origin: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.

## Phase 12

Branch: `codex/phase-12-routing-dns-policy`. Base: **PHASE_11_COMMIT**.
Implementation: **NOT STARTED**. Branch creation is the final action; stop there.

## Deferred

Advanced routing, DNS policy, Selector, URL-Test, Fallback, Load-Balance, RuleSet,
TUN, System Proxy, Subscriptions, Providers, Vision, client FinalMask/Sudoku,
Xray TCP half-close qualification, arm64 runtime, Windows race qualification,
NoBrand migration and existing server deferrals.

## Evidence

Acceptance: `D:/splicore-validation/phase11-20261003/final-acceptance.json`.
Freeze: `D:/splicore-validation/phase11-freeze-20261003`.
Owned service lab: `/root/splicore-p11-freeze-20261003/service-lab`.
Manifests, command logs, traffic/schema/secret audits, packages and Git closure
remain external. Prior acceptance and historical reports are preserved.

## Final Result

**PHASE 11 FROZEN** after all gates and the authorized single-commit Git closure.

## Blockers

None within the bounded Experimental Phase 11 scope.
