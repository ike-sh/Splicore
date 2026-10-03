# Splicore Phase 11 Client Outbound Expansion Report

- Documentation status: Experimental
- Audience: Maintainers and reviewers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Phase 11 implementation and actual acceptance evidence.
- Lifecycle: Phase 11 acceptance record; keep Phase 0–10 reports unchanged.

## Baseline

Phase 10 Freeze: `463cb8ea4fc497d684b0f4ff8923015009d1187e`.
Branch: `codex/phase-11-client-outbound-expansion`. Entry CLEAN, index EMPTY.
Baseline DIRECT, Snell, server/client coexistence and full owned default race:
PASS before edits, recorded in `baseline.json`.

All evidence, binaries, packages, database/key fixtures and logs are external:
`D:\splicore-validation\phase11-20261003`. Linux private service labs live under
`/root/splicore-p11-20261003`. Tests use only loopback and synthetic material.
Go 1.26.6, offline module cache, unchanged go.mod/go.sum and pinned artifacts.

Final artifact hashes and the complete source snapshot are authoritative in
`final-a/update.json`, `final-b/update.json` and their source archives.
`final-package-gates.json` checks repeatability; `final-service-gates.json` binds
installed acceptance to those source digests. Review this report with those
external records. Intermediate experiments and failures remain as diagnostics.

## Status

Client Runtime: **Experimental**.
Server Runtime: **UNCHANGED frozen capabilities**, regression tested.
SOCKS TCP and UDP ASSOCIATE and all six registered adapter pairs are implemented.
This is readiness for source review, with the platform limits below.

## Local SOCKS

TCP: SUPPORTED. UDP ASSOCIATE: SUPPORTED.
IPv4, IPv6 and domain targets: PASS. IPv6 loopback TCP listener and UDP relay:
PASS on the tested Linux and Windows hosts.

Association isolation: PASS. Each control connection owns one loopback relay,
source endpoint, target flow map, generation reference and worker buffers.
Requested IP must match the TCP peer; a source port is requested explicitly or
claimed by the first valid datagram. Foreign IP/port, RSV errors and FRAG packets
are discarded. Fragments cannot claim a source endpoint. No LAN relay is opened.

Control EOF, expiry, runtime shutdown and affected reconcile close sockets, join
workers and release references. Maximum 32 target flows per association; idle
expiry is two minutes. Tests invoke the expiry boundary directly without waiting
two minutes. `udp-source-10.json`: lifecycle/source ownership 10x PASS.

## Outbound Matrix

IPv4/IPv6/Domain columns describe application targets. Server endpoint families
are also tested, preserving canonical domain names in SQLite.

| Protocol | Engine | TCP | UDP | IPv4 | IPv6 | Domain | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Snell | native | PASS | PASS | PASS | PASS | PASS | Experimental; existing regression |
| Hysteria2 | native | PASS | PASS | PASS | PASS | PASS | Experimental |
| TUIC v5 | native | PASS | PASS | PASS | PASS | PASS | Experimental |
| VLESS flow-none | native | PASS | PASS | PASS | PASS | PASS | Experimental; plain/TLS/REALITY |
| VLESS flow-none | xray | PASS | PASS | PASS | PASS | PASS | Experimental; plain/TLS/REALITY |
| Mieru | native | PASS | PASS | PASS | PASS | PASS | Experimental; TCP/UDP underlays |

## Hysteria2

Credential: existing encrypted `PasswordPayload`, referenced by RemoteNode.
TCP, UDP, IPv4/IPv6/domain targets and server endpoints: PASS.
QUIC: inherited native client implementation, unchanged auth/crypto/wire.
Wrong credential: actual TCP/UDP rejection PASS; valid rotation and recovery PASS.
16 TCP plus 16 UDP mixed operations and 4 MiB integrity: PASS.

## TUIC

Version: **v5 only**. Credential: existing canonical `UUIDPasswordPayload`.
The generic write-only credential value carries a strict JSON UUID/password pair;
there is no duplicate client credential domain or protocol column.
TCP, UDP, IPv4/IPv6/domain, wrong credential, recovery, mixed concurrency and
4 MiB integrity: PASS. QUIC uses the inherited native implementation.

## VLESS Native

Flow: **none**. Plain, TLS with explicit CA, and REALITY: PASS.
TCP/UDP and all target families: PASS. UUID is the existing canonical credential.
Client security uses only public key, short-id, SNI and public trust material.
Server private key is neither required nor represented by ClientTLS.
Wrong UUID, REALITY key/short-id/SNI and untrusted TLS CA: reject PASS; recovery PASS.
Vision: typed **REJECT**, preserving ADR 0017 at validation/construction boundaries.

## VLESS Xray

Flow: **none**. Plain/TLS/REALITY, TCP/UDP and target families: PASS.
Vision: REJECT. FinalMask/Sudoku client: DEFERRED.
Supervisor reused: PASS. New supervisor: NONE. Same Engine, Handle collection,
process owner, sole Wait/reaper, generation artifacts and shutdown boundary.

The private SOCKS projection owns raw/control sockets and packet projection keeps
FQDN responses. UUID/client public fields are rendered into private artifacts;
argv carries artifact paths, without secret values. Artifacts use existing
0600/0700 and Windows ACL enforcement and are removed by the existing owner.

Three qualification findings were fixed in owned adapter code:

- Windows TCP/UDP ephemeral pools have different excluded/occupied ranges.
  Reserve a complete pair before process construction, selecting bounded
  candidates from both allocators. Match real Winsock 10048/10013. Failed
  candidates close; unrelated errors and exhaustion fail construction. This
  never restarts a failed child or retries application traffic. A real pool
  sweep of 500 repetitions passed after the fix.
- Xray explicit CA trust must render `disableSystemRoot: true`, providing an
  exclusive custom root store on Windows as well as Linux. Trusted traffic and
  wrong-CA rejection passed against both server engines.
- Raw private TCP CloseWrite did not convey end-to-end EOF through every VLESS
  server, retaining a session after complete payload transfer. The projection
  exposes the stream contract; Application EOF closes the owned tunnel.
  **Xray TCP half-close is not qualified.** DIRECT keeps its own contract.

No upstream runtime or wire changes were used for these fixes.

## Mieru

Official module: `github.com/enfein/mieru/v3 v3.38.0`, unchanged.
External mita: **NO**. Official Client Store/Start/DialContext/Stop APIs are embedded.
TCP/UDP application traffic over TCP and UDP underlays: PASS.
IPv4/IPv6/domain targets and endpoints, wrong password, reconnect, 4 MiB and
16 TCP plus 16 UDP: PASS.

Multiple outbounds: PASS. Distinct endpoint/credential/mux contexts serve traffic
concurrently; closing Node A's runtime leaves Node B operational. Application
lifecycle 10x PASS. Owned socket/event-loop gate: 10 repetitions containing
**200 client lifecycles**, PASS with callers retaining logical connections when
the adapter closes. Credentials and sessions stay isolated.

## Architecture

| Invariant / metric | Result |
| --- | --- |
| Node != Outbound | PASS; independent IDs and references |
| Protocol != Engine | PASS; one canonical VLESS node serves native and Xray adapters |
| ClientProfile != Runtime | PASS; runtime consumes canonical settings/credentials |
| Central client protocol switches added | 0 |
| Application protocol branches added | 0 |
| Protocol-specific Node fields | 0; generic public security and bounded options |
| Protocol-specific DB columns | 0 |
| New migrations | 0; frozen schema 5 retained |
| New engine types | 0 |
| New process supervisors / client services | 0 |

Composition registers adapter pairs. Each protocol owns its option validation;
Application retains the generic mutation boundary and shared revision/HMAC flow.
SQLite remains authority. ClientProfile and runtime reuse public ClientTLS and
canonical credential/settings types, never exporter serialization.

Unchanged adapters retain leases across label/metadata/route changes. Endpoint or
credential changes rebuild only affected adapters. Abort releases candidate
references without closing committed adapters. Explicit restart forces rebuild.
TCP sessions retain old generation ownership; affected UDP associations close
after commit. Passive health belongs to the adapter lease, isolating retired
traffic from replacement health. Unsafe node/outbound reference deletion rejects.

## Self Interop

Splicore Client → Splicore Server actual traffic:

| Adapter | Result |
| --- | --- |
| Snell/native | PASS |
| Hysteria2/native | PASS |
| TUIC/native | PASS |
| VLESS/native | PASS |
| VLESS/xray | PASS |
| Mieru/native | PASS, both underlays |

The VLESS matrix crosses two client engines with native/Xray servers for
plain/TLS/REALITY; both clients consume one canonical node in each cell.
Installed expansion retains eight frozen server inbounds and tests eight client
adapter cells, including Mieru underlays and VLESS engine combinations.

## Reference Interop

Actually executed on localhost with existing pinned artifacts:

| Splicore client | Reference server | TCP | UDP |
| --- | --- | --- | --- |
| Snell/native | sing-box 1.14.1 | PASS | PASS |
| Hysteria2/native | sing-box 1.14.1 | PASS | PASS |
| TUIC/native | sing-box 1.14.1, explicit h3 ALPN | PASS | PASS |
| VLESS/native | sing-box 1.14.1 | PASS | PASS |
| VLESS/xray | sing-box 1.14.1 | PASS | PASS |
| VLESS/native | Xray 26.3.27 | PASS | PASS |
| VLESS/xray | Xray 26.3.27 | PASS | PASS |

Standalone official Mieru **server** reference: NOT EXECUTED; no safely reusable
pinned server artifact was available locally. This is not counted as self interop
or a mandatory conditional gate. The existing official Mieru **client** artifact
is exercised against Splicore servers in installed server regressions.

## UDP

SOCKS associations: standard UDP ASSOCIATE, separate from TCP CONNECT.
16 concurrent associations and mixed TCP/UDP: PASS. Packet cross-talk: NONE observed.
Socket/association/worker leak: NONE observed in repeated lifecycle qualification.
Default race: PASS.

Resolution semantics: DIRECT, Snell and Mieru resolve UDP targets locally per
flow to satisfy their existing packet response contracts. HY2/TUIC/VLESS retain
domain targets for remote resolution. TCP proxy targets resolve remotely.
Canonical node domains stay unchanged; Mieru TCP underlays pass the original
server domain to net.Dialer for normal IPv4/IPv6 connection selection.
No DNS engine, fake DNS, interception, or resolver policy is added.

## Stress

TCP 16 concurrent: PASS. UDP 16 concurrent: PASS across adapter combinations.
Native matrix uses 16 TCP plus 16 UDP per adapter; VLESS does the same for both
engines after valid Bob rotation. Mieru UDP underlay has its own mixed-load gate.
Installed matrix independently mixes TCP/UDP across outbounds.

4 MiB: PASS per adapter; installed cells each check 4 MiB payload integrity.
Reconnect: actual remote shutdown then recovery without local daemon restart,
PASS. Abnormal client close, remote close, runtime close and adapter stop:
PASS, no observed panic, deadlock or growth of owned workers/sockets.

## Server + Client Mixed Runtime

Server runtimes: Snell, HY2, TUIC, native/Xray VLESS, Xray Sudoku and both Mieru
underlays remain active in the installed daemon. Client outbounds: all six
adapter pairs plus DIRECT, with additional underlay/engine cells.
Concurrent traffic: PASS. Runtime namespace, credential, session, port and
shutdown isolation: PASS. No extra daemon, engine type, package or service.

## Credential Rotation

| Protocol | Valid old → valid new | Invalid input / wrong remote credential |
| --- | --- | --- |
| Snell | PASS; valid replacement server credential and rebuilt adapter | PASS |
| HY2 | PASS; Alice/Bob and replacement credentials | PASS |
| TUIC | PASS; canonical UUID/password pair and rebuilt adapter | PASS |
| VLESS | PASS; Alice → Bob on both client engines | PASS |
| Mieru | PASS; canonical username/password pair and isolation | PASS |

Rollback: malformed/unsupported credentials and failed candidate construction
leave committed intent and live adapters intact. Well-formed but remotely wrong
credentials can commit as intent; subsequent traffic rejects and passive health
reports failure. Remote authentication is not falsely claimed as validation or
as an automatic transaction rollback. Restoring valid intent recovers traffic.

## Recovery

systemd restart: PASS. SQLite restores Nodes, Outbounds, routes and Local SOCKS;
TCP/UDP traffic resumes. Initial/restart/parent crash/upgrade/failed-upgrade
rollback/reinstall campaigns all run server plus client smoke.

Offline node isolation: PASS. Reinstall campaign commits an offline HY2 endpoint,
restarts the actual installed unit, observes only that outbound failing/passively
unhealthy, verifies sibling traffic, restores the node and verifies recovery.
Server/API and daemon startup remain operational.

## Stats

Node, Outbound and LocalInbound: unified projections of application payload.
Sessions: kind distinguishes TCP stream from UDP association. UDP target flows
do not become TCP sessions. UDP counters distinguish association total/active
and packets upload/download. TCP counters remain total/active sessions.
Upload/download byte counters exclude SOCKS headers and protocol control/framing.
All eight client counters are decimal strings; frozen server Stats is unchanged.
Double counting: tests assert payload/counter values; dimensions are alternate
views and must never be summed. No protocol-specific public stats models.

## API / CLI

Unified node API: PASS. Unified outbound API: PASS.
Protocol-specific client API routes: NONE. Unified validate/plan/apply CLI:
PASS for all protocol fixture types. Canonical DTO creation supports all adapters.
Capability API expresses protocol, engine, client role, TCP/UDP, address families,
TLS/QUIC/REALITY, allowed flow and domain-resolution semantics. Vision unsupported
and platform compilation constraints are explicit.

Secrets: REDACTED in normal reads, status, doctor and mutation results. Generic
credential input is write-only. OpenAPI public ClientTLS, options, capabilities,
session kind and eight client counters match live installed responses. Static
document/link/schema checking and six full expansion status schemas: PASS.

## Security

Default SOCKS binding: **loopback**. UDP source/control ownership enforced.
Credential leaks in qualified API/status/doctor fixtures: NONE detected.
Runtime artifact leaks in qualified outputs: NONE detected; UUID/private artifacts
stay in restricted generation directories and are removed by process ownership.
Native clients write no unnecessary secret files. Client REALITY has no server
private-key field or access requirement. No argv secret values.

Support bundle: PASS. The actual installed unit journal receives synthetic raw
secrets from a temporary test ExecStartPre. Raw journal contains them; generated
0600 support archive contains none. Test drop-in is removed before installation
operations. Artifact/raw config files are excluded from archived safe evidence.

## Race / Lifecycle

Default race: PASS. Default checkptr: PASS, with no suppression.
Shared race: PASS for `./common/... ./protocol/... ./adapter/...` with standard
with_quic/with_utls build tags. No inherited files changed after this shared gate.
Full owned suite and tagless package suite: PASS. Final vet: PASS.

| Gate | Evidence | Result |
| --- | --- | --- |
| Full owned race/checkptr | owned-race-qualified-final.json | PASS |
| Tagless owned tests | owned-tagless-final.json | PASS |
| Shared race | shared-default-race.json | PASS |
| SOCKS UDP source/lifecycle 10x | udp-source-10.json | PASS |
| Mieru application lifecycle 10x | mieru-client-10.json | PASS |
| Mieru 200 owned client lifecycles | mieru-owned-loop-qualified.json | PASS |
| Native matrix worker exit 10x | native-owned-workers-10.json | PASS |
| Xray outbound lifecycle 10x | xray-lifecycle-qualified-final-10.json | PASS |
| Windows VLESS expanded matrix 10x | windows-vless-final-10.json | PASS |
| Windows kernel paired port sweep | windows-paired-pool-qualified.json | PASS |
| Final owned vet | owned-vet-final.json | PASS |

Goroutine leak: NONE observed in repeated owned lifecycle gates. Native matrix
starts each repetition with baseline 2 goroutines; runtime close leaves only
six still-owned echo fixtures, which fixture cleanup joins before the next
baseline. Stack checks cover sing-quic, Mieru and association workers.
The SDK exposes no client event-loop join API; testing confirms socket close
drives exit. This observation is not represented as an upstream join guarantee.

```text
go test -race -count=1 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore
go test -race -count=1 -tags with_quic,with_utls ./common/... ./protocol/... ./adapter/...
go test -race -count=10 ./internal/splicore/clientruntime -run TestSOCKSUDP
go test -race -count=10 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/application -run TestPhase11XrayOutboundLifecycle
```

All race gates retain default checkptr and no GODEBUG/gcflags workaround.
Child reference binaries retain their pinned build; Go race instruments the
Splicore process and embedded Go code, not an external Xray binary.

## Fuzz

Bounded synthetic fuzz gates, three seconds each, PASS:

- Canonical node options: 60,127 executions.
- REALITY public client settings: 112,018 executions.
- SOCKS UDP address parsing: 63,417 executions.

No cryptography, protocol wire or external-target fuzzing.

## Server Regressions

Snell: PASS. HY2: PASS. TUIC: PASS. VLESS Native: PASS. VLESS Xray: PASS.
FinalMask/Sudoku server: PASS. Mieru: PASS, both underlays.
Owned suite, actual installed service and pinned third-party client regressions
cover frozen scopes. Installed references include sing-box, Mihomo, Xray and
official Mieru clients. Phase 10 DIRECT/Snell/coexistence also PASS.
Vision remains rejected on server and client; ADR 0017 unchanged.

## Distribution

Package: PASS. Installed service: PASS. Server+Client installed: PASS.
All build/package/evidence outputs are external, local development artifacts.
No release, publication, signing or new client package/service.

Campaigns: clean install, restart, parent SIGKILL/owned Xray child cleanup,
unrelated Xray unaffected, normal upgrade, injected migration failure/transaction
rollback, support secret scan, uninstall retaining state, reinstall, unsafe
symlink/mount purge rejection and explicit lab purge. Non-root identity,
capabilities, low ports, private paths/key/config persistence also qualified.

The migration failure fixture is an **external source copy** with schema 6 DDL
followed by a deliberate SQL error. Production migrations remain byte-identical.
Final candidates use explicit epoch 1790899200. Repeat Linux amd64 package and
source archive hashes must match; manifests bind the complete dirty source.

Lab-only start-counter reset occurs between independent installation campaigns
and before uninstall. Production StartLimit settings are unchanged. Failed
operations are not retried. Earlier start-limit fixture failures are retained.

Outer disposable init teardown reached the systemd stop deadline in completed
campaigns; verification found MainPID 0 and an empty/absent cgroup. This is recorded
as process cleanup PASS, not a clean outer-init exit. The production Splicore
service stop/restart and owned child checks are separate actual gates.

## Platform

| Platform | Qualification |
| --- | --- |
| Ubuntu 24.04 WSL2 amd64 | Primary full runtime, default race/checkptr, systemd installed matrix PASS |
| Windows amd64 | Full owned tests/build PASS; local TCP/UDP, native QUIC/Mieru and VLESS plain/TLS/REALITY matrix PASS; VLESS expanded matrix 10x PASS |
| Linux arm64 | BUILD only; client runtime NOT CERTIFIED, no arm64 runtime executed |

Windows lacks a local GCC toolchain; Windows race was not run. Race qualification
is Linux CGO-enabled default race. No Windows service/TUN qualification is claimed.
IPv6 results apply to the available loopback stack on these two hosts.

## Runtime Audit

sing-box inherited source changes: **0**. Mieru module source changes: **0**.
Xray upstream source/artifact changes: **0**. Wire/crypto/auth changes: **0**.
go.mod/go.sum changes: **0**. New unsafe pointer use: **0**.

Mieru client audit: private Client profile/mux per adapter; shared package cipher
cache/metrics and process-wide quiet logger formatter already belong to the SDK.
They do not supply client accounting or credential authority. Client APIs do not
start daemon RPC, signal handlers or a singleton client runtime. SDK Stop joins
mux maintenance but exports no event-loop Wait. Splicore owns raw/logical sockets,
orders admission before Wait, cancels pending operations, closes all sockets and
joins injected operations before Stop; 200 lifecycle gate checks actual loop exit.

Native adapters own one private Box/context, with no shared scratch state.
Xray reuses existing process ownership. Generation state/options are copied;
references/health/counters use atomics or narrow map/admission locks. Payload I/O
does not take a global manager mutex. Flow/direction buffers have one owner,
and pool-encoded packets are copied before buffers are returned.

Phase 0–10 reports and frozen migrations: 24 protected files unchanged.
Inherited non-owned files: 1,275 unchanged. NoBrand: 145 audited files unchanged.
Docker: NOT QUERIED / NOT TOUCHED. No third-party systems or network scans.

## Deferred

Advanced Routing, DNS Engine, Selector, URL-Test, Fallback, Load-Balance, RuleSet,
TUN, System Proxy, Subscriptions, Providers, Active Node Health,
FinalMask/Sudoku client outbound, Vision and NoBrand migration.
Linux arm64 runtime certification and Xray TCP half-close remain unqualified.

## Git

Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
HEAD/main/refs/remotes unchanged. Index EMPTY; implementation, tests, scripts and
documentation remain unstaged for review. No history rewrite/reset/clean/stash.

## Final Result

**CLIENT OUTBOUND EXPANSION READY FOR REVIEW**

## Blockers

None within the requested Phase 11 scope. Experimental status and explicit
platform/half-close/reference limitations above remain visible.
