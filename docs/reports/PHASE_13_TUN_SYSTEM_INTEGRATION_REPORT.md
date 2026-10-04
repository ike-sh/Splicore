# Splicore Phase 13 TUN System Integration Report

- Documentation status: Generated
- Audience: Maintainers and reviewers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Phase 13 implementation, local evidence and remaining acceptance blockers.
- Lifecycle: Preserve this review snapshot; a future freeze needs separate authorization.

## Baseline

Phase 12 Freeze: `d09f5f10797aa63798419fa77ffd676257f1b609`.
Branch: `codex/phase-13-tun-system-integration`; entry working tree CLEAN/index EMPTY.
Evidence: `D:/splicore-validation/phase13-20261003` and owned private Linux labs
under `/root/splicore-p13-20261003`. Linux Go 1.26.6, Windows Go 1.26.2;
GOPROXY/GOSUMDB off, local toolchain. No downloads or external traffic targets.
Only existing Windows/WSL environments were authorized by the maintainer.

The Windows blocker closure update uses a separate evidence directory,
`D:/splicore-validation/phase13-windows-20261004`, preserving the original campaign.
See the [Windows closure report](PHASE_13_WINDOWS_BLOCKER_CLOSURE_REPORT.md) for that
campaign's gates and source provenance. Earlier distribution hashes below identify
the prior candidate. The final unified-underlay campaign is recorded separately in
the [underlay closure report](PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md), with evidence
under `D:/splicore-validation/phase13-underlay-20261004`; it closes the remaining
runtime implementation blocker and establishes READY FOR REVIEW without a freeze.

## Status

| Surface | Result |
| --- | --- |
| TUN | Experimental Linux implementation; WSL isolated kernel acceptance PASS |
| HTTP Local Proxy | Loopback CONNECT/plain HTTP PASS |
| Mixed | Loopback SOCKS/HTTP shared port PASS |
| System Proxy | Typed intent/journal/mock restoration implemented; real Windows activation BLOCKED |
| DNS Interception | Shared managed DNS engine, TCP/UDP53 PASS; host DNS untouched |
| Native Linux qualification | NOT CERTIFIED; isolated native Ubuntu unavailable |
| Windows qualification | NOT CERTIFIED; no development-host mutations performed |

## TUN Architecture

Canonical model: existing client `LocalInbound` typed `tun` variant. SQLite schema 7
adds generic host integration desired state; old migrations 0001–0006 are unchanged.
One client graph, one outbound registry, shared routing/DNS/policy, sessions and counters.
Underlying stack: pinned official sing-tun v0.9.3/gVisor through local adapters;
sing-box v1.14.1 source and dependency versions remain unchanged.
sing-box/upstream runtime source modified: **0**. No new IP/TCP/UDP stack or driver.

Immutable staged counter maps and reference-counted generations prevent scratch/state
sharing between old and new flows. Per-flow direction buffers are owned; borrowed DNS
callback payload is copied before asynchronous work. Packet readers stop before device
release; UDP direction goroutines join. Manager closure also releases unacknowledged
candidate descriptors by their process-owned handles, without guessing an OS identity.

See [source audit](../development/PHASE_13_TUN_AUDIT.md),
[local inbound model](../architecture/LOCAL_INBOUND_MODEL.md) and
[ownership ADR](../adr/0027-tun-host-network-ownership.md).

## Linux

TUN, opt-in auto-route, IPv4/IPv6 TCP/UDP and DNS interception: PASS in disposable
network/mount namespaces. Auto-route false creates/configures only the owned device.
Privileges: dedicated non-root service UID plus CAP_NET_ADMIN; ordinary service retains
CAP_NET_BIND_SERVICE only. No unrestricted root daemon installation is introduced.
Native runtime qualification: **NOT CERTIFIED**. WSL qualification: measured isolated
kernel behavior only; no native Ubuntu auto-route, VPN/roaming or power-loss claim.

## Windows

Owned Wintun now separates adapter/session creation through existing public pinned
APIs, retains partial handles and uses exact GUID/service orphan recovery. Official
gVisor receives copied ring payloads. Typed LAN WinINET snapshots include all seven
supported intent fields, durable intermediates, ordered notifications and external-C
preservation. Stateful matrices are qualified; real activation is still **BLOCKED**.
Protected runtime underlay coverage for DIRECT, DNS/bootstrap/health, native
client/server and Mieru now passes actual-runtime/fake Windows backend integration.
Dynamic/shared/retained references and reused TUN reconcile safely. Required Xray
child protection is unavailable on Windows and rejects. Real auto-route remains
**NOT CERTIFIED/fail closed**; the original TUN/proxy capability guards remain.
DNS host settings unchanged. No real driver/admin/TUN/route/proxy qualification was run.
Driver: operator-supplied Wintun; no approved DLL artifact/version, download, installation
or redistribution. Cached Go wrapper license MIT; passive availability/version observation
is separate from qualification. TUN/routes need elevation; SOCKS/HTTP/mixed do not.
Ordinary Windows complete tests/build PASS. Windows race: **NOT EXECUTED**.

## Host Route Ownership

Snapshot all records and persist all intents before the first write. Create device and
addresses, start official stack, apply owned table/routes/rules, read back each step,
acknowledge and activate. Reverse compensation preserves recorded previous state.
Owned route protocol 198, unused table/priorities, exact attributes and interface index
are checked. Linux scope includes boot ID, network namespace and service UID; Windows
scope includes machine GUID hash and user SID. No whole-table flush or system reset.
Partial failure rollback and exact route/rule restoration: PASS. Unrelated routes modified: NO.
Externally changed records are preserved and reported degraded. The created ephemeral
TUN remains process-owned; external configuration of that device is outside the supported contract.

## Network Journal

Location: `StateDirectory/host-network/journal.json`. Linux private directory/file modes
0700/0600; Windows protected current SID/SYSTEM DACL. Reject unsafe paths/ownership,
corruption, unsupported shapes and excessive sizes. Exclusive writer lock, fsync/atomic
replace, bounded generations/steps. Generation/owner/time/before/after/restore status
are operational only; SQLite remains desired-state authority. Journal has no credentials;
sensitive PAC/credential snapshots reject. Corruption reports degraded and never guesses deletion.
Mock crash/partial writes/external changes and real process next-start recovery PASS.

## Loop Prevention

Linux protects the dedicated daemon UID through the existing main table, including
native server/client sockets, inherited Xray children, DIRECT and managed/bootstrap DNS.
Control, loopback/local subnets and explicit excludes bypass capture. Dynamic endpoint
DNS IPs remain protected by UID; a one-time IP pin is not the only loop defense.
Applications using the service UID also bypass TUN and must use a separate application UID.
Bootstrap IPv4-mapped IPv6 results are normalized with `Unmap()` before route planning.
This fixes actual `EINVAL` when a domain node supplied `::ffff:127.0.0.1` as an IPv6 route.
Minimal regression/default race 10x PASS; service campaign with domain nodes rerun after fix.
Linux result: PASS within this dedicated-UID model, now joined by explicit protected
socket marks and verified child ownership. Windows runtime wiring: PASS through the
contract/fake backend; real activation remains BLOCKED pending qualification.

## DNS Interception

UDP/53 and TCP/53 crossing TUN use the Phase 12 engine. Controlled direct UDP/TCP DNS
sinks received **zero** unintended queries. No host resolver settings are modified.
Bounded standard IN question/EDNS parsing; immutable DNS responses and decreasing cache
TTLs. IP/domain observations only accept related nontruncated A/AAAA/CNAME answers,
expire within 300 seconds, cap 4096 entries and discard competing name annotations.
DoH and FakeIP: DEFERRED. ICMP forwarding is rejected; no transparent HTTPS interception.

## HTTP / Mixed

HTTP CONNECT, retained buffered bytes, plain HTTP, SOCKS and mixed dispatch PASS.
Default bind is literal loopback only. Request/response headers bounded to 64 KiB;
proxy credentials/hop fields and all duplicate Connection nominations are stripped,
including trailers. Plain HTTP supports one request per connection. All ingress shares
the same routing, DNS and policy graph; no extra public listener authentication surface.

## System Proxy

Typed LAN WinINET API snapshots now include seven supported intent fields and
durable intermediate states. Exact restore, partial failures, crash journals,
external-C preservation and notification order PASS in stateful fixtures. Legacy
registry records remain read-only; registry setters were removed. Real Windows
enable/disable stays BLOCKED pending real platform qualification. Unified runtime
underlay integration now passes its implementation gates. Actual destructive
WinINET runtime is NOT CERTIFIED.
Linux desktop proxy: UNSUPPORTED; no shell profile edits. macOS: NOT IMPLEMENTED.

## Recovery

Real owned process SIGTERM restores; SIGKILL removes ephemeral device and leaves stale
owned rules; next process reconciles journal and exactly restores baseline. PASS.
DNS restore means no host DNS mutation plus interception teardown. Proxy restore is mock
evidence only. `network repair` requires stopped listeners and repairs recorded resources.
Service post-stop and uninstall helper run recovery as the original service UID; no journal
chown/root interpretation. Actual abrupt power-loss recovery remains NOT QUALIFIED.

## Lifecycle

TUN start/stop, auto-route and DNS interception **10x PASS**, exact routes/rules/interface
restoration in each iteration. HTTP/mixed **10x default race PASS**. Typed WinINET,
Wintun partial ownership and bypass reconciliation matrices 10x PASS. Closed
candidate/device ownership tests PASS. Kernel traffic,
joined workers and control/session teardown pass the real lifecycle checks; these are
bounded local measurements, not a promise that every OS resource class has been certified.

## Traffic

| Path | IPv4/IPv6 TCP | IPv4/IPv6 UDP |
| --- | --- | --- |
| TUN → DIRECT | PASS | PASS |
| TUN → Snell/native → server | PASS | PASS |
| TUN → HY2/native → server | PASS | PASS |
| TUN → TUIC/native → server | PASS | PASS |
| TUN → VLESS/native → server | PASS | PASS |
| TUN → VLESS/xray → server | PASS | PASS |
| TUN → Mieru/native → server | PASS | PASS |

Actual target-bound echo fixtures, 16 concurrent flows, eight 4096-byte UDP payloads
per flow and Snell 4 MiB TCP PASS. UDP fragment/reassembly path measured at MTU 1500.
All targets live inside owned namespaces; packet captures were used only for local diagnosis.
Server + SOCKS + HTTP + mixed + TUN simultaneously PASS.

## Policy

Observed DNS domain and CIDR routing, Selector, URL-Test, Fallback and round-robin
Load-Balance: PASS with real TUN payload. Existing TCP/UDP retain generation/member during
route/selector changes; new flows use the new selection. UDP member/target affinity PASS.
HTTP plain/CONNECT uses shared policy/outbound selection. Windows system proxy→HTTP
scenario M remains NOT QUALIFIED/activation BLOCKED.

## Race

Default tagged complete owned tests PASS with `-race -count=1`, including Xray integration.
Real TUN binary is compiled using `go test -race ... -c` with **default checkptr**;
its Python outer gate metadata alone says race not requested because it launches Python.
The inner compile command/log is the race evidence. Tagless owned race PASS; affected
shared DNS/TLS/UOT/dialer/VLESS/HY2/TUIC/clientio/jsonstrict race tests PASS.
Four fuzz targets (TUN settings, intercepted DNS, network journal, system proxy records)
ran 10 seconds each with race/default checkptr: PASS. No sleep/retry masking, recover,
race/checkptr disabling or broad data-path mutex was introduced.

Final commands/evidence:

```text
go test -race -count=1 -tags with_gvisor,with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore/...
go test -race -count=10 -run TestBootstrapMappedIPv4UsesIPv4BypassRoute ./internal/splicore/hostnetwork
go test -race -count=10 -tags with_gvisor,with_quic,with_utls -run 'HTTP|Mixed' ./internal/splicore/clientruntime
go test -race -count=1 ./internal/splicore/... ./cmd/splicore/...
```

Real TUN: `phase13-route-fixed-kernel-race.log` (inner race compile/default checkptr).
Complete race: `phase13-route-fixed-owned-race.json`; Windows ordinary:
`phase13-route-fixed-windows.json`; shared: `phase13-shared-fixed-race.json`.
HTTP lifecycle, tagless, vet and four fuzz gate JSON/log pairs are retained externally.

## Failure Injection

| Fault | Evidence and semantics |
| --- | --- |
| TUN create | Mock write fault/ready fault; release only owned candidate, no guessed delete; PASS |
| Route apply | First/second route and route-after-ready faults; stop readers then reverse compensation; PASS |
| DNS apply | NOT APPLICABLE to host DNS: no host DNS writes; shared DNS validation/activation failure regressions PASS |
| Journal write | Before writes, applied ack and final ack faults; no unjournaled activation; PASS |
| Health/readback | Ready failure and strict current-state/ownership verification; PASS |
| Permission denied | Actual standard service without NET_ADMIN; protected failure and exact unchanged state; PASS |
| Driver missing | Windows passive driver observation and unconditional ownership gate; unsafe constructor not entered; real missing-driver mutation NOT EXECUTED |
| System proxy write | Typed LAN WinINET stateful partial apply/restore/notification/external-C tests PASS; real Windows write BLOCKED |
| Corruption/external mutation | Degraded, preserve external resources; no guessed repair; PASS |

## Distribution

| Gate | Result |
| --- | --- |
| Linux amd64/arm64 + Windows amd64 package | PASS (arm64/Windows build qualification only) |
| Reproducible amd64 package/source archive | PASS |
| Fresh install of frozen Phase 12 package | PASS |
| Phase 12 schema 6 → Phase 13 schema 7 | PASS; old rows/history preserved, default host integration disabled |
| Non-TUN upgrade routes/rules/DNS unchanged | PASS |
| Restart/crash and unrelated Xray preservation | PASS |
| Deliberately failing schema-8 upgrade/full rollback | PASS |
| Standard service without NET_ADMIN | PASS; TUN failure preserves config/network and releases candidate |
| Non-root optional TUN service/hardening | PASS; service UID 999, only BIND_SERVICE + NET_ADMIN |
| Active TUN uninstall → exact baseline | PASS; original service UID journal preserved |
| Reinstall → desired TUN reactivation | PASS |
| Active TUN hard crash → stale journal → purge | PASS; helper restores owned rules before removing state |
| Purge symlink/bind-mount safety | PASS |
| Support bundle synthetic secret scan | PASS |
| Owned lab cleanup | PASS; MainPID 0, no remaining cgroup processes; outer nested init required forced timeout teardown |

Evidence: `package-fixed-gates.json`, `final-service-gates.json`, and
`service-lab-final/{distribution-gate,permission-failure,active-tun-uninstall,
active-tun-reinstall,active-tun-stale-before-purge,active-tun-purge,cleanup}.json`.
Candidate production source SHA256:
`cb618920440d20e4fe0aaeb3ddf39455205d87b62d60a5b398b73abc1679b88f`.
Linux amd64 candidate archive SHA256:
`5d6ba8aa8c0650e08e6bee9dbecfeed0034cad50769de62f944c1d6e9f8e7577`.
All artifacts remain external/local-only; the diagnostic instrumented package is not the accepted candidate.

Packages include `with_quic,with_utls,with_gvisor` and optional `splicore-tun.conf`.
One existing dedicated-user `splicore.service`; optional NET_ADMIN drop-in retains
ProtectSystem/ProtectHome/ProtectKernel*/ProtectControlGroups/NoNewPrivileges.
Administrator-owned drop-in is deliberately preserved on uninstall/purge and must
be explicitly removed by its administrator. No driver is bundled or downloaded.
Upgrade gate compares all old rows and migration history exactly, permits only schema
metadata 6→7 and the single disabled host-profile default. Failed schema-8 migration
still requires complete database/binary/unit/bootstrap/key/receipt equality after rollback.
Package/service evidence identifies its exact source snapshot; final report/navigation
edits after packaging do not change the tested production implementation.

## Server Regressions

Complete owned/default race includes frozen Snell, HY2, TUIC, VLESS native/Xray,
FinalMask/Sudoku and Mieru tests: PASS. Installed pinned reference-client campaigns
are additionally recorded in Distribution. No server protocol wire behavior was changed.

## Client Regressions

Frozen six outbound adapters and existing SOCKS TCP/UDP complete tests PASS.
Windows allocator fixture now isolates its injected reported port from unrelated OS
port exclusions; independent real kernel allocation stress remains enabled and PASS.
No allocator production code or upstream source was changed.

## Phase12 Regressions

Complete routing/DNS/policy race regressions PASS. Installed representative A–H
scenarios (domain/CIDR/groups/probes/affinity/DNS/update/coexistence) rerun in distribution.
Live API schema checks PASS, including TUN/host profile/status plus inherited responses.
The three pre-upgrade snapshots are validated against the exact Phase 12 freeze contract;
upgrade/rollback/reinstall and current live responses use the Phase 13 contract.
No compatibility field was made optional to accept older runtime snapshots.

## Platform Qualification

| Platform | Qualification |
| --- | --- |
| Ubuntu native amd64 | NOT CERTIFIED; no isolated native VM available |
| WSL2 Ubuntu 24.04 | Isolated kernel TUN/race/service evidence PASS; native qualification pending |
| Windows amd64 | Complete ordinary tests/build PASS; real host mutations NOT EXECUTED; race NOT EXECUTED |
| Linux arm64 | BUILD ONLY; runtime NOT CERTIFIED |
| macOS | NOT IMPLEMENTED / NOT CERTIFIED |

## Architecture Metrics

New Protocol IDs: 0. New Engine IDs: 0. New daemon binaries: 0.
New services: 0 (the optional profile uses the existing unit).
Protocol-specific TUN fields: 0. Protocol-specific route branches: 0.
Platform variants: 3 (Linux, Windows, unsupported); six new platform implementation
files (three network adapters, three journal permission/atomic-I/O variants).
Stack build variants: 2 (official gVisor and unavailable stub), not a second client runtime.

## Deferred

Subscriptions, remote providers, node import, Geo data, DoH, FakeIP, network roaming,
full arbitrary VPN coexistence, upstream strict-route equivalents, ICMP forwarding,
Vision and NoBrand migration. Native power-loss/platform qualification remains pending.
Docker: DO NOT QUERY / DO NOT TOUCH. No remote scanner or third-party systems accessed.

## Git

Stage: NONE. Commit: NONE. Push: NONE. Tag: NONE. Release: NONE.
HEAD/main/refs/remotes unchanged; index EMPTY. Review changes remain unstaged.
Historical Phase 0–12 reports, old migrations, NoBrand and dependency files unchanged.
Final hashes/changed paths are recorded in external `final-audit.json`.

## Final Result

**TUN SYSTEM INTEGRATION READY FOR REVIEW**.

The final [underlay closure report](PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md) records
source-bound default race/checkptr, 10x lifecycle, actual adapter/fake Windows,
isolated kernel, protocol and installed distribution acceptance. Windows Wintun,
WinINET and unified runtime wiring implementation blockers are closed. Real
platform qualification limits remain; Phase 13 is not frozen.

## Blockers

Implementation blockers in the requested Phase 13 closure scope: **None**.
Real Windows activation remains guarded; required unavailable child/System DNS
protection rejects. Qualification limits: isolated native Ubuntu auto-route and
actual Windows driver/admin/traffic/restore environment unavailable; Windows full
race not executed; arm64 runtime not certified. The final underlay report bounds
the Xray child traffic evidence and preserves failed fixture attempts.

Diagnostic failures remain in external evidence: IPv6 DAD/wildcard UDP echo fixture
mistakes were corrected without product wire changes; device-node umask was corrected;
the real mapped-bootstrap-address route bug received a minimal product fix. Diagnostic
instrumentation existed only in external source copies, never in the reviewed checkout.
Nested systemd auxiliary-process kill failure was resolved in the fixture with a verified
owned service cgroup.kill; production stop/restart policy was not weakened. The live-schema
driver initially used the current schema for old package snapshots; it now validates each
version against its corresponding frozen/current contract.
