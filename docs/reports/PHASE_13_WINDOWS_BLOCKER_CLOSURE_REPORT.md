# Splicore Phase 13 Windows Blocker Closure Report

- Documentation status: Generated
- Audience: Maintainers and reviewers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Windows ownership implementation, safe local evidence and remaining blockers.
- Lifecycle: Update final gate evidence; no freeze without separate authorization.

## Baseline

Phase 12: `d09f5f10797aa63798419fa77ffd676257f1b609`.
Branch: `codex/phase-13-tun-system-integration`; HEAD/refs remain at entry baseline.
This round entered with existing Phase 13 unstaged changes; index EMPTY. Prior
evidence in `D:/splicore-validation/phase13-20261003` is preserved. Current evidence:
`D:/splicore-validation/phase13-windows-20261004`. Toolchains and dependencies remain
local, GOPROXY/GOSUMDB off; Windows Go 1.26.2, WSL Go 1.26.6.

This report preserves the Windows ownership campaign and its artifacts. The later
unified runtime campaign in `D:/splicore-validation/phase13-underlay-20261004` closes
the remaining implementation blocker. Its current source/gates and exact limits are
in the [underlay closure report](PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md).

## Original Blockers

| Blocker / files | Original behavior | Invariant / failure window | Ownership and recovery boundary |
| --- | --- | --- | --- |
| Windows loop prevention — clientruntime/host.go, hostnetwork/platform_windows.go; native/Xray/DNS socket owners | First-start node IP snapshot; Windows capture rejected | Every runtime socket owner must have a protected underlay; fresh DNS and retained sessions cannot lose protection | Unified typed provider now wired to actual runtime; implementation closed, real activation guarded |
| Wintun partial creation — hostnetwork/platform_windows.go; pinned sing-tun constructor | CreateAdapter succeeds, StartSession fails, constructor loses handle | Keep adapter ownership through all partial failures; durable identity precedes creation | Splicore now uses existing public Wintun adapter/session APIs, exact handles and GUID/service SetupAPI recovery; no upstream edit |
| WinINET restoration — hostnetwork/platform_windows.go, journal.go | Five registry fields omit default-connection/PAC/autodetect semantics | Capture complete supported LAN intent before writes; partial apply/restore must remain identifiable; preserve external C | Typed per-connection API snapshot, schema-2 journal, transition states and ordered notification; legacy registry setter removed |

## Loop Prevention

| Requirement | Model / fixture result | Runtime integration |
| --- | --- | --- |
| IPv4 / IPv6 | PASS: correct family/physical interface GUID/index/next-hop | PASS: actual DIRECT TCP/UDP family socket operations |
| Domain | PASS: resolver callback produces current address set | PASS: fresh bootstrap before reuse-key computation |
| Mapped IPv4 | PASS: Unmap canonical host route, no wrong-family route | Existing Linux fix preserved |
| Dynamic re-resolution | PASS: fresh result → add/readback/ack new → remove unused old | PASS: actual manager IP1→IP2, retained C1 and new C2 |
| Shared endpoint refs | PASS: merged dependency reasons retain IP needed by B when A changes | PASS: retained snapshots/actual A-B adapters and Mieru SDK refs |
| Xray | PASS: child reason attached to node endpoint routes | Verified Linux inherited UID plan; required Windows child protection rejects |
| DNS bootstrap / upstream | PASS: explicit dependency graph and unknown-System-underlay rejection | PASS: protected UDP/TCP/DoT; unsafe required System combinations reject |
| Health / local control | PASS: dependency projection; loopback never routed onto physical interface | PASS: protected selected probe outbound; local exemptions retained |
| Dependency loops | PASS: validate before resolution/mutation | Production capture guard preserved |
| Route conflicts | PASS: borrow identical pre-existing route; never rewrite/delete/count it as owned | Real Windows qualification deferred |

Reconciliation uses narrow host-control locking, generation/owner binding,
add-before-remove, durable intent, readback, compensation and final-ack rollback.
External mutation degrades the generation, preserves C and rejects further updates.
Completed history is compacted; 600 endpoint changes do not exhaust a live journal.
These tests exercise real Manager/Lease code with stateful backends, not OS mutations.

**Result: model PASS; actual runtime wiring PASS through the production contract
and fake Windows backend. Implementation blocker CLOSED.** Real Windows activation
and destructive qualification remain guarded; see the final underlay report.

## Wintun Ownership

State machine: durable intent → ADAPTER_CREATED → SESSION_STARTED → addresses →
routes → readiness → ACTIVE. Each journal step owns its rollback; session handles
stay process-local. Exact adapter GUID/generation/owner distinguish unrelated
same-name adapters. Constructor and failed-readback candidates retain their handles.
Native requested-GUID mismatch is synchronously closed before returning an
unverified adapter. Close errors keep descriptors available for later cleanup.

Read/write admission and WaitGroup joining prevent session lifetime races. Driver
ring data is copied before asynchronous gVisor use. Close interrupts readers,
joins I/O, ends the session, then closes the adapter. Parent adapter deletion is
deferred while child compensation has failed. Double Stop/rollback/recovery is
idempotent. GUID/service-based SetupAPI recovery also sees nonpresent devices;
insufficient identity or required reboot becomes recovery debt, never broad deletion.

The final lifetime review also fixed partial EndSession cleanup: admission remains
permanently closed once stopping starts, even if auxiliary handle cleanup fails
after the native session is already ended. The retained session is cleanup debt
only. Targeted fixtures assert zero ring Read/Write calls afterward and exactly one
native end; descriptor restart is rejected.

WintunCloseAdapter is void; the pinned wrapper's return-register error is not an
OS cleanup result. Resource readback remains required. OpenAdapter Close alone does
not remove an orphan. Public API symbols are checked before constructor entry.

Adapter identity, pre-existing safety, partial rollback, exact debt, crash recovery,
concurrent Read/Write/Close and double cleanup: **PASS in fixtures**. Component
ownership implementation is present; aggregate Windows activation remains guarded.
Real Wintun runtime: **NOT CERTIFIED**.

## WinINET

Snapshot: default LAN (`pszConnection=nil`), flags, server, bypass, PAC,
autodiscovery flags, secondary PAC and reload interval. Query FLAGS_UI; restore
FLAGS under the Windows 7+ contract. Named RAS connections/read-only detection
cache are outside mutation scope. Returned OS strings are bounded/copied/GlobalFree'd.
Unsupported or sensitive PAC/userinfo/query/fragment snapshots fail before mutation.
The model follows the [Microsoft per-connection option contract](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw).

| Case | Result |
| --- | --- |
| Direct/no proxy, manual, manual+bypass | PASS: A→B→A |
| PAC, autodetect, valid combined flags | PASS: exact supported intent restoration |
| External B→C | PASS: C preserved; durable conflict/degraded |
| Setter fails before/after mutation | PASS: restore A or retain exact debt |
| Notification fails | PASS: failure surfaced and recovery required |
| Crash during apply/restore | PASS: durable intermediates identify owned state |
| Generation/fingerprint/scope | PASS: wrong scope rejects restoration |
| Owned listener failure | PASS: restore prior state; external C remains degraded |

Apply options in order 2,3,4,6,7,5,1, then SETTINGS_CHANGED(39), REFRESH(37).
Before each setter compare current state; afterward verify. Forward and restore
intermediates are durable before writes. Repeated Stop does not notify again.
The HTTP/mixed listener must be owned and match the literal loopback endpoint
before applying B. Unexpected accept-worker exit triggers deterministic restoration.

**Result: typed LAN ownership/restore fixture PASS.** Native WinINET destructive
runtime NOT CERTIFIED; original production activation guard remains.

## Host Transaction

Journal before mutation: **PASS in stateful transactions**. Runtime underlay
coverage is now wired, including fresh/shared/retained endpoints and reused TUN.
The full real Windows transaction remains **NOT CERTIFIED**; no guard was removed
or converted to a warning.

Atomic journal: exclusive lock, private permissions, bounded parser, temp write,
file fsync and atomic replace; Windows WRITE_THROUGH. Power-loss qualification
remains deferred. Schema 1 remains readable; new Windows shapes require schema 2.
Corrupt/truncated/unknown-version journals fail closed with redacted `journal_corrupt`
diagnostics, not a reset. Reverse rollback preserves unknown external resources.
Failed journal writes/cleanup leave precise steps and degraded recovery debt.

## Failure Injection

| Stage | Stateful fixture acceptance |
| --- | --- |
| Adapter create / partial create / GUID mismatch | PASS |
| Session start / partial session | PASS |
| Address / route | PASS, reverse compensation |
| DNS data-plane readiness | PASS; host DNS setter is absent by design |
| Journal intent / step ack / final ack | PASS; mutation blocked or compensated |
| WinINET setters / notification / restoration | PASS |
| Health / local listener exit | PASS |
| Failed rollback / parent debt / double cleanup | PASS |

## Safety

Developer Windows routes modified: **NO**.
Developer Windows DNS modified: **NO**.
Developer WinINET modified: **NO**.
Real destructive Windows tests: **NONE**.
No TUN/Wintun interface/driver was created on the developer host. No reset,
registry setter, reboot, external scan or third-party runtime target was executed.
Docker/Redis/TeleLedger/NoBrand were not queried or touched. Linux changes stayed
inside owned disposable namespaces/nested service labs. No sanitizer suppression,
skipped gate, panic recovery or timing-based masking was introduced.

## Qualification

| Surface | Result |
| --- | --- |
| Windows implementation | **COMPLETE at contract/fake-backend level**; runtime wiring blocker closed |
| Windows real TUN / auto-route / WinINET | **NOT CERTIFIED** |
| Windows ordinary owned/cmd tests | PASS, tagged complete packages |
| Windows full race | **NOT EXECUTED** |
| Portable Windows models under WSL race/checkptr | PASS, 10x |
| Native API symbols / ABI | PASS, entry-point resolution only |

## Linux / WSL Regression

The following gate names/hashes belong to the preserved Windows campaign directory.
Current final underlay source and gates are listed in the separate closure report.

| Gate | Result / evidence |
| --- | --- |
| Default tagged race/checkptr | PASS — final-owned-race |
| Tagless race | PASS — final-tagless-race |
| Shared DNS/TLS/UOT/dialer/VLESS/HY2/TUIC/clientio/jsonstrict race | PASS — accepted-shared-race |
| Wintun/WinINET/bypass/control/lifecycle 10x | PASS — final-state-race-10x; includes partial EndSession reproducer |
| Kernel TUN lifecycle 10x | PASS — final-kernel-tun-race; nested test binary built with race/default checkptr |
| Routing/DNS/policy/six adapters | PASS — complete race and isolated kernel test |
| Four bounded parser/model fuzz targets | PASS — final-fuzz-*; race enabled, no real backend |
| Vet | PASS — final-vet |
| Three-platform/repeated package build | PASS — final-package; source/archive and Linux amd64 binary reproducible |
| Upgrade / rollback / uninstall / purge | PASS — final-service; final candidate, exact restore and clean owned-lab teardown |

Reviewed candidate before the final session-lifetime fix, source SHA256:
`79b20b9fe0027f1a79c4c6abfc9e9ba27a4fc23f7b671d692a88d0571c62a1ea`.
Linux amd64 archive SHA256:
`14367e1ae752f3c4503462f036d3732ea8074524de9beb23cf32d4cda27b8520`.
All artifacts are external/local-only. Documentation updates after packaging are
identified separately by the final audit; production implementation must match.
The initially rejected build remains in evidence: source changed during build;
the stable reviewed candidate and repeat passed without weakening that check. Its
service campaign passed upgrade/rollback/uninstall/purge with clean lab teardown.
Final candidate source SHA256:
`9db64d7e654810804a38c4185a20ab2ab761521044f22ebd2a30419e30f85428`.
Final Linux amd64 archive SHA256:
`8ca6970d88a84a8f31773c37cc1765ae28b8da4970abdae6f376296783a86441`.
Final package/repeat gates PASS; the preceding reviewed artifact is not presented
as acceptance of the final lifetime fix. Source-bound final service evidence is
recorded separately.

Final installed campaign: schema 6→7 upgrade, failed schema-8 rollback, server
reference clients, SOCKS TCP/UDP, six outbounds, routing/DNS/policy A–H, restart/crash,
active TUN uninstall/reinstall and stale-journal purge PASS. Non-root TUN hardening
and permission failure remain qualified. Owned service cleanup leaves zero processes;
outer nested init required timeout teardown, not a graceful outer-init exit claim.
Evidence: `final-service-accepted-gates.json` and `service-lab-accepted-final`.

## Protocol Regressions

Server: Snell, HY2, TUIC, VLESS Native/Xray, FinalMask/Sudoku and Mieru tests PASS
in complete owned race/Windows ordinary campaigns. Client: SOCKS TCP/UDP, six
outbounds, routing/DNS/policy PASS. Installed reference-client/service acceptance
is recorded separately in the current nested-service campaign. No protocol/wire
implementation changes were made this round.

## Runtime Source Audit

sing-box: **0**. Mieru: **0**. Xray: **0**. Wire: **0**.
go.mod/go.sum and migrations 0001–0006 unchanged. Changes are Splicore-owned
hostnetwork/clientruntime code, fixtures and current documentation. Final path/hash
comparison against entry is recorded in external `final-audit.json`.

Prior Windows campaign final audit: PASS. All 31 protected files match entry, refs/remotes unchanged,
index EMPTY. This round changed 39 Splicore-owned code/fixture/document paths;
packaged production source matches the current checkout. The only post-package
change is this report. Final live response/schema/documentation checks PASS,
including frozen Phase 12 pre-upgrade and current Phase 13 responses.

## Git

Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
Phase 13 is not frozen. Existing unstaged Phase 13 changes were preserved.

## Final Result

**TUN SYSTEM INTEGRATION READY FOR REVIEW** after the unified-underlay campaign.
Wintun and WinINET implementation blockers remain closed. The source-bound current
result is in the [underlay closure report](PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md).
Phase 13 is not frozen; real Windows activation remains guarded.

## Remaining Blockers

Implementation blockers in this requested closure scope: **None**. Actual runtime
integration, fresh domain resolution, retained/shared references and reused TUN
reconciliation now pass; required unavailable Xray/System capabilities fail closed.
The real Windows qualification and activation guards remain as listed below.

## Platform Qualifications Deferred

Native Ubuntu auto-route/DNS takeover, real Windows TUN/auto-route/WinINET, Windows
full race and arm64 runtime. Host DNS takeover is not an implemented Phase 13 feature.
See [current Phase 13 report](PHASE_13_TUN_SYSTEM_INTEGRATION_REPORT.md),
[Windows](../PLATFORM_WINDOWS.md) and [ADR 0030](../adr/0030-windows-host-network-ownership.md).
