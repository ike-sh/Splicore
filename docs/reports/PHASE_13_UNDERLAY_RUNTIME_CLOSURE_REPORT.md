# Splicore Phase 13 Unified Underlay Runtime Closure Report

- Documentation status: Generated
- Audience: Maintainers and reviewers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Final source-bound underlay runtime closure evidence.
- Lifecycle: Current review campaign; no Phase 13 freeze is authorized.

## Baseline

Phase 12: `d09f5f10797aa63798419fa77ffd676257f1b609`.
Branch: `codex/phase-13-tun-system-integration`.
Evidence: `D:/splicore-validation/phase13-underlay-20261004`.

The entry checkout already contained unstaged Phase 13 work; it was preserved.
HEAD, refs, remotes and the empty index remain at entry. No Phase 13 freeze is
authorized. Windows Go 1.26.2 / CGO disabled; Ubuntu 24.04 WSL Go 1.26.6 / CGO enabled.
Local toolchains and module caches were used with GOPROXY/GOSUMDB off.

## Original Remaining Blocker

Unified runtime underlay wiring was incomplete despite passing Windows bypass
model/reconciliation tests. DIRECT, DNS/bootstrap, health, native client/server,
Mieru and Xray did not share one protection boundary. First-start endpoint snapshots
did not retain old runtime references or reconcile fresh endpoints on a reused TUN.
Wintun partial-create ownership and typed LAN WinINET exact restore were already
closed implementation blockers; their previous evidence is preserved in
`D:/splicore-validation/phase13-windows-20261004`.

## Egress Inventory

Paths below are relative to `internal/splicore/`. TCP and packet paths are both
included. Application ingress, private child relays and control sockets are local
or inbound surfaces; they do not acquire physical endpoint routes.

| Surface | Call Path | Protection | Result |
| --- | --- | --- | --- |
| DIRECT | clientruntime.serveStream / DialContext / servePacket / serveUDP → selected directDialer.DialContext / ListenPacket → underlay.Dialer | Typed DirectEgress; socket Control after route selection | PASS |
| DNS | networkruntime.question → dialPurpose → DIRECT provider or selected protected adapter → UDP/TCP/TLS connection | DNSUpstream; original resolver/detour retained | PASS |
| System DNS | networkruntime.systemLookup / native.protectedLocalDNS.Exchange → underlay.LookupNetIP → protected resolver socket | Required unsafe stub/API/mDNS combinations reject | PASS / fail closed |
| Bootstrap DNS | clientruntime.resolveNode / prepareInfrastructure → networkruntime.Bootstrap → explicit bootstrap question or protected systemLookup | DNSBootstrap; direct numeric root before dependent runtime | PASS |
| Health | networkruntime.probe → owned HTTP transport → dialPurpose → selected protected outbound | HealthProbe; bootstrap-safe endpoint lookup | PASS |
| Snell Client | SnellOutboundFactory.Build → buildClientBox → protectedOutbounds.CreateOutbound → protectedNetwork → official common/dialer socket Control | ProxyUnderlay, including UDP transport path | PASS |
| HY2 Client | Hysteria2OutboundFactory.Build → buildClientBox → protected registry/NetworkManager → official dialer.ListenPacket → QUIC | ProxyUnderlay on UDP socket, shared QUIC lifetime | PASS |
| TUIC Client | TUICOutboundFactory.Build → buildClientBox → protected registry/NetworkManager → official dialer.ListenPacket → QUIC | ProxyUnderlay on UDP socket, shared QUIC lifetime | PASS |
| VLESS Native Client | VLESSOutboundFactory.Build → buildClientBox → protected registry/NetworkManager → official dialer/TLS/REALITY | ProxyUnderlay for plain/TLS/REALITY, flow none | PASS |
| Mieru Client | MieruOutboundFactory.Build → official api.NewClient/ClientConfig Dialer/PacketDialer/Resolver hooks → mieruDialer → underlay.Dialer | ProxyUnderlay; SDK and clientio own sockets/workers | PASS |
| Native Server Target | SnellCompiler / newQUICRuntime / VLESSCompiler → explicit protected final DIRECT outbound → official dialer → target TCP/UDP | ServerTarget; protected native DNS and REALITY context | PASS |
| Mieru Server Target | official server → mieruHandle.route → injected target DialContext / protected packet socket | ServerTarget for TCP/UDP; SDK listener is ingress | PASS |
| Xray Client | OutboundFactory.Build → AcquireChild → Handle.Start.Verify → owned child launch → Bind(actual generation, PID) → private SOCKS → child proxy socket | Verified inherited Linux UID/main-table plan; unavailable required platform rejects | PASS / fail closed |
| Xray Server | Engine.Compile → AcquireChild → Handle.Start.Verify/Bind → pinned child inbound → child final target socket | Same inherited process plan; separate child ownership | PASS / fail closed |
| Local ingress | TUN, SOCKS/HTTP/mixed, protocol listeners | Owned admission/listener lifetime; remote egress separately protected | Intentionally Local / ingress |
| Control plane | UDS API, systemd Unix notify, bounded local journalctl, Xray loopback relay/port reservation | Literal/local endpoint validation; no physical bypass for loopback | Intentionally Local |

Every reviewed source/function/call is recorded in
`static-audit/inventory-after.json` and `.md`: **61 production construction or
delegation surfaces, 112 test-only surfaces, Unknown 0**. The original lexical
inventory (`inventory-before.json/.md`) remains intact; its 86 matches included
declarations. `inventory-before-review.json` records five Mieru classification
corrections. These are different counting methods, not a reduction from 86 sockets
to 61. The initial inventory includes current dialer/binding/loop-protection and
NeedsProtection fields; the reviewed final inventory gives each call's disposition.

The [static guard](../../scripts/splicore-underlay-audit.py) compares actual reviewed
calls with its reviewed JSON inventory, rejects unknown functions/changed calls,
checks construction invariants and rejects production imports of the testkit spy.
It is a review guard; actual runtime tests and platform readback supply behavior proof.

## Underlay Architecture

Contract: daemon-shared `underlay.Factory`, typed `Purpose` and `Scope` (runtime and
generation), `Backend.Protect/Reconcile/Verify`, snapshot `Lease`, `ChildLease` and
`EngineUnderlayPlan`. Construction requires an explicit provider, including no-TUN
construction. Application code supplies runtime identity; platform mechanics stay
in underlay/hostnetwork.

Dialer Factory: `Factory.New` / `DialerFrom` provides TCP, packet and resolver
capabilities. Native boxes extend isolated service contexts and wrap the official
OutboundRegistry, DNSTransportRegistry and NetworkManager; explicit final DIRECT
avoids an implicit unprotected default. Official sing-box/sing primitives are reused.

Packet path: `ListenPacket.Control` receives the remote socket purpose/address,
including QUIC and Mieru packet hooks. UDP associations, QUIC runtimes and resolver
generations own references for their lifetimes, not per packet/query/stream.

Platform abstraction:

| Mechanism | Linux | Windows production contract / fixture |
| --- | --- | --- |
| Per-socket protection | Official RoutingMark, `0x534c0001` | Official interface-binding primitive |
| Endpoint route protection | UID/mark main-table rules cover dynamic targets; no per-target churn | Durable bounded infrastructure routes; desired plus retained refs |
| Interface binding | Not required by the selected Linux strategy | IP_UNICAST_IF / IPV6_UNICAST_IF through existing primitive |
| Mark/table | Journaled service UID, socket mark and main-table rules | Not selected |
| External child | Verified inherited service UID/main-table | Unavailable in required mode; fail closed |
| System resolver | Protected non-stub sockets; unsafe stubs reject | Required native System API path unavailable; fail closed |

The real Windows provider is still unavailable behind activation guards. Actual
production adapters are tested with the same contract and a stateful fake Windows
backend; this does not certify real host mutation.

Logical routing independence: **PASS**. Routing/DNS/policy first chooses the action,
resolver or health outbound. Protection does not select DIRECT/proxy, bypass private
address policy, change a ProtocolID or expose Xray JSON as public API.
See [ADR 0031](../adr/0031-unified-underlay-protection.md).

## DIRECT

TCP: PASS. UDP: PASS. IPv4: PASS. IPv6: PASS. Domain: PASS. Protected: **PASS**.
The actual Application/SOCKS fixture observes DirectEgress socket operations for
IPv4/IPv6/domain TCP and UDP. The isolated kernel TUN campaign also exercises both
families and protocols. Arbitrary DIRECT destinations use socket protection;
they cannot acquire persistent infrastructure endpoint routes.

## DNS

System: no-TUN keeps ordinary resolver behavior. Required mode uses protected
numeric DNS sockets and rejects unsafe system stubs/independent Windows APIs/mDNS.
Native local DNS cannot silently use resolved or another independently forwarding
process. Xray verifies its independent system resolver before required launch or
TUN activation; empty, invalid, loopback/mapped loopback, multicast and zoned
nameservers reject.

UDP: PASS. TCP: PASS. DoT: PASS, including hostname bootstrap and original hostname
SNI. Bootstrap: PASS, explicit TUN-independent root without dependent proxy lookup.
Configured DIRECT/outbound/group detours remain intact. Health uses the same safe
bootstrap boundary; dependency loops reject before mutation/publication.

Loop protection: **PASS / typed fail closed for unavailable combinations**.
Kernel DNS interception leak counters: unintended UDP **0**, TCP **0**. No developer
host DNS settings were changed; DoH remains deferred.

## Native Client Outbounds

| Adapter | Evidence |
| --- | --- |
| Snell | Actual application TCP/UDP sees ProxyUnderlay and server target operations |
| HY2 | Actual QUIC packet socket Control plus TCP/UDP application echo |
| TUIC | Actual QUIC packet socket Control plus TCP/UDP application echo |
| VLESS | Plain/TLS/REALITY flow-none actual TCP/UDP; TLS identity retained; Vision rejects |
| Mieru | Official v3.38.0 TCP and UDP underlay hooks; actual TCP/UDP application echo |

All **PASS** in `TestUnderlayActualNativeClientAndServerSocketPaths`, full regressions
and isolated kernel tests. No adapter maintains its own Windows loop-prevention model.
No-TUN server/client, SOCKS and HTTP regressions require no extra host privilege.

## Native Server Egress

Snell: PASS. HY2: PASS. TUIC: PASS. VLESS plain/TLS/REALITY: PASS. Mieru: PASS.
The same actual application fixture observes ServerTarget operations alongside
ProxyUnderlay, for TCP and UDP. Native protocol routers have an explicit protected
final DIRECT outbound; official Mieru server target handling uses the injected
provider. Arbitrary final destinations use socket/interface or UID protection,
not permanent per-destination host routes. Listener sockets remain ingress.

## Xray

Client: PASS for owned process plan, actual pinned child client traffic in the
isolated TUN matrix and complete protocol regressions. Server: PASS for the same
production plan construction, actual helper-process generation/PID/retirement and
pinned server protocol regressions. The kernel client matrix uses a localhost
proxy server; it is not presented as a separate non-loopback Xray server-target
capture test. The Linux inherited UID/main-table rule applies to both child roles
and is journaled/read back before TUN publication.

Mechanism: `EngineUnderlayPlan` binds the actual process generation/PID once;
required preflight/health checks verify host protection and safe child resolver.
Process termination and sole `Wait` complete before releasing child ownership.
Binding failure after launch now kills, joins `Wait` and removes the artifact.
Closed/unknown/rebound plans reject. Official sockopt mark/interface capabilities
were audited locally; the selected Linux process strategy needs no renderer change.

Pinned runtime: v26.3.27, commit
`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`. Source modified: **NO**.
Phase 6 artifacts unchanged. Unavailable platform behavior: **FAIL CLOSED** for
required child protection, including Windows. No-TUN Xray remains supported.

## Dynamic DNS

Initial IP: synthetic `192.0.2.1`; new IP: `192.0.2.2`.
At runtime reconciliation, fresh bootstrap precedes the adapter reuse key;
validated immutable address sets contribute to that key. New protection first:
**PASS**. New connection C2 uses the new endpoint; old C1 echo survives: **PASS**.
IP1 remains protected until C1 and its adapter retire; last-reference cleanup:
**PASS**. Failed empty resolution and failed IP3 provisioning preserve C1/C2 and
the previous effective set. Synthetic addresses are route-state fixtures; no
external traffic is sent to them. Actual echo uses owned local sockets/net.Pipe.

## Generations

TUN generation: host/interface lease and device identity.
Runtime generation: immutable selected client snapshot and retained session refs.
Underlay generation: snapshot lease ID, including bounded infrastructure endpoints.
Xray generation: actual child process generation/PID, separate from snapshot ID.
Route/policy/DNS snapshots remain owned by their existing runtime lifecycle.

Old refs: retained until sessions, packet workers and adapter cleanup finish.
Reused TUN: **PASS**; node and DNS updates keep the same simulated TUN/listener
object while reconciling protection and swapping the selected snapshot. Real
kernel start/stop and retained TCP/UDP generation tests also PASS. Readback failure
stops candidate ingress and closes the owned device after restoration.

## Shared Endpoints

Reference model: each generation owns logical endpoint reasons; effective protection
is current desired plus all retained leases. Multiple reasons deduplicate the OS
route without transferring ownership. Two actual runtime adapters with the same
IP: **PASS**. Two official Mieru SDK runtimes with a shared synthetic route reference:
**PASS** for TCP and UDP transports. Closing A preserves B's echo and protection;
closing the final owner removes the route. Early delete: **NO**.

## Journal

Owned protections: existing unified host journal records intent, exact scope,
generation/owner, before/after state, readback and compensation. Windows endpoint
reconciliation upgrades readable schema-1 journals to schema 2 before new shapes.
Linux UID/mark rules use the existing journaled host transaction.

Crash recovery: PASS in stateful failure fixtures, real isolated kernel process
recovery and installed service parent/child crash tests. Stale generation: reconcile
recorded owned mutations against observed state before establishing canonical
desired state; no fake resurrection of dead socket references. Pre-existing
resources: **UNAFFECTED**, borrowed identical routes never become owned.
Unknown external mutation is preserved and degrades health. Journal/cleanup failure
retains exact debt; failed adapter retirement retains protection and blocks new
required admission. Manager shutdown reports accumulated cleanup errors.

## Wintun

Previous blocker: **CLOSED; no regression**. Partial failure: PASS. Ownership: PASS.
Existing split adapter/session ownership, exact GUID/service orphan recovery,
copied driver-ring payload and joined I/O remain intact. Once stopping begins,
admission stays closed even if later handle cleanup fails. The full hostnetwork
suite runs ten times under default race/checkptr; native symbol/ABI fixtures PASS.
Real Wintun runtime remains NOT CERTIFIED; no real adapter/driver was created.

## WinINET

Previous blocker: **CLOSED; no regression**. Exact restore: PASS. External mutation:
PASS. Typed supported default-LAN snapshot, durable setter intermediates and ordered
notifications remain intact; external C is preserved with recovery debt. Stateful
partial apply/restore/crash/notification fixtures run ten times. Real WinINET
activation remains guarded and NOT CERTIFIED.

## Integration Tests

Actual runtime → fake Windows backend: **PASS**. Production Application/registry,
client selection, native protocol runtimes, SDK hooks and socket Control execute;
test-only spies observe purpose, family and protection operations. Dynamic/shared/
reused-generation tests separately exercise production manager publication and
host reconciliation. Xray's unavailable Windows child capability rejects launch.
Static dial escape audit: **PASS**. Unknown production egress callsites: **0**.

## Race

| Gate | Result | Evidence / seconds |
| --- | --- | --- |
| Default owned/cmd tagged race | PASS | final-owned-race / 129.48 |
| Default owned/cmd tagless race | PASS | final-tagless-race / 99.86 |
| Underlay integration/lifecycle 10x | PASS | final-underlay-race-10x / 59.94 |
| Complete hostnetwork 10x | PASS | final-host-state-race-10x / 24.03 |
| Affected shared package race | PASS | final-shared-race / 38.18 |
| Isolated kernel TUN race | PASS | final-kernel-tun-race / 119.55 |
| Vet | PASS | final-vet / 29.51 |
| Safe native Windows owned/cmd tests | PASS | final-windows-tests / 107.72 |

checkptr: **DEFAULT, PASS**; no disabling flag/environment. Shared coverage includes
common/dialer, dns/..., route/..., DIRECT/Snell/HY2/TUIC/VLESS and clientio.
Lease registry, reconciliation, snapshot retirement and process plan synchronization
are covered. Registry metadata uses narrow locks and immutable sets; state flags/
counters use atomics. No global lock wraps payload Read/Write.

The kernel wrapper launches Python, so its generic JSON says race "not requested";
its log and harness explicitly show the nested Go test binary built with **-race
and default checkptr**. Native Windows full race: **NOT EXECUTED** (CGO disabled).

## Lifecycle

| Required lifecycle | Result / test evidence |
| --- | --- |
| Dynamic DNS reconcile 10x | PASS — TestUnderlayDynamicDNSReusedTUNAndRuntimeRetirement |
| Generation retirement 10x | PASS — same test plus retirement debt test |
| Shared endpoint refs 10x | PASS — actual A/B adapters and Mieru concurrent runtimes |
| Reused TUN reconcile 10x | PASS — object identity, fresh node and DNS updates |
| Xray underlay lifecycle 10x | PASS — generation/PID, rejection and binding-failure Wait tests |
| Mieru underlay lifecycle 10x | PASS — two SDK runtimes, both transport hooks, worker exit |
| Host activation/cleanup 10x | PASS — complete hostnetwork fixtures |
| Real kernel TUN cycles 10x | PASS — six outbounds, retained TCP/UDP, rebuilt client children |

Leaks: fixture leases/routes return to zero, Mieru protocol workers exit, owned
connections/packet workers close/join, child Wait completes and artifacts retire.
Kernel DNS leaks UDP=0/TCP=0. Installed lab cleanup reports **0 remaining processes**
and empty service cgroup. These are bounded lifecycle measurements, not certification
of every resource class on every platform.

## Failure Injection

| Failure | Result |
| --- | --- |
| Protection provisioning / socket Control / readback | Typed failure before new admission; rollback or exact retained debt; PASS |
| Empty/invalid resolution / dependency loop | Candidate rejected, old working generation survives; PASS |
| Journal intent/ack/final ack and corrupted state | No unjournaled publication; compensation/debt and degraded diagnostics; PASS |
| Old-generation adapter cleanup / double release / unknown lease | Retain required protections, report debt, reject unknown ownership without panic; PASS |
| Xray unavailable / unsafe resolver / child Bind failure | Reject before required launch, or terminate/join launched child; PASS |
| Mieru missing provider/hooks | Constructor validation rejects; official hooks used in supported paths; PASS |
| External mutation / pre-existing resource | Preserve external/borrowed state; conflict surfaced; PASS |

Five local 10-second race-enabled fuzz gates PASS: UnderlayResolvedSet,
WinINETSnapshot, NetworkJournal, WindowsBypassDesiredSet and
WindowsEndpointNormalization. No real host mutation is fuzzed.

Earlier diagnostic logs remain in evidence. The final service fixture history is
explicitly separated from accepted execution:

| Attempt | Observation / correction |
| --- | --- |
| final-service | External fault-migration artifact was not built yet; failed precondition before lab entry |
| final-service-accepted | Loopback system DNS while Xray was alive correctly triggered required-mode fail-closed |
| final-service-accepted-2 | DNS veth was introduced before an existing loopback-only smoke assertion; fixture timing corrected |
| final-service-accepted-3 | Automatic IPv6 link-local state changed restoration baseline; owned IPv4 DNS veth uses addrgenmode none |
| final-service-accepted-4 | PASS; authoritative DNS in a second owned namespace, no external forwarding; exact route/rule/DNS readback equal |

These are independent fixture corrections, not production retries or weakened
assertions. No sanitizer suppression, panic recovery, test skipping or sleep-based
masking was introduced. Accepted evidence retains failures and the original exact
restoration assertions. Outer nested init has `Result=timeout/ActiveState=failed`
after teardown; MainPID=0, cgroup empty and remaining processes=0. This qualifies
cleanup, not graceful outer-init termination.

## Safety

Developer Windows routes modified: **NO**. Developer DNS modified: **NO**.
Developer WinINET modified: **NO**. Developer TUN modified: **NO**.
No real Windows adapter, driver, route reset, DNS takeover or proxy setter was run.
Linux changes were limited to owned disposable namespaces/nested service labs.
Authoritative DNS, echo, proxy and reference clients are local owned fixtures;
no external scans or third-party runtime targets. Docker, Redis, TeleLedger and
NoBrand were not queried or touched.

## Platform Qualification

| Surface | Qualification |
| --- | --- |
| Windows underlay implementation | COMPLETE at contract/actual-runtime/fake-backend level; required unavailable paths fail closed |
| Windows real TUN | NOT CERTIFIED; activation guarded |
| Windows real auto-route | NOT CERTIFIED; activation guarded |
| Windows real WinINET | NOT CERTIFIED; activation guarded |
| Windows full race | NOT EXECUTED |
| Linux/WSL safe qualification | PASS: isolated kernel/race/service/default-checkptr evidence |
| Native Ubuntu host-network qualification | DEFERRED; no isolated native VM |
| arm64 runtime | NOT CERTIFIED; build only |

Dedicated Linux service UID is part of the protection contract; application traffic
must use a different UID. Unprotected independent DNS stubs are unsupported in
required mode. Arbitrary VPN/roaming and abrupt power-loss qualification remain
deferred. Review readiness does not enable the real Windows backend or remove guards.

## Regressions

Server: PASS — Snell, HY2, TUIC, VLESS Native/Xray, FinalMask/Sudoku and Mieru complete
owned race/Windows ordinary regressions. Client: PASS — six outbounds, SOCKS TCP/UDP,
HTTP/mixed and no-TUN operation. Routing/DNS/Policy: PASS — complete suites, isolated
TUN matrix and installed A–H smoke scenarios, retained sessions and DNS interception.

Distribution: **PASS** — three-platform local package build and repeat reproducibility;
clean install, low ports, restart, parent/child crash, unrelated child preservation,
Phase 12 schema 6→7 upgrade, failed schema-8 migration rollback, support secret gate,
active TUN uninstall/reinstall/purge and exact route/rule/DNS restoration.
Final service gate `final-service-accepted-4` took 103.48 seconds. Original service
UID and hardening were preserved; owned lab teardown leaves zero processes.

Live documentation/schema validation: PASS for six adapter/network stages, eight
network response schema types plus policy entries, and current TUN/host responses.
Initial/restart/crash snapshots use pinned Phase 12 schema; upgrade/rollback/reinstall
use current schema. No required field was weakened to accept old snapshots.

### Acceptance source integrity

`functional-manifest.json` captures **345** owned functional files before final
acceptance. SHA256:
`5b94721c1926f832d1ca87ade8a730d7bc606294c46cedd395fd11ca4b9a4576`.
Final audit verifies every functional file and packaged provenance against the same
checkout. Functional source did not change after final gates or packaging.

| Artifact / provenance | SHA256 |
| --- | --- |
| Packaged source manifest | 6490ec8e8592a6317eddedc0d7f59d8023c6372fc120c17b255429146b6241fc |
| Linux amd64 archive | 808c11efb85b26f7110f6dbe511ccec20c456a519db2d4c3c40779206bcf7376 |
| Linux arm64 archive | 3d6b2d78c675849acf4351af478a09a8f08bcf02ba6b9256e5b00ff399898c7f |
| Windows amd64 binary | f9d956508379fa3458dd267b7834a6f92d1be385fb3cd1185ea5f7ccc30cf4fa |
| Source archive | 6c3c679730cce5316d79738ccebf71ad3cb02a1948552f7f18070b92b6c1b9a3 |

Artifacts are development/local-only; Linux amd64 and source archives reproduce.
The archive contains the documentation snapshot from packaging. Final closure
report/readiness wording were completed afterward: these **documentation-only**
differences are listed and hashed in external `final-audit.json`; they are not
claimed to be embedded in the candidate. No functional rebuild is needed for those
report changes. Current docs are validated separately after finalization.

## Runtime Audit

sing-box source modifications: **0**. Mieru source modifications: **0**.
Xray source modifications: **0**. Wire modifications: **0**.
NoBrand: **UNCHANGED**. Docker: **UNTOUCHED**. Dependencies/artifacts unchanged.
All 31 protected files, historical Phase 0–12 reports and old migrations match entry.
All original files remain; changes are confined to owned Splicore runtime/fixtures,
two underlay audit script/inventory files and current docs. Exact changed paths and
all current file hashes are in `final-audit.json`. Static audit Unknown=0;
`git diff --check`, source/provenance, refs/index and required final gates PASS.

Canonical updates cover SYSTEM_INTEGRATION, CLIENT_RUNTIME, ENGINE_MODEL,
ROUTING_MODEL, DNS_MODEL, both PLATFORM documents, RECOVERY,
architecture/SECURITY_BOUNDARIES, TESTING, OPERATIONS, CAPABILITY_MATRIX,
DEVELOPMENT_CONTEXT and OpenAPI UnderlayStatus. There is no root SECURITY.md;
the existing canonical security document is used. ADR 0031 records the contract.
DoH, Geo, Subscriptions, Providers, NoBrand and Vision remain deferred.

## Git

Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
HEAD/branch/refs/remotes unchanged; index empty. All review changes remain unstaged.
Phase 13 is **NOT FROZEN**.

## Final Result

**TUN SYSTEM INTEGRATION READY FOR REVIEW**.

The unified runtime wiring implementation blocker is closed within the verified
contracts, actual adapter/fake Windows integration and isolated Linux qualification.
Wintun and WinINET implementation blockers remain closed. This is review readiness,
not platform certification or freeze authorization.

## Remaining Blockers

Implementation blockers in this requested scope: **None**. Real Windows
TUN/auto-route/WinINET, native Ubuntu host network, Windows full race and arm64
runtime remain qualification limits. Unsafe System DNS and unavailable required
Xray platform protection deliberately reject. The Xray kernel matrix's bounded
client/server-target evidence is described above; no wider capture claim is made.

Evidence index: `final-audit.json`, `final-docs-live.json`,
`package-final-gates.json`, `final-service-accepted-gates.json`,
`service-lab-accepted-final-4/network-restore-readback.json`,
`service-lab-accepted-final-4/cleanup.json` and each named gate's `.json/.log`,
all under `D:/splicore-validation/phase13-underlay-20261004`.
