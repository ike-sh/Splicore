# Unified Runtime Hardening Inventory

Documentation status: Current implementation audit
Audience: Maintainers and reviewers
Last reviewed: 2026-10-04
Owner: Splicore maintainer
Responsibility: Phase 15 lifecycle, ownership, failure and recovery audit
Lifecycle: Experimental implementation; no freeze or platform certification

Base: `7be20f14ccb59112c98f2fa07c0cab20a436bd88`. Audit precedes production
changes. SQLite is domain authority; runtime generations and operational files
are derived state. Runtime engine remains native only. Existing protocol,
routing, DNS, policy and timeout semantics are preserved.

## Resource inventory

| Surface / owner | Acquire | Activate / reference | Retire / release | Rollback | Crash / restart recovery |
| --- | --- | --- | --- | --- | --- |
| Daemon / app.Serve | Validate, local control listener, vault, SQLite, application | Recover server/client then scheduler; READY and HTTP | Cancel HTTP work, join shutdown, management/client/server, store/listener | Defers unwind partial construction | Service restarts from committed SQLite; no snapshot authority |
| Server runtime / runtimeState | Protocol projection and native Compile | Start, Health, commit, Activate; handles by inbound ID | Admission closes; cancel, close listeners/sessions, join workers | Candidate Close and FailOperation; replacement reconstructs old intent | RecoverPending, project committed bindings/credentials |
| Snell/VLESS listeners / native handle | Owned TCP listener during Start | Precommit admission disabled; authenticated connections tracked | Closed admission, listener/socket close, worker join | box construction/start cleanup plus handle Close | Recompile; failed handles are not reused |
| HY2/TUIC listener / quicHandle | Owned UDP socket, upstream embedded service | Admission packet wrapper; atomic meters | Cancel then existing bounded QUIC close grace; socket/service close | Partial Start closes socket/TLS/service | Fresh compiled handle from DB |
| Mieru / mieruHandle | Embedded official server; owned listener/socket callbacks | Track closers before admitting sessions | Cancel, close tracked resources, server Stop, worker join | Partial handles retain cleanup ownership | Fresh embedded server; no external process |
| Client runtime / Manager | Validated immutable cloned state, lease, adapters, staged listeners | Prepared.Activate publishes one pointer; reference acquisition under routeMu | Close admission; cancel sessions/control queries; release last generation | Prepared.Abort owns new resources only | Recover committed ClientState; degraded client does not invalidate server |
| Outbound adapter / dialerLease | Factory.Build or ref to identical effective adapter | Generation refs; sessions retain generation through socket cleanup | Last lease ref closes adapter after borrowed sockets | Abort decrements only candidate refs | Rebuild; credential/endpoint key prevents stale reuse |
| Routing snapshot / networkruntime.Matcher | Compile cloned ordered rules | Entire matcher published with runtime generation | Session generation references | Invalid compile cannot publish | Recompile DB; first-match unchanged |
| DNS / networkruntime.Engine | Cloned DNS config; bounded cache, owner and counters | Queries retain owner; per-query deadlines; copied cache messages | Cancel owned queries, FlushCache epoch, release sockets | Stale exchange cannot refill a flushed epoch | Fresh cache; committed DNS config wins |
| Policy / Engine groupState | Validated DAG, private samples, bounded workers | Group mutex + atomic counters; private UDP affinity | StopScheduler then owner.Close | Inherit only identical reachable groups/adapters | Old probe callbacks update only old engine |
| Proxy providers / managementState | Four refresh slots; serialized provider ID; encrypted source | Revision-bound preview; prepare/commit/activate | Scheduler cancel/join; active fetch cancel/join; clear plans | Failed candidate retains old nodes/validators/runtime | Persisted generation and encrypted source; offline restart |
| RuleSet providers / same transaction | Bounded parse; referenced ruleset ID | Rules and generation committed together with routing snapshot | Same provider controls | Old rules persist on fetch/parse/compile/commit failure | Rebuild committed inline rules offline |
| Local SOCKS/HTTP/Mixed listener / localListener | New bind or identical live socket reuse | Accept registration under Manager.mu | Ready=false, socket Close; join accept/session workers | Port conflict preserves working listener | DB listener intent; explicit degraded recovery on collision |
| TCP session / session | Bounded 4096 session admission | Local/remote sockets, generation, two copy workers | Cancel, close both directions; both copy workers finish | Dial/handshake failure unwinds generation | Volatile sessions terminate; no persisted socket state |
| UDP association / receive loop | Source-validated local relay | At most 32 flows, private scratch buffers/affinity | TCP owner/cancel/idle close relay and flows; worker join | Packet/dial failure bounded; no timeout changes | Volatile sessions terminate |
| TUN / tunIngress | Prepared owned device/stack, staged generation | One generation per TCP/UDP/DNS flow; reuse unchanged interface | Stop admission/stack before journal restore | Start/device/route failure unwinds owned handles | Reconcile durable journal before DB intent |
| Route / hostnetwork.Lease | Snapshot and persist prior state before mutation | Exact owner/generation/readback gate | Restore owned state; preserve external edits | Reverse steps with cleanup context | Journal replays interrupted writes; conflict fails closed |
| DNS interception / tunIngress | Existing TUN DNS ownership | TCP/UDP DNS flow retains one generation | Flow cancel/socket close and stack stop | Same TUN rollback | No standalone persistent DNS snapshot authority |
| Underlay / Factory.Lease | Begin pins generation; normalize bounded infrastructure endpoints | Shared endpoint references + protected numeric sockets | Last generation/socket closes lease; failed cleanup retains debt | Restore prior effective endpoints; degrade if restore fails | Host journal recovery before unsafe activation |
| Network journal / FileStore | Private directory and exclusive lock | Temp write, fsync, atomic replace, directory sync | Manager closes backend/store once | Temporary file cleanup; persisted conflict debt | Strict decoder, bounded generations, ownership checks |
| Wintun / ownedWintun | Persist GUID/owner, retain partial adapter/session | I/O Add ordered before Close Wait; ring data copied | Serialize interrupt/wait/end/adapter Close | Partial construction and End failure retain exact debt | Exact identity; no real Windows activation in this phase |
| WinINET / journal transition | Snapshot all supported connection state | Persist intermediate ownership before writes | Restore only matching owned fingerprint | Partial write matrix preserves external changes | Synthetic scope/identity recovery; unsafe activation blocked |
| Shared endpoint / underlay backend | Reconcile union of retained generation endpoints | Immutable replacement under control locks | Release only last reference; borrowed routes preserved | Prior set restored on partial failure | Durable owned route identity |
| SQLite / Store | Private files, exclusive installation lock, WAL/FULL, four connections | Repository/application transactions; expected revision | DB close before installation unlock | SQL rollback; bounded independent failed-operation journal | WAL recovery, immutable migration checksums, pending recovery |
| Temp/export/config artifact / writer | Private new temp file and explicit path | Sync/atomic rename where durability contract requires | Remove failed intermediates | Keep prior complete file | Rebuild derived files; never overwrite DB authority |
| Backup/restore / maintenance/install | Stopped service/exclusive lock; coherent snapshot and matching key | Existing preflight and forward migration | Release installation lock; clean incomplete destination | Failed replacement restores prior installation | SQLite snapshot and committed provider state; crash leftovers are nonauthority |
| Support bundle / operations | Read-only fixed projections; new 0600 destination | Sorted bounded safe archive members | Close archive/file; remove partial output | Errors/cancellation must remove partial output | Diagnostic artifact only; no raw DB/env/credentials |
| Stats / generation/session meters | Fixed IDs and counters | Atomic updates and copied projections | Current maps replaced; old maps live only with refs | No candidate counter publication | Volatile; no per-address/domain/session label retention |

## Lock ordering and cancellation

Application server/client control locks serialize their corresponding mutation
transactions. Repository write lock never calls back into application/runtime.
Client Manager.mu may acquire routeMu only for pointer publication; acquire()
releases routeMu before any cleanup or Manager.mu acquisition. Snapshot release,
adapter I/O/Close, policy stop, journal restore and socket close execute outside
Manager.mu. Policy group/dns mutexes are separate; no group lock spans probe I/O.
Management.mu is released before client.mu and HTTP I/O. SchedulerMu may wait
for workers; workers never acquire SchedulerMu. Native lifecycle locks do not
span payload I/O. Wintun closeMu precedes admission mu; I/O never takes closeMu.
Underlay/host backend locks serialize metadata and journal control, with no
reverse application acquisition. No global data path mutex is introduced.

Startup EnableRuntime/EnableClientRuntime/ConfigureHost are composition-only
initialization, before publishing the service. Prepared candidates have one
control owner; consumption must additionally reject manager shutdown and stale
publication. Session Background contexts are deliberately owned by Manager and
canceled on Close; rollback cleanup uses bounded independent contexts. Every
detached worker needs an explicit join or a resource owner.

## Findings and minimal fixes

- H15-001: HTTP Serve can return before its shutdown worker finishes; partial
  readiness failure also leaves that worker unjoined. Risk: teardown overlaps
  active application requests and shutdown errors are discarded.
- H15-002: Prepared.Activate has no closed-manager or expected-generation gate;
  Abort/Activate consumption is unsynchronized. Risk: post-shutdown resurrection
  or stale candidate publication and duplicate ownership release.
- H15-003: System DNS Bootstrap bypasses Engine.owner when managed DNS is
  disabled. Risk: work after engine Close and uncanceled retired resolver work.
- H15-004: provider failure metadata is applied to whichever provider revision
  is current after fetch completes. Risk: old request degrades an updated source.
- H15-005: Store.Close repeats installation unlock/file close. Risk: concurrent
  shutdown reports spurious failures instead of joining one release.
- H15-006: support archive writes do not stop for an already canceled request.
  Risk: unnecessary derived output after shutdown/cancellation.
- H15-007: native Activate stores admission even after Close. Risk: stale control
  callback reopens admission on a stopped handle.
- H15-008: abrupt death bypasses FileStore.Save temporary cleanup. Risk: reserved
  `.journal-*` files accumulate across restarts. Reopen must clean only private
  regular temporaries after acquiring exclusive directory ownership.
- H15-009: client support projection recognizes only Snell; client doctor treats
  degraded/enabled-stopped runtime as informational and application doctor lacks
  runtime/provider health comparisons. Risk: useful diagnosis is hidden. Fixed
  native protocol enum projection and passive health checks; no active probing.

H15-001 joins the shutdown worker and admitted handlers (including forced Close)
before runtime/SQLite release; request contexts inherit daemon cancellation.
H15-002 serializes candidate consumption, checks the expected snapshot pointer
and rejects activation after manager Close. The candidate retains its base
pointer, preventing pointer ABA reuse; the mutex does not cover payload I/O.
H15-003 joins system bootstrap to the network owner. H15-004 carries the observed
SQLite revision across I/O and discards stale failure metadata. H15-005 joins
SQLite Close through sync.Once. H15-006 checks cancellation before output and
between archive writes. H15-007 uses existing lifecycle locks to prevent stopped
native handles reopening admission. H15-008 removes private reserved crash
temporaries only after exclusive lock acquisition; unsafe types fail closed.

## Qualified failure and recovery windows

The new child-process suite exits without cleanup at transaction-before-commit,
after-commit/before-activation, runtime prepare, after activation, before old
adapter retirement, proxy/RuleSet fetch and committed refresh, partial journal
write, renamed journal, unacknowledged host write, active synthetic TUN metadata,
and private backup destination creation. Production fault hooks are not added.
SQLite/WAL and installation locks are real; host mutations are synthetic. Kernel
TUN recovery is separately checked in isolated WSL namespaces. An interface
creation with no persisted identity deliberately retains debt and fails closed;
recovery cannot safely infer ownership. A crashed explicit backup output is
preserved and cannot be reused silently; the source remains authority.

Generation/snapshot lifetime is exercised 25 times with retained old references;
TCP half-close and UDP retirement/shutdown are exercised 10 times with real
localhost sockets. Tests record goroutines/FDs/listeners/sessions/generations/
leases at start, peak and end. The echo fixture uses ordinary copy to avoid
counting the Linux stdlib splice pipe pool as Splicore descriptors. No production
copy path or timeout changes are made. Journal tests measure crash temporaries.

The complete Phase 15 implementation report and raw local gate evidence are in
`D:\splicore-validation\phase15-hardening-20261004`. This inventory is not a
freeze report or platform certification.

Other audited surfaces retain existing mechanisms. New tests and existing
failure/recovery regressions must substantiate PASS; the final Phase 15 report
records exact evidence, source changes, resource measurements and limitations.

## Validation boundaries

All fixtures are synthetic and owned localhost or isolated WSL namespaces.
No external target, NoBrand, Docker, Redis or TeleLedger access. No destructive
Windows or native Ubuntu host-network qualification. Linux arm64 is build only.
Vision/FinalMask/Sudoku/DoH/FakeIP remain deferred or out of scope. Existing
upstream runtime, wire protocol and migrations remain unchanged.
