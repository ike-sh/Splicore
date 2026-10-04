# Development Context

- Documentation status: Canonical
- Audience: Developers, maintainers and returning coding agents
- Last reviewed: 2026-10-04
- Owner: Project maintainers
- Responsibility: Current project constraints and the minimum recovery context.
- Lifecycle: Replace obsolete constraints when reviewed scope changes; never append a diary.

## Goal and current phase

Phase 6 freezes the Experimental Xray compatibility engine and
VLESS native/xray duality. The reference and gates follow
[ADR 0018](adr/0018-xray-owned-child-engine.md).
The [Phase 6 report](reports/PHASE_6_XRAY_ENGINE_DUALITY_REPORT.md) records passing
duality/runtime/regression gates and explicit platform limits. Phase 7 freezes
Experimental FinalMask/Sudoku from official Xray v26.3.27
without changing the Phase 6 artifact. See [ADR 0019](adr/0019-xray-specialized-feature-boundary.md)
and [workflow](development/PHASE_7_XRAY_EXTENSIONS.md). The
[freeze report](reports/PHASE_7_FREEZE_REPORT.md) records the authorized local checkpoint.
Phase 8 is **FROZEN**. It freezes Experimental Mieru native embedding
under its [freeze report](reports/PHASE_8_FREEZE_REPORT.md).
Phase 9 / Distribution is **FROZEN**, with local pinned packages, a
dedicated user, one systemd unit, snapshot upgrade/rollback and redacted diagnostics.
Installed-service lifecycle and protocol gates pass on Ubuntu 24.04 WSL2 amd64;
arm64 is build only. See [distribution](DISTRIBUTION.md) and the
[Phase 9 report](reports/PHASE_9_DISTRIBUTION_SERVICE_FOUNDATION_REPORT.md).
The [Phase 9 freeze report](reports/PHASE_9_FREEZE_REPORT.md) records the authorized
single commit, main fast-forward and clean branch preparation:
`codex/phase-10-client-runtime-foundation`. Phase 10 freezes an **Experimental Client Runtime** under the maintainer authorization.
Local SOCKS TCP, DIRECT and Snell/native are implemented. Phase 11 adds standard
SOCKS UDP ASSOCIATE and HY2/TUIC/VLESS native or Xray/Mieru outbounds. NoBrand migration is deferred
until the unified client/server core is complete. The [Phase 10 freeze report](reports/PHASE_10_FREEZE_REPORT.md)
records the single commit, main fast-forward and clean
`codex/phase-11-client-outbound-expansion` branch. Phase 11 is **FROZEN** under its
[freeze report](reports/PHASE_11_FREEZE_REPORT.md). The prepared branch is
`codex/phase-12-routing-dns-policy`; Phase 12 is **FROZEN** under its
[freeze report](reports/PHASE_12_FREEZE_REPORT.md). The prepared next branch is
`codex/phase-13-tun-system-integration`, based on Phase 12. Phase 13 is **FROZEN**
under its [freeze report](reports/PHASE_13_FREEZE_REPORT.md). Unified runtime underlay
wiring, dynamic/retained/shared references and reused TUN reconciliation pass final
gates; Wintun and WinINET ownership blockers remain closed. Real Windows
qualification still blocks activation. The prepared branch is
`codex/phase-14-client-management-providers`; implementation is **NOT STARTED**.
See the frozen boundary below.
Push/tag/release remain prohibited.

Splicore is an independent modular client/server proxy core derived from sing-box.
Phases 0–11 are locally frozen. Phase 5 implements an Experimental VLESS/REALITY
Native candidate. Vision is **DEFERRED / UNSUPPORTED** due to pinned dependency
checkptr and Read/Write defects. Flow-none VLESS/REALITY remains supported;
its fresh acceptance gates pass with default checkptr and race. The supported
surface passed review gates and is locally frozen under the
[freeze report](reports/PHASE_5_FREEZE_REPORT.md). See [VLESS](protocol/VLESS.md), [workflow](development/PHASE_5_VLESS.md)
and [report](reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md).
Snell/Hysteria2/TUIC remain Experimental; no Stable release.

## Reproducible baseline and authorization

- Upstream v1.14.1: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
- Phase 0 freeze: `687425bdbfff6c76f900035068c23a03c4547062`.
- Phase 1 freeze: `a2ca59e6dbf1a239feae5e471ec1914cae0f1eac`.
- Phase 2 freeze: `5bc50a69b0df2c3dc9ede86015c9e4a6b86e2981`.
- Phase 3 freeze: `94555d9608ebcc36c5a396bc06a5743cce4e0788`.
- Phase 4 freeze: `2a9c0f3e14de29050c1228ce013b2f1ad4556946`.
- Phase 5 freeze: `afacb248440aedb6ac5a2f0d14ad7defedddb627`.
- Phase 6 freeze is the commit containing the [Phase 6 report](reports/PHASE_6_XRAY_ENGINE_DUALITY_REPORT.md),
  with message `feat(engine): add Xray compatibility engine duality` and sole parent Phase 5.
- The maintainer authorized the missing main fast-forward to Phase 5, one Phase 6
  freeze commit, main fast-forward to Phase 6 and a clean Phase 7 branch.
- `codex/phase-6-xray-engine-duality` retains Phase 6 at `438b1096b9ec357cddb163cf89f78935e711bf3d`.
- `codex/phase-7-xray-vless-extensions` starts at `438b1096b9ec357cddb163cf89f78935e711bf3d`.
- The maintainer authorized Phase 7 integration after the preliminary source audit.
- The maintainer authorized one Phase 7 commit, message
  `feat(engine): add experimental Xray VLESS extensions`, sole parent Phase 6,
  main fast-forward and creation of `codex/phase-8-mieru-native-integration`.
- `codex/phase-7-xray-vless-extensions` retains Phase 7 at
  `ca48d8429abb21fcaf7ee21d68e37d1ec5d6ec4d`; Phase 8 began CLEAN there.
- The maintainer authorized one Phase 8 commit, message
  `feat(protocol): add experimental Mieru native integration`, sole parent Phase 7,
  main fast-forward and creation of `codex/phase-9-distribution-service-foundation`.
  The Phase 8 commit contains the freeze report; obtain its full SHA from
  `git rev-parse codex/phase-8-mieru-native-integration`. main and Phase 9 start there.
  Phase 8 SHA: `bd141f98e28d9499a88fe610ba3fc49aca48bf14`.
- The maintainer explicitly authorized one Phase 9 freeze commit:
  `feat(dist): add Linux service distribution foundation`, sole parent Phase 8,
  main fast-forward and creation of `codex/phase-10-client-runtime-foundation`.
  Resolve its full SHA from `git rev-parse codex/phase-9-distribution-service-foundation`;
  the freeze report cannot embed its own commit SHA. Phase 10 starts CLEAN there.
  Stage/commit authorization was limited to this freeze; subsequent work remains
  uncommitted unless separately authorized. Push/tag/release NONE.
- Sole remote: https://github.com/SagerNet/sing-box.git; no origin.
- Phase 9 SHA: `d47ef2c584654eaa8eaa965ef26b7acc24881e1f`.
- The maintainer separately authorized one Phase 10 freeze commit:
  `feat(client): add client runtime foundation`, sole parent Phase 9,
  main fast-forward and creation of `codex/phase-11-client-outbound-expansion`.
  Resolve its full SHA from `git rev-parse codex/phase-10-client-runtime-foundation`;
  the freeze report cannot embed its own commit SHA. Phase 11 starts CLEAN there.
  Phase 10 SHA: `463cb8ea4fc497d684b0f4ff8923015009d1187e`.
- The maintainer separately authorized one Phase 11 freeze commit:
  `feat(client): expand protocol outbounds and SOCKS UDP`, sole parent Phase 10,
  main fast-forward and creation of `codex/phase-12-routing-dns-policy`, then stop.
  Resolve its full SHA from `git rev-parse codex/phase-11-client-outbound-expansion`;
  the freeze report cannot embed its own commit SHA. Phase 12 starts CLEAN there.
  That authorization covered Phase 11 closure only. The subsequent Phase 12 request
  authorized implementation and local acceptance gates.
- Phase 11 SHA: `5397f8e6ef8e28981099b14b9e09400593048b7e`.
- The maintainer separately authorized one Phase 12 freeze commit:
  `feat(client): add routing DNS and policy engines`, sole parent Phase 11,
  main fast-forward and creation of `codex/phase-13-tun-system-integration`, then stop.
  Resolve Phase 12 SHA from `git rev-parse codex/phase-12-routing-dns-policy`;
  the report cannot embed its own commit SHA. Stage/commit authorization is limited
  to this freeze. TUN/system proxy/NoBrand work is not authorized by this closure.
- Historical Phase 0–11 reports/evidence and migrations 0001–0005 immutable.
- Fresh artifacts/tools/logs/binaries/state/caches external; upstream runtime edits 0.
  Phase 8 adds the audited official Mieru module, with no dependency upgrades.
- Phase 6 authorizes official pinned Xray research/download, owned external child,
  standard flow-none VLESS/REALITY dual placement, tests and documentation.
  Phase 7 adds bounded FinalMask/Sudoku; no Vision workaround, Mieru or Panel.
  NoBrand source audit is read-only; production changes remain NONE.

## Architecture constraints

- Protocol and Engine are separate identities. API/domain represent `vless` + `native`;
  `vless` + `xray` is an implemented Experimental external child placement.
- Shared selection defaults to native; unavailable placement rejects before side effects.
  Account/Binding/Subscription/ClientProfile remain independent of engine names.
- Account, Binding and Credential separate identity, authorization and secret ownership.
- Listener, DisplayEndpoint, SNI, REALITY target and egress are distinct concepts.
- SQLite committed generation is domain authority; bootstrap owns process settings.
- RuntimeIntent and ClientProfile are separate projections; exporters own client mappings.
- Domain/ports do not depend on HTTP, SQL drivers or upstream runtime options.
- Registration is explicit and compiled; no dynamic Go plugins.
- Journal, generation fences and compensation handle non-atomic DB/socket lifecycle.
- Strict quota/rate needs proven payload enforcement; polling is insufficient.
- Interoperability requires exact client/profile traffic evidence, separate from rendering.

## Implemented and deferred scope

Schema 4 extends only the generic credential-kind CHECK for typed inbound-owned
X25519 private keys. Existing AES-256-GCM vault/AAD protects UUIDs and private keys;
the protected external master key is not stored in SQLite. No protocol columns or
Account fields. Key rotation/recovery provisioning and Windows production DACLs
remain deferred. Old migrations, ciphertext/AAD and relationship constraints survive.

Phase6 composition fills the Phase5 xray slot; historical constructors remain fixtures.
Shared creation/resource builder owns validate/plan/pending/start/health/commit/admission;
recovery/reconcile loads committed server secrets through a separate port. Client
projection cannot read that port. Protected Linux UDS API/CLI share commands.
Ordinary reads/doctor/logs omit secrets; scoped client export reveals UUID but never
server private key or internal target/listener. REALITY requires `with_utls`.

VLESS supports TCP/XUDP, immutable UUID users, plain/static TLS/REALITY and flow none.
Vision is deferred/unsupported; config, API/CLI/import, runtime and exports reject it. HotUserUpdate and
HotReload false: reconcile interrupts the affected Inbound and resets counters.
HY2/TUIC retain shared static TLS/QUIC admission and immutable Binding attribution.
See [ADR 0016](adr/0016-vless-engine-server-secrets.md) and the
[fourth-protocol audit](ARCHITECTURE.md#phase-5-fourth-protocol-realization).

General Account mutation/rotation, quota/rate, durable usage aggregates, delete,
dynamic TLS, Snell userkey multi-user, generic imports and Stable remain deferred.

## Authority and forbidden shortcuts

Start at the [docs index](README.md), [architecture](ARCHITECTURE.md),
[specification map](architecture/README.md) and [ADRs](adr/README.md).
OpenAPI owns the API; migrations own actual schema; historical reports record past
outcomes. Update current specs under the [documentation policy](DOCUMENTATION_POLICY.md).
Do not expose raw runtime JSON, let installers edit SQLite, add protocol Account
columns, weaken unsupported policy, or infer qualification from rendered exports.
Preserve upstream provenance, LICENSE, copyright and non-affiliation.

## Validation context

Ubuntu-24.04 WSL2 native ext4 runtime/TLS/socket and default race traffic are gates.
Pinned Mihomo 1.19.30 and sing-box 1.14.1 remain unchanged; verify their SHA256.
Source snapshots include a byte manifest; caches/temp/binaries/fuzz/logs external.
Runtime namespaces use loopback only plus a private synthetic hosts mount; host
network and /etc/hosts remain unchanged. No sanitizer suppression or upstream dependency patch is authorized. Retain the original failed diagnostics. Re-enable
requires an explicit reviewed dependency evaluation and all ADR 0017 gates.

Docker/Redis/TeleLedger UNTOUCHED. External cleanup DEFERRED. Real NoBrand untouched.
Do not query/restart Docker, operate Redis, repair the WSL default user's shell,
or alter unrelated `/` Git configuration. Two inherited unsafe.Pointer vet findings
are tracked in the [baseline ledger](architecture/UPSTREAM_BASELINE.md).
Phase 6 evidence: `D:\splicore-validation\phase6-20261002` and
`/root/splicore-p6-20261002`. Phase 5 evidence/reports and original race triage
remain preserved. [Phase 7 workflow](development/PHASE_7_XRAY_EXTENSIONS.md) owns current gates.

## Xray runtime boundary

Xray v26.3.27 is operator-provided and exact binary SHA/version verified. Core
never downloads. Missing optional binary leaves native-only startup healthy;
committed Xray recovery requires that engine and has no fallback. Capability
API composes engine support and reports last node validation separately.
Splicore owns public admission and a protected ephemeral generation; child owns
private loopback VLESS processing. Wait reaps/cleans; crash marks failed/degraded,
manual recovery only. Hot updates, Xray attributed/persistent stats and strict
quota/rate/session enforcement are deferred. [ADR 0018](adr/0018-xray-owned-child-engine.md).

## Phase 7 boundary

FinalMask is the framework; Sudoku is the single qualified TCP mask. Protocol vless,
Engine xray, plain/flow none, prefer_ascii/padding0–3. Masked UDP NOT QUALIFIED,
TLS/REALITY combinations UNSUPPORTED. Typed engine options persist in existing
settings JSON, schema 4 unchanged. Inbound-owned shared Password uses the vault;
Accounts retain UUIDs. A narrow authorized client-secret port excludes private keys.
Xray 26.3.27 client JSON is supported; masked Mihomo/sing-box/Surge/URI reject.
Availability uses exact Phase 6 SHA256/version. Supervisor/stats/policy remain Phase 6.
Windows crash safety qualification and Xray arm64 runtime remain deferred.

## Phase 8 current ownership boundary

Frozen branch `codex/phase-8-mieru-native-integration`, Phase 7 parent above.
Phase 10 started from the frozen Phase 9 commit and is now locally frozen.
[Mieru](protocol/MIERU.md),
[ADR 0020](adr/0020-mieru-owned-native-embedding.md),
[workflow](development/PHASE_8_MIERU.md), [report](reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md).
No permanent mita child, source fork/copy, wire rewrite, new EngineID, shared domain
fields/migrations/routes or real NoBrand modifications. Docker DO NOT QUERY / DO NOT TOUCH.
QuotaNative/speed/hot updates/durable accounting unexposed; clients remain Experimental.

## Phase 10 frozen boundary

Frozen branch: `codex/phase-10-client-runtime-foundation`. Its sole parent is Phase 9
`d47ef2c584654eaa8eaa965ef26b7acc24881e1f`; entry worktree was clean and index empty.
Schema 5 adds generic client intent and node-owned encrypted credentials, retaining
migrations 0001–0004. Shared generation lifetime and transactional restart are
owned in [Client Runtime](architecture/CLIENT_RUNTIME.md). One binary/unit runs both
roles. TUN, DNS/policy/subscription and NoBrand migration remain deferred. Phase 10 is FROZEN under the [freeze report](reports/PHASE_10_FREEZE_REPORT.md).
Phase 11 entry branch: `codex/phase-11-client-outbound-expansion`, based on the
Phase 10 freeze commit `463cb8ea4fc497d684b0f4ff8923015009d1187e`. Entry worktree
was CLEAN with EMPTY index. Phase 11 now implements the six outbound adapter pairs
and local SOCKS UDP, locally frozen under its authorized single commit.
Push/tag/release NONE; Docker DO NOT QUERY / TOUCH.
Acceptance evidence: `D:\splicore-validation\phase10-20261002`.
Freeze evidence: `D:\splicore-validation\phase10-freeze-20261003`.

## Phase 11 frozen boundary and Phase 12 entry

Default race/checkptr is required without sanitizer suppression. Evidence is outside
the checkout at `D:\splicore-validation\phase11-20261003`. Source/NoBrand/historical
reports/migrations and unrelated refs match the entry manifest. Freeze evidence is
`D:\splicore-validation\phase11-freeze-20261003`; exact-file staging and one commit
were separately authorized. main fast-forwards to Phase 11, and the final action
creates `codex/phase-12-routing-dns-policy`. At that entry, worktree CLEAN; index EMPTY.
The subsequent Phase 12 request implemented routing/DNS/policy; its separately
authorized local freeze is recorded below.
Push, tag and release NONE.
Client capability qualification remains Experimental; Vision rejects all engines,
FinalMask/Sudoku client runtime remains deferred, and frozen server scopes remain.
See [client runtime](architecture/CLIENT_RUNTIME.md) and
[report](reports/PHASE_11_CLIENT_OUTBOUND_EXPANSION_REPORT.md) and
[freeze](reports/PHASE_11_FREEZE_REPORT.md). Windows tests/build PASS, race NOT EXECUTED;
Linux arm64 BUILD ONLY/runtime NOT CERTIFIED; Xray TCP half-close NOT QUALIFIED.

## Phase 12 boundaries

Canonical graph lives in SQLite schema 6; owned immutable snapshots and ephemeral
health/cache are runtime artifacts. Ordered domain/IP/port/network/local/set rules,
Selector/URL-Test/Fallback/RR and System/UDP/TCP/verified DoT are implemented.
DoH, regex, FakeIP/TUN, Geo data, providers/subscriptions and automation remain deferred.
The unchanged Phase 12 acceptance report owns its review-time evidence. The
[freeze report](reports/PHASE_12_FREEZE_REPORT.md) records exact-file staging,
one authorized commit and main fast-forward. Push/tag/release NONE.
[Routing](architecture/ROUTING_MODEL.md), [DNS](architecture/DNS_MODEL.md),
[policy](architecture/POLICY_MODEL.md), [report](reports/PHASE_12_ROUTING_DNS_POLICY_REPORT.md).

## Phase 13 frozen boundary

Branch `codex/phase-13-tun-system-integration`, base
`d09f5f10797aa63798419fa77ffd676257f1b609`, entered CLEAN/index EMPTY.
The maintainer separately authorized exact-file staging, one commit
`feat(client): add TUN and system integration foundation`, main fast-forward and
creation of `codex/phase-14-client-management-providers`, then immediate stop.
The Phase 13 commit contains the [freeze report](reports/PHASE_13_FREEZE_REPORT.md);
resolve its full SHA with `git rev-parse codex/phase-13-tun-system-integration`.
Freeze evidence: `D:/splicore-validation/phase13-freeze-20261004`.
Earlier evidence: `D:/splicore-validation/phase13-20261003`.
See [system integration](SYSTEM_INTEGRATION.md) for implemented Linux/HTTP/DNS scope
and real Windows activation guards. Windows ownership closure evidence is
`D:/splicore-validation/phase13-windows-20261004`; Wintun split ownership, typed LAN
WinINET and bypass reconciliation are implemented/fixture-qualified. Current
underlay closure evidence is `D:/splicore-validation/phase13-underlay-20261004`.
Unified socket/resolver/child capabilities, fresh DNS, retained refs and reused TUN
reconciliation are implemented and source-bound final gates PASS. The Experimental
scope is frozen; real Windows activation guards remain.
Only existing Windows/WSL is authorized;
native Linux and Windows host-network runtime qualification remain pending.
FakeIP/DoH/providers/subscriptions/Vision/NoBrand migration remain deferred.
Docker DO NOT QUERY / DO NOT TOUCH. Historical Phase 0–12 reports remain unchanged.

## Phase 14 entry and authorization limit

Phase 14 branch starts CLEAN with EMPTY index at the Phase 13 freeze commit.
Implementation is NOT STARTED; branch creation is the final authorized mutation.
The freeze does not authorize Subscription/Provider or NoBrand work. Prior source
audit/actual adapter evidence stays under `D:/splicore-validation/phase13-underlay-20261004`;
see [acceptance](reports/PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md).
Freeze gates include default race/checkptr, shared/10x lifetimes, static audit,
safe kernel lab, builds, distribution/service, live schemas and staged privacy.
Real Windows/native Ubuntu/arm64 runtime qualification stays pending; activation
guards and all deferred scopes remain. Push/tag/release NONE. Stage/commit
authorization was limited to the single Phase 13 freeze.
