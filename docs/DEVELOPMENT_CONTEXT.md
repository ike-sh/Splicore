# Development Context

- Documentation status: Canonical
- Audience: Developers, maintainers and returning coding agents
- Last reviewed: 2026-10-02
- Owner: Project maintainers
- Responsibility: Current project constraints and the minimum recovery context.
- Lifecycle: Replace obsolete constraints when reviewed scope changes; never append a diary.

## Goal and current phase

Splicore is an independent modular server proxy core derived from sing-box.
Phases 0–5 are locally frozen. Phase 5 implements an Experimental VLESS/REALITY
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
- Phase 4 freeze / main: `2a9c0f3e14de29050c1228ce013b2f1ad4556946`.
- Phase 5 freeze: the commit containing the local freeze report.
- One Phase 5 freeze commit and a Phase 6 branch are authorized by the maintainer.
- Phase 6 implementation remains unstaged/uncommitted; push/tag/release NONE.
- Sole remote: https://github.com/SagerNet/sing-box.git; no origin.
- Historical Phase 0–4 reports/evidence and migrations 0001–0003 immutable.
- Fresh artifacts/tools/logs/binaries/state/caches external; upstream runtime/dependency edits 0.
- Phase 5 authorizes native VLESS/REALITY and structural xray metadata only.
  No Xray download/run/render, FinalMask, Sudoku, Mieru, Panel or real NoBrand access.

## Architecture constraints

- Protocol and Engine are separate identities. API/domain represent `vless` + `native`;
  `vless` + `xray` is a valid future placement, currently not compiled/implemented.
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

Direct Phase5 composition registers four protocols, native compilers and exporters.
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
Fresh final evidence: `D:\splicore-validation\phase5-vision-deferred-20261002` and
`/root/splicore-validation/phase5-vision-deferred-20261002`. Initial Phase 5 and
`go-race-triage-20261002` evidence remain preserved; the final report owns current outcomes.
