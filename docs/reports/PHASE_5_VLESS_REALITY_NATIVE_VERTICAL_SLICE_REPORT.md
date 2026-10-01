# Splicore Phase 5 VLESS / REALITY Native Vertical Slice Report

- Documentation status: Historical
- Audience: Reviewers, protocol, engine and security maintainers
- Last reviewed: 2026-10-02
- Owner: Project maintainers
- Responsibility: Record the Phase 5 candidate, exact acceptance evidence and blockers.
- Lifecycle: Preserve this review snapshot; later fixes require fresh corresponding evidence.

## Baseline

Phase 4 Freeze / HEAD / main: `2a9c0f3e14de29050c1228ce013b2f1ad4556946`.
Upstream: sing-box v1.14.1, `1ac1a339cb1223e9c70eae14c44411c75033c02d`;
VLESS dependency sing-vmess v0.2.8 remains pinned. Branch:
`codex/phase-5-vless-reality-vertical-slice`. Entry working tree CLEAN;
candidate changes now unstaged/uncommitted. Sole remote upstream; no origin.

Fresh external evidence: `D:\splicore-validation\phase5-20261002`.
Native source/runtime: `/root/splicore-validation/phase5-20261002` on WSL2 ext4.
Source snapshot/manifest and validated functional manifest record exact bytes.
No evidence, binary, private input, DB, cache or fuzz artifact is added to the repo.
Phase 0–4 reports/evidence and migrations 0001–0003 remain unchanged.

## Status

VLESS: **Experimental**. REALITY: **Experimental**. Phase 5: **NOT READY**.
Default-race flow-none traffic and production Vision traffic pass. Vision's pinned
dependency fails checkptr and actual runtime race gates. Own unit race PASS does
not cover those traffic failures. No Stable or qualified VLESS client declaration.

## Architecture

Protocol ID: `vless`. Engine ID: `native`. Future compatible engine: `xray`.
Protocol != Engine: **PASS**. Domain/API represent each independently; engine
metadata lists implementations for the same protocol. VLESS protocol validation
accepts future placement; native compiler rejects xray intent, placeholder compiler
rejects execution and creation rejects unavailable xray before side effects.
No Xray download, execution, rendering, FinalMask or Sudoku implementation.

Account/Binding/Subscription and central ClientProfile gain no protocol/engine fields.
Existing inbound-owned Credential accommodates typed server secrets. Optional shared
server-material/repository ports and engine selection are foundation changes;
[ADR 0016](../adr/0016-vless-engine-server-secrets.md) owns the decision.

## Supported Surface

| Surface | Candidate contract |
|---|---|
| VLESS | Wire 0, canonical UUID, TCP only, XUDP payload over TCP |
| Plain | security=none, flow=none; no TLS encryption |
| Static TLS | Existing explicit CA/key-file model, TLS 1.3, independent SNI |
| REALITY | with_utls, typed public settings and separate inbound private key |
| Flow | Closed enum none / xtls-rprx-vision; Vision runtime qualification BLOCKED |
| Transports | TCP; UDP payload via XUDP, no UDP listener |
| Multi-user | Immutable UUID users, max 16; Alice/Bob one listener |
| Address families | IPv4/IPv6/domain; REALITY tests all three; plain/static TLS live tests IPv4 |
| Stats | Native authenticated routed payload/session counters by Inbound/Binding |
| Mutations | HotUserUpdate=false, HotReload=false; affected-Inbound reconcile/restart |
| Policy | Quota/rate/max sessions unsupported; explicit metadata-only remains metadata |
| Deferred | WS/gRPC/HTTPUpgrade/QUIC transports, extra mux controls, kTLS, dynamic TLS |

### Pinned source audit

| Source boundary | Audited behavior / managed choice |
|---|---|
| [VLESS inbound](../../protocol/vless/inbound.go) and [options](../../option/vless.go) | users/UUID/flow, pinned service, TLS, TCP listener and optional upstream transport/mux; managed surface excludes extra transports/mux controls |
| [VLESS outbound](../../protocol/vless/outbound.go) | packet encoding none/packetaddr/xudp paths; managed clients explicitly select xudp |
| sing-vmess v0.2.8 vless/service.go | UUID→user auth and flow enforcement, TCP/UDP/mux dispatch; service UpdateUsers is used only before Start |
| sing-vmess v0.2.8 vless/vision.go | Vision TLS wrapping and pointer/state access; exact checkptr/data races below |
| [REALITY server](../../common/tls/reality_server.go) | with_utls; 32-byte raw URL base64 private key, allowlisted server name, TCP target dialer, padded [8]byte short IDs; absent list admits all-zero ID |
| [TLS constructor](../../common/tls/server.go) | Reused TLS/REALITY construction; no copied wire/handshake/crypto code |
| [Pinned Mihomo source](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/adapter/outbound/vless.go) | Exact UUID/network/flow/TLS/reality-opts/packet-encoding/client-fingerprint fields; client config and actual traffic tested |

Baseline supports more options than this bounded profile. User/short-ID count caps,
canonical UUID/key encoding and rejection of duplicate padded IDs are deliberate
validation bounds, not invented upstream wire semantics. No arbitrary flow string.
No native safe hot UpdateUsers contract is claimed. The owned runtime adapter
tracks raw sockets and route meters around the unchanged service/TLS constructors.

## Credential

UUID generation: cryptographically secure UUID v4 via existing identity generator.
Supplied UUID: nonzero, dashed 36 chars; upper/lowercase accepted and duplicate
identities compare case-insensitively. Reject invalid/null/nonstring input and
duplicate keys. UUID is an account-owned typed Credential secret. Default JSON,
formatting, ordinary API, doctor, journal and logs redact it. Explicit authorized
client export reveals it. No protocol-secret Account columns.

## REALITY Secrets

| Material | Ownership / handling |
|---|---|
| Private key | Inbound-owned PrivateKeyPayload{algorithm=x25519, secret material}; strict canonical raw URL base64, 32 bytes |
| Generation / derivation | Standard-library crypto/ecdh X25519 and crypto/rand; supplied private/public pair must match |
| Storage | Existing AES-256-GCM vault; AAD binds credential ID, owner, kind and schema; protected external master key |
| Input | Separate write-only server_secret.private_key; omission generates before pending; explicit null rejects |
| Redaction / API / logs | Private key absent from default serialization, GET, doctor, audit/journal, errors, logs and all client outputs |
| Public key | Derived and persisted in typed public settings; ClientProfile/export contains this value only |
| Short ID | Even hex, 0–16 chars; zero-pad to 8 bytes; max 16 IDs; reject duplicate padded identity |
| Empty short IDs | Missing/empty list normalizes to all-zero ID; empty string valid; client selects first configured ID |
| Server name | Explicit validated DNS SNI/allowlist; independent of display host |
| Target | Separate validated host/port; TLS handshake target, absent from client profile |

Display endpoint domain A, SNI/target domain B and local listener are independently
tested. No automatic endpoint→SNI overwrite. Startup's bounded two-second target
TCP probe detects unreachable target; it does not prove TLS compatibility or
sustained target health. REALITY camouflage fallback can contact the target on
wrong authentication, while no authenticated user payload is routed.

## Secret Leak Gate

| Output | Result |
|---|---|
| Mihomo | PASS |
| sing-box | PASS |
| URI | PASS for supported plain/REALITY dialect |
| API export / ordinary reads | PASS |

**Server private key leaked: NO.** Blocking unit tests traverse all exporters and
API envelopes. Actual campaigns check private key absence even in explicitly
secret-returning export; ordinary responses/logs/doctor and raw DB/WAL plaintext
are checked for both UUID and private key. Export includes only authorized UUID
and public client fields, never runtime target/listener/server material.
Tests generate synthetic external secrets; no real private key fixture is committed.

## Multi-user

Alice/Bob same listener: PASS. Concurrent connections/authentication: PASS.
UUID→immutable Binding identity attribution: PASS independently of client tag.
Wrong UUID rejects user payload. Disable Alice: restart affected Inbound, close
sessions; Alice fails and Bob reconnects. Re-enable and committed SQLite restart:
PASS. Replacement resets runtime counters and interrupts every user on that Inbound.

## Runtime

Start, listener Health, Stop, Restart, committed-state Recovery and TCP port release:
PASS for accepted flow-none campaigns and production functional Vision campaigns.
Owned TCP/TLS lifecycle gates admission until commit, bounds initial handshakes to
five seconds, tracks unauthenticated/authenticated raw sockets, cancels/closes/waits.
Wrong key/config reject before publication; conflict/unreachable target compensate.
Vision default race runtime is **FAIL**, irrespective of production lifecycle PASS.

## Transaction

Shared Validate→Plan→materialize→Pending→compile/start→Health→SQL Commit→Activate.
Server credential commits with resources in the same transaction. Invalid UUID,
private/public pair, short ID, target and engine selection reject before side effects.
TCP port conflict, unreachable target and injected compile/start/health failures
publish no resources, release the candidate and preserve committed revision.
Binding recovery/reconcile retains committed server credentials. SQLite recovery
uses committed state plus explicit protected TLS references, not exported configs.
Existing shared commit-fault/compensation tests remain passing.

## Stats

Inbound: native routed payload bytes and sessions. Binding: authenticated UUID maps
to immutable Binding ID and isolated meters. Account: represented by those Binding
relationships, without durable aggregate counters or billing claims. Connections:
current/total routed TCP/XUDP sessions; unauthenticated socket counts are not billed.
Alice/Bob deltas and tag-independent attribution pass. Counters are runtime-generation
scoped and reset on reconcile/restart. Persistent usage and strict enforcement deferred.

## ClientProfile

Display endpoint, UUID, closed flow, security, REALITY public key, selected short ID,
server name, TCP transport and XUDP are represented. Private key: **ABSENT**.
Internal target/listener/engine: ABSENT. Static TLS carries explicit public CA/SNI.
Default serialization redacts UUID; only scoped export reveals client credentials.
Central ClientProfile code/cases remain unchanged.

## Exporters

- Mihomo 1.19.30: VLESS node, separate host/port, UUID, network=tcp, udp=true,
  packet-encoding=xudp, explicit flow, TLS/SNI; CA fingerprint or REALITY public-key/
  short-id plus chrome client-fingerprint. Actual parse and traffic PASS.
- sing-box 1.14.1: VLESS outbound, UUID, packet_encoding=xudp, explicit flow;
  explicit CA/SNI/insecure=false or uTLS/chrome/REALITY public_key/short_id. Traffic PASS.
- VLESS URI: bounded plain/REALITY grammar, IPv4/domain/IPv6 brackets, UUID,
  flow/security/SNI/pbk/sid/type/fp/packetEncoding and strict escaping. Parser/exporter
  contracts/fuzz PASS; reference-client URI import **NOT QUALIFIED**.
- Explicit-CA TLS URI: UnsupportedExport because this dialect cannot carry trust.
- Surge: UnsupportedExport; no VLESS support is inferred or fabricated.

## Interoperability

Final default-race binary SHA256: `5711d050b3160869d49844f8ce030b54d40cc592a7fd1fb2c54da0863c90b3d0`.
Final production binary SHA256: `779cab110f38ab7e7f34521236b55c62973aeb4b1293c2299f57fce61cb366b4`.
Mihomo 1.19.30 executable SHA256: `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`.
sing-box 1.14.1 executable SHA256: `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9`.
Pinned clients reused from verified Phase 4 artifacts; no client upgrade.

All 36 functional cells below pass. The 16 Vision production cells remain blocked
for race qualification. UDP is XUDP over TCP, not a VLESS UDP listener.

| Client | Version | User | Endpoint | Security | Flow | TCP | UDP | REALITY | Result |
|---|---|---|---|---|---|---|---|---|---|
| mihomo | 1.19.30 | Alice | 127.0.0.1 | reality | none | PASS | PASS | yes | PASS default race |
| mihomo | 1.19.30 | Bob | 127.0.0.1 | reality | none | PASS | PASS | yes | PASS default race |
| mihomo | 1.19.30 | Alice | ::1 | reality | none | PASS | PASS | yes | PASS default race |
| mihomo | 1.19.30 | Bob | ::1 | reality | none | PASS | PASS | yes | PASS default race |
| mihomo | 1.19.30 | Alice | localhost | reality | none | PASS | PASS | yes | PASS default race |
| mihomo | 1.19.30 | Bob | localhost | reality | none | PASS | PASS | yes | PASS default race |
| sing-box | 1.14.1 | Alice | 127.0.0.1 | reality | none | PASS | PASS | yes | PASS default race |
| sing-box | 1.14.1 | Bob | 127.0.0.1 | reality | none | PASS | PASS | yes | PASS default race |
| sing-box | 1.14.1 | Alice | ::1 | reality | none | PASS | PASS | yes | PASS default race |
| sing-box | 1.14.1 | Bob | ::1 | reality | none | PASS | PASS | yes | PASS default race |
| sing-box | 1.14.1 | Alice | localhost | reality | none | PASS | PASS | yes | PASS default race |
| sing-box | 1.14.1 | Bob | localhost | reality | none | PASS | PASS | yes | PASS default race |
| mihomo | 1.19.30 | Alice | 127.0.0.1 | none | none | PASS | PASS | N/A | PASS default race |
| mihomo | 1.19.30 | Bob | 127.0.0.1 | none | none | PASS | PASS | N/A | PASS default race |
| sing-box | 1.14.1 | Alice | 127.0.0.1 | none | none | PASS | PASS | N/A | PASS default race |
| sing-box | 1.14.1 | Bob | 127.0.0.1 | none | none | PASS | PASS | N/A | PASS default race |
| mihomo | 1.19.30 | Alice | 127.0.0.1 | tls | none | PASS | PASS | N/A | PASS default race |
| mihomo | 1.19.30 | Bob | 127.0.0.1 | tls | none | PASS | PASS | N/A | PASS default race |
| sing-box | 1.14.1 | Alice | 127.0.0.1 | tls | none | PASS | PASS | N/A | PASS default race |
| sing-box | 1.14.1 | Bob | 127.0.0.1 | tls | none | PASS | PASS | N/A | PASS default race |
| mihomo | 1.19.30 | Alice | 127.0.0.1 | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| mihomo | 1.19.30 | Bob | 127.0.0.1 | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| mihomo | 1.19.30 | Alice | ::1 | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| mihomo | 1.19.30 | Bob | ::1 | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| mihomo | 1.19.30 | Alice | localhost | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| mihomo | 1.19.30 | Bob | localhost | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| sing-box | 1.14.1 | Alice | 127.0.0.1 | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| sing-box | 1.14.1 | Bob | 127.0.0.1 | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| sing-box | 1.14.1 | Alice | ::1 | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| sing-box | 1.14.1 | Bob | ::1 | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| sing-box | 1.14.1 | Alice | localhost | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| sing-box | 1.14.1 | Bob | localhost | reality | xtls-rprx-vision | PASS | PASS | yes | PASS functional; race BLOCKED |
| mihomo | 1.19.30 | Alice | 127.0.0.1 | tls | xtls-rprx-vision | PASS | PASS | N/A | PASS functional; race BLOCKED |
| mihomo | 1.19.30 | Bob | 127.0.0.1 | tls | xtls-rprx-vision | PASS | PASS | N/A | PASS functional; race BLOCKED |
| sing-box | 1.14.1 | Alice | 127.0.0.1 | tls | xtls-rprx-vision | PASS | PASS | N/A | PASS functional; race BLOCKED |
| sing-box | 1.14.1 | Bob | 127.0.0.1 | tls | xtls-rprx-vision | PASS | PASS | N/A | PASS functional; race BLOCKED |

Accepted JSON under external native-evidence: final-runtime/vless-reality-none,
final-runtime/vless-none-none, final-runtime/vless-tls-none,
vf/production-vless-reality-xtls-rprx-vision and vf/production-vless-tls-xtls-rprx-vision.
Each includes exact server/client hashes and per-user deltas. IPv6/domain plain and
static TLS live cells are NOT RUN; no claim is made from REALITY coverage alone.

## Negative Interop

Wrong UUID/public key/short ID/server name: both clients reject authenticated
payload in REALITY none and production Vision campaigns; server remains healthy.
These negative rows say PASS for the rejection assertion, not successful access.
Wrong UUID plus untrusted CA/SNI cases cover static TLS; plain wrong UUID rejects.
No panic or secret leak in accepted campaigns. Vision race crashes are separately
retained failures, not counted as successful negative tests.

## Stress

Concurrency 16: PASS functional all accepted cells; default race PASS flow none,
Vision race FAIL. 4 MiB integrity: PASS; Vision adds verified inner TLS 1.3 4 MiB.
XUDP: 32 integrity/sequence packets per cell. Reconnect, reset/abnormal close,
forced client kill, clean shutdown/listener reuse, disable/re-enable, attribution
and SQLite restart: PASS in accepted campaigns.

## Regressions

| Protocol / gate | Actual final outcome |
|---|---|
| Snell | PASS 9 cells: three supported client/version combinations × IPv4/IPv6/domain; real TCP/UDP, 16 concurrent, 4 MiB, failures/recovery/port release |
| Hysteria2 | PASS 12 cells: both clients/users × IPv4/IPv6/domain; shared storage/API/transactions/reconcile/recovery/TCP/UDP |
| TUIC | PASS 12 cells: both clients/users × IPv4/IPv6/domain; shared TLS/QUIC/auth/recovery/runtime |
| Original sing-box | PASS Windows/Linux builds, Linux arm64 compile, original root-module CI with pinned release tags/ldflags |

Root CI initially found a stale cmd/splicore identity-test schema=3 expectation.
Updated it for schema 4; full root CI and Windows command test then PASS. No original
sing-box runtime source changed. Docker-dependent nested test module excluded.

## Protocol / Engine Architecture

Direct Phase5 registry registers four protocols; VLESS plain/TLS/REALITY are feature
profiles under one identity. Engine registry exposes native and non-running xray
implementations for vless. Native compiler map owns execution. Shared creation selector
and independent API plan/inbound/implementation metadata make future binding representable.
Domain/ports contain no concrete engine schema. Build without with_utls reports
REALITY not_compiled and rejects creation.

| Fourth-protocol audit | Additions |
|---|---|
| Central protocol switches | 0 |
| Central engine branches | 1 generic native placement guard |
| Application protocol branches | 0 |
| Storage protocol-specific columns | 0 |
| Account protocol-specific fields | 0 |
| ClientProfile central protocol cases | 0 |

Engine selection plumbing is generic and permitted. Module/native/exporter format
switches are local ownership; composition maps are registration. Phase 3 creation,
phase-chain and display allowlist debt remains resolved by Phase 4. No shared QUIC
control-plane copy or VLESS Account specialization. Future Xray binding: **YES**.

## Security

Credential UUID and REALITY private key retain typed secret redaction and encrypted
storage. Public key is distinct from private key in types and projections. Logs,
doctor, ordinary API and sanitized evidence omit secrets. Blocking exporter/API
leak gate PASS. Changed-source artifact/secret scan PASS; no generated material
in repo. Synthetic UUID literals are test fixtures, not real credentials.
The existing standard-library AEAD/X25519 boundary is used; no homemade encryption.
No promise of perfect Go heap zeroization, crash-dump safety or production Windows
DACL provisioning. Future support bundles must preserve server-secret exclusion.

## Storage

Schema migration: **YES**, 0004_private_key, schema 4. Reason: extend the generic
closed credential-kind CHECK for inbound-owned X25519 PrivateKeyPayload; ownership
already exists. No fixed reality_private_key/vless_uuid or Account columns.
Migration preserves prior ciphertext/AAD, FKs, Binding/policy relationships and
Snell single-Binding trigger. Populated schema 2/3→4 and private-key roundtrip PASS.
SQLite committed state authority: PASS, with real close/reopen recovery.

Secret-at-rest model is recoverable AES-256-GCM Credential encryption from Phase 1,
using protected externally supplied master key, not plaintext SQLite secrets.
Master key is absent from DB; SQLite file access plus possession of that key can
decrypt secrets. Filesystem permissions/ownership remain required. TLS key files
remain external. Rotation/recovery provisioning/backup orchestration and Windows
production ACLs remain deferred; these are not claimed solved by schema 4.

## Platform

Windows amd64 Go 1.26.2: tagged/no-tag own units/build PASS, command units PASS,
own vet PASS, original sing-box release-tag build PASS. Production control API
still Linux only. Linux Ubuntu-24.04 WSL2/ext4 Go 1.26.6: own units/vet/race units,
default race builds/flow-none traffic and all prior-protocol regressions PASS.
Vision runtime race/checkptr FAIL. Linux arm64: both executables compile with
with_quic/with_utls or full original release tags; execution NOT RUN.

## Upstream Runtime Modifications

Count: **0**. Dependency modifications: **0**. Wire source copies: **0**.
VLESS/REALITY/mux/XUDP/crypto remain pinned upstream. New owned adapter composes
services and lifecycle/accounting hooks. Original runtime/dependency files untouched.

## Tests

| Gate | Final result / external evidence |
|---|---|
| Windows tagged/no-tag units, builds, command | PASS; windows-final-gates.tsv |
| Windows/Linux own vet | PASS; windows-vet-final.log / linux-vet-final.log |
| Linux own unit + unit race | PASS; linux-unit-final.log / linux-race-unit-final.log |
| Default race REALITY/plain/TLS flow none | PASS; reality-none-final.log, none-none-final.log, tls-none-final.log |
| Default race Vision | FAIL checkptr; final runtime server-1.log plus earlier static TLS reproduction |
| Vision dependency-scoped checkptr diagnostic | FAIL actual DATA RACE; runtime/vless-*-xtls-rprx-vision/server logs |
| Production Vision | PASS functional 16 cells; *-vision-production-final-short.log; does not qualify race |
| Runtime/transaction/recovery/negative/leak | PASS accepted campaigns + own fault/boundary tests |
| Snell/HY2/TUIC real regressions | PASS 9/12/12 cells; *-regression-final.log and JSON |
| Original root-module CI | PASS; upstream-root-ci-final.log; prior stale-schema failure retained |
| Arm64 compile | PASS; linux-arm64-splicore.log / linux-arm64-original.log |
| Docs/links/OpenAPI/live safe responses | PASS 72 Markdown documents / 689 links; OpenAPI and actual safe VLESS/HY2/TUIC/Snell responses; docs-gates.json |
| Secret/source/artifact/index/protected-file audit | PASS; repo-audit.json / native-evidence-manifest.json |
| git diff --check | PASS tracked and untracked; no staging used |

Fuzz covers parsers/validation only, no cryptographic primitive fuzzing. External
Go cache/temp/test workspace; no failed corpus or fuzz output in repo.

| Target | Time / workers | Executions | Result |
|---|---|---|---|
| Settings | 10 s / 2 workers | 286813 | PASS |
| UUID | 10 s / 2 workers | 396734 | PASS |
| ShortID | 10 s / 2 workers | 408939 | PASS |
| Target | 10 s / 2 workers | 367941 | PASS |
| uri | 10 s / 2 workers | 296168 | PASS |

Windows initial original-build runner stopped on Go's harmless download stderr due
to PowerShell Stop policy. A subprocess runner completed the real build. Early
external harness attempts found missing target resolver, eager bool default, reuse
checks including TIME_WAIT, and overlong private UDS paths. Fixed shared local resolver,
harness logic/reuse assertion or shortened external directory; no safety gate waived.
Accepted final campaigns use actual result JSON. Failed checkptr/race diagnostics
and development attempts remain retained and distinctly labeled. No global
sanitizer disable or dependency patch is used for acceptance.

Owned process cleanup PASS: 352 recorded launches, 0 live owned processes.
Private inputs removed; 807 safe evidence files hashed externally.


## Docker

Touched: **NO**. Docker/Redis/TeleLedger **UNTOUCHED**. No daemon queries, restarts,
cleanup or reference Docker tests. External cleanup: **DEFERRED**. Host /etc/hosts
unchanged; each runtime campaign owns a loopback-only network and private hosts mount.
Default WSL user shell and unrelated `/` Git configuration unchanged.

## NoBrand

Real changes/access: **NONE**. [Synthetic VLESS fixture](../../tests/fixtures/nobrand/vless-reality.json)
and [mapping](../integration/NOBRAND_MIGRATION.md#synthetic-vless--reality-mapping)
cover name, listener, public endpoint, UUID, flow, separate private/public model,
short IDs, server name and target. Private material omitted for secure generation.
Installer integration must use typed validate/plan/apply; no sing-box JSON renderer
or direct SQLite mutation. Production importer/canary deferred.

## Documentation

Canonical README/index/context/architecture, SDK, engine, client compatibility,
storage/ERD, transaction/security, API/OpenAPI, interop and synthetic migration
updated. Added VLESS support, Phase 5 workflow and ADR 0016. Current context replaces
obsolete authorization rather than appending a diary. Historical Phase 0–4 reports:
**UNCHANGED**, checked against entry hashes and Git diff.

## Git

Stage **NONE**; Commit **NONE**; Push **NONE**; Tag **NONE**; Release **NONE**.
HEAD/main and sole upstream remote unchanged. Index SHA256 unchanged:
`4104273f36b58833e65920d91aae48f035d1fff838d726184eefccb0113a8026`.
Work remains unstaged on Phase 5 branch for review. No local main fast-forward.

## Deferred

Xray runtime, FinalMask, Sudoku, Mieru, Panel, unified quota/rate enforcement,
persistent aggregate usage, NoBrand production canary, Stable designation,
extra transports/mux controls, URI client-import qualification, hot users/reload,
key rotation/provisioning and production Windows control/ACL qualification.

## Architecture Deviations

No forbidden runtime/model deviation. Generic engine selector/API engine identity,
server-secret ports and schema 4 are necessary bounded foundation changes;
their rationale and future compatibility are tested. Native TCP ownership is a
small adapter around existing wire/TLS, not a copied protocol implementation.
Vision cannot satisfy the required safety gate within the unchanged-upstream and
pinned-dependency boundary. This report records that limit without waiving it.

## Final Result

**NOT READY**. Native VLESS/REALITY implementation, structural Protocol != Engine,
secret boundaries, flow-none interoperability and prior regressions are reviewable.
Phase 5 acceptance remains blocked by Vision runtime safety.

## Blockers

1. **Vision checkptr fatal on default Go 1.26 race builds.** Pinned sing-vmess v0.2.8
   NewVisionConn uses pointer→uintptr offset arithmetic at vision.go:87. Final
   REALITY Vision default-race server and earlier static TLS Vision server terminate.
   Final evidence: native-evidence/final-runtime/vless-reality-xtls-rprx-vision/server-1.log;
   static TLS evidence: native-evidence/runtime/development-tls-vision-checkptr-failure/server-1.log.
2. **Actual Vision Read/Write data race.** A diagnostic build with
   `-gcflags=github.com/sagernet/sing-vmess/vless=-d=checkptr=0` still reports races
   between VisionConn.Read at vision.go:174 and filterTLS/Write at vision.go:250/196,
   with further shared-state access. Both REALITY and static TLS reproduce this.
   Evidence: native-evidence/runtime/vless-reality-xtls-rprx-vision/server-1.log and
   native-evidence/runtime/vless-tls-xtls-rprx-vision/server-1.log. This exception is
   diagnostic only, never a passing race build.

[Pinned Vision source](https://github.com/SagerNet/sing-vmess/blob/v0.2.8/vless/vision.go)
and default/diagnostic logs agree. Production functional PASS cannot clear either
blocker. Resolving these requires a reviewed decision about the pinned upstream
boundary or removal of Vision from the accepted surface, followed by fresh traffic
and race evidence. No such scope change is silently made here.
