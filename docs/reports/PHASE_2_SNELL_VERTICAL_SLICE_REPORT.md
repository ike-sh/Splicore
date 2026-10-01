# Splicore Phase 2 Snell Vertical Slice Report

- Documentation status: Historical
- Audience: Maintainers and Phase 2 reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Completed Phase 2 scope, actual evidence, limitations and review result.
- Lifecycle: Acceptance snapshot for this uncommitted worktree; corrections require explicit review.

## Baseline

Phase 1 Freeze Commit / HEAD / main:
`a2ca59e6dbf1a239feae5e471ec1914cae0f1eac`.
Phase 0 freeze: `687425bdbfff6c76f900035068c23a03c4547062`.
Upstream: sing-box v1.14.1, `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
Entry branch `codex/phase-2-snell-vertical-slice`, clean entry worktree, empty index.
Only remote upstream; no origin. Module remains github.com/sagernet/sing-box.

## Support Status

Snell **Experimental**. Managed server v5 no obfs and v6 default encrypted/shaped
mode. Native server supports 5/6; native client supports 4/6. No separate v4 server.
Unsupported/deferred: QUIC Proxy Mode, managed obfs, non-default v6 modes,
userkey multi-user, policy enforcement, listener/user hot mutation and stable status.
Other protocol adapters remain Foundation placeholders.

## Architecture

| Boundary | Realization |
|---|---|
| Account | domain identity created with active enabled status; no secret columns |
| Binding | exactly one enabled Account/Credential association per managed Inbound |
| Credential | typed PSK, explicit reveal, owner-bound AES-256-GCM ciphertext |
| Inbound | native engine, one IP/TCP listener, one independent DisplayEndpoint |
| Protocol Module | strict settings/PSK validation, capabilities, neutral runtime/profile builders |
| Engine | minimal private Box per Inbound; stock Snell constructor/ConnectionHandler |
| ClientProfile | canonical endpoint, typed secret, version settings, TCP transport, metadata |
| Exporter | Mihomo node, sing-box outbound, Surge declaration; explicit client contracts |

Domain/ports depend on neither SQL nor HTTP/upstream options. Protocol module
knows neither SQLite nor NoBrand. Factory registration is explicit in composition.
Native auth/userkey exists upstream; managed multi-user=false is a bounded product
profile, not a claim that upstream lacks user support. Limit: 64 managed Inbounds.

## Runtime

Start/Stop/Health/Restart/recovery/port-conflict: **PASS**. Occupied ports return
typed `port_conflict` through application/API (409)/CLI. Start owns a TCP listener
with candidate admission closed; Health checks its running accept loop. Raw sockets
are tracked and given a 5-second unauthenticated deadline; authenticated routing
clears it. Close shuts listener, handshakes, routes and owned handlers. Repeated
Close is safe and ports are reusable. Listener health is readiness only; complete
auth/traffic qualification is supplied by independent real-client tests.

Each Inbound owns one Box with Snell/direct/local DNS and empty other registries.
Static platform context leaves egress selection to the OS and avoids automatic
network resets. An inherited monitor startup race was observed and avoided through
production composition, not runtime patches/test exclusions. See ADR 0013 below.
No complex hot reload, delete/reconcile or shared engine capacity claim.

## Transaction

Create: validate → HMAC/revision plan → compile without sockets → persist
`snell_create` pending → Start → Health → SQL resource/global revision/journal
commit → Activate. Plans bind compact JSON field order/content and daemon-local
key; they require replan after mutation/restart. PSKs are generated at apply.

Rollback **PASS**: invalid version/config/changed plan, occupied port, injected
compile/start/health faults and injected credential storage failure after SQL
Account/Inbound insertion. No candidate rows/revision/admission survive; failed
journal is persisted with fixed safe code. Concurrent applies: one commit, five
stale-revision rejections. Pending admission test proves candidate TCP is closed
before storage commit. No network I/O runs within SQL callbacks.

## Restart / Recovery

Unit/integration and actual daemon restart **PASS**. Committed IDs, revisions,
listeners and encrypted PSKs restore from SQLite. The synthetic input is changed
to `{}` before restart to prove it is not authority. Interrupted create-only pending
journals become failed; committed resources remain. Unknown pending Foundation
operations keep their mutation fence and require review. Restore failure aborts
startup and closes restored handles. Arbitrary-update crash recovery/durable
candidate payloads/full idempotency remain deferred.

## Credential

Generation: crypto/rand 32 bytes, 256-bit entropy, 43 base64url characters.
Explicit input: 12..255 bytes of portable ASCII alphabet; validation never echoes
input. Native v5 broader key syntax is intentionally restricted; v6 length preserved.
Value/Credential/Profile/Document/Apply/Export formatting is redacted. Default
Profile/metadata JSON omits payloads. Export alone intentionally returns PSK.
Private Linux key provisioning/loading, overwrite refusal, permissions/symlink/
size validation and reload tests **PASS**. No key is stored in DB/argv/environment.
Windows production key provisioning remains unavailable. Plaintext strings in
process memory are not guaranteed zeroized.

## Capability

TCP: supported. UDP payload: supported over TCP; UDP listener/underlay: false.
IPv4/IPv6/domain endpoints: supported and live tested. Multi-user native: false
for this implemented profile. Attributed authenticated payload/routed-session
stats: supported. Quota/rate/max-session enforcement/TLS/REALITY/hot updates: false
or unsupported. Capabilities list only pinned live-qualified Mihomo/sing-box pairs;
Surge is excluded from live qualification.

## Stats

Real Inbound upload/download and total/active routed session counters **PASS**.
Each of nine live cells transfers 4 MiB plus concurrent/reconnect/UDP traffic;
upload increases **4,785,012** bytes and download **4,784,998** bytes in the final
matrix. The 14-byte difference is the deliberately interrupted upload. Counters
use standard authenticated router tracker + sing counter wrappers, excluding
wire overhead. Metadata associates counts with the sole Binding/Account; no
invented native user attribution. Active sessions return to zero after each
client stops. Values serialize as decimal strings. Durable usage/billing and
cross-Inbound account aggregation are deferred; counters reset on restart.

## ClientProfile

Endpoint comes only from DisplayEndpoint; listener/route/egress stay fixed when
public host/port changes. Credentials are typed PSK; options carry canonical
server version, explicit UDPPayload=true and TCP transport. No Engine/upstream
runtime object in ClientProfile. IPv4, IPv6 and domain projection tests **PASS**.

## Exporters

Mihomo 1.19.30: v5 server → explicit v4 node, UDP=true; v6 rejects UnsupportedExport.
sing-box 1.14.1: v5→v4 and v6→v6 outbound JSON. Surge Mac 6.7.0/iOS 5.20.0:
v5→v4 and v6→v6 contract tests only, automatic UDP without invented parameters.
Export envelopes state server_version/client_wire_version/compatibility so no
silent downgrade occurs. Unknown client versions/features return typed
`unsupported_export` (HTTP 422). No Snell URI/canonical JSON exporter implemented.

Contract sources: [Mihomo pinned source](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/adapter/outbound/snell.go),
[sing-box pinned options](https://github.com/SagerNet/sing-box/blob/v1.14.1/option/snell.go),
[Surge manual](https://manual.nssurge.com/policies/snell.html).
Surge raw IPv6 host/port encoding follows the published grammar; exact parser/
licensed runtime is unavailable and is not claimed PASS.

## Interoperability Matrix

Server for all live rows: Splicore dirty Phase 2 worktree, Linux amd64. Final traffic
run uses a Go race-enabled server binary. IPv4/IPv6/domain are server endpoints
127.0.0.1 / ::1 / localhost; payload targets are isolated local synthetic TCP/UDP.

| Server | Client | Client version | Server/client Snell | TCP | UDP | IPv4 | IPv6 | Domain | Result |
|---|---|---|---|---|---|---|---|---|---|
| Splicore | Mihomo | 1.19.30 | 5 / 4 | PASS | PASS | PASS | PASS | PASS | 3 live cells PASS |
| Splicore | sing-box | 1.14.1 | 5 / 4 | PASS | PASS | PASS | PASS | PASS | 3 live cells PASS |
| Splicore | sing-box | 1.14.1 | 6 / 6 | PASS | PASS | PASS | PASS | PASS | 3 live cells PASS |
| Splicore | Mihomo | 1.19.30 | 6 / unsupported | N/A | N/A | contract | contract | contract | explicit rejection PASS |
| Splicore | Surge | Mac 6.7.0 / iOS 5.20.0 | 5 / 4; 6 / 6 | NOT RUN | NOT RUN | contract | contract | contract | EXPORTER CONTRACT ONLY |

## Runtime Tests

Wrong PSK, wrong version and wrong port: **PASS** for each automated client/server
pair (nine negative cells). Mihomo negative uses v3 because it cannot parse v6.
Stopped server: **PASS** sing-box v6. Concurrent: **PASS** 16 transfers per live
cell. Large transfer: **PASS** 4,194,304-byte synthetic SHA256 integrity per cell.
Reconnect/abnormal close/session cleanup: **PASS** each live cell. Shutdown,
listener reuse, restart TCP/UDP for v5/v6: **PASS**. No panic/data race in final logs.

## Platform

Windows amd64 Go 1.26.2: owned tests, Splicore and retained sing-box builds **PASS**.
Linux amd64 Go 1.26.6: runtime, real client interop, owned tests/race, full root
CI and both builds **PASS**. Container image digest:
`sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6`.
Linux arm64 CGO=0: Splicore and retained sing-box compile **PASS**; runtime NOT RUN.
Windows production daemon/DACL provisioning and macOS/mobile runtime NOT RUN.

## NoBrand Compatibility

Synthetic fixture and actual CLI validate/plan/apply plus authorized API export:
**PASS**. Logical name/listener/PSK/version/DisplayEndpoint mapping documented.
Legacy v4 requires an explicit reviewed v5-server compatibility conversion;
unsupported QUIC/userkey/modes are rejected. Real NoBrand state/source/production
changes: **NONE**. No upsert/production importer/canary is claimed.

## Security

PSK logs/metadata/doctor/System/errors/journal: **no exposure** in tests/scans.
Authenticated payload and sole-binding attribution avoid fake per-user stats.
Pending gate, encryption, strict settings/no secret-bearing opaque JSON, private
UDS and key file boundaries are tested. No arbitrary credential GET or support
upload exists. Export is explicitly secret-returning and requires private handling.
Only synthetic fixtures; binaries/keys/client configs/logs stay external.

## API / CLI

Four GET routes: System, Capabilities, Inbound list and one Inbound. Five POST
routes: Snell validate/plan/apply, display mutation, secret-returning export.
Handler → application → journal/runtime/storage; no direct HTTP runtime mutation.
Strict 64 KiB JSON, depth 16, duplicate/unknown fields rejected. Full metadata
snapshot is bounded to 64 managed Inbounds. JSON CLI commands and safe typed
errors/exit status are implemented. No interactive menu/generic REST expansion.

## Upstream Runtime Modifications

Count: **0**. Existing protocol, option, router, Box, listener and other runtime
sources are unchanged. New code lives under internal/splicore; scripts/fixture/docs
are owned. No root go.mod/go.sum dependency changes and no NoBrand edits.

## Upstream Regression

Retained sing-box builds **PASS** Windows/Linux amd64 and Linux arm64 compile.
Linux full root CI with unchanged release default tags/linker flags **PASS**,
using container-only SYS_ADMIN/NET_ADMIN/NET_RAW/seccomp qualification and tcpdump.
Windows full root CI still fails only common/tlsspoof and common/windivert with
the inherited WinDivert cross-disk rename/environment problems. This is not labeled
a full Windows PASS. Historical baseline limitations remain unchanged.
New upstream regressions: **NONE observed**. The newly exercised upstream monitor
race is recorded explicitly; managed direct-only composition avoids it.

## Tests

Owned unit/integration and negative transaction/restart/metadata/export tests:
**PASS** Windows and Linux. Linux owned race plus real concurrent race binary:
**PASS**. Settings fuzz: **PASS**, 56,330 executions in a short smoke run.
Export fuzz: **PASS**, 105,944 executions in the final smoke run. Owned vet: **PASS**.
Docs/OpenAPI/live responses and whitespace/scope/secret/history checks: see final
validation below. No upstream crypto fuzzing or exhaustive long fuzz qualification.

## Client Dependencies

| Client | Version | SHA256 archive | SHA256 executable |
|---|---|---|---|
| Mihomo | 1.19.30 | `cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553` | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` |
| sing-box | 1.14.1 | `12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f` | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` |

Official release archives are pinned and verified on every cache use by
[downloader](../../scripts/splicore-clients.py). Download failures were classified
DEPENDENCY_UNAVAILABLE and successful retries verified identical pinned hashes.
No latest pin/downloaded binary is committed.

## Documentation

Updated README/docs indexes, development context/workflow, protocol SDK/engine/
runtime/transaction/storage/version/client/API/OpenAPI/testing/interop/NoBrand
mapping. Added Snell support, workflow and ADR 0013. Historical Phase 0/1 reports
and archived evidence modified: **NONE**.

## Git

Branch: codex/phase-2-snell-vertical-slice. HEAD/main remain Phase 1 freeze.
Staging: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
Changes remain reviewable in the working tree; fresh evidence is external at
`C:\Users\admin\AppData\Local\Temp\splicore-phase2-20261001`.

## Deferred

Hysteria2, TUIC, VLESS/REALITY, Mieru, Xray, Panel, NoBrand production canary,
stable designation, native userkey provisioning, policies, durable usage, account
mutation/revocation, listener delete/hot update, credential rotation, generic
idempotent import/full crash recovery, Surge live interop and production scale.

## Architecture Deviations

Bounded per-Inbound Box/owned listener/static platform composition is documented
in [ADR 0013](../adr/0013-snell-runtime-composition.md), proposed for review.
The create-only coordinator uses listener readiness and independent post-commit
interop qualification, synchronous HMAC/revision planning, explicit Linux key
files and known pending recovery. Broader architectural contracts remain future
design; wire semantics/SQLite authority/public domain boundaries are preserved.

## Final Validation

**PASS**: 60 owned Markdown documents, 527 local links, OpenAPI 3.1 refs/unique
operation IDs, 18 contract operations with exactly nine implemented, explicit
secret-returning export marker, and five actual System/Capabilities/Inbound
responses validated against their schemas. Tracked `git diff --check` and direct
untracked whitespace/newline checks pass. Scope/secret audit finds no private-key
blocks, binary/log/database additions, dependency changes, historical report or
archived evidence changes. Upstream runtime modification count remains zero.
Index is empty; branch/HEAD/main/remote gates remain unchanged.

## Final Result

**SNELL VERTICAL SLICE READY FOR REVIEW**

## Blockers

**None for the authorized experimental Phase 2 scope.** Surge live runtime,
Windows inherited upstream integration failures and all deferred features remain
explicit limitations; no stable or production NoBrand qualification is claimed.
