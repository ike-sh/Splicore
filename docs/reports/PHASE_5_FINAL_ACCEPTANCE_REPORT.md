# Splicore Phase 5 Final Acceptance Report

- Documentation status: Historical
- Audience: Reviewers and maintainers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Record Vision deferral and fresh acceptance of the non-Vision surface.
- Lifecycle: Preserve actual gate outcomes; later changes require fresh evidence.

## Baseline

Phase 4 Freeze / unchanged HEAD: `2a9c0f3e14de29050c1228ce013b2f1ad4556946`.
Branch: `codex/phase-5-vless-reality-vertical-slice`.
Upstream: **sing-box v1.14.1**, commit `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
Dependency: **sing-vmess v0.2.8**. No baseline upgrade or dependency change.

Fresh evidence: `D:\splicore-validation\phase5-vision-deferred-20261002`;
native source/runtime: `/root/splicore-validation/phase5-vision-deferred-20261002`.
HY2/TUIC regression inputs used shorter external directories
`/root/splicore-validation/p5vd-hysteria2-20261002` and
`/root/splicore-validation/p5vd-tuic-20261002`.
Validated snapshot includes a byte manifest. Final Go/script/fixture bytes equal
that snapshot; only documentation changed after the formal builds/tests.

## Status

| Surface | Status |
|---|---|
| VLESS, canonical flow=none | Supported / Experimental |
| REALITY without Vision | Supported / Experimental; requires with_utls |
| Vision / xtls-rprx-vision | **DEFERRED / UNSUPPORTED** |

No Stable declaration, Phase 5 freeze or release. Review readiness is limited to
the supported flow-none surface.

## Vision Defect

Dependency: sing-vmess v0.2.8. Classification: **UPSTREAM DEPENDENCY DEFECT**.
Original default checkptr reproducer: **10/10 FAIL**.
Original diagnostic race reproducer: **10/10 FAIL with real Read/Write races**.
Those failures remain preserved; they are not rerun or rewritten as passing gates.

NewVisionConn uses an unsafe TLS pointer conversion that fails default checkptr.
The same VisionConn owns mutable numberOfPacketToFilter/isTLS filtering state;
Read and Write/filterTLS access it concurrently. writeAccess covers only Write.
There is no evidence attributing this defect to Splicore connection wrappers,
stats, buffer reuse/pool return, concurrent Close, session attribution or transactions.
Splicore shared-concurrency/runtime patch for this defect: **NONE**.
Dependency patch, vendoring, replace/fork, monkey patch or upgrade: **NONE**.

Timeline: initial Vision implementation and functional traffic → default checkptr
fatal → diagnostic actual race → independent minimal reproducer → dependency
ownership identified → Vision deferred → fresh non-Vision final acceptance.
The [initial Phase 5 report](PHASE_5_VLESS_REALITY_NATIVE_VERTICAL_SLICE_REPORT.md)
is unchanged. Full local call chains and ownership findings remain in
`D:\splicore-validation\go-race-triage-20261002\GO_RACE_TRIAGE_REPORT.md`;
the original vision_race_test.go and its hash remain unchanged.

## Vision Fail-Closed

| Entry / boundary | Outcome |
|---|---|
| Canonical settings, creation config and config import | PASS: typed not_implemented |
| API validate / plan / apply | PASS: HTTP 501 / not_implemented in live tests |
| CLI validate / plan / apply | PASS: explicit typed rejection, no output config |
| Protocol validation and materialization | PASS: reject Vision for plain/TLS/REALITY |
| Protocol runtime builder | PASS: independent rejection when creation validation is bypassed |
| Native compiler | PASS: hard gate before Supports, TLS material access or construction |
| ClientProfile / client options | PASS: reject requested Vision |
| Mihomo exporter / Describe | PASS: UnsupportedExport |
| sing-box exporter / Describe | PASS: UnsupportedExport |
| VLESS URI exporter / renderer / import | PASS: UnsupportedExport |
| Migration fixture | PASS: none only; no UUID/private material literals |
| Capability discovery | PASS: Vision=false; supported_flows=[none] |
| Committed authoritative SQLite state | REJECTED; unchanged revision and no inbound |

API/CLI rejection tests keep fake engine construction count=0. An injected missed
creation/inbound validator reaches the independent runtime gate, compensates its
pending operation and leaves authoritative revision=0 with no committed inbound
and no pending transaction. Engine construction count remains 0.
Direct compiler tests lack valid TLS/secret inputs and still return unsupported
before accessing those inputs. Managed users register only empty wire flow;
a memory-only Vision header request fails the pinned service's existing flow
mismatch check before VisionConn construction or routed handler dispatch.
No request is silently cleared, downgraded or accepted with only a warning.

Bootstrap Schema 1 accepts process paths/API only and rejects unknown fields.
There is no general settings-update endpoint. Existing display/binding updates
use strict request schemas and cannot accept flow/settings fields. No Vision-only
schema or persisted-state migration is added; generic credential schema 4 remains.

## Non-Vision Default Race

| Gate | Result |
|---|---|
| Default checkptr | PASS for all supported formal safety gates |
| Default go test -race, all Splicore packages and command | PASS |
| Native single-user traffic | PASS, plain/TLS/REALITY |
| Dual-user / 16 concurrent | PASS |
| 4 MiB integrity for each user | PASS |
| Reconnect | PASS |
| Abnormal close and continuing healthy service | PASS |
| Supported native traffic reproducer, consecutive 10 iterations | **10/10 PASS** |
| Affected shared-package race | PASS |

The supported traffic test is TestVLESSNonVisionDefaultRaceTraffic. Its channel
barrier, joined workers and owned echo/TLS target lifecycle use no sleep/retry
workaround. Formal builds have no checkptr exception, race suppression, recover
wrapper, skipped safety gate or global data-path mutex. Existing client harness
readiness/reconcile waits coordinate process startup/restart; they are not a fix
for the Vision race. All destinations are owned loopback endpoints in isolated
network/mount namespaces, with only lo available.

```text
go test -race -count=1 -tags=with_quic,with_utls ./internal/splicore/... ./cmd/splicore
go test -race -count=10 -tags=with_quic,with_utls -run=^TestVLESSNonVisionDefaultRaceTraffic$ -v ./internal/splicore/engine/native
go test -race -count=1 -tags=with_quic,with_utls -run=Vision -v ./internal/splicore/protocol/vless ./internal/splicore/engine/native ./internal/splicore/application ./internal/splicore/exporter
go test -race -count=1 -tags=with_quic,with_utls ./route/... ./common/tls ./protocol/vless ./adapter/... github.com/sagernet/sing/common/bufio
```

Exact commands, exits and durations: linux-gates.json and windows-gates.json.
Packages without test files in shared gates compile successfully.

## Protocol / Engine

Protocol: **vless**. Engine: **native**. REALITY is a security profile under VLESS.
Future Xray representation: **PASS**; registered metadata exposes vless + xray as
not_compiled / runtime_implemented=false, and selecting it rejects before effects.
No Xray binary, download, process, config renderer, FinalMask or Sudoku is added.
Account, Binding, Subscription and central ClientProfile remain engine-neutral.

## REALITY

| Value | Ownership / verified behavior |
|---|---|
| Private key | Inbound-owned x25519 PrivateKeyPayload; encrypted by existing AES-256-GCM vault; server-only |
| Public key | Standard-library X25519 derivation; public settings and explicit client export |
| Short ID | Bounded even hex, padded baseline semantics; selected client-needed ID exported |
| Server name | Explicit independent DNS/SNI allowlist; not overwritten by display endpoint |
| Target | Independent owned synthetic TLS 1.3 target; never included in client projection |
| UUID | Account-owned encrypted credential; generated dynamically or supplied write-only |

General schema 4 only extends credential-kind support. Migrations 0001–0003,
existing ciphertext/AAD, relationships, policy data and Snell constraints remain.
Committed SQLite intent is recovery authority. Master keys and TLS inputs are
external. Durable key provisioning/rotation, Windows production DACLs and perfect
Go heap zeroization remain outside the acceptance claim.

## Private-Key Leak Gate

| Surface | Result |
|---|---|
| Mihomo export | PASS |
| sing-box export | PASS |
| URI export | PASS for plain/REALITY; explicit-CA TLS correctly UnsupportedExport |
| API client export | PASS; UUID allowed for authorized binding, server private key absent |
| Ordinary API / errors | PASS |
| Logs | PASS |
| Doctor | PASS |
| SQLite/WAL plaintext scan | PASS |

REALITY server private key leaked: **NO**. Dynamic exact-secret comparisons run
while the generated inputs exist; client config content is not archived publicly.
Sanitized export envelopes use [REDACTED]. The synthetic fixture omits both users'
UUIDs and server private material for generation at apply.

## Multi-user

Alice: **PASS**. Bob: **PASS**. Same-inbound concurrent traffic: **PASS**.
Wrong UUID: **EXPECTED FAIL**, no authenticated forwarded payload.
Credential attribution follows authenticated UUID, not a client-side label.
Disable uses capability-declared per-Inbound reconcile/restart because
HotUserUpdate=false and HotReload=false. Saved Alice configurations fail after
disable; Bob reconnects. SQLite restart preserves disabled state; re-enable,
existing-client reconnect, forced client kill and socket release all **PASS**.
Reconcile interrupts that Inbound's sessions and resets generation counters.

## Interop Matrix

Only cached checksum-pinned client binaries were used; no latest lookup/download.
Server is the default race-built Splicore binary; checkptr is enabled.
Plain/static TLS are qualified on IPv4 in this campaign; REALITY covers all three
endpoint forms. IPv6/domain plain/static TLS real-client cells are not claimed.
UDP means **XUDP payload over TCP**, with no UDP listener. URI parser/export
contract is qualified; reference-client URI import remains unqualified.
Surge returns UnsupportedExport and has no VLESS live qualification.

| Client | Version | Binary SHA256 | Archive SHA256 |
|---|---|---|---|
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | `cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553` |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | `12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f` |

Full supported matrix: **20/20 cells PASS**, all flow=none.

| Client | Version | SHA256 | User | Endpoint | Security | TCP | UDP/XUDP | REALITY | Result |
|---|---|---|---|---|---|---|---|---|---|
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | ::1 | reality | PASS | PASS | PASS | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | ::1 | reality | PASS | PASS | PASS | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | localhost | reality | PASS | PASS | PASS | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | localhost | reality | PASS | PASS | PASS | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | ::1 | reality | PASS | PASS | PASS | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | ::1 | reality | PASS | PASS | PASS | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | localhost | reality | PASS | PASS | PASS | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | localhost | reality | PASS | PASS | PASS | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |

Each cell verifies 16 concurrent, 4 MiB SHA256 integrity, 32 sequenced UDP packets,
reconnect, abnormal RST close and authenticated per-user counter growth. Static
TLS uses explicit trusted synthetic CA and independent SNI; no insecure PASS path.

Race-server binary SHA256: `c7d7b7d201469fcf9b7d16162b9231f39345874dd930c643067bb3dc8787463f`.

## Negative Tests

| REALITY input | Mihomo | sing-box | Observed behavior |
|---|---|---|---|
| Wrong UUID | EXPECTED FAIL | EXPECTED FAIL | No authenticated proxy payload |
| Wrong public key | EXPECTED FAIL | EXPECTED FAIL | No authenticated proxy payload |
| Wrong short ID | EXPECTED FAIL | EXPECTED FAIL | No authenticated proxy payload |
| Wrong server name | EXPECTED FAIL | EXPECTED FAIL | No authenticated proxy payload |
| Healthy server after negatives | PASS | PASS | Subsequent valid traffic/reconcile/recovery pass |

REALITY camouflage/fallback may contact the synthetic target; the gate measures
authenticated user payload, not whether any target connection occurred.
TLS wrong SNI/CA and plain/TLS wrong UUID are also rejected as expected.

## Stats

| Dimension | Actual support / result |
|---|---|
| Inbound | Runtime-generation authenticated routed payload/session totals; PASS |
| Binding | Per-UUID upload/download and session counters; every matrix row grows; PASS |
| Account | Binding maps to the authenticated Account; relabelled-client isolation PASS |
| Connections | Active/total runtime sessions; close, reconcile and shutdown accounting PASS |
| Persistent aggregate Account usage / billing | **DEFERRED** |

Quota/rate/max-session enforcement remains unsupported. Metadata-only policy data
is preserved; this report does not claim durable aggregates or enforcement.

## Regressions

| Protocol / baseline | Unit + relevant race | Real-client runtime smoke |
|---|---|---|
| Snell | PASS | **9/9 cells PASS**, TCP/UDP, negatives, restart, listener release |
| Hysteria2 | PASS | **12/12 cells PASS**, trusted TLS, multi-user, QUIC/TCP/UDP, recovery |
| TUIC v5 | PASS | **12/12 cells PASS**, UUID/password isolation, QUIC/TCP/UDP, recovery |
| Original sing-box | PASS root-module release-tag tests | Windows/Linux amd64 builds and Linux arm64 compile PASS |

One initial HY2 regression launch failed before daemon startup because its Unix
socket pathname was 117 bytes, beyond Linux's 107-byte pathname bound. The failure
log and diagnosis remain preserved. A fresh shorter external directory with the
identical race-server binary passed the complete campaign. No runtime fix, retry
masking or safety exception was used. TUIC likewise used a short fresh directory.
Original root-module tests exclude the separate Docker test module naturally;
that module was not queried or run.

## Scalability

| Phase 5 audit | Count / result |
|---|---|
| Central protocol switches added | **0** |
| Central engine branches | **1** generic native placement guard, existing in initial Phase 5 |
| Application protocol-specific branches | **0** |
| Account protocol fields | **0** |
| Storage protocol-specific columns | **0** |
| Central ClientProfile protocol cases | **0** |
| Protocol != Engine | **PASS** |

Vision deferral adds no central protocol/engine branch. Local protocol/native/
exporter flow gates stay with their owners. Explicit composition maps register
the fourth protocol. No shared QUIC control-plane copy or Account specialization.

## Upstream / Dependency Audit

Upstream runtime modifications: **0**. Dependency source modifications: **0**.
Dependency patch: **0**. Wire implementation modifications/copies: **0**.
go.mod/go.sum unchanged; no replace, vendor or fork. Sing-vmess, sing and uTLS
cached source compares byte-for-byte against the existing module archives:
33 / 329 / 351 files, respectively, with **0 mismatches**.
Vision source and original reproducer hashes match the prior triage audit.

The managed runtime composes pinned upstream services/TLS/XUDP. Flow-none wire
behavior is unchanged. Original upstream runtime/binary retains its baseline
source; this report's fail-closed claim applies to the Splicore managed surface.
Source scope, exact Git diff/name-status/stat/check, final manifest and index/refs
audit are external in final-source-audit.json and final-*.txt.

## Platform

| Platform | Result / scope |
|---|---|
| Windows amd64, Go 1.26.2 | PASS tagged/no-tag units; Splicore and original sing-box builds |
| Linux WSL2 Ubuntu-24.04, Go 1.26.6, native ext4 | PASS builds/units/default race/vet/fuzz/runtime/client interop |
| Linux arm64 | PASS Splicore and original sing-box compile; execution NOT RUN |

Production control API remains Linux-only. Offline dependency mode uses
GOPROXY=off, GOSUMDB=off, GOTOOLCHAIN=local. External temp/cache directories were
used; formal safety gates use default sanitizers.

## Tests

| Gate | Result / fresh evidence |
|---|---|
| Unit, current package/full Splicore surface, tagged and no-tag | PASS; windows-/linux-gates.json |
| Default race | PASS; linux-default-race.log |
| Native runtime, 10 consecutive iterations | PASS; linux-default-race-traffic-10x.log |
| Shared race | PASS; shared-default-race.log |
| Vet | PASS; linux-vet.log |
| Vision rejection | PASS; vision-reject.log; live vision-rejection-response.json |
| VLESS/REALITY interop | PASS; interop-vless-*.log; 20 matrix cells |
| Leak gate | PASS; accepted result JSON plus source/evidence scan |
| Prior protocol regressions | PASS; regression-snell.log; *-resume.log; interop-resume-gates.json |
| Original root-module test suite | PASS; original-root-unit.log |
| Docs / OpenAPI | PASS; docs-gates.json |
| Actual live API / export envelopes / Vision Problems | PASS; six campaign response sets |
| Secret scan | PASS; secret-scan.json |
| Source/dependencies/history/index | PASS; final-source-audit.json; dependency-integrity.json |
| git diff --check | PASS; final-diff-check.txt |

Fuzzing uses parser/validator targets, 10 seconds and two workers per target;
no cryptographic primitive claim or failed corpus in the repo.

| Fuzz target | Executions | Result |
|---|---|---|
| settings | 240792 | PASS |
| uuid | 388581 | PASS |
| shortid | 396634 | PASS |
| target | 373154 | PASS |
| uri | 297860 | PASS |

Doc checker covers **74 owned Markdown documents**,
**717 local links** and **28 OpenAPI operations**;
all actual response schemas, export envelopes, synthetic request fixtures and live
Vision Problem responses pass. The supported request schema rejects Vision.
Secret scan covers **1802 worktree text files** and
**297 sanitized evidence files** with no new credential leak.
Pre-existing upstream/historical synthetic vectors and four invalid/duplicate/fuzz
UUID parser sentinels are classified separately; no generated runtime credentials,
private keys, API tokens or production inputs were added to source/report/evidence.

Owned cleanup: **131 recorded launches, 0 live owned processes**.
VLESS/HY2/TUIC private inputs were removed by their finally blocks. The older Snell
harness left temporary client configs and master-key/SQLite state; scoped external
cleanup removed those inputs and excluded secret configs from public evidence.
Logs/results remain preserved. Sanitized evidence is hashed in
native-evidence-manifest.json. No unrelated process or directory was cleaned.

## Files Changed

Vision deferral changes are confined to Splicore-owned settings/protocol/runtime
gates, exporters, tests, synthetic fixture, interop script and current docs:

- [Settings/flow validation](../../internal/splicore/protocol/vless/settings.go),
  [protocol projection/runtime](../../internal/splicore/protocol/vless/vless.go),
  [native compiler](../../internal/splicore/engine/native/vless.go).
- [Exporter](../../internal/splicore/exporter/vless.go) and
  [URI import/export](../../internal/splicore/exporter/vless_uri.go).
- Rejection tests in [protocol](../../internal/splicore/protocol/vless/vision_deferred_test.go),
  [application](../../internal/splicore/application/vision_deferred_test.go),
  [native](../../internal/splicore/engine/native/vision_deferred_test.go) and
  [exporter](../../internal/splicore/exporter/vision_deferred_test.go).
- [Native traffic test](../../internal/splicore/engine/native/vless_runtime_test.go),
  existing VLESS positive/secret tests and dynamically generated test credentials.
- [Interop harness](../../scripts/splicore-vless-interop.py) and
  [synthetic fixture](../../tests/fixtures/nobrand/vless-reality.json).
- Canonical documentation/OpenAPI and this report; full pre-existing Phase 5
  working-tree scope is preserved in external entry/final manifests and Git audits.

## Documentation

Decision: [ADR 0017](../adr/0017-defer-vision-dependency-safety.md).
Canonical README, architecture/context, SDK/engine capability model, client
compatibility, interop matrix, security/testing/transaction model, API/OpenAPI,
NoBrand migration, protocol guide, workflow and indexes are updated.
Generic server-secret architecture [ADR 0016](../adr/0016-vless-engine-server-secrets.md)
remains valid. Historical Phase 0–4 reports/evidence: **UNCHANGED**.
Historical initial Phase 5 report and original race triage: **PRESERVED**.
Migrations 0001–0003: **UNCHANGED**. No Vision-only compatibility migration.

## Docker

Touched/query: **NO**. Docker, Redis and TeleLedger untouched. External Docker
cleanup: **DEFERRED**. No external target scan or third-party system access.
Host /etc/hosts unchanged; only namespace-local synthetic mount/resolution used.

## NoBrand

Real changes/access: **NONE** to D:\code\NoBrand-OneClick.
Synthetic VLESS/REALITY mapping only; Vision generated: **NO**.
No production canary, deployment or direct SQLite/runtime JSON integration.

## Git

Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
No Phase 5 freeze or history changes. HEAD/refs and index remain unchanged.
Index SHA256: `4104273f36b58833e65920d91aae48f035d1fff838d726184eefccb0113a8026`.
All implementation/doc changes remain available for review in the working tree.

## Vision Re-enable Criteria

1. Require an upstream fixed release or explicit maintainer approval for a
   reviewed dependency patch in an independent patch/upgrade evaluation.
2. Require default checkptr PASS and race PASS for Vision.
3. Require the original minimal reproducer **10/10 PASS**.
4. Require exact-version Mihomo and sing-box interop PASS.
5. Require prior-protocol regressions and all secret gates PASS.
6. Require an explicit reviewed product decision; a new dependency release does
   not enable Vision automatically. Baseline sync remains independent.

## Final Result

**VLESS REALITY NATIVE VERTICAL SLICE READY FOR REVIEW** for flow-none only.
VLESS and REALITY remain Experimental; Vision remains DEFERRED / UNSUPPORTED.
No freeze, commit, release or deployment is performed.

## Blockers

**None for the declared supported flow-none review surface.**
Vision's dependency defects remain unresolved and block any future Vision
re-enable. URI reference-client import, plain/TLS IPv6/domain live qualification,
Surge live support, persistent Account aggregates, production provisioning and
external Docker cleanup retain their explicit deferred/unqualified scope.
