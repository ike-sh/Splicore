# Splicore Phase 6 Xray Engine Duality Report

- Documentation status: Historical
- Audience: Reviewers and maintainers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Record the external Xray adapter, canonical duality and actual acceptance evidence.
- Lifecycle: Preserve these outcomes; subsequent changes require fresh evidence.

## Baseline

Phase 5 Freeze: `afacb248440aedb6ac5a2f0d14ad7defedddb627`, the authorized local
checkpoint recorded in the [freeze report](PHASE_5_FREEZE_REPORT.md).
Parent: `2a9c0f3e14de29050c1228ce013b2f1ad4556946`.
Upstream sing-box: **v1.14.1**, commit `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
Branch: `codex/phase-6-xray-engine-duality`; entry working tree CLEAN.
Phase 6 is locally frozen in the commit containing this report; its sole parent
is Phase 5 and its message is `feat(engine): add Xray compatibility engine duality`.
Historical Phase 0–5 reports, prior evidence and database migrations are unchanged.

Evidence: `D:\splicore-validation\phase6-20261002`.
Linux ext4 source/runtime: `/root/splicore-p6-20261002/source` and
`/root/splicore-p6-20261002/review-runtime`; regression roots `rr-snell`, `rr-hysteria2`, `rr-tuic`
under the same ext4 parent. All actual traffic runs use private loopback-only network
and mount namespaces; only synthetic local services are contacted.
`candidate-manifest.json` ties the tested source snapshot to byte hashes.
Final Go/script/fixture bytes equal that snapshot; only documentation changes follow it.
The initial completed acceptance is retained in `initial-completed-acceptance`.
The repeated request prompted a requirement review: strict external-policy error
typing and REALITY profile/export equivalence coverage were completed, then the
full acceptance matrix and regressions were rerun against the new race binary.

## Xray Reference

Version: **v26.3.27**, executable **26.3.27**, build **d2758a0**, Go **1.26.1**.
Source: [official fixed release](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27).
The inspected newer releases were prereleases. This is an explicit stable reference,
with no `latest` artifact or automatic version tracking.
License: **MPL-2.0**, verified from the fixed official LICENSE and downloaded archives.
Binary distribution model: **EXTERNAL CHILD**, operator-supplied absolute path.
Core never downloads; future installers/distributors must supply reviewed pinned
artifacts and fulfill source/license/notice obligations.

| Platform | Official archive SHA256 | Extracted binary SHA256 |
|---|---|---|
| Linux amd64 | `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae` | `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` |
| Windows amd64 | `d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad` | `15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1` |
| Linux arm64, provided but not downloaded/runtime-qualified | `4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c` | Unqualified; adapter rejects the node artifact |

Archive digests match official release API assets. Only binary/LICENSE/README were
extracted into external evidence directories; no executable or archive enters Git.
`xray-reference.json` and `xray-release.json` preserve provenance and archive inventory.

## Status

| Surface | Status |
|---|---|
| Xray Compatibility Engine | Experimental |
| VLESS / REALITY via Native | Experimental |
| VLESS / REALITY via Xray | Experimental |
| Vision | **DEFERRED / UNSUPPORTED**, both engines |
| FinalMask | **NOT IMPLEMENTED** |
| Sudoku | **NOT IMPLEMENTED** |

No Stable designation. Vision remains behind [ADR 0017](../adr/0017-defer-vision-dependency-safety.md).
Existing canonical REALITY `with_utls` build gating remains for both placements.

## Protocol / Engine Duality

Protocol ID: **vless**. Native Engine ID: **native**. Xray Engine ID: **xray**.
Same Account model: **PASS**. Same Binding model: **PASS** (existing placement-specific rows).
Same Credential: **PASS**, the same Account-owned UUID credential IDs are reused
across persisted native/xray placements. Same ClientProfile: **PASS**.
Same Exporters: **PASS**, Mihomo, sing-box and URI reuse their existing implementations.
Result: **PASS**.

`TestXrayPinnedTransactionRecoveryAndSharedAccount` and
`TestXrayPinnedREALITYClientProfileEquivalenceAndSharedAccount` commit Alice/Bob Xray state,
persists a native placement referencing the same Accounts/UUID Credentials, recovers
both runtimes for plain/REALITY, and compare normalized profile/export bytes. REALITY
server credentials retain per-Inbound ownership while the two placements share
the same private/public key material. Only placement-specific profile IDs are
normalized; actual persisted native Bindings are matched by CredentialID.
No XrayAccount,
xray_uuid, XrayCredential, XrayEndpoint, renamed protocol or new SQLite migration exists.
Actual client campaigns separately prove authenticated traffic for both users.

## Engine Registry

Native: existing Phase 5 compilers/protocols/exporters reused.
Xray: existing reserved `xray` identity filled by the Phase6 composition; historical
Phase5 fixture composition retains its placeholder.
Illegal pair rejection: **PASS**, Snell+xray yields typed
`unsupported_engine_for_protocol` / UnsupportedEngineForProtocol, HTTP 422.
Availability: build support is distinct from last node artifact validation through
System engines and capability `engine_implementations.node_status`.
Missing optional Xray leaves native-only startup healthy. A required committed Xray
placement fails recovery explicitly without fallback or changing SQLite engine/revision.

## Process Supervisor

| Contract | Outcome |
|---|---|
| Binary validation | PASS; clean absolute regular non-symlink artifact, platform hash and version |
| Version | PASS; fixed parser and bounded 4096-byte output, safe availability status |
| Start | PASS; direct exec, allowlisted environment, no shell |
| Health | PASS; process/exit state plus child ownership of exact private listening socket |
| Stop | PASS; owned target termination, deadline then force termination and Wait join |
| Unexpected exit | PASS; failed runtime/degraded inbound and System, config/socket cleanup |
| Crash handling | PASS; SQLite revision unchanged, explicit recovery restores traffic |
| Restart policy | Manual only; no automatic restart/backoff or crash loop |
| Double start | PASS; deterministic rejection |
| Double stop | PASS; joined idempotent cleanup |
| Unrelated process safety | PASS; real second Xray remains alive across owned stop/crash/recovery |
| Abrupt parent death | PASS on Linux; parent SIGKILL terminates owned child |

Per-handle lifecycle/state locks protect admission/status. Mutable canonical intent
is serialized to owned immutable bytes during Compile. Socket forwarding occurs
outside the state mutex. Workers/sockets are joined before generation cleanup, with
one process Wait owner. Status snapshots copy exit-code pointers. No global data-path
mutex, unsafe Go TLS pointer conversion, pool lifetime patch or upstream edit is used.
Version/config-check children also use the ownership launcher.

Linux uses parent-death SIGKILL and a process group; signaling targets retained
process handles and never disk-recorded PIDs. Windows uses kill-on-close Job Objects,
assigned immediately after Start. The short Windows start-to-assignment parent-crash
interval is **not production-qualified**; Linux is the real runtime acceptance platform.

## Runtime Artifacts

Location: dedicated configured runtime root, random `generation-UUID` directories.
Bootstrap exposes only binary_path/runtime_directory; no public Xray JSON.
Permissions: Linux **0700 directories / 0600 config**, effective-owner checks;
Windows protected user/SYSTEM DACLs.
Authority: **SQLite**. JSON is an ephemeral private artifact.
Config regeneration: **PASS**, old generation/config removed and a new child/config
generated from committed SQLite without rereading canonical input files.
Cleanup: **PASS** on stop, startup failure, transaction compensation, child crash and
recovery. Exclusive kernel root lease and `os.Root` confinement permit stale
generation cleanup without killing recorded PIDs; unrelated files are preserved.

Abrupt daemon exit leaves a stale control socket under the existing transport rule.
Startup still requires operator review/removal after confirming that no listener
exists. Acceptance cleans only its exact owned socket after joining the dead parent
and verifying child exit, socket type, no listener, and unchanged inode. Xray generation
cleanup remains automatic under the root lease. No transport safeguard is relaxed.

## Security

UUID: existing encrypted Credential storage; revealed only to the private renderer
or authorized client export. Ordinary API/status/doctor/logs stay redacted.
REALITY private key: existing encrypted server-secret storage; only private runtime
config receives it. Never returned in ClientProfile, exporter or ordinary API.
Process argv secret: **NONE**; paths only. Runtime config permissions: **PASS**.
Child logs: raw output discarded; metadata counter saturates at 1 MiB, version capture
bounded at 4096 bytes. No raw child diagnostics propagate to application errors.
Client private-key leak: **NONE**. Exact generated UUID/private-key checks pass for
both engines' ordinary API/errors/logs/doctor and closed SQLite/WAL; exporters may
return authorized UUID/public fields and never server private key/target/listener.
Secret scan: **PASS** across tracked/untracked text and sanitized public evidence;
baseline synthetic/upstream patterns classified, no new finding. Temporary credential,
master-key/config/database inputs removed after process joins. Public evidence keeps
safe response envelopes with export content replaced by `[REDACTED]`.

## Transaction

| Stage | Outcome |
|---|---|
| Validate domain and engine pair | PASS; rejects Vision/illegal pair/strict policy before artifact use |
| Availability | PASS; missing/bad/hash/version failures reject before pending state |
| Pending | PASS; existing journal authority retained |
| Render | PASS; typed private VLESS raw TCP, none/TLS/REALITY, no flow |
| Start and Health | PASS; child listener owned and healthy, public precommit connections close with EOF |
| Commit | PASS; existing SQLite transaction activates public relay afterward |
| Rollback | PASS; child, artifact, sockets and pending/credential state compensated |

Binary missing: **PASS**, validate/plan/apply leave revision, inbounds and pending count unchanged.
Bad executable: **PASS**, wrong hash/nonartifact rejected.
Wrong version: **PASS**, exact parser rejects it (wrong stock binary also fails hash policy first).
Invalid config/runtime snapshot/path: **PASS**, helper process validation/renderer failures
join and clean the generation. Port conflict: **PASS**, real pinned integration rollback.
Child early exit: **PASS**. Health timeout/no listener: **PASS**.
Runtime generation failure: **PASS**, invalid runtime path rejected and public listener released.
Commit credential-write failure: **PASS**, real child health was reached and precommit
EOF verified; failure then leaves no inbound/revision/pending/generation/listener.

## Restart Recovery

SQLite: **PASS**. Config regenerated: **PASS**. Child restarted: **PASS**.
Traffic restored: **PASS** for Alice/Bob after graceful restart and explicit child-crash
recovery; Alice disabled state also survives restart. Parent-death recovery removes
stale generation artifact and keeps revision. Required missing engine fails unavailable,
reports degraded in application state, and preserves committed placement.
`owned-cleanup.json`: no live recorded owned processes, no private campaign directories;
each isolated namespace exits and releases its listeners. No global process termination.

## Multi-user

Alice: **PASS**. Bob: **PASS**, same inbound.
Wrong UUID: **EXPECTED FAIL**, no authenticated proxy payload.
Disable/re-enable uses existing Binding reconcile; Bob remains recoverable while
Alice is disabled. Native UUID attribution remains verified; Xray attributed stats
remain deferred and are not inferred from relay bytes.

## Capabilities

Native VLESS: TCP/XUDP, UUID multi-user, IPv4/IPv6/domain, none/TLS/REALITY,
runtime-generation per-Binding attributed payload stats; user reconcile requires restart.
Xray VLESS: same bounded transport/security/domain surface; static user reconcile
restarts the affected child. Effective capability composition: **PASS**.
Protocol and engine features intersect, result slices are owned snapshots, and
unknown support/mutation enum values fail closed in both argument orders.
HotUserUpdate: **false**, both engines. HotReload: **false**.
Stats: Xray per-user/persistent/attributed adapter **DEFERRED / UNSUPPORTED**;
zero response counters are placeholders and passing echo integrity qualifies traffic.
Unsupported strict quota/speed/session policies: **FAIL CLOSED**. Strict VLESS/Xray
quota/upload/download requests return typed UnsupportedPolicyForEngine /
`unsupported_policy_for_engine` (HTTP 422) before binary availability or pending
state. Malformed policies remain Invalid (400), native preserves its existing
Invalid contract, and explicit metadata-only
records are not enforcement claims. Original source-IP policy is unsupported because
the child receives the private relay peer. Vision effective capability stays false.

## ClientProfile Equivalence

Native and Xray use the same canonical VLESS profile builder, UUID credential and
public security projection. Normalized profile bytes and the same exporters match
in pinned plain and REALITY integration tests with both engines actually started.
Public key, first short-ID and SNI are asserted; private key is excluded.
Semantic equality: **PASS**.
Engine-specific exporter: **NONE**. Client profiles never include process/artifact
identity, server private key or internal REALITY target.
URI flow-none contract passes for plain/REALITY; URI with explicit static TLS CA
remains UnsupportedExport. URI client import and Surge VLESS are not qualified.

## Interoperability Matrix

All **40/40** actual cells below use `splicore-race-default`, SHA256
`0d093aa96db431f9c69c3d92115d37461ae2c97e7a70ee553cceb97d04a2ed2e`, with default checkptr/race enabled and canonical flow=none.
Reference clients: Mihomo **1.19.30**, SHA256
`20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`;
sing-box **1.14.1**, SHA256
`9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9`.
Each campaign verifies concurrency 16, 4 MiB integrity, XUDP sequence (32 packets),
reconnect, abnormal close, reconcile, committed SQLite restart and listener release.
REALITY qualifies IPv4/IPv6/domain; plain/static TLS traffic qualifies IPv4.
No payload retry is used to accept a failed matrix cell. Bounded reconnect probes
only assess existing clients after an intentional runtime lifecycle transition.

| Engine | Client | Version | User | Endpoint | Security | TCP | UDP/XUDP | REALITY | Result |
|---|---|---|---|---|---|---|---|---|---|
| native | mihomo | 1.19.30 | Alice | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| native | mihomo | 1.19.30 | Bob | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| native | sing-box | 1.14.1 | Alice | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| native | sing-box | 1.14.1 | Bob | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| native | mihomo | 1.19.30 | Alice | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| native | mihomo | 1.19.30 | Bob | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| native | mihomo | 1.19.30 | Alice | ::1 | reality | PASS | PASS | PASS | PASS |
| native | mihomo | 1.19.30 | Bob | ::1 | reality | PASS | PASS | PASS | PASS |
| native | mihomo | 1.19.30 | Alice | localhost | reality | PASS | PASS | PASS | PASS |
| native | mihomo | 1.19.30 | Bob | localhost | reality | PASS | PASS | PASS | PASS |
| native | sing-box | 1.14.1 | Alice | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| native | sing-box | 1.14.1 | Bob | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| native | sing-box | 1.14.1 | Alice | ::1 | reality | PASS | PASS | PASS | PASS |
| native | sing-box | 1.14.1 | Bob | ::1 | reality | PASS | PASS | PASS | PASS |
| native | sing-box | 1.14.1 | Alice | localhost | reality | PASS | PASS | PASS | PASS |
| native | sing-box | 1.14.1 | Bob | localhost | reality | PASS | PASS | PASS | PASS |
| native | mihomo | 1.19.30 | Alice | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| native | mihomo | 1.19.30 | Bob | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| native | sing-box | 1.14.1 | Alice | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| native | sing-box | 1.14.1 | Bob | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| xray | mihomo | 1.19.30 | Alice | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| xray | mihomo | 1.19.30 | Bob | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| xray | sing-box | 1.14.1 | Alice | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| xray | sing-box | 1.14.1 | Bob | 127.0.0.1 | none | PASS | PASS | N/A | PASS |
| xray | mihomo | 1.19.30 | Alice | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| xray | mihomo | 1.19.30 | Bob | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| xray | mihomo | 1.19.30 | Alice | ::1 | reality | PASS | PASS | PASS | PASS |
| xray | mihomo | 1.19.30 | Bob | ::1 | reality | PASS | PASS | PASS | PASS |
| xray | mihomo | 1.19.30 | Alice | localhost | reality | PASS | PASS | PASS | PASS |
| xray | mihomo | 1.19.30 | Bob | localhost | reality | PASS | PASS | PASS | PASS |
| xray | sing-box | 1.14.1 | Alice | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| xray | sing-box | 1.14.1 | Bob | 127.0.0.1 | reality | PASS | PASS | PASS | PASS |
| xray | sing-box | 1.14.1 | Alice | ::1 | reality | PASS | PASS | PASS | PASS |
| xray | sing-box | 1.14.1 | Bob | ::1 | reality | PASS | PASS | PASS | PASS |
| xray | sing-box | 1.14.1 | Alice | localhost | reality | PASS | PASS | PASS | PASS |
| xray | sing-box | 1.14.1 | Bob | localhost | reality | PASS | PASS | PASS | PASS |
| xray | mihomo | 1.19.30 | Alice | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| xray | mihomo | 1.19.30 | Bob | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| xray | sing-box | 1.14.1 | Alice | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |
| xray | sing-box | 1.14.1 | Bob | 127.0.0.1 | tls | PASS | PASS | N/A | PASS |

Exact rows and lifecycle/negative outcomes are in each
`runtime-evidence/acceptance-vless*/interop-results.json` and campaign logs.

## Negative Tests

Wrong UUID: **EXPECTED FAIL**, both clients/engines in all security campaigns.
Wrong public key, short-id and server-name: **EXPECTED FAIL**, both clients/engines
in REALITY. Camouflage may connect to the synthetic target; no authenticated proxy
payload is accepted and managed runtime stays healthy.
Static TLS wrong SNI/untrusted CA: **EXPECTED FAIL**.
Vision: **REJECT**, daemon validate/plan/apply and offline CLI; typed not_implemented,
unchanged committed revision. Capabilities reject it for both placements.
Strict policy: quota/upload/download each reject through daemon validate/plan/apply
and offline CLI for both engines, with unchanged revision. Xray uses the explicit
unsupported_policy_for_engine error. `policy-rejection-response.json` preserves
safe typed responses; unit checks additionally prove availability was not reached
and no inbound/pending state exists. Explicit metadata_only remains accepted as
unenforced intent.

Preserved investigation failures and their resolutions:

1. Initial REALITY campaign failed with serial OpenSSL s_server. The pinned Xray
   REALITY implementation issues concurrent target TLS probes. Replacing only the
   local target fixture with a concurrent Python TLS1.3/X25519 server and honest
   HTTP/1.1 ALPN resolved the failure for both engines. No runtime/wire/crypto patch.
   Evidence: `interop-xray-reality.log`, `diagnose-reality.log`, safe diagnostic
   classifications, then `interop-xray-reality-final.log` and fresh acceptance logs.
2. Parent-SIGKILL recovery initially reached the existing stale-control-socket
   operator-review guard. Owned test-socket review/cleanup fixes the harness;
   transport source is unchanged. `initial-parent-socket-failure.log` retained.
3. Initial shared race command used nonexistent transport/vless; corrected to
   protocol/vless and the required shared packages. `initial-shared-path-failure.log`
   retained; `shared-default-race.log` then passes.

## Regressions

VLESS Native: **PASS**, fresh 20-cell duality campaign.
Snell: **PASS**, 9 actual cells (v5 Mihomo/sing-box; v6 sing-box).
Hysteria2: **PASS**, 12 actual cells.
TUIC: **PASS**, 12 actual cells.
Regression detail: snell 9 cells, hysteria2 12 cells, tuic 12 cells; concurrency/large payload/negative credentials,
restart/listener cleanup and safe live schema responses pass on the same final race binary.
Original sing-box: **PASS**, Linux full repository tests and release-profile builds
for amd64/arm64; Windows build with with_quic/with_utls. Upstream source unchanged.

## Platform

Windows: Go **1.26.2**, full Splicore tagged/no-tag units, manager/process tests,
pinned Windows Xray transaction/recovery integration, and builds **PASS**.
Linux WSL2 Ubuntu-24.04 ext4: Go **1.26.6**, default race/checkptr, pinned actual
interop/child ownership/recovery gates **PASS**; loopback-only network namespaces.
arm64: Splicore Linux arm64 compile **PASS**, original sing-box arm64 compile **PASS**.
Official Xray arm64 archive exists, but its binary is not downloaded/qualified; the
adapter rejects an unqualified artifact. No arm64 runtime acceptance claimed.
Windows abnormal Xray child-exit/parent-crash qualification:
**DEFERRED PLATFORM QUALIFICATION**. The Start-to-Job-Object-assignment interval
remains unqualified; passing Windows units/integration do not qualify that lifecycle.
Xray arm64 runtime: **NOT CERTIFIED**. No Windows production orphan guarantee
or general production release is claimed.

## Runtime Source Audit

sing-box upstream runtime modified: **0**.
Xray source modified/copied: **0**. Wire modified: **0**.
Go module manifests/dependencies changed: **0**.
Shared native TLS snapshot helpers moved into Splicore tlsconfig; existing native
wrapper delegates to the same checks, with no TLS wire change.
Dependency integrity compares sing-vmess v0.2.8 (33 files), sing v0.9.4 (329 files)
and utls v1.8.7 (351 files) against their cached module ZIPs: no mismatch/extra files.
Original Vision source/reproducer hashes remain unchanged and its historical
checkptr/race failures are not reclassified as passing. Vision stays rejected.
`final-source-audit.json` verifies protected files, index, refs and source snapshot.

## Tests

| Gate | Outcome / evidence |
|---|---|
| Unit | PASS; final-unit, final-no-tags, windows-unit and windows-unit-no-tags logs |
| Race | PASS; final-race.log covers all Splicore + cmd and pinned integration; shared-default-race.log covers route/common/protocol/vless/adapter/include/sing bufio |
| Default checkptr | Enabled; no gcflags suppression in any accepting race command/binary |
| 10x process reproducer | PASS; go test -race -count=10 -tags with_utls -run TestSupervisor ./internal/splicore/engine/xray, review-process-10x.log |
| Fuzz | PASS; FuzzRuntimePath and FuzzRendererBoundary, 10s each / four workers; fuzz-gates.json |
| Process | PASS; fixture OS processes on both platforms plus actual owned/unrelated Xray campaigns |
| Transaction | PASS; tagged pinned tests, precommit EOF, commit failure compensation, port conflict and missing artifacts |
| Targeted completion gates | PASS; review-targeted-race.log includes REALITY shared-account/profile/export equivalence and typed policy HTTP rejection |
| Recovery | PASS; dual placements, graceful/child/parent failure generations and restored traffic |
| Interop | PASS; 40 VLESS cells plus Snell/HY2/TUIC regressions, acceptance-interop-gates.json / regression-gates.json |
| Security | PASS; exact-secret comparisons, bounded logs, ownership/path/artifact gates |
| Docs / Links | PASS; owned Markdown graph/metadata and local links, docs-live-gates.json |
| OpenAPI | PASS; schema validation and reference resolution; nine live campaigns |
| Live API | PASS; System, capabilities, inbound views, plan/apply/binding and safe export envelopes; CLI/status/doctor exercised |
| Secret scan | PASS; secret-scan.json, no new source/public-evidence finding |
| Vet | PASS; final-vet.log |
| Original repository | PASS; original-all-unit.log and original build logs |
| git diff --check | PASS, tracked and untracked source; final-source-audit.json |

Exact principal commands (offline module cache, no disabling of safety checks):

```sh
go test -count=1 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore
go test -race -count=1 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore
go test -race -count=10 -tags with_utls -run TestSupervisor ./internal/splicore/engine/xray
go test -race -count=1 -tags with_quic,with_utls ./route/... ./common/... ./protocol/vless ./adapter/... ./include/... github.com/sagernet/sing/common/bufio
go test -count=1 ./internal/splicore/... ./cmd/splicore
go vet -tags with_quic,with_utls ./internal/splicore/... ./cmd/splicore
```

Pinned integration requires SPLICORE_XRAY_BINARY; absence fails that explicit gate.
It never silently skips. The optional tag keeps ordinary units independent of a
downloaded artifact. Fuzz seed/path/renderer inputs remain local.

## Licensing

Xray boundary: **EXTERNAL CHILD**. Source copied: **NONE**.
License docs: **UPDATED**, [license boundary](../architecture/LICENSE_BOUNDARIES.md).
Fixed archives contain LICENSE/README and no NOTICE; Windows includes optional
wintun license/DLL which this adapter does not extract/use. Preserve notices and
MPL covered-source access when distributing stock or modified Xray binaries;
the process boundary is not an exemption from distribution obligations.

## Docker

Touched: **NO**. Queried: **NO**. Redis/TeleLedger: **UNTOUCHED**.
External cleanup: **DEFERRED**. Only this phase's owned local test inputs/processes
were joined and cleaned. No scan of external targets or production migration.

## NoBrand

Real changes: **NONE** to `D:\code\NoBrand-OneClick`.
Only Splicore-side future integration contract updated: choose canonical engine;
do not generate or manage Xray JSON/service independently.

## Git

The maintainer authorized one Phase 6 freeze commit containing this report, with
message `feat(engine): add Xray compatibility engine duality` and sole parent
`afacb248440aedb6ac5a2f0d14ad7defedddb627`. The full resulting SHA and commit
statistics are recorded in the external freeze evidence and final freeze report.
Only the 59 approved Phase 6 paths are staged. Push: **NONE**. Tag: **NONE**.
Release: **NONE**. Working tree after commit: **CLEAN**.

Before staging, main was repaired from Phase 4 to the existing Phase 5 commit by
an atomic old-value-checked ref update. All 1,840 worktree file hashes and the
index SHA256 were identical before/after; diff stat/name-status/check also matched.
This repaired a missing fast-forward without rewriting history or commits.
After the Phase 6 commit, main is fast-forwarded normally to Phase 6 and the clean
`codex/phase-7-xray-vless-extensions` branch is created from it. Phase 7 implementation
is **NOT STARTED**. The preliminary external Phase 7 source audit is preserved
outside the repository as **PRELIMINARY EVIDENCE ONLY**, excluded from this commit.

Freeze evidence: `D:\splicore-validation\phase6-20261002\repair-freeze-20261002`.
Fresh Windows build/tests, Linux default race/checkptr tests/build, supervisor 10x,
native/Xray VLESS smoke, Snell/HY2/TUIC regressions, docs/links/OpenAPI/live schemas,
source match, evidence integrity and worktree/staged secret scans pass. All 1,482
functional source/test/script files match the final 40/40 acceptance snapshot;
only freeze documentation follows it. Earlier acceptance/evidence files remain preserved.

## Deferred

Vision; FinalMask; Sudoku; Mieru; Panel; unified quota/rate/session enforcement;
persistent aggregate usage and Xray attributed/per-user stats; NoBrand production
canary; Stable designation. Windows production parent-death qualification and
Xray arm64 artifact/runtime qualification remain future gates.

## Architecture Deviations

[ADR 0018](../adr/0018-xray-owned-child-engine.md) records the implementation choices:
Splicore owns a public precommit admission listener and forwards unchanged byte
streams to a private child socket after commit; the child has no original peer IP.
Availability/status are optional extensions of existing engine ports. Manual
recovery, whole-child user reconcile, discarded raw logs and conservative stats
are explicit capability limits. Canonical models, transaction authority and wire
formats remain unchanged. No second architecture or independent service is created.
Existing all-or-nothing startup recovery semantics are retained for missing required
engines; application reports degraded/unavailable and daemon startup fails clearly.

## Final Result

**PHASE 6 FROZEN**.
The freeze covers the Experimental bounded Linux reference and Windows development
build/unit/integration gates. It does not declare Stable, production migration,
Vision support, Windows production orphan qualification or arm64 Xray runtime support.

## Blockers

**None for the defined Phase 6 freeze scope.** Deferred/platform limits are explicit above.
