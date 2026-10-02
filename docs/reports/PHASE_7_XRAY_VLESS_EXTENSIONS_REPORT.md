# Splicore Phase 7 Xray VLESS Extensions Report

- Documentation status: Historical
- Audience: Reviewers and maintainers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Record bounded managed FinalMask/Sudoku integration and actual acceptance evidence.
- Lifecycle: Preserve these outcomes; subsequent changes require fresh evidence.

## Baseline

Phase 6 Freeze: `438b1096b9ec357cddb163cf89f78935e711bf3d`, message
`feat(engine): add Xray compatibility engine duality`, sole parent Phase 5
`afacb248440aedb6ac5a2f0d14ad7defedddb627`.
Branch: `codex/phase-7-xray-vless-extensions`. Entry working tree: CLEAN.
HEAD/main/Phase 6 refs unchanged. Stage/commit/push/tag/release NONE.
Upstream sing-box v1.14.1 and all dependencies remain unchanged.

The preliminary source audit completed before integration. Its raw Xray probe
is Source/Runtime Reference Evidence only. Acceptance below uses Splicore's actual
canonical API, persistence, renderer, supervisor and authorized exporter.

## Source Audit

### FinalMask

Implementation source: official Xray transport mask manager and configuration loader.
Repository: XTLS/Xray-core.
Version/commit: v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`.
Xray reference compatibility: YES.
Config contract: `streamSettings.finalmask.tcp`, entries with `type` and `settings`.
Client contract: both peers implement the selected mask with matching parameters.
FinalMask is the framework containing Sudoku. This phase qualifies one Sudoku TCP
mask only; other masks, chains and UDP masks are not exposed.

Source records: pinned `infra/conf/transport_internet.go`, mask manager and distro
registration; seven source/license SHA256 records reverified against the external
read-only audit manifest. No source import or modification.

Pinned [configuration loader](https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/infra/conf/transport_internet.go)
and [mask manager](https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/transport/internet/finalmask/finalmask.go)
identify the audited source.

### Sudoku

Implementation source: official `transport/internet/finalmask/sudoku`.
Repository/version/commit: the same official Xray pin; no fork.
Xray reference compatibility: YES.
Config contract: `type=sudoku`; settings `password`, `ascii`, `paddingMin`,
`paddingMax`. Supported Splicore profile: plain VLESS, TCP, flow none,
`prefer_ascii`, padding 0–3. Custom tables, aliases and broader normalized upstream
inputs are excluded. Invalid/null/duplicate/unknown inputs reject before runtime.
Client contract: matching exact password string seed and parameters, plus its
Account UUID. Import preserves hex letter case; the string is not hex-decoded.
Ordinary VLESS and independent Sudoku implementations are not assumed compatible.

NoBrand read-only audit baseline: `f98cf70e7159c07826101676a4a08394f0a203f9`.
The audited renderer/install/golden contracts map to the same official artifact
and profile. Splicore uses its independent typed public contract; NoBrand's `fm`
sharing-link dialect is not a supported Splicore URI format.

## Source Compatibility Decision

Current Phase 6 Xray reference supports FinalMask: YES.
Current Phase 6 Xray reference supports Sudoku: YES.
Artifact change required: NO.
ENGINE FEATURE SOURCE MISMATCH: not observed.

## Supply Chain

Runtime source: official fixed XTLS/Xray-core v26.3.27 release, commit above.
Linux amd64 binary SHA256:
`8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`.
Windows amd64 binary SHA256:
`15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1`.
License: MPL-2.0, verified from pinned source and existing Phase 6 audit.
Distribution: operator-provided external child, no runtime bundled or downloaded
by Core. Existing notice/source obligations and process boundary remain unchanged.
Artifact change/fork/new dependency: NONE.
[Decision](../adr/0019-xray-specialized-feature-boundary.md),
[license boundary](../architecture/LICENSE_BOUNDARIES.md).

## Architecture

Protocol: `vless`. Engine: `xray`.
FinalMask: engine feature. Sudoku: engine feature, within FinalMask TCP.
New Protocol IDs: 0.
Typed `engine_options` stays inside existing versioned VLESS settings JSON.
No arbitrary Xray JSON, protocol wire code or mask algorithm is implemented.
Phase7 composition reuses Phase6 and the existing VLESS exporter.

## Capability Composition

| Pair | Supported scope | FinalMask/Sudoku | Vision |
|---|---|---|---|
| Native VLESS | Existing plain/TLS/REALITY, flow none | Unsupported | Unsupported |
| Xray standard | Existing plain/TLS/REALITY, flow none, exact artifact | Explicit feature selection only | Unsupported |
| Xray + FinalMask | Single Sudoku mask, plain TCP, prefer_ascii/padding0–3 | Experimental | Unsupported |
| Xray + Sudoku | Same bounded FinalMask profile | Experimental | Unsupported |

Feature descriptors include TCP/plain/flow-none scope, UDPQualified=false and
client/version support. Effective capabilities intersect protocol and engine
descriptors. Node feature availability follows exact version/hash validation,
separately from adapter build support. Missing/wrong/unrecognized artifact rejects.
TLS/REALITY mask combinations UNSUPPORTED. Masked UDP/XUDP NOT QUALIFIED.

## Domain Impact

Account changes: 0. Binding changes: 0. Endpoint changes: 0.
Credential model: existing UUID remains Account-owned; existing encrypted Password
kind holds the Inbound-owned, client-needed transport seed. REALITY private keys
remain server-only. Generic vault/AAD and schema 4 are reused.
Storage protocol columns: 0. Schema migrations: 0.

## Runtime Renderer

Standard VLESS: PASS.
FinalMask: PASS, single Sudoku TCP entry only.
Sudoku: PASS, exact camelCase runtime fields and imported password case.
Compile produces owned immutable config bytes; caller settings/credential mutation
after Compile cannot change the handle. Missing/wrong-owner server secret rejects.
No change to the standard renderer's wire contract.

## Supervisor

Shared Phase 6 supervisor: PASS.
New supervisor: NONE.
Existing owned child, private socket, public admission, Start/Health/Commit/Activate,
join/cleanup and manual recovery paths are reused. Supervisor race tests run 10 times.
Managed masked child SIGKILL marks degraded, leaves committed revision unchanged,
and explicit daemon restart regenerates config and restores traffic.

## ClientProfile

Core profile reused: PASS.
FinalMask extension: typed transport requirements.
Sudoku extension: exact profile options and redacted client-needed password.
Engine leaked into client semantics: NO.
Profile JSON and formatting omit the password. A narrow client shared-secret port
filters active inbound-owned Password rows before decrypting, after enabled Account
and Binding authorization. A corrupt excluded private-key row does not get decrypted;
direct reveal of that row correctly fails. Server private keys never enter profiles.

## Exporters

| Masked format/client | Version | Status |
|---|---|---|
| Xray JSON | 26.3.27 | SUPPORTED; actual managed TCP traffic PASS |
| Mihomo | 1.19.30 | UNSUPPORTED; explicit rejection PASS |
| sing-box | 1.14.1 | UNSUPPORTED; explicit rejection PASS |
| Surge | All | UNSUPPORTED |
| URI | All | UNSUPPORTED |
| Xray JSON | Unknown/other | UNSUPPORTED |

The existing VLESS exporter gains format `xray`, content shape `xray-outbound`,
with no Engine-ID branch. Other formats do not drop the mask or return ordinary
VLESS as fallback. Existing standard VLESS client formats retain their behavior.
FinalMask support here means the bounded Sudoku profile, not all upstream masks.

## Interoperability

Managed Splicore feature acceptance uses canonical validate/plan/apply, then the
authorized exporter output as the actual pinned Xray client outbound.

| Client | Version | Binary SHA256 | Feature | REALITY | User | TCP | UDP | Result |
|---|---|---|---|---|---|---|---|---|
| Xray | 26.3.27 | `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` | FinalMask/Sudoku | UNSUPPORTED combination | Alice | PASS | NOT QUALIFIED | PASS |
| Xray | 26.3.27 | `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` | FinalMask/Sudoku | UNSUPPORTED combination | Bob | PASS | NOT QUALIFIED | PASS |

Each row covers 32 KiB echo, 16 concurrent sessions, 4 MiB integrity, reconnect
and abnormal close, in an isolated loopback-only namespace on native ext4.
Missing mask/wrong mask password/wrong UUID deny authenticated payload; unknown
runtime mask type rejects config. The managed feature harness uses no payload
retry or sleep. These are real traffic cells; renderer/source probes are excluded.
Default-race server SHA256:
`29eb96cca8a700f3788809a2c2553bccbab93aeeca504bc74cf9deb9ae85c278`.

## Multi-user

FinalMask: PASS with Alice/Bob sharing the transport seed.
Sudoku: PASS with distinct Account-owned UUIDs and Bindings.
Disable Alice rejects its new authenticated payload while Bob remains usable;
restart preserves disabled state and both identities. Re-enable restores Alice.
Reconcile interrupts/restarts the affected Inbound; no hot update is claimed.

## Transaction

Validation: PASS; native/TLS/REALITY/Vision/unknown/null/raw JSON/bad secret reject.
Feature availability: PASS; invalid combinations precede availability/pending.
Render: PASS. Start: PASS. Health: PASS. Commit: PASS.
Rollback: PASS; injected commit failure removes child/artifact/listener and leaves
revision zero, no authoritative Inbound and no pending operation.
Precommit admission: PASS; public TCP closes without routing before commit.
Recovery: PASS; SQLite recreates new ephemeral generation without source document,
preserving credential IDs/exact password/revision. Required missing artifact
degrades/fails without native fallback. Pinned masked transaction/export/recovery
tests complete 10 race-enabled iterations.

## Security

Feature secrets: encrypted inbound-owned Password, exact string seed; generated
with crypto/rand before pending, imported through write-only transport_secret.
Xray runtime artifact: existing private 0700 directory / 0600 config boundary,
deleted after join; argv/environment contain no secret values.
Logs: PASS redaction/secret checks; child output policy remains Phase 6.
API: PASS; ordinary reads/plan/apply/capabilities/doctor omit the seed and UUID.
Authorized export is secret-returning; content is redacted before archival.
Secret scan: PASS over archived evidence/gate logs, zero new secret/race/checkptr/panic findings.
Closed SQLite plaintext scan and private-key exclusion test PASS.

## Regressions

| Surface | Fresh actual cells | Result |
|---|---|---|
| Native VLESS REALITY, flow none | 12: two clients × two users × IPv4/IPv6/domain | PASS |
| Xray standard VLESS, plain flow none | 4: two clients × two users | PASS |
| Snell | 9 | PASS |
| Hysteria2 | 12 | PASS |
| TUIC | 12 | PASS |

All use the same default-race Splicore binary. Existing standard clients remain
Mihomo 1.19.30 SHA256 `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`
and sing-box 1.14.1 SHA256 `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9`.
Native and standard regressions include their existing TCP/UDP/security/recovery
checks; masked UDP is excluded and cannot inherit their qualification.

## Architecture Scalability

New central protocol switches: 0.
New Protocol IDs: 0.
Account feature fields: 0. Binding feature fields: 0.
Storage protocol columns: 0. Migrations: 0.
New supervisors: 0. Copied exporters: 0. Exporter engine branches: 0.
Two bounded Xray placement guards are concentrated in VLESS feature/inbound
validation. Renderer feature mapping is confined to the existing Xray adapter;
public option/feature intersection and storage ports are typed and reusable.
Result: PASS.

## Platform

Linux amd64: PASS, Ubuntu-24.04 WSL2, native ext4, loopback-only mount/network
namespaces, Go 1.26.6, default race/checkptr traffic and full tests.
Windows amd64: PASS Go 1.26.2 full-tag unit/pinned integration/build, including
normal child stop/recovery; normal ownership regression tests pass.
Windows abnormal child-exit/parent-crash: DEFERRED PLATFORM QUALIFICATION.
Xray arm64 runtime: NOT CERTIFIED / DEFERRED. Linux arm64 cross compile PASS
is build evidence only. No new runtime artifact was downloaded or executed.

## Runtime Source Audit

sing-box source changes: 0 outside Splicore-owned adapter/control-plane paths.
Xray source changes: 0. Wire reimplementation: 0.
Dependencies: unchanged. Unsafe pointer code: none added.
Historical Phase 0–6 reports and migrations 0001–0004: unchanged.

## Docker

Touched: NO. Not queried. Redis/TeleLedger untouched. External cleanup deferred.

## NoBrand

Read-only audit: YES. Real changes: NONE.
Final comparison of 145 audited file hashes and HEAD/status PASS.
No NoBrand install/test/runtime or production migration executed.

## Tests

| Gate | Result |
|---|---|
| Full Splicore/cmd unit, full tags and no tags | PASS |
| Final Linux default race/checkptr, full tags and pinned integration | PASS |
| Affected route/common/VLESS/adapter/include/sing bufio default race | PASS |
| Masked pinned transaction/export/recovery ×10 | PASS |
| Existing supervisor race tests ×10 | PASS |
| Parser fuzz, 10 seconds/four workers | PASS, 664341 executions |
| Generic renderer fuzz, 10 seconds/four workers | PASS |
| Masked renderer fuzz, 10 seconds/four workers | PASS, 315439 executions |
| Renderer/owned snapshots/feature availability | PASS |
| ClientProfile/exporter/rejection/redaction | PASS |
| Transaction/compensation/recovery | PASS |
| Managed interop and five regressions | PASS |
| Linux vet, Windows tests/build, arm64 build | PASS |
| Docs/Markdown/OpenAPI/static references | PASS |
| Six managed response sets; feature Problem/CLI contracts | PASS |
| Secret scan/process join/private cleanup | PASS |
| git diff --check | PASS |

No race/checkptr suppression, skipped feature acceptance test or runtime panic
recovery was introduced. Unavailable artifacts reject rather than skip.

### Retained development failures

Initial redundant feature validation changed an existing Vision bypass regression's
failure stage; the added gate now handles only explicitly selected engine options.
A test helper wrongly used the single-Binding repository method with a Binding ID;
it now enumerates the actual multi-user Bindings. An unused import was removed.
The first managed harness reached traffic/recovery/secret stages, then its final
bind probe encountered TCP TIME_WAIT; SO_REUSEADDR now matches listener semantics.
All original failure logs are retained externally.

A standard Xray development campaign once closed a concurrent payload early.
The independent full diagnostic passed and recorded one ListenOverflows/ListenDrops
with the shared echo fixture's backlog 5. That observation identifies fixture
saturation but does not prove the exact cause of the earlier close. The fixture
now uses backlog 64 for the declared 16-client load. The fresh final standard Xray
campaign passes all four cells. No runtime change or payload retry was used to
address that development failure; both logs and the diagnostic counters are retained.
An external runner prefix/path error was corrected before its campaigns executed.

## Evidence

External evidence root: `D:\splicore-validation\phase7-integration-20261002`.
Linux source/runtime root: `/root/splicore-p7-20261002`.
The accepted Phase 6 source/runtime root remains unchanged.
Key records: final-linux-gates.json, core-gates.json, extra-gates.json,
sudoku-interop-gates.json, remaining-interop-gates.json, runtime-evidence-manifest.json,
docs-live-gates.json, openapi-feature-contract.json, secret-scan.json,
owned-cleanup.json and final-source-audit.json.
Runtime-evidence contains sanitized individual client rows, ordinary live API/CLI
responses, redacted export envelopes and process metadata. Private inputs/configs,
keys and databases were removed after joining owned processes.

## Git at integration handoff

Stage: NONE. Commit: NONE. Push: NONE. Tag: NONE. Release: NONE.
At that handoff, HEAD/branch/main/Phase 6 and all Git refs were unchanged; staged blob tree equaled HEAD.
Index file bytes differ from entry; the cached diff is empty and no content changes
were staged. No Git history edits. Reviewable work was left unstaged.

## Final Status at integration handoff

FINALMASK READY FOR REVIEW — Experimental, single Sudoku TCP profile only.
SUDOKU READY FOR REVIEW — Experimental, plain TCP/flow none/prefer_ascii/padding0–3.

## Phase Result

XRAY VLESS EXTENSIONS READY FOR REVIEW.

## Blockers

None for the explicitly bounded profile and review handoff.

## Deferred

Vision; other masks/chains/custom tables; masked UDP/XUDP; masked TLS/REALITY;
other client implementations/versions; Windows abnormal child/parent termination
qualification; Xray arm64 runtime; Mieru; Panel; unified quota/rate enforcement;
persistent aggregate usage; production NoBrand migration; Stable designation.

## Phase 7 freeze disposition

The maintainer subsequently authorized the [Phase 7 local freeze](PHASE_7_FREEZE_REPORT.md).
Functional source, tests and drivers match the final acceptance manifest byte for
byte; freeze changes only documentation. The bounded features remain Experimental,
masked UDP remains NOT QUALIFIED, masked TLS/REALITY remains UNSUPPORTED and Vision
remains DEFERRED / UNSUPPORTED. Official Xray v26.3.27 and platform qualification
are unchanged. The original handoff evidence and retained failures above remain
historical. URI fm is a read-only NoBrand reference contract only; Splicore masked
URI export is unsupported, with no runtime interoperability claim.
