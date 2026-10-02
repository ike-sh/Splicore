# Splicore Phase 7 Freeze Report

- Documentation status: Historical
- Audience: Maintainers and checkpoint reviewers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Record the authorized Phase 7 local freeze and unchanged qualification boundary.
- Lifecycle: Preserve this checkpoint; subsequent work requires fresh scope and evidence.

## Baseline

Phase 6: `438b1096b9ec357cddb163cf89f78935e711bf3d`.
Entry branch: `codex/phase-7-xray-vless-extensions`; HEAD and main both Phase 6.
Entry changes: the 53 accepted Phase 7 paths only, no staged or unknown changes,
no origin. The maintainer explicitly authorized one local freeze commit, main
fast-forward and a clean Phase 8 branch. No Mieru implementation is authorized.

## Status

FinalMask: Experimental. Sudoku: Experimental.
Vision: DEFERRED / UNSUPPORTED; ADR 0017 remains in force.
The prior [acceptance report](PHASE_7_XRAY_VLESS_EXTENSIONS_REPORT.md) reached
FINALMASK READY FOR REVIEW and SUDOKU READY FOR REVIEW. This checkpoint freezes
that bounded scope without promoting Stable or enlarging runtime qualification.

## Supported Scope

plain TCP: supported. flow-none: supported. single Sudoku mask: supported.
ASCII: prefer_ascii only. Padding: 0–3 only.
Masked UDP/XUDP: NOT QUALIFIED; feature UDPQualified=false and profile UDP=false.
Masked TLS/REALITY: UNSUPPORTED; explicitly rejects, never downgrades to plain.
Other masks/chains/custom tables/parameters: rejected.

## Source Contract

Official Xray v26.3.27, source commit
`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`.
No third-party fork, binary upgrade or new download.
FinalMask is the framework; Sudoku is its single qualified TCP mask.
Typed canonical engine_options.finalmask.tcp maps to Xray
streamSettings.finalmask.tcp with type=sudoku and settings password/ascii/
paddingMin/paddingMax. Password is an exact 32 hex-character string seed;
import preserves case. It is client-needed, inbound-owned and encrypted separately
from Account UUIDs and server-only REALITY private keys.

Linux amd64 Xray SHA256:
`8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`.
Windows amd64 Xray SHA256:
`15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1`.
Existing MPL-2.0/process distribution boundary unchanged.

## Client Compatibility

| Surface | Frozen status |
|---|---|
| Xray 26.3.27 JSON | SUPPORTED / tested managed real TCP traffic |
| Mihomo 1.19.30 masked profile | UNSUPPORTED; exporter rejects |
| sing-box 1.14.1 masked profile | UNSUPPORTED; exporter rejects |
| Surge masked profile | UNSUPPORTED |
| URI fm | CONTRACT ONLY: audited NoBrand source/reference dialect |
| Splicore masked URI exporter/import | UNSUPPORTED; no fm implementation or runtime qualification |

Reference URI/source evidence does not count as Splicore client interoperability.
Existing standard VLESS export behavior remains unchanged. Vision rejects in all
managed creation, runtime and export paths.

## Architecture

Protocol: vless. Engine: xray. FinalMask/Sudoku: typed engine features/options.
New Protocol IDs: 0. Account fields: 0. Binding fields: 0.
Credential/Endpoint dedicated feature fields: 0. Storage protocol columns: 0.
New supervisor implementations: 0. Exporter engine branches: 0.
The Phase 6 supervisor, generic settings persistence, credential vault and
ClientProfile core remain shared. Client transport requirements carry no Engine ID.
SQLite committed state remains authority; runtime Xray JSON remains ephemeral.

### Scope classification

| Category | Accepted paths / responsibility |
|---|---|
| A. Xray feature model | ports/features, transportmask typed options |
| B. FinalMask | bounded framework option and renderer mapping |
| C. Sudoku | single profile validation and shared password materialization |
| D. Capability composition | ports intersection, VLESS descriptors, engine status/doctor |
| E. Runtime renderer | existing engine/xray config renderer and owned snapshot |
| F. ClientProfile extensions | typed transport requirements and authorized shared-secret port |
| G. Exporter capability | existing VLESS exporter adds Xray format, rejects other masked formats |
| H. Transaction/recovery | existing lifecycle reused, narrow storage secret projection |
| I. Tests/interop | bounded parser/renderer/storage/application tests and local managed driver |
| J. API/OpenAPI | existing commands, typed fields, feature/status projections and safe error code |
| K. Docs/ADR | canonical specifications, accepted ADR 0019 and frozen development context |
| L. Phase 7 reports | original acceptance evidence plus this local freeze record |

## Runtime Audit

Upstream sing-box source: 0 changes. Xray source: 0 changes.
Wire reimplementation: 0. Dependencies: 0 changes. Migrations: 0 changes.
Account/Binding/Endpoint and credential domain structs unchanged.
No vless-finalmask or vless-sudoku ProtocolID; no second supervisor.
Phase 0–6 historical reports remain unchanged.

## Acceptance Source Match

All 1,856 acceptance files initially match the final acceptance manifest byte for
byte, manifest SHA256 `28071f1bae5ea852417c8e589e88347e9376a38015202c72a33ea01c2d81894b`.
Freeze updates documentation only. Functional source, tests and drivers remain
byte-identical to that snapshot. Staged content is checked against the same manifest.
The fresh default-race build matches the accepted server binary SHA256:
`29eb96cca8a700f3788809a2c2553bccbab93aeeca504bc74cf9deb9ae85c278`.

## Acceptance

Managed Alice/Bob: PASS, two genuine feature TCP cells.
Race/checkptr: PASS. Sudoku integration 10x: PASS. Supervisor 10x: PASS.
Transaction/create/precommit admission/rollback: PASS. SQLite recovery: PASS.
Regressions: 49 PASS — native REALITY12, standard Xray4, Snell9, HY2 12, TUIC12.
Fuzz: PASS. Docs/links: PASS. OpenAPI: PASS. Live API/CLI: PASS.
These full acceptance results and their evidence hashes are retained unchanged.

### Fresh freeze gates

Windows full-tag tests and build: PASS.
Linux WSL2 native ext4 full-tag tests/build and default race/checkptr: PASS.
Managed FinalMask/Sudoku critical campaign: PASS, Alice/Bob and recovery/negative cases.
Standard Xray, Native VLESS, Snell, HY2 and TUIC critical smokes: PASS.
Each regression smoke uses one complete pinned reference-client IPv4 cell with
TCP/UDP, concurrency16 and 4 MiB checks. It is a bounded new smoke, not a rerun
or replacement of the accepted 49-cell matrix. Repository drivers remain unchanged.
Docs/links/OpenAPI and accepted live response sets: PASS; fresh masked live API/CLI: PASS.
Final worktree/staged secret scans and git diff checks: PASS.

The original development failures remain in the acceptance report and external
evidence. No failure log was removed; no runtime workaround, suppression or test
skip is used as a freeze gate.

## Security

Only explicit authorized client export returns UUID/shared password. Normal API,
logs, doctor and argv omit them. REALITY private keys are excluded before client
secret decryption. Rendered Xray config, keys, DBs and logs remain external and
private; campaign children join and private data is removed. No binary, client,
runtime config, key, DB, log, cache, coverage or fuzz artifact enters the Git stage.

## Platform

Linux amd64: qualified for the bounded Experimental scope.
Windows normal tests/build/owned lifecycle: PASS.
Windows abnormal child-exit/parent-crash qualification: DEFERRED.
Xray arm64 runtime: NOT CERTIFIED. Existing cross compile is build evidence only.
No platform status is promoted by the freeze.

## Docker / NoBrand

Docker: not queried or touched. Redis/TeleLedger: untouched.
NoBrand: read-only reference audit; real source changes NONE. Audited file hashes
and HEAD/status remain unchanged. Production integration remains deferred.

## Commit

This report is included in the unique Phase 7 local freeze commit with message:
`feat(engine): add experimental Xray VLESS extensions`.
Sole parent: `438b1096b9ec357cddb163cf89f78935e711bf3d`.
Its full SHA and exact diff statistics are recorded in the external post-commit
audit and completion reply; the commit is identified here by subject/parent to
avoid embedding a self-referential SHA. Explicit staging includes 54 source/test/
canonical documentation/report paths. No amend or history rewrite.

## Git

main and codex/phase-7-xray-vless-extensions identify the same Phase 7 commit;
main fast-forwarded from Phase 6 only. Working tree CLEAN after commit and branch
creation. Prior freeze ancestry remains linear. Origin NONE; sole remote upstream
remains unchanged. Push NONE. Tag NONE. Release NONE.

## Phase 8

Branch: codex/phase-8-mieru-native-integration.
Base: the Phase 7 freeze commit, equal to main and Phase 7 branch.
Implementation: NOT STARTED. Work stops immediately after clean branch creation.

## Evidence

Freeze evidence: `D:\splicore-validation\phase7-integration-20261002\freeze-20261002`.
Acceptance evidence: its unchanged parent directory.
Fresh runtime root: `/root/p7f-20261002`; accepted Phase 6/7 roots unchanged.
Key records: acceptance-source-match.json, linux-gates.json, smoke-gates.json,
docs-gates.json, staged-source-match.json, secret-scan-worktree.json,
secret-scan-staged.json and post-commit-audit.json.
No external evidence tree is staged or committed.

## Deferred

Vision; masked UDP/XUDP; masked TLS/REALITY; other masks/chains/custom tables;
other clients/versions; Windows abnormal child-exit qualification; Xray arm64
runtime; Mieru; Panel; unified quota/rate enforcement; persistent usage;
NoBrand production integration; Stable designation.

## Final Result

PHASE 7 FROZEN.

## Blockers

None for the authorized local freeze of the bounded Experimental scope.
