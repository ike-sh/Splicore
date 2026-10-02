# Splicore Phase 9 Freeze Report

- Documentation status: Historical
- Audience: Maintainers and subsequent client-runtime developers
- Last reviewed: 2026-10-02
- Owner: Project maintainers
- Responsibility: Authorized Phase 9 checkpoint, qualifications and Git closure.
- Lifecycle: Freeze snapshot; subsequent implementation uses a new phase report.

## Baseline

Phase 8: `bd141f98e28d9499a88fe610ba3fc49aca48bf14`.
Entry branch: `codex/phase-9-distribution-service-foundation`.
Entry HEAD and main both equal Phase 8; index empty; sole remote is upstream.
No origin or unexpected changes were found.

## Pre-Freeze

Status: **DISTRIBUTION FOUNDATION READY FOR REVIEW**.
Working tree: approved Phase 9 uncommitted changes, intentionally dirty.
The [implementation report](PHASE_9_DISTRIBUTION_SERVICE_FOUNDATION_REPORT.md)
remains byte-for-byte unchanged as its acceptance snapshot.

The maintainer explicitly authorized final audit, exact-file staging, staged
audit, one commit, main fast-forward and a clean Phase 10 branch. The previous
stage/commit prohibition is lifted only for this closure. No history rewrite,
push/tag/release, new remote, NoBrand changes or Docker access is authorized.

## Qualification

| Platform / boundary | Frozen qualification |
| --- | --- |
| Ubuntu24.04 WSL2 amd64 | QUALIFIED for current Experimental distribution scope |
| Linux arm64 | BUILD ONLY / RUNTIME NOT CERTIFIED |
| Windows amd64 | BUILD / TEST ONLY; SERVICE DISTRIBUTION NOT CERTIFIED |
| SELinux | NOT CERTIFIED |
| AppArmor | NOT CERTIFIED |
| Unexpected power loss / killed installer | MANUAL RECOVERY BOUNDARY |

The service remains Experimental. No stable channel or production rollout is
claimed. Vision, broader masks, quota/rate and other existing deferred protocol
qualifications stay deferred. Optional Xray remains the exact Phase 6 official
v26.3.27 artifact; Mieru remains embedded v3.38.0 without a mita service.

## Acceptance

| Gate | Result |
| --- | --- |
| Installed traffic | **48/48 PASS** |
| Clean install / first start | **PASS** |
| Restart | **PASS** |
| Parent crash recovery / owned Xray cleanup | **PASS** |
| Unrelated Xray | **UNAFFECTED** |
| Upgrade | **PASS** |
| Failed migration rollback / coherent SQLite snapshot | **PASS** |
| Program uninstall / state retention | **PASS** |
| Reinstall | **PASS** |
| Explicit purge / path and bind-mount safety | **PASS** |
| Non-root service / low ports / sensitive modes | **PASS** |
| Default race/checkptr | **PASS** |
| Distribution / operations 10x race | **PASS** |
| Affected common/adapter/transport race | **PASS** |
| Linux amd64 / Windows tagged tests and builds | **PASS** |
| Linux arm64 compile | **PASS**, runtime remains uncertified |
| Repeated build / package and source inspection | **PASS** |
| Doctor / API health | **PASS** |
| Support bundle secret gate | **PASS**, blocking |
| Docs / links / OpenAPI / live schema validation | **PASS** |
| Prestage / staged secret, scope and whitespace audits | **PASS** |
| Acceptance Source Match | **PASS** |

All eight installed profiles run through six stages: initial, restart, parent
crash recovery, upgrade, rollback and reinstall. Snell/HY2/TUIC/Mieru TCP+UDP
payload, flow-none native/Xray VLESS TCP and bounded plain-TCP Sudoku remain
the existing accepted profiles. This does not expand protocol qualification.

The secret gate scans every decompressed archive member for synthetic Snell PSK,
HY2/TUIC/Mieru passwords, VLESS UUID, REALITY private key and API token. Installed
journal injection proves raw values entered the unit journal before redacted
bundle generation. Automatic upload: **NO**. No secrets leak.

## Acceptance Source Match

Entry match: all **1906** source files equal the final prior acceptance source
archive, digest `da032acc09f22f6421e16478be83a2b5cd2a0260ac3d40a496c0c270581e22c3`.
Subsequent freeze edits change documentation only; runtime, tests, scripts,
bootstrap, unit and migration bytes remain unchanged.

Fresh formal freeze gates still build and inspect the exact final freeze source
and exercise installed-service lifecycle/traffic plus live API schema projections.
Artifact identity includes the documentation changes. Builds do not change source.
Precommit artifacts accurately retain Phase 8 commit plus `source_dirty:true`;
they are private qualification artifacts, not a published Phase 9 release.
Complete source manifests and final digest are recorded externally.

## Runtime Audit

sing-box upstream source: **0 modifications**.
Mieru upstream source: **0 modifications**.
Xray source/artifact: **0 modifications**.
Wire: **0 modifications**. New protocols: **0**.
Historical Phase 0–8 reports, original Phase 9 acceptance report and SQL
migrations 0001–0004: **UNCHANGED**.
NoBrand source/HEAD/status/tracked hashes: **UNCHANGED**.
Docker: **UNTOUCHED / NOT QUERIED**. Redis / TeleLedger: **UNTOUCHED**.

## Scope

Approved files cover distribution/package, local installer/updater/rollback,
SQLite maintenance backup, systemd, dedicated identity/permissions, doctor,
support bundle, sanitized exits/crash recovery, manifest/version identity,
tests, canonical docs/ADR and Phase 9 reports. No generated binary, archive,
runtime config/DB/key, support bundle, log, cache or external evidence is staged.
An explicit path list is used; `git add .` is not used.
Functional changes remain the already accepted Phase 9 implementation.

## Commit

Exactly **ONE** authorized Phase 9 commit contains this freeze report.
Message: `feat(dist): add Linux service distribution foundation`.
Sole parent: `bd141f98e28d9499a88fe610ba3fc49aca48bf14`.
PHASE_9_COMMIT: resolve
`git rev-parse codex/phase-9-distribution-service-foundation`.
The commit cannot embed its own full SHA; the actual SHA, file/insertion/deletion
counts and post-commit closure checks are recorded externally and in the final
maintainer-facing report. No amend, rebase, squash, merge commit or forced movement.

## Git

Final required equality: main == Phase 9 == new Phase 10 HEAD == PHASE_9_COMMIT.
main moves only by
`git merge --ff-only codex/phase-9-distribution-service-foundation`.
Working tree: **CLEAN**. Index: **EMPTY** after authorized closure.
History rewritten: **NO**. Existing unrelated refs remain unchanged.

Linear ancestry: Phase 9 → Phase 8 above → Phase 7
`ca48d8429abb21fcaf7ee21d68e37d1ec5d6ec4d` → Phase 6
`438b1096b9ec357cddb163cf89f78935e711bf3d` → Phase 5
`afacb248440aedb6ac5a2f0d14ad7defedddb627` → Phase 4
`2a9c0f3e14de29050c1228ce013b2f1ad4556946` → earlier frozen ancestry.

## Remote

origin: **NONE**. Sole existing upstream remote unchanged.
Push: **NONE**.

## Tag / Release

Tag: **NONE**. Release: **NONE**. No public artifact publication.
SHA256 integrity remains relative to independently trusted metadata;
artifact signing and public channels remain deferred.

## Phase 10

Old NoBrand Canary Plan: **CANCELLED / DEFERRED**.
No NoBrand canary branch is created, selected or deleted.
Branch: `codex/phase-10-client-runtime-foundation`.
Base: **PHASE_9_COMMIT**. Working tree: **CLEAN**. Index: **EMPTY**.
Implementation: **NOT STARTED**. No RemoteNode, outbound, SOCKS, Snell client,
client schema or Phase 10 documentation is created in this freeze task.

## Next Direction

Complete the unified Splicore client/server core before NoBrand migration.
Client runtime implementation follows a separate authorized phase.

## Evidence

Fresh Windows evidence root: `D:/splicore-validation/phase9-freeze-20261002`.
Native Linux fixtures/lab: `/root/splicore-p9-freeze-20261002`.
Entry audit, accepted/final source manifests, Windows/Linux gates, package
metadata/inspection, actual installed-service results, permissions, bounded
redacted support archive, live schema fixtures, staged audit/secret scan and
final Git closure records remain external. Prior acceptance evidence at
`D:/splicore-validation/phase9-20261002` remains intact.
Raw synthetic secrets and journals stay private in the disposable native lab.
Owned lab processes are stopped and their cleanup state recorded.

## Final Result

**PHASE 9 FROZEN** after the authorized single-commit and Git closure checks.

## Blockers

None within the bounded Experimental distribution scope.
