# Splicore Phase 21 Core Scope Correction Fix Round 1 Report

- Documentation status: Canonical
- Audience: Maintainers and targeted Core-scope reviewers
- Last reviewed: 2026-10-09
- Owner: Core maintainers
- Responsibility: Docker scope correction, preservation evidence and re-review handoff.
- Lifecycle: Candidate fix report; targeted independent re-review required; no Freeze.

## Verdict

**PHASE 21 CORE SCOPE CORRECTION READY FOR RE-REVIEW**

## Product Boundary Correction

Splicore is an independent proxy Core usable as server and client Core.
Docker: EXTERNAL LOCAL TEST TOOL ONLY. Docker Distribution and Container Packaging:
OUT OF CORE. Docker/Compose/container-image publication are not repository product
surfaces. External/local validation remains allowed outside the Core repository.
See [Core scope](../architecture/CORE_SCOPE.md#container-packaging).

Docker build: NOT A PHASE FREEZE GATE. Docker image: NOT A SPLICORE RELEASE ARTIFACT.
Docker runtime: NOT A PLATFORM QUALIFICATION TARGET. Native binary builds are the
repository distribution check. No Docker command, build, run, Compose, image smoke,
image/container cleanup or Docker installation change was performed in this round.

## P21CR-001 and chronology

Deep Core Purge: READY FOR REVIEW.
Independent Review: **PHASE 21 DEEP CORE PURGE REVIEW FAILED**.
P21CR-001 Previous: MAJOR / OPEN. Review correctly evaluated the then-present
materially changed Docker recipes as supported candidate distribution assets with
missing build/smoke evidence. The failed Review and its finding remain unchanged.

An intervening Docker-validation Fix Round 1 report already existed at this round's
entry. That report and its external evidence remain historical truth; this scope
correction supersedes its proposed Docker-targeted next step, without rewriting it.

Scope decision: Docker is external/local validation tooling, outside Splicore Core.
Resolution: **REMOVE OUT-OF-SCOPE DOCKER REPOSITORY SURFACE**.
P21CR-001 Current: **SCOPE-CORRECTED — PENDING RE-REVIEW**.
It is not CLOSED. A later targeted Core-scope re-review may evaluate
OUT-OF-SCOPE SURFACE REMOVED. Independent re-review is not performed by this fix.

## Git State

Branch: `codex/phase-21-shared-transport`.
HEAD: `1ef9458a2c06aa974e721db2fe4f271bb9068ef6`. Working tree: DIRTY / UNSTAGED. Index: EMPTY.
Cached diff/name-status are empty. Index content tree equals HEAD tree
`56c181b39cf4c435aba03d4d815b1125f03e0444` at entry and exit.
The preexisting `.git/index.lock` is preserved. Direct `git write-tree` fails on
that lock; `git write-tree` succeeds on an exact external index snapshot, following
the prior Review's method. Raw `.git/index` hashes are not staged-content authority.

## Docker Repository Surface Before and After

| Surface | Before | After |
| --- | ---: | ---: |
| Dockerfiles | 2 | 0 |
| Compose deployment files | 0 | 0 |
| .dockerignore | 0 | 0 |
| Docker packaging scripts | 0 | 0 |
| Docker tracked test orchestration | 0 | 0 |
| Docker publish CI jobs | 0 | 0 |
| Docker-only CI configuration rules | 1 | 0 |
| Docker deployment documents | 2 | 0 |
| Mixed current document advertising container packaging | 1 | 0 |
| Docker runtime dependencies | 0 | 0 |

All repository files, including hidden/ignored files, were scanned. Remaining
mentions are classified as HISTORICAL_DOC, EXTERNAL_TEST_REFERENCE or FALSE_POSITIVE.
Core TUN/Docker bridge compatibility text, namespace primitives, legal copyrights,
historical container evidence and this product exclusion statement are preserved.
There is no active in-repository Docker distribution, deployment or test harness.

## Files Removed

4 tracked files: `Dockerfile`, `Dockerfile.binary`, `docs/installation/docker.md`,
`docs/installation/docker.zh.md`. Exact entry hashes and classifications are in
`docker-scope-deletions.json` in the new external evidence directory.

## Files Modified and Added

4 existing files modified:

- `.github/renovate.json`: remove only Dockerfile dependency-update rule.
- `docs/architecture/CORE_SCOPE.md`: explicit product boundary and native build gate.
- `docs/architecture/FORK_BOUNDARY.md`: replace container packaging claim with native binaries.
- `test/config/vless-tls-client.json`: replace Docker host alias with `127.0.0.1`; all protocol fields retained.

1 file added: this focused report. README and all four Core workflows are byte-identical
to round entry. Core installers, native binary packaging, service assets and generic
process/namespace tests remain present. No CI action versions changed.

Historical pre-fix count: 1195. Actual round entry: 1196, including the already-existing
Docker-validation fix report. Final count: **1193** = 1196 - 4 + 1. No magic count target.
Every round delta is accounted for. Historical external cleanup manifests are immutable;
the new evidence manifest reclassifies removed Docker assets as OUT_OF_SCOPE_DOCKER.

## Core Source Semantic Changes

**NONE.** All 530 Go files, including production and test source, are byte-identical
to round entry and accepted Deep Core Purge source. `go.mod` and `go.sum` are unchanged.
Dependencies Added=0, Updated=0, Removed=0. `go mod tidy` was not needed because
no Go dependency consumer changed. Runtime config, protocol, transport and TUN semantics
are unchanged; the static peer fixture's address only removes Docker orchestration coupling.

## Tests

`go test -count=1 ./...`: **PASS** (101.304s).
`go test -count=1 -tags=with_gvisor,with_quic,with_utls ./...`: **PASS** (107.704s).
Both commands ran in an owned Linux WSL namespace with loopback, offline cached
dependencies, a nonexistent DOCKER_HOST socket and failing Docker CLI guards.
Docker CLI invocations: **0**. Docker daemon required: **NO**. No daemon was stopped.
Source and default/native dependency graphs show zero Docker API/orchestration dependencies.
Optional external peer process tests keep their existing opt-in contract; no new
interoperability qualification is asserted.

## Native Builds

All builds use CGO_ENABLED=0 and `with_gvisor,with_quic,with_utls`; actual outputs
remain in the external evidence directory. No release or publication occurred.

| Target | Result | Exact output | SHA256 |
| --- | --- | --- | --- |
| linux-amd64 | PASS | `D:/splicore-validation/phase21-core-scope-correction-fix1-20261009/builds/splicore-linux-amd64` | `71fdb8f1ebeb58bdb7652ad4407ffcbed920cf0702045154a1a0b664a3f6b414` |
| windows-amd64 | PASS | `D:/splicore-validation/phase21-core-scope-correction-fix1-20261009/builds/splicore-windows-amd64.exe` | `6a237f5507ed48e7b51950f99fded9ff8929c232bf2e4f2c728405a01030b601` |
| linux-arm64 | PASS | `D:/splicore-validation/phase21-core-scope-correction-fix1-20261009/builds/splicore-linux-arm64` | `9e32be858cb783ecabab2df9e22797078acb1d39f50c40c3128aa1a21d888699` |

Linux arm64 remains **BUILD ONLY**. Windows runtime was not newly executed or
qualified; prior Windows test evidence remains COMPILE ONLY. Binary build success
does not change platform qualification.

## TUN, Shared Transport, Protocols and Frozen Migrations

TUN: PRESERVED. WebSocket: UNCHANGED. HTTPUpgrade: UNCHANGED. gRPC: UNCHANGED.
Protocols: UNCHANGED. P21R-001: CLOSED. P21R-002: CLOSED.
Frozen migrations 0001–0008, including `0007_host_integration.sql`: Changed=0;
entry, exit and frozen HEAD hashes match. No new migration.

## Dependency and Runtime Seals

SagerNet Source/Direct/Graph/Binary: **0/0/0/0**. Source means runtime imports;
required copyright attribution remains. Fresh graphs and metadata/symbol audits of
all three new native binaries contain no SagerNet/Docker/external Core modules.
External Core Runtime: Xray=0, sing-box=0, Mihomo=0. Generic Linux netns/netlink
primitives are retained. Underlay: 93 → 93, Unknown=0; accepted audit reused after
all Go consumers, audit script and callsite inventory hash verification.
Secrets: real=0, unresolved=0; fresh source/evidence scan and exact reviewed line
classifications. No real credentials used.

Core Scope Seal: proxy_core=true, server_core=true, client_core=true,
desktop_client=false, docker_distribution=false, container_orchestrator=false,
system_proxy_manager=false, wininet_manager=false, winhttp_manager=false,
desktop_pac_manager=false, native_tun=true, routing=true, dns=true, policy=true,
shared_transport=true.

The raw module graph retains 17 container-related declarations from gVisor's
unused upstream branches. None has a Core production/default/native test package
or new binary consumer. These declarations are explicitly classified in
`docker-dependency-audit.json`; gVisor's Core TUN/netstack dependency is preserved.

## Existing Stress and Race Evidence

10m17.756167083s, unexpected errors=0. Still applicable: **YES**.
All 532 stress source/dependency entries and stress executable identity match.
Accepted default/native/shared race/checkptr ON and raw log hashes are verified.
No full race, 10-minute stress or 36/36 interoperability rerun is required for
removing Docker assets with unchanged Go/dependencies/runtime semantics.

## Platform Qualification, Evidence and Actions

Historical: PARTIALLY PASSED. Phase21: NOT PLATFORM QUALIFIED.
Linux arm64: BUILD ONLY. Docker: OUT OF PRODUCT SCOPE.
Public GitHub: UNCHANGED, not accessed. NoBrand-OneClick: NOT ACCESSED.
New BLOCKER=0, new MAJOR=0 from this fix's acceptance checks; the original MAJOR
finding remains SCOPE-CORRECTED — PENDING RE-REVIEW.

New external evidence:
`D:/splicore-validation/phase21-core-scope-correction-fix1-20261009/`.
Prior Deep Core Purge, failed Review and prior Docker-validation evidence retain
their original membership and bytes. Exact source/preservation/build/test audits,
manifests, raw logs and terminal evidence seal are available there.

Git Actions: staged=NO, committed=NO, pushed=NO, tagged=NO, released=NO, frozen=NO.
Phase22: NO. No automatic independent re-review.

## Next Step

**TARGETED CORE-SCOPE RE-REVIEW OF P21CR-001**. Stop after this fix report.

# PHASE 21 CORE SCOPE CORRECTION READY FOR RE-REVIEW
