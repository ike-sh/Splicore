# Splicore Phase 21 Deep Core Purge Docker Validation Fix Round 1 Report

## Verdict

PHASE 21 READY FOR DOCKER TARGETED RE-REVIEW

## Finding and chronology

Deep Core Purge: READY FOR REVIEW.
Independent Review: PHASE 21 DEEP CORE PURGE REVIEW FAILED.
Original finding P21CR-001: MAJOR / OPEN; changed Docker recipes lacked build,
container startup and runtime smoke evidence. The original failed report is preserved.

P21CR-001: VALIDATION COMPLETED — PENDING TARGETED RE-REVIEW.
Only a separately authorized Independent Targeted Re-Review may close it.

## Validated candidate

Branch: `codex/phase-21-shared-transport`.
HEAD: `1ef9458a2c06aa974e721db2fe4f271bb9068ef6` (Phase 20 frozen).
Working tree: DIRTY / UNSTAGED. Index staged contents equal HEAD.
Core Go source, dependencies, frozen migrations 0001–0008 and shared transports
remain unchanged during this round. P21R-001 and P21R-002 remain CLOSED.
Neither Docker recipe was modified during this round. Relevant English and Chinese
Docker instructions were corrected from obsolete sing-box usage to the actual Core
CLI and private state-directory contract. No protocol, API, storage or host fix.

## Docker evidence

| Recipe | Build | Startup | Data plane | Shutdown | Result |
| --- | --- | --- | --- | --- | --- |
| Dockerfile, final runtime stage | PASS | PASS | PASS | PASS | PASS |
| Dockerfile.binary, runtime image | PASS | PASS | PASS | PASS | PASS |

Docker Desktop Linux amd64 engine on WSL2 was available. Each recipe received
its own no-cache build. The binary recipe used the current source-recipe binary,
with explicit SHA256 identity binding. Both actual PID 1 processes were Splicore.
The module identity is `github.com/ike-sh/Splicore`; CGO_ENABLED=0 and static ELF
were verified. Image filesystem/build metadata/symbol audits found no SagerNet,
external proxy core, active desktop artifacts, unexpected source/evidence junk
or real/unresolved secrets. CA bundles were observed in both images.

Runtime validation used `--network none`, loopback-only target/client traffic,
all capabilities dropped, synthetic configs, fresh private SQLite state and
protected UDS management. No host routes, proxy settings, TUN or public listeners
were changed. Primary SOCKS5 payload/reply and HTTP through Mixed each passed 10/10.
Primary startup/readiness/payload/graceful-stop cycles passed 5/5, including persisted
database restoration. Valid bootstrap accepted; invalid schema rejected. API JSON,
passive CLI doctor, version/help and retired endpoint/command rejection passed.

The first harness attempt pointed state_directory at a new volume root (0755),
which Core correctly rejected. Its failure evidence is preserved. The corrected
synthetic config lets Core create `/var/lib/splicore/state` with mode 0700; no Core
permission check was changed. A fresh full `go test ./...` passed after correcting
the test runner cache path; the original dependency-loading failure is preserved.
Existing race/checkptr and 10m17.756s stress (unexpected errors=0) remain reusable
by unchanged executable-source identity.

The evidence directory records the second unchanged-recipe build and its runtime
smoke, exact final source manifests, image IDs, stop times, cleanup and terminal seals:

`D:/splicore-validation/phase21-deep-core-purge-review-fix1-20261009/`

Authoritative detailed report: `PHASE21_DEEP_CORE_PURGE_REVIEW_FIX1_REPORT.md`.
Machine-readable outcome: `summary.json`. Initial failures and old Review evidence
remain available. No broad Docker cleanup was performed.

## Limits and next step

No HEALTHCHECK is defined; image user remains inherited root. `.dockerignore` is
absent; builder context includes repository metadata and historical fixtures, while
the audited final runtime image copies only the Core binary from that context.
TUN Docker runtime: NOT PART OF THIS TARGETED P21CR-001 CLOSURE.
HTTP retains the accepted single-request / Connection: close contract.

Historical qualification: PARTIALLY PASSED. Phase21: NOT PLATFORM QUALIFIED.
Windows runtime qualification is unchanged; Linux arm64 remains BUILD ONLY.
No stage, commit, push, tag, release, Freeze or Phase22. Public GitHub unchanged;
NoBrand-OneClick not accessed. Stop after report; next step is separately authorized
TARGETED INDEPENDENT RE-REVIEW OF P21CR-001 ONLY.

# PHASE 21 READY FOR DOCKER TARGETED RE-REVIEW
