# Splicore Phase 21 Deep Core Purge Report

- Documentation status: Canonical
- Audience: Maintainers and targeted cleanup reviewers
- Last reviewed: 2026-10-09
- Owner: Core maintainers
- Responsibility: Completed cleanup scope, local validation and review handoff.
- Lifecycle: Candidate report; targeted independent review required before Freeze.

## Verdict and source

**PHASE 21 DEEP CORE PURGE READY FOR REVIEW**

Base HEAD: `1ef9458a2c06aa974e721db2fe4f271bb9068ef6`.
Branch: `codex/phase-21-shared-transport`. Index EMPTY; working tree DIRTY / UNSTAGED.
Splicore is an independent proxy core for server and client roles. See
[Core scope](../architecture/CORE_SCOPE.md).

## Cleanup

Removed desktop System Proxy/WinINET desired state, native Internet Settings
setters, desktop leases, application operations and config/API/CLI enablement.
WinHTTP mutation, Desktop PAC, GUI and tray have no active production path.
Preserved Native TUN, routes/interfaces/socket control, DNS/routing/policy,
Core recovery, API/CLI, SQLite, credentials, backup/restore and distribution.

Deleted 47 files including four desktop implementation/test files,
orphan driver/certificate/mobile assets and obsolete build targets. Historical
Foundation/Phase 2–5 compositions moved to test fixtures excluded from production.
NativeCore directly composes current coverage. Current docs, Docker identity and
CI consumers were corrected. No protocol or shared transport behavior was changed.

## Legacy data

Frozen migrations 0001–0008 remain byte-identical. Migration 0007 and
`client_host_profiles` are inert: current Core has zero readers/writers. TUN
already lives independently in `local_inbounds`; no forward migration is needed.
Physical backups preserve old bytes; current configuration exports omit desktop
desired state, and old config fields receive typed rejection.

Only restored historical journal steps decode as private opaque history. Active
legacy debt returns typed NotImplemented before store/OS writes; new Core plans
cannot create desktop records. Core route compensation remains functional.
Historical normal Windows activation was blocked before OS mutation, so no
WinINET repair utility is retained. Release-tag conclusions are bounded to local
history; public publication state was not queried or asserted.

## Dependencies and artifacts

All 19 direct modules have consumers. Offline tidy added,
updated and removed zero modules; verify PASS. There are 71
production packages and 3 test-only helper packages, with zero
unexplained dead packages. Three actual command closures and symbol inventories
contain no desktop manager, placeholder factory or external Core launcher.
SagerNet is 0/0/0/0; Underlay is 93 → 93, Unknown=0.
Accidental generated/runtime/IDE artifacts and unexplained archives are zero.
Frozen historical captures, ADRs and reports are preserved with provenance.

## Local validation

- Full default/native tests, default/native/shared race and checkptr ON: PASS.
- Fresh/schema6/schema7/schema8 upgrades, mixed inert data, backup/reopen and
  existing backup/restore/crash suites: PASS. Normal legacy writes=0.
- Core/storage/shared lifecycle x25 and real isolated WSL TUN x25: PASS.
- Changed Core/legacy journal fuzz and existing journal fuzz: PASS, no crash.
- Final cleaned-tree mixed stress: 10m17.756167083s, unexpected errors=0;
  TUN, proxy ingress, owned protocols and WS/HTTPUpgrade/gRPC exercised.
- Linux amd64, Windows amd64 and Linux arm64 builds: PASS. Windows tests are
  COMPILE ONLY; arm64 BUILD ONLY. Docker image builds were not executed.
- Secrets real=0/unresolved=0; final file/package/dependency/schema unknown=0.

Protocol wire, accepted shared transport and native runtime files are hash-bound
to the accepted Re-Review tree. Accepted 36/36 + Review 9/9 interop evidence is
reused; P21R-001/P21R-002 and all other accepted findings remain CLOSED.
Snell's existing nonblocking limits remain unchanged.

## Preservation, limits and next step

External evidence: `D:/splicore-validation/phase21-deep-core-purge-20261009/`.
It contains the full1230-file precleanup archive, manifests, actual validation
logs, final source bindings and protected prior evidence checks.
Historical platform status remains PARTIALLY PASSED; Phase 21 is NOT PLATFORM
QUALIFIED. No stage, commit, push, tag, release, Freeze or Phase22 occurred.
Public GitHub is unchanged; NoBrand-OneClick was not accessed.

Next required step: **TARGETED DEEP CORE PURGE INDEPENDENT REVIEW**.
This cleanup validation does not perform that review. Stop at this handoff.
