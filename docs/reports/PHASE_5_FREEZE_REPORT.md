# Splicore Phase 5 Local Freeze Report

- Documentation status: Historical
- Audience: Maintainers and Phase 6 reviewers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Record the authorized local freeze of the accepted flow-none VLESS/REALITY surface.
- Lifecycle: Preserve this checkpoint; future changes belong to a later phase.

## Authorization and baseline

The maintainer selected "complete Phase 5 freeze, then continue Phase 6" after
the local audit found the Phase 5 implementation still uncommitted. This authorizes
one local Phase 5 freeze commit and creation of the Phase 6 branch. No push, tag,
release, history rewrite or Phase 6 implementation commit is authorized.

Parent: Phase 4 freeze `2a9c0f3e14de29050c1228ce013b2f1ad4556946`.
The Phase 5 freeze is the commit containing this report; its exact SHA is recorded
in the Phase 6 baseline. Upstream remains sing-box v1.14.1 / sing-vmess v0.2.8.

## Accepted surface

VLESS and REALITY flow-none are Experimental. Vision is DEFERRED / UNSUPPORTED
under [ADR 0017](../adr/0017-defer-vision-dependency-safety.md). All managed
configuration/runtime/profile/export paths reject Vision. No dependency patch,
sanitizer suppression or wire implementation change is included.

The [final acceptance report](PHASE_5_FINAL_ACCEPTANCE_REPORT.md) remains unchanged
and owns the full 20-cell matrix, hashes and detailed outcomes. The
[initial report](PHASE_5_VLESS_REALITY_NATIVE_VERTICAL_SLICE_REPORT.md) preserves
the original Vision implementation and failing safety evidence.

## Freeze verification

Fresh evidence remains at `D:\splicore-validation\phase5-vision-deferred-20261002`.
Before freezing, final source audit reconfirmed that all Go/script/fixture bytes
match the formally tested candidate. Freeze edits add this checkpoint and update
current status/navigation only; no functional code changed after acceptance.

| Gate | Result |
|---|---|
| Windows/Linux full owned units and builds | PASS |
| Default checkptr/race and affected shared race | PASS |
| Non-Vision native traffic, ten consecutive iterations | 10/10 PASS |
| VLESS client matrix | 20/20 PASS |
| Snell/Hysteria2/TUIC regressions | 9/12/12 cells PASS |
| Fuzz, vet, original sing-box tests, arm64 compile | PASS |
| Docs/OpenAPI/live responses | PASS; freeze navigation rechecked |
| Source/dependency/secret/whitespace audit | PASS |
| Historical Phase 0–4 reports/evidence and migrations 0001–0003 | UNCHANGED |
| Upstream runtime/dependency/wire modifications | 0 / 0 / 0 |

## Git and external boundaries

One reviewed commit on codex/phase-5-vless-reality-vertical-slice, followed by a
new codex/phase-6-xray-engine-duality branch from that commit. Main is not moved.
Push/tag/release: NONE. Docker/Redis/TeleLedger/real NoBrand: UNTOUCHED.
Original triage reports/reproducer/logs are preserved. No generated binary or
private runtime input is included in Git.

## Result

**PHASE 5 LOCALLY FROZEN; EXPERIMENTAL FLOW-NONE VLESS/REALITY ACCEPTED.**
Phase 6 begins with Xray still an unavailable structural placeholder. Vision
remains deferred; Xray must not reopen it.
